<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Support\ClientIp;
use Tuijncode\LaravelWaf\Support\QuietLog;

/** Records distinct attack variants before the normal finding deduplication. */
class AttemptRecorder
{
    private const FINGERPRINT_PREFIX_BYTES = 262144;

    private static bool $missingTableWarned = false;

    private static bool $missingKeyWarned = false;

    /** @var array<string, bool> */
    private array $readyTables = [];

    /** @param array<int, SignatureMatch> $matches */
    public function record(Request $request, array $matches): void
    {
        if (! config('waf.attempts.enabled', false) || $matches === []) {
            return;
        }

        $ip = ClientIp::from($request);
        if ($ip === '') {
            return;
        }

        $hashKey = (string) config('app.key', '');
        if ($hashKey === '') {
            if (! self::$missingKeyWarned) {
                self::$missingKeyWarned = true;
                QuietLog::write('warning', 'laravel-waf: attempt recording requires APP_KEY for keyed payload hashes');
            }

            return;
        }

        $table = (string) config('waf.attempts.table', 'waf_attempts');

        try {
            if (! isset($this->readyTables[$table]) && ! Schema::hasTable($table)) {
                if (! self::$missingTableWarned) {
                    self::$missingTableWarned = true;
                    QuietLog::write('warning', "laravel-waf: attempt recording enabled but {$table} is missing; publish and run waf-migrations-attempts");
                }

                return;
            }
            $this->readyTables[$table] = true;

            $window = filter_var(config('waf.attempts.window_minutes', 60), FILTER_VALIDATE_INT);
            $window = $window !== false && $window > 0 ? $window : 60;
            $limit = filter_var(config('waf.attempts.max_per_ip', 200), FILTER_VALIDATE_INT);
            $limit = $limit !== false && $limit > 0 ? $limit : 200;
            $now = now();
            $windowSeconds = $window * 60;
            $windowId = intdiv($now->timestamp, $windowSeconds);
            $ttl = max(1, ($windowId + 1) * $windowSeconds - $now->timestamp);
            $counter = 'laravel-waf|attempt-count|'.sha1($ip).'|'.$windowId;
            Cache::add($counter, 0, $ttl);

            foreach ($matches as $match) {
                if ((int) Cache::get($counter, 0) >= $limit) {
                    break;
                }

                if ($match->matched === '') {
                    continue;
                }

                $raw = match ($match->context) {
                    'query' => (string) parse_url($request->getRequestUri(), PHP_URL_QUERY),
                    'body' => $request->getContent() !== ''
                        ? $request->getContent()
                        : (string) json_encode($request->request->all(), JSON_INVALID_UTF8_SUBSTITUTE),
                    'path' => $request->getPathInfo(),
                    'headers' => (string) json_encode($request->headers->all(), JSON_INVALID_UTF8_SUBSTITUTE),
                    'cookie' => (string) $request->headers->get('cookie', ''),
                    default => $match->matched,
                };
                $variant = substr(hash_hmac('sha256', $raw, $hashKey), 0, 16);
                $key = 'laravel-waf|attempt|'.sha1($ip.'|'.$match->id.'|'.$variant).'|'.$windowId;
                if (! Cache::add($key, true, $ttl)) {
                    continue;
                }

                if (Cache::increment($counter) > $limit) {
                    Cache::forget($key);
                    break;
                }

                try {
                    DB::table($table)->insertOrIgnore([
                        'ip_address' => $ip,
                        'rule_id' => $match->id,
                        'fingerprint' => $this->fingerprint($raw, $hashKey),
                        'variant' => $variant,
                        'window_id' => $windowId,
                        'created_at' => $now,
                    ]);
                } catch (\Throwable $e) {
                    Cache::forget($key);
                    Cache::decrement($counter);

                    throw $e;
                }
            }
        } catch (\Throwable $e) {
            QuietLog::write('warning', 'laravel-waf: attempt recording failed', ['error' => $e->getMessage()]);
        }
    }

    private function fingerprint(string $raw, string $hashKey): string
    {
        $text = substr($raw, 0, self::FINGERPRINT_PREFIX_BYTES);
        for ($pass = 0; $pass < 3; $pass++) {
            $decoded = html_entity_decode(rawurldecode($text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($decoded === $text) {
                break;
            }
            $text = $decoded;
        }

        $text = mb_strtolower(mb_scrub($text, 'UTF-8'));
        $text = preg_replace('/\s+/', ' ', trim($text)) ?? $text;

        // shortcut: encodings after 256 KiB remain distinct; use streaming normalisation if larger variants need grouping.
        $tail = '';
        if (strlen($raw) > self::FINGERPRINT_PREFIX_BYTES) {
            $hash = hash_init('sha256', HASH_HMAC, $hashKey);
            for ($offset = self::FINGERPRINT_PREFIX_BYTES, $length = strlen($raw); $offset < $length; $offset += 16384) {
                hash_update($hash, substr($raw, $offset, 16384));
            }
            $tail = hash_final($hash);
        }

        return substr(hash_hmac('sha256', $text.$tail, $hashKey), 0, 16);
    }
}
