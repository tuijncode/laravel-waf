<?php

namespace Tuijncode\LaravelWaf\Services;

use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Support\SurfaceDecoder;

/**
 * Keeps captured secrets out of the log table.
 *
 * The WAF detects API keys, passwords, tokens and card numbers — so the value
 * that tripped the rule must never be stored verbatim, or the `waf_logs` table
 * becomes a honeypot of the very data it protects. This masks those values in
 * anything about to be persisted.
 */
class Redactor
{
    private const DEFAULT_FIELDS = [
        'password', 'password_confirmation', 'current_password', 'new_password', 'old_password',
        'passwd', 'pwd', 'secret', 'client_secret', 'api_key', 'apikey',
        'api_secret', 'private_key', 'token', '_token', 'access_token',
        'refresh_token', 'id_token', 'auth_token', 'csrf_token', 'xsrf_token',
        'session_id', 'sessionid', 'phpsessid', 'authorization',
        'card_number', 'credit_card', 'cvv', 'cvc', 'pin', 'otp',
    ];

    /**
     * Description/category fragments that mark a finding as carrying a secret.
     */
    private const DEFAULT_LABELS = [
        'key', 'token', 'secret', 'password', 'credential',
        'card', 'private key', 'session id', 'jwt', 'oauth', 'bearer',
    ];

    public function enabled(): bool
    {
        return (bool) config('waf.redact.enabled', true);
    }

    /**
     * Does this finding's captured value need masking?
     */
    public function isSensitive(SignatureMatch $match): bool
    {
        $haystack = strtolower($match->description.' '.$match->category);

        foreach ((array) config('waf.redact.labels', self::DEFAULT_LABELS) as $label) {
            if ($label !== '' && str_contains($haystack, strtolower((string) $label))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Mask the middle of a value, keeping just enough at the edges to remain
     * recognisable (e.g. `AKIA…EXAMPLE` → `AK****************LE`).
     */
    public function mask(string $value): string
    {
        $length = mb_strlen($value);

        if ($length <= 4) {
            return str_repeat('*', max($length, 1));
        }

        $keep = $length <= 8 ? 1 : 2;

        return mb_substr($value, 0, $keep)
            .str_repeat('*', $length - (2 * $keep))
            .mb_substr($value, -$keep);
    }

    /** @param array<int, string> $values */
    public function scrub(string $text, array $values): string
    {
        if ($values === []) {
            return $text;
        }

        foreach (SurfaceDecoder::variants($text, 4) as $variant) {
            foreach ($values as $value) {
                if ($value !== '' && str_contains($variant, $value)) {
                    // A rule only captures its first match (possibly truncated);
                    // keeping the rest of this text could disclose another secret.
                    return '[REDACTED]';
                }
            }
        }

        return $text;
    }

    /** Mask named credentials even when no secret signature matched them. */
    public function fields(string $text): string
    {
        if (! $this->enabled() || $text === '') {
            return $text;
        }

        $fields = array_filter(
            (array) config('waf.redact.fields', self::DEFAULT_FIELDS),
            fn ($field): bool => is_string($field) && $field !== '',
        );
        if ($fields === []) {
            return $text;
        }

        $names = implode('|', array_map(fn (string $field): string => preg_quote($field, '/'), $fields));
        $mask = '[REDACTED]';
        $key = '(?:%(?:25)*5B|\[|(?<![A-Za-z0-9_-]))(?:'.$names.')(?:%(?:25)*5D|\])?(?:(?:%(?:25)*5B|\[)[^&=\[\]]*(?:%(?:25)*5D|\]))*';

        // Covers query/form parameters, including user[password] and password[0].
        // A quoted value may contain &, so mask the whole fragment in that case.
        if (@preg_match('/'.$key.'=\s*["\']/i', $text) !== 0) {
            return $mask;
        }
        $text = @preg_replace('/('.$key.'=)[^&]*/i', '$1'.$mask, $text);
        if ($text === null) {
            return $mask;
        }

        $jsonKey = '/"(?:'.$names.')"\s*:/i';
        $queryKey = '/'.$key.'=/i';
        $rawKeys = @preg_match_all($jsonKey, $text);
        $rawQueryKeys = @preg_match_all($queryKey, $text);
        if ($rawKeys === false || $rawQueryKeys === false) {
            return $mask;
        }
        foreach (SurfaceDecoder::variants($text, 4) as $variant) {
            if ($variant === $text) {
                continue;
            }
            $decodedKeys = @preg_match_all($jsonKey, $variant);
            $decodedQueryKeys = @preg_match_all($queryKey, $variant);
            if ($decodedKeys === false || $decodedKeys > $rawKeys
                || $decodedQueryKeys === false || $decodedQueryKeys > $rawQueryKeys) {
                return $mask;
            }
        }

        // Nested JSON needs a parser to identify its end; mask the fragment instead.
        if (@preg_match('/"(?:'.$names.')"\s*:\s*[\[{]/i', $text) !== 0) {
            return $mask;
        }

        // Evidence can contain a JSON fragment captured by another signature.
        return @preg_replace('/("(?:'.$names.')"\s*:\s*)(?:"(?:\\\\.|[^"\\\\])*"|[^,}\s]+)/i', '$1"'.$mask.'"', $text) ?? $mask;
    }

    /** Make untrusted text safe to store and read in logs, then bound its byte size. */
    public function storable(string $text, int $limit): string
    {
        if (! mb_check_encoding($text, 'UTF-8')) {
            $text = mb_scrub($text, 'UTF-8');
        }

        $text = preg_replace_callback(
            '/[\x00-\x08\x0A-\x1F\x7F]|\xC2[\x80-\x9F]|\xE2\x80[\xAA-\xAE]|\xE2\x81[\xA6-\xA9]/',
            fn (array $m): string => strlen($m[0]) === 1
                ? sprintf('\\x%02X', ord($m[0]))
                : sprintf('\\u%04X', mb_ord($m[0], 'UTF-8')),
            $text,
        ) ?? $text;

        return mb_strcut($text, 0, $limit, 'UTF-8');
    }

    /**
     * Collect the captured values that must be masked from a set of matches.
     *
     * @param  array<int, SignatureMatch>  $matches
     * @return array<int, string>
     */
    public function sensitiveValues(array $matches): array
    {
        if (! $this->enabled()) {
            return [];
        }

        $values = [];
        foreach ($matches as $match) {
            if ($this->isSensitive($match)) {
                $values[] = $match->matched;
            }
        }

        return array_values(array_unique(array_filter($values)));
    }
}
