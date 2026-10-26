<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Support\CacheFailure;
use Tuijncode\LaravelWaf\Support\TargetHash;

/**
 * Allow-list for tuning out noise.
 *
 * Operators register signatures they trust (by the finding's rule id or full
 * label and, optionally, a path glob). When a later finding matches one of
 * those entries it is flagged as an accepted false positive rather than a live
 * threat. The active set is memoised briefly to spare the database on every
 * request.
 */
class ExclusionRuleService
{
    private const TABLE = 'waf_exclusion_rules';

    private const CACHE_BUCKET = 'laravel-waf.exclusions.active';

    /**
     * Decide whether a finding should be treated as an accepted false positive.
     *
     * The label must match exactly — the rule id ("942100"), the description
     * ("SQL Injection Attack: UNION SELECT detected") or the whole signature
     * ("[942100] SQL Injection Attack: ..."). Substring matching would hand an
     * exclusion an unbounded blast radius (a label of "942" would silence every
     * SQLi signature), which is the wrong failure mode for the control whose
     * whole job is switching detections off — in blocking mode, silently
     * switching protection off.
     */
    public function accepts(string $signature, string $path): bool
    {
        return $this->acceptsAll([$signature], $path);
    }

    /** @param array<int, string> $signatures */
    public function acceptsAll(array $signatures, string $path): bool
    {
        $urlPath = parse_url($path, PHP_URL_PATH);
        if ($urlPath === false) {
            return false;
        }

        $targetHash = TargetHash::fromUrl($path);
        $path = trim((string) $urlPath, '/');
        $active = $this->active();

        foreach ($signatures as $signature) {
            // "[942100] SQL Injection Attack: ..." → id and description handles.
            $handles = [$signature];
            if (preg_match('/^\[([^\]]+)\]\s*(.*)$/s', $signature, $parts)) {
                $handles[] = $parts[1];
                if ($parts[2] !== '') {
                    $handles[] = $parts[2];
                }
            }

            if (! $active->contains(function (object $entry) use ($handles, $path, $targetHash): bool {
                $label = trim((string) $entry->match_label);

                if ($label === '' || ! in_array($label, $handles, true)) {
                    return false;
                }

                if (blank($entry->path_glob)) {
                    return true;
                }

                if ($entry->path_glob === '/') {
                    return $path === '';
                }

                if (str_starts_with($entry->path_glob, 'sha256:')) {
                    return $targetHash !== null && hash_equals(substr($entry->path_glob, 7), $targetHash);
                }

                return fnmatch($entry->path_glob, $path);
            })) {
                return false;
            }
        }

        return true;
    }

    /**
     * Promote a previously logged finding into a standing exclusion.
     */
    public function acceptFromLog(int $logId, int|string|null $userId = null, ?string $reason = null): ?object
    {
        $finding = DB::table(config('waf.table_name', 'waf_logs'))->find($logId);

        if ($finding === null) {
            return null;
        }

        $finding = (object) $finding;

        // The bracketed rule id (e.g. "[942110]") is the most precise handle;
        // fall back to the whole label when the shape is unexpected.
        $label = preg_match('/^\[([^\]]+)\]/', $finding->type, $hit)
            ? $hit[1]
            : $finding->type;

        $labels = array_values(array_unique(array_filter(array_map(
            trim(...),
            explode(',', (string) ($finding->rule_ids ?? '')),
        ))));
        if ($labels === []) {
            $labels = [$label];
        }

        $targetHash = $finding->target_hash ?? null;
        if ($targetHash === null && $finding->url === '[REDACTED]') {
            throw new \InvalidArgumentException('Cannot scope an exclusion from a redacted legacy log. Add a manual exclusion with an explicit path.');
        }

        if ($finding->url === '[REDACTED]') {
            $path = 'sha256:'.$targetHash;
        } else {
            $urlPath = parse_url($finding->url, PHP_URL_PATH);
            if ($urlPath === false) {
                throw new \InvalidArgumentException('Cannot scope an exclusion from a malformed log URL. Add a manual exclusion with an explicit path.');
            }
            $path = addcslashes(trim((string) $urlPath, '/'), '*?[]\\');
        }
        $path = $path === '' ? '/' : $path;
        $newId = DB::transaction(function () use ($labels, $path, $logId, $userId, $reason): int {
            $firstId = 0;
            foreach ($labels as $matchLabel) {
                $id = DB::table(self::TABLE)->insertGetId([
                    'match_label' => $matchLabel,
                    'path_glob' => $path,
                    'source_log_id' => $logId,
                    'created_by_user_id' => $userId,
                    'reason' => $reason,
                    'is_active' => true,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
                $firstId = $firstId ?: $id;
            }

            return $firstId;
        });

        $this->refresh();

        return DB::table(self::TABLE)->find($newId);
    }

    /** Create a manual exclusion and make it effective immediately. */
    public function add(string $label, ?string $pathGlob = null, int|string|null $userId = null, ?string $reason = null): ?object
    {
        $label = trim($label);
        if ($label === '') {
            throw new \InvalidArgumentException('An exclusion label is required.');
        }

        $path = $pathGlob === null ? null : trim($pathGlob, '/');
        if ($pathGlob !== null && $pathGlob !== '' && $path === '') {
            $path = '/';
        }

        $id = DB::table(self::TABLE)->insertGetId([
            'match_label' => $label,
            'path_glob' => $path,
            'created_by_user_id' => $userId,
            'reason' => $reason,
            'is_active' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->refresh();

        return DB::table(self::TABLE)->find($id);
    }

    public function drop(int $ruleId): bool
    {
        $removed = DB::table(self::TABLE)->where('id', $ruleId)->delete() > 0;

        if ($removed) {
            $this->refresh();
        }

        return $removed;
    }

    /**
     * @return Collection<int, \stdClass>
     */
    public function listing(): Collection
    {
        if (! $this->installed()) {
            return collect();
        }

        return DB::table(self::TABLE)->latest()->get();
    }

    public function refresh(): void
    {
        try {
            Cache::forget(self::CACHE_BUCKET);
        } catch (\Throwable $e) {
            CacheFailure::report($e);
        }
    }

    /**
     * @return Collection<int, \stdClass>
     */
    private function active(): Collection
    {
        // Cache plain arrays, never objects. Laravel's cache stores unserialize
        // with an `allowed_classes` restriction (cache.serializable_classes,
        // which defaults to false in Laravel 12+), so a cached Collection or
        // stdClass would come back as __PHP_Incomplete_Class and make this
        // method throw — silently disabling the WAF. Rebuild the objects on read.
        $load = function (): array {
            return $this->installed()
                ? DB::table(self::TABLE)->where('is_active', true)->get()
                    ->map(static fn (object $row): array => (array) $row)->all()
                : [];
        };

        try {
            $rows = Cache::remember(self::CACHE_BUCKET, now()->addMinutes(10), $load);
        } catch (\Throwable $e) {
            CacheFailure::report($e);
            try {
                $rows = $load();
            } catch (\Throwable $e) {
                CacheFailure::report($e);
                $rows = [];
            }
        }

        return collect($rows)->map(static fn (array $row): object => (object) $row);
    }

    private function installed(): bool
    {
        try {
            return Schema::hasTable(self::TABLE);
        } catch (\Throwable) {
            return false;
        }
    }
}
