<?php

namespace Tuijncode\LaravelWaf\Support;

use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tuijncode\LaravelWaf\Jobs\FlushWafHits;
use Tuijncode\LaravelWaf\Jobs\RecordWafHit;

/** Counts duplicates while the first finding is still waiting for storage. */
class DedupCounter
{
    public function duplicate(string $seenKey): void
    {
        try {
            $flush = Cache::lock($seenKey.'|lock', 5)->block(0, function () use ($seenKey): ?string {
                [$eventId, $createdAt] = $this->seen($seenKey);
                if (! is_string($eventId) && ! is_int($eventId)) {
                    return null;
                }

                if ($this->asyncQueue() && is_string($eventId)) {
                    return $this->queueDuplicate($eventId, $createdAt);
                }

                $this->countDirect($eventId);

                return null;
            });
        } catch (LockTimeoutException) {
            [$eventId, $createdAt] = $this->seen($seenKey);
            if ($this->asyncQueue() && is_string($eventId)) {
                $flush = $this->queueDuplicate($eventId, $createdAt);
            } elseif (is_string($eventId) || is_int($eventId)) {
                $this->countDirect($eventId);

                return;
            } else {
                return;
            }
        }

        if ($flush !== null) {
            try {
                Bus::dispatch((new FlushWafHits($seenKey, $flush))
                    ->delay(now()->addSeconds(5))
                    ->onConnection(config('waf.queue.connection'))
                    ->onQueue(config('waf.queue.queue', 'default')));
            } catch (\Throwable) {
                $this->recoverRejectedFlush($seenKey, $flush);
            }
        }
    }

    public function stored(string $seenKey, string $eventId): bool
    {
        return Cache::lock($seenKey.'|lock', 5)->block(2, function () use ($eventId): bool {
            if (! $this->sync($eventId)) {
                throw new \RuntimeException('Queued WAF finding was not stored');
            }
            Cache::put($this->storedKey($eventId), true, now()->addMinutes(max(1, (int) config('waf.dedup_minutes', 5))));

            return $this->asyncQueue() && Cache::has($this->pendingKey($eventId))
                && Cache::add($this->flushKey($eventId), true, now()->addYears(10));
        });
    }

    public function flush(string $seenKey, string $eventId): bool
    {
        return Cache::lock($seenKey.'|lock', 5)->block(2, function () use ($seenKey, $eventId): bool {
            $stored = $this->sync($eventId);
            if ($stored && $this->seen($seenKey)[0] === $eventId) {
                return false;
            }

            if (! $stored) {
                $this->release($seenKey, $eventId);
            }
            Cache::forget($this->pendingKey($eventId));
            Cache::forget($this->storedKey($eventId));
            Cache::forget($this->flushKey($eventId));

            return true;
        });
    }

    public function failed(string $seenKey, string $eventId): void
    {
        $this->release($seenKey, $eventId);
        Cache::forget($this->pendingKey($eventId));
        Cache::forget($this->storedKey($eventId));
        Cache::forget($this->flushKey($eventId));
    }

    public function release(string $seenKey, string $eventId): void
    {
        if ($this->seen($seenKey)[0] === $eventId) {
            Cache::forget($seenKey);
        }
    }

    public function cancelFlush(string $eventId): void
    {
        Cache::forget($this->flushKey($eventId));
    }

    public function recoverRejectedFlush(string $seenKey, string $eventId): void
    {
        try {
            if (! $this->flush($seenKey, $eventId)) {
                $this->shortenPending($seenKey, $eventId);
            }
        } finally {
            $this->cancelFlush($eventId);
        }
    }

    private function shortenPending(string $seenKey, string $eventId): void
    {
        Cache::lock($seenKey.'|lock', 5)->block(2, function () use ($eventId): void {
            $key = $this->pendingKey($eventId);
            Cache::put($key, Cache::get($key, 0), now()->addMinutes(max(1, (int) config('waf.dedup_minutes', 5)) + 1));
        });
    }

    private function pendingKey(string $eventId): string
    {
        return 'laravel-waf|pending|'.$eventId;
    }

    private function queueDuplicate(string $eventId, ?string $createdAt): ?string
    {
        $key = $this->pendingKey($eventId);
        // Keep a cache fallback for a queue outage; the hit job survives a cache restart.
        Cache::add($key, 0, now()->addYears(10));
        Cache::increment($key);

        $createdAt ??= Cache::get('laravel-waf|created|'.$eventId);
        $hit = new RecordWafHit($eventId, (string) Str::uuid(), is_string($createdAt) ? $createdAt : null);
        try {
            Bus::dispatch($hit
                ->onConnection(config('waf.queue.connection'))
                ->onQueue(config('waf.queue.queue', 'default')));
        } catch (\Throwable $e) {
            QuietLog::write('warning', 'laravel-waf: could not queue durable hit', ['error' => $e->getMessage()]);
            try {
                $hit->handle();
            } catch (\Throwable $fallback) {
                QuietLog::write('warning', 'laravel-waf: could not store durable hit directly', ['error' => $fallback->getMessage()]);
            }
        }

        return Cache::has($this->storedKey($eventId))
            && Cache::add($this->flushKey($eventId), true, now()->addYears(10))
                ? $eventId : null;
    }

    private function sync(string $eventId): bool
    {
        return DB::transaction(function () use ($eventId): bool {
            try {
                // Wait for an in-flight hit job before reconciling a newly stored finding.
                $durable = DB::table('waf_hit_totals')->where('event_id', $eventId)
                    ->lockForUpdate()->value('hit_count');
            } catch (QueryException $e) {
                if (Schema::hasTable('waf_hit_totals')) {
                    throw $e;
                }
                $durable = null;
            }
            if ($durable === null) {
                try {
                    $durable = DB::table('waf_hit_events')->where('event_id', $eventId)->count();
                } catch (QueryException $e) {
                    if (Schema::hasTable('waf_hit_events')) {
                        throw $e;
                    }
                    $durable = 0;
                }
            }
            $total = 1 + max(
                (int) Cache::get($this->pendingKey($eventId), 0),
                $durable,
            );
            $table = config('waf.table_name', 'waf_logs');
            DB::table($table)->where('event_id', $eventId)->where('hit_count', '<', $total)
                ->update(['hit_count' => $total, 'updated_at' => now()]);

            return DB::table($table)->where('event_id', $eventId)->exists();
        });
    }

    private function countDirect(string|int $eventId): void
    {
        $column = is_int($eventId) ? 'id' : 'event_id';
        $updated = DB::table(config('waf.table_name', 'waf_logs'))
            ->where($column, $eventId)
            ->increment('hit_count', 1, ['updated_at' => now()]);

        if ($updated === 0 && is_string($eventId)) {
            $key = $this->pendingKey($eventId);
            Cache::add($key, 0, now()->addDays(2));
            Cache::increment($key);
        }
    }

    private function storedKey(string $eventId): string
    {
        return 'laravel-waf|stored|'.$eventId;
    }

    private function flushKey(string $eventId): string
    {
        return 'laravel-waf|flush|'.$eventId;
    }

    private function asyncQueue(): bool
    {
        $connection = config('waf.queue.connection') ?? config('queue.default');

        return config('waf.queue.enabled', false)
            && config("queue.connections.{$connection}.driver", $connection) !== 'sync';
    }

    /** @return array{string|int|null, ?string} */
    private function seen(string $seenKey): array
    {
        $value = Cache::get($seenKey);
        if (is_array($value)) {
            $eventId = $value['event_id'] ?? null;
            $createdAt = $value['created_at'] ?? null;

            return [is_string($eventId) ? $eventId : null, is_string($createdAt) ? $createdAt : null];
        }

        return [is_string($value) || is_int($value) ? $value : null, null];
    }
}
