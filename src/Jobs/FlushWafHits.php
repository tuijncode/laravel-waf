<?php

namespace Tuijncode\LaravelWaf\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Support\CacheFailure;
use Tuijncode\LaravelWaf\Support\DedupCounter;
use Tuijncode\LaravelWaf\Support\MissingWafSchema;
use Tuijncode\LaravelWaf\Support\QuietLog;

/** Coalesce duplicate hits into one database update per short burst. */
class FlushWafHits implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public function __construct(private readonly string $seenKey, private readonly string $eventId) {}

    public int $tries = 0;

    public function handle(DedupCounter $counter): void
    {
        try {
            foreach ([
                'waf_hit_events' => ['id', 'event_id', 'created_at'],
                'waf_hit_totals' => ['event_id', 'hit_count', 'updated_at'],
            ] as $table => $columns) {
                if (Schema::hasTable($table) && ! Schema::hasColumns($table, $columns)) {
                    $this->fail(new MissingWafSchema("Queued WAF flush needs all columns in {$table}"));

                    return;
                }
            }

            if (! $counter->flush($this->seenKey, $this->eventId)) {
                $this->release(max(60, (int) config('waf.dedup_minutes', 5) * 60));
            }
        } catch (QueryException $e) {
            $table = config('waf.table_name', 'waf_logs');
            try {
                $missing = ! Schema::hasTable($table)
                    || ! Schema::hasColumns($table, ['event_id', 'hit_count', 'updated_at'])
                    || (Schema::hasTable('waf_hit_events')
                        && ! Schema::hasColumns('waf_hit_events', ['id', 'event_id', 'created_at']))
                    || (Schema::hasTable('waf_hit_totals')
                        && ! Schema::hasColumns('waf_hit_totals', ['event_id', 'hit_count', 'updated_at']));
            } catch (\Throwable) {
                $missing = false;
            }
            if ($missing) {
                $this->fail(new MissingWafSchema('Queued WAF flush needs complete log and hit tables', previous: $e));

                return;
            }

            throw $e;
        }
    }

    public function failed(?\Throwable $exception): void
    {
        if ($exception instanceof MissingWafSchema) {
            try {
                app(DedupCounter::class)->failed($this->seenKey, $this->eventId);
            } catch (\Throwable $e) {
                CacheFailure::report($e);
            }

            return;
        }

        $connection = config('waf.queue.connection') ?? config('queue.default');
        if (config("queue.connections.{$connection}.driver", $connection) === 'sync') {
            return;
        }

        try {
            if (app(DedupCounter::class)->flush($this->seenKey, $this->eventId)) {
                return;
            }
        } catch (\Throwable $e) {
            CacheFailure::report($e);
        }

        try {
            Bus::dispatch((new self($this->seenKey, $this->eventId))
                ->delay(now()->addMinutes(15))
                ->onConnection(config('waf.queue.connection'))
                ->onQueue(config('waf.queue.queue', 'default')));
        } catch (\Throwable $e) {
            try {
                app(DedupCounter::class)->recoverRejectedFlush($this->seenKey, $this->eventId);
            } catch (\Throwable $fallback) {
                CacheFailure::report($fallback);
            }
            QuietLog::write('error', 'laravel-waf: could not retry queued hit-count flush', ['error' => $e->getMessage()]);
        }
    }

    public function backoff(): array
    {
        return [5, 15, 60, 300, 900];
    }
}
