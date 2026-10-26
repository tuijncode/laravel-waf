<?php

namespace Tuijncode\LaravelWaf\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Support\CacheFailure;
use Tuijncode\LaravelWaf\Support\DedupCounter;
use Tuijncode\LaravelWaf\Support\MissingWafSchema;
use Tuijncode\LaravelWaf\Support\QuietLog;

/**
 * Writes a single firewall finding to storage away from the request path.
 *
 * Dispatched only when queueing is switched on, so a slow database never bleeds
 * into response times on a route that is under attack.
 */
class StoreWafLog implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    public int $tries = 0;

    /**
     * @param  array<string, mixed>  $row
     */
    public function __construct(private readonly array $row, private readonly ?string $dedupKey = null) {}

    public function handle(): void
    {
        $table = config('waf.table_name', 'waf_logs');
        try {
            $inserted = $this->store(false);
        } catch (QueryException $e) {
            $missing = false;
            try {
                $missing = ! Schema::hasTable($table) || ! Schema::hasColumns($table, array_keys($this->row))
                    || (Schema::hasTable('waf_purge_watermarks')
                        && ! Schema::hasColumns('waf_purge_watermarks', ['table_name', 'purged_before']));
            } catch (\Throwable) {
                // A database outage can also prevent schema inspection; keep retrying it.
            }
            if ($missing) {
                $this->fail(new MissingWafSchema('Queued WAF finding table is missing required columns', previous: $e));

                return;
            }

            throw $e;
        }
        if ($inserted === null) {
            if ($this->dedupKey !== null) {
                try {
                    app(DedupCounter::class)->failed($this->dedupKey, $this->row['event_id']);
                } catch (\Throwable $e) {
                    CacheFailure::report($e);
                }
            }

            return;
        }
        if ($inserted === 0 && ! DB::table($table)->where('event_id', $this->row['event_id'])->exists()) {
            throw new \RuntimeException('Queued WAF finding was not stored');
        }

        if ($this->dedupKey !== null) {
            try {
                $flush = app(DedupCounter::class)->stored($this->dedupKey, $this->row['event_id']);
            } catch (\Throwable $e) {
                QuietLog::write('warning', 'laravel-waf: queued counter update deferred', ['error' => $e->getMessage()]);
                $flush = true;
            }

            if ($flush) {
                try {
                    Bus::dispatch((new FlushWafHits($this->dedupKey, $this->row['event_id']))
                        ->delay(now()->addSeconds(5))
                        ->onConnection(config('waf.queue.connection'))
                        ->onQueue(config('waf.queue.queue', 'default')));
                } catch (\Throwable) {
                    app(DedupCounter::class)->recoverRejectedFlush($this->dedupKey, $this->row['event_id']);
                }
            }
        }
    }

    /** Apply the same purge guard to a synchronous finding write. */
    public function storeInline(): ?int
    {
        return $this->store(true);
    }

    private function store(bool $inline): ?int
    {
        $table = config('waf.table_name', 'waf_logs');

        return DB::transaction(function () use ($table, $inline): ?int {
            if (Schema::hasTable('waf_purge_watermarks')) {
                $marker = DB::table('waf_purge_watermarks')->where('table_name', $table)
                    ->sharedLock()->first(['purged_before']);
                if ($marker === null) {
                    DB::table('waf_purge_watermarks')->insertOrIgnore([
                        'table_name' => $table,
                        'purged_before' => null,
                    ]);
                    $marker = DB::table('waf_purge_watermarks')->where('table_name', $table)
                        ->sharedLock()->first(['purged_before']);
                }
                $cutoff = $marker->purged_before;
                if ($cutoff !== null && Carbon::parse($this->row['created_at'])->lessThan($cutoff)) {
                    foreach (['waf_hit_events', 'waf_hit_totals'] as $hitTable) {
                        if (Schema::hasTable($hitTable)) {
                            DB::table($hitTable)->where('event_id', $this->row['event_id'])->delete();
                        }
                    }

                    return null;
                }
                if (DB::table('waf_purge_watermarks')->where('table_name', 'event:'.$this->row['event_id'])->exists()) {
                    return null;
                }
            }

            return $inline
                ? (int) DB::table($table)->insertGetId($this->row)
                : DB::table($table)->insertOrIgnore($this->row);
        });
    }

    public function failed(?\Throwable $exception): void
    {
        if ($exception instanceof MissingWafSchema) {
            if ($this->dedupKey !== null) {
                try {
                    app(DedupCounter::class)->failed($this->dedupKey, $this->row['event_id']);
                } catch (\Throwable $e) {
                    CacheFailure::report($e);
                }
            }

            return;
        }

        $connection = config('waf.queue.connection') ?? config('queue.default');
        if (config("queue.connections.{$connection}.driver", $connection) === 'sync') {
            return;
        }

        try {
            Bus::dispatch((new self($this->row, $this->dedupKey))
                ->delay(now()->addMinutes(15))
                ->onConnection(config('waf.queue.connection'))
                ->onQueue(config('waf.queue.queue', 'default')));
        } catch (\Throwable $e) {
            QuietLog::write('error', 'laravel-waf: could not retry queued finding', ['error' => $e->getMessage()]);
        }
    }

    public function backoff(): array
    {
        return [5, 15, 60, 300, 900];
    }
}
