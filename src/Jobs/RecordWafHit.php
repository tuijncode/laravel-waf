<?php

namespace Tuijncode\LaravelWaf\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Support\MissingWafSchema;

/** Durable, idempotent record of one deduplicated request. */
class RecordWafHit implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;

    public int $tries = 0;

    private ?string $findingCreatedAt = null;

    public function __construct(private readonly string $eventId, private readonly string $hitId, ?string $findingCreatedAt = null)
    {
        $this->findingCreatedAt = $findingCreatedAt ?? now()->toISOString();
    }

    public function handle(): void
    {
        try {
            DB::transaction(function (): void {
                $table = config('waf.table_name', 'waf_logs');
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
                    // Older serialized jobs lack the finding timestamp, but Laravel's queue envelope retains dispatch time.
                    $createdAt = $this->findingCreatedAt;
                    if ($createdAt === null && $this->job !== null) {
                        $queuedAt = $this->job->payload()['createdAt'] ?? null;
                        $createdAt = is_numeric($queuedAt) ? Carbon::createFromTimestampUTC((int) $queuedAt)->toISOString() : null;
                    }
                    if (($cutoff !== null && ($createdAt !== null
                        ? Carbon::parse($createdAt)->lessThan($cutoff)
                        : ! DB::table($table)->where('event_id', $this->eventId)->exists()))
                        || DB::table('waf_purge_watermarks')->where('table_name', 'event:'.$this->eventId)->exists()) {
                        return;
                    }
                }

                $inserted = DB::table('waf_hit_events')->insertOrIgnore([
                    'id' => $this->hitId,
                    'event_id' => $this->eventId,
                    'created_at' => now(),
                ]);

                DB::table('waf_hit_totals')->insertOrIgnore([
                    'event_id' => $this->eventId,
                    'hit_count' => 0,
                    'updated_at' => now(),
                ]);
                if ($inserted === 1) {
                    DB::table('waf_hit_totals')->where('event_id', $this->eventId)
                        ->increment('hit_count', 1, ['updated_at' => now()]);
                }

                $total = 1 + (int) DB::table('waf_hit_totals')->where('event_id', $this->eventId)->value('hit_count');
                DB::table($table)->where('event_id', $this->eventId)
                    ->where('hit_count', '<', $total)->update(['hit_count' => $total, 'updated_at' => now()]);
            });
        } catch (QueryException $e) {
            try {
                $table = config('waf.table_name', 'waf_logs');
                $missing = ! Schema::hasTable('waf_hit_events')
                    || ! Schema::hasColumns('waf_hit_events', ['id', 'event_id', 'created_at'])
                    || ! Schema::hasTable('waf_hit_totals')
                    || ! Schema::hasColumns('waf_hit_totals', ['event_id', 'hit_count', 'updated_at'])
                    || (Schema::hasTable('waf_purge_watermarks')
                        && ! Schema::hasColumns('waf_purge_watermarks', ['table_name', 'purged_before']))
                    || ! Schema::hasTable($table)
                    || ! Schema::hasColumns($table, ['event_id', 'hit_count', 'updated_at']);
            } catch (\Throwable) {
                $missing = false;
            }
            if ($missing) {
                $this->fail(new MissingWafSchema('Queued WAF hit counting needs its tables and required columns', previous: $e));

                return;
            }

            throw $e;
        }
    }

    public function backoff(): array
    {
        return [5, 15, 60, 300, 900];
    }
}
