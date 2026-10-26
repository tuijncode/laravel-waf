<?php

namespace Tuijncode\LaravelWaf\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Read-side Eloquent model over the `waf_logs` table.
 *
 * Findings are written with the query builder (so they work with or without
 * this model, queued or inline), but this gives host applications a first-class
 * model for querying and reporting — and, via Prunable, retention through
 * Laravel's own `model:prune` scheduler.
 *
 * @property int $id
 * @property ?string $event_id
 * @property string $ip_address
 * @property string $type
 * @property string $category
 * @property int $confidence_score
 * @property string $action_taken
 * @property ?Carbon $created_at
 */
class WafLog extends Model
{
    use Prunable {
        pruneAll as private pruneModels;
    }

    protected $guarded = [];

    protected $casts = [
        'anomaly_score' => 'integer',
        'confidence_score' => 'integer',
    ];

    private ?Carbon $pruneHorizon = null;

    public function getTable(): string
    {
        return config('waf.table_name', 'waf_logs');
    }

    /**
     * Prune findings older than the configured retention horizon. Only takes
     * effect once retention is enabled; otherwise nothing is eligible.
     */
    public function prunable(): Builder
    {
        if (! config('waf.retention.enabled', false)) {
            // An always-false constraint: nothing is prunable.
            return static::query()->whereRaw('1 = 0');
        }

        $days = filter_var(config('waf.retention.days', 90), FILTER_VALIDATE_INT);
        if ($days === false || $days < 1) {
            return static::query()->whereRaw('1 = 0');
        }

        return static::query()->where('created_at', '<', $this->pruneHorizon ?? now()->subDays($days));
    }

    public function pruneAll(int $chunkSize = 1000): int
    {
        $days = filter_var(config('waf.retention.days', 90), FILTER_VALIDATE_INT);
        if (config('waf.retention.enabled', false) && $days !== false && $days > 0) {
            $this->pruneHorizon = now()->subDays($days)->startOfSecond();
            try {
                $this->advancePurgeWatermark($this->pruneHorizon);

                return $this->pruneModels($chunkSize);
            } finally {
                $this->pruneHorizon = null;
            }
        }

        return $this->pruneModels($chunkSize);
    }

    public function prune(): ?bool
    {
        $days = filter_var(config('waf.retention.days', 90), FILTER_VALIDATE_INT);
        if ($days === false || $days < 1) {
            throw new \InvalidArgumentException('waf.retention.days must be a positive integer before pruning WAF findings.');
        }

        DB::beginTransaction();
        try {
            $this->advancePurgeWatermark(now()->subDays($days)->startOfSecond());
            $table = $this->getTable();
            $current = DB::table('waf_purge_watermarks')->where('table_name', $table)
                ->lockForUpdate()->value('purged_before');
            $markEvent = $this->event_id !== null && ($current === null || $this->created_at === null
                || $this->created_at >= new \DateTimeImmutable($current));
            if ($markEvent) {
                DB::table('waf_purge_watermarks')->insertOrIgnore([
                    'table_name' => 'event:'.$this->event_id,
                    'purged_before' => now(),
                ]);
            }
            if ($this->event_id !== null) {
                foreach (['waf_hit_events', 'waf_hit_totals'] as $hitTable) {
                    if (Schema::hasTable($hitTable)) {
                        DB::table($hitTable)->where('event_id', $this->event_id)->delete();
                    }
                }
            }
            if (Schema::hasTable('waf_exclusion_rules')) {
                DB::table('waf_exclusion_rules')
                    ->where('source_log_id', $this->getKey())
                    ->update(['source_log_id' => null]);
            }

            $deleted = $this->delete();
            if ($deleted !== true) {
                DB::rollBack();

                return $deleted;
            }

            DB::commit();

            return true;
        } catch (\Throwable $e) {
            DB::rollBack();

            throw $e;
        }
    }

    private function advancePurgeWatermark(\DateTimeInterface $horizon): void
    {
        if (! Schema::hasTable('waf_purge_watermarks')
            || ! Schema::hasColumns('waf_purge_watermarks', ['table_name', 'purged_before'])) {
            throw new \RuntimeException('Run the waf-migrations-upgrade migrations before pruning WAF findings.');
        }

        $table = $this->getTable();
        $current = DB::table('waf_purge_watermarks')->where('table_name', $table)->value('purged_before');
        if ($current !== null && $horizon <= new \DateTimeImmutable($current)) {
            return;
        }

        DB::transaction(function () use ($table, $horizon): void {
            DB::table('waf_purge_watermarks')->insertOrIgnore([
                'table_name' => $table,
                'purged_before' => null,
            ]);
            $current = DB::table('waf_purge_watermarks')->where('table_name', $table)
                ->lockForUpdate()->value('purged_before');
            if ($current === null || $horizon > new \DateTimeImmutable($current)) {
                DB::table('waf_purge_watermarks')->where('table_name', $table)
                    ->update(['purged_before' => $horizon]);
            }
            $cutoff = $current === null || $horizon > new \DateTimeImmutable($current) ? $horizon : new \DateTimeImmutable($current);
            DB::table('waf_purge_watermarks')->where('table_name', 'like', 'event:%')
                ->where('purged_before', '<', $cutoff)
                ->where('purged_before', '<', now()->subMinutes(max(1, (int) config('waf.dedup_minutes', 5)) + 1))
                ->delete();
        });
    }
}
