<?php

namespace Tuijncode\LaravelWaf\Support;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/** Set-based finding retention shared by the command and model scheduler. */
class PurgeFindings
{
    /** @return array{hits:int, totals:int, findings:int, unlinked:int} */
    public static function before(string $table, \DateTimeInterface $horizon): array
    {
        return DB::transaction(function () use ($table, $horizon): array {
            DB::table('waf_purge_watermarks')->insertOrIgnore([
                'table_name' => $table,
                'purged_before' => null,
            ]);
            $watermark = DB::table('waf_purge_watermarks')->where('table_name', $table)
                ->lockForUpdate()->value('purged_before');
            $oldFindings = fn () => DB::table($table)->select('event_id')->where('created_at', '<', $horizon);
            $hits = Schema::hasTable('waf_hit_events')
                ? DB::table('waf_hit_events')->where(fn ($query) => $query
                    ->where('created_at', '<', $horizon)
                    ->orWhereIn('event_id', $oldFindings()))->delete()
                : 0;
            $totals = Schema::hasTable('waf_hit_totals')
                ? DB::table('waf_hit_totals')->where(fn ($query) => $query
                    ->where('updated_at', '<', $horizon)
                    ->orWhereIn('event_id', $oldFindings()))->delete()
                : 0;
            $unlinked = Schema::hasTable('waf_exclusion_rules')
                ? DB::table('waf_exclusion_rules')
                    ->whereIn('source_log_id', fn ($query) => $query->select('id')->from($table)
                        ->where('created_at', '<', $horizon))
                    ->update(['source_log_id' => null])
                : 0;
            $findings = DB::table($table)->where('created_at', '<', $horizon)->delete();
            if ($watermark === null || $horizon > new \DateTimeImmutable($watermark)) {
                DB::table('waf_purge_watermarks')->where('table_name', $table)
                    ->update(['purged_before' => $horizon]);
            }
            $cutoff = $watermark === null || $horizon > new \DateTimeImmutable($watermark) ? $horizon : new \DateTimeImmutable($watermark);
            DB::table('waf_purge_watermarks')->where('table_name', 'like', 'event:%')
                ->where('purged_before', '<', $cutoff)
                ->where('purged_before', '<', now()->subMinutes(max(1, (int) config('waf.dedup_minutes', 5)) + 1))
                ->delete();

            return ['hits' => $hits, 'totals' => $totals, 'findings' => $findings, 'unlinked' => $unlinked];
        });
    }
}
