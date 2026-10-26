<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Support\PurgeFindings;

class PurgeWafLogsCommand extends Command
{
    protected $signature = 'waf:purge {--days=30 : Age threshold in days}';

    protected $description = 'Prune firewall findings older than the given age';

    public function handle(): int
    {
        $days = filter_var($this->option('days'), FILTER_VALIDATE_INT);
        if ($days === false || $days < 0) {
            $this->error('--days must be a non-negative whole number.');

            return self::FAILURE;
        }
        $horizon = now()->subDays($days);
        $table = config('waf.table_name', 'waf_logs');
        if (! Schema::hasTable('waf_purge_watermarks')
            || ! Schema::hasColumns('waf_purge_watermarks', ['table_name', 'purged_before'])) {
            $this->error('The waf_purge_watermarks table is missing. Run the waf-migrations-upgrade migrations first.');

            return self::FAILURE;
        }

        $attemptsTable = (string) config('waf.attempts.table', 'waf_attempts');
        $attemptDays = filter_var(config('waf.attempts.retention_days', 7), FILTER_VALIDATE_INT);
        $attemptHorizon = now()->subDays($attemptDays !== false && $attemptDays > 0 ? $attemptDays : 7);
        $attemptCount = Schema::hasTable($attemptsTable)
            ? DB::table($attemptsTable)->where('created_at', '<', $attemptHorizon)->count()
            : 0;
        $hitCount = Schema::hasTable('waf_hit_events')
            ? DB::table('waf_hit_events')->where('created_at', '<', $horizon)->count()
            : 0;
        $hitTotalCount = Schema::hasTable('waf_hit_totals')
            ? DB::table('waf_hit_totals')->where('updated_at', '<', $horizon)->count()
            : 0;

        $total = DB::table($table)->where('created_at', '<', $horizon)->count();

        if ($total === 0 && $attemptCount === 0 && $hitCount === 0 && $hitTotalCount === 0) {
            PurgeFindings::before($table, $horizon);
            $this->line("Nothing to prune — no findings predate {$days} day(s) ago.");

            return self::SUCCESS;
        }

        $question = "Prune {$total} finding(s) older than {$days} day(s)"
            .($attemptCount > 0 ? " and {$attemptCount} old attempt variant(s)" : '')
            .($hitCount > 0 ? " and {$hitCount} old hit record(s)" : '')
            .($hitTotalCount > 0 ? " and {$hitTotalCount} old hit total(s)" : '').'?';
        $confirmed = ! $this->input->isInteractive() || $this->confirm($question);

        if (! $confirmed) {
            $this->line('Aborted.');

            return self::SUCCESS;
        }

        if ($attemptCount > 0) {
            $removed = DB::table($attemptsTable)->where('created_at', '<', $attemptHorizon)->delete();
            $this->line("Pruned {$removed} old attempt variant(s).");
        }

        $removed = PurgeFindings::before($table, $horizon);
        if ($removed['unlinked'] > 0) {
            $this->line("Kept {$removed['unlinked']} exclusion rule(s) after unlinking pruned findings.");
        }
        if ($hitCount > 0 || $removed['hits'] > 0) {
            $this->line("Pruned {$removed['hits']} old hit record(s).");
        }
        if ($hitTotalCount > 0 || $removed['totals'] > 0) {
            $this->line("Pruned {$removed['totals']} old hit total(s).");
        }
        if ($total > 0 || $removed['findings'] > 0) {
            $this->info("Pruned {$removed['findings']} finding(s).");
        }

        return self::SUCCESS;
    }
}
