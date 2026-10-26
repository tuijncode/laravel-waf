<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

class WafStatsCommand extends Command
{
    protected $signature = 'waf:stats {--days=7 : How many days back to summarise}';

    protected $description = 'Summarise recorded WAF findings';

    public function handle(): int
    {
        $days = filter_var($this->option('days'), FILTER_VALIDATE_INT);
        if ($days === false || $days < 1) {
            $this->error('--days must be a positive integer.');

            return self::INVALID;
        }
        $since = now()->subDays($days);
        $table = config('waf.table_name', 'waf_logs');

        $base = DB::table($table)->where('created_at', '>=', $since);
        $total = (clone $base)->count();

        $this->info("WAF findings in the last {$days} day(s): {$total}");

        if ($total === 0) {
            return self::SUCCESS;
        }

        $this->breakdown('By category', (clone $base)
            ->selectRaw('category as label, COUNT(*) as n')
            ->groupBy('category')->orderByDesc('n')->get());

        $this->breakdown('By severity', (clone $base)
            ->selectRaw('threat_level as label, COUNT(*) as n')
            ->groupBy('threat_level')->orderByDesc('n')->get());

        $this->breakdown('By action', (clone $base)
            ->selectRaw('action_taken as label, COUNT(*) as n')
            ->groupBy('action_taken')->orderByDesc('n')->get());

        $topIps = (clone $base)
            ->selectRaw('ip_address as label, COUNT(*) as n')
            ->groupBy('ip_address')->orderByDesc('n')->limit(10)->get();

        $this->newLine();
        $this->line('<comment>Top source IPs</comment>');
        $this->table(['IP', 'Findings'], $topIps->map(fn ($r) => [$r->label, $r->n])->all());

        return self::SUCCESS;
    }

    private function breakdown(string $title, Collection $rows): void
    {
        $this->newLine();
        $this->line("<comment>{$title}</comment>");
        $this->table(['', 'Count'], $rows->map(fn ($r) => [$r->label, $r->n])->all());
    }
}
