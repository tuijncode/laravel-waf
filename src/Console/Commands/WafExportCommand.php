<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Export offending IPs from the findings table as an edge blocklist — feed the
 * WAF's detections to fail2ban, nginx, Apache or a spreadsheet.
 *
 * Data lines go to stdout (so the command can be redirected to a file);
 * progress and errors go to stderr, keeping the piped output clean.
 */
class WafExportCommand extends Command
{
    protected $signature = 'waf:export
        {--format=plain : Output format: plain|fail2ban|nginx|apache|csv}
        {--jail=laravel-waf : fail2ban jail to ban into (fail2ban format only)}
        {--min-level=error : Minimum severity to include (notice|warning|error|critical)}
        {--days=0 : Only findings from the last N days (0 = all time)}
        {--min-hits=1 : Minimum total hit count per IP}
        {--limit=0 : Cap the number of IPs exported (0 = no cap)}';

    protected $description = 'Export offending IPs as a blocklist (fail2ban/nginx/apache/csv)';

    private const RANKS = ['notice' => 1, 'warning' => 2, 'error' => 3, 'critical' => 4];

    private const FORMATS = ['plain', 'fail2ban', 'nginx', 'apache', 'csv'];

    public function handle(): int
    {
        $err = $this->output->getErrorStyle();

        $format = (string) $this->option('format');
        if (! in_array($format, self::FORMATS, true)) {
            $err->writeln("<error>Unknown format '{$format}' (allowed: ".implode(', ', self::FORMATS).').</error>');

            return self::INVALID;
        }

        // The fail2ban output is shell commands meant to be piped into a shell,
        // so the jail name (the only free-text value on those lines) is held to
        // characters that can't break out of the command.
        if ($format === 'fail2ban' && ! preg_match('/^[A-Za-z0-9._-]+$/', (string) $this->option('jail'))) {
            $err->writeln('<error>Jail names may only contain letters, digits, dots, hyphens and underscores.</error>');

            return self::INVALID;
        }

        $minLevel = (string) $this->option('min-level');
        if (! isset(self::RANKS[$minLevel])) {
            $err->writeln("<error>Unknown severity '{$minLevel}' (allowed: ".implode(', ', array_keys(self::RANKS)).').</error>');

            return self::INVALID;
        }

        $rows = $this->query($minLevel);

        if ($rows->isEmpty()) {
            $err->writeln('<comment>No matching IPs.</comment>');

            return self::SUCCESS;
        }

        $this->render($format, $rows);

        $err->writeln("<info>Exported {$rows->count()} IP(s).</info>");

        return self::SUCCESS;
    }

    /**
     * @return Collection<int, \stdClass>
     */
    private function query(string $minLevel)
    {
        $table = config('waf.table_name', 'waf_logs');
        $days = max(0, (int) $this->option('days'));
        $minHits = max(1, (int) $this->option('min-hits'));
        $limit = max(0, (int) $this->option('limit'));

        // Rank the stored severity string so the threshold can be applied with
        // a HAVING aggregate rather than pulling every row into PHP.
        $case = "CASE threat_level WHEN 'critical' THEN 4 WHEN 'error' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END";

        $query = DB::table($table)
            ->select(
                'ip_address',
                DB::raw('SUM(hit_count) as hits'),
                DB::raw("MAX({$case}) as lvl"),
                DB::raw('MAX(created_at) as last_seen'),
            )
            ->groupBy('ip_address')
            ->havingRaw("MAX({$case}) >= ?", [self::RANKS[$minLevel]])
            ->havingRaw('SUM(hit_count) >= ?', [$minHits])
            ->orderByRaw('SUM(hit_count) DESC');

        if ($days > 0) {
            $query->where('created_at', '>=', now()->subDays($days));
        }

        if ($limit > 0) {
            $query->limit($limit);
        }

        return $query->get();
    }

    /**
     * @param  Collection<int, \stdClass>  $rows
     */
    private function render(string $format, Collection $rows): void
    {
        $labels = array_flip(self::RANKS);
        $jail = (string) $this->option('jail');

        if ($format === 'csv') {
            $this->line('ip_address,hits,max_level,last_seen');
        }

        foreach ($rows as $row) {
            $ip = (string) $row->ip_address;
            $level = $labels[(int) $row->lvl] ?? 'notice';

            $this->line(match ($format) {
                'fail2ban' => "fail2ban-client set {$jail} banip {$ip}",
                'nginx' => "deny {$ip};",
                'apache' => "Require not ip {$ip}",
                'csv' => implode(',', [
                    $this->csvCell($ip),
                    (int) $row->hits,
                    $this->csvCell($level),
                    $this->csvCell((string) $row->last_seen),
                ]),
                default => $ip,
            });
        }
    }

    /**
     * Escape a CSV cell, including the leading =+-@ guard that stops a
     * spreadsheet from evaluating a value as a formula.
     */
    private function csvCell(string $value): string
    {
        if ($value !== '' && in_array($value[0], ['=', '+', '-', '@', "\t", "\r"], true)) {
            $value = "'".$value;
        }

        if (str_contains($value, ',') || str_contains($value, '"') || str_contains($value, "\n")) {
            $value = '"'.str_replace('"', '""', $value).'"';
        }

        return $value;
    }
}
