<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Database\Query\JoinClause;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Reads the `waf_logs` table to surface attacks that only reveal themselves in
 * aggregate: the same target hit from many IPs, a single attack class spreading
 * across the fleet, or one IP hammering many endpoints at once.
 */
class CorrelationAnalyzer
{
    private function table(): string
    {
        return config('waf.table_name', 'waf_logs');
    }

    /**
     * Hosts and paths targeted by several distinct IPs inside a short window,
     * regardless of query-string variations.
     *
     * @return array<int, array{url:string, ips:int, hits:int, first_seen:?string, last_seen:?string}>
     */
    public function coordinatedAttacks(int $windowMinutes = 15, int $minIps = 3, int $limit = 20): array
    {
        if ($limit <= 0) {
            return [];
        }

        $target = match (DB::connection()->getDriverName()) {
            'sqlite' => "CASE WHEN instr(url, '?') = 0 THEN url ELSE substr(url, 1, instr(url, '?') - 1) END",
            'mysql', 'mariadb' => "SUBSTRING_INDEX(url, '?', 1)",
            'pgsql' => "split_part(url, '?', 1)",
            'sqlsrv' => "LEFT(url, CHARINDEX('?', url + '?') - 1)",
            default => throw new \RuntimeException('Unsupported database driver for WAF correlation'),
        };
        $group = "COALESCE(target_hash, {$target})";
        $display = "COALESCE(MIN(CASE WHEN url = '[REDACTED]' THEN NULL ELSE {$target} END), '[REDACTED]')";

        return DB::table($this->table())
            ->where('created_at', '>=', now()->subMinutes($windowMinutes))
            ->where(function ($query): void {
                $query->whereNotNull('target_hash')->orWhere('url', '!=', '[REDACTED]');
            })
            ->selectRaw("{$display} as url, COUNT(DISTINCT ip_address) as ips, SUM(hit_count) as hits, MIN(created_at) as first_seen, MAX(created_at) as last_seen")
            ->groupByRaw($group)
            ->havingRaw('COUNT(DISTINCT ip_address) >= ?', [$minIps])
            ->orderByDesc('ips')
            ->orderByDesc('hits')
            ->orderBy('url')
            ->limit($limit)
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /**
     * Attack classes (categories) mounted by many distinct IPs over a longer
     * horizon — a campaign rather than a one-off probe.
     *
     * @return array<int, array{category:string, ips:int, hits:int, first_seen:?string, last_seen:?string}>
     */
    public function campaigns(int $windowHours = 24, int $minIps = 5, int $limit = 20): array
    {
        return DB::table($this->table())
            ->where('created_at', '>=', now()->subHours($windowHours))
            ->select(
                'category',
                DB::raw('COUNT(DISTINCT ip_address) as ips'),
                DB::raw('SUM(hit_count) as hits'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen'),
            )
            ->groupBy('category')
            ->havingRaw('COUNT(DISTINCT ip_address) >= ?', [$minIps])
            ->orderByDesc('ips')
            ->limit($limit)
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /**
     * Single IPs generating a burst of findings across (potentially) many
     * distinct attack types in a short window.
     *
     * @return array<int, array{ip_address:string, hits:int, types:int, first_seen:?string, last_seen:?string}>
     */
    public function rapidAttackers(int $windowMinutes = 5, int $minHits = 10, int $limit = 20): array
    {
        return DB::table($this->table())
            ->where('created_at', '>=', now()->subMinutes($windowMinutes))
            ->select(
                'ip_address',
                // SUM(hit_count), not COUNT(*): the dedup window collapses a
                // burst of the same attack into one row, so counting rows would
                // miss exactly the volumetric hammering this is meant to catch.
                DB::raw('SUM(hit_count) as hits'),
                DB::raw('COUNT(DISTINCT type) as types'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen'),
            )
            ->groupBy('ip_address')
            ->havingRaw('SUM(hit_count) >= ?', [$minHits])
            ->orderByDesc('hits')
            ->limit($limit)
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /** Distinct raw forms of one matched attack from the same IP. */
    public function mutationChains(int $windowMinutes = 60, int $minVariants = 3, int $limit = 20): array
    {
        $table = (string) config('waf.attempts.table', 'waf_attempts');
        if (! Schema::hasTable($table)) {
            return [];
        }

        return DB::table($table)
            ->where('created_at', '>=', now()->subMinutes(max(1, $windowMinutes)))
            ->select('ip_address', 'rule_id', 'fingerprint',
                DB::raw('COUNT(DISTINCT variant) as variants'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen'))
            ->groupBy('ip_address', 'rule_id', 'fingerprint')
            ->havingRaw('COUNT(DISTINCT variant) >= ?', [max(2, $minVariants)])
            ->orderByDesc('variants')
            ->limit(max(1, $limit))
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /** Different normalised payloads aimed at the same rule by one IP. */
    public function retryBursts(int $windowMinutes = 60, int $minPayloads = 5, int $limit = 20): array
    {
        $table = (string) config('waf.attempts.table', 'waf_attempts');
        if (! Schema::hasTable($table)) {
            return [];
        }

        return DB::table($table)
            ->where('created_at', '>=', now()->subMinutes(max(1, $windowMinutes)))
            ->select('ip_address', 'rule_id',
                DB::raw('COUNT(DISTINCT fingerprint) as payloads'),
                DB::raw('MIN(created_at) as first_seen'),
                DB::raw('MAX(created_at) as last_seen'))
            ->groupBy('ip_address', 'rule_id')
            ->havingRaw('COUNT(DISTINCT fingerprint) >= ?', [max(2, $minPayloads)])
            ->orderByDesc('payloads')
            ->limit(max(1, $limit))
            ->get()
            ->map(fn ($row): array => (array) $row)
            ->all();
    }

    /** Payloads shared by the same group of IPs, requiring multiple fingerprints. */
    public function sharedPayloads(int $windowMinutes = 60, int $minIps = 3, int $minPayloads = 2, int $limit = 20): array
    {
        $table = (string) config('waf.attempts.table', 'waf_attempts');
        if (! Schema::hasTable($table)) {
            return [];
        }

        $since = now()->subMinutes(max(1, $windowMinutes));
        $maxRows = min(100000, max(1, (int) (config('waf.attempts.max_correlation_rows') ?? 10000)));
        $sample = DB::table($table)->where('created_at', '>=', $since)
            ->select('id')->limit($maxRows + 1);
        if (DB::query()->fromSub($sample, 'recent_attempts')->count() > $maxRows) {
            throw new \RuntimeException("Shared-payload correlation exceeds {$maxRows} rows in the selected window; raise waf.attempts.max_correlation_rows or narrow the window.");
        }

        $eligible = DB::table($table)
            ->where('created_at', '>=', $since)
            ->select('rule_id', 'fingerprint')
            ->groupBy('rule_id', 'fingerprint')
            ->havingRaw('COUNT(DISTINCT ip_address) >= ?', [max(2, $minIps)]);
        $members = DB::table($table.' as attempts')
            ->joinSub($eligible, 'eligible', fn (JoinClause $join) => $join
                ->on('eligible.rule_id', '=', 'attempts.rule_id')
                ->on('eligible.fingerprint', '=', 'attempts.fingerprint'))
            ->where('attempts.created_at', '>=', $since)
            ->select('attempts.rule_id', 'attempts.fingerprint', 'attempts.ip_address')
            ->distinct()
            ->orderBy('attempts.rule_id')
            ->orderBy('attempts.fingerprint')
            ->orderBy('attempts.ip_address')
            ->limit($maxRows + 1)
            ->cursor();

        $groups = [];
        $addGroup = static function (string $rule, string $fingerprint, array $ips) use (&$groups): void {
            $key = hash('sha256', implode('|', $ips));
            $groups[$key] ??= ['ip_addresses' => $ips, 'rule_ids' => [], 'fingerprints' => []];
            $groups[$key]['rule_ids'][] = $rule;
            $groups[$key]['fingerprints'][] = $fingerprint;
        };
        $rule = $fingerprint = null;
        $ips = [];
        $seen = 0;
        foreach ($members as $row) {
            if (++$seen > $maxRows) {
                throw new \RuntimeException("Shared-payload correlation exceeds {$maxRows} rows; raise waf.attempts.max_correlation_rows or narrow the window.");
            }
            if ($rule !== null && ($row->rule_id !== $rule || $row->fingerprint !== $fingerprint)) {
                $addGroup($rule, $fingerprint, $ips);
                $ips = [];
            }
            $rule = $row->rule_id;
            $fingerprint = $row->fingerprint;
            $ips[] = $row->ip_address;
        }
        if ($rule !== null) {
            $addGroup($rule, $fingerprint, $ips);
        }

        $result = [];
        foreach ($groups as $group) {
            $payloads = count(array_unique($group['fingerprints']));
            if ($payloads >= max(2, $minPayloads)) {
                $result[] = [
                    'ip_addresses' => $group['ip_addresses'],
                    'ips' => count($group['ip_addresses']),
                    'payloads' => $payloads,
                    'rule_ids' => array_values(array_unique($group['rule_ids'])),
                ];
            }
        }

        usort($result, fn (array $a, array $b): int => $b['payloads'] <=> $a['payloads']);

        return array_slice($result, 0, max(1, $limit));
    }

    /** Read-only triage ranking. Components sum to the reported score. */
    public function rankActors(int $windowMinutes = 60, int $limit = 10): array
    {
        $limit = min(50, max(1, $limit));
        $since = now()->subMinutes(max(1, $windowMinutes));
        $severity = "CASE findings.threat_level WHEN 'critical' THEN 4 WHEN 'error' THEN 3 WHEN 'warning' THEN 2 ELSE 1 END";
        $rows = DB::table($this->table().' as findings')
            ->where('findings.created_at', '>=', $since)
            ->where('findings.action_taken', '!=', 'excluded')
            ->select('findings.ip_address', DB::raw('SUM(findings.hit_count) as hits'),
                DB::raw('COUNT(DISTINCT findings.category) as categories'),
                DB::raw("MAX({$severity}) as peak_rank"))
            ->groupBy('findings.ip_address');

        $attemptTable = (string) config('waf.attempts.table', 'waf_attempts');
        if (Schema::hasTable($attemptTable)) {
            $variants = DB::table($attemptTable)
                ->where('created_at', '>=', $since)
                ->select('ip_address')
                ->selectRaw('COUNT(DISTINCT variant) as variants')
                ->groupBy('ip_address', 'rule_id', 'fingerprint');
            $peaks = DB::query()->fromSub($variants, 'variant_groups')
                ->select('ip_address')
                ->selectRaw('MAX(variants) as peak_variants')
                ->groupBy('ip_address');
            $rows->leftJoinSub($peaks, 'attempt_peaks', 'attempt_peaks.ip_address', '=', 'findings.ip_address')
                ->selectRaw('MAX(attempt_peaks.peak_variants) as peak_variants');
        } else {
            $rows->selectRaw('0 as peak_variants');
        }

        $ranked = [];
        foreach ($rows->cursor() as $row) {
            $peakVariants = (int) $row->peak_variants;

            $components = [
                'severity' => [1 => 5, 2 => 10, 3 => 25, 4 => 40][(int) $row->peak_rank] ?? 0,
                'persistence' => min(20, (int) floor(log(1 + (int) $row->hits, 2) * 5)),
                'diversity' => min(20, max(0, (int) $row->categories - 1) * 5),
                'mutation' => $peakVariants >= 3 ? min(20, ($peakVariants - 2) * 5) : 0,
            ];

            $ranked[] = [
                'ip_address' => $row->ip_address,
                'score' => array_sum($components),
                'hits' => (int) $row->hits,
                'categories' => (int) $row->categories,
                'peak_variants' => $peakVariants,
                'components' => $components,
            ];

            usort($ranked, fn (array $a, array $b): int => ($b['score'] <=> $a['score'])
                ?: ($b['hits'] <=> $a['hits']) ?: strcmp($a['ip_address'], $b['ip_address']));
            if (count($ranked) > $limit) {
                array_pop($ranked);
            }
        }

        return $ranked;
    }

    /**
     * A one-line count of each correlation signal, for dashboards / cron.
     *
     * @return array{coordinated_attacks:int, campaigns:int, rapid_attackers:int, mutation_chains:int, retry_bursts:int, shared_payloads:int}
     */
    public function summary(): array
    {
        return [
            'coordinated_attacks' => count($this->coordinatedAttacks()),
            'campaigns' => count($this->campaigns()),
            'rapid_attackers' => count($this->rapidAttackers()),
            'mutation_chains' => count($this->mutationChains()),
            'retry_bursts' => count($this->retryBursts()),
            'shared_payloads' => count($this->sharedPayloads()),
        ];
    }
}
