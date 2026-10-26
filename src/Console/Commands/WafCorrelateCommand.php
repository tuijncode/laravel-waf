<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

class WafCorrelateCommand extends Command
{
    protected $signature = 'waf:correlate
                            {--coordinated-window=15 : Minutes for coordinated-attack detection}
                            {--campaign-hours=24 : Hours for campaign detection}
                            {--rapid-window=5 : Minutes for rapid-attacker detection}
                            {--mutation-window=60 : Minutes for attempt comparison}
                            {--rank : Show a read-only risk ranking of IP addresses}';

    protected $description = 'Correlate WAF findings to surface distributed / coordinated attacks';

    public function handle(CorrelationAnalyzer $analyzer): int
    {
        foreach (['coordinated-window', 'campaign-hours', 'rapid-window', 'mutation-window'] as $option) {
            $value = filter_var($this->option($option), FILTER_VALIDATE_INT);
            if ($value === false || $value < 1) {
                $this->error("--{$option} must be a positive integer.");

                return self::INVALID;
            }
        }

        $coordinated = $analyzer->coordinatedAttacks((int) $this->option('coordinated-window'));
        $campaigns = $analyzer->campaigns((int) $this->option('campaign-hours'));
        $rapid = $analyzer->rapidAttackers((int) $this->option('rapid-window'));
        $attemptWindow = (int) $this->option('mutation-window');
        $mutations = $analyzer->mutationChains($attemptWindow);
        $retries = $analyzer->retryBursts($attemptWindow);
        try {
            $shared = $analyzer->sharedPayloads($attemptWindow);
        } catch (\RuntimeException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }
        $ranked = $this->option('rank') ? $analyzer->rankActors($attemptWindow) : [];

        if (! $coordinated && ! $campaigns && ! $rapid && ! $mutations && ! $retries && ! $shared && ! $ranked) {
            $this->info('No correlated attack activity detected.');

            return self::SUCCESS;
        }

        if ($coordinated) {
            $this->line('<comment>Coordinated attacks (one target, many IPs)</comment>');
            $this->table(['URL', 'IPs', 'Hits', 'First', 'Last'], array_map(fn (array $r) => [
                $r['url'], $r['ips'], $r['hits'], $r['first_seen'], $r['last_seen'],
            ], $coordinated));
        }

        if ($campaigns) {
            $this->newLine();
            $this->line('<comment>Campaigns (one attack class, many IPs)</comment>');
            $this->table(['Category', 'IPs', 'Hits', 'First', 'Last'], array_map(fn (array $r) => [
                $r['category'], $r['ips'], $r['hits'], $r['first_seen'], $r['last_seen'],
            ], $campaigns));
        }

        if ($rapid) {
            $this->newLine();
            $this->line('<comment>Rapid attackers (one IP, many findings)</comment>');
            $this->table(['IP', 'Hits', 'Types', 'First', 'Last'], array_map(fn (array $r) => [
                $r['ip_address'], $r['hits'], $r['types'], $r['first_seen'], $r['last_seen'],
            ], $rapid));
        }

        if ($mutations) {
            $this->newLine();
            $this->line('<comment>Attack variants (one matched attack, changing raw requests)</comment>');
            $this->table(['IP', 'Rule', 'Variants', 'First', 'Last'], array_map(fn (array $r) => [
                $r['ip_address'], $r['rule_id'], $r['variants'], $r['first_seen'], $r['last_seen'],
            ], $mutations));
        }

        if ($retries) {
            $this->newLine();
            $this->line('<comment>Different payloads (one IP, one rule)</comment>');
            $this->table(['IP', 'Rule', 'Payloads', 'First', 'Last'], array_map(fn (array $r) => [
                $r['ip_address'], $r['rule_id'], $r['payloads'], $r['first_seen'], $r['last_seen'],
            ], $retries));
        }

        if ($shared) {
            $this->newLine();
            $this->line('<comment>Shared payloads across IPs</comment>');
            $this->table(['IPs', 'Payloads', 'Addresses', 'Rules'], array_map(fn (array $r) => [
                $r['ips'], $r['payloads'], implode(', ', array_slice($r['ip_addresses'], 0, 5)), implode(', ', $r['rule_ids']),
            ], $shared));
        }

        if ($ranked) {
            $this->newLine();
            $this->line('<comment>IP risk ranking (triage only)</comment>');
            $this->table(['IP', 'Score', 'Severity', 'Persistence', 'Diversity', 'Mutation'], array_map(fn (array $r) => [
                $r['ip_address'], $r['score'], $r['components']['severity'], $r['components']['persistence'],
                $r['components']['diversity'], $r['components']['mutation'],
            ], $ranked));
        }

        return self::SUCCESS;
    }
}
