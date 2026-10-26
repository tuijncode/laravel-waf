<?php

use Illuminate\Support\Facades\DB;

function seedFinding(array $overrides = []): void
{
    DB::table('waf_logs')->insert(array_merge([
        'ip_address' => '10.0.0.1',
        'method' => 'GET',
        'url' => 'http://localhost/',
        'type' => '[942100] SQLi',
        'category' => 'sqli',
        'threat_level' => 'critical',
        'confidence_score' => 60,
        'confidence_label' => 'high',
        'action_taken' => 'logged',
        'created_at' => now(),
        'updated_at' => now(),
    ], $overrides));
}

it('reports there is nothing to summarise when empty', function () {
    $this->artisan('waf:stats')
        ->expectsOutputToContain('WAF findings in the last 7 day(s): 0')
        ->assertSuccessful();
});

it('summarises recent findings', function () {
    seedFinding(['category' => 'sqli', 'ip_address' => '1.1.1.1']);
    seedFinding(['category' => 'xss', 'ip_address' => '1.1.1.1']);
    seedFinding(['category' => 'xss', 'ip_address' => '2.2.2.2']);

    $this->artisan('waf:stats --days=30')
        ->expectsOutputToContain('WAF findings in the last 30 day(s): 3')
        ->assertSuccessful();
});

it('ignores findings outside the window', function () {
    seedFinding(['created_at' => now()->subDays(40), 'updated_at' => now()->subDays(40)]);

    $this->artisan('waf:stats --days=7')
        ->expectsOutputToContain('WAF findings in the last 7 day(s): 0')
        ->assertSuccessful();
});

it('rejects invalid day windows', function () {
    foreach (['abc', '0', '-1'] as $days) {
        $this->artisan('waf:stats', ['--days' => $days])
            ->expectsOutputToContain('--days must be a positive integer.')
            ->assertExitCode(2);
    }
});
