<?php

use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

function record(array $overrides = []): void
{
    DB::table('waf_logs')->insert(array_merge([
        'ip_address' => '10.0.0.1',
        'method' => 'GET',
        'url' => 'http://localhost/login',
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

function recordAttempt(string $ip, string $rule, string $fingerprint, string $variant): void
{
    DB::table('waf_attempts')->insert([
        'ip_address' => $ip,
        'rule_id' => $rule,
        'fingerprint' => $fingerprint,
        'variant' => $variant,
        'window_id' => 1,
        'created_at' => now(),
    ]);
}

beforeEach(fn () => $this->analyzer = new CorrelationAnalyzer);

it('detects a coordinated attack: one URL, many IPs', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'] as $ip) {
        record(['ip_address' => $ip, 'url' => 'http://localhost/wp-login.php']);
    }
    record(['ip_address' => '9.9.9.9', 'url' => 'http://localhost/other']); // not coordinated

    $found = $this->analyzer->coordinatedAttacks(windowMinutes: 15, minIps: 3);

    expect($found)->toHaveCount(1)
        ->and($found[0]['url'])->toBe('http://localhost/wp-login.php')
        ->and((int) $found[0]['ips'])->toBe(4);
});

it('groups coordinated requests by target without their different query strings', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3'] as $index => $ip) {
        record(['ip_address' => $ip, 'url' => "http://localhost/login?user={$index}"]);
    }
    record(['ip_address' => '1.1.1.1', 'url' => 'http://localhost/login?user=extra']);
    record(['ip_address' => '4.4.4.4', 'url' => 'http://other.test/login?user=4']);

    $found = $this->analyzer->coordinatedAttacks();

    expect($found)->toHaveCount(1)
        ->and($found[0]['url'])->toBe('http://localhost/login')
        ->and($found[0]['ips'])->toBe(3)
        ->and($found[0]['hits'])->toBe(4);
});

it('keeps different redacted targets separate while grouping the same target', function () {
    foreach (['alpha', 'beta', 'gamma'] as $index => $path) {
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.($index + 1)])
            ->get('/'.$path.'?q=AKIAIOSFODNN7EXAMPLE')->assertOk();
    }

    expect($this->analyzer->coordinatedAttacks())->toBe([]);

    foreach ([4, 5] as $lastOctet) {
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.$lastOctet])
            ->get('/alpha?q=AKIAIOSFODNN7EXAMPLE')->assertOk();
    }

    $found = $this->analyzer->coordinatedAttacks();
    expect($found)->toHaveCount(1)
        ->and($found[0]['url'])->toBe('[REDACTED]')
        ->and((int) $found[0]['ips'])->toBe(3);
});

it('groups visible and redacted findings for the same target', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.1'])
        ->get('/login?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    foreach ([2, 3] as $lastOctet) {
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.$lastOctet])
            ->get('/login?q=AKIAIOSFODNN7EXAMPLE')->assertOk();
    }

    $found = $this->analyzer->coordinatedAttacks();
    expect($found)->toHaveCount(1)
        ->and($found[0]['url'])->toBe('http://localhost/login')
        ->and((int) $found[0]['ips'])->toBe(3);
});

it('omits legacy redacted logs without a target hash from coordinated groups', function () {
    foreach (['192.0.2.1', '192.0.2.2', '192.0.2.3'] as $ip) {
        record(['ip_address' => $ip, 'url' => '[REDACTED]']);
    }

    expect($this->analyzer->coordinatedAttacks())->toBe([]);
});

it('limits coordinated results after grouping many distinct targets', function () {
    for ($i = 0; $i < 150; $i++) {
        record(['ip_address' => '1.1.1.1', 'url' => "http://localhost/probe/{$i}?a=1"]);
        record(['ip_address' => '2.2.2.2', 'url' => "http://localhost/probe/{$i}?a=2"]);
    }

    $found = $this->analyzer->coordinatedAttacks(minIps: 2, limit: 5);

    expect($found)->toHaveCount(5)
        ->and($found[0]['url'])->toBe('http://localhost/probe/0')
        ->and($found[0]['ips'])->toBe(2);
});

it('detects a campaign: one category, many IPs', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'] as $ip) {
        record(['ip_address' => $ip, 'category' => 'xss', 'url' => "http://localhost/p/{$ip}"]);
    }

    $found = $this->analyzer->campaigns(windowHours: 24, minIps: 5);

    expect($found)->toHaveCount(1)
        ->and($found[0]['category'])->toBe('xss')
        ->and((int) $found[0]['ips'])->toBe(5);
});

it('detects a rapid attacker: one IP, many findings', function () {
    for ($i = 0; $i < 12; $i++) {
        record(['ip_address' => '6.6.6.6', 'type' => "[94210{$i}] probe {$i}"]);
    }
    record(['ip_address' => '7.7.7.7']); // below threshold

    $found = $this->analyzer->rapidAttackers(windowMinutes: 5, minHits: 10);

    expect($found)->toHaveCount(1)
        ->and($found[0]['ip_address'])->toBe('6.6.6.6')
        ->and((int) $found[0]['hits'])->toBe(12);
});

it('counts volume via hit_count, not just distinct rows', function () {
    // A single deduplicated finding that stands for 15 requests.
    record(['ip_address' => '6.6.6.6', 'hit_count' => 15]);

    $found = $this->analyzer->rapidAttackers(windowMinutes: 5, minHits: 10);

    expect($found)->toHaveCount(1)
        ->and((int) $found[0]['hits'])->toBe(15);
});

it('ignores activity outside the window', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3'] as $ip) {
        record(['ip_address' => $ip, 'created_at' => now()->subHours(2), 'updated_at' => now()->subHours(2)]);
    }

    expect($this->analyzer->coordinatedAttacks(windowMinutes: 15, minIps: 3))->toBe([]);
});

it('summarises the correlation signals', function () {
    foreach (['1.1.1.1', '2.2.2.2', '3.3.3.3'] as $ip) {
        record(['ip_address' => $ip, 'url' => 'http://localhost/target']);
    }

    expect($this->analyzer->summary())
        ->toHaveKeys(['coordinated_attacks', 'campaigns', 'rapid_attackers', 'mutation_chains', 'retry_bursts', 'shared_payloads'])
        ->and($this->analyzer->summary()['coordinated_attacks'])->toBe(1);
});

it('finds distinct payloads from one IP against one rule', function () {
    for ($n = 1; $n <= 5; $n++) {
        recordAttempt('10.0.0.1', '941100', sprintf('%016d', $n), sprintf('%016d', $n));
    }
    recordAttempt('10.0.0.2', '941100', 'aaaaaaaaaaaaaaaa', 'aaaaaaaaaaaaaaaa');

    $found = $this->analyzer->retryBursts();
    expect($found)->toHaveCount(1)
        ->and($found[0]['ip_address'])->toBe('10.0.0.1')
        ->and((int) $found[0]['payloads'])->toBe(5);

    $this->artisan('waf:correlate')->expectsOutputToContain('Different payloads')->assertSuccessful();
});

it('requires multiple payloads shared by the same IP group', function () {
    foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
        recordAttempt($ip, '941100', 'aaaaaaaaaaaaaaaa', '1111111111111111');
        recordAttempt($ip, '941100', 'bbbbbbbbbbbbbbbb', '2222222222222222');
    }

    $found = $this->analyzer->sharedPayloads();
    expect($found)->toHaveCount(1)
        ->and($found[0]['ips'])->toBe(3)
        ->and($found[0]['payloads'])->toBe(2);

    $this->artisan('waf:correlate')->expectsOutputToContain('Shared payloads')->assertSuccessful();

    recordAttempt('10.0.0.4', '941100', 'aaaaaaaaaaaaaaaa', '3333333333333333');
    expect($this->analyzer->sharedPayloads())->toBe([]);
});

it('does not count old IPs toward shared payloads in the current window', function () {
    foreach (['aaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbb'] as $fingerprint) {
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
            recordAttempt($ip, '941100', $fingerprint, $fingerprint);
        }
    }

    DB::table('waf_attempts')->whereIn('ip_address', ['10.0.0.2', '10.0.0.3'])
        ->update(['created_at' => now()->subHours(2)]);

    expect($this->analyzer->sharedPayloads(windowMinutes: 60))->toBe([]);
});

it('uses the default shared-payload budget with an older published config', function () {
    config()->set('waf.attempts.max_correlation_rows', null);
    foreach (['aaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbb'] as $fingerprint) {
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
            recordAttempt($ip, '941100', $fingerprint, $fingerprint);
        }
    }

    expect($this->analyzer->sharedPayloads())->toHaveCount(1);
});

it('finds a shared group beyond fifty higher-volume fingerprints', function () {
    for ($n = 1; $n <= 50; $n++) {
        foreach (range(1, 4) as $ip) {
            recordAttempt("10.0.1.{$ip}", '941100', sprintf('%016d', $n), sprintf('%016d', $n));
        }
    }
    foreach ([51, 52] as $n) {
        foreach (range(1, 3) as $ip) {
            recordAttempt("10.0.2.{$ip}", '941100', sprintf('%016d', $n), sprintf('%016d', $n));
        }
    }

    DB::connection()->enableQueryLog();
    DB::connection()->flushQueryLog();
    $groups = $this->analyzer->sharedPayloads();
    $queryCount = count(DB::connection()->getQueryLog());
    DB::connection()->disableQueryLog();
    expect($groups)->toHaveCount(2)
        ->and($groups[1]['ip_addresses'])->toBe(['10.0.2.1', '10.0.2.2', '10.0.2.3'])
        ->and($groups[1]['payloads'])->toBe(2)
        ->and($queryCount)->toBeLessThan(5);
});

it('reports an incomplete shared-payload analysis instead of returning partial results', function () {
    config()->set('waf.attempts.max_correlation_rows', 5);
    foreach ([51, 52] as $n) {
        foreach (range(1, 3) as $ip) {
            recordAttempt("10.0.2.{$ip}", '941100', sprintf('%016d', $n), sprintf('%016d', $n));
        }
    }

    $this->artisan('waf:correlate')
        ->expectsOutputToContain('Shared-payload correlation exceeds 5 rows')
        ->assertFailed();
});

it('checks the source row budget before grouping attempts', function () {
    config()->set('waf.attempts.max_correlation_rows', 5);
    for ($n = 1; $n <= 6; $n++) {
        recordAttempt('10.0.2.1', '941100', sprintf('%016d', $n), sprintf('%016d', $n));
    }

    $this->artisan('waf:correlate')
        ->expectsOutputToContain('Shared-payload correlation exceeds 5 rows')
        ->assertFailed();
});

it('ranks IPs by visible severity, persistence, diversity and mutation components', function () {
    record(['ip_address' => '10.0.0.1']);
    record(['ip_address' => '10.0.0.2', 'threat_level' => 'warning', 'hit_count' => 30]);
    record(['ip_address' => '10.0.0.3', 'threat_level' => 'error', 'hit_count' => 2]);
    record(['ip_address' => '10.0.0.3', 'threat_level' => 'error', 'hit_count' => 1, 'category' => 'xss']);
    record(['ip_address' => '10.0.0.4', 'action_taken' => 'excluded']);

    foreach (['aaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbb', 'cccccccccccccccc', 'dddddddddddddddd'] as $variant) {
        recordAttempt('10.0.0.3', '941100', '1111111111111111', $variant);
    }

    $ranked = $this->analyzer->rankActors();
    expect(array_column($ranked, 'ip_address'))->toBe(['10.0.0.3', '10.0.0.1', '10.0.0.2'])
        ->and($ranked[0]['score'])->toBe(array_sum($ranked[0]['components']))
        ->and($ranked[0]['components']['mutation'])->toBe(10);

    $this->artisan('waf:correlate --rank')->expectsOutputToContain('IP risk ranking')->assertSuccessful();
});

it('ranks every candidate before applying the result limit', function () {
    for ($i = 1; $i <= 5; $i++) {
        record(['ip_address' => "10.0.0.{$i}", 'threat_level' => 'critical']);
    }
    record(['ip_address' => '10.0.0.99', 'threat_level' => 'error', 'hit_count' => 100]);
    record(['ip_address' => '10.0.0.99', 'threat_level' => 'error', 'category' => 'xss']);
    foreach (['aaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbb', 'cccccccccccccccc', 'dddddddddddddddd'] as $variant) {
        recordAttempt('10.0.0.99', '941100', '1111111111111111', $variant);
    }

    expect($this->analyzer->rankActors(limit: 1)[0]['ip_address'])->toBe('10.0.0.99');
});

it('reports nothing via the command when there is no correlated activity', function () {
    $this->artisan('waf:correlate')
        ->expectsOutputToContain('No correlated attack activity detected.')
        ->assertSuccessful();
});

it('rejects invalid correlation windows', function () {
    foreach (['coordinated-window', 'campaign-hours', 'rapid-window', 'mutation-window'] as $option) {
        $this->artisan('waf:correlate', ["--{$option}" => 'invalid'])
            ->expectsOutputToContain("--{$option} must be a positive integer.")
            ->assertExitCode(2);
        $this->artisan('waf:correlate', ["--{$option}" => '-1'])->assertExitCode(2);
    }
});
