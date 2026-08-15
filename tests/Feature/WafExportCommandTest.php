<?php

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

function seedExportFinding(string $ip, string $level, int $hits = 1, ?string $createdAt = null): void
{
    DB::table('waf_logs')->insert([
        'ip_address' => $ip,
        'url' => '/',
        'type' => '[942100] test',
        'category' => 'sqli',
        'threat_level' => $level,
        'hit_count' => $hits,
        'created_at' => $createdAt ?? now(),
        'updated_at' => now(),
    ]);
}

it('exports offending IPs as a plain list ordered by hit volume', function () {
    seedExportFinding('203.0.113.10', 'critical', hits: 20);
    seedExportFinding('203.0.113.11', 'error', hits: 5);

    Artisan::call('waf:export');
    $out = Artisan::output();

    expect($out)->toContain('203.0.113.10')
        ->and($out)->toContain('203.0.113.11');

    // Highest hit count first.
    expect(strpos($out, '203.0.113.10'))->toBeLessThan(strpos($out, '203.0.113.11'));
});

it('excludes IPs below the minimum severity', function () {
    seedExportFinding('203.0.113.20', 'warning', hits: 99);

    Artisan::call('waf:export', ['--min-level' => 'error']);

    expect(Artisan::output())->not->toContain('203.0.113.20');
});

it('excludes IPs below the minimum hit count', function () {
    seedExportFinding('203.0.113.30', 'critical', hits: 2);

    Artisan::call('waf:export', ['--min-hits' => 5]);

    expect(Artisan::output())->not->toContain('203.0.113.30');
});

it('collapses an IP across rows and sums its hit counts', function () {
    seedExportFinding('203.0.113.40', 'warning', hits: 3);
    seedExportFinding('203.0.113.40', 'critical', hits: 4);

    Artisan::call('waf:export', ['--min-hits' => 6, '--format' => 'csv']);
    $out = Artisan::output();

    // 3 + 4 = 7 total hits, max level critical.
    expect($out)->toContain('203.0.113.40,7,critical');
});

it('renders the nginx deny format', function () {
    seedExportFinding('203.0.113.50', 'critical', hits: 10);

    Artisan::call('waf:export', ['--format' => 'nginx']);

    expect(Artisan::output())->toContain('deny 203.0.113.50;');
});

it('renders the apache deny format', function () {
    seedExportFinding('203.0.113.60', 'critical', hits: 10);

    Artisan::call('waf:export', ['--format' => 'apache']);

    expect(Artisan::output())->toContain('Require not ip 203.0.113.60');
});

it('emits a csv header', function () {
    seedExportFinding('203.0.113.70', 'critical', hits: 10);

    Artisan::call('waf:export', ['--format' => 'csv']);

    expect(Artisan::output())->toContain('ip_address,hits,max_level,last_seen');
});

it('honours the days window', function () {
    seedExportFinding('203.0.113.80', 'critical', hits: 10, createdAt: now()->subDays(30));

    Artisan::call('waf:export', ['--days' => 7]);

    expect(Artisan::output())->not->toContain('203.0.113.80');
});

it('rejects an unknown format', function () {
    expect(Artisan::call('waf:export', ['--format' => 'bogus']))->toBe(2);
});

it('renders the fail2ban set-banip format with the default jail', function () {
    seedExportFinding('203.0.113.90', 'critical', hits: 10);

    Artisan::call('waf:export', ['--format' => 'fail2ban']);

    expect(Artisan::output())->toContain('fail2ban-client set laravel-waf banip 203.0.113.90');
});

it('uses a custom jail name in the fail2ban format', function () {
    seedExportFinding('203.0.113.91', 'critical', hits: 10);

    Artisan::call('waf:export', ['--format' => 'fail2ban', '--jail' => 'sshd']);

    expect(Artisan::output())->toContain('fail2ban-client set sshd banip 203.0.113.91');
});

it('rejects a jail name that could break out of the shell command', function () {
    seedExportFinding('203.0.113.92', 'critical', hits: 10);

    $status = Artisan::call('waf:export', ['--format' => 'fail2ban', '--jail' => 'a; rm -rf /']);

    expect($status)->toBe(2)
        ->and(Artisan::output())->not->toContain('203.0.113.92');
});
