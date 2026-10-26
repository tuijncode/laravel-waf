<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;

it('reports the signatures a payload trips', function () {
    $this->artisan('waf:test', ['payload' => "' UNION SELECT * FROM users--"])
        ->expectsOutputToContain('942100')
        ->expectsOutputToContain('Confidence')
        ->assertExitCode(0);
});

it('reports a clean payload as no threat', function () {
    $this->artisan('waf:test', ['payload' => 'hello world'])
        ->expectsOutputToContain('No threats detected')
        ->assertExitCode(0);
});

it('honours safe fields in JSON dry runs', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->artisan('waf:test', [
        '--method' => 'POST',
        '--json' => true,
        '--ua' => 'Mozilla/5.0',
        '--body' => json_encode(['content' => '<script>alert(1)</script>']),
    ])->expectsOutputToContain('No threats detected')->assertExitCode(0);
});

it('uses an explicit Content-Type header when parsing a dry-run body', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->artisan('waf:test', [
        '--method' => 'POST',
        '--ua' => 'Mozilla/5.0',
        '--header' => ['Content-Type: application/json'],
        '--body' => json_encode(['content' => '<script>alert(1)</script>']),
    ])->expectsOutputToContain('No threats detected')->assertSuccessful();
});

it('surfaces a scanner user-agent', function () {
    $this->artisan('waf:test', ['payload' => 'hello', '--ua' => 'sqlmap/1.7'])
        ->expectsOutputToContain('scanner')
        ->assertExitCode(0);
});

it('rejects a malformed header option', function () {
    $this->artisan('waf:test', ['payload' => 'x', '--header' => ['no-colon-here']])
        ->assertExitCode(2);
});

it('writes nothing to the database (dry run)', function () {
    $this->artisan('waf:test', ['payload' => "' UNION SELECT * FROM users--"])
        ->assertExitCode(0);

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('reports flood blocking below the ordinary block threshold', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 99);
    config()->set('waf.ddos.block', true);
    config()->set('waf.ddos.threshold', 1);
    RateLimiter::hit('laravel-waf|flood|'.sha1('127.0.0.1'));
    RateLimiter::hit('laravel-waf|flood|'.sha1('127.0.0.1'));

    $this->artisan('waf:test', ['payload' => 'hello', '--ua' => 'Mozilla/5.0'])
        ->expectsOutputToContain('would BLOCK')->assertSuccessful();
});

it('does not predict a block below minimum confidence', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    config()->set('waf.min_confidence', 99);

    $this->artisan('waf:test', ['payload' => 'UNION ALL SELECT 1'])
        ->expectsOutputToContain('below minimum confidence, ignored')->assertSuccessful();
});

it('does not predict a block for an excluded finding', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100', 'path_glob' => null, 'is_active' => true,
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $this->artisan('waf:test', ['payload' => 'UNION ALL SELECT 1'])
        ->expectsOutputToContain('not blocked')->assertSuccessful();
});

it('labels the dry-run verdict as conditional when the WAF is disabled', function () {
    config()->set('waf.enabled', false);
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);

    $this->artisan('waf:test', ['payload' => 'UNION ALL SELECT 1'])
        ->expectsOutputToContain('if inspected')
        ->assertSuccessful();
});
