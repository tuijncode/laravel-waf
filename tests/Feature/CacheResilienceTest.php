<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Tuijncode\LaravelWaf\Events\RequestBlocked;

$attack = fn () => '/?q='.rawurlencode("' UNION SELECT * FROM users--");

beforeEach(function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 40);
});

it('still scans and blocks when flood counting fails', function () use ($attack) {
    RateLimiter::shouldReceive('hit')->andThrow(new RuntimeException('cache offline'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('still scans when reading the flood counter fails', function () use ($attack) {
    RateLimiter::shouldReceive('attempts')->andThrow(new RuntimeException('cache offline'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('still blocks when deduplication cannot claim a cache key', function () use ($attack) {
    Cache::partialMock()->shouldReceive('add')->andThrow(new RuntimeException('cache offline'));

    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(2);
});

it('still honours exclusions through the database when their cache fails', function () {
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100',
        'path_glob' => null,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    Cache::partialMock()->shouldReceive('remember')->andThrow(new RuntimeException('cache offline'));

    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1'))->assertOk();

    expect(DB::table('waf_logs')->value('action_taken'))->toBe('excluded');
});

it('still blocks when the exclusion table cannot be read', function () use ($attack) {
    $database = DB::getFacadeRoot();
    DB::shouldReceive('table')->andReturnUsing(function (string $table) use ($database) {
        if ($table === 'waf_exclusion_rules') {
            throw new RuntimeException('exclusion read unavailable');
        }

        return $database->table($table);
    });
    DB::shouldReceive('transaction')->andReturnUsing(fn (callable $callback) => $database->transaction($callback));
    DB::shouldReceive('connection')->andReturnUsing(fn (?string $name = null) => $database->connection($name));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->value('action_taken'))->toBe('blocked');
});

it('still blocks when an auto-ban strike cannot be counted', function () use ($attack) {
    config()->set('waf.ddos.enabled', false);
    config()->set('waf.auto_ban.enabled', true);
    RateLimiter::shouldReceive('hit')->andThrow(new RuntimeException('cache offline'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('still inspects when checking a standing ban fails', function () use ($attack) {
    config()->set('waf.auto_ban.enabled', true);
    Cache::partialMock()->shouldReceive('has')->andThrow(new RuntimeException('cache offline'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('keeps the block after storage when updating the dedup key fails', function () use ($attack) {
    Cache::partialMock()->shouldReceive('put')->andThrow(new RuntimeException('cache offline'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('records findings with the null cache driver', function () use ($attack) {
    config()->set('cache.default', 'null');
    Event::fake([RequestBlocked::class]);

    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(2);
    Event::assertDispatchedTimes(RequestBlocked::class, 2);
});

it('records every finding when deduplication is disabled', function () use ($attack) {
    config()->set('waf.dedup_minutes', 0);

    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(2);
});
