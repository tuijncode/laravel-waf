<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Tuijncode\LaravelWaf\Events\IpBanned;
use Tuijncode\LaravelWaf\Services\AutoBanManager;

$attack = fn () => '/?q='.rawurlencode("' UNION SELECT * FROM users--");

beforeEach(function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 40);
    config()->set('waf.auto_ban.enabled', true);
    config()->set('waf.auto_ban.max_blocks', 2);
    config()->set('waf.auto_ban.window', 60);
    config()->set('waf.auto_ban.duration', 3600);
});

it('bans a client after repeated blocks and refuses it up front', function () use ($attack) {
    // Two blocked attacks earn the ban...
    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();

    // ...after which even a harmless request is refused, with Retry-After.
    $this->get('/?q=hello')
        ->assertForbidden()
        ->assertHeader('Retry-After', '3600');

    // The banned request short-circuits: no finding is recorded for it
    // (the identical attacks collapse to one row via dedup).
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('enforces a ban on skipped paths while honoring the IP whitelist', function () use ($attack) {
    config()->set('waf.skip_paths', ['health/*']);
    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();

    $this->get('/health/check')->assertForbidden()->assertHeader('Retry-After', '3600');

    config()->set('waf.whitelisted_ips', ['127.0.0.1']);
    $this->get('/health/check')->assertOk();
});

it('never bans while the feature is disabled', function () use ($attack) {
    config()->set('waf.auto_ban.enabled', false);

    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();

    $this->get('/?q=hello')->assertOk();
});

it('does not ban below the strike threshold', function () use ($attack) {
    $this->get($attack())->assertForbidden(); // one strike, max is two

    $this->get('/?q=hello')->assertOk();
});

it('dispatches IpBanned once when the ban is applied', function () use ($attack) {
    Event::fake([IpBanned::class]);

    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden(); // ban applied on the second strike
    $this->get('/?q=hello')->assertForbidden(); // already banned, no new event

    Event::assertDispatchedTimes(IpBanned::class, 1);
    Event::assertDispatched(IpBanned::class, fn (IpBanned $e) => $e->ipAddress === '127.0.0.1' && $e->seconds === 3600);
});

it('announces a ban only for the worker that atomically claims it', function () {
    Event::fake([IpBanned::class]);
    RateLimiter::shouldReceive('hit')->twice()->andReturn(2, 3);
    Cache::shouldReceive('add')->twice()->andReturn(true, false);
    Cache::shouldNotReceive('has');
    Cache::shouldNotReceive('put');

    $bans = app(AutoBanManager::class);
    $bans->strike('127.0.0.1');
    $bans->strike('127.0.0.1');

    Event::assertDispatchedTimes(IpBanned::class, 1);
});

it('lifts a standing ban', function () use ($attack) {
    $bans = app(AutoBanManager::class);

    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();
    expect($bans->banned('127.0.0.1'))->toBeTrue();

    expect($bans->lift('127.0.0.1'))->toBeTrue()
        ->and($bans->banned('127.0.0.1'))->toBeFalse();

    // A lift on an IP with no ban reports false.
    expect($bans->lift('127.0.0.1'))->toBeFalse();

    // And the client is inspected normally again.
    $this->get('/?q=hello')->assertOk();
});

it('unbans an IP through the waf:unban command', function () use ($attack) {
    $this->get($attack())->assertForbidden();
    $this->get($attack())->assertForbidden();
    expect(app(AutoBanManager::class)->banned('127.0.0.1'))->toBeTrue();

    $this->artisan('waf:unban', ['ip' => '127.0.0.1'])
        ->expectsOutputToContain('Lifted the ban for 127.0.0.1.')
        ->assertSuccessful();

    expect(app(AutoBanManager::class)->banned('127.0.0.1'))->toBeFalse();
});

it('rejects an invalid IP argument', function () {
    $this->artisan('waf:unban', ['ip' => 'not-an-ip'])->assertExitCode(2);
});
