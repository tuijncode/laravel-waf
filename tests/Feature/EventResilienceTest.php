<?php

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tuijncode\LaravelWaf\Events\IpBanned;
use Tuijncode\LaravelWaf\Events\RequestBlocked;
use Tuijncode\LaravelWaf\Events\ThreatDetected;

$attack = fn () => '/?q='.rawurlencode("' UNION SELECT * FROM users--");

beforeEach(function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 40);
});

it('still blocks and stores a finding when a threat listener fails', function () use ($attack) {
    Event::listen(ThreatDetected::class, fn () => throw new RuntimeException('listener failed'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('still blocks when a blocked-request listener fails', function () use ($attack) {
    Event::listen(RequestBlocked::class, fn () => throw new RuntimeException('listener failed'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('keeps a new ban when its listener fails', function () use ($attack) {
    config()->set('waf.auto_ban.enabled', true);
    config()->set('waf.auto_ban.max_blocks', 1);
    Event::listen(IpBanned::class, fn () => throw new RuntimeException('listener failed'));

    $this->get($attack())->assertForbidden();
    $this->get('/?q=hello')->assertForbidden()->assertHeader('Retry-After');
});

it('records a finding without a user ID when the auth guard fails', function () use ($attack) {
    Auth::shouldReceive('id')->once()->andThrow(new RuntimeException('guard failed'));

    $this->get($attack())->assertForbidden();

    expect(DB::table('waf_logs')->value('user_id'))->toBeNull();
});
