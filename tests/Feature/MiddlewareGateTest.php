<?php

use Illuminate\Support\Facades\DB;

$attack = fn () => 'q='.rawurlencode('<script>alert(1)</script>');

it('does nothing when the WAF is disabled', function () use ($attack) {
    config()->set('waf.enabled', false);

    $this->get('/?'.$attack())->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('does nothing outside the enabled environments', function () use ($attack) {
    config()->set('waf.enabled_environments', ['production']); // running in "testing"

    $this->get('/?'.$attack())->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('skips whitelisted IPs', function () use ($attack) {
    config()->set('waf.whitelisted_ips', ['127.0.0.1']);

    $this->get('/?'.$attack())->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('skips whitelisted IPs with stray whitespace around the entry', function () use ($attack) {
    // A stale published config predating the trim-on-parse fix hands the
    // middleware untrimmed entries ("1.2.3.4, 5.6.7.8" split on commas);
    // the whitelist must still match.
    config()->set('waf.whitelisted_ips', [' 127.0.0.1 ']);

    $this->get('/?'.$attack())->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('skips paths matching skip_paths but inspects others', function () use ($attack) {
    config()->set('waf.skip_paths', ['ignored/*']);

    $this->get('/ignored/thing?'.$attack())->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(0);

    $this->get('/watched/thing?'.$attack())->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('only inspects only_paths when configured', function () use ($attack) {
    config()->set('waf.only_paths', ['api/*']);

    $this->get('/?'.$attack())->assertOk();          // path "" is not in only_paths
    expect(DB::table('waf_logs')->count())->toBe(0);

    $this->get('/api/search?'.$attack())->assertOk(); // matches api/*
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('inspects the livewire update endpoint but skips its assets', function () use ($attack) {
    // The default skip list carves out Livewire's JS asset, not its update route.
    $this->get('/livewire/livewire.js?'.$attack())->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(0);

    $this->get('/livewire/update?'.$attack())->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(1);
});
