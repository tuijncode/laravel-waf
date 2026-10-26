<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

beforeEach(function () {
    config()->set('waf.pattern_pack', false);
    config()->set('waf.custom_patterns', ['/attack/i' => 'Attack Marker']);
});

it('compares raw variants before finding deduplication without storing payloads', function () {
    config()->set('waf.attempts.enabled', true);

    foreach (['attack', '%61ttack', '%2561ttack'] as $variant) {
        $this->get('/?q='.$variant)->assertOk();
    }

    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and(DB::table('waf_attempts')->count())->toBe(3);

    $chains = app(CorrelationAnalyzer::class)->mutationChains(minVariants: 3);
    expect($chains)->toHaveCount(1)
        ->and((int) $chains[0]['variants'])->toBe(3)
        ->and(DB::table('waf_attempts')->pluck('fingerprint')->unique()->count())->toBe(1)
        ->and(json_encode(DB::table('waf_attempts')->get()))->not->toContain('attack');

    $this->artisan('waf:correlate')->expectsOutputToContain('Attack variants')->assertSuccessful();
});

it('keeps different payloads separate even when the same rule matches', function () {
    config()->set('waf.attempts.enabled', true);

    $this->get('/?q=attack-one')->assertOk();
    $this->get('/?q=attack-two')->assertOk();

    expect(DB::table('waf_attempts')->pluck('fingerprint')->unique()->count())->toBe(2)
        ->and(app(CorrelationAnalyzer::class)->mutationChains(minVariants: 2))->toBe([]);
});

it('keeps payloads separate when they differ beyond the fingerprint prefix', function () {
    config()->set('waf.attempts.enabled', true);
    $prefix = str_repeat('a', 262144);

    $this->get('/?q='.$prefix.'attack-one')->assertOk();
    $this->get('/?q='.$prefix.'attack-two')->assertOk();

    expect(DB::table('waf_attempts')->pluck('fingerprint')->unique()->count())->toBe(2)
        ->and(app(CorrelationAnalyzer::class)->mutationChains(minVariants: 2))->toBe([]);
});

it('groups encoded variants of a long payload under one fingerprint', function () {
    config()->set('waf.attempts.enabled', true);
    $prefix = str_repeat('a', 16000);

    $this->get('/?q='.$prefix.'attack')->assertOk();
    $this->get('/?q='.$prefix.'%61ttack')->assertOk();

    expect(DB::table('waf_attempts')->pluck('fingerprint')->unique()->count())->toBe(1)
        ->and(app(CorrelationAnalyzer::class)->mutationChains(minVariants: 2))->toHaveCount(1);
});

it('does not write attempt rows while disabled and caps writes per IP', function () {
    $this->get('/?q=attack')->assertOk();
    expect(DB::table('waf_attempts')->count())->toBe(0);

    config()->set('waf.attempts.enabled', true);
    config()->set('waf.attempts.max_per_ip', 2);
    foreach (['attack', '%61ttack', '%2561ttack'] as $variant) {
        $this->get('/?q='.$variant)->assertOk();
    }

    expect(DB::table('waf_attempts')->count())->toBe(2);

    $rule = DB::table('waf_attempts')->value('rule_id');
    $variant = substr(hash_hmac('sha256', 'q=%2561ttack', (string) config('app.key')), 0, 16);
    $windowId = intdiv(now()->timestamp, 60 * 60);
    expect(Cache::has('laravel-waf|attempt|'.sha1('127.0.0.1|'.$rule.'|'.$variant).'|'.$windowId))->toBeFalse();
});

it('uses the normal attempt cap and window for invalid settings', function () {
    config()->set('waf.attempts.enabled', true);
    config()->set('waf.attempts.max_per_ip', 'invalid');
    config()->set('waf.attempts.window_minutes', 0);

    $this->get('/?q=attack-one')->assertOk();
    $this->get('/?q=attack-two')->assertOk();

    expect(DB::table('waf_attempts')->count())->toBe(2)
        ->and(DB::table('waf_attempts')->distinct()->value('window_id'))->toBe(intdiv(now()->timestamp, 60 * 60));
});

it('keeps normal WAF logging available when the optional attempt table is missing', function () {
    config()->set('waf.attempts.enabled', true);
    Schema::drop('waf_attempts');

    $this->get('/?q=attack')->assertOk();

    $analyzer = app(CorrelationAnalyzer::class);
    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and($analyzer->retryBursts())->toBe([])
        ->and($analyzer->sharedPayloads())->toBe([])
        ->and($analyzer->rankActors())->toHaveCount(1);
});

it('checks the attempt table schema once per running recorder', function () {
    config()->set('waf.attempts.enabled', true);
    Schema::partialMock()->shouldReceive('hasTable')->once()->with('waf_attempts')->andReturn(true);

    $this->get('/?q=attack-one')->assertOk();
    $this->get('/?q=attack-two')->assertOk();

    expect(DB::table('waf_attempts')->count())->toBe(2);
});

it('records a repeated variant again in a later window', function () {
    config()->set('waf.attempts.enabled', true);

    $this->get('/?q=attack')->assertOk();
    $this->travel(61)->minutes();
    $this->get('/?q=attack')->assertOk();

    expect(DB::table('waf_attempts')->count())->toBe(2);
});

it('records a repeated variant on both sides of a fixed window boundary', function () {
    config()->set('waf.attempts.enabled', true);
    config()->set('waf.attempts.max_per_ip', 1);
    $this->travelTo(now()->startOfHour()->addMinutes(59)->addSeconds(59));

    $this->get('/?q=attack')->assertOk();
    $this->travel(2)->seconds();
    $this->get('/?q=attack')->assertOk();

    expect(DB::table('waf_attempts')->count())->toBe(2)
        ->and(DB::table('waf_attempts')->distinct()->count('window_id'))->toBe(2);
});

it('releases an attempt claim when its database write fails', function () {
    config()->set('waf.attempts.enabled', true);
    config()->set('waf.attempts.max_per_ip', 2);
    $this->get('/?q=attack-one')->assertOk();

    Schema::drop('waf_attempts');
    $this->get('/?q=attack-two')->assertOk();
    (require __DIR__.'/../../database/migrations/create_waf_attempts_table.php.stub')->up();
    $this->get('/?q=attack-two')->assertOk();

    expect(DB::table('waf_attempts')->count())->toBe(1);
});
