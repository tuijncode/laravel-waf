<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

beforeEach(function () {
    $this->backtrackLimit = ini_get('pcre.backtrack_limit');
    ini_set('pcre.backtrack_limit', '100');
    config()->set('waf.pattern_pack', false);
    config()->set('waf.custom_patterns', [
        '/(a+)+$/' => ['label' => 'Expensive Pattern', 'targets' => ['query']],
        '/known-attack/' => ['label' => 'Known Attack', 'targets' => ['query']],
    ]);
});

afterEach(function () {
    ini_set('pcre.backtrack_limit', $this->backtrackLimit);
});

it('reports a PCRE failure and keeps scanning in fail-open mode', function () {
    Log::spy();

    $url = '/?x='.str_repeat('a', 40).'!&q=known-attack';
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();

    expect(DB::table('waf_logs')->where('type', 'like', '%Known Attack%')->count())->toBe(1);
    Log::shouldHaveReceived('warning')
        ->withArgs(fn (string $message, array $context): bool => $message === 'laravel-waf: signature evaluation error'
            && $context['rule_id'] === 'CUSTOM-1'
            && str_contains($context['error'], 'Backtrack limit exhausted'))
        ->once();
});

it('refuses the request on a PCRE failure in fail-closed mode', function () {
    config()->set('waf.on_error', 'closed');

    $this->get('/?x='.str_repeat('a', 40).'!')->assertStatus(503);
});

it('keeps the fail-closed response when error logging fails', function () {
    config()->set('waf.on_error', 'closed');
    Log::shouldReceive('error')->andThrow(new RuntimeException('log unavailable'));

    $this->get('/?x='.str_repeat('a', 40).'!')->assertStatus(503);
});
