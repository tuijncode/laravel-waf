<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\WafInspector;

beforeEach(fn () => config()->set('waf.pattern_pack', false)); // isolate user patterns

it('detects a user-defined simple custom pattern', function () {
    config()->set('waf.custom_patterns', [
        '/\bmy-secret-token\b/i' => 'Internal Token Leak',
    ]);

    $this->get('/?q='.rawurlencode('here is my-secret-token'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('custom')
        ->and($log->type)->toContain('Internal Token Leak')
        ->and($log->rule_ids)->toContain('CUSTOM-1')
        ->and($log->threat_level)->toBe('error'); // default custom severity
});

it('honours the severity and targets of a full custom pattern definition', function () {
    config()->set('waf.custom_patterns', [
        '/forbidden/i' => [
            'label' => 'Forbidden Keyword',
            'severity' => 'critical',
            'targets' => ['query'],
        ],
    ]);

    $this->get('/?q=forbidden')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->threat_level)->toBe('critical')
        ->and($log->type)->toContain('Forbidden Keyword');
});

it('keeps a custom rule’s target priority when several surfaces match', function () {
    config()->set('waf.custom_patterns', [
        '/attack/i' => ['label' => 'Attack', 'targets' => ['body', 'query']],
    ]);
    $request = Request::create('/?q=attack', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], 'attack');

    $match = collect(app(WafInspector::class)->inspect($request)->matches)
        ->first(fn ($match) => $match->id === 'CUSTOM-1');
    expect($match->context)->toBe('body');
});

it('matches an anchored custom pattern against a decoded body variant', function () {
    config()->set('waf.custom_patterns', [
        '/^evil$/' => ['label' => 'Encoded body', 'targets' => ['body']],
    ]);

    $request = Request::create('/', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], '%65vil');

    expect(app(WafInspector::class)->inspect($request)->ruleIds())->toContain('CUSTOM-1');
});

it('does not match a core rule across separate decoded body variants', function () {
    $request = Request::create('/', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], 'select%20+union');

    expect(app(WafInspector::class)->inspect($request)->ruleIds())->not->toContain('942100');
});

it('matches a long custom pattern across chunk boundaries', function () {
    config()->set('waf.custom_patterns', [
        '/X.{4500}Y/s' => ['label' => 'Long Pattern', 'targets' => ['body']],
    ]);
    $body = str_repeat('a', 13500).'X'.str_repeat('a', 4500).'Y';

    expect(app(WafInspector::class)->inspect(Request::create('/', 'POST', [], [], [], [], $body))->ruleIds())
        ->toContain('CUSTOM-1');

    $encoded = str_repeat('a', 13500).'%58'.str_repeat('a', 4500).'%59';
    expect(app(WafInspector::class)->inspect(Request::create('/', 'POST', [], [], [], [], $encoded))->ruleIds())
        ->toContain('CUSTOM-1');
});

it('matches an operator pattern longer than a scan window', function () {
    config()->set('waf.custom_patterns', [
        '/X.{40000}Y/s' => ['label' => 'Long Pattern', 'targets' => ['body']],
    ]);
    $body = 'X'.str_repeat('a', 40000).'Y';

    expect(app(WafInspector::class)->inspect(Request::create('/', 'POST', [], [], [], [], $body))->ruleIds())
        ->toContain('CUSTOM-1');

    $encoded = '%58'.str_repeat('a', 40000).'%59';
    expect(app(WafInspector::class)->inspect(Request::create('/', 'POST', [], [], [], [], $encoded))->ruleIds())
        ->toContain('CUSTOM-1');
});

it('keeps valid and core rules active when custom metadata cannot be serialized', function () {
    config()->set('waf.custom_patterns', [
        '/bad/i' => ['label' => fn (): string => 'Bad'],
        '/good/i' => 'Good',
    ]);

    $ids = app(WafInspector::class)->inspect(Request::create('/?q=good%20%27%20UNION%20SELECT%20password%20FROM%20users', 'GET'))->ruleIds();

    expect($ids)->toContain('CUSTOM-2')->toContain('942100');
});

it('finds a validated custom match late in a long body', function () {
    config()->set('waf.custom_patterns', [
        '/\b\d{16}\b/' => ['label' => 'Card number', 'targets' => ['body'], 'validator' => 'luhn'],
    ]);
    $body = str_repeat('x', 50000).' 4111111111111111';

    expect(app(WafInspector::class)->inspect(Request::create('/', 'POST', [], [], [], [], $body))->ruleIds())
        ->toContain('CUSTOM-1');
});

it('keeps a valid Luhn alternative when another branch matches a short digit', function () {
    config()->set('waf.custom_patterns', [
        '/\d|CARD\d{16}/' => ['label' => 'Card number', 'targets' => ['body'], 'validator' => 'luhn'],
    ]);

    expect(app(WafInspector::class)->inspect(Request::create('/', 'POST', [], [], [], [], 'CARD4111111111111111'))->ruleIds())
        ->toContain('CUSTOM-1');
});

it('skips malformed custom definitions while keeping valid and core rules active', function () {
    config()->set('waf.custom_patterns', [
        '/bad-target/i' => ['label' => 'Bad target', 'targets' => 'query'],
        '/bad-label/i' => ['label' => ['unexpected'], 'targets' => ['query']],
        '/good/i' => ['label' => 'Good', 'targets' => ['query']],
    ]);

    $ids = app(WafInspector::class)->inspect(Request::create('/?q=good%20%27%20UNION%20SELECT%20password%20FROM%20users', 'GET'))->ruleIds();

    expect($ids)->toContain('CUSTOM-3')->toContain('942100');
});

it('skips an invalid custom pattern without breaking inspection', function () {
    config()->set('waf.custom_patterns', [
        '/broken(/' => 'Never Compiles',            // invalid regex
        '/\bhit\b/i' => 'Valid One',
    ]);

    $this->get('/?q=hit')->assertOk();

    expect(DB::table('waf_logs')->where('type', 'like', '%Valid One%')->count())->toBe(1);
});
