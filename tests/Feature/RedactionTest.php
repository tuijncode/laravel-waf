<?php

use Illuminate\Support\Facades\DB;

it('masks a detected secret in the stored url and payload', function () {
    $this->get('/?token=AKIAIOSFODNN7EXAMPLE')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->type)->toContain('AWS Access Key ID')
        ->and($log->url)->toBe('[REDACTED]')
        ->and($log->payload)->toBe('[REDACTED]');
});

it('does not store a guessable target hash without an app key', function () {
    config()->set('app.key', '');

    $this->get('/private-path?q=AKIAIOSFODNN7EXAMPLE')->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->url)->toBe('[REDACTED]')
        ->and($log->target_hash)->toBeNull();
});

it('masks a secret even when part of it is double URL encoded', function () {
    $this->get('/?q=%2541KIAIOSFODNN7EXAMPLE')->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->type)->toContain('AWS Access Key ID')
        ->and($log->url)->toBe('[REDACTED]')
        ->and($log->payload)->toBe('[REDACTED]');
});

it('masks secrets hidden with the same escapes the inspector decodes', function (string $encoded) {
    $this->get('/?q='.rawurlencode($encoded))->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->type)->toContain('AWS Access Key ID')
        ->and($log->url)->toBe('[REDACTED]');
})->with(['\\u0041KIAIOSFODNN7EXAMPLE', '%u0041KIAIOSFODNN7EXAMPLE', '&#x41;KIAIOSFODNN7EXAMPLE']);

it('does not store a second secret when a rule captures only the first', function () {
    $this->get('/?q=AKIAIOSFODNN7EXAMPLE&other=AKIA1234567890123456')->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->url)->toBe('[REDACTED]')
        ->and($log->payload)->toBe('[REDACTED]');
});

it('redacts other log fields when they contain a second uncaptured secret', function () {
    $this->get('/?q=AKIAIOSFODNN7EXAMPLE', [
        'User-Agent' => 'Mozilla/5.0 AKIA1234567890123456',
    ])->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->url)->toBe('[REDACTED]')
        ->and($log->payload)->toBe('[REDACTED]')
        ->and($log->user_agent)->toBe('[REDACTED]');
});

it('does not store the suffix of a token longer than the match capture', function () {
    $jwt = 'eyJ'.str_repeat('a', 1100).'.'.str_repeat('b', 30).'.'.str_repeat('c', 30);
    $this->get('/?q='.$jwt)->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->type)->toContain('JWT Detected')
        ->and($log->url)->toBe('[REDACTED]')
        ->and($log->payload)->toBe('[REDACTED]');
});

it('stores the raw value when redaction is disabled', function () {
    config()->set('waf.redact.enabled', false);

    $this->get('/?token=AKIAIOSFODNN7EXAMPLE')->assertOk();

    expect(DB::table('waf_logs')->value('url'))->toContain('AKIAIOSFODNN7EXAMPLE');
});

it('leaves non-sensitive findings untouched', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    // A SQLi payload is not a secret, so the evidence is stored as-is.
    expect(DB::table('waf_logs')->value('payload'))->toContain('UNION');
});

it('does not store array credentials when another parameter triggers a finding', function () {
    $this->get('/?password%5B0%5D=demo-secret&q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->value('url'))->toContain('password%5B0%5D=[REDACTED]')
        ->not->toContain('demo-secret');
});

it('does not store credential arrays from a user agent on an unrelated finding', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), [
        'User-Agent' => '{"password":["first-secret","second-secret"]}',
    ])->assertOk();

    expect(DB::table('waf_logs')->value('user_agent'))->toBe('[REDACTED]');
});

it('does not store quoted credential values from a user agent', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), [
        'User-Agent' => 'Mozilla password="quoted secret"',
    ])->assertOk();

    expect(DB::table('waf_logs')->value('user_agent'))->not->toContain('quoted secret');
});

it('does not store percent-encoded JSON credentials on an unrelated finding', function () {
    $json = rawurlencode('{"password":["first-secret","second-secret"]}');
    $this->get('/?data='.$json.'&q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->value('url'))->toBe('[REDACTED]');
});

it('does not store a credential behind a percent-encoded parameter name', function () {
    $this->get('/?%70assword=first-secret&q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->value('url'))->toBe('[REDACTED]');
});
