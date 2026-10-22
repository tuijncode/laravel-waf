<?php

use Illuminate\Support\Facades\DB;

it('detects bundled pack signatures end to end', function (string $query, string $label) {
    $this->get('/?'.$query)->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('custom')
        ->and($log->type)->toContain($label);
})->with([
    'AWS access key' => ['token=AKIAIOSFODNN7EXAMPLE', 'AWS Access Key ID'],
    'GitHub token' => ['t=ghp_'.str_repeat('a', 36), 'GitHub Token'],
    'Ignition RCE probe' => ['x=/_ignition/execute-solution', 'Ignition RCE'],
    'SSTI arithmetic' => ['tpl='.rawurlencode('{{7*7}}'), 'SSTI Arithmetic Probe'],
    'Open redirect' => ['next=//evil.example', 'Open Redirect'],
    'Prototype pollution' => ['__proto__[admin]=1', 'Prototype Pollution'],
    'GraphQL introspection' => ['q='.rawurlencode('{__schema{types{name}}}'), 'GraphQL Introspection'],
    'Java deserialization (hex magic)' => ['data=aced0005737200046a617661', 'Java Deserialization Payload (hex)'],
    // Regression: `$`-anchored patterns must also match a value at the end of a
    // query parameter, not only at the end of the whole inspected surface.
    '.env probe via query' => ['file=.env', 'Environment File Access'],
    'backup archive probe via query' => ['f=backup.sql', 'Backup / Archive File Probe'],
    // Regression: leading `\b` before a literal dot broke these entirely.
    'DS_Store probe' => ['f='.rawurlencode('/.DS_Store'), 'Sensitive Artefact Probe'],
    'bash_history probe' => ['f='.rawurlencode('/.bash_history'), 'Sensitive Artefact Probe'],
    // Regression: `^`-anchored web.config missed the query-value variant.
    'web.config probe via query' => ['f=web.config', 'Server Config Access'],
]);

it('detects a valid credit card number in a POST body', function () {
    // A real, Luhn-valid Visa test PAN.
    $this->post('/', ['pan' => '4111111111111111'])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->type)->toContain('Card Number');
});

it('blocks an Ignition exploit route in blocking mode without blocking text mentions', function () {
    config()->set('waf.mode', 'blocking');

    $this->post('/_ignition/execute-solution')->assertForbidden();

    expect(DB::table('waf_logs')->sole()->confidence_score)->toBe(100);

    $this->get('/?x=/_ignition/execute-solution')->assertOk();
    $this->get('/_ignition/execute-solution-preview')->assertOk();
});

it('ignores a 16-digit number that fails the Luhn check', function () {
    // Right shape, wrong checksum — an order id, not a card number.
    $this->post('/', ['order' => '4111111111111112'])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});
