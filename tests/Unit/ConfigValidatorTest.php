<?php

use Tuijncode\LaravelWaf\Support\ConfigValidator;

beforeEach(fn () => $this->validator = new ConfigValidator);

it('passes the shipped default configuration', function () {
    expect($this->validator->validate())->toBe([]);
});

it('requires an app key when redacted targets need keyed hashes', function () {
    config()->set('app.key', '');

    expect($this->validator->validate())->toContain('APP_KEY is required for keyed hashes of redacted WAF targets.');
});

it('flags an invalid mode', function () {
    config()->set('waf.mode', 'blockign');

    expect($this->validator->validate())->toContain(
        "waf.mode must be one of [detection, blocking], got 'blockign'."
    );
});

it('flags an out-of-range paranoia level', function () {
    config()->set('waf.paranoia_level', 9);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.paranoia_level');
});

it('flags a severity typo', function () {
    config()->set('waf.custom_pattern_severity', 'criticl');

    expect(implode(' ', $this->validator->validate()))->toContain('waf.custom_pattern_severity');
});

it('flags a confidence value outside 0-100', function () {
    config()->set('waf.block_confidence', 150);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.block_confidence');
});

it('flags a non-positive ddos threshold', function () {
    config()->set('waf.ddos.threshold', 0);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.ddos.threshold');
});

it('flags an unknown disabled category', function () {
    config()->set('waf.disabled_categories', ['sqli', 'notacategory']);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown category 'notacategory'");
});

it('accepts a valid known disabled category', function () {
    config()->set('waf.disabled_categories', ['sqli', 'nosqli', 'scanner']);

    expect($this->validator->validate())->toBe([]);
});

it('accepts integer values provided as numeric strings (env style)', function () {
    config()->set('waf.paranoia_level', '2');
    config()->set('waf.block_confidence', '60');

    expect($this->validator->validate())->toBe([]);
});

it('flags an invalid on_error mode', function () {
    config()->set('waf.on_error', 'colsed');

    expect($this->validator->validate())->toContain(
        "waf.on_error must be one of [open, closed], got 'colsed'."
    );
});

it('flags a non-array enabled_environments', function () {
    config()->set('waf.enabled_environments', 'production');

    expect(implode(' ', $this->validator->validate()))->toContain('waf.enabled_environments');
});

it('flags non-string enabled environments', function () {
    config()->set('waf.enabled_environments', [42]);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.enabled_environments entries');
});

it('flags path lists that are not arrays of strings', function () {
    config()->set('waf.only_paths', 'api/*');
    config()->set('waf.skip_paths', [['ignored/*']]);

    $problems = implode(' ', $this->validator->validate());
    expect($problems)->toContain('waf.only_paths')->toContain('waf.skip_paths');
});

it('flags a non-positive auto_ban setting', function () {
    config()->set('waf.auto_ban.max_blocks', 0);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.auto_ban.max_blocks');
});

it('flags invalid retention settings', function () {
    config()->set('waf.retention.days', 'invalid');
    config()->set('waf.attempts.retention_days', 0);

    $problems = implode(' ', $this->validator->validate());
    expect($problems)->toContain('waf.retention.days')
        ->toContain('waf.attempts.retention_days');
});

it('flags invalid attempt cap and window settings', function () {
    config()->set('waf.attempts.window_minutes', 0);
    config()->set('waf.attempts.max_per_ip', 'invalid');

    $problems = implode(' ', $this->validator->validate());
    expect($problems)->toContain('waf.attempts.window_minutes')
        ->toContain('waf.attempts.max_per_ip');
});

it('allows older attempt configuration without cap and window settings', function () {
    config()->set('waf.attempts.window_minutes', null);
    config()->set('waf.attempts.max_per_ip', null);

    expect($this->validator->validate())->toBe([]);
});

it('flags an unsafe shared-payload row budget', function () {
    config()->set('waf.attempts.max_correlation_rows', 100001);

    expect(implode(' ', $this->validator->validate()))->toContain('waf.attempts.max_correlation_rows');
});

it('uses the default row budget with an older published attempt config', function () {
    config()->set('waf.attempts.max_correlation_rows', null);

    expect($this->validator->validate())->toBe([]);
});

it('flags an unparsable custom pattern regex', function () {
    config()->set('waf.custom_patterns', ['/broken(/' => 'Broken']);

    expect(implode(' ', $this->validator->validate()))->toContain('not a valid regular expression');
});

it('flags an unknown custom pattern severity', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'severity' => 'criticl'],
    ]);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown severity 'criticl'");
});

it('flags an unknown custom pattern target surface', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'targets' => ['querry']],
    ]);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown surface 'querry'");
});

it('flags malformed custom pattern metadata', function () {
    config()->set('waf.custom_patterns', [
        '/bad-target/i' => ['label' => 'Bad target', 'targets' => 'query'],
        '/bad-label/i' => ['label' => ['unexpected'], 'targets' => ['query']],
        '/bad-validator/i' => ['label' => 'Bad validator', 'validator' => ['luhn']],
        '/bad-paranoia/i' => ['label' => 'Bad paranoia', 'paranoia' => []],
    ]);

    $problems = implode(' ', $this->validator->validate());
    expect($problems)->toContain('targets must be a non-empty array')
        ->toContain('label must be a string')
        ->toContain('names unknown validator')
        ->toContain('paranoia must be an integer between 1 and 4');
});

it('flags an unknown custom pattern validator', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'validator' => 'moon-phase'],
    ]);

    expect(implode(' ', $this->validator->validate()))->toContain("unknown validator 'moon-phase'");
});

it('accepts the built-in luhn validator', function () {
    config()->set('waf.custom_patterns', [
        '/ok/i' => ['label' => 'X', 'validator' => 'luhn'],
    ]);

    expect($this->validator->validate())->toBe([]);
});

it('keeps broad Luhn patterns available for bounded runtime inspection', function () {
    config()->set('waf.custom_patterns', [
        '/\d/' => ['label' => 'Digits', 'validator' => 'luhn'],
    ]);

    expect($this->validator->validate())->toBe([]);
});
