<?php

use Tuijncode\LaravelWaf\Rules\CoreRuleSet;
use Tuijncode\LaravelWaf\Rules\Signature;
use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\ConfidenceScorer;

it('ships with 30 or more detection patterns', function () {
    expect(count(CoreRuleSet::rules()))->toBeGreaterThanOrEqual(30);
});

it('returns typed Signature objects', function () {
    expect(CoreRuleSet::rules())->each->toBeInstanceOf(Signature::class);
});

it('has a valid regex and unique id for every rule', function () {
    $ids = [];

    foreach (CoreRuleSet::rules() as $rule) {
        expect(@preg_match($rule->regex, ''))->not->toBeFalse("Invalid regex for rule {$rule->id}");
        expect($rule->severity)->toBeIn(['critical', 'error', 'warning', 'notice']);
        expect($rule->paranoia)->toBeGreaterThanOrEqual(1);
        expect($ids)->not->toContain($rule->id);
        $ids[] = $rule->id;
    }
});

it('scores a single critical match into the high-confidence band', function () {
    $scorer = new ConfidenceScorer;

    $result = $scorer->calculate([
        new SignatureMatch('942100', 'sqli', 'SQLi', 'x', 'critical', 'query', 'x'),
    ]);

    expect($result['score'])->toBeGreaterThanOrEqual(35)
        ->and($result['anomaly_score'])->toBe(5)
        ->and($result['label'])->toBeIn(['medium', 'high', 'critical']);
});

it('returns a zero score for a clean request', function () {
    $scorer = new ConfidenceScorer;

    expect($scorer->calculate([])['score'])->toBe(0)
        ->and($scorer->calculate([])['label'])->toBe('none');
});

it('distinguishes a validator regex failure from no match', function () {
    $limit = ini_get('pcre.backtrack_limit');
    ini_set('pcre.backtrack_limit', '100');

    try {
        $rule = new Signature('TEST', 'custom', 'Test', 'Test', 'error', ['query'], '/(a+)+$/', validator: 'luhn');
        expect(fn () => $rule->match(str_repeat('a', 40).'!'))
            ->toThrow(RuntimeException::class, 'Backtrack limit exhausted');
    } finally {
        ini_set('pcre.backtrack_limit', $limit);
    }
});

it('checks later validator candidates without collecting them all', function () {
    $rule = new Signature('TEST', 'custom', 'Test', 'Test', 'error', ['body'], '/\b\d{16}\b/', validator: 'luhn');
    $subject = str_repeat('1234567890123456 ', 10000).'4111111111111111';

    expect($rule->match($subject))->toBe('4111111111111111');
});

it('bounds rejected validator candidates in short and long subjects', function (int $length) {
    $rule = new Signature('TEST', 'custom', 'Test', 'Test', 'warning', ['body'], '/0/', validator: 'luhn');

    expect(fn () => $rule->match(str_repeat('0', $length)))
        ->toThrow(OverflowException::class, 'validation candidate limit exceeded');
})->with([30000, 100000]);
