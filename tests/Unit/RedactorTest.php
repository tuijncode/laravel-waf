<?php

use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\Redactor;

beforeEach(fn () => $this->redactor = new Redactor);

function sig(string $description, string $category = 'custom', string $matched = 'x'): SignatureMatch
{
    return new SignatureMatch('id', $category, 'name', $description, 'critical', 'query', $matched);
}

it('masks the middle of a value', function () {
    expect($this->redactor->mask('AKIAIOSFODNN7EXAMPLE'))
        ->toStartWith('AK')
        ->toEndWith('LE')
        ->not->toContain('IOSFODNN')
        ->toContain('*');
});

it('fully masks very short values', function () {
    expect($this->redactor->mask('abcd'))->toBe('****')
        ->and($this->redactor->mask('x'))->toBe('*');
});

it('flags secret-bearing findings as sensitive', function () {
    expect($this->redactor->isSensitive(sig('AWS Access Key ID')))->toBeTrue()
        ->and($this->redactor->isSensitive(sig('Password in URL')))->toBeTrue()
        ->and($this->redactor->isSensitive(sig('Credit / Debit Card Number')))->toBeTrue()
        ->and($this->redactor->isSensitive(sig('SQL Injection', 'sqli')))->toBeFalse();
});

it('scrubs sensitive values out of text', function () {
    $scrubbed = $this->redactor->scrub('token=AKIAIOSFODNN7EXAMPLE&x=1', ['AKIAIOSFODNN7EXAMPLE']);

    expect($scrubbed)->toBe('[REDACTED]');
});

it('collects only sensitive matched values', function () {
    $matches = [sig('AWS Access Key ID', 'custom', 'AKIA123'), sig('SQL Injection', 'sqli', "' OR 1=1")];

    expect($this->redactor->sensitiveValues($matches))->toBe(['AKIA123']);
});

it('masks named credentials in flat, nested and JSON text', function () {
    $text = 'password=hunter2&user%5Btoken%5D=abc123&x=1 {"api_key":"private-value"}';

    expect($this->redactor->fields($text))
        ->toContain('password=[REDACTED]')
        ->toContain('token%5D=[REDACTED]')
        ->toContain('"api_key":"[REDACTED]"')
        ->toContain('&x=1')
        ->not->toContain('hunter2', 'abc123', 'private-value');
});

it('masks sensitive array parameters in encoded and literal query strings', function () {
    $text = 'password%5B0%5D=first&password[]=second&token[meta][1]=third&password%255B0%255D=fourth&user%255Btoken%255D=fifth&x=visible';

    expect($this->redactor->fields($text))
        ->toBe('password%5B0%5D=[REDACTED]&password[]=[REDACTED]&token[meta][1]=[REDACTED]&password%255B0%255D=[REDACTED]&user%255Btoken%255D=[REDACTED]&x=visible');
});

it('does not leave quoted or nested credential values in evidence', function () {
    expect($this->redactor->fields('password="quoted secret"&x=visible'))
        ->toBe('[REDACTED]')
        ->and($this->redactor->fields('password="quoted&secret"&x=visible'))
        ->toBe('[REDACTED]')
        ->and($this->redactor->fields('{"password":["first-secret","second-secret"]}'))
        ->toBe('[REDACTED]')
        ->and($this->redactor->fields('{"password":{"nested":"private-value"}}'))
        ->toBe('[REDACTED]');
});

it('masks credentials in percent-encoded JSON query values', function () {
    $json = rawurlencode('{"password":["first-secret","second-secret"]}');

    expect($this->redactor->fields('https://example.test/?data='.$json.'&q=UNION%20SELECT'))
        ->toBe('[REDACTED]');
});

it('masks credentials when a query parameter name is percent encoded', function () {
    expect($this->redactor->fields('https://example.test/?%70assword=first-secret&q=UNION%20SELECT'))
        ->toBe('[REDACTED]')
        ->and($this->redactor->fields('https://example.test/?password=safe&%74oken=second-secret'))
        ->toBe('[REDACTED]');
});

it('stores valid bounded UTF-8 and makes control characters visible', function () {
    $text = "agent\xFF\x1B\xE2\x80\xAE ok";
    $stored = $this->redactor->storable($text, 80);

    expect(mb_check_encoding($stored, 'UTF-8'))->toBeTrue()
        ->and($stored)->toContain('\\x1B', '\\u202E')
        ->not->toContain("\xFF", "\x1B", "\xE2\x80\xAE")
        ->and(strlen($this->redactor->storable(str_repeat('é', 300), 499)))->toBeLessThanOrEqual(499);
});
