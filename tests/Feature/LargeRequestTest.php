<?php

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Facades\Waf;
use Tuijncode\LaravelWaf\Services\WafInspector;

it('allows large harmless blog and API bodies in blocking mode', function () {
    config()->set('waf.mode', 'blocking');

    $html = str_repeat('<p>Blog content</p>', 4000);
    $this->call('POST', '/', [], [], [], ['CONTENT_TYPE' => 'text/html'], $html)->assertOk();
    $this->postJson('/', ['data' => str_repeat('a', 80000)])->assertOk();
    $this->post('/', ['attachment' => UploadedFile::fake()->create('sample.txt', 64)])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('still finds an attack in the middle of a large request', function () {
    config()->set('waf.mode', 'blocking');
    $body = str_repeat('a', 25000)."' UNION SELECT * FROM users--".str_repeat('b', 25000);
    $request = Request::create('/', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], $body);

    expect(Waf::inspect($request)->ruleIds())->toContain('942100');
    $this->call('POST', '/', [], [], [], ['CONTENT_TYPE' => 'text/plain'], $body)->assertStatus(403);
});

it('finds an attack near the end of a streamed request surface', function () {
    $body = str_repeat('a', 250000)."' UNION SELECT * FROM users--";
    $request = Request::create('/', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], $body);

    expect(Waf::inspect($request)->ruleIds())->toContain('942100');
});

it('finds a script tag whose long attributes cross scan windows', function () {
    $body = '<script '.str_repeat('a', 18000).'="x">alert(1)';
    $request = Request::create('/', 'POST', [], [], [], ['CONTENT_TYPE' => 'text/plain'], $body);

    expect(Waf::inspect($request)->ruleIds())->toContain('941100');
});

it('keeps the normalised scan subject bounded for a large encoded body', function () {
    $body = str_repeat('%41', 2 * 1024 * 1024);
    $normalise = (new ReflectionClass(WafInspector::class))->getMethod('normalise');
    $largest = 0;
    $count = 0;
    foreach ($normalise->invoke(app(WafInspector::class), $body) as $subject) {
        $largest = max($largest, strlen($subject));
        $count++;
    }

    expect($count)->toBeGreaterThan(1)
        ->and($largest)->toBeLessThan(100000);
});

it('streams large parsed fields while finding an attack near the end', function () {
    $value = str_repeat('a', 1000000).'<script>alert(1)</script>';
    $request = Request::create('/', 'POST', ['content' => $value]);

    expect(Waf::inspect($request)->ruleIds())->toContain('941100');

    $body = (new ReflectionClass(WafInspector::class))->getMethod('bodySurface')
        ->invoke(app(WafInspector::class), $request);
    $parts = iterator_to_array($body, false);
    expect($parts)->toHaveCount(3)
        ->and(strlen($parts[0]))->toBeLessThan(20000)
        ->and(strlen($parts[1]))->toBeLessThan(20000);
});
