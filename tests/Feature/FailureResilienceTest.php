<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Tuijncode\LaravelWaf\Http\Middleware\WafMiddleware;

it('uses the connection address when forwarded IP headers conflict', function () {
    Request::setTrustedProxies(['192.0.2.15'], SymfonyRequest::HEADER_FORWARDED | SymfonyRequest::HEADER_X_FORWARDED_FOR);

    try {
        $request = Request::create('http://example.test/?q='.rawurlencode("' UNION SELECT * FROM users--"), 'GET', [], [], [], [
            'REMOTE_ADDR' => '192.0.2.15',
            'HTTP_FORWARDED' => 'for=198.51.100.20',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.30',
        ]);

        $response = app(WafMiddleware::class)->handle($request, fn () => response('ok'));

        expect($response->getStatusCode())->toBe(200)
            ->and(DB::table('waf_logs')->value('ip_address'))->toBe('192.0.2.15');
    } finally {
        Request::setTrustedProxies([], SymfonyRequest::HEADER_X_FORWARDED_FOR);
    }
});

it('keeps denylist blocking when the logger cannot write', function () {
    config()->set('waf.blocklisted_ips', ['203.0.113.25']);
    Log::shouldReceive('warning')->andThrow(new RuntimeException('log unavailable'));

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.25'])
        ->get('/')
        ->assertForbidden();
});

it('keeps a recorded finding when its diagnostic log fails', function () {
    Log::shouldReceive('warning')->andThrow(new RuntimeException('log unavailable'));

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});
