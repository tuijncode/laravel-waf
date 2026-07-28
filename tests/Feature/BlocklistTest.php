<?php

it('refuses a denylisted IP, even in detection mode', function () {
    // The test client's IP is 127.0.0.1; detection mode normally never blocks.
    config()->set('waf.mode', 'detection');
    config()->set('waf.blocklisted_ips', ['127.0.0.1']);

    $this->get('/?q=hello')->assertForbidden();
});

it('refuses a denylisted IP on a skip_path too', function () {
    config()->set('waf.blocklisted_ips', ['127.0.0.1']);

    // /up is in skip_paths, so inspection is normally skipped — but the
    // denylist is settled before path logic.
    $this->get('/up')->assertForbidden();
});

it('supports CIDR ranges in the denylist', function () {
    config()->set('waf.blocklisted_ips', ['127.0.0.0/8']);

    $this->get('/')->assertForbidden();
});

it('refuses a denylisted IP with stray whitespace around the entry', function () {
    // Untrimmed entries reach the middleware from stale published configs;
    // the denylist must still match.
    config()->set('waf.blocklisted_ips', [' 127.0.0.1 ']);

    $this->get('/?q=hello')->assertForbidden();
});

it('lets a non-denylisted IP through', function () {
    config()->set('waf.blocklisted_ips', ['203.0.113.5']);

    $this->get('/?q=hello')->assertOk()->assertSee('ok');
});

it('lets an allowlisted IP win over the denylist', function () {
    config()->set('waf.whitelisted_ips', ['127.0.0.1']);
    config()->set('waf.blocklisted_ips', ['127.0.0.1']);

    $this->get('/?q=hello')->assertOk()->assertSee('ok');
});
