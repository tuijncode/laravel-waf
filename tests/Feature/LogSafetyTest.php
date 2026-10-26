<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Facades\Waf;

it('masks credentials in a URL when another signature triggered the finding', function () {
    config()->set('waf.pattern_pack', false);

    $this->get('/?password=hunter2&q='.rawurlencode('<script>alert(1)</script>'))
        ->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->url)->toContain('password=[REDACTED]')
        ->not->toContain('hunter2');
});

it('masks credentials in encoded nested query fields', function () {
    config()->set('waf.pattern_pack', false);

    $this->get('/?user%5Bpassword%5D=hunter2&q='.rawurlencode('<script>alert(1)</script>'))
        ->assertOk();

    expect(DB::table('waf_logs')->value('url'))
        ->toContain('password%5D=[REDACTED]')
        ->not->toContain('hunter2');
});

it('stores a safe User-Agent and masks a credential in it', function () {
    $this->get('/.env', ['User-Agent' => "client\xFF\x1B\xE2\x80\xAE token=abc123"])->assertOk();

    $agent = DB::table('waf_logs')->value('user_agent');
    expect($agent)->toContain('token=[REDACTED]', '\\x1B', '\\u202E')
        ->not->toContain('abc123', "\xFF", "\x1B", "\xE2\x80\xAE");
});

it('bounds stored HTTP methods to the log column length', function () {
    $request = Request::create('/?q='.rawurlencode("' UNION SELECT * FROM users--"), 'LONGMETHOD123');

    Waf::handle($request);

    expect(DB::table('waf_logs')->value('method'))->toBe('LONGMETHOD');
});
