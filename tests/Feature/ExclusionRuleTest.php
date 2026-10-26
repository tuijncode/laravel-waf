<?php

use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;

it('logs a matching threat as excluded instead of dropping it', function () {
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100',   // matches the "[942100] ..." rule id in the type
        'path_glob' => null,        // any path
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    app(ExclusionRuleService::class)->refresh();

    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->action_taken)->toBe('excluded');
});

it('never blocks an excluded threat even in blocking mode', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);

    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100',
        'path_glob' => null,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    app(ExclusionRuleService::class)->refresh();

    // Would normally be blocked, but the exclusion keeps it a 200.
    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1'))->assertOk();

    expect(DB::table('waf_logs')->where('action_taken', 'excluded')->count())->toBe(1);
});

it('does not let one excluded rule hide another attack', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.pattern_pack', false);

    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100',
        'path_glob' => null,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    app(ExclusionRuleService::class)->refresh();

    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1').'&x='.rawurlencode('<script>alert(1)</script>'))
        ->assertForbidden();

    expect(DB::table('waf_logs')->value('action_taken'))->toBe('blocked');
});

it('only suppresses on the configured path pattern', function () {
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100',
        'path_glob' => 'search',   // exclusion scoped to /search only
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    app(ExclusionRuleService::class)->refresh();

    // Request hits "/", not "/search", so the exclusion does not apply.
    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('ignores an exclusion whose label is only a partial match', function (string $label) {
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => $label,
        'path_glob' => null,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    app(ExclusionRuleService::class)->refresh();

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->value('action_taken'))->toBe('logged');
})->with([
    'family prefix' => '942',            // would suppress every SQLi rule under substring matching
    'category word' => 'SQL',            // would suppress every rule mentioning SQL
    'description fragment' => 'UNION SELECT',
]);

it('accepts an exclusion labelled with the full description', function () {
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => 'SQL Injection Attack: UNION SELECT detected',
        'path_glob' => null,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    app(ExclusionRuleService::class)->refresh();

    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1'))->assertOk();

    expect(DB::table('waf_logs')->value('action_taken'))->toBe('excluded');
});

it('builds an exclusion rule from a logged threat', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $logId = DB::table('waf_logs')->value('id');

    $rule = app(ExclusionRuleService::class)->acceptFromLog($logId, userId: 1, reason: 'known false positive');

    expect($rule)->not->toBeNull()
        ->and($rule->match_label)->toBe('942100')
        ->and($rule->source_log_id)->toBe($logId);
});

it('scopes a root finding to the root path', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    $query = '?q='.rawurlencode('UNION ALL SELECT 1');

    $this->get('/'.$query)->assertForbidden();
    app(ExclusionRuleService::class)->acceptFromLog(DB::table('waf_logs')->value('id'));

    $this->get('/'.$query)->assertOk();
    $this->get('/admin'.$query)->assertForbidden();
});

it('scopes a legacy root finding and treats glob characters in its path literally', function () {
    $service = app(ExclusionRuleService::class);
    foreach (['http://localhost/', 'http://localhost/a*b'] as $url) {
        $id = DB::table('waf_logs')->insertGetId([
            'ip_address' => '192.0.2.1', 'url' => $url, 'type' => '[942100] SQLi',
            'category' => 'sqli', 'created_at' => now(), 'updated_at' => now(),
        ]);
        $service->acceptFromLog($id);
    }

    expect($service->accepts('942100', 'http://localhost/'))->toBeTrue()
        ->and($service->accepts('942100', 'http://localhost/other'))->toBeFalse()
        ->and($service->accepts('942100', 'http://localhost/a*b'))->toBeTrue()
        ->and($service->accepts('942100', 'http://localhost/axb'))->toBeFalse();
});

it('keeps a manually empty path glob unscoped', function () {
    $service = app(ExclusionRuleService::class);
    $service->add('942100', '');

    expect($service->accepts('942100', 'http://localhost/'))->toBeTrue()
        ->and($service->accepts('942100', 'http://localhost/admin'))->toBeTrue();
});

it('limits a manual root exclusion to the root path', function () {
    $service = app(ExclusionRuleService::class);
    $rule = $service->add('942100', '/');

    expect($rule->path_glob)->toBe('/')
        ->and($service->accepts('942100', 'http://localhost/'))->toBeTrue()
        ->and($service->accepts('942100', 'http://localhost/admin'))->toBeFalse();
});

it('does not apply a root exclusion when the request URL has a malformed host', function () {
    $service = app(ExclusionRuleService::class);
    $service->add('942100', '/');

    expect($service->accepts('942100', 'http://bad:port/admin'))->toBeFalse()
        ->and($service->accepts('942100', 'http://localhost/'))->toBeTrue();
});

it('rejects a malformed log URL instead of creating a root exclusion', function () {
    $id = DB::table('waf_logs')->insertGetId([
        'ip_address' => '192.0.2.1', 'url' => 'http://bad:port/admin', 'type' => '[942100] SQLi',
        'category' => 'sqli', 'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(fn () => app(ExclusionRuleService::class)->acceptFromLog($id))
        ->toThrow(InvalidArgumentException::class);
    expect(DB::table('waf_exclusion_rules')->count())->toBe(0);
});

it('scopes a redacted finding without exposing its path', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    $query = '?q=AKIAIOSFODNN7EXAMPLE';

    $this->get('/source'.$query)->assertForbidden();
    $log = DB::table('waf_logs')->sole();
    expect($log->url)->toBe('[REDACTED]')
        ->and($log->target_hash)->toMatch('/^[a-f0-9]{64}$/');

    app(ExclusionRuleService::class)->acceptFromLog($log->id);

    $this->get('/source'.$query)->assertOk();
    $this->get('/other'.$query)->assertForbidden();
});

it('does not apply a hash-scoped exclusion when the app key is missing', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    $uri = '/source?q=AKIAIOSFODNN7EXAMPLE';

    $this->get($uri)->assertForbidden();
    app(ExclusionRuleService::class)->acceptFromLog(DB::table('waf_logs')->value('id'));

    config()->set('app.key', '');
    $this->get($uri)->assertForbidden();
});

it('rejects a legacy redacted finding whose path cannot be recovered safely', function () {
    $this->get('/?q=AKIAIOSFODNN7EXAMPLE')->assertOk();
    $log = DB::table('waf_logs')->sole();
    DB::table('waf_logs')->where('id', $log->id)->update(['target_hash' => null]);

    expect(fn () => app(ExclusionRuleService::class)->acceptFromLog($log->id))
        ->toThrow(InvalidArgumentException::class);
    expect(DB::table('waf_exclusion_rules')->count())->toBe(0);
});

it('makes a manual exclusion effective after the active list was cached', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    $uri = '/?q='.rawurlencode('UNION ALL SELECT 1');
    $this->get($uri)->assertForbidden();

    $rule = app(ExclusionRuleService::class)->add('942100');

    expect($rule->match_label)->toBe('942100');
    $this->get($uri)->assertOk();
    expect(DB::table('waf_logs')->where('action_taken', 'excluded')->count())->toBe(1);
});

it('accepts every rule in a logged finding', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    $uri = '/?q='.rawurlencode('UNION ALL SELECT 1').'&x='.rawurlencode('<script>alert(1)</script>');
    $headers = ['User-Agent' => 'curl/8.4.0'];
    $this->get($uri, $headers)->assertForbidden();
    $log = DB::table('waf_logs')->sole();

    expect($log->rule_ids)->toContain('913110');

    app(ExclusionRuleService::class)->acceptFromLog($log->id);

    expect(DB::table('waf_exclusion_rules')->pluck('match_label')->all())
        ->toBe(explode(',', $log->rule_ids));
    $this->get($uri, $headers)->assertOk();
    expect(DB::table('waf_logs')->where('action_taken', 'excluded')->count())->toBe(1);
});
