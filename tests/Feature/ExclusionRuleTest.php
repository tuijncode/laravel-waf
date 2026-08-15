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

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

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
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->where('action_taken', 'excluded')->count())->toBe(1);
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
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

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

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

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
