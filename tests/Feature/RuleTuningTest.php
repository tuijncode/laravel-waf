<?php

use Illuminate\Support\Facades\DB;

it('silences a specific rule via disabled_rules', function () {
    config()->set('waf.disabled_rules', ['942100']);

    // Payload that ONLY the UNION rule (942100) would catch.
    $this->get('/?q='.rawurlencode('UNION ALL SELECT'))->assertOk();

    expect(DB::table('waf_logs')->where('rule_ids', 'like', '%942100%')->count())->toBe(0);
});

it('silences a whole category via disabled_categories', function () {
    config()->set('waf.disabled_categories', ['nosqli']);

    $this->get('/?filter[$ne]=1')->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('silences scanner signals via disabled rule or category', function (string $setting, string $value) {
    config()->set("waf.{$setting}", [$value]);

    $this->get('/', ['User-Agent' => 'sqlmap/1.7'])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
})->with([
    ['disabled_rules', '913100'],
    ['disabled_categories', 'scanner'],
]);

it('silences bot and flood signals via disabled categories', function () {
    config()->set('waf.disabled_categories', ['bot', 'ddos']);
    config()->set('waf.ddos.threshold', 1);

    $this->get('/', ['User-Agent' => 'curl/8.0'])->assertOk();
    $this->get('/', ['User-Agent' => 'curl/8.0'])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('runs broad rules at paranoia level 2 (default)', function () {
    // 930100 (../) is a broad rule; on its own it should still be caught at PL2.
    $this->get('/?p='.rawurlencode('../secret'))->assertOk();

    expect(DB::table('waf_logs')->where('rule_ids', 'like', '%930100%')->count())->toBe(1);
});

it('drops broad rules at paranoia level 1', function () {
    config()->set('waf.paranoia_level', 1);

    // ../ alone is a broad (PL2) rule — muted at PL1, so nothing is logged.
    $this->get('/?p='.rawurlencode('../secret'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('still catches high-confidence rules at paranoia level 1', function () {
    config()->set('waf.paranoia_level', 1);

    // /etc/passwd (930110) is PL1 — always on.
    $this->get('/?p='.rawurlencode('/etc/passwd'))->assertOk();

    expect(DB::table('waf_logs')->where('rule_ids', 'like', '%930110%')->count())->toBe(1);
});

it('honours a per-pattern paranoia level on a custom rule', function () {
    config()->set('waf.paranoia_level', 1);
    config()->set('waf.pattern_pack', false);
    config()->set('waf.custom_patterns', [
        '/\baggressive-probe\b/i' => ['label' => 'Aggressive', 'paranoia' => 3],
    ]);

    // PL3 pattern is muted at PL1.
    $this->get('/?x=aggressive-probe')->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(0);

    // Raise the level and it fires.
    config()->set('waf.paranoia_level', 3);
    $this->get('/?x=aggressive-probe')->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(1);
});
