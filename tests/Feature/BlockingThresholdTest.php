<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;
use Tuijncode\LaravelWaf\Services\InspectionResult;
use Tuijncode\LaravelWaf\Services\WafInspector;

beforeEach(fn () => config()->set('waf.mode', 'blocking'));

it('blocks a high-confidence request', function () {
    config()->set('waf.block_confidence', 40);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), [
        'User-Agent' => 'sqlmap/1.7',
    ])->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('logs but lets through a finding below the block threshold', function () {
    config()->set('waf.block_confidence', 90);

    // An open-redirect probe scores in the medium band — logged, not blocked.
    $this->get('/?next=//evil.example')->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('blocks a decisive probe outright, below the default threshold', function () {
    config()->set('waf.block_confidence', 60);

    // A bare `.env` fetch from an ordinary client scores 37 on the anomaly math
    // alone — but the rule is decisive, so it is forced to 100 and blocked.
    $response = $this->get('/.env')->assertForbidden();

    $log = DB::table('waf_logs')->sole();
    expect($log->confidence_score)->toBe(100)
        ->and($log->action_taken)->toBe('blocked');
});

it('never blocks in detection mode', function () {
    config()->set('waf.mode', 'detection');
    config()->set('waf.block_confidence', 0);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"), [
        'User-Agent' => 'sqlmap/1.7',
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('logs but does not block a flood while ddos.block is off', function () {
    config()->set('waf.ddos.threshold', 2);
    config()->set('waf.ddos.block', false);

    // A pure flood scores 25 — below block_confidence — so it is only logged.
    $this->get('/?q=hi')->assertOk();
    $this->get('/?q=hi')->assertOk();
    $this->get('/?q=hi')->assertOk(); // 3 > 2

    $log = DB::table('waf_logs')->where('category', 'ddos')->first();
    expect($log)->not->toBeNull()
        ->and($log->action_taken)->toBe('logged');
});

it('blocks a flood on the volumetric signal when ddos.block is on', function () {
    config()->set('waf.ddos.threshold', 2);
    config()->set('waf.ddos.block', true);
    config()->set('waf.block_confidence', 60); // flood scores well under this

    $this->get('/?q=hi')->assertOk();
    $this->get('/?q=hi')->assertOk();

    // The next over-budget request is refused on the flood signal alone, with
    // a Retry-After matching the ddos window.
    $this->get('/?q=hi')
        ->assertForbidden()
        ->assertHeader('Retry-After', (string) config('waf.ddos.window'));

    expect(DB::table('waf_logs')->where('category', 'ddos')->where('action_taken', 'blocked')->count())
        ->toBeGreaterThan(0);
});

it('does not scan requests after the flood block threshold', function () {
    config()->set('waf.ddos.threshold', 1);
    config()->set('waf.ddos.block', true);
    $inspector = new class extends WafInspector
    {
        public int $scans = 0;

        public function inspect(Request $request): InspectionResult
        {
            $this->scans++;

            return parent::inspect($request);
        }
    };
    $this->app->instance(WafInspector::class, $inspector);

    $this->get('/?q=hi')->assertOk();
    $this->get('/?q=hi')->assertForbidden();
    $this->get('/?q=hi')->assertForbidden();

    expect($inspector->scans)->toBe(1)
        ->and(DB::table('waf_logs')->where('category', 'ddos')->value('hit_count'))->toBe(2);
});

it('redacts unscanned flood evidence before storing it', function () {
    config()->set('waf.ddos.threshold', 1);
    config()->set('waf.ddos.block', true);

    $this->get('/?q=hi')->assertOk();
    $this->get('/?q=AKIAIOSFODNN7EXAMPLE')->assertForbidden();

    $log = DB::table('waf_logs')->where('category', 'ddos')->sole();
    expect($log->url)->toBe('[REDACTED]')
        ->and($log->payload)->toBe('[REDACTED]')
        ->and($log->user_agent)->toBe('[REDACTED]');
});

it('still scans a flood when its signal is excluded', function () {
    config()->set('waf.ddos.threshold', 1);
    config()->set('waf.ddos.block', true);
    app(ExclusionRuleService::class)->add('912100');

    $this->get('/?q=hi')->assertOk();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertForbidden();

    expect(DB::table('waf_logs')->where('action_taken', 'blocked')->value('rule_ids'))
        ->toContain('942100');
});

it('still scans when the flood alone is below the minimum confidence', function () {
    config()->set('waf.ddos.threshold', 1);
    config()->set('waf.ddos.block', true);
    config()->set('waf.min_confidence', 30);

    $this->get('/?q=hi')->assertOk();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertForbidden();

    expect(DB::table('waf_logs')->where('action_taken', 'blocked')->value('rule_ids'))
        ->toContain('942100');
});
