<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Events\RequestBlocked;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;

it('logs a repeated identical threat only once within the dedup window', function () {
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get($q)->assertOk();
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('bumps the hit counter on a deduplicated finding instead of dropping it', function () {
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get($q)->assertOk();
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect((int) $log->hit_count)->toBe(3);
});

it('surfaces a single-attack flood as a rapid attacker via hit_count', function () {
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    // 12 identical hits collapse to one row (hit_count 12). Counting rows would
    // see 1 and miss it; SUM(hit_count) surfaces the volume.
    for ($i = 0; $i < 12; $i++) {
        $this->get($q)->assertOk();
    }

    expect(DB::table('waf_logs')->count())->toBe(1);

    $found = app(CorrelationAnalyzer::class)->rapidAttackers(windowMinutes: 5, minHits: 10);

    expect($found)->toHaveCount(1)
        ->and($found[0]['ip_address'])->toBe('127.0.0.1')
        ->and((int) $found[0]['hits'])->toBe(12);
});

it('keeps the last duplicate when a burst stops', function () {
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    for ($i = 0; $i < 12; $i++) {
        $this->get($q)->assertOk();
    }

    $this->travel(10)->minutes();
    $log = DB::table('waf_logs')->sole();
    expect((int) $log->hit_count)->toBe(12);
});

it('tallies duplicates under queueing', function () {
    config()->set('queue.default', 'sync');
    config()->set('waf.queue.enabled', true);

    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();
    $this->get($q)->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect((int) $log->hit_count)->toBe(3);
});

it('releases the dedup slot when the log write fails, so the finding is not lost', function () {
    $q = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    // Break the log table so the first write fails silently (the WAF never
    // takes the application down over a storage error) ...
    Schema::rename('waf_logs', 'waf_logs_broken');
    $this->get($q)->assertOk();

    // ... then restore it. The retry within the dedup window must be stored:
    // a slot claimed by a failed write would suppress the finding for the
    // whole window with nothing in the log.
    Schema::rename('waf_logs_broken', 'waf_logs');
    $this->get($q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('logs distinct threats separately', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT 1--"))->assertOk();
    $this->get('/?q='.rawurlencode('<script>alert(1)</script>'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(2);
});

it('does not collapse a new blocked rule set into an excluded finding', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100', 'path_glob' => null, 'is_active' => true,
        'created_at' => now(), 'updated_at' => now(),
    ]);
    app(ExclusionRuleService::class)->refresh();

    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1'))->assertOk();
    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1').'&x='.rawurlencode('<script>alert(1)</script>'))
        ->assertForbidden();

    expect(DB::table('waf_logs')->pluck('action_taken')->all())->toBe(['excluded', 'blocked']);
});

it('announces separate blocks when an extra rule joins the same primary finding', function () {
    config()->set('waf.mode', 'blocking');
    config()->set('waf.block_confidence', 0);
    Event::fake([RequestBlocked::class]);

    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1'))->assertForbidden();
    $this->get('/?q='.rawurlencode('UNION ALL SELECT 1').'&x='.rawurlencode('<script>alert(1)</script>'))
        ->assertForbidden();

    expect(DB::table('waf_logs')->count())->toBe(2);
    Event::assertDispatchedTimes(RequestBlocked::class, 2);
});

it('collapses the same attack across paths by default', function () {
    $q = 'q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get('/alpha?'.$q)->assertOk();
    $this->get('/beta?'.$q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('keeps the same attack per path when dedup_include_path is on', function () {
    config()->set('waf.dedup_include_path', true);
    $q = 'q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get('/alpha?'.$q)->assertOk();
    $this->get('/beta?'.$q)->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(2);
});

it('drops findings below the minimum confidence', function () {
    config()->set('waf.min_confidence', 99);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('keeps findings at or above the minimum confidence', function () {
    config()->set('waf.min_confidence', 1);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});
