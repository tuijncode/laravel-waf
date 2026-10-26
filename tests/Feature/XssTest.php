<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tuijncode\LaravelWaf\Events\ThreatDetected;

// http://localhost:8000/?q=<script>alert(1)</script>
it('detects and logs a cross-site scripting attempt', function () {
    Event::fake([ThreatDetected::class]);

    $response = $this->get('/?q='.rawurlencode('<script>alert(1)</script>'));

    $response->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('xss')
        ->and($log->threat_level)->toBe('critical')
        ->and($log->rule_ids)->toContain('941100');

    Event::assertDispatched(ThreatDetected::class, function (ThreatDetected $event) {
        return in_array('941100', $event->result->ruleIds(), true);
    });
});

it('does not treat a longer element name as a script tag', function () {
    $this->get('/?q='.rawurlencode('<scripted>safe</scripted>'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});
