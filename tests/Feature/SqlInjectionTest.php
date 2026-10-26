<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tuijncode\LaravelWaf\Events\ThreatDetected;
use Tuijncode\LaravelWaf\Support\TargetHash;

// http://localhost:8000/?q=' UNION SELECT * FROM users--
it('detects and logs a SQL injection attempt', function () {
    Event::fake([ThreatDetected::class]);

    $response = $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"));

    // Detection mode never interferes with the response.
    $response->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('sqli')
        ->and($log->threat_level)->toBe('critical')
        ->and($log->rule_ids)->toContain('942100')
        ->and($log->target_hash)->toBe(TargetHash::fromUrl('http://localhost/'))
        ->and($log->confidence_score)->toBeGreaterThanOrEqual(40);

    Event::assertDispatched(ThreatDetected::class, function (ThreatDetected $event) {
        return $event->result->confidenceScore() > 0
            && in_array('942100', $event->result->ruleIds(), true);
    });
});
