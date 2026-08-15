<?php

use Illuminate\Support\Facades\DB;

it('detects a percent-encoded null byte in the query string', function () {
    // Classic extension-check bypass: the %00 truncates the string in a
    // C-based layer, so `passwd%00.jpg` reads as `passwd`.
    $this->get('/?file='.rawurlencode("passwd\0.jpg"))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('protocol')
        ->and($log->rule_ids)->toContain('920270');
});

it('does not flag an ordinary query string', function () {
    $this->get('/?file=avatar.jpg&page=2')->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});
