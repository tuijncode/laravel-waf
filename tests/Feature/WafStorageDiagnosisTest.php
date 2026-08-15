<?php

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;

it('explains a missing log table instead of only logging a raw SQL error', function () {
    Log::spy();
    Schema::drop('waf_logs');

    // The write fails inside the middleware, which stays passive — the request
    // still succeeds — but the operator gets a message that names the fix.
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    Log::shouldHaveReceived('error')
        ->withArgs(fn (string $message): bool => str_contains($message, 'findings are being discarded')
            && str_contains($message, 'waf:doctor'))
        ->once();
});

it('explains a missing write column (a stale, un-upgraded schema)', function () {
    Log::spy();
    Schema::table('waf_logs', function ($table) {
        $table->dropColumn('confidence_label');
    });

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    Log::shouldHaveReceived('error')
        ->withArgs(fn (string $message): bool => str_contains($message, 'confidence_label')
            && str_contains($message, 'waf-migrations-upgrade'))
        ->once();
});

it('explains the storage failure only once within the window', function () {
    Log::spy();
    Schema::drop('waf_logs');

    // Two distinct findings so the per-finding dedup does not collapse them;
    // the explanation itself is throttled independently and should appear once.
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $this->get('/?x='.rawurlencode('<script>alert(1)</script>'))->assertOk();

    Log::shouldHaveReceived('error')
        ->withArgs(fn (string $message): bool => str_contains($message, 'findings are being discarded'))
        ->once();
});
