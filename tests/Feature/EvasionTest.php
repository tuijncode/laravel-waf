<?php

use Illuminate\Support\Facades\DB;

it('sees through HTML-entity-encoded XSS', function () {
    $this->get('/?q='.rawurlencode('&lt;script&gt;alert(1)&lt;/script&gt;'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('941100');
});

it('sees through double URL-encoding', function () {
    // %253Cscript%253E → %3Cscript%3E → <script>
    $this->get('/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('941100');
});

it('sees through IIS %u-encoded XSS', function () {
    // %u003c / %u003e are the IIS Unicode forms of < and > — ordinary percent
    // decoding leaves them intact, so without the %u pass the payload hides.
    $this->get('/?q=%u003cscript%u003ealert(1)%u003c%u002fscript%u003e')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('941100');
});

it('sees through backslash-u escaped XSS', function () {
    // chr(92) is a backslash, so $u is the two characters backslash-u. The
    // payload is the JS/JSON unicode-escape form of <script>alert(1)</script>
    // (each angle bracket written as a backslash-u escape). Without the
    // backslash-escape decoding pass the signature never sees the tags.
    $u = chr(92).'u';
    $payload = $u.'003cscript'.$u.'003ealert(1)'.$u.'003c/script'.$u.'003e';

    $this->get('/?q='.rawurlencode($payload))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('941100');
});

it('sees through backslash-x escaped traversal', function () {
    // \x2e\x2e\x2f decodes to ../
    $this->get('/?file='.rawurlencode('\x2e\x2e\x2fetc\x2fpasswd'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('930110');
});

it('repeats decoding when a backslash escape reveals URL encoding', function () {
    // The first pass turns \x25 into %, and the next turns %3C into <.
    $this->get('/?q='.rawurlencode('\x253Cscript\x253Ealert(1)\x253C/script\x253E'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('941100');
});

it('sees through null-byte splitting', function () {
    // /etc/pass\0wd — the null byte splits the signature until it is stripped.
    $this->get('/?file=/etc/pass%00wd')->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('930110');
});

it('sees through inline SQL-comment evasion at paranoia level 1', function () {
    // At PL1 the broad comment-sequence rule (942170) is off, and 942100 needs
    // whitespace between UNION and SELECT — so UNION/**/SELECT slips through
    // unless the comment is normalised away first.
    config()->set('waf.paranoia_level', 1);

    $this->get('/?q='.rawurlencode('UNION/**/SELECT password FROM users'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('942100');
});

it('sees through a MySQL executable comment', function () {
    config()->set('waf.paranoia_level', 1);

    // /*!50000UNION*/ executes as UNION in MySQL; keeping the inner keyword
    // exposes the UNION SELECT to rule 942100.
    $this->get('/?q='.rawurlencode('/*!50000UNION*/ SELECT pw FROM users'))->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('942100');
});

it('does not fabricate a match from a benign block comment', function () {
    // A comment between two harmless words must not normalise into a signature.
    config()->set('waf.paranoia_level', 1);

    $this->get('/?note='.rawurlencode('total/**/amount'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('sees an attack pushed past the surface cap by padding', function () {
    // 20k of junk ahead of the payload would hide it behind a hard truncation;
    // head + tail sampling keeps the end of the body in view.
    $this->post('/', [
        'pad' => str_repeat('a', 20000),
        'q' => "' UNION SELECT * FROM users--",
    ])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->rule_ids)->toContain('942100');
});
