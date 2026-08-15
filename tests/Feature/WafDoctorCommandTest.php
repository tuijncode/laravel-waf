<?php

use Illuminate\Support\Facades\Schema;

it('passes on a correctly installed and wired WAF', function () {
    // The base TestCase creates both tables and registers a `waf`-guarded
    // route, so a clean install should report no failures.
    $this->artisan('waf:doctor')
        ->expectsOutputToContain('WAF middleware is wired up')
        ->assertSuccessful();
});

it('fails when the WAF is disabled', function () {
    config()->set('waf.enabled', false);

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('The WAF is disabled')
        ->assertFailed();
});

it('fails when the log table is missing', function () {
    Schema::drop('waf_logs');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('every finding is being discarded')
        ->assertFailed();
});

it('warns when a required write column is missing', function () {
    Schema::table('waf_logs', function ($table) {
        $table->dropColumn('confidence_label');
    });

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('is missing confidence_label')
        ->assertFailed();
});

it('warns when the exclusion table is missing but does not fail', function () {
    Schema::drop('waf_exclusion_rules');

    // A missing exclusion table is a warning (detection still records), so the
    // command still exits zero.
    $this->artisan('waf:doctor')
        ->expectsOutputToContain("No 'waf_exclusion_rules' table")
        ->assertSuccessful();
});

it('reports a stale published pattern pack that is missing shipped signatures', function () {
    $path = config_path('waf-patterns.php');
    @mkdir(dirname($path), 0777, true);

    // A published pack frozen with only one old signature — every signature
    // shipped since is absent, so the doctor should flag drift.
    file_put_contents($path, "<?php\n\nreturn ['custom' => ['/legacy/i' => 'Legacy Only']];\n");

    try {
        $this->artisan('waf:doctor')
            ->expectsOutputToContain('Published pattern pack is missing')
            ->assertSuccessful();
    } finally {
        @unlink($path);
    }
});
