<?php

use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

it('passes on a correctly installed and wired WAF', function () {
    // The base TestCase creates both tables and registers a `waf`-guarded
    // route, so a clean install should report no failures.
    $this->artisan('waf:doctor')
        ->expectsOutputToContain('WAF middleware is wired up')
        ->assertSuccessful();
});

it('fails when waf appears only in an unused middleware group', function () {
    Route::getFacadeRoot()->setRoutes(new RouteCollection);
    Route::middlewareGroup('unused-waf', ['waf']);
    Route::get('/', fn () => 'ok');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('not applied to any route')
        ->assertFailed();
});

it('fails when the WAF is disabled', function () {
    config()->set('waf.enabled', false);

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('The WAF is disabled')
        ->assertFailed();
});

it('fails when an invalid mode disables blocking', function () {
    config()->set('waf.mode', 'blockign');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('waf.mode must be one of')
        ->assertFailed();
});

it('fails when enabled retention has an invalid age', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 'invalid');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('waf.retention.days must be a positive integer')
        ->assertFailed();
});

it('fails when the log table is missing', function () {
    Schema::drop('waf_logs');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('every finding is being discarded')
        ->assertFailed();
});

it('reports a missing purge watermark table', function () {
    Schema::drop('waf_purge_watermarks');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("The 'waf_purge_watermarks' table is missing")
        ->assertFailed();
});

it('reports a missing durable hit table when asynchronous storage is enabled', function () {
    config()->set('waf.queue.enabled', true);
    config()->set('waf.queue.connection', 'database');
    Schema::drop('waf_hit_events');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("Queued hit counting needs the 'waf_hit_events' table")
        ->assertFailed();
});

it('reports missing columns in a present durable hit table', function () {
    config()->set('waf.queue.enabled', true);
    config()->set('waf.queue.connection', 'database');
    Schema::table('waf_hit_totals', fn ($table) => $table->dropColumn('hit_count'));

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("'waf_hit_totals' is missing hit_count")
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

it('reports a missing target hash column before finding writes fail', function () {
    Schema::table('waf_logs', fn ($table) => $table->dropIndex(['target_hash']));
    Schema::table('waf_logs', fn ($table) => $table->dropColumn('target_hash'));

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('is missing target_hash')
        ->assertFailed();
});

it('reports a rule-id column that cannot hold many matches', function () {
    Schema::table('waf_logs', function ($table) {
        $table->string('rule_ids')->nullable()->change();
    });

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('too short')
        ->assertFailed();
});

it('reports a numeric user ID column that cannot store UUIDs', function () {
    Schema::table('waf_logs', fn ($table) => $table->unsignedBigInteger('user_id')->nullable()->change());

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('cannot store UUID or string user IDs')
        ->assertFailed();
});

it('warns when exclusion creators cannot use UUIDs', function () {
    Schema::table('waf_exclusion_rules', fn ($table) => $table->unsignedBigInteger('created_by_user_id')->nullable()->change());

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("'waf_exclusion_rules.created_by_user_id' cannot store UUID or string user IDs")
        ->assertSuccessful();
});

it('checks the separate rate limiter cache store', function () {
    config()->set('cache.default', 'redis');
    config()->set('cache.limiter', 'array');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("Cache store 'redis' (cache.default) supports bans and dedup")
        ->expectsOutputToContain("Cache store 'array' (cache.limiter) is per-process — flood counters and ban strikes reset between requests")
        ->assertSuccessful();
});

it('keeps the default cache warning separate from a healthy rate limiter', function () {
    config()->set('cache.default', 'array');
    config()->set('cache.limiter', 'redis');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("Cache store 'array' (cache.default) is per-process — bans and dedup reset between requests")
        ->expectsOutputToContain("Cache store 'redis' (cache.limiter) supports flood counters and ban strikes")
        ->assertSuccessful();
});

it('fails when a cache store is not configured', function (string $setting) {
    config()->set($setting, 'missing-waf-store');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("Cache store 'missing-waf-store' ({$setting}) is not configured")
        ->assertFailed();
})->with(['cache.default', 'cache.limiter']);

it('fails when a configured cache store has an unknown driver', function () {
    config()->set('cache.stores.broken-waf-store', ['driver' => 'missing-waf-driver']);
    config()->set('cache.default', 'broken-waf-store');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("Cache store 'broken-waf-store' (cache.default) cannot be resolved")
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

it('reports a missing attempt table when variant recording is enabled', function () {
    config()->set('waf.attempts.enabled', true);
    Schema::drop('waf_attempts');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("'waf_attempts' is missing")
        ->assertFailed();
});

it('reports a missing app key when variant recording is enabled', function () {
    config()->set('waf.attempts.enabled', true);
    config()->set('app.key', '');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('Attempt recording needs APP_KEY')
        ->assertFailed();
});

it('reports a missing app key when target redaction is enabled', function () {
    config()->set('app.key', '');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('APP_KEY is required for keyed hashes of redacted WAF targets')
        ->assertFailed();
});

it('warns when attempt recording has no scheduled purge', function () {
    config()->set('waf.attempts.enabled', true);
    config()->set('waf.retention.enabled', false);

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('Attempt recording is enabled without scheduled retention')
        ->assertSuccessful();
});

it('does not warn about attempt retention when scheduled purge is enabled', function () {
    config()->set('waf.attempts.enabled', true);
    config()->set('waf.retention.enabled', true);

    $this->artisan('waf:doctor')
        ->doesntExpectOutputToContain('Attempt recording is enabled without scheduled retention')
        ->assertSuccessful();
});

it('warns when the HTTP kernel trusts every proxy', function () {
    $this->app->make(HttpKernel::class)->prependMiddleware(TrustProxies::class);
    TrustProxies::at('*');

    try {
        $this->artisan('waf:doctor')
            ->expectsOutputToContain('WAF IP decisions may use spoofed X-Forwarded-For')
            ->assertSuccessful();
    } finally {
        TrustProxies::flushState();
    }
});

it('warns when proxy trust comes from configuration', function () {
    $this->app->make(HttpKernel::class)->prependMiddleware(TrustProxies::class);
    config()->set('trustedproxy.proxies', '*');

    $this->artisan('waf:doctor')
        ->expectsOutputToContain('WAF IP decisions may use spoofed X-Forwarded-For')
        ->assertSuccessful();
});

it('does not warn when a specific proxy is trusted', function () {
    $this->app->make(HttpKernel::class)->prependMiddleware(TrustProxies::class);
    config()->set('trustedproxy.proxies', ['192.0.2.1']);

    $this->artisan('waf:doctor')
        ->doesntExpectOutputToContain('WAF IP decisions may use spoofed X-Forwarded-For')
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
