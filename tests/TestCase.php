<?php

namespace Tuijncode\LaravelWaf\Tests;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Tuijncode\LaravelWaf\WafServiceProvider;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        if (in_array(getenv('WAF_TEST_DB_DRIVER'), ['mysql', 'pgsql'], true)) {
            $database = (string) config('database.connections.testing.database');
            if (getenv('WAF_TEST_RESET_DB') !== '1' || ! str_ends_with($database, '_test')) {
                throw new \RuntimeException('WAF database tests require WAF_TEST_RESET_DB=1 and a dedicated database ending in _test.');
            }
            foreach (['waf_hit_events', 'waf_hit_totals', 'waf_purge_watermarks', 'waf_exclusion_rules', 'waf_attempts', 'waf_logs'] as $table) {
                Schema::dropIfExists($table);
            }
        }

        $this->createWafLogsTable();
        $this->createWafExclusionRulesTable();
        $this->createWafAttemptsTable();
        (require __DIR__.'/../database/migrations/create_waf_hit_events_table.php.stub')->up();
        (require __DIR__.'/../database/migrations/create_waf_hit_totals_table.php.stub')->up();
        (require __DIR__.'/../database/migrations/create_waf_purge_watermarks_table.php.stub')->up();

        // A catch-all route guarded by the WAF middleware so feature tests can
        // fire attack payloads at any path.
        Route::middleware('waf')->any('/{path?}', fn () => 'ok')->where('path', '.*');
    }

    protected function getPackageProviders($app): array
    {
        return [WafServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $driver = getenv('WAF_TEST_DB_DRIVER');
        $app['config']->set('database.connections.testing', $driver === 'mysql' || $driver === 'pgsql'
            ? [
                'driver' => $driver,
                'host' => getenv('WAF_TEST_DB_HOST') ?: '127.0.0.1',
                'port' => getenv('WAF_TEST_DB_PORT') ?: ($driver === 'mysql' ? 3306 : 5432),
                'database' => getenv('WAF_TEST_DB_NAME') ?: 'waf_test',
                'username' => getenv('WAF_TEST_DB_USER') ?: 'waf_test',
                'password' => getenv('WAF_TEST_DB_PASSWORD') ?: 'waf_test',
                'prefix' => '',
            ]
            : [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ]);

        // The array cache supports atomic increments (needed by DDoS + dedup).
        $app['config']->set('cache.default', 'array');
        $app['config']->set('app.key', '0123456789abcdef0123456789abcdef');

        $app['config']->set('waf.enabled', true);
        $app['config']->set('waf.enabled_environments', null);
        $app['config']->set('waf.mode', 'detection');
        $app['config']->set('waf.table_name', 'waf_logs');
        $app['config']->set('waf.whitelisted_ips', []);
        $app['config']->set('waf.min_confidence', 10);
    }

    protected function createWafLogsTable(): void
    {
        Schema::create('waf_logs', function (Blueprint $table) {
            $table->id();
            $table->uuid('event_id')->nullable()->unique();
            $table->string('ip_address')->index();
            $table->string('method', 10)->nullable();
            $table->text('url');
            $table->string('target_hash', 64)->nullable()->index();
            $table->string('user_agent', 500)->nullable();
            $table->text('type');
            $table->string('category', 30)->index();
            $table->text('rule_ids')->nullable();
            $table->text('payload')->nullable();
            $table->string('threat_level', 20)->default('notice')->index();
            $table->unsignedSmallInteger('anomaly_score')->default(0);
            $table->unsignedTinyInteger('confidence_score')->default(0)->index();
            $table->string('confidence_label', 20)->default('none');
            $table->string('action_taken', 20)->default('logged');
            $table->unsignedInteger('hit_count')->default(1);
            $table->string('user_id', 191)->nullable()->index();
            $table->timestamps();
            $table->index('created_at');
        });
    }

    protected function createWafExclusionRulesTable(): void
    {
        Schema::create('waf_exclusion_rules', function (Blueprint $table) {
            $table->id();
            $table->string('match_label');
            $table->string('path_glob')->nullable();
            $table->unsignedBigInteger('source_log_id')->nullable();
            $table->string('created_by_user_id', 191)->nullable();
            $table->text('reason')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->timestamps();
        });
    }

    protected function createWafAttemptsTable(): void
    {
        $migration = require __DIR__.'/../database/migrations/create_waf_attempts_table.php.stub';
        $migration->up();
    }
}
