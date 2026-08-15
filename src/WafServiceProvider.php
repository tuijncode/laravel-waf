<?php

namespace Tuijncode\LaravelWaf;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use Tuijncode\LaravelWaf\Console\Commands\PurgeWafLogsCommand;
use Tuijncode\LaravelWaf\Console\Commands\WafCorrelateCommand;
use Tuijncode\LaravelWaf\Console\Commands\WafDoctorCommand;
use Tuijncode\LaravelWaf\Console\Commands\WafExportCommand;
use Tuijncode\LaravelWaf\Console\Commands\WafStatsCommand;
use Tuijncode\LaravelWaf\Console\Commands\WafTestCommand;
use Tuijncode\LaravelWaf\Console\Commands\WafUnbanCommand;
use Tuijncode\LaravelWaf\Http\Middleware\WafMiddleware;
use Tuijncode\LaravelWaf\Services\AutoBanManager;
use Tuijncode\LaravelWaf\Services\BotDetector;
use Tuijncode\LaravelWaf\Services\ConfidenceScorer;
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;
use Tuijncode\LaravelWaf\Services\DdosMonitor;
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;
use Tuijncode\LaravelWaf\Services\Redactor;
use Tuijncode\LaravelWaf\Services\ScannerDetector;
use Tuijncode\LaravelWaf\Services\WafInspector;
use Tuijncode\LaravelWaf\Support\ConfigValidator;

class WafServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/waf.php', 'waf');
        $this->mergeConfigFrom(__DIR__.'/../config/waf-patterns.php', 'waf-patterns');

        $this->app->singleton(ConfidenceScorer::class, fn () => new ConfidenceScorer);
        $this->app->singleton(ScannerDetector::class, fn () => new ScannerDetector);
        $this->app->singleton(BotDetector::class, fn () => new BotDetector);
        $this->app->singleton(DdosMonitor::class, fn () => new DdosMonitor);
        $this->app->singleton(ExclusionRuleService::class, fn () => new ExclusionRuleService);
        $this->app->singleton(Redactor::class, fn () => new Redactor);
        $this->app->singleton(AutoBanManager::class, fn () => new AutoBanManager);
        $this->app->singleton(CorrelationAnalyzer::class, fn () => new CorrelationAnalyzer);

        $this->app->singleton('laravel-waf', function ($app) {
            return new WafInspector(
                $app->make(ConfidenceScorer::class),
                $app->make(ScannerDetector::class),
                $app->make(BotDetector::class),
                $app->make(DdosMonitor::class),
                $app->make(ExclusionRuleService::class),
                $app->make(Redactor::class),
            );
        });

        $this->app->alias('laravel-waf', WafInspector::class);
    }

    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerMiddleware();
        $this->registerCommands();
        $this->registerSchedule();
        $this->validateConfiguration();
    }

    /**
     * Surface configuration mistakes as log warnings, throttled to once an hour
     * per distinct problem set so a persistent misconfig never floods the log.
     */
    protected function validateConfiguration(): void
    {
        if (! config('waf.validate_config', true)) {
            return;
        }

        $problems = (new ConfigValidator)->validate();
        if ($problems === []) {
            return;
        }

        try {
            $key = 'laravel-waf:config-warned:'.md5(implode('|', $problems));
            if (! Cache::add($key, true, now()->addHour())) {
                return;
            }
        } catch (\Throwable) {
            // Cache unavailable — fall through and log anyway.
        }

        foreach ($problems as $problem) {
            Log::warning('laravel-waf: '.$problem);
        }
    }

    protected function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        // Each file is published individually so users can pull the main config
        // and the pattern pack apart, while 'waf-config' still publishes both.
        $this->publishes([
            __DIR__.'/../config/waf.php' => config_path('waf.php'),
        ], ['waf-config', 'waf-config-main']);

        $this->publishes([
            __DIR__.'/../config/waf-patterns.php' => config_path('waf-patterns.php'),
        ], ['waf-config', 'waf-config-patterns']);

        $this->publishes([
            __DIR__.'/../database/migrations/create_waf_logs_table.php.stub' => $this->migrationPath('create_waf_logs_table'),
            __DIR__.'/../database/migrations/create_waf_exclusion_rules_table.php.stub' => $this->migrationPath('create_waf_exclusion_rules_table', 1),
        ], 'waf-migrations');

        // Upgrade migration for installs that already ran the create migrations
        // on an earlier version. Published on its own tag so a fresh install
        // (whose create migration already has these columns) isn't handed it.
        $this->publishes([
            __DIR__.'/../database/migrations/upgrade_waf_logs_table.php.stub' => $this->migrationPath('upgrade_waf_logs_table', 2),
        ], 'waf-migrations-upgrade');
    }

    /**
     * Target path for a published migration. A migration published earlier
     * (under a then-current timestamp) keeps its filename, so re-running
     * vendor:publish skips it (or overwrites in place under --force) instead
     * of minting a duplicate copy with a fresh timestamp.
     */
    protected function migrationPath(string $name, int $offset = 0): string
    {
        $existing = glob(database_path('migrations/*_'.$name.'.php')) ?: [];

        if ($existing !== []) {
            return $existing[0];
        }

        return database_path('migrations/'.date('Y_m_d_His', time() + $offset).'_'.$name.'.php');
    }

    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('waf', WafMiddleware::class);
    }

    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                PurgeWafLogsCommand::class,
                WafStatsCommand::class,
                WafCorrelateCommand::class,
                WafUnbanCommand::class,
                WafTestCommand::class,
                WafExportCommand::class,
                WafDoctorCommand::class,
            ]);
        }
    }

    protected function registerSchedule(): void
    {
        if (! config('waf.retention.enabled', false)) {
            return;
        }

        $this->app->booted(function () {
            if (! class_exists(Schedule::class)) {
                return;
            }

            $days = (int) config('waf.retention.days', 90);

            $this->app->make(Schedule::class)
                ->command("waf:purge --days={$days}")
                ->daily()
                ->at('02:00')
                ->withoutOverlapping()
                ->runInBackground();
        });
    }
}
