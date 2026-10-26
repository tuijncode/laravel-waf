<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Http\Middleware\WafMiddleware;
use Tuijncode\LaravelWaf\Support\ConfigValidator;
use Tuijncode\LaravelWaf\Support\UserIdColumnType;

/**
 * Checks that the WAF is actually working, not merely installed.
 *
 * Every check corresponds to a way a WAF fails silently: a log table that
 * predates an upgrade migration (every finding discarded on insert), a
 * middleware that was never wired to a route (nothing inspected), a config
 * published two versions ago that shadows the pattern pack shipped since, a
 * cache driver that can't count floods. None of them raise an error anyone
 * would notice — the log just stays empty, which reads as "no attacks" rather
 * than "nothing is being recorded".
 *
 * Exits non-zero only on a real failure, so it can sit in CI or a deploy step.
 */
class WafDoctorCommand extends Command
{
    protected $signature = 'waf:doctor';

    protected $description = 'Check that the WAF is installed, wired up and recording';

    /** Columns the finding writer inserts. Missing any one discards every finding. */
    private const WRITE_COLUMNS = [
        'event_id', 'ip_address', 'method', 'url', 'target_hash', 'user_agent', 'type',
        'category', 'rule_ids', 'payload', 'threat_level', 'anomaly_score',
        'confidence_score', 'confidence_label', 'action_taken', 'hit_count',
        'user_id', 'created_at', 'updated_at',
    ];

    private int $failures = 0;

    private int $warnings = 0;

    public function handle(): int
    {
        $this->newLine();
        $this->line('  <fg=white;options=bold>Laravel WAF — health check</>');
        $this->line('  <fg=gray>mode: '.config('waf.mode', 'detection')
            .' · paranoia: '.config('waf.paranoia_level', 2)
            .' · on_error: '.config('waf.on_error', 'open')
            .' · cache: '.config('cache.default').'</>');
        $this->newLine();

        $this->checkEnabled();
        $this->checkConfigSanity();
        $this->checkWriteSchema();
        $this->checkPurgeWatermark();
        $this->checkHitTable();
        $this->checkAttemptTable();
        $this->checkExclusionTable();
        $this->checkMiddleware();
        $this->checkProxyTrust();
        $this->checkAttemptRetention();
        $this->checkConfigDrift();
        $this->checkCacheDriver();

        return $this->summarise();
    }

    // ── checks ──────────────────────────────────────────────────────────────

    private function checkEnabled(): void
    {
        if (! config('waf.enabled', true)) {
            $this->reportFailure('The WAF is disabled', 'Set WAF_ENABLED=true in your .env.');

            return;
        }

        $environments = config('waf.enabled_environments');
        $current = (string) $this->laravel->environment();

        if (! empty($environments) && ! in_array($current, (array) $environments, true)) {
            $this->reportFailure(
                "The WAF is off in this environment ('{$current}')",
                "Add '{$current}' to waf.enabled_environments, or set it to null to run everywhere."
            );

            return;
        }

        $this->reportPass('The WAF is enabled for this environment');
    }

    /**
     * The boot-time validator logs these as warnings, but a log line is easy to
     * miss — and a typo'd WAF_MODE silently drops the firewall to detection.
     */
    private function checkConfigSanity(): void
    {
        $problems = (new ConfigValidator)->validate();

        if ($problems === []) {
            $this->reportPass('Configuration values are sane');

            return;
        }

        foreach ($problems as $problem) {
            $this->reportFailure($problem, 'Correct the configured value.');
        }
    }

    private function checkWriteSchema(): void
    {
        $table = (string) config('waf.table_name', 'waf_logs');

        if (! $this->tableExists($table)) {
            $this->reportFailure(
                "The '{$table}' table does not exist — every finding is being discarded",
                'Run: php artisan vendor:publish --tag=waf-migrations && php artisan migrate'
            );

            return;
        }

        $missing = $this->missingColumns($table, self::WRITE_COLUMNS);

        if ($missing !== []) {
            $this->reportFailure(
                "'{$table}' is missing ".implode(', ', $missing).' — every finding is being discarded',
                'Run: php artisan vendor:publish --tag=waf-migrations-upgrade && php artisan migrate'
            );

            return;
        }

        $ruleIdsType = strtolower(Schema::getColumnType($table, 'rule_ids', true));
        if (! str_contains($ruleIdsType, 'text') && ! str_contains($ruleIdsType, 'max')) {
            $this->reportFailure(
                "'{$table}.rule_ids' is too short for findings with many matched rules",
                'Run: php artisan vendor:publish --tag=waf-migrations-upgrade && php artisan migrate'
            );

            return;
        }

        if (! UserIdColumnType::acceptsStrings(Schema::getColumnType($table, 'user_id', true))) {
            $this->reportFailure(
                "'{$table}.user_id' cannot store UUID or string user IDs",
                'Run: php artisan vendor:publish --tag=waf-migrations-upgrade && php artisan migrate'
            );

            return;
        }

        $this->reportPass("'{$table}' has every column the writer needs");
    }

    private function checkExclusionTable(): void
    {
        if (! $this->tableExists('waf_exclusion_rules')) {
            $this->reportWarning(
                "No 'waf_exclusion_rules' table — exclusion rules can't be stored (detection is unaffected)",
                'Run: php artisan vendor:publish --tag=waf-migrations && php artisan migrate'
            );

            return;
        }

        $type = Schema::hasColumn('waf_exclusion_rules', 'created_by_user_id')
            ? Schema::getColumnType('waf_exclusion_rules', 'created_by_user_id', true) : '';
        if (! UserIdColumnType::acceptsStrings($type)) {
            $this->reportWarning(
                "'waf_exclusion_rules.created_by_user_id' cannot store UUID or string user IDs",
                'Run: php artisan vendor:publish --tag=waf-migrations-upgrade && php artisan migrate'
            );

            return;
        }

        $this->reportPass('Exclusion rules table is present');
    }

    private function checkPurgeWatermark(): void
    {
        if (! $this->tableExists('waf_purge_watermarks')) {
            $this->reportFailure(
                "The 'waf_purge_watermarks' table is missing — old queued findings can return after a purge",
                'Run: php artisan vendor:publish --tag=waf-migrations-upgrade && php artisan migrate'
            );

            return;
        }

        $missing = $this->missingColumns('waf_purge_watermarks', ['table_name', 'purged_before']);
        if ($missing !== []) {
            $this->reportFailure(
                "'waf_purge_watermarks' is missing ".implode(', ', $missing),
                'Run the published purge-watermark migration.'
            );

            return;
        }

        $this->reportPass('Purge watermark table is present');
    }

    private function checkHitTable(): void
    {
        $connection = config('waf.queue.connection') ?? config('queue.default');
        if (! config('waf.queue.enabled', false)
            || config("queue.connections.{$connection}.driver", $connection) === 'sync') {
            return;
        }

        $complete = true;
        foreach ([
            'waf_hit_events' => ['id', 'event_id', 'created_at'],
            'waf_hit_totals' => ['event_id', 'hit_count', 'updated_at'],
        ] as $table => $columns) {
            if (! $this->tableExists($table)) {
                $complete = false;
                $this->reportFailure(
                    "Queued hit counting needs the '{$table}' table",
                    'Run: php artisan vendor:publish --tag=waf-migrations-upgrade && php artisan migrate'
                );

                continue;
            }

            $missing = $this->missingColumns($table, $columns);
            if ($missing !== []) {
                $complete = false;
                $this->reportFailure(
                    "Queued hit counting: '{$table}' is missing ".implode(', ', $missing),
                    'Restore the missing columns from the published migration, then rerun waf:doctor.'
                );
            }
        }

        if ($complete) {
            $this->reportPass('Queued hit-count tables are complete');
        }
    }

    private function checkAttemptTable(): void
    {
        if (! config('waf.attempts.enabled', false)) {
            return;
        }

        if ((string) config('app.key', '') === '') {
            $this->reportFailure('Attempt recording needs APP_KEY', 'Set APP_KEY before enabling WAF_ATTEMPTS.');

            return;
        }

        $table = (string) config('waf.attempts.table', 'waf_attempts');
        if (! $this->tableExists($table)) {
            $this->reportFailure(
                "Attempt recording is enabled but '{$table}' is missing",
                'Run: php artisan vendor:publish --tag=waf-migrations-attempts && php artisan migrate'
            );

            return;
        }

        $missing = $this->missingColumns($table, ['ip_address', 'rule_id', 'fingerprint', 'variant', 'window_id', 'created_at']);
        if ($missing !== []) {
            $this->reportFailure("'{$table}' is missing ".implode(', ', $missing), 'Run the attempt-table migration.');

            return;
        }

        $this->reportPass('Attempt variant table is ready');
    }

    private function checkMiddleware(): void
    {
        if (! $this->middlewareIsWired()) {
            $this->reportFailure(
                'The WAF middleware is not applied to any route — no request is being inspected',
                "Add the 'waf' alias (or ".WafMiddleware::class.') to your routes, a middleware group, or the global stack.'
            );

            return;
        }

        $this->reportPass('WAF middleware is wired up');
    }

    private function checkProxyTrust(): void
    {
        try {
            $kernel = $this->laravel->make(HttpKernel::class);
            foreach ($kernel->getGlobalMiddleware() as $middleware) {
                if (! is_string($middleware) || ! is_a($middleware, TrustProxies::class, true)) {
                    continue;
                }

                $proxies = (new \ReflectionMethod($middleware, 'proxies'))
                    ->invoke($this->laravel->make($middleware)) ?: config('trustedproxy.proxies');
                $configured = is_string($proxies) ? explode(',', $proxies) : (array) $proxies;

                if (array_intersect(['*', '**'], array_map('trim', $configured)) !== []) {
                    $this->reportWarning(
                        'TrustProxies trusts any connecting proxy; WAF IP decisions may use spoofed X-Forwarded-For',
                        'Ensure the app is reachable only through your proxy, or configure its trusted IP addresses.'
                    );

                    return;
                }
            }
        } catch (\Throwable) {
            // An unreadable proxy setup cannot be diagnosed reliably.
        }
    }

    private function checkAttemptRetention(): void
    {
        if (config('waf.attempts.enabled', false) && ! config('waf.retention.enabled', false)) {
            $this->reportWarning(
                'Attempt recording is enabled without scheduled retention; variant rows will accumulate',
                'Set WAF_RETENTION=true and run Laravel scheduler, or run waf:purge regularly.'
            );
        }
    }

    /**
     * mergeConfigFrom merges top-level keys only, and a published file wins
     * outright for every key it defines. A config published before an option
     * (or a pattern-pack signature) existed silently keeps the old behaviour.
     */
    private function checkConfigDrift(): void
    {
        $this->checkMainConfigDrift();
        $this->checkPatternPackDrift();
    }

    private function checkMainConfigDrift(): void
    {
        $published = config_path('waf.php');

        if (! file_exists($published)) {
            $this->reportPass('Main config: using package defaults (nothing published)');

            return;
        }

        $theirs = $this->loadConfigFile($published);
        $ours = $this->loadConfigFile(__DIR__.'/../../../config/waf.php');

        if ($theirs === null || $ours === null) {
            $this->reportWarning('Could not read the published waf.php for comparison', "Check {$published} returns an array.");

            return;
        }

        $missing = array_diff($this->settingKeys($ours), $this->settingKeys($theirs));

        if ($missing === []) {
            $this->reportPass('Published waf.php knows every option of this version');

            return;
        }

        $this->reportWarning(
            'Published waf.php predates '.count($missing).' option(s): '.implode(', ', $missing),
            'Those run on package defaults. Re-publish with --force after backing up, or hand-merge.'
        );
    }

    /**
     * The dangerous form of drift: the pattern pack is one top-level `custom`
     * key, so a published copy freezes the whole pack — every signature shipped
     * after publication simply never loads, with nothing logged anywhere.
     */
    private function checkPatternPackDrift(): void
    {
        $published = config_path('waf-patterns.php');

        if (! file_exists($published)) {
            $this->reportPass('Pattern pack: using the shipped pack (nothing published)');

            return;
        }

        $theirs = $this->loadConfigFile($published);
        $ours = $this->loadConfigFile(__DIR__.'/../../../config/waf-patterns.php');

        if ($theirs === null || $ours === null) {
            $this->reportWarning('Could not read the published waf-patterns.php for comparison', "Check {$published} returns an array.");

            return;
        }

        $missing = array_diff_key((array) ($ours['custom'] ?? []), (array) ($theirs['custom'] ?? []));

        if ($missing === []) {
            $this->reportPass('Published pattern pack has every shipped signature');

            return;
        }

        $labels = array_map(
            static fn ($definition): string => is_array($definition)
                ? (string) ($definition['label'] ?? 'unlabelled')
                : (string) $definition,
            array_slice($missing, 0, 3),
        );

        $this->reportWarning(
            'Published pattern pack is missing '.count($missing).' signature(s) shipped since it was published'
            .' (e.g. '.implode(', ', $labels).')',
            'New detections never load — the published copy wins wholesale. Re-publish waf-patterns.php with --force, or hand-merge.'
        );
    }

    private function checkCacheDriver(): void
    {
        $default = (string) config('cache.default');
        $limiter = (string) (config('cache.limiter') ?: $default);
        $stores = ['cache.default' => $default];
        if ($limiter !== $default) {
            $stores['cache.limiter'] = $limiter;
        }

        foreach ($stores as $setting => $store) {
            $definition = $store === 'null' ? ['driver' => 'null'] : config("cache.stores.{$store}");
            if (! is_array($definition) || ! is_string($definition['driver'] ?? null) || $definition['driver'] === '') {
                $this->reportFailure(
                    "Cache store '{$store}' ({$setting}) is not configured",
                    "Define it in cache.stores or change {$setting} to an existing store."
                );

                continue;
            }

            $driver = $definition['driver'];
            try {
                Cache::store($store);
            } catch (\Throwable) {
                $this->reportFailure(
                    "Cache store '{$store}' ({$setting}) cannot be resolved",
                    "Check its driver and dependencies in cache.stores.{$store}."
                );

                continue;
            }

            $role = $setting === 'cache.limiter' ? 'flood counters and ban strikes'
                : ($limiter === $default ? 'flood counters, ban strikes, bans and dedup' : 'bans and dedup');

            switch ($driver) {
                case 'null':
                    $this->reportWarning(
                        "Cache store '{$store}' ({$setting}) stores nothing — {$role} do not persist",
                        "Switch {$setting} to redis, memcached or database."
                    );

                    break;

                case 'array':
                    $this->reportWarning(
                        "Cache store '{$store}' ({$setting}) is per-process — {$role} reset between requests",
                        "Fine in tests; in production switch {$setting} to a shared store."
                    );

                    break;

                case 'file':
                case 'database':
                    $counting = $setting === 'cache.limiter' ? 'flood and strike counting'
                        : ($limiter === $default ? 'flood, strike and dedup counting' : 'dedup counting');
                    $this->reportWarning(
                        "Cache store '{$store}' ({$setting}) has no atomic increment — {$counting} may be approximate under concurrency",
                        "For exact counting switch {$setting} to redis or memcached."
                    );

                    break;

                default:
                    $this->reportPass("Cache store '{$store}' ({$setting}) supports {$role}");
            }
        }
    }

    // ── output ──────────────────────────────────────────────────────────────

    /*
     * Named report* deliberately: Illuminate\Console\Command already defines
     * public warn() and (since Laravel 11) public fail(), and PHP won't let a
     * subclass narrow an inherited method's visibility.
     */

    private function reportPass(string $title): void
    {
        $this->line("  <fg=green>PASS</>  {$title}");
    }

    private function reportWarning(string $title, string $fix): void
    {
        $this->warnings++;
        $this->line("  <fg=yellow>WARN</>  {$title}");
        $this->line("        <fg=gray>{$fix}</>");
    }

    private function reportFailure(string $title, string $fix): void
    {
        $this->failures++;
        $this->line("  <fg=red>FAIL</>  {$title}");
        $this->line("        <fg=gray>{$fix}</>");
    }

    private function summarise(): int
    {
        $this->newLine();

        if ($this->failures > 0) {
            $this->line("  <fg=red;options=bold>{$this->failures} failure(s)</> and {$this->warnings} warning(s). The WAF is not working correctly.");
            $this->newLine();

            return self::FAILURE;
        }

        if ($this->warnings > 0) {
            $this->line("  <fg=yellow;options=bold>{$this->warnings} warning(s)</>, no failures. The WAF is recording.");
            $this->newLine();

            return self::SUCCESS;
        }

        $this->line('  <fg=green;options=bold>All checks passed.</>');
        $this->newLine();

        return self::SUCCESS;
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private function tableExists(string $table): bool
    {
        try {
            return Schema::hasTable($table);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Columns from $wanted that the table does not have. Checked one by one
     * with hasColumn() — stable across every supported Laravel version — and a
     * column that can't be inspected is reported missing rather than assumed
     * present, since claiming present is the dangerous direction.
     *
     * @param  array<int, string>  $wanted
     * @return array<int, string>
     */
    private function missingColumns(string $table, array $wanted): array
    {
        $missing = [];

        foreach ($wanted as $column) {
            try {
                if (! Schema::hasColumn($table, $column)) {
                    $missing[] = $column;
                }
            } catch (\Throwable) {
                $missing[] = $column;
            }
        }

        return $missing;
    }

    private function middlewareIsWired(): bool
    {
        $needles = [WafMiddleware::class, 'waf'];

        try {
            $kernel = $this->laravel->make(HttpKernel::class);

            if (method_exists($kernel, 'getGlobalMiddleware')
                && array_intersect($needles, array_filter($kernel->getGlobalMiddleware(), 'is_string')) !== []) {
                return true;
            }
        } catch (\Throwable) {
            // No HTTP kernel to ask — the route scan below still applies.
        }

        try {
            $router = $this->laravel->make(Router::class);

            foreach ($router->getRoutes()->getRoutes() as $route) {
                if (in_array(WafMiddleware::class, $router->gatherRouteMiddleware($route), true)) {
                    return true;
                }
            }
        } catch (\Throwable) {
            // Nothing else to try.
        }

        return false;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function loadConfigFile(string $path): ?array
    {
        try {
            $config = @include $path;
        } catch (\Throwable) {
            return null;
        }

        return is_array($config) ? $config : null;
    }

    /**
     * The dotted option keys of a config array, recursing into associative
     * arrays only — list values (skip_paths, redact.labels, …) and the
     * regex-keyed custom_patterns map are user content, not option names.
     *
     * @param  array<string, mixed>  $config
     * @return array<int, string>
     */
    private function settingKeys(array $config, string $prefix = ''): array
    {
        $keys = [];

        foreach ($config as $key => $value) {
            if ($prefix === '' && $key === 'custom_patterns') {
                $keys[] = $key;

                continue;
            }

            if (is_array($value) && $value !== [] && ! array_is_list($value)) {
                $keys = array_merge($keys, $this->settingKeys($value, $prefix.$key.'.'));

                continue;
            }

            $keys[] = $prefix.$key;
        }

        return $keys;
    }
}
