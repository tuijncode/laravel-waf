<?php

namespace Tuijncode\LaravelWaf\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;
use Tuijncode\LaravelWaf\Events\RequestBlocked;
use Tuijncode\LaravelWaf\Services\AutoBanManager;
use Tuijncode\LaravelWaf\Services\InspectionResult;
use Tuijncode\LaravelWaf\Services\WafInspector;

/**
 * Front-line WAF middleware.
 *
 * Register it globally, or per-route via the `waf` alias:
 *
 *   Route::middleware('waf')->group(...);
 *
 * In `detection` mode it inspects and logs but never interferes with the
 * response. In `blocking` mode it refuses high-confidence requests with a
 * configurable response (see `config/waf.php` → `block_response`).
 */
class WafMiddleware
{
    public function __construct(
        protected WafInspector $inspector,
        protected AutoBanManager $bans,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        // Explicit per-IP verdicts are settled before any path/mode logic, so a
        // denylisted client is refused everywhere (even on skip_paths) and a
        // whitelisted one is never touched. Allow wins over deny on overlap.
        if (config('waf.enabled', true)) {
            $ip = (string) $request->ip();

            if ($ip !== '' && $this->ipMatches($ip, config('waf.whitelisted_ips', []))) {
                return $next($request);
            }

            if ($ip !== '' && $this->ipMatches($ip, config('waf.blocklisted_ips', []))) {
                Log::warning('laravel-waf: request refused (denylisted IP)', ['ip' => $ip]);

                return $this->blockResponse($request, new InspectionResult);
            }
        }

        if (! $this->shouldInspect($request)) {
            return $next($request);
        }

        try {
            // A banned client is refused before the inspection pipeline runs.
            // The ban itself was recorded when it was earned, so no per-request
            // finding or event is produced here.
            if ($this->bans->banned((string) $request->ip())) {
                return $this->blockResponse($request, new InspectionResult, [
                    'Retry-After' => (string) $this->bans->duration(),
                ]);
            }

            $result = $this->inspector->handle($request);

            if ($result !== null && $this->inspector->shouldBlock($result)) {
                // The strike is per request so a flood earns its ban quickly...
                $this->bans->strike((string) $request->ip());

                // ...but the event is throttled to once per finding (same
                // IP + signature + window as the log), so a flood can't drown
                // listeners in duplicate RequestBlocked dispatches.
                if ($this->announceBlock($request, $result)) {
                    RequestBlocked::dispatch($request, $result);
                }

                return $this->blockResponse($request, $result);
            }
        } catch (\Throwable $e) {
            Log::error('laravel-waf: inspection error', ['error' => $e->getMessage()]);

            // Fail open by default (the WAF must never take the application
            // down); operators running blocking mode can opt into fail-closed.
            if (config('waf.on_error', 'open') === 'closed') {
                return response('Service Unavailable', 503);
            }
        }

        return $next($request);
    }

    /**
     * Whether to dispatch RequestBlocked for this block. Throttled to once per
     * IP + signature per dedup window, matching how often the finding itself is
     * logged, so a flood doesn't overwhelm listeners with duplicate events.
     */
    protected function announceBlock(Request $request, InspectionResult $result): bool
    {
        $minutes = (int) config('waf.dedup_minutes', 5);

        if ($minutes <= 0) {
            return true;
        }

        $key = 'laravel-waf|announced|'.md5($request->ip().'#'.$result->summary());

        return Cache::add($key, true, now()->addMinutes($minutes));
    }

    /**
     * Build the response returned to a blocked client. Honours JSON clients,
     * an optional custom view, and adds Retry-After for rate-based blocks.
     *
     * @param  array<string, string>  $headers
     */
    protected function blockResponse(Request $request, InspectionResult $result, array $headers = []): Response
    {
        $status = (int) config('waf.block_response.status', 403);
        $message = (string) config('waf.block_response.message', 'Forbidden');

        if ($result->isDdos) {
            $headers['Retry-After'] = (string) config('waf.ddos.window', 60);
        }

        if (config('waf.block_response.always_json') || $request->expectsJson()) {
            return response()->json(['message' => $message], $status, $headers);
        }

        $view = config('waf.block_response.view');
        if ($view && view()->exists($view)) {
            return response()->view($view, ['result' => $result], $status, $headers);
        }

        return response($message, $status, $headers);
    }

    /**
     * Whether the IP matches any entry (exact or CIDR) in the configured list.
     *
     * Entries are trimmed before matching: IpUtils::checkIp() treats an entry
     * with stray whitespace (" 1.2.3.4") as unparsable and silently never
     * matches it. The shipped config trims on parse, but an application
     * running a stale published copy of it would pass untrimmed entries here —
     * and a whitelist that silently stopped matching must not take effect.
     */
    protected function ipMatches(string $ip, mixed $list): bool
    {
        $entries = array_filter(array_map(
            static fn ($entry): string => is_string($entry) ? trim($entry) : '',
            (array) $list,
        ), static fn (string $entry): bool => $entry !== '');

        return $entries !== [] && IpUtils::checkIp($ip, array_values($entries));
    }

    protected function shouldInspect(Request $request): bool
    {
        if (! config('waf.enabled', true)) {
            return false;
        }

        $environments = config('waf.enabled_environments');
        if (! empty($environments) && ! in_array(app()->environment(), $environments, true)) {
            return false;
        }

        $ip = (string) $request->ip();
        if ($ip !== '' && $this->ipMatches($ip, config('waf.whitelisted_ips', []))) {
            return false;
        }

        $path = ltrim($request->path(), '/');

        $only = config('waf.only_paths', []);
        if (! empty($only)) {
            foreach ($only as $pattern) {
                if (fnmatch($pattern, $path)) {
                    return true;
                }
            }

            return false;
        }

        foreach (config('waf.skip_paths', []) as $pattern) {
            if (fnmatch($pattern, $path)) {
                return false;
            }
        }

        return true;
    }
}
