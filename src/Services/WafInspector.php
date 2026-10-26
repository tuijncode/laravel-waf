<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Route as LaravelRoute;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Tuijncode\LaravelWaf\Events\ThreatDetected;
use Tuijncode\LaravelWaf\Jobs\StoreWafLog;
use Tuijncode\LaravelWaf\Rules\CoreRuleSet;
use Tuijncode\LaravelWaf\Rules\Signature;
use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Support\CacheFailure;
use Tuijncode\LaravelWaf\Support\ClientIp;
use Tuijncode\LaravelWaf\Support\DedupCounter;
use Tuijncode\LaravelWaf\Support\QuietEvent;
use Tuijncode\LaravelWaf\Support\QuietLog;
use Tuijncode\LaravelWaf\Support\SurfaceDecoder;
use Tuijncode\LaravelWaf\Support\TargetHash;

/**
 * Request inspection engine.
 *
 * Pulls apart an incoming request into inspectable surfaces, runs them past the
 * OWASP-style signature set (plus scanner, bot and flood signals), scores the
 * outcome and — when it clears the threshold — records a finding and announces
 * it through the ThreatDetected event for the host application to act on.
 */
class WafInspector
{
    /** Bound regex work per subject while inspecting every part of large inputs. */
    private const SURFACE_CHUNK = 16384;

    // shortcut: matches spanning over 16 KiB of raw input can be missed; raise the window or use a streaming detector if longer matches are required.
    private const SURFACE_OVERLAP = 8192;

    /** PCRE failures already reported by this worker. */
    private static array $regexFailures = [];

    private static bool $queueFailureWarned = false;

    private ?object $indexedRouteCollection = null;

    private int $indexedRouteCount = -1;

    private ?RouteCollection $lateRoutes = null;

    /** @var array<string, array<int, LaravelRoute>> */
    private array $literalRoutes = [];

    /** @var array<string, array<int, LaravelRoute>> */
    private array $dynamicRoutes = [];

    /** @var array<string, array<int, array{string, bool}>> */
    private array $literalRouteKeys = [];

    /** @var array<string, array<int, array{string, bool}>> */
    private array $dynamicRouteKeys = [];

    private const SEVERITIES = ['critical', 'error', 'warning', 'notice'];

    public function __construct(
        private ?ConfidenceScorer $scorer = null,
        private ?ScannerDetector $scanners = null,
        private ?BotDetector $bots = null,
        private ?DdosMonitor $flood = null,
        private ?ExclusionRuleService $exclusions = null,
        private ?Redactor $redactor = null,
        private ?AttemptRecorder $attempts = null,
    ) {
        $this->scorer ??= new ConfidenceScorer;
        $this->scanners ??= new ScannerDetector;
        $this->bots ??= new BotDetector;
        $this->flood ??= new DdosMonitor;
        $this->exclusions ??= new ExclusionRuleService;
        $this->redactor ??= new Redactor;
        $this->attempts ??= new AttemptRecorder;
    }

    /** Call after changing a registered route's URI in place. */
    public function refreshRouteIndex(LaravelRoute $route): void
    {
        (new \ReflectionProperty(LaravelRoute::class, 'compiled'))->setValue($route, null);
        $this->indexedRouteCollection = null;
        $this->indexedRouteCount = -1;
        $this->lateRoutes = null;
        $this->literalRoutes = $this->dynamicRoutes = [];
        $this->literalRouteKeys = $this->dynamicRouteKeys = [];
    }

    /**
     * Evaluate a request. This is read-only: nothing is stored, dispatched or
     * counted — the flood counter is only advanced by handle().
     */
    public function inspect(Request $request): InspectionResult
    {
        $hits = $this->scan($this->collectSurfaces($request));
        if ($probe = $this->pathProbe($request, 'ai_probes', 'AI-PROBE', 'ai_probe', 'AI Infrastructure Probe')) {
            $hits[] = $probe;
        }
        if ($probe = $this->pathProbe($request, 'probe_paths', 'PATH-PROBE', 'probe', 'Unserved Path Probe')) {
            $hits[] = $probe;
        }

        $agent = (string) ($request->userAgent() ?? '');
        $scanner = $this->signalEnabled('913100', 'scanner') ? $this->scanners->detect($agent) : null;
        // A whitelisted agent (e.g. a known uptime monitor) is exempt from bot
        // detection, so a legitimate curl health check isn't logged every window.
        $bot = ($scanner || ! $this->signalEnabled('913110', 'bot') || $this->isWhitelistedAgent($agent))
            ? null : $this->bots->detect($agent);
        $flooding = config('waf.ddos.enabled', true) && $this->signalEnabled('912100', 'ddos')
            && $this->flood->tripped(ClientIp::from($request));

        if ($scanner !== null) {
            $hits[] = new SignatureMatch(
                id: '913100',
                category: 'scanner',
                name: 'Scanner',
                description: "Security scanner detected: {$scanner->name}",
                severity: $scanner->severity,
                context: 'user-agent',
                matched: $agent,
            );
        }

        return new InspectionResult(
            matches: $hits,
            isScanner: $scanner !== null,
            scannerName: $scanner?->name,
            isBot: $bot !== null,
            botName: $bot?->name,
            isDdos: $flooding,
            confidence: $this->scorer->calculate($hits, $scanner !== null, $bot !== null, $flooding),
        );
    }

    /**
     * Whether the agent is on the operator's allowlist of trusted automated
     * clients (case-insensitive substring match).
     */
    private function isWhitelistedAgent(string $agent): bool
    {
        if ($agent === '') {
            return false;
        }

        foreach ((array) config('waf.whitelisted_agents', []) as $needle) {
            $needle = (string) $needle;
            if ($needle !== '' && stripos($agent, $needle) !== false) {
                return true;
            }
        }

        return false;
    }

    private function signalEnabled(string $ruleId, string $category): bool
    {
        return ! in_array($ruleId, (array) config('waf.disabled_rules', []), true)
            && ! in_array($category, (array) config('waf.disabled_categories', []), true);
    }

    /**
     * Evaluate a request and, when warranted, record the finding + fire the event.
     * Returns the finding only when it is actionable (i.e. not an accepted
     * false positive), so callers may block on it.
     */
    public function handle(Request $request): ?InspectionResult
    {
        // Count the request towards the client's flood budget before the
        // read-only inspection checks it.
        if (config('waf.ddos.enabled', true) && $this->signalEnabled('912100', 'ddos')) {
            $ip = ClientIp::from($request);
            $this->flood->hit($ip);

            if (config('waf.mode', 'detection') === 'blocking' && config('waf.ddos.block', false) && $this->flood->tripped($ip)) {
                $flood = new InspectionResult(
                    isDdos: true,
                    confidence: $this->scorer->calculate([], false, false, true),
                );
                if ($this->wouldBlock($request, $flood)) {
                    // shortcut: early flood blocks omit other signatures and attempt fingerprints; add sampled inspection if that evidence is required.
                    $this->record($request, $flood, false, true);

                    return $flood;
                }
            }
        }

        $result = $this->inspect($request);

        $this->attempts->record($request, $result->matches);

        if (! $result->isThreat() || $result->confidenceScore() < (int) config('waf.min_confidence', 10)) {
            return null;
        }

        // Accepted false positives are still recorded for the audit trail, but
        // withheld from the caller so they never trigger a block.
        $accepted = $this->accepted($request, $result);

        $this->record($request, $result, $accepted);

        return $accepted ? null : $result;
    }

    /**
     * Whether a finding warrants an actual block: only in blocking mode, and
     * then either once the confidence clears `block_confidence` or — when
     * `ddos.block` is on — on the volumetric flood signal alone.
     */
    public function shouldBlock(InspectionResult $result): bool
    {
        if (config('waf.mode', 'detection') !== 'blocking') {
            return false;
        }

        // A flood's confidence score sits below the usual block threshold by
        // design (25), so blocking it is gated on an explicit opt-in rather
        // than on the score.
        if ($result->isDdos && config('waf.ddos.block', false)) {
            return true;
        }

        return $result->confidenceScore() >= (int) config('waf.block_confidence', 60);
    }

    public function wouldBlock(Request $request, InspectionResult $result): bool
    {
        return $result->isThreat()
            && $result->confidenceScore() >= (int) config('waf.min_confidence', 10)
            && $this->shouldBlock($result)
            && ! $this->accepted($request, $result);
    }

    private function accepted(Request $request, InspectionResult $result): bool
    {
        return $this->exclusions->acceptsAll($result->signatures(), $this->requestUrl($request));
    }

    /**
     * Slice the request into the named surfaces the signatures target.
     *
     * @return array<string, iterable<string>>
     */
    private function collectSurfaces(Request $request): array
    {
        return [
            'query' => $this->querySurface($request),
            'body' => $this->bodySurface($request),
            'path' => [rawurldecode($request->getPathInfo())],
            'headers' => $this->headerSurface($request),
            'cookie' => $this->stringify($request->cookies->all()),
        ];
    }

    /**
     * The query as both its raw `?a=b&c=d` string (so URL-syntax signatures
     * work) and its parsed form (so signatures that read decoded values and
     * nested keys work). A leading "?" is prepended so the very first parameter
     * is anchored the same way as the rest.
     */
    private function querySurface(Request $request): array
    {
        $parts = [];

        // getQueryString() has already collapsed duplicate keys; keep the URI's
        // original pairs and filter safe fields one pair at a time.
        $raw = (string) parse_url($request->getRequestUri(), PHP_URL_QUERY);
        if ($raw !== '' && $this->hasSafeFields()) {
            $pairs = explode('&', $raw);
            $marked = [];
            foreach ($pairs as $index => $pair) {
                $marked[] = explode('=', $pair, 2)[0].'=waf_pair_'.$index;
            }
            // Parsing all keys together preserves the indexes assigned to [] fields.
            @parse_str(implode('&', $marked), $fields);
            $present = array_fill_keys(Arr::flatten($fields), true);
            $visible = array_fill_keys(Arr::flatten($this->withoutSafeFields($fields)), true);
            $kept = [];
            foreach ($pairs as $index => $pair) {
                $marker = 'waf_pair_'.$index;
                if (isset($present[$marker])) {
                    if (isset($visible[$marker])) {
                        $kept[] = $pair;
                    }
                } else {
                    // A later scalar duplicate overwrote this pair during parsing.
                    parse_str($pair, $field);
                    if ($field === [] || $this->withoutSafeFields($field) !== []) {
                        $kept[] = $pair;
                    }
                }
            }
            $raw = implode('&', $kept);
        }
        if ($raw !== '') {
            $parts[] = '?'.rawurldecode($raw);
        }

        $params = $this->withoutSafeFields($request->query->all());
        if ($params !== []) {
            if ($this->hasSafeFields()) {
                $parts[] = '?'.rawurldecode(http_build_query($params, '', '&', PHP_QUERY_RFC3986));
            }
            array_push($parts, ...$this->stringify($params));
        }

        return $parts;
    }

    /**
     * The body as its parsed fields, uploaded file names, and raw content for
     * unstructured, form-encoded and JSON requests.
     */
    private function bodySurface(Request $request): \Generator
    {
        // On JSON requests this bag holds the parsed JSON fields (Laravel
        // swaps in the JSON input source), with \uXXXX escapes decoded —
        // RequestSurfaceTest pins that, since the raw content alone would
        // let an escape-encoded payload slip past every signature.
        $bag = $request->isJson() ? $request->json()->all() : $request->request->all();
        $fields = $this->withoutSafeFields($bag);
        // Laravel keeps uploads in the separate files bag; form fields sharing
        // a parent name with an upload still need inspection.
        yield from $this->structuredBody($fields);

        $names = $this->uploadedFileNames($request);
        if ($names !== []) {
            yield implode("\n", $names);
        }

        // The raw body is skipped when safe fields are configured and the body
        // parsed into named fields — otherwise a safe field's value would leak
        // back in through the raw content. Unstructured bodies (raw XML/text,
        // which have no named fields to protect) are still scanned raw.
        $raw = (string) $request->getContent();
        $multipartUpload = $request->allFiles() !== []
            && str_starts_with(strtolower((string) $request->headers->get('content-type')), 'multipart/form-data');
        if ($raw !== '' && ! $multipartUpload && ! ($this->hasSafeFields() && $bag !== [])) {
            yield $raw;
        }
    }

    /** @param array<string, mixed> $fields */
    private function structuredBody(array $fields): \Generator
    {
        $batch = [];
        $bytes = 0;
        foreach (Arr::dot($fields) as $path => $value) {
            if (is_array($value)) {
                yield (string) $path;

                continue;
            }

            $size = strlen((string) $path) + strlen((string) $value);
            if ($batch !== [] && $bytes + $size > 65536) {
                yield '?'.rawurldecode(http_build_query($batch, '', '&', PHP_QUERY_RFC3986));
                yield from $this->stringify($batch);
                $batch = [];
                $bytes = 0;
            }

            if ($size > 65536) {
                $field = [];
                Arr::set($field, (string) $path, substr((string) $value, 0, self::SURFACE_CHUNK));
                yield '?'.rawurldecode(http_build_query($field, '', '&', PHP_QUERY_RFC3986));
                yield from $this->stringify($field);
                yield (string) $value;

                continue;
            }

            Arr::set($batch, (string) $path, $value);
            $bytes += $size;
        }

        if ($batch !== []) {
            yield '?'.rawurldecode(http_build_query($batch, '', '&', PHP_QUERY_RFC3986));
            yield from $this->stringify($batch);
        }
    }

    /**
     * Whether the operator has configured any safe (excluded) fields.
     */
    private function hasSafeFields(): bool
    {
        return (array) config('waf.safe_fields', []) !== [];
    }

    /**
     * Strip operator-designated "safe" fields from an input bag before it is
     * scanned. Field names are matched against each value's dot-notation path
     * with `*` wildcards, and a bare name (`content`) also excludes everything
     * nested beneath it (`content.*`).
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    private function withoutSafeFields(array $data): array
    {
        $safe = (array) config('waf.safe_fields', []);

        if ($safe === [] || $data === []) {
            return $data;
        }

        $result = [];

        foreach (Arr::dot($data) as $path => $value) {
            $path = (string) $path;

            $excluded = false;
            foreach ($safe as $pattern) {
                $pattern = (string) $pattern;
                if (Str::is($pattern, $path) || str_starts_with($path, $pattern.'.')) {
                    $excluded = true;

                    break;
                }
            }

            if (! $excluded) {
                Arr::set($result, $path, $value);
            }
        }

        return $result;
    }

    /**
     * Client-supplied names of uploaded files (e.g. a `c99.php` web shell).
     * The binary content itself is never scanned.
     *
     * @return array<int, string>
     */
    private function uploadedFileNames(Request $request): array
    {
        $names = [];

        foreach (Arr::flatten($request->allFiles()) as $file) {
            if ($file instanceof UploadedFile) {
                $names[] = (string) $file->getClientOriginalName();
            }
        }

        return array_values(array_filter($names));
    }

    /**
     * Header values worth inspecting, dropping transport plumbing and the
     * cookie header (cookies are inspected on their own surface).
     */
    private function headerSurface(Request $request): array
    {
        $ignore = ['cookie'];

        $pairs = [];
        foreach ($request->headers->all() as $name => $values) {
            if (in_array($name, $ignore, true)) {
                continue;
            }
            $pairs[$name] = implode(' ', (array) $values);
        }

        return $this->stringify($pairs);
    }

    private function stringify(array $data): array
    {
        // Without the substitute flag, one invalid UTF-8 byte in any field makes
        // json_encode return false and the whole parsed surface vanishes — on a
        // multipart request (no raw body available) that would blind the WAF to
        // the entire body.
        return $data === [] ? [] : [(string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)];
    }

    /**
     * Inspect overlapping chunks, exposing each alongside decoded views
     * so one encoding layer cannot hide another. Repeat at most three times;
     * each transform is appended only when it changes the string:
     *
     *   1. percent-decoding (twice, to unwrap double URL-encoding)
     *   2. HTML-entity decoding (e.g. `&lt;script&gt;` → `<script>`)
     *   3. IIS `%uXXXX` decoding (e.g. `%u003cscript%u003e` → `<script>`)
     *   4. backslash escape decoding (JS/JSON-style \uXXXX and \xXX → char)
     *   5. null-byte stripping (e.g. `<scr%00ipt>` → `<script>`)
     *   6. SQL-comment stripping (an inline block comment between UNION and
     *      SELECT is folded to a space, so the pair reads as `UNION SELECT`)
     */
    private function normalise(string $raw): \Generator
    {
        for ($offset = 0, $length = strlen($raw); $offset < $length; $offset += self::SURFACE_CHUNK) {
            $start = max(0, $offset - self::SURFACE_OVERLAP);
            yield from SurfaceDecoder::variants(substr($raw, $start, self::SURFACE_CHUNK + 2 * self::SURFACE_OVERLAP));
        }
    }

    /**
     * Test every signature against the surfaces it targets, keeping the first
     * hit per signature.
     *
     * @param  array<string, iterable<string>>  $surfaces
     * @return array<int, SignatureMatch>
     */
    private function scan(array $surfaces): array
    {
        $hits = [];
        $hitPriorities = [];

        $level = (int) config('waf.paranoia_level', 2);
        $mutedRules = (array) config('waf.disabled_rules', []);
        $mutedCategories = (array) config('waf.disabled_categories', []);

        $bySurface = [];
        foreach (array_merge(CoreRuleSet::rules(), $this->extraSignatures(), $this->llmSignatures()) as $index => $signature) {
            if (in_array($signature->id, $mutedRules, true)
                || in_array($signature->category, $mutedCategories, true)
                || ! $signature->firesAtParanoia($level)) {
                continue;
            }

            foreach ($signature->targets as $priority => $surface) {
                $bySurface[$surface][$index] = [$signature, $priority];
            }
        }

        $operatorPatterns = (array) config('waf.custom_patterns', []);
        foreach ($surfaces as $surface => $parts) {
            foreach ($parts as $raw) {
                foreach ($this->normalise($raw) as $subject) {
                    foreach ($bySurface[$surface] ?? [] as $index => [$signature, $priority]) {
                        if (isset($hitPriorities[$index]) && $priority >= $hitPriorities[$index]) {
                            continue;
                        }

                        $hit = $this->matchSignature($signature, $subject, $surface);

                        if ($hit !== null) {
                            $hits[$index] = $hit;
                            $hitPriorities[$index] = $priority;
                            if ($priority === 0) {
                                foreach ($signature->targets as $target) {
                                    unset($bySurface[$target][$index]);
                                }
                            }
                        }
                    }
                }

                if ($operatorPatterns !== [] && strlen($raw) > self::SURFACE_CHUNK + 2 * self::SURFACE_OVERLAP) {
                    // shortcut: full decoding is limited to 1 MiB to bound temporary memory; use a streaming matcher for larger encoded spans.
                    $decoded = strlen($raw) <= 1048576 ? rawurldecode(rawurldecode($raw)) : $raw;
                    foreach ($bySurface[$surface] ?? [] as $index => [$signature, $priority]) {
                        if (! str_starts_with($signature->id, 'CUSTOM-')
                            || ! array_key_exists($signature->regex, $operatorPatterns)
                            || $signature->validator !== null
                            || (isset($hitPriorities[$index]) && $priority >= $hitPriorities[$index])) {
                            continue;
                        }

                        $hit = $this->matchSignature($signature, $raw, $surface);
                        if ($hit === null && $decoded !== $raw) {
                            $hit = $this->matchSignature($signature, $decoded, $surface);
                        }
                        if ($hit !== null) {
                            $hits[$index] = $hit;
                            $hitPriorities[$index] = $priority;
                            if ($priority === 0) {
                                foreach ($signature->targets as $target) {
                                    unset($bySurface[$target][$index]);
                                }
                            }
                        }
                    }
                }

                foreach ($bySurface[$surface] ?? [] as $index => [$signature, $priority]) {
                    if (! $signature->streamingMkfifo
                        || (isset($hitPriorities[$index]) && $priority >= $hitPriorities[$index])
                        || ! $this->hasLongMkfifoPipe($raw)) {
                        continue;
                    }

                    $hits[$index] = $signature->hit($surface, 'mkfifo ... |');
                    $hitPriorities[$index] = $priority;
                    if ($priority === 0) {
                        foreach ($signature->targets as $target) {
                            unset($bySurface[$target][$index]);
                        }
                    }
                }
            }
        }

        ksort($hits);

        return array_values($hits);
    }

    private function matchSignature(Signature $signature, string $subject, string $surface): ?SignatureMatch
    {
        try {
            $matched = $signature->match($subject);

            return $matched === null ? null : $signature->hit($surface, $matched);
        } catch (\RuntimeException $e) {
            if (config('waf.on_error', 'open') === 'closed') {
                throw $e;
            }

            $rule = $signature->id.'|'.$signature->regex;
            if (! isset(self::$regexFailures[$rule])) {
                self::$regexFailures[$rule] = true;
                QuietLog::write('warning', 'laravel-waf: signature evaluation error', [
                    'rule_id' => $signature->id,
                    'error' => $e->getMessage(),
                ]);
            }

            return null;
        }
    }

    private function hasLongMkfifoPipe(string $raw): bool
    {
        if (! preg_match('/(?:^|[=;&|\r\n\x22\x27])[ \t]{0,32}mkfifo\b[ \t]+[^\s;|]+[ \t]*;[ \t]*cat\b[ \t]+[^\s|]+/im', $raw, $marker, PREG_OFFSET_CAPTURE)) {
            return false;
        }

        return preg_match('/\|[ \t]*(?:\/(?:usr\/)?bin\/)?(?:ba)?sh\b/i', $raw, offset: $marker[0][1] + strlen($marker[0][0])) === 1;
    }

    /** Flag a configured probe only when the application does not serve its path. */
    private function pathProbe(Request $request, string $group, string $ruleId, string $category, string $name): ?SignatureMatch
    {
        if (! config("waf.{$group}.enabled", false)) {
            return null;
        }

        $path = rawurldecode($request->getPathInfo());
        foreach ((array) config("waf.{$group}.paths", []) as $pattern => $label) {
            if (! fnmatch(strtolower((string) $pattern), strtolower($path), FNM_PATHNAME)) {
                continue;
            }

            if (in_array($ruleId, (array) config('waf.disabled_rules', []), true)
                || in_array($category, (array) config('waf.disabled_categories', []), true)
                || $this->applicationServes($request)) {
                return null;
            }

            return new SignatureMatch(
                id: $ruleId,
                category: $category,
                name: $name,
                description: (string) $label,
                severity: 'warning',
                context: 'path',
                matched: $path,
            );
        }

        return null;
    }

    private function applicationServes(Request $request): bool
    {
        $routes = Route::getRoutes();
        $matched = $request->route();
        if ($matched instanceof LaravelRoute && $this->servesProbe($matched, $request)) {
            return true;
        }

        $path = trim($request->decodedPath(), '/');
        $segment = explode('/', $path, 2)[0];

        if ($routes instanceof RouteCollection && get_class($routes) === RouteCollection::class) {
            // Laravel's route maps keep the current object under a stable key.
            // Their sizes reveal additions; key lookups reveal replacements.
            $plain = (new \ReflectionProperty(RouteCollection::class, 'allRoutes'))->getValue($routes);
            $domains = (new \ReflectionProperty(RouteCollection::class, 'allDomainRoutes'))->getValue($routes);
            $count = count($plain) + count($domains);
            if ($this->indexedRouteCollection !== $routes || $this->indexedRouteCount !== $count) {
                $this->literalRouteKeys = [];
                $this->dynamicRouteKeys = [];
                foreach ($domains as $key => $route) {
                    $this->indexRegularRoute($route, $key, true);
                }
                foreach ($plain as $key => $route) {
                    $this->indexRegularRoute($route, $key, false);
                }
                $this->indexedRouteCollection = $routes;
                $this->indexedRouteCount = $count;
            }

            $candidates = array_merge(
                $this->literalRouteKeys[$path] ?? [],
                $this->dynamicRouteKeys[''] ?? [],
                $segment === '' ? [] : ($this->dynamicRouteKeys[$segment] ?? []),
            );
            foreach ($candidates as [$key, $domain]) {
                $route = $domain ? ($domains[$key] ?? null) : ($plain[$key] ?? null);
                if ($route !== null && $this->servesProbe($route, $request)) {
                    return true;
                }
            }

            return false;
        }

        // Custom collections may not use Laravel's internal maps.
        if (! $routes instanceof CompiledRouteCollection) {
            foreach ($routes->getRoutes() as $route) {
                if ($this->servesProbe($route, $request)) {
                    return true;
                }
            }

            return false;
        }

        // Enumerating compiled routes recreates every Route object, so index
        // their static portion once and inspect only late additions thereafter.
        if ($this->indexedRouteCollection !== $routes) {
            $this->literalRoutes = [];
            $this->dynamicRoutes = [];
            $this->lateRoutes = (new \ReflectionProperty(CompiledRouteCollection::class, 'routes'))->getValue($routes);
            foreach ($routes->getRoutes() as $route) {
                $uri = trim($route->uri(), '/');
                if ($route->isFallback || $this->isBroadRootRoute($route, $uri)) {
                    continue;
                }

                if (str_contains($uri, '{')) {
                    $first = explode('/', $uri, 2)[0];
                    $bucket = str_contains($first, '{') ? '' : $first;
                    $this->dynamicRoutes[$bucket][] = $route;
                } else {
                    $this->literalRoutes[$uri][] = $route;
                }
            }
            $this->indexedRouteCollection = $routes;
        }

        // Ignore HTTP method, and check every candidate even when a catch-all
        // was registered first.
        $candidates = array_merge(
            $this->literalRoutes[$path] ?? [],
            $this->dynamicRoutes[''] ?? [],
            $segment === '' ? [] : ($this->dynamicRoutes[$segment] ?? []),
        );
        foreach ($candidates as $route) {
            if ($this->servesProbe($route, $request)) {
                return true;
            }
        }

        // Laravel stores post-cache registrations in a separate live
        // RouteCollection; getRoutes() would reconstruct every compiled route.
        if ($this->lateRoutes !== null) {
            foreach ($this->lateRoutes->getRoutes() as $route) {
                if ($this->servesProbe($route, $request)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function indexRegularRoute(LaravelRoute $route, string $key, bool $domain): void
    {
        $uri = trim($route->uri(), '/');

        if (str_contains($uri, '{')) {
            $first = explode('/', $uri, 2)[0];
            $bucket = str_contains($first, '{') ? '' : $first;
            $this->dynamicRouteKeys[$bucket][] = [$key, $domain];
        } else {
            $this->literalRouteKeys[$uri][] = [$key, $domain];
        }
    }

    private function servesProbe(LaravelRoute $route, Request $request): bool
    {
        $uri = trim($route->uri(), '/');
        if ($route->isFallback || $this->isBroadRootRoute($route, $uri)) {
            return false;
        }

        if (! str_contains($uri, '{') && $uri !== trim($request->decodedPath(), '/')) {
            return false;
        }

        try {
            return $route->matches($request, false);
        } catch (\Throwable) {
            return true;
        }
    }

    private function isBroadRootRoute(LaravelRoute $route, string $uri): bool
    {
        if (! preg_match('#^\{([^/{}?]+)\??\}$#', $uri, $parts)) {
            return false;
        }

        $constraint = $route->wheres[$parts[1]] ?? null;

        return $constraint === null || in_array($constraint, ['.*', '.+'], true);
    }

    /** @return array<int, Signature> */
    private function llmSignatures(): array
    {
        if (! config('waf.llm_injection.enabled', false)) {
            return [];
        }

        $patterns = [
            '/<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|\[\/?(?:INST|SYS)\]/i' => 'LLM Role Marker Injection',
            '/\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|earlier|system)\s+(?:instruction|prompt|direction|rule|context|message)/i' => 'LLM Instruction Override',
            '/\b(?:summari[sz]e|classify|categori[sz]e|report|mark|treat|label|flag)\s+(?:this|it|the)(?:\s+(?:alert|event|log|entry|incident|activity|request|finding))?\s+as\b/i' => 'LLM Triage Manipulation',
            '/\b(?:append|send|post|output|reveal|print|repeat)\s+(?:the\s+|your\s+)?(?:system\s+prompt|initial\s+instruction|above\s+instruction|your\s+instruction)/i' => 'LLM Prompt Exfiltration',
        ];

        $signatures = [];
        foreach ($patterns as $regex => $label) {
            $signatures[] = new Signature(
                id: 'LLM-'.(count($signatures) + 1),
                category: 'llm_injection',
                name: 'LLM Prompt Injection',
                description: $label,
                severity: 'warning',
                targets: ['query', 'body', 'headers'],
                regex: $regex,
            );
        }

        return $signatures;
    }

    /** Compiled operator signatures, memoised per distinct configuration. */
    private static array $compiled = [];

    /**
     * Turn the shipped pack + operator `custom_patterns` into runnable
     * signatures. Bad expressions are reported once and dropped.
     *
     * @return array<int, Signature>
     */
    private function extraSignatures(): array
    {
        $pack = config('waf.pattern_pack', true) ? (array) config('waf-patterns.custom', []) : [];
        $operator = (array) config('waf.custom_patterns', []);
        $fallback = config('waf.custom_pattern_severity', 'error');
        $fallback = in_array($fallback, self::SEVERITIES, true) ? $fallback : 'error';
        $defaultParanoia = (int) config('waf.custom_pattern_paranoia', 1);

        // Operator entries take precedence on a shared regex key.
        $definitions = array_merge($pack, $operator);

        try {
            $fingerprint = md5(serialize([$definitions, $fallback, $defaultParanoia]));
        } catch (\Throwable) {
            // A malformed operator value must not prevent core rules from running.
            return $this->compile($definitions, $fallback, $defaultParanoia);
        }

        return self::$compiled[$fingerprint] ??= $this->compile($definitions, $fallback, $defaultParanoia);
    }

    /**
     * @param  array<string, mixed>  $definitions
     * @return array<int, Signature>
     */
    private function compile(array $definitions, string $fallback, int $defaultParanoia): array
    {
        $everySurface = ['query', 'body', 'path', 'headers', 'cookie'];
        $signatures = [];
        $n = 0;

        foreach ($definitions as $regex => $definition) {
            $n++;

            if (@preg_match($regex, '') === false) {
                QuietLog::write('warning', 'laravel-waf: dropping unparsable custom pattern', ['pattern' => $regex]);

                continue;
            }

            $rich = is_array($definition);
            $severity = $rich ? ($definition['severity'] ?? $fallback) : $fallback;
            $targets = $rich ? ($definition['targets'] ?? $everySurface) : $everySurface;
            if (! is_array($targets) || $targets === []
                || array_filter($targets, fn ($target): bool => ! is_string($target) || ! in_array($target, $everySurface, true))) {
                QuietLog::write('warning', 'laravel-waf: dropping custom pattern with invalid targets', ['pattern' => $regex]);

                continue;
            }

            if ($rich && ((isset($definition['label']) && ! is_string($definition['label']))
                || (isset($definition['validator']) && ! is_string($definition['validator']))
                || (isset($definition['paranoia']) && filter_var($definition['paranoia'], FILTER_VALIDATE_INT) === false))) {
                QuietLog::write('warning', 'laravel-waf: dropping malformed custom pattern', ['pattern' => $regex]);

                continue;
            }

            try {
                $signatures[] = new Signature(
                    id: 'CUSTOM-'.$n,
                    category: 'custom',
                    name: 'Custom Pattern',
                    description: $rich ? ($definition['label'] ?? 'Custom Pattern') : (string) $definition,
                    severity: in_array($severity, self::SEVERITIES, true) ? $severity : $fallback,
                    targets: $targets,
                    regex: $regex,
                    paranoia: $rich ? (int) ($definition['paranoia'] ?? $defaultParanoia) : $defaultParanoia,
                    decisive: $rich && (bool) ($definition['decisive'] ?? false),
                    validator: $rich && isset($definition['validator']) ? $definition['validator'] : null,
                    streamingMkfifo: $rich && ($definition['streaming_mkfifo'] ?? false) === true,
                );
            } catch (\Throwable $e) {
                QuietLog::write('warning', 'laravel-waf: dropping malformed custom pattern', ['pattern' => $regex, 'error' => $e->getMessage()]);
            }
        }

        return $signatures;
    }

    /**
     * Store the finding (inline or via queue) and broadcast it. A short-lived
     * throttle key collapses bursts of the same finding from one client.
     */
    private function record(Request $request, InspectionResult $result, bool $accepted, bool $redactEvidence = false): void
    {
        $ip = ClientIp::from($request);
        $signature = $result->summary();
        $identity = implode('|', $result->signatures()).'#'.$this->action($result, $accepted);

        // The dedup key optionally folds in the request path, so the same attack
        // aimed at many endpoints is not collapsed into a single finding (which
        // would hide its breadth from the correlation analytics).
        $scope = config('waf.dedup_include_path', false)
            ? $ip.'#'.$request->path().'#'.$identity
            : $ip.'#'.$identity;

        $hash = md5($scope);
        $seenKey = 'laravel-waf|seen|'.$hash;
        $eventId = (string) Str::uuid();
        $createdAt = now();
        $minutes = (int) config('waf.dedup_minutes', 5);
        $window = $createdAt->copy()->addMinutes($minutes);
        $store = (string) config('cache.default');
        $dedup = $minutes > 0 && config("cache.stores.{$store}.driver", $store) !== 'null';

        // Cache::add is atomic: a false return means we saw this very recently.
        // Rather than drop the duplicate outright, bump the hit counter on the
        // finding it collapses into, so the true volume stays visible to the
        // correlation analytics without writing a new row.
        $new = true;
        if ($dedup) {
            try {
                $new = Cache::add($seenKey, [
                    'event_id' => $eventId,
                    'created_at' => $createdAt->toISOString(),
                ], $window);
            } catch (\Throwable $e) {
                CacheFailure::report($e);
            }
        }

        if (! $new) {
            try {
                app(DedupCounter::class)->duplicate($seenKey);
            } catch (\Throwable $e) {
                CacheFailure::report($e);
            }

            return;
        }

        // A stable id that identifies this finding in both the sync and queued
        // storage paths, so a ThreatDetected listener can reference the row.
        // A single captured secret cannot rule out more in other fields.
        $secrets = $this->redactor->sensitiveValues($result->matches);
        $containsSecret = $secrets !== [] || $redactEvidence;
        $requestUrl = $this->requestUrl($request);
        $url = $this->redactor->storable($containsSecret
            ? '[REDACTED]' : $this->redactor->fields($requestUrl), 2000);
        $payload = $this->redactor->storable($containsSecret
            ? '[REDACTED]' : $this->redactor->fields($this->evidence($result)), 4000);

        $row = [
            'event_id' => $eventId,
            'ip_address' => $ip,
            'method' => $this->redactor->storable($request->method(), 10),
            'url' => $url,
            'target_hash' => TargetHash::fromUrl($requestUrl),
            'user_agent' => $this->redactor->storable($containsSecret
                ? '[REDACTED]' : $this->redactor->fields((string) $request->userAgent()), 500),
            'type' => $signature,
            'category' => $this->classify($result),
            'rule_ids' => implode(',', $result->ruleIds()),
            'payload' => $payload,
            'threat_level' => $result->severity(),
            'anomaly_score' => $result->anomalyScore(),
            'confidence_score' => $result->confidenceScore(),
            'confidence_label' => $result->confidenceLabel(),
            'action_taken' => $this->action($result, $accepted),
            'hit_count' => 1,
            'user_id' => $this->userId(),
            'created_at' => $createdAt,
            'updated_at' => $createdAt,
        ];

        $id = $this->persist($row, $dedup ? $seenKey : null);

        if ($dedup && $id === false) {
            // The write failed, so release the dedup slot — otherwise the
            // finding stays suppressed for the whole window with nothing
            // stored, and the attack disappears from the log entirely.
            try {
                app(DedupCounter::class)->failed($seenKey, $eventId);
            } catch (\Throwable $e) {
                CacheFailure::report($e);
            }
        } elseif ($dedup && $id !== null) {
            try {
                app(DedupCounter::class)->stored($seenKey, $eventId);
            } catch (\Throwable $e) {
                CacheFailure::report($e);
            }
        }

        QuietLog::write('warning', 'laravel-waf finding detected', [
            'ip' => $ip,
            'event_id' => $eventId,
            'signature' => $signature,
            'severity' => $result->severity(),
            'confidence' => $result->confidenceScore(),
            'action' => $row['action_taken'],
        ]);

        QuietEvent::dispatch(new ThreatDetected($row, $result, $ip, $eventId));
    }

    private function userId(): int|string|null
    {
        try {
            return Auth::id();
        } catch (\Throwable) {
            return null;
        }
    }

    private function requestUrl(Request $request): string
    {
        try {
            return $request->fullUrl();
        } catch (\Throwable) {
            // Forwarded headers can conflict; keep the raw request target as evidence.
            return 'http://'.(string) $request->server->get('HTTP_HOST', '').$request->getRequestUri();
        }
    }

    /**
     * @param  array<string, mixed>  $row
     * @return int|false|null the inserted row id (inline path), null when
     *                        queued, or false when the inline write failed
     */
    private function persist(array $row, ?string $dedupKey): int|false|null
    {
        if (config('waf.queue.enabled', false)) {
            try {
                Bus::dispatch((new StoreWafLog($row, $dedupKey))
                    ->onConnection(config('waf.queue.connection'))
                    ->onQueue(config('waf.queue.queue', 'default')));

                return null;
            } catch (\Throwable $e) {
                if (! self::$queueFailureWarned) {
                    self::$queueFailureWarned = true;
                    QuietLog::write('warning', 'laravel-waf: queue unavailable; writing findings directly', [
                        'error' => $e->getMessage(),
                    ]);
                }
            }
        }

        try {
            return (new StoreWafLog($row))->storeInline() ?? false;
        } catch (\Throwable $e) {
            QuietLog::write('error', 'laravel-waf: could not persist finding', ['error' => $e->getMessage()]);
            $this->explainPersistFailure(array_keys($row));

            return false;
        }
    }

    /**
     * When findings can't be stored, say why in words that name the fix — once
     * per hour, not once per finding. A stale schema (the package was upgraded
     * but the upgrade migration never ran) otherwise surfaces only as a raw SQL
     * error per request while the log table quietly stays empty — which reads
     * as "no attacks", not "nothing is being recorded".
     *
     * @param  array<int, string>  $columns
     */
    private function explainPersistFailure(array $columns): void
    {
        try {
            if (! Cache::add('laravel-waf|storage-explained', true, now()->addHour())) {
                return;
            }

            $table = (string) config('waf.table_name', 'waf_logs');

            if (! Schema::hasTable($table)) {
                QuietLog::write('error',
                    "laravel-waf: findings are being discarded — the '{$table}' table does not exist. "
                    .'Run: php artisan vendor:publish --tag=waf-migrations && php artisan migrate. '
                    .'Then verify with: php artisan waf:doctor'
                );

                return;
            }

            $missing = array_values(array_filter(
                $columns,
                static fn (string $column): bool => ! Schema::hasColumn($table, $column),
            ));

            if ($missing !== []) {
                QuietLog::write('error',
                    "laravel-waf: findings are being discarded — '{$table}' is missing the "
                    .implode(', ', $missing).' column(s); the package was likely upgraded without its '
                    .'upgrade migration. Run: php artisan vendor:publish --tag=waf-migrations-upgrade '
                    .'&& php artisan migrate. Then verify with: php artisan waf:doctor'
                );
            }
        } catch (\Throwable) {
            // Diagnosis is best-effort; the raw error is already logged above.
        }
    }

    private function classify(InspectionResult $result): string
    {
        if (! empty($result->matches)) {
            return $result->matches[0]->category;
        }

        return match (true) {
            $result->isScanner => 'scanner',
            $result->isDdos => 'ddos',
            default => 'bot',
        };
    }

    private function action(InspectionResult $result, bool $accepted): string
    {
        if ($accepted) {
            return 'excluded';
        }

        return $this->shouldBlock($result) ? 'blocked' : 'logged';
    }

    private function evidence(InspectionResult $result): string
    {
        $lines = array_map(
            fn (SignatureMatch $hit) => "{$hit->id} @ {$hit->context} => {$hit->matched}",
            $result->matches,
        );

        if ($result->isDdos) {
            $lines[] = 'flood: hit rate over the configured ceiling';
        }

        return implode("\n", $lines);
    }
}
