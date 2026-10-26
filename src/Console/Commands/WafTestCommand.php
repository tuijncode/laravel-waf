<?php

namespace Tuijncode\LaravelWaf\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Http\Request;
use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\InspectionResult;
use Tuijncode\LaravelWaf\Services\WafInspector;

/**
 * Dry-run a payload through the inspector and print what it trips — for tuning
 * rules and reproducing a false positive without sending a live request. This
 * uses the read-only inspection path: nothing is logged, counted or blocked.
 */
class WafTestCommand extends Command
{
    protected $signature = 'waf:test
        {payload? : Payload to test (placed in the ?q= query parameter)}
        {--method=GET : HTTP method}
        {--path=/ : Request path}
        {--query= : Full raw query string (overrides the payload argument)}
        {--body= : Request body (raw string)}
        {--json : Send the body as application/json}
        {--ua= : User-Agent header}
        {--header=* : Extra header as "Name: value" (repeatable)}';

    protected $description = 'Dry-run a payload through the WAF and report what it trips';

    public function handle(WafInspector $inspector): int
    {
        $request = $this->buildRequest();

        if ($request === null) {
            return self::INVALID;
        }

        $result = $inspector->inspect($request);

        if (! $result->isThreat()) {
            $this->info('No threats detected.');

            return self::SUCCESS;
        }

        $this->renderMatches($result->matches);
        $this->renderSignals($result);
        $this->renderScore($result, $inspector, $request);

        return self::SUCCESS;
    }

    private function buildRequest(): ?Request
    {
        $method = strtoupper((string) $this->option('method'));
        $path = '/'.ltrim((string) $this->option('path'), '/');

        $query = $this->option('query');
        if ($query === null && $this->argument('payload') !== null) {
            $query = 'q='.rawurlencode((string) $this->argument('payload'));
        }

        $uri = $path.($query ? '?'.$query : '');

        $server = [];
        if ($ua = $this->option('ua')) {
            $server['HTTP_USER_AGENT'] = (string) $ua;
        }
        if ($this->option('json')) {
            $server['CONTENT_TYPE'] = 'application/json';
        }

        foreach ((array) $this->option('header') as $header) {
            if (! str_contains((string) $header, ':')) {
                $this->error("Ignoring malformed header '{$header}' (expected \"Name: value\").");

                return null;
            }
            [$name, $value] = explode(':', (string) $header, 2);
            $name = strtoupper(str_replace('-', '_', trim($name)));
            $server[in_array($name, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $name : 'HTTP_'.$name] = trim($value);
        }

        $content = $this->option('body');

        return Request::createFromBase(Request::create(
            $uri, $method, [], [], [], $server, $content !== null ? (string) $content : null
        ));
    }

    /**
     * @param  array<int, SignatureMatch>  $matches
     */
    private function renderMatches(array $matches): void
    {
        if ($matches === []) {
            return;
        }

        $this->line('<comment>Signatures matched</comment>');
        $this->table(
            ['Rule', 'Category', 'Severity', 'Surface', 'Matched'],
            array_map(fn (SignatureMatch $m): array => [
                $m->id,
                $m->category,
                $m->severity,
                $m->context,
                mb_strimwidth($m->matched, 0, 60, '…'),
            ], $matches),
        );
    }

    private function renderSignals(InspectionResult $result): void
    {
        $signals = [];
        if ($result->isScanner) {
            $signals[] = "scanner ({$result->scannerName})";
        }
        if ($result->isBot) {
            $signals[] = "bot ({$result->botName})";
        }
        if ($result->isDdos) {
            $signals[] = 'flood (rate threshold exceeded)';
        }

        if ($signals !== []) {
            $this->newLine();
            $this->line('<comment>Other signals:</comment> '.implode(', ', $signals));
        }
    }

    private function renderScore(InspectionResult $result, WafInspector $inspector, Request $request): void
    {
        $score = $result->confidenceScore();
        $blockAt = (int) config('waf.block_confidence', 60);
        $mode = (string) config('waf.mode', 'detection');
        $wouldBlock = $inspector->wouldBlock($request, $result);

        $this->newLine();
        $this->line("Confidence: <info>{$score}</info> ({$result->confidenceLabel()})   "
            ."Anomaly: <info>{$result->anomalyScore()}</info>   "
            ."Severity: <info>{$result->severity()}</info>");
        $this->line("Block threshold: {$blockAt} · mode: {$mode} · if inspected → "
            .($wouldBlock
                ? '<error> would BLOCK </error>'
                : ($score < (int) config('waf.min_confidence', 10)
                    ? '<info>below minimum confidence, ignored</info>'
                    : '<info>not blocked</info>')));
    }
}
