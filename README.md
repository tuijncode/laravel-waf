# Laravel WAF

[![Tests](https://github.com/tuijncode/laravel-waf/actions/workflows/tests.yml/badge.svg)](https://github.com/tuijncode/laravel-waf/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/tuijncode/laravel-waf.svg)](https://packagist.org/packages/tuijncode/laravel-waf)
[![PHP Version](https://img.shields.io/packagist/php-v/tuijncode/laravel-waf.svg)](https://packagist.org/packages/tuijncode/laravel-waf)
[![License](https://img.shields.io/packagist/l/tuijncode/laravel-waf.svg)](LICENSE.txt)

A Web Application Firewall (WAF) for Laravel. It inspects every incoming request
against a signature set modelled on the [OWASP Core Rule Set](https://coreruleset.org/)
and logs — or blocks — anything that looks like an attack.

## Features

- **40+ detection patterns** — SQL injection, XSS, RCE (including Shellshock and
  Windows command execution), directory traversal / LFI, RFI, SSRF, XXE, Log4Shell,
  NoSQL injection, PHP injection, command injection and LDAP / XPath injection,
  organised by OWASP CRS rule id and category.
- **Scanner detection** — SQLMap, Nikto, Nmap, Burp Suite, Acunetix, WPScan,
  Nessus, Nuclei, Metasploit, Arachni, Wapiti, Commix, ffuf, feroxbuster and more,
  by their User-Agent fingerprint.
- **Bot detection** — scripting libraries, headless browsers and empty/spoofed
  user agents.
- **DDoS monitoring** — rate-based threshold detection over a configurable window.
- **Auto-ban** — optionally ban an IP outright (cache-based, self-expiring) after
  repeated blocks, so a persistent attacker stops costing a full inspection per
  request.
- **Confidence scoring** — every threat gets a 0-100 score derived from the CRS
  anomaly score plus contextual signals (breadth, request location, scanner/bot/DoS).
- **Evasion-resistant** — surfaces are URL-decoded (twice), HTML-entity decoded,
  IIS `%uXXXX`- and backslash-escape (`\uXXXX` / `\xXX`) decoded, null-byte
  stripped and SQL-comment folded before matching (so `UNION/**/SELECT` is caught
  even at paranoia 1). Large request bodies are inspected in overlapping
  chunks, without a size-based block. Parsed upload file names and form fields
  are inspected, but file contents are not.
- **Secret redaction** — free-text log fields are redacted for sensitive
  findings, and named credential values are masked on other findings; stored text is valid UTF-8 with
  control and bidirectional formatting characters escaped.
- **AI infrastructure probes** — optional detection for unserved Ollama, model
  API, MCP and Langflow paths (`WAF_AI_PROBES=true`).
- **Other-stack probes** — optional, route-aware detection for unserved WordPress,
  cPanel, Swagger and similar paths (`WAF_PROBE_PATHS=true`).
- **Prompt-injection signals** — optional detection of role markers and
  instructions aimed at an AI application or AI-assisted triage
  (`WAF_LLM_INJECTION=true`).
- **`waf_logs` storage** — detected threats are persisted for auditing.
- **`ThreatDetected` event** — hook in your own response (block, ban, notify, SIEM).
- **Exclusion rules** — suppress known false positives by rule id / label and path.
- **Field-level exclusions** — mark rich-text / free-form fields as `safe_fields`
  to silence false positives without disabling a whole rule (dot-notation +
  wildcards).
- **IP allow & deny lists** — a CIDR-aware allowlist that skips inspection, and a
  denylist that refuses matching IPs up front in any mode.
- **Correlation analytics** — detect coordinated / distributed campaigns across
  many IPs from the logs (`waf:correlate`).
- **Attack variant comparison** — optionally retain bounded hashes of distinct
  attempts before finding deduplication, then surface mutation chains.
- **Operator tooling** — dry-run a payload (`waf:test`) and export offending IPs as
  a fail2ban / nginx / Apache / CSV blocklist (`waf:export`), alongside stats,
  purge and unban commands.
- **Health check** — `waf:doctor` verifies the WAF is installed, wired to a route
  and actually recording, catching the silent failures (stale schema, config
  drift, unwired middleware) that leave the log deceptively empty.
- **Config validation** — misconfiguration is surfaced as a log warning at boot.
- **Queue support** — defer logging off the request cycle.
- **Retention** — prune old logs manually or on a daily schedule.

## Installation

```bash
composer require tuijncode/laravel-waf
```

Publish the config and migration, then migrate:

```bash
php artisan vendor:publish --tag=waf-config
php artisan vendor:publish --tag=waf-migrations
php artisan migrate
```

### Upgrading from 1.0.x

1.1 adds an `event_id` column and a `created_at` index to `waf_logs`. A fresh
install gets them from the create migration; existing installs publish the
upgrade migration (idempotent, safe to run once) and migrate:

```bash
php artisan vendor:publish --tag=waf-migrations-upgrade
php artisan migrate
```

Existing installations should repeat the upgrade publish and migration step
after this release. It adds a new migration that widens `waf_logs.rule_ids` to
text and one that adds the nullable `target_hash` column; previously published
upgrade migrations remain in place. Two further upgrade migrations backfill
target hashes for older visible findings and deactivate orphaned wildcard
exclusions whose original scope cannot be verified. Re-publish the upgrade
migrations even if you previously ran them; review manual wildcard exclusions
without a source log and recreate those you still need. Set `APP_KEY` before
running the target-hash backfill migration.
Laravel 10 applications using SQLite need `doctrine/dbal` installed before
running this column-change migration.

The latest upgrade migrations widen `waf_logs.user_id` and
`waf_exclusion_rules.created_by_user_id` to store UUID and other string user
IDs. Existing installations must publish and run them before using string
user IDs in findings or exclusions. On PostgreSQL, changing the log column
rewrites `waf_logs` under an exclusive lock. For a large log table, schedule
this migration in a maintenance window and allow enough disk space for a copy
of the table and its indexes.

1.2 adds only new config options (`blocklisted_ips`, `safe_fields`) and commands
— no migration is required. Re-publish the config to pick up the new keys, or add
them by hand.

`waf-config` publishes both config files at once. To publish them separately:

```bash
php artisan vendor:publish --tag=waf-config-main # config/waf.php only
php artisan vendor:publish --tag=waf-config-patterns # config/waf-patterns.php only
```

## Usage

Apply the `waf` middleware globally (in `bootstrap/app.php` on Laravel 11+) or per
route group:

```php
Route::middleware('waf')->group(function () {
    // protected routes
});
```

By default the WAF runs in **detection** mode: it inspects and logs but never
interferes with the response. Set `WAF_MODE=blocking` to have it abort
high-confidence requests with a `403`.

> [!IMPORTANT]
> **Behind a proxy, CDN or load balancer?** Everything keys off
> `$request->ip()` — DDoS counting, the IP allowlist and the logged IP. If
> Laravel's [trusted proxies](https://laravel.com/docs/requests#configuring-trusted-proxies)
> aren't configured, that resolves to the *proxy's* address, so flood detection
> and allowlisting silently misbehave and every finding shows the same IP.
> Configure `TrustProxies` (or `$middleware->trustProxies(...)` on Laravel 11+)
> so the real client IP is used.

### Responding to threats

Every logged threat dispatches `Tuijncode\LaravelWaf\Events\ThreatDetected`.
Implement your own response by listening for it:

```php
use Tuijncode\LaravelWaf\Events\ThreatDetected;

Event::listen(function (ThreatDetected $event) {
    // $event->log        — the row written to waf_logs
    // $event->result     — the full InspectionResult
    // $event->ipAddress  — the offending IP
    // $event->eventId    — UUID of the stored finding (works even when queued)

    if ($event->result->confidenceScore() >= 80) {
        // e.g. ban the IP, page on-call, push to your SIEM ...
    }
});
```

Each finding carries an `event_id` (UUID) column so a listener can reference
the exact stored row — including when the insert is queued and the row doesn't
exist yet at dispatch time. If a listener throws, the WAF records the error and
continues its own block decision; handle retries for external actions in your
listener or queue worker.
Queued listeners receive a redacted copy of `ThreatDetected`: free-text log
fields and matched values are replaced with `[REDACTED]`. Synchronous listeners
retain the full event. Use `eventId` to retrieve the stored finding if needed.

> **`user_id` is usually `null`.** When the middleware runs globally it
> executes before the session/auth middleware, so `Auth::id()` isn't resolved
> yet. Apply the `waf` middleware after `StartSession`/`Authenticate` (e.g. on
> your `web` group) if you need the authenticated user on findings.

## Configuration

Key options in `config/waf.php`:

| Option                | Default     | Description                                                  |
|-----------------------|-------------|--------------------------------------------------------------|
| `mode`                | `detection` | `detection` (log only) or `blocking`.                        |
| `on_error`            | `open`      | Fail `open` (let through) or `closed` (503) on error.        |
| `min_confidence`      | `10`        | Threats below this 0-100 score are ignored.                  |
| `block_confidence`    | `60`        | In blocking mode, refuse requests at/above this score.       |
| `paranoia_level`      | `2`         | `1` = high-confidence rules only; `2` adds broader rules.    |
| `disabled_rules`      | `[]`        | Rule ids to silence, e.g. `['930100']`.                      |
| `disabled_categories` | `[]`        | Categories to silence, e.g. `['nosqli']`.                    |
| `skip_paths`          | assets, …   | Wildcard paths excluded from inspection.                     |
| `only_paths`          | `[]`        | If set, ONLY these paths are inspected.                      |
| `safe_fields`         | `[]`        | Input fields excluded from scanning (dot-notation, `*`).     |
| `ai_probes.enabled`   | `false`     | Detect probes for unserved AI endpoints (`WAF_AI_PROBES`).   |
| `probe_paths.enabled` | `false`     | Detect probes for unserved non-AI endpoints.                 |
| `llm_injection.enabled` | `false`   | Detect prompt-injection text in request data.                |
| `attempts.enabled`    | `false`     | Record distinct attack variants (`WAF_ATTEMPTS`).           |
| `whitelisted_ips`     | `[]`        | CIDR-aware IP allowlist (skips inspection).                  |
| `blocklisted_ips`     | `[]`        | CIDR-aware IP denylist (refused up front, any mode).         |
| `whitelisted_agents`  | `[]`        | User-Agent substrings exempt from bot detection.             |
| `dedup_include_path`  | `false`     | Add the path to the dedup key (one finding per path).        |
| `ddos.threshold`      | `300`       | Requests per `ddos.window` seconds before a DoS flag.        |
| `ddos.block`          | `false`     | In blocking mode, refuse floods on the volumetric signal.    |
| `auto_ban.enabled`    | `false`     | Temporarily ban an IP after repeated blocks (blocking mode). |

> DDoS monitoring is built on Laravel's rate limiter, so it works with any
> configured cache store. Only inspected requests count towards the budget:
> traffic to `skip_paths` and from whitelisted IPs is not tallied.
>
> A flood scores 25 — below the default `block_confidence` (60) — so in blocking
> mode it is logged but not refused unless you set `ddos.block` (or
> `WAF_DDOS_BLOCK=true`). It is then refused on the flood signal alone, with a
> `Retry-After` header.

### IP allow & deny lists

Two CIDR-aware lists short-circuit inspection at the edge, both accepting a
comma-separated env value (e.g. `WAF_BLOCKLISTED_IPS="203.0.113.4,10.0.0.0/8"`):

- **`whitelisted_ips`** (`WAF_WHITELISTED_IPS`) — trusted addresses skip
  inspection entirely.
- **`blocklisted_ips`** (`WAF_BLOCKLISTED_IPS`) — known-bad addresses are refused
  up front with the block response, before any inspection, on every path and in
  either mode. It is an explicit operator decision independent of the scoring
  engine, so it blocks **even in `detection` mode**.

If an address is on both lists the allowlist wins. Entries are trimmed before
matching, so spaces after the commas are fine — even on an older published
`config/waf.php` that doesn't trim on parse.

### Blocking & the block response

In `blocking` mode, a request whose confidence reaches `block_confidence` is
refused. The response is configurable (`config/waf.php` → `block_response`):
custom status/message, a Blade `view`, automatic JSON for API clients (or
`always_json`), and a `Retry-After` header on rate-based blocks. A
`Tuijncode\LaravelWaf\Events\RequestBlocked` event fires when a request is
blocked so you can ban the IP or record a metric:

```php
use Tuijncode\LaravelWaf\Events\RequestBlocked;

Event::listen(function (RequestBlocked $event) {
    Firewall::ban($event->request->ip()); // your own logic
});
```

Every request that trips the block is still refused, but the event is throttled
to once per IP + signature per dedup window (the same rate the finding is
logged at), so a flood can't drown your listener in duplicate events.
Queued `RequestBlocked` listeners receive the method, client IP and verdict;
the request path, query, body, headers and cookies are removed before the event
enters the queue. Synchronous listeners still receive the original request.

### Auto-ban repeat offenders

Instead of (or on top of) your own `RequestBlocked` listener, the WAF can ban a
repeat offender itself. With `WAF_AUTO_BAN=true`, an IP that earns
`auto_ban.max_blocks` blocks inside a rolling `auto_ban.window` (seconds) is
refused up front for `auto_ban.duration` seconds — without running the full
inspection pipeline on every request. Bans live in the cache and expire on
their own. Requests refused by a standing ban are not logged again (the
findings that earned the ban already were) and carry a `Retry-After` header.

When a ban is first applied, a `Tuijncode\LaravelWaf\Events\IpBanned` event
fires (with `$event->ipAddress` and `$event->seconds`) so you can mirror it to
a firewall or alert. Lift a ban early from code or the console:

```php
app(\Tuijncode\LaravelWaf\Services\AutoBanManager::class)->lift('203.0.113.9');
```

```bash
php artisan waf:unban 203.0.113.9
```

### Fail open or fail closed

If the cache store is down, signature inspection and blocking continue.
Flood counters, standing bans and deduplication are temporarily unavailable;
repeated findings may create separate rows. Exclusion rules are read directly
from the database. The WAF logs one warning per worker.

For other inspection errors, the WAF fails **open** by default: the request
goes through and the error is logged. Set `WAF_ON_ERROR=closed` to refuse those
requests with a `503` instead.

### Tuning out false positives

Four levers, cheapest first:

- **`paranoia_level`** — drop to `1` to run only the highest-confidence rules.
- **`safe_fields`** — exclude specific rich-text / free-form fields from scanning
  (below), the surgical fix for a field that legitimately carries markup or code.
- **`disabled_rules` / `disabled_categories`** — silence a specific noisy rule
  or a whole category pre-emptively.
- **Exclusion rules** — accept a specific finding on a specific path (below).

### Exclusion rules (false positives)

Suppress a noisy detection with the service, or build exclusions from a
threat you already logged:

```php
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;

app(ExclusionRuleService::class)->add('941130', pathGlob: 'editor/*');

app(ExclusionRuleService::class)->acceptFromLog(
    logId: $wafLogId,
    userId: auth()->id(),
    reason: 'Legitimate content in the CMS editor',
);
```

This creates one exclusion per rule or signal recorded in the finding's
`rule_ids`, scoped to its target, and returns the first created row.
New sensitive findings use a keyed target hash for this scope, so redacted URLs remain
private. An older finding with a fully redacted URL cannot be promoted safely;
create a manual exclusion with an explicit path instead. Run the published
`waf-migrations-upgrade` migrations before using this feature after upgrading.
Rotating `APP_KEY` invalidates hash-scoped exclusions; recreate those rules
from new findings after a rotation.
New findings store a keyed target hash whether their URL is visible or redacted,
so correlation counts both forms together. The upgrade backfill adds hashes to
older visible findings; fully redacted legacy rows without a hash remain
unscopable.
The upgrade migration also repairs existing log-derived root and literal-path
exclusions when their source log remains available. It deactivates exclusions
whose old source URL was fully redacted; review those rules after upgrading.
The separate orphaned-exclusion upgrade migration deactivates old unscoped
exclusions without a source log because their
origin cannot be established. This includes intentional manual global rules;
review and recreate those after the upgrade. With no `APP_KEY`, redacted
findings are logged without a target hash and cannot be promoted automatically.
The later orphaned-glob migration also deactivates wildcard rules without a
source log, including intentional manual rules. Review and recreate those
afterward.
Both service methods refresh the active-rule cache immediately. If you edit
`waf_exclusion_rules` directly, call `refresh()` after the database change.

A threat is suppressed when `match_label` exactly equals its rule id (for
example `941130`), its full description, or its complete stored `type`, and
its path matches the optional `path_glob` (wildcards supported; leave empty
to match any path). A partial label such as `94` does not match.

When every matching rule and signal is excluded, the finding is still written
to `waf_logs` with `action_taken = 'excluded'` (for auditing) and is not blocked.
A separate, unexcluded match keeps the request actionable. Blocklist exports
omit excluded findings.
Purging old findings keeps active exclusion rules; their `source_log_id` is
cleared when the source finding is removed.

### Safe fields

Some fields legitimately carry markup or code — a CMS body, a WYSIWYG editor, a
code-snippet field — and scanning them is pure noise. List them under
`safe_fields` to skip them, matched against each value's dot-notation path with
`*` wildcards:

```php
'safe_fields' => [
    'content',        // the "content" field and anything nested under it
    'post.body',      // a nested field
    'blocks.*.html',  // the "html" key of every entry in "blocks"
],
```

Inspection uses bounded overlapping windows. A signature must fit within
16 KiB of raw request input to be detected reliably across window boundaries;
operator custom patterns also check full raw surfaces and percent-decoded
surfaces up to 1 MiB. Use a dedicated streaming detector for larger encoded
matches.

When `safe_fields` is non-empty the raw request body / query string is no longer
scanned wholesale (that would smuggle a safe field's value straight back in); the
parsed input, minus the safe fields, is scanned in both structured and form-style
views. Unstructured bodies
(raw XML / text, which have no named fields to protect) are still scanned in full.

### Custom patterns

Detection draws on three layers, in order of precedence:

1. The built-in **OWASP core rules** (`Tuijncode\LaravelWaf\Rules\CoreRuleSet`).
2. The **default pattern pack** in `config/waf-patterns.php` (toggle with
   `WAF_PATTERN_PACK`).
3. Your **own signatures** in `config/waf.php` under `custom_patterns` — these
   win on a regex collision with the pack.

Add your own in `config/waf.php`:

```php
'custom_patterns' => [
    // Simple: regex => label (uses the default custom severity)
    '/\bmy-secret-token\b/i' => 'Internal Token Leak',

    // Full control over severity and which request parts to scan
    '/forbidden/i' => [
        'label'     => 'Forbidden Keyword',
        'severity'  => 'critical',                // critical|error|warning|notice
        'targets'   => ['query', 'body'],
        'validator' => 'luhn',                    // optional post-match check (built-in: luhn)
    ],
],
```

Matches are logged under the `custom` category with rule ids `CUSTOM-1`,
`CUSTOM-2`, … Invalid patterns are logged once and skipped.

A larger, ready-made **signature pack** ships separately in
`config/waf-patterns.php` and is merged in automatically:

- **Secrets & API keys** — AWS, Google, Slack, GitHub / GitLab, Stripe, Twilio,
  SendGrid, npm, DigitalOcean, AI providers, private-key material and JWTs.
- **Payment card data (PCI)** — Visa / Mastercard / Amex / Discover PANs,
  Luhn-validated so ordinary 16-digit values aren't mistaken for a card.
- **Sensitive files** — `.env`, `.git`, `.ssh`, `id_rsa`, `wp-config.php`,
  backup/archive artefacts.
- **Endpoint probing** — phpMyAdmin, WordPress, Spring Actuator, Apache status.
- **Framework / CVE probes** — Laravel Ignition RCE, PHPUnit eval-stdin,
  Spring4Shell, OGNL / Struts, server-side includes, prototype pollution.
- **Insecure deserialization** — Java and .NET payload markers.
- **SSTI / XSS / SQLi variants**, CRLF header injection, open redirect,
  GraphQL introspection, web shells, reverse shells and crypto miners.

The Ignition `/_ignition/execute-solution` route is blocked in blocking mode when
the WAF middleware runs globally. Probes served directly by the web server or
handled before Laravel starts (including an exposed PHPUnit file) never reach
this middleware; patch the affected software and restrict them at the server.

Credential signatures are scoped to the URL / query string (not request bodies),
so normal login POSTs and `Authorization: Bearer …` headers don't trip them.
Publish the file to customise, or turn the pack off entirely with
`WAF_PATTERN_PACK=false`. On a regex collision, your own pattern wins.

The optional AI probe list is configured under `ai_probes.paths` in `waf.php`.
It includes Ollama, compatible model APIs, MCP, agent configuration files and
selected AI application frameworks.
It checks decoded paths and ignores endpoints backed by a concrete application
route, including routes registered for another HTTP method. Its warning-level
finding is logged at the default confidence threshold; normal blocking mode
does not block it on its own. The `ai_probe` category or `AI-PROBE` rule can be
disabled like other findings. If you published `waf.php` before this setting
existed, add the `ai_probes` block from the package config before enabling it.

`WAF_PROBE_PATHS=true` similarly reports unserved paths such as `/swagger`,
`/cpanel` and `/wp-content/*`. Configure its list under `probe_paths.paths`.
Both probe lists are case-insensitive, handle percent-encoded paths and ignore
paths backed by an application route. The `probe` category or `PATH-PROBE` rule
can be disabled like other findings.
If application code changes a registered route URI in place with `setUri()`,
call `app(\Tuijncode\LaravelWaf\Services\WafInspector::class)->refreshRouteIndex($route)`
afterward. Registering or replacing routes normally needs no manual refresh.

`WAF_LLM_INJECTION=true` detects prompt role markers, instruction overrides,
triage manipulation and requests to reveal a system prompt in queries, bodies
and headers. The path and cookies are excluded. Findings use the
`llm_injection` category and `LLM-1` through `LLM-4` rule IDs; a single warning
does not block at the default threshold. Enable this only when your app or log
triage pipeline handles untrusted text with an AI model.

Log redaction is enabled by default. `waf.redact.fields` can override the
built-in credential field names; the built-in list also applies when an older
published `waf.php` has no `fields` entry.
When a sensitive rule fires, the stored URL, evidence and User-Agent become
`[REDACTED]`. The rule IDs, category, score and client IP remain available.

### Queue support

Set `WAF_QUEUE=true` to dispatch the `waf_logs` insert to a queue instead of
writing it inline. The `ThreatDetected` event still fires synchronously, so
blocking decisions remain immediate. Use an asynchronous queue connection for
delayed retries; Laravel's `sync` connection writes and counts inline.

### Correlation analytics

Some attacks only show up in aggregate. `CorrelationAnalyzer` mines `waf_logs`
for distributed activity — one target hit from many IPs, one attack class
spreading across the fleet, or a single IP hammering many endpoints:

```php
use Tuijncode\LaravelWaf\Services\CorrelationAnalyzer;

$analyzer = app(CorrelationAnalyzer::class);
$analyzer->coordinatedAttacks(windowMinutes: 15, minIps: 3);
$analyzer->campaigns(windowHours: 24, minIps: 5);
$analyzer->rapidAttackers(windowMinutes: 5, minHits: 10);
$analyzer->mutationChains(windowMinutes: 60, minVariants: 3);
$analyzer->retryBursts(windowMinutes: 60, minPayloads: 5);
$analyzer->sharedPayloads(windowMinutes: 60, minIps: 3, minPayloads: 2);
$analyzer->rankActors(windowMinutes: 60, limit: 10);
$analyzer->summary(); // includes mutation_chains, retry_bursts and shared_payloads
```

Because identical threats are deduplicated (see `dedup_minutes`), each finding
carries a `hit_count` — every request the dedup window folded into it. The
analyzer sums `hit_count` rather than counting rows, so a high-volume flood of a
single signature still surfaces as a rapid attacker instead of collapsing to a
count of one. This also includes duplicates received while a queued finding is
waiting to be stored.

To compare attempts that deduplication hides, publish and run the optional
migration, then set `WAF_ATTEMPTS=true`:

```bash
php artisan vendor:publish --tag=waf-migrations-attempts
php artisan migrate
```

The attempt table stores IP, rule id and two short hashes keyed with `APP_KEY`,
not raw payloads. Recording is skipped if `APP_KEY` is missing.
It records at most 200 distinct variants per IP in a 60-minute window by
default. `waf:correlate` reports IPs sending at least three raw variants of
the same normalised input; `waf:purge` removes attempt rows older than seven
days by default. Set `WAF_RETENTION=true` and run Laravel's scheduler to purge
automatically; otherwise run `waf:purge` yourself. `Waf::inspect()` remains
read-only.

`retryBursts()` spots one IP trying different payloads against a rule.
`sharedPayloads()` requires at least two payload fingerprints shared by the
same group of at least three IPs. `rankActors()` orders IPs for investigation
using a 0–100 score with four visible parts: peak severity, hit volume,
category diversity and mutation count. Every IP in the time window is scored
before the result limit is applied. This score does not block requests.
Run `waf:correlate --rank` to include the ranking in console output.
Shared-payload analysis inspects at most `waf.attempts.max_correlation_rows`
(10,000 by default); exceeding the budget returns an error rather than a
partial result. Raise the budget up to 100,000 if the host has sufficient memory.

Duplicates arriving before the first insert are held in the cache and added
when that insert succeeds. With direct storage, later duplicates update
`hit_count` immediately. With queued storage, they are grouped into a delayed
flush job, so the stored count can lag until the queue runs that job. Each
queued duplicate also gets an idempotent hit job. This preserves its count if
the cache restarts before a flush, at the cost of one queue job and one small
database record per duplicate. A durable total keeps processing work bounded
as a burst grows. `waf:purge` removes old hit records and totals.

### Console commands

```bash
php artisan waf:doctor                # verify the WAF is installed, wired and recording
php artisan waf:stats --days=7        # summary: counts by category / severity / IP
php artisan waf:correlate             # surface coordinated / distributed attacks
php artisan waf:correlate --rank      # include the IP risk ranking
php artisan waf:purge --days=90       # delete findings older than N days
php artisan waf:unban 203.0.113.9     # lift a standing auto-ban for an IP
php artisan waf:test "payload"        # dry-run a payload and see what it trips
php artisan waf:export --format=nginx # export offending IPs as a blocklist
```

Set `WAF_RETENTION=true` (and `WAF_RETENTION_DAYS`) to run the purge
automatically every day at 02:00 via Laravel's scheduler.

If queued finding storage is enabled and the queue rejects a job, the WAF tries
to write that finding directly. This keeps the audit trail available but can
add database latency while the queue is unavailable.
Queued writes and pending hit-count flushes keep retrying through temporary
database outages. Keep the queue and cache available to preserve that audit trail.
Before enabling `WAF_QUEUE`, publish and run the `waf-migrations-upgrade`
migrations to create `waf_hit_events` and `waf_hit_totals` (or use
`waf-migrations` on a fresh installation). The totals migration backfills
existing hit records. On an upgrade, run it before restarting queue workers
with the new package code. The same migration tag creates
`waf_purge_watermarks`, which `waf:purge` requires. Each purge records its cutoff
even when no old findings exist, so delayed queue jobs cannot restore them.
Laravel `model:prune` for `WafLog` also requires this migration and records the
cutoff on every enabled run, including runs with no old rows. It fails before
processing findings if the migration is missing.
`waf:doctor` checks these tables and their columns.
A missing schema is a permanent job failure; database outages continue to retry.

#### Health check (`waf:doctor`)

A WAF fails quietly: a log table left behind by an upgrade that never ran its
migration, a middleware that was never wired to a route, a config published two
versions ago that freezes out every signature shipped since. In each case the
log simply stays empty — which looks exactly like "no attacks".

```bash
php artisan waf:doctor
```

It checks that the WAF is enabled for this environment, that `waf_logs` has
every column the writer needs (a missing one discards **every** finding), that
the exclusion table exists, that the middleware is genuinely applied to a route
or group, that your published config and pattern pack haven't drifted behind
this version, and that the cache driver can support flood counting, bans and
dedup. It also warns when every connecting proxy is trusted (which can make IP
decisions spoofable if the app is reachable directly), or when attempt recording
has no scheduled purge. Each finding prints the command or setting that fixes
it, and the command exits non-zero only on a real failure — so it drops straight
into CI or a deploy step. Invalid WAF configuration fails the check.

#### Dry-running a payload (`waf:test`)

Reproduce a false positive or check a rule without sending a live request:

```bash
php artisan waf:test "' UNION SELECT * FROM users--"
php artisan waf:test --path=/search --query="q=<script>alert(1)</script>"
php artisan waf:test "payload" --ua="sqlmap/1.7" --header="X-Forwarded-For: 1.2.3.4"
```

It prints the signatures that matched (rule id, category, severity, surface and
the matched substring), any scanner / bot / flood signals, and the confidence
score with whether the request would block at your current threshold. It runs
the read-only inspection path — nothing is logged, counted or blocked. The
verdict assumes the request reaches the WAF middleware for inspection; it does
not account for disabled middleware, skipped paths or IP allow/block lists.

#### Exporting a blocklist (`waf:export`)

Turn recorded findings into an edge blocklist for fail2ban, nginx, Apache, or a
spreadsheet:

```bash
php artisan waf:export                                  # plain IP list (stdout)
php artisan waf:export --format=nginx > /etc/nginx/waf-deny.conf
php artisan waf:export --format=fail2ban --jail=laravel-waf | sh
php artisan waf:export --format=csv --min-level=critical --days=7 --min-hits=5
```

Offending IPs are grouped and ordered by total hit volume. Filter with
`--min-level` (severity floor, default `error`), `--days` (recent window),
`--min-hits` and `--limit`. Formats: `plain` (one IP per line), `fail2ban`
(`fail2ban-client set <jail> banip <ip>` lines — set the jail with `--jail`),
`nginx` (`deny <ip>;`), `apache` (`Require not ip <ip>`) and `csv`. Data goes to
stdout for redirection; the export count and any notices go to stderr, keeping
the piped output clean. Invalid numeric options fail before any IP is exported.

### Querying findings

Findings are written with the query builder, but a read-side Eloquent model is
provided for reporting:

```php
use Tuijncode\LaravelWaf\Models\WafLog;

WafLog::where('category', 'sqli')->latest()->take(20)->get();
```

It is `Prunable`: with retention enabled, `php artisan model:prune --model="Tuijncode\LaravelWaf\Models\WafLog"`
deletes findings past `retention.days`, an alternative to `waf:purge` if you
already run Laravel's pruning scheduler. Both paths keep standing exclusion
rules and clear their reference to a deleted finding. `model:prune` respects
Laravel's `--chunk` setting and fires individual Eloquent delete events;
`waf:purge` is the faster choice for large retention batches.

### Configuration validation

At boot the package checks your config and logs a warning (never throws) for
anything invalid — a bad `mode`, an out-of-range `paranoia_level`, a severity
typo, an unknown `disabled_categories` entry. Warnings are throttled to once an
hour per problem set. Disable with `WAF_VALIDATE_CONFIG=false`.

## Testing & quality

```bash
composer test         # Pest suite
composer test:style   # Pint (code style, --test)
composer test:types   # PHPStan / Larastan static analysis
```

The suite drives real requests through the middleware and asserts on the logged
finding. Among the cases it covers are the canonical attacks:

| Attack              | Example request                              |
|---------------------|----------------------------------------------|
| SQL injection       | `/?q=' UNION SELECT * FROM users--`          |
| XSS                 | `/?q=<script>alert(1)</script>`              |
| Directory traversal | `/?file=../../etc/passwd`                    |
| RCE                 | `/?cmd=system('ls -la')`                     |

CI runs the suite across PHP 8.2–8.5 and Laravel 10–13.
The MySQL/PostgreSQL lock test also needs `WAF_TEST_DB_DRIVER`, a dedicated
`WAF_TEST_DB_NAME` ending in `_test`, and `WAF_TEST_RESET_DB=1`; it recreates
the WAF test tables in that database.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
