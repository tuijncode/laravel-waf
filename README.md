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
  even at paranoia 1); oversized payloads are sampled head + tail so padding can't
  push an attack out of view, and the client names of uploaded files are inspected
  too.
- **Secret redaction** — captured API keys, passwords and card numbers are masked
  before they reach `waf_logs`.
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
- **Operator tooling** — dry-run a payload (`waf:test`) and export offending IPs as
  a fail2ban / nginx / Apache / CSV blocklist (`waf:export`), alongside stats,
  purge and unban commands.
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
exist yet at dispatch time.

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
| `whitelisted_ips`     | `[]`        | CIDR-aware IP allowlist (skips inspection).                  |
| `blocklisted_ips`     | `[]`        | CIDR-aware IP denylist (refused up front, any mode).         |
| `whitelisted_agents`  | `[]`        | User-Agent substrings exempt from bot detection.             |
| `dedup_include_path`  | `false`     | Add the path to the dedup key (one finding per path).        |
| `dedup_flush_seconds` | `10`        | Coalesce `hit_count` writes; `0` writes every bump through.  |
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

If inspection itself throws (say the cache store is down), the WAF fails
**open** by default: the request goes through and the error is logged, so the
WAF can never take your application down. Operators who prefer security over
availability — typically in blocking mode — can set `WAF_ON_ERROR=closed` to
refuse requests with a `503` instead.

### Tuning out false positives

Four levers, cheapest first:

- **`paranoia_level`** — drop to `1` to run only the highest-confidence rules.
- **`safe_fields`** — exclude specific rich-text / free-form fields from scanning
  (below), the surgical fix for a field that legitimately carries markup or code.
- **`disabled_rules` / `disabled_categories`** — silence a specific noisy rule
  or a whole category pre-emptively.
- **Exclusion rules** — accept a specific finding on a specific path (below).

### Exclusion rules (false positives)

Suppress a noisy detection by inserting a row into `waf_exclusion_rules`, or
build one from a threat you already logged:

```php
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;

app(ExclusionRuleService::class)->acceptFromLog(
    logId: $wafLogId,
    userId: auth()->id(),
    reason: 'Legitimate content in the CMS editor',
);
```

A threat is suppressed when its `type` contains the rule's `match_label`
(e.g. a rule id like `941130`) and its path matches the optional
`path_glob` (wildcards supported; leave empty to match any path). Labels
shorter than 3 characters are ignored — a substring like `94` would otherwise
silently suppress entire rule families.

Excluded threats are still written to `waf_logs` with `action_taken = 'excluded'`
(for auditing) but are never blocked.

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

When `safe_fields` is non-empty the raw request body / query string is no longer
scanned wholesale (that would smuggle a safe field's value straight back in); the
parsed input, minus the safe fields, is scanned instead. Unstructured bodies
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

Credential signatures are scoped to the URL / query string (not request bodies),
so normal login POSTs and `Authorization: Bearer …` headers don't trip them.
Publish the file to customise, or turn the pack off entirely with
`WAF_PATTERN_PACK=false`. On a regex collision, your own pattern wins.

### Queue support

Set `WAF_QUEUE=true` to dispatch the `waf_logs` insert to a queue instead of
writing it inline. The `ThreatDetected` event still fires synchronously, so
blocking decisions remain immediate.

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
$analyzer->summary(); // ['coordinated_attacks' => …, 'campaigns' => …, 'rapid_attackers' => …]
```

Because identical threats are deduplicated (see `dedup_minutes`), each finding
carries a `hit_count` — every request the dedup window folded into it. The
analyzer sums `hit_count` rather than counting rows, so a high-volume flood of a
single signature still surfaces as a rapid attacker instead of collapsing to a
count of one. (Under queueing, duplicates aren't tallied — the row id isn't
known synchronously — so `hit_count` stays 1 there.)

To keep this off the database on a route under attack, duplicate bumps are
accumulated in the cache and flushed at most once per `dedup_flush_seconds`
(default 10), so the stored count is eventually consistent rather than one
`UPDATE` per request. Set `dedup_flush_seconds` to `0` for an exact, immediate
count if you'd rather trade the write.

### Console commands

```bash
php artisan waf:stats --days=7        # summary: counts by category / severity / IP
php artisan waf:correlate             # surface coordinated / distributed attacks
php artisan waf:purge --days=90       # delete findings older than N days
php artisan waf:unban 203.0.113.9     # lift a standing auto-ban for an IP
php artisan waf:test "payload"        # dry-run a payload and see what it trips
php artisan waf:export --format=nginx # export offending IPs as a blocklist
```

Set `WAF_RETENTION=true` (and `WAF_RETENTION_DAYS`) to run the purge
automatically every day at 02:00 via Laravel's scheduler.

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
the read-only inspection path — nothing is logged, counted or blocked.

#### Exporting a blocklist (`waf:export`)

Turn recorded findings into an edge blocklist for fail2ban, nginx, Apache, or a
spreadsheet:

```bash
php artisan waf:export                                  # plain IP list (stdout)
php artisan waf:export --format=nginx > /etc/nginx/waf-deny.conf
php artisan waf:export --format=csv --min-level=critical --days=7 --min-hits=5
```

Offending IPs are grouped and ordered by total hit volume. Filter with
`--min-level` (severity floor, default `error`), `--days` (recent window),
`--min-hits` and `--limit`. Formats: `plain` (one IP per line — also suits a
fail2ban blocklist), `nginx` (`deny <ip>;`), `apache` (`Require not ip <ip>`)
and `csv`. Data goes to stdout for redirection; the export count and any notices
go to stderr, keeping the piped output clean.

### Querying findings

Findings are written with the query builder, but a read-side Eloquent model is
provided for reporting:

```php
use Tuijncode\LaravelWaf\Models\WafLog;

WafLog::where('category', 'sqli')->latest()->take(20)->get();
```

It is `Prunable`: with retention enabled, `php artisan model:prune --model="Tuijncode\LaravelWaf\Models\WafLog"`
deletes findings past `retention.days`, an alternative to `waf:purge` if you
already run Laravel's pruning scheduler.

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

## License

MIT — see [LICENSE.txt](LICENSE.txt).
