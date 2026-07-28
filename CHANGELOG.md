# Changelog

All notable changes to `tuijncode/laravel-waf` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-07-28

### Fixed

- Whitelist and denylist entries are now trimmed at match time, in the
  middleware itself. The shipped config already trims on parse (since 1.2.0),
  but an application still running a published `config/waf.php` copy that
  predates that fix passed untrimmed entries (`"1.2.3.4, 5.6.7.8"` split on
  commas) straight to the IP check, where a space-prefixed entry silently
  never matches — leaving a whitelist (or denylist) that had quietly stopped
  working. Matching no longer depends on which copy of the config the
  application has published.

## [1.2.0] - 2026-07-24

### Added

- New Shellshock (CVE-2014-6271) signature (rule 932140), matching the empty
  function-definition injection across the query, body, headers and cookies.
- Windows command-execution signature (rule 932150) covering `cmd.exe /c`,
  PowerShell with an execution flag (`-enc`, `-command`, `iex`, `invoke-`,
  `downloadstring`), `wscript.exe` / `cscript.exe` and `net user` /
  `net localgroup` — the existing RCE rules only knew unix binaries.
- Encoded-loopback SSRF signature (rule 934130): the hex (`0x7f000001`),
  decimal (`2130706433`), octal (`0177.0.0.1`) and `::ffff:127.*` forms of
  127.0.0.1 that bypass the plain loopback rule.
- DNS-rebinding SSRF signature (rule 934140) for IP-embedding services
  (`nip.io`, `sslip.io`, `xip.io`).
- SQL `CHAR()` / `CHR()` character-code encoding signature (rule 942180),
  requiring four or more codes so a legitimate single `CHAR(10)` is left alone.
- PHP RCE-prone function/setting signature (rule 933140): `preg_replace` with
  the code-evaluating `/e` modifier, `allow_url_include` / `allow_url_fopen`
  and `php_uname()`.
- LDAP injection (rule 943100, category `ldapi`) and XPath injection (rule
  943110, category `xpathi`) signatures. Both overlap with ordinary
  punctuation, so they run only at paranoia level 2.
- Java deserialization detection now also matches the raw/hex stream magic
  (`aced0005…`) alongside the existing base64 (`rO0AB…`) form.
- Scanner fingerprints for Arachni, Wapiti, Skipfish, Commix, Jaeles, Dalfox,
  XSStrike, JoomScan, DroopeScan, WhatWeb, Qualys, FeroxBuster, FFUF and Wfuzz.
- Request normalisation now also decodes IIS `%uXXXX` escapes (e.g.
  `%u003cscript%u003e` → `<script>`) and JS/JSON-style backslash escapes
  (`\uXXXX` and `\xXX`), closing encoding-based evasions that ordinary
  percent-decoding left intact.
- Extra signatures: CSS `expression()` XSS (rule 941170), SQL `UNHEX()` hex
  decoding (rule 942190), `get_current_user()` folded into the PHP RCE rule
  (933140), and Drupalgeddon2 render-array injection (CVE-2018-7600) in the
  pattern pack.
- Request normalisation now folds away SQL comments, so inline-comment evasion
  (a block comment wedged between `UNION` and `SELECT`, a MySQL executable
  comment `/*!…*/`, or a trailing `-- ` / `#`) is caught by the keyword rules
  even at paranoia level 1 — where the broad comment-sequence rule (942170) is
  off and the previously un-normalised payload slipped through entirely.
- Static IP denylist (`blocklisted_ips`, `WAF_BLOCKLISTED_IPS`): CIDR-aware,
  refused up front before any inspection, on every path and in either mode —
  the deny-side mirror of `whitelisted_ips`. A whitelisted IP wins on overlap.
- `safe_fields`: exclude named input fields from inspection to silence false
  positives on rich-text / free-form fields, without disabling a whole rule.
  Matches the dot-notation path of each value with `*` wildcards (`content`,
  `post.body`, `blocks.*.html`); when set, the raw body/query is no longer
  scanned wholesale so a safe field's value can't leak back in.
- `waf:test` command: dry-run a payload through the inspector and print the
  signatures it trips, the confidence/anomaly/severity, and whether it would
  block — for tuning rules and reproducing a false positive. Read-only: nothing
  is logged, counted or blocked.
- `waf:export` command: export offending IPs from `waf_logs` as an edge
  blocklist (`plain`, `nginx`, `apache`, `csv`), filtered by `--min-level`,
  `--days`, `--min-hits` and `--limit`, ordered by hit volume. Data goes to
  stdout for redirection; the CSV path carries a formula-injection guard.

### Fixed

- A single invalid UTF-8 byte in any request field no longer blinds the WAF to
  the whole parsed surface: `json_encode` returned `false` on such input and the
  surface silently became an empty string. On multipart requests (where no raw
  body is available to fall back on) that made the entire body invisible to
  every signature. Encoding now uses `JSON_INVALID_UTF8_SUBSTITUTE`.
- The OWASP ZAP scanner fingerprint is no longer the bare substring `zap`,
  which also matched legitimate agents such as Zapier's webhook client. It now
  matches `owasp zap` and `zaproxy`.
- A failed `waf_logs` write no longer claims the dedup slot: the finding was
  suppressed for the whole dedup window with nothing stored, so a transient
  database error could drop an attack from the log entirely. The slot is now
  released on a failed write and the next occurrence retries.
- Comma-separated `WAF_WHITELISTED_IPS` / `WAF_WHITELISTED_AGENTS` entries are
  now trimmed, so `"1.2.3.4, 5.6.7.8"` whitelists the second address too
  (previously the leading space made it silently never match).
- `vendor:publish --tag=waf-migrations` is now idempotent: a migration
  published earlier keeps its filename instead of being duplicated under a
  fresh timestamp on every re-publish.
- Declared the `illuminate/bus`, `illuminate/console`, `illuminate/events` and
  `illuminate/queue` dependencies that the console commands, events and the
  queued log job import.
- `waf:purge` now selects the findings to delete (and their dependent exclusion
  rules) with a DB-side subquery instead of loading every doomed id into PHP
  memory, so a large purge no longer risks a memory spike.

## [1.1.0] - 2026-07-15

### Added

- Auto-ban: with `WAF_AUTO_BAN=true` (blocking mode), an IP that earns
  `auto_ban.max_blocks` blocks inside a rolling `auto_ban.window` is refused up
  front for `auto_ban.duration` seconds — without running the inspection
  pipeline on every request. Bans are cache-based and expire on their own;
  banned responses carry a `Retry-After` header. A `IpBanned` event fires when
  a ban is applied, `AutoBanManager::lift()` and `php artisan waf:unban {ip}`
  clear one early.
- Fail-open / fail-closed choice: `WAF_ON_ERROR=closed` refuses requests with a
  `503` when inspection itself throws, instead of the default fail-open.
- The client names of uploaded files are now inspected on the `body` surface,
  so a `c99.php`-style web shell upload is caught by name. The binary content
  itself is never scanned.
- Named post-match validators for signatures: a signature can name a `validator`
  (built-in: `luhn`) that a regex hit must also pass. The bundled card-number
  rule now Luhn-validates, so ordinary 16-digit values (order ids, tracking
  numbers) are no longer flagged as a PAN.
- User-Agent allowlist (`whitelisted_agents`): trusted automated clients (e.g. a
  known uptime monitor) are exempt from bot detection, while signature, scanner
  and flood detection still apply.
- `ddos.block` toggle: a flood scores below `block_confidence` by design, so in
  blocking mode it was logged but never refused. Enable `ddos.block` (or
  `WAF_DDOS_BLOCK=true`) to refuse an over-budget client on the flood signal
  alone, with a `Retry-After` header.
- `hit_count` column on `waf_logs`: a duplicate collapsed by the dedup window
  now bumps the existing finding's counter instead of being dropped, so the
  true request volume stays on the record. The correlation analytics sum it, so
  `waf:correlate`'s rapid-attacker detection sees a single-signature flood that
  row-counting previously missed. (Under queueing the row id isn't known
  synchronously, so duplicates there aren't tallied.) To keep this off the
  database on a route under attack, the bumps are accumulated in the cache and
  written back at most once per `dedup_flush_seconds` (default 10; set to 0 for
  an exact, write-per-duplicate count) — so the stored count is eventually
  consistent rather than costing one UPDATE per request.
- `RequestBlocked` is throttled to once per IP + signature per dedup window
  (matching how often the finding is logged), so a flood — especially with
  `ddos.block` on — can't drown a listener in duplicate block events. The
  auto-ban strike still counts every blocked request, so a ban is still earned
  quickly.
- Every finding carries an `event_id` (UUID) column, also passed on the
  `ThreatDetected` event, so a listener can reference the stored row even when
  the insert is queued.
- Read-side `WafLog` Eloquent model, `Prunable` for retention via Laravel's
  `model:prune`.
- `dedup_include_path`: fold the request path into the dedup key so the same
  attack across many endpoints stays visible to the correlation analytics
  instead of collapsing into one finding.
- Config validation now also covers `custom_patterns` and the pattern pack (the
  regex must compile, severities/target surfaces/validators must be known — a
  typo like `targets: ['querry']` previously made a pattern silently dead), plus
  `enabled_environments` and the new `on_error` / `auto_ban` options.
- The `waf_logs` migration indexes `created_at`; purge, stats and correlation
  analytics all filter on it, against a table that grows fastest under attack.
- Upgrade migration (`waf-migrations-upgrade` publish tag) that adds the
  `event_id` and `hit_count` columns and the `created_at` index to an existing
  `waf_logs` table. Idempotent, so it is safe on a table that already has them.

### Fixed

- `$`-anchored pack patterns (the `.env`, `.git` and `.svn` probes and the
  backup/archive probe) missed hits at the end of a query parameter: inspected
  surfaces are newline-joined decode variants, and without `/m` the `$` anchor
  only matches at the very end of the joined string. Most notably the decisive
  `.env` rule did not fire on `?file=.env`. These patterns now carry `/m`.
- The Sensitive Artefact Probe (`.bash_history`, `.zsh_history`, `.DS_Store`)
  never matched a real probe: a leading `\b` before the literal dot required a
  word boundary that `/.DS_Store` doesn't have. The boundary is removed.
- The `web.config` probe missed the query-value variant — a `^` anchor without
  `/m`, the same class of bug as the `$` anchors. It now carries `/m` and a
  wider set of leading delimiters.
- Bot-only findings were never recorded under the default configuration: a
  lone bot signal scored 8, below the default `min_confidence` of 10. It now
  scores 12, so scripted clients (curl, python-requests, headless browsers)
  actually show up in `waf_logs`.
- Payloads larger than the 16 KB per-surface cap are now sampled head + tail
  instead of hard-truncated, so prepending 16 KB of padding can no longer push
  an attack out of the inspected window.
- Catastrophic regex cost on floods: the SSTI object-access, Ruby-interpolation,
  CRLF-injection and obfuscated-Log4Shell signatures used unbounded spans that
  turn quadratic on a long `{{{{…`, `#{#{…` or `\r\n\r\n…` run (a crafted
  request could pin a worker for minutes). Spans are bounded, the SSTI and Ruby
  rules only start at the first delimiter of a run, and the CRLF rule no longer
  lets `\s*` swallow further line breaks. `PerformanceTest` now covers all of
  these flood shapes.
- `Waf::inspect()` is now truly read-only: it no longer advances the flood
  counter, which double-counted DDoS hits when the facade was used alongside
  the middleware. Counting moved to `handle()`; `DdosMonitor::tripped()` is a
  pure check and the new `DdosMonitor::hit()` registers a request.
- Captured match values are no longer truncated at 200 characters, which left
  the tail of a long secret (e.g. a JWT) unmasked in the stored URL and
  payload. The capture cap is now 1024 characters.
- Exclusion rules with a `match_label` shorter than 3 characters are ignored:
  the label is matched as a substring, so `"94"` would silently suppress every
  `94x`-family rule.
- `DdosMonitor` constructor arguments were dead — the merged config always
  overrode them. Explicit arguments now win over the config.
- `CorrelationAnalyzer::rapidAttackers()` under-counted: it ran `COUNT(*)` per
  IP, but the 5-minute dedup window collapsed a burst of one attack into a
  single row, so a high-volume single-signature flood scored 1 and slipped past
  the threshold. It now sums `hit_count`.

### Changed

- Livewire's asset routes are still skipped, but its `livewire/update` endpoint
  is now inspected by default — it carries user input worth checking. Add
  `livewire/*` back to `skip_paths` if that proves too noisy.
- `CoreRuleSet::rules()` is built once per process instead of building ~40
  signature objects on every request (relevant under Octane).

## [1.0.2] - 2026-07-11

### Fixed

- The exclusion allow-list no longer silently disables the WAF under Laravel's
  restricted cache deserialization. `ExclusionRuleService` cached the active
  rules as an `Illuminate\Support\Collection`, but cache stores unserialize with
  an `allowed_classes` restriction (`cache.serializable_classes`, which defaults
  to `false` in Laravel 12+), so on every cache hit the value came back as
  `__PHP_Incomplete_Class`. `active()` then threw a `TypeError`, `WafMiddleware`
  caught it and failed open — letting every request through, including probes
  that would otherwise be blocked. The active set is now cached as plain arrays
  and the objects are rebuilt on read, so no host-application config change is
  needed.

### Changed

- The config publish tag `waf-config` still publishes both config files, and each
  file can now be published on its own: `waf-config-main` for `config/waf.php` and
  `waf-config-patterns` for `config/waf-patterns.php`.

## [1.0.1] - 2026-07-08

### Added

- Decisive signatures: a `decisive` flag on custom patterns forces confidence to
  100 on a single match, so unambiguous probes are blocked outright regardless of
  `block_confidence`. The bundled `.env`, `.git`, `.svn`, credential-directory,
  SSH private key and server-config probes are now decisive.

### Fixed

- A bare `.env` / `.git/config` probe from an ordinary client no longer slips
  through in blocking mode. Previously a lone file-probe hit scored 37 (below the
  default block threshold of 60), because a single signature could never reach the
  threshold on the anomaly math alone.

## [1.0.0] - 2026-07-06

### Added

- OWASP Core Rule Set inspection engine covering SQL injection, XSS, RCE, LFI /
  directory traversal, RFI, SSRF, XXE, Log4Shell, NoSQL injection, PHP injection
  and command injection.
- Scanner, bot and rate-based flood detection.
- 0–100 confidence scoring with an anomaly score and categorical label.
- `waf_logs` storage and the `ThreatDetected` event for custom responses.
- Detection / blocking modes with a configurable block response (status,
  message, JSON, custom view, `Retry-After`) and a `RequestBlocked` event.
- Rule tuning: `paranoia_level`, `disabled_rules` and `disabled_categories`.
- A bundled signature pack (`config/waf-patterns.php`) of provider secrets,
  card numbers, sensitive files, framework/CVE probes, deserialization, SSTI,
  CRLF, open redirect and more — toggleable and mergeable with your own
  `custom_patterns`.
- Exclusion rules for accepted false positives (logged as `excluded`).
- Secret redaction: captured API keys, passwords and card numbers are masked
  before being written to `waf_logs`.
- Evasion-resistant surface normalisation: double URL-decode, HTML-entity decode
  and null-byte stripping.
- Correlation analytics (`CorrelationAnalyzer` + `waf:correlate`) for coordinated
  attacks, campaigns and rapid attackers.
- Boot-time configuration validation (logs warnings, never throws).
- Queue support for off-request logging.
- `waf:purge` (with an optional daily retention schedule), `waf:stats` and
  `waf:correlate` console commands.
- Typed value objects (`Signature`, `SignatureMatch`, `Detection`) throughout the
  engine.
