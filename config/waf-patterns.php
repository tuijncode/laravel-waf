<?php

/*
|--------------------------------------------------------------------------
| WAF Default Pattern Pack
|--------------------------------------------------------------------------
|
| A ready-made library of extra signatures layered on top of the OWASP Core
| Rule Set. Two value formats are supported per entry:
|
|   '/regex/i' => 'Label',                                   // default severity
|   '/regex/i' => ['label' => '...', 'severity' => '...', 'targets' => [...]],
|
| severity : critical | error | warning | notice   (default: WAF_CUSTOM_SEVERITY)
| targets  : which request parts to scan — query, body, path, headers, cookie
|            (default: all of them)
| decisive : true marks a hit as a certain attack (e.g. a bare `.env` probe).
|            One match forces confidence to 100, so blocking mode blocks it
|            outright — no second signal or lowered block_confidence needed.
|
| False-positive discipline:
|   - Secret/token formats are specific enough to scan everywhere.
|   - "Leaked in the URL" credential rules are scoped to query/path so normal
|     login POST bodies and `Authorization: Bearer …` headers don't trip them.
|   - File/endpoint probes are scoped to query/path (not headers) so a benign
|     Referer can't raise them.
|
| Merged with your own `waf.custom_patterns` (yours wins on a regex collision).
| Disable the whole pack with WAF_PATTERN_PACK=false.
|
*/

$c = fn (string $label, array $targets = []) => array_filter([
    'label' => $label, 'severity' => 'critical', 'targets' => $targets,
]);
$e = fn (string $label, array $targets = []) => array_filter([
    'label' => $label, 'severity' => 'error', 'targets' => $targets,
]);
$w = fn (string $label, array $targets = []) => array_filter([
    'label' => $label, 'severity' => 'warning', 'targets' => $targets,
]);
$n = fn (string $label, array $targets = []) => array_filter([
    'label' => $label, 'severity' => 'notice', 'targets' => $targets,
]);
// Decisive: a certain attack. Critical severity + forces confidence to 100 so a
// single hit blocks outright (see the `decisive` note in the header above).
$d = fn (string $label, array $targets = []) => array_filter([
    'label' => $label, 'severity' => 'critical', 'targets' => $targets, 'decisive' => true,
]);

return [

    'custom' => [

        // ---------------------------------------------------------------
        // Secrets, keys & tokens (specific provider formats)
        // ---------------------------------------------------------------
        '/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/' => $c('Private Key Material'),
        '/\bAKIA[0-9A-Z]{16}\b/' => $c('AWS Access Key ID'),
        '/\bASIA[0-9A-Z]{16}\b/' => $c('AWS Temporary Access Key'),
        '/\bAIza[0-9A-Za-z_\-]{35}\b/' => $c('Google API Key'),
        '/\bya29\.[0-9A-Za-z_\-]{20,}/' => $c('Google OAuth Token'),
        '/"type"\s*:\s*"service_account"/i' => $c('GCP Service Account Key'),
        '/\bxox[baprs]-[0-9A-Za-z\-]{10,}/' => $c('Slack Token'),
        '/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+/' => $c('Slack Webhook URL'),
        '/\bgh[pousr]_[0-9A-Za-z]{30,}\b/' => $c('GitHub Token'),
        '/\bgithub_pat_[0-9A-Za-z_]{22,}\b/' => $c('GitHub Fine-grained Token'),
        '/\bglpat-[0-9A-Za-z_\-]{20,}\b/' => $c('GitLab Access Token'),
        '/\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/' => $c('Stripe Secret Key'),
        '/\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{24,}\b/' => $c('AI Provider API Key'),
        '/\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b/' => $c('SendGrid API Key'),
        '/\b(?:AC|SK)[0-9a-fA-F]{32}\b/' => $c('Twilio Credential'),
        '/\bkey-[0-9a-zA-Z]{32}\b/' => $c('Mailgun API Key'),
        '/\bnpm_[0-9A-Za-z]{36}\b/' => $c('npm Access Token'),
        '/\bdop_v1_[0-9a-f]{64}\b/' => $c('DigitalOcean Token'),
        '/\bsq0(?:atp|csp)-[0-9A-Za-z_\-]{22,}/' => $c('Square Token'),
        '/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/' => $w('JWT Detected', ['query', 'path']),

        // ---------------------------------------------------------------
        // Credentials leaked in the URL / query string
        // ---------------------------------------------------------------
        '/(?:access|api|secret|private|auth|client)[_-]?(?:token|key|secret)\s*[=:]\s*["\']?[A-Za-z0-9\-_\.=]{16,}/i' => $e('API Key / Token in URL', ['query', 'path']),
        '/[?&](?:password|passwd|pwd)=[^&\s]{3,}/i' => $e('Password in URL', ['query', 'path']),
        '/\b(?:php|j)?session(?:_?id)?\s*=\s*["\']?[A-Za-z0-9]{16,}/i' => $w('Session ID in URL', ['query', 'path']),
        '/\/\/[^\/\s:@]+:[^\/\s:@]+@/' => $e('Credentials in URL (user:pass@)', ['query', 'body']),

        // ---------------------------------------------------------------
        // Credit / debit card numbers — Visa / Mastercard / Amex / Discover
        // ---------------------------------------------------------------
        // Guarded by a Luhn check so ordinary 16-digit values (order ids,
        // tracking numbers) are not mistaken for a PAN.
        '/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/' => [
            'label' => 'Credit / Debit Card Number',
            'severity' => 'critical',
            'targets' => ['query', 'body'],
            'validator' => 'luhn',
        ],

        // ---------------------------------------------------------------
        // Sensitive file & directory access
        // ---------------------------------------------------------------
        // Patterns anchored on `$` need /m: inspected surfaces are newline-joined
        // variants (raw + decoded + parsed), so "end of value" is a line end.
        '/\.env(?:\.[a-z]+)?(?:$|[?&\/])/im' => $d('Environment File Access', ['query', 'path']),
        '/\.git(?:\/(?:config|HEAD|index)|\/|\\\\|$)/im' => $d('Git Directory Access', ['query', 'path']),
        '/\.svn(?:\/|\\\\|$)/im' => $d('SVN Directory Access', ['query', 'path']),
        '/\.(?:ssh|aws|azure|kube|docker)(?:\/|\\\\)/i' => $d('Credential Directory Access', ['query', 'path']),
        '/\b(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)\b/i' => $d('SSH Private Key Access', ['query', 'path']),
        // /m so the `^` anchor also fires at the start of a query value, which is
        // a separate line in the newline-joined surface (not just string start).
        '/\.(?:htpasswd|htaccess)\b|(?:^|[\/?&=])web\.config\b/im' => $d('Server Config Access', ['query', 'path']),
        '/\b(?:wp-config|configuration|settings|local|database)\.(?:php|ya?ml|ini)\b/i' => $e('App Config File Access', ['query', 'path']),
        '/\b(?:composer|package|yarn)\.(?:json|lock)\b/i' => $w('Dependency Manifest Access', ['query', 'path']),
        '/\.(?:bak|old|orig|save|swp|swo|sql|tar|gz|tgz|zip|rar|7z|dump)(?:$|[?&])/im' => $w('Backup / Archive File Probe', ['query', 'path']),
        '/(?:\.bash_history|\.zsh_history|\.DS_Store)\b/i' => $w('Sensitive Artefact Probe', ['query', 'path']),
        '/\bphpinfo\s*\(|\/phpinfo\b/i' => $e('PHPInfo Probe', ['query', 'path', 'body']),

        // ---------------------------------------------------------------
        // Admin / infrastructure endpoint probing
        // ---------------------------------------------------------------
        '/\/(?:phpmyadmin|pma|adminer|dbadmin|mysqladmin)\b/i' => $w('Database Admin Probe', ['query', 'path']),
        '/\/(?:wp-admin|wp-login\.php|xmlrpc\.php)\b/i' => $w('WordPress Endpoint Probe', ['query', 'path']),
        '/\/wp-json\/wp\/v2\/users|[?&]author=\d+/i' => $n('WordPress User Enumeration', ['query', 'path']),
        '/\/actuator(?:\/(?:env|heapdump|health|beans|mappings|threaddump))?\b/i' => $w('Spring Actuator Probe', ['query', 'path']),
        '/\/server-status\b|\/server-info\b/i' => $w('Apache Status Probe', ['query', 'path']),
        '/\/(?:internal|legacy|console|debug-bar)\b/i' => $w('Restricted Path Probe', ['query', 'path']),

        // ---------------------------------------------------------------
        // Framework / CVE exploitation attempts
        // ---------------------------------------------------------------
        '/(?m:^\/_ignition\/execute-solution\/?$)/i' => $d('Laravel Ignition RCE (CVE-2021-3129)', ['path']),
        '/\/_ignition\/execute-solution\b/i' => $c('Laravel Ignition RCE (CVE-2021-3129)', ['query', 'path', 'body']),
        '/eval-stdin\.php\b/i' => $c('PHPUnit RCE (CVE-2017-9841)', ['query', 'path']),
        '/class\.(?:module\.)?classLoader/i' => $c('Spring4Shell (class.classLoader)', ['query', 'body']),
        // Drupalgeddon2 (CVE-2018-7600): render-array keys smuggled into input.
        '/#(?:pre_render|post_render|lazy_builder|access_callback)\b/i' => $c('Drupalgeddon Render Injection', ['query', 'body']),
        '/%\{[^}]{0,200}\}|@java\.lang\.(?:Runtime|ProcessBuilder)@|\(#[a-z_]+=/i' => $c('OGNL / Struts Injection', ['query', 'body']),
        '/<!--\s*#\s*(?:exec|include|echo|config|fsize|flastmod)\b/i' => $c('Server-Side Include Injection', ['query', 'body']),
        '/(?:__proto__|constructor\s*[\[.]\s*prototype|prototype\s*\[\s*["\']__proto__)/i' => $e('Prototype Pollution', ['query', 'body']),

        // ---------------------------------------------------------------
        // Insecure deserialization
        // ---------------------------------------------------------------
        '/(?:^|[^A-Za-z0-9+\/])rO0AB[A-Za-z0-9+\/]{8,}/' => $c('Java Deserialization Payload', ['query', 'body', 'cookie', 'headers']),
        // Raw/hex form of the same Java serialization stream magic (0xACED0005).
        '/(?:^|[^0-9a-f])aced0005[0-9a-f]{8,}/i' => $c('Java Deserialization Payload (hex)', ['query', 'body', 'cookie', 'headers']),
        '/AAEAAAD\/\/\/\//' => $c('.NET Deserialization Payload', ['query', 'body', 'cookie']),

        // ---------------------------------------------------------------
        // Server-side template injection (payload-shaped, low false positive)
        // ---------------------------------------------------------------
        // Inner spans are bounded ({0,300}) — an unbounded [^}]* turns
        // quadratic on a long run of braces and stalls the whole inspection.
        // The lookbehind starts a match only at the first `{{` of a brace run
        // (inner positions are covered by the span), keeping a brace flood
        // linear without losing any probe the bounded span would catch.
        '/\{\{\s*\d+\s*[\*\/\+\-]\s*\d+\s*\}\}/' => $c('SSTI Arithmetic Probe', ['query', 'body']),
        '/(?<!\{)\{\{[^}]{0,300}(?:config|self|request|session|settings|__class__|__globals__|__subclasses__|__mro__|cycler|joiner|lipsum|_self)[^}]{0,300}\}\}/is' => $c('SSTI Object Access', ['query', 'body']),
        '/\{%[-\s]*(?:if|for|set|include|import|with|debug|autoescape)\b[^%]{0,300}%\}/is' => $e('SSTI Template Tag', ['query', 'body']),
        '/<%[=@!]?[^%]{1,500}%>/s' => $e('Template Injection (JSP/ASP/ERB)', ['query', 'body']),
        '/(?<!\{)#\{[^}]{0,300}(?:`|system|exec|open|read|eval|IO\.|File\.)[^}]{0,300}\}/i' => $c('Ruby Interpolation Injection', ['query', 'body']),

        // ---------------------------------------------------------------
        // XSS / client-side variants (beyond the core rules)
        // ---------------------------------------------------------------
        '/%3c(?:script|img|svg|iframe|body|details|math|object|embed)/i' => $e('URL-encoded HTML Injection', ['query', 'body', 'path']),
        '/(?:document|window|top|self|this)\s*\.\s*location\s*(?:\.\s*(?:href|assign|replace))?\s*=/i' => $w('JS Location Redirect', ['query', 'body']),
        '/(?:String\.fromCharCode|fromCharCode|decodeURIComponent|unescape|atob)\s*\(/i' => $e('Obfuscated JS', ['query', 'body']),
        '/data:text\/html[;,]/i' => $e('data: URI HTML Payload', ['query', 'body']),
        '/\bon(?:focus|toggle|pointerover|pointerenter|animationstart|animationend|beforescriptexecute|wheel)\s*=/i' => $e('Obscure Event Handler', ['query', 'body']),

        // ---------------------------------------------------------------
        // HTTP response splitting / open redirect
        // ---------------------------------------------------------------
        // Only spaces/tabs between the line break and the header name — `\s`
        // would also swallow further CRLFs and go quadratic on a newline flood.
        '/(?:%0d%0a|%0a|%0d|\r\n|\r|\n)[ \t]*(?:set-cookie|location|content-type|content-length|refresh)\s*:/i' => $e('CRLF / Header Injection', ['query', 'path']),
        '/[?&](?:redirect(?:_uri|_url)?|url|next|return(?:url|_url)?|goto|dest(?:ination)?|continue|forward|out|to|image_url)=(?:%2f%2f|\/\/|%5c%5c|\\\\|%09|javascript(?:%3a|:))/i' => $w('Open Redirect', ['query']),

        // ---------------------------------------------------------------
        // SQL injection variants (beyond the core rules)
        // ---------------------------------------------------------------
        '/\bwaitfor\s+delay\b/i' => $e('SQL Time-based Blind (WAITFOR)', ['query', 'body', 'path']),
        '/\b(?:benchmark|pg_sleep|dbms_pipe\.receive_message)\s*\(/i' => $e('SQL Time-based Blind', ['query', 'body', 'path']),
        '/\b(?:group_concat|concat_ws)\s*\(/i' => $e('SQL String Concatenation', ['query', 'body']),
        '/\b(?:extractvalue|updatexml)\s*\(/i' => $e('SQL Error-based (XML)', ['query', 'body']),
        '/\bhaving\b\s+\d+\s*=\s*\d+|\bprocedure\s+analyse\s*\(/i' => $e('SQL Enumeration Probe', ['query', 'body']),

        // ---------------------------------------------------------------
        // Web shells, reverse shells & crypto miners
        // ---------------------------------------------------------------
        '/\b(?:c99|r57|b374k|wso|c100|weevely|filesman|indoxploit|alfa(?:team)?shell)\b/i' => $c('Web Shell Signature', ['query', 'body', 'path']),
        '/eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|hex2bin)\s*\(/i' => $c('Encoded Eval Execution', ['query', 'body']),
        '/(?:ba)?sh\s+-i\b|\/dev\/tcp\/|\bnc\s+-[a-z]*e\b|mkfifo\b[^|]*\|/i' => $c('Reverse Shell', ['query', 'body']),
        '/(?:python[0-9.]*|perl|ruby)\s+-[a-z]+\s+["\'][^"\']*(?:socket|Socket)/i' => $c('Scripted Reverse Shell', ['query', 'body']),
        '/\b(?:coinhive|cryptonight|xmrig|minexmr|nicehash|supportxmr)\b/i' => $e('Crypto Miner', ['query', 'body']),

        // ---------------------------------------------------------------
        // API abuse / enumeration
        // ---------------------------------------------------------------
        '/\/(?:v[0-9]+\/)?users?\/\d+\/(?:delete|remove|disable|ban)\b/i' => $w('Destructive User Operation', ['query', 'path']),
        '/[?&]limit=\d{4,}/i' => $n('Excessive Result Limit', ['query']),
        '/\b(?:IntrospectionQuery|__schema\s*\{|__type\s*\()/i' => $n('GraphQL Introspection', ['query', 'body']),

        // ---------------------------------------------------------------
        // Debug / dev tooling exposure
        // ---------------------------------------------------------------
        '/XDEBUG_SESSION(?:_START)?\b/i' => $n('XDebug Session', ['query', 'path', 'cookie']),
        '/[?&]--inspect\b|\bnode\s+--inspect/i' => $n('Node Debug Mode', ['query']),
    ],

];
