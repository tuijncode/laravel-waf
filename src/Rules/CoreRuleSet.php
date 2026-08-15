<?php

namespace Tuijncode\LaravelWaf\Rules;

/**
 * OWASP Core Rule Set (CRS) inspired signature collection.
 *
 * Each rule mirrors the structure of a real CRS rule: a stable rule id, the
 * CRS rule category (paranoia group), a human readable message, a severity
 * (which drives the anomaly score) and the request parts the rule targets.
 *
 * Severity to anomaly score mapping (as used by CRS):
 *   critical => 5, error => 4, warning => 3, notice => 2
 */
class CoreRuleSet
{
    public const SEVERITY_SCORES = [
        'critical' => 5,
        'error' => 4,
        'warning' => 3,
        'notice' => 2,
    ];

    /**
     * Rules that trade a little precision for breadth. They only run at
     * paranoia level 2 and above; at level 1 only the highest-confidence
     * signatures fire, which keeps false positives to a minimum.
     */
    public const BROAD_RULE_IDS = [
        '942110', // SELECT ... FROM
        '942120', // boolean tautology
        '942170', // SQL comment sequence
        '941120', // inline event handler
        '941130', // dangerous HTML tag
        '941140', // DOM sink
        '941150', // JS execution primitive
        '930100', // ../ traversal
        '931100', // RFI parameter
        '932100', // command chaining
        '932120', // unix binary
        '934110', // loopback SSRF
        '934120', // private-network SSRF
        '943100', // LDAP injection (parenthesis/filter syntax — FP-prone)
        '943110', // XPath injection (axis/function syntax — FP-prone)
    ];

    /**
     * The paranoia level at which a rule id begins to fire (1 = always on).
     */
    public static function paranoiaFor(string $id): int
    {
        return in_array($id, self::BROAD_RULE_IDS, true) ? 2 : 1;
    }

    /** @var array<int, Signature>|null */
    private static ?array $rules = null;

    /**
     * The full signature list as typed value objects, built once per process.
     *
     * @return array<int, Signature>
     */
    public static function rules(): array
    {
        return self::$rules ??= array_map(
            fn (array $r): Signature => new Signature(
                id: $r['id'],
                category: $r['category'],
                name: $r['name'],
                description: $r['description'],
                severity: $r['severity'],
                targets: $r['targets'],
                regex: $r['regex'],
                paranoia: self::paranoiaFor($r['id']),
            ),
            self::definitions(),
        );
    }

    /**
     * The raw rule definitions.
     *
     * @return array<int, array{id:string, category:string, name:string, description:string, severity:string, targets:array<int,string>, regex:string}>
     */
    private static function definitions(): array
    {
        return array_merge(
            self::protocolEnforcement(),
            self::sqlInjection(),
            self::crossSiteScripting(),
            self::localFileInclusion(),
            self::remoteFileInclusion(),
            self::remoteCommandExecution(),
            self::phpInjection(),
            self::serverSideRequestForgery(),
            self::xmlExternalEntity(),
            self::javaAndLog4Shell(),
            self::noSqlInjection(),
            self::ldapInjection(),
            self::xpathInjection(),
        );
    }

    /** REQUEST-920: Protocol Enforcement. */
    protected static function protocolEnforcement(): array
    {
        return [
            [
                'id' => '920270',
                'category' => 'protocol',
                'name' => 'Protocol Violation',
                'description' => 'Protocol Attack: null byte (%00) in request data',
                'severity' => 'critical',
                // The body is deliberately not targeted: raw binary bodies
                // (protobuf, msgpack, file streams) legitimately contain NULs.
                // Nothing legitimate carries one in the query, path, headers or
                // cookies — there it only serves to truncate a string in C-based
                // layers (e.g. `file=passwd%00.jpg` defeating an extension check).
                // The normaliser keeps the pre-decoded variant of each surface,
                // so both the encoded `%00` and a decoded NUL are visible here.
                'targets' => ['query', 'path', 'headers', 'cookie'],
                'regex' => '/%00|\x00/',
            ],
        ];
    }

    /** REQUEST-942: SQL Injection Attacks. */
    protected static function sqlInjection(): array
    {
        return [
            [
                'id' => '942100',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: UNION SELECT detected',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path', 'headers', 'cookie'],
                'regex' => '/\bunion\b\s+(all\s+)?\bselect\b/i',
            ],
            [
                'id' => '942110',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: SELECT ... FROM detected',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/\bselect\b[\s\S]{1,200}?\bfrom\b/i',
            ],
            [
                'id' => '942120',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: SQL boolean-based tautology (e.g. OR 1=1)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path', 'headers', 'cookie'],
                'regex' => '/\b(or|and)\b\s+["\']?\d+["\']?\s*(=|<>|!=|<|>)\s*["\']?\d+/i',
            ],
            [
                'id' => '942130',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: common DDL/DML keyword (drop/insert/update/delete)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/\b(drop|alter|truncate|insert\s+into|delete\s+from|update)\b\s+[\w`\'"]+/i',
            ],
            [
                'id' => '942140',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: database metadata / schema probing',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/\b(information_schema|pg_catalog|sysobjects|mysql\.user|sqlite_master)\b/i',
            ],
            [
                'id' => '942150',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: time-based blind (sleep/benchmark/waitfor)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers', 'cookie'],
                'regex' => '/\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b/i',
            ],
            [
                'id' => '942160',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: file read/write primitives (load_file/into outfile)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/\b(load_file\s*\(|into\s+(out|dump)file)\b/i',
            ],
            [
                'id' => '942170',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: SQL comment sequence used for evasion',
                'severity' => 'error',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/(--\s|#\s|\/\*!?)|;\s*(--|#)/',
            ],
            [
                'id' => '942180',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: CHAR()/CHR() character-code encoding used to build a string',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                // Four or more comma-separated codes: that is the encoding-bypass
                // shape, not the odd legitimate single CHAR(10) newline.
                'regex' => '/\b(?:char|chr)\s*\(\s*\d{1,3}\s*(?:,\s*\d{1,3}\s*){3,}\)/i',
            ],
            [
                'id' => '942190',
                'category' => 'sqli',
                'name' => 'SQL Injection',
                'description' => 'SQL Injection Attack: UNHEX() hex-string decoding',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\bunhex\s*\(/i',
            ],
        ];
    }

    /** REQUEST-941: Cross-Site Scripting (XSS). */
    protected static function crossSiteScripting(): array
    {
        return [
            [
                'id' => '941100',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: <script> tag detected',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path', 'headers'],
                'regex' => '/<script\b[^>]*>|<\/script\s*>/i',
            ],
            [
                'id' => '941110',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: javascript: URI scheme',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/javascript\s*:/i',
            ],
            [
                'id' => '941120',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: inline event handler (onerror/onload/onclick ...)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/\bon(error|load|click|mouseover|focus|submit|toggle|animationstart)\s*=/i',
            ],
            [
                'id' => '941130',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: dangerous HTML tag (iframe/object/embed/svg/img)',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/<(iframe|object|embed|svg|img|body|video|audio|marquee)\b[^>]*/i',
            ],
            [
                'id' => '941140',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: DOM access / JS sink (document.cookie, window.location)',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/document\s*\.\s*(cookie|location|write)|window\s*\.\s*location/i',
            ],
            [
                'id' => '941150',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: JS execution primitive (eval/alert/prompt/String.fromCharCode)',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\b(eval|alert|confirm|prompt|atob|String\.fromCharCode)\s*\(/i',
            ],
            [
                'id' => '941160',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: URL-encoded <script> payload',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/%3c\s*script|&lt;\s*script/i',
            ],
            [
                'id' => '941170',
                'category' => 'xss',
                'name' => 'XSS',
                'description' => 'XSS Attack: CSS expression() in a style context',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                // Bounded span between the style attribute and expression() so a
                // long run of non-'>' characters can't turn the match quadratic.
                'regex' => '/style\s*=[^>]{0,200}?\bexpression\s*\(/i',
            ],
        ];
    }

    /** REQUEST-930: Local File Inclusion / Directory Traversal. */
    protected static function localFileInclusion(): array
    {
        return [
            [
                'id' => '930100',
                'category' => 'lfi',
                'name' => 'Directory Traversal',
                'description' => 'Path Traversal Attack: ../ or ..\\ sequence',
                'severity' => 'error',
                'targets' => ['query', 'body', 'path', 'headers'],
                'regex' => '/(\.\.[\/\\\\])|(%2e%2e[\/\\\\%])|(\.\.%2f)/i',
            ],
            [
                'id' => '930110',
                'category' => 'lfi',
                'name' => 'Directory Traversal',
                'description' => 'Path Traversal Attack: access to a well-known sensitive OS file',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/(\/etc\/(passwd|shadow|hosts))|(\/proc\/self\/(environ|cmdline))|(boot\.ini)|(win\.ini)/i',
            ],
            [
                'id' => '930120',
                'category' => 'lfi',
                'name' => 'Local File Inclusion',
                'description' => 'LFI Attack: PHP stream wrapper (php://, file://, phar://, expect://)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'path'],
                'regex' => '/\b(php|file|phar|expect|zip|glob|data):\/\//i',
            ],
        ];
    }

    /** REQUEST-931: Remote File Inclusion. */
    protected static function remoteFileInclusion(): array
    {
        return [
            [
                'id' => '931100',
                'category' => 'rfi',
                'name' => 'Remote File Inclusion',
                'description' => 'RFI Attack: remote URL passed to an inclusion parameter',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/[?&](file|path|page|include|template|document|folder|root|dir)=\s*(https?|ftp):\/\//i',
            ],
        ];
    }

    /** REQUEST-932: Remote Command Execution. */
    protected static function remoteCommandExecution(): array
    {
        return [
            [
                'id' => '932100',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: shell command chaining / substitution',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                // A separator (; | & newline backtick) immediately followed by a
                // shell command, or a command-substitution construct. Requiring a
                // trailing command avoids matching the many legitimate semicolons
                // that appear in headers, cookies and query strings.
                'regex' => '/(\$\(|`|\|\s*)\s*(cat|ls|id|whoami|nc|netcat|curl|wget|bash|sh|python|perl|ping|uname|chmod|rm|echo|kill|dir|type)\b|[;&|]{1,2}\s*(cat|ls|id|whoami|nc|curl|wget|bash|sh|ping|uname|chmod|rm|echo)\b|\bIFS\b/i',
            ],
            [
                'id' => '932110',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: PHP/system command execution function',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i',
            ],
            [
                'id' => '932120',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: common unix binary invoked as a command',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\b(cat|nc|netcat|ncat|ping|wget|curl|whoami|id|uname|ls|dir|chmod|chown|kill|nslookup|dig)\b\s+[-\/\w]/i',
            ],
            [
                'id' => '932130',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: reverse shell / bind shell primitive',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/(\/bin\/(ba|z|c|k)?sh)|(\/dev\/tcp\/)|(bash\s+-i)/i',
            ],
            [
                'id' => '932140',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: Shellshock function-definition injection (CVE-2014-6271)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers', 'cookie'],
                // The empty function definition followed by a command is the
                // Shellshock signature; it rides in on User-Agent/Referer too.
                'regex' => '/\(\s*\)\s*\{\s*[^}]{0,60}\}\s*;/',
            ],
            [
                'id' => '932150',
                'category' => 'rce',
                'name' => 'RCE',
                'description' => 'RCE Attack: Windows command execution (cmd.exe / PowerShell / wscript / net user)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                // Each alternative requires the executable *plus* an argument or
                // flag, so ordinary prose mentioning "powershell" won't trip it.
                'regex' => '/\bcmd(?:\.exe)?\s*\/[ck]\b|\bpowershell(?:\.exe)?\b[^\n]{0,40}?(?:-e(?:nc|ncodedcommand)?\b|-c(?:ommand)?\b|iex\b|invoke-|downloadstring)|\b[wc]script\.exe\b|\bnet(?:\.exe)?\s+(?:user|localgroup)\b/i',
            ],
        ];
    }

    /** REQUEST-933: PHP Injection. */
    protected static function phpInjection(): array
    {
        return [
            [
                'id' => '933100',
                'category' => 'php',
                'name' => 'PHP Injection',
                'description' => 'PHP Injection Attack: opening PHP tag',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/<\?(php|=)?\s/i',
            ],
            [
                'id' => '933110',
                'category' => 'php',
                'name' => 'PHP Injection',
                'description' => 'PHP Injection Attack: dangerous PHP function (eval/assert/base64_decode/create_function)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/\b(eval|assert|create_function|base64_decode|gzinflate|str_rot13|call_user_func(_array)?)\s*\(/i',
            ],
            [
                'id' => '933120',
                'category' => 'php',
                'name' => 'PHP Injection',
                'description' => 'PHP Injection Attack: PHP superglobal reference',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\$_(GET|POST|REQUEST|SERVER|COOKIE|SESSION|ENV|FILES)\b/i',
            ],
            [
                'id' => '933130',
                'category' => 'php',
                'name' => 'PHP Object Injection',
                'description' => 'PHP Injection Attack: serialized object (insecure deserialization)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'cookie'],
                'regex' => '/\bO:\d+:"[a-z_\x80-\xff][a-z0-9_\x80-\xff]*":\d+:{/i',
            ],
            [
                'id' => '933140',
                'category' => 'php',
                'name' => 'PHP Injection',
                'description' => 'PHP Injection Attack: RCE-prone function / setting (preg_replace /e, allow_url_include, php_uname, get_current_user)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                // preg_replace with the deprecated /e modifier evaluates its
                // replacement as code; allow_url_include enables remote include.
                // The pattern span is bounded so it stays linear.
                'regex' => '/\ballow_url_(?:include|fopen)\b|\b(?:php_uname|get_current_user)\s*\(|\bpreg_replace(?:_callback)?\s*\(\s*(["\'])[^"\']{0,200}\/[a-z]{0,10}e[a-z]{0,10}\1/i',
            ],
        ];
    }

    /** REQUEST-934: Server-Side Request Forgery. */
    protected static function serverSideRequestForgery(): array
    {
        return [
            [
                'id' => '934100',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: cloud metadata endpoint (169.254.169.254 / metadata.google.internal)',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/(169\.254\.169\.254)|(metadata\.google\.internal)|(metadata\.azure\.com)/i',
            ],
            [
                'id' => '934110',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: request pointed at loopback / localhost',
                'severity' => 'error',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/(https?|gopher|dict|ftp):\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)/i',
            ],
            [
                'id' => '934120',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: request pointed at RFC1918 private network',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/(https?|gopher|dict|ftp):\/\/(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}/i',
            ],
            [
                'id' => '934130',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: encoded loopback address (hex/decimal/octal 127.0.0.1)',
                'severity' => 'error',
                'targets' => ['query', 'body', 'headers'],
                // The encoding is the tell: 0x7f000001, 2130706433, 0177.0.0.1
                // and ::ffff:127.* all resolve to loopback and evade rule 934110.
                'regex' => '/(?:https?|gopher|dict|ftp):\/\/(?:0x7f[0-9a-f]{6}\b|2130706433\b|0177\.0\.0\.1\b|\[?::ffff:127\.)/i',
            ],
            [
                'id' => '934140',
                'category' => 'ssrf',
                'name' => 'SSRF',
                'description' => 'SSRF Attack: DNS-rebinding service embedding an IP address (nip.io/sslip.io/xip.io)',
                'severity' => 'error',
                'targets' => ['query', 'body', 'headers'],
                'regex' => '/\b\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3}\.(?:nip|sslip|xip)\.io\b/i',
            ],
        ];
    }

    /** XML External Entity. */
    protected static function xmlExternalEntity(): array
    {
        return [
            [
                'id' => '944100',
                'category' => 'xxe',
                'name' => 'XXE',
                'description' => 'XXE Attack: external entity declaration',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/<!ENTITY\b/i',
            ],
            [
                'id' => '944110',
                'category' => 'xxe',
                'name' => 'XXE',
                'description' => 'XXE Attack: DOCTYPE with entity/SYSTEM declaration',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/<!DOCTYPE[^>]*(ENTITY|SYSTEM)/is',
            ],
        ];
    }

    /** REQUEST-944: Java attacks including Log4Shell. */
    protected static function javaAndLog4Shell(): array
    {
        return [
            [
                'id' => '944150',
                'category' => 'log4shell',
                'name' => 'Log4Shell',
                'description' => 'Log4Shell Attack: JNDI lookup (${jndi:ldap://...})',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers', 'cookie'],
                'regex' => '/\$\{jndi:(ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)s?:/i',
            ],
            [
                'id' => '944160',
                'category' => 'log4shell',
                'name' => 'Log4Shell',
                'description' => 'Log4Shell Attack: obfuscated JNDI lookup expression',
                'severity' => 'critical',
                'targets' => ['query', 'body', 'headers', 'cookie'],
                // Bounded spans: an unbounded [^}]* goes quadratic on brace floods.
                'regex' => '/\$\{[^}]{0,300}(jndi|lower:|upper:|env:|sys:|::-)[^}]{0,300}\}/i',
            ],
        ];
    }

    /** REQUEST-934: NoSQL Injection (Node / Mongo). */
    protected static function noSqlInjection(): array
    {
        return [
            [
                'id' => '934200',
                'category' => 'nosqli',
                'name' => 'NoSQL Injection',
                'description' => 'NoSQL Injection Attack: Mongo operator ($ne/$gt/$where/$regex/$in)',
                'severity' => 'critical',
                'targets' => ['query', 'body'],
                'regex' => '/[\[{"\']?\s*\$(ne|gt|gte|lt|lte|where|regex|in|nin|or|and|not|exists)\s*["\']?\s*[:=]/i',
            ],
        ];
    }

    /**
     * REQUEST-943: LDAP Injection.
     *
     * Broad by nature (parenthesis-and-operator soup also appears in ordinary
     * text), so these run at paranoia level 2 — see BROAD_RULE_IDS.
     */
    protected static function ldapInjection(): array
    {
        return [
            [
                'id' => '943100',
                'category' => 'ldapi',
                'name' => 'LDAP Injection',
                'description' => 'LDAP Injection Attack: filter-syntax manipulation (e.g. )(|( or *)(uid=*)',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\)\s*\(\s*[|&]|\*\s*\)\s*\(|\)\s*\(\s*(?:uid|cn|sn|mail|givenname|objectclass|userpassword)\s*=/i',
            ],
        ];
    }

    /**
     * REQUEST-943: XPath Injection.
     *
     * Also paranoia level 2 — XPath axis/function syntax overlaps with URL
     * paths and ordinary punctuation.
     */
    protected static function xpathInjection(): array
    {
        return [
            [
                'id' => '943110',
                'category' => 'xpathi',
                'name' => 'XPath Injection',
                'description' => 'XPath Injection Attack: axis / node-test / function syntax',
                'severity' => 'error',
                'targets' => ['query', 'body'],
                'regex' => '/\b(?:ancestor|descendant|following|preceding|self)::|\/\/\w+\[|\/text\s*\(\s*\)|\b(?:count|substring|string-length|name)\s*\(\s*\/\//i',
            ],
        ];
    }
}
