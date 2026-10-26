<?php

namespace Tuijncode\LaravelWaf\Support;

use Tuijncode\LaravelWaf\Rules\CoreRuleSet;
use Tuijncode\LaravelWaf\Rules\Signature;
use Tuijncode\LaravelWaf\Rules\Validators;

/**
 * Sanity-checks the published configuration so a typo in `.env` (e.g.
 * WAF_MODE=blockign or WAF_PARANOIA=9) surfaces as a clear warning instead of
 * silently changing how the firewall behaves.
 */
class ConfigValidator
{
    private const SEVERITIES = ['critical', 'error', 'warning', 'notice'];

    private const SURFACES = ['query', 'body', 'path', 'headers', 'cookie'];

    /**
     * Return a list of human-readable problems, or an empty array if the
     * configuration is sound.
     *
     * @return array<int, string>
     */
    public function validate(): array
    {
        $problems = [];

        $this->oneOf($problems, 'waf.mode', ['detection', 'blocking']);
        $this->oneOf($problems, 'waf.on_error', ['open', 'closed']);
        $this->oneOf($problems, 'waf.custom_pattern_severity', self::SEVERITIES);

        $this->intRange($problems, 'waf.paranoia_level', 1, 4);
        $this->intRange($problems, 'waf.custom_pattern_paranoia', 1, 4);
        $this->intRange($problems, 'waf.min_confidence', 0, 100);
        $this->intRange($problems, 'waf.block_confidence', 0, 100);
        $this->intRange($problems, 'waf.block_response.status', 100, 599);
        $this->intRange($problems, 'waf.dedup_minutes', 0, 1440);

        $this->positiveInt($problems, 'waf.ddos.threshold');
        $this->positiveInt($problems, 'waf.ddos.window');

        $this->positiveInt($problems, 'waf.auto_ban.max_blocks');
        $this->positiveInt($problems, 'waf.auto_ban.window');
        $this->positiveInt($problems, 'waf.auto_ban.duration');
        $this->positiveInt($problems, 'waf.retention.days');
        $this->positiveInt($problems, 'waf.attempts.retention_days');
        foreach (['window_minutes', 'max_per_ip'] as $key) {
            if (config("waf.attempts.{$key}") !== null) {
                $this->positiveInt($problems, "waf.attempts.{$key}");
            }
        }
        if (config('waf.attempts.max_correlation_rows') !== null) {
            $this->intRange($problems, 'waf.attempts.max_correlation_rows', 1, 100000);
        }

        $this->environments($problems);
        $this->pathLists($problems);
        $this->knownCategories($problems);
        $this->customPatterns($problems);
        $this->safeFields($problems);

        if (config('waf.redact.enabled', true) && (string) config('app.key', '') === '') {
            $problems[] = 'APP_KEY is required for keyed hashes of redacted WAF targets.';
        }

        return $problems;
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function safeFields(array &$problems): void
    {
        $safe = config('waf.safe_fields', []);

        if (! is_array($safe)) {
            $problems[] = 'waf.safe_fields must be an array of field names, got '.$this->show($safe).'.';

            return;
        }

        foreach ($safe as $field) {
            if (! is_string($field)) {
                $problems[] = 'waf.safe_fields entries must be strings, got '.$this->show($field).'.';
            }
        }
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function environments(array &$problems): void
    {
        $environments = config('waf.enabled_environments');

        if ($environments !== null && ! is_array($environments)) {
            $problems[] = 'waf.enabled_environments must be null or an array of environment names, got '
                .$this->show($environments).'.';
        } elseif (is_array($environments) && array_filter($environments, 'is_string') !== $environments) {
            $problems[] = 'waf.enabled_environments entries must be environment names.';
        }
    }

    /** @param array<int, string> $problems */
    private function pathLists(array &$problems): void
    {
        foreach (['only_paths', 'skip_paths'] as $name) {
            $paths = config("waf.{$name}");
            if (! is_array($paths) || array_filter($paths, 'is_string') !== $paths) {
                $problems[] = "waf.{$name} must be an array of path patterns.";
            }
        }
    }

    /**
     * Check the operator's own signatures (and the published pattern pack): the
     * regex must compile, and any explicit severity or target must be known —
     * a typo in `targets` would otherwise make the pattern silently dead.
     *
     * @param  array<int, string>  $problems
     */
    private function customPatterns(array &$problems): void
    {
        $pack = config('waf.pattern_pack', true) ? (array) config('waf-patterns.custom', []) : [];
        $definitions = array_merge($pack, (array) config('waf.custom_patterns', []));

        foreach ($definitions as $regex => $definition) {
            $regex = (string) $regex;

            if (@preg_match($regex, '') === false) {
                $problems[] = "custom pattern '{$regex}' is not a valid regular expression.";
            }

            if (! is_array($definition)) {
                continue;
            }

            if (isset($definition['label']) && ! is_string($definition['label'])) {
                $problems[] = "custom pattern '{$regex}' label must be a string.";
            }

            $severity = $definition['severity'] ?? null;
            if ($severity !== null && ! in_array($severity, self::SEVERITIES, true)) {
                $problems[] = "custom pattern '{$regex}' has unknown severity ".$this->show($severity)
                    .' (allowed: '.implode(', ', self::SEVERITIES).').';
            }

            if (isset($definition['targets']) && (! is_array($definition['targets']) || $definition['targets'] === [])) {
                $problems[] = "custom pattern '{$regex}' targets must be a non-empty array.";
            } else {
                foreach ($definition['targets'] ?? [] as $target) {
                    if (! in_array($target, self::SURFACES, true)) {
                        $problems[] = "custom pattern '{$regex}' targets unknown surface ".$this->show($target)
                            .' (known: '.implode(', ', self::SURFACES).').';
                    }
                }
            }

            $validator = $definition['validator'] ?? null;
            if ($validator !== null && (! is_string($validator) || ! Validators::known($validator))) {
                $problems[] = "custom pattern '{$regex}' names unknown validator ".$this->show($validator).'.';
            }
            if (isset($definition['paranoia'])) {
                $paranoia = filter_var($definition['paranoia'], FILTER_VALIDATE_INT);
                if ($paranoia === false || $paranoia < 1 || $paranoia > 4) {
                    $problems[] = "custom pattern '{$regex}' paranoia must be an integer between 1 and 4.";
                }
            }
        }
    }

    /**
     * @param  array<int, string>  $problems
     * @param  array<int, string>  $allowed
     */
    private function oneOf(array &$problems, string $key, array $allowed): void
    {
        $value = config($key);

        if (! in_array($value, $allowed, true)) {
            $problems[] = "{$key} must be one of [".implode(', ', $allowed).'], got '.$this->show($value).'.';
        }
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function intRange(array &$problems, string $key, int $min, int $max): void
    {
        $int = filter_var(config($key), FILTER_VALIDATE_INT);

        if ($int === false || $int < $min || $int > $max) {
            $problems[] = "{$key} must be an integer between {$min} and {$max}, got ".$this->show(config($key)).'.';
        }
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function positiveInt(array &$problems, string $key): void
    {
        $int = filter_var(config($key), FILTER_VALIDATE_INT);

        if ($int === false || $int < 1) {
            $problems[] = "{$key} must be a positive integer, got ".$this->show(config($key)).'.';
        }
    }

    /**
     * @param  array<int, string>  $problems
     */
    private function knownCategories(array &$problems): void
    {
        $known = $this->categories();

        foreach ((array) config('waf.disabled_categories', []) as $category) {
            if (! in_array($category, $known, true)) {
                $problems[] = "waf.disabled_categories contains unknown category '{$category}' (known: ".implode(', ', $known).').';
            }
        }
    }

    /**
     * @return array<int, string>
     */
    private function categories(): array
    {
        $core = array_map(fn (Signature $s): string => $s->category, CoreRuleSet::rules());

        return array_values(array_unique(array_merge($core, ['custom', 'scanner', 'bot', 'ddos', 'ai_probe', 'probe', 'llm_injection'])));
    }

    private function show(mixed $value): string
    {
        return is_scalar($value) ? var_export($value, true) : gettype($value);
    }
}
