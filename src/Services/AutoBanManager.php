<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\RateLimiter;
use Tuijncode\LaravelWaf\Events\IpBanned;
use Tuijncode\LaravelWaf\Support\CacheFailure;
use Tuijncode\LaravelWaf\Support\QuietEvent;

/**
 * Temporary, cache-based IP bans (blocking mode only).
 *
 * A client that keeps getting blocked is eventually cut off up front: after
 * `max_blocks` blocks inside a rolling `window`, the IP is banned for
 * `duration` seconds and every further request is refused before the full
 * inspection pipeline runs — an attacker no longer costs a regex sweep per
 * request. Bans live in the cache, so they expire on their own and never
 * require storage of their own.
 */
class AutoBanManager
{
    public function enabled(): bool
    {
        return (bool) config('waf.auto_ban.enabled', false);
    }

    public function banned(string $ip): bool
    {
        if (! $this->enabled()) {
            return false;
        }

        try {
            return Cache::has($this->key($ip));
        } catch (\Throwable $e) {
            CacheFailure::report($e);

            return false;
        }
    }

    /**
     * Register a block against the client and ban it once the strike count
     * inside the rolling window reaches the configured maximum. Dispatches
     * IpBanned when the ban is first applied.
     */
    public function strike(string $ip): void
    {
        if (! $this->enabled()) {
            return;
        }

        try {
            $strikes = RateLimiter::hit(
                'laravel-waf|strikes|'.sha1($ip),
                (int) config('waf.auto_ban.window', 300),
            );

            if ($strikes < (int) config('waf.auto_ban.max_blocks', 5)) {
                return;
            }

            // Only the worker that creates the ban announces it.
            if (Cache::add($this->key($ip), true, $this->duration())) {
                QuietEvent::dispatch(new IpBanned($ip, $this->duration()));
            }
        } catch (\Throwable $e) {
            CacheFailure::report($e);
        }
    }

    /**
     * Lift a standing ban (and reset its strike count). Returns true when a ban
     * was actually cleared.
     */
    public function lift(string $ip): bool
    {
        RateLimiter::clear('laravel-waf|strikes|'.sha1($ip));

        if (! Cache::has($this->key($ip))) {
            return false;
        }

        Cache::forget($this->key($ip));

        return true;
    }

    public function duration(): int
    {
        return (int) config('waf.auto_ban.duration', 3600);
    }

    private function key(string $ip): string
    {
        return 'laravel-waf|ban|'.sha1($ip);
    }
}
