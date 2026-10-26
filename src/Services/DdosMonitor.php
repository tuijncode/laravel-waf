<?php

namespace Tuijncode\LaravelWaf\Services;

use Illuminate\Support\Facades\RateLimiter;
use Tuijncode\LaravelWaf\Support\CacheFailure;

/**
 * Volumetric abuse detector.
 *
 * Leans on the framework's own rate limiter to count hits per client inside a
 * decaying window, keeping this class free of any store-specific bookkeeping.
 * Counting (`hit`) and checking (`tripped`) are separate operations, so a
 * read-only inspection never inflates the counter.
 */
class DdosMonitor
{
    protected int $ceiling;

    protected int $windowSeconds;

    public function __construct(?int $ceiling = null, ?int $windowSeconds = null)
    {
        $this->ceiling = $ceiling ?? (int) config('waf.ddos.threshold', 300);
        $this->windowSeconds = $windowSeconds ?? (int) config('waf.ddos.window', 60);
    }

    /**
     * Count the current request against the client's budget.
     */
    public function hit(string $client): void
    {
        try {
            RateLimiter::hit($this->bucket($client), $this->windowSeconds);
        } catch (\Throwable $e) {
            CacheFailure::report($e);
        }
    }

    /**
     * Whether the client has gone over budget. Read-only: does not count a hit.
     */
    public function tripped(string $client): bool
    {
        try {
            return RateLimiter::attempts($this->bucket($client)) > $this->ceiling;
        } catch (\Throwable $e) {
            CacheFailure::report($e);

            return false;
        }
    }

    public function ceiling(): int
    {
        return $this->ceiling;
    }

    public function windowSeconds(): int
    {
        return $this->windowSeconds;
    }

    private function bucket(string $client): string
    {
        return 'laravel-waf|flood|'.sha1($client);
    }
}
