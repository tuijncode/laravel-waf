<?php

namespace Tuijncode\LaravelWaf\Support;

use Illuminate\Support\Facades\Log;

class QuietLog
{
    /** @param array<string, mixed> $context */
    public static function write(string $level, string $message, array $context = []): void
    {
        try {
            match ($level) {
                'error' => Log::error($message, $context),
                default => Log::warning($message, $context),
            };
        } catch (\Throwable) {
            // Diagnostics must not interrupt inspection or a completed write.
        }
    }
}
