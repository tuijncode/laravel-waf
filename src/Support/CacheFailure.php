<?php

namespace Tuijncode\LaravelWaf\Support;

class CacheFailure
{
    private static bool $reported = false;

    public static function report(\Throwable $error): void
    {
        if (self::$reported) {
            return;
        }

        self::$reported = true;
        QuietLog::write('warning', 'laravel-waf: cache unavailable; continuing without cache-backed signals', [
            'error' => $error->getMessage(),
        ]);
    }
}
