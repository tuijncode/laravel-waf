<?php

namespace Tuijncode\LaravelWaf\Support;

class QuietEvent
{
    public static function dispatch(object $event): void
    {
        try {
            event($event);
        } catch (\Throwable $e) {
            QuietLog::write('error', 'laravel-waf: event listener failed', [
                'event' => class_basename($event),
                'error' => $e->getMessage(),
            ]);
        }
    }
}
