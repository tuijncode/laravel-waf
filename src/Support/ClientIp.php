<?php

namespace Tuijncode\LaravelWaf\Support;

use Illuminate\Http\Request;

class ClientIp
{
    public static function from(Request $request): string
    {
        try {
            $ip = (string) $request->ip();
        } catch (\Throwable) {
            $ip = '';
        }

        // Conflicting forwarded headers can make ip() throw or return 0.0.0.0.
        return $ip === '' || $ip === '0.0.0.0'
            ? (string) $request->server->get('REMOTE_ADDR', '')
            : $ip;
    }
}
