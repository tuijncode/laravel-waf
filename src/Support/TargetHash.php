<?php

namespace Tuijncode\LaravelWaf\Support;

class TargetHash
{
    public static function fromUrl(string $url): ?string
    {
        $key = (string) config('app.key', '');

        return $key === '' ? null : hash_hmac('sha256', explode('?', $url, 2)[0], $key);
    }
}
