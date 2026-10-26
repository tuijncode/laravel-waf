<?php

namespace Tuijncode\LaravelWaf\Support;

class UserIdColumnType
{
    public static function acceptsStrings(string $type): bool
    {
        $type = strtolower($type);
        if (str_contains($type, 'text')) {
            return true;
        }

        if (! str_contains($type, 'varchar') && ! str_contains($type, 'varying')) {
            return false;
        }

        // SQL Server reports nvarchar length in bytes (two per character).
        $minimum = str_starts_with($type, 'nvarchar') ? 382 : 191;

        return ! preg_match('/\((\d+)\)/', $type, $length) || (int) $length[1] >= $minimum;
    }
}
