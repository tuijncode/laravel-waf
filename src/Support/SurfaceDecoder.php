<?php

namespace Tuijncode\LaravelWaf\Support;

/** Decode the same evasions for inspection and secret redaction. */
class SurfaceDecoder
{
    /** @return array<int, string> */
    public static function variants(string $raw, int $passes = 3): array
    {
        $variants = [$raw];
        $current = $raw;
        $transforms = [
            static fn (string $value): string => rawurldecode(rawurldecode($value)),
            static fn (string $value): string => html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            self::decodeIisUnicode(...),
            self::decodeBackslashEscapes(...),
            static fn (string $value): string => str_replace("\0", '', $value),
            self::stripSqlComments(...),
        ];

        for ($pass = 0; $pass < $passes; $pass++) {
            $before = $current;

            foreach ($transforms as $transform) {
                $decoded = $transform($current);
                if ($decoded !== $current) {
                    $variants[] = $current = $decoded;
                }
            }

            if ($current === $before) {
                break;
            }
        }

        return array_values(array_unique($variants));
    }

    private static function stripSqlComments(string $value): string
    {
        if (! str_contains($value, '/*') && ! str_contains($value, '--') && ! str_contains($value, '#')) {
            return $value;
        }

        if (str_contains($value, '*/')) {
            $value = (string) preg_replace('#/\*!(?:\d{5})?(.{0,2000}?)\*/#s', ' $1 ', $value);
            $value = (string) preg_replace('#/\*.{0,2000}?\*/#s', ' ', $value);
        }

        return (string) preg_replace('/(?:--\s|\#)[^\n]*/', ' ', $value);
    }

    private static function decodeIisUnicode(string $value): string
    {
        if (stripos($value, '%u') === false) {
            return $value;
        }

        return (string) preg_replace_callback(
            '/%u([0-9a-fA-F]{4})/',
            static fn (array $m): string => (string) mb_convert_encoding(
                pack('n', (int) hexdec($m[1])), 'UTF-8', 'UTF-16BE'
            ),
            $value,
        );
    }

    private static function decodeBackslashEscapes(string $value): string
    {
        if (! str_contains($value, '\\')) {
            return $value;
        }

        $value = (string) preg_replace_callback(
            '/\\\\u([0-9a-fA-F]{4})/',
            static fn (array $m): string => (string) mb_convert_encoding(
                pack('n', (int) hexdec($m[1])), 'UTF-8', 'UTF-16BE'
            ),
            $value,
        );

        return (string) preg_replace_callback(
            '/\\\\x([0-9a-fA-F]{2})/',
            static fn (array $m): string => chr((int) hexdec($m[1])),
            $value,
        );
    }
}
