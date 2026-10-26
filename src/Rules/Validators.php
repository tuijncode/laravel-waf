<?php

namespace Tuijncode\LaravelWaf\Rules;

/**
 * Named post-match validators.
 *
 * A regex alone can't express every constraint — a 16-digit run is not a card
 * number unless it also passes a Luhn check. A signature can name one of these
 * validators; a regex hit only counts as a match when the validator agrees.
 *
 * Validators are referenced by name (a plain string), never a closure, so a
 * pattern pack stays compatible with `config:cache`.
 */
class Validators
{
    /**
     * Whether the captured value clears the named validator. An unknown name
     * never suppresses a hit (fail open on a typo, which config validation
     * flags separately).
     */
    public static function passes(string $name, string $value): bool
    {
        return match ($name) {
            'luhn' => self::luhn($value),
            default => true,
        };
    }

    public static function known(string $name): bool
    {
        return in_array($name, ['luhn'], true);
    }

    /**
     * The Luhn checksum used by every major card scheme, so random 16-digit
     * values (order ids, tracking numbers) are not mistaken for a PAN.
     */
    private static function luhn(string $value): bool
    {
        if (strlen($value) < 12) {
            return false;
        }

        $digits = (string) preg_replace('/\D/', '', $value);

        if (strlen($digits) < 12) {
            return false;
        }

        $sum = 0;
        $double = false;

        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $n = (int) $digits[$i];

            if ($double && ($n *= 2) > 9) {
                $n -= 9;
            }

            $sum += $n;
            $double = ! $double;
        }

        return $sum % 10 === 0;
    }
}
