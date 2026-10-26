<?php

use Tuijncode\LaravelWaf\Support\UserIdColumnType;

it('accepts string columns wide enough for user IDs', function (string $type, bool $accepted) {
    expect(UserIdColumnType::acceptsStrings($type))->toBe($accepted);
})->with([
    ['varchar(8)', false],
    ['character varying(36)', false],
    ['varchar(191)', true],
    ['character varying(255)', true],
    ['nvarchar(200)', false],
    ['nvarchar(381)', false],
    ['nvarchar(382)', true],
    ['nvarchar(max)', true],
    ['varchar', true], // SQLite uses an unbounded VARCHAR affinity.
    ['text', true],
    ['bigint', false],
    ['char(191)', false],
]);
