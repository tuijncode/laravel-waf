<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

it('widens an existing rule list without losing stored findings', function () {
    Schema::table('waf_logs', function (Blueprint $table) {
        $table->string('rule_ids')->nullable()->change();
    });
    DB::table('waf_logs')->insert([
        'ip_address' => '203.0.113.1', 'url' => '/', 'type' => 'test',
        'category' => 'custom', 'rule_ids' => 'CUSTOM-1',
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $migration = require __DIR__.'/../../database/migrations/widen_waf_rule_ids_table.php.stub';
    $migration->up();
    $migration->up();

    $long = implode(',', array_map(fn (int $n): string => 'CUSTOM-'.$n, range(1, 40)));
    DB::table('waf_logs')->update(['rule_ids' => $long]);

    expect(Schema::getColumnType('waf_logs', 'rule_ids'))->toBe('text')
        ->and(DB::table('waf_logs')->value('rule_ids'))->toBe($long);
});
