<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Support\TargetHash;

it('adds the target hash to an existing log table without dropping data', function () {
    Schema::table('waf_logs', fn ($table) => $table->dropIndex(['target_hash']));
    Schema::table('waf_logs', fn ($table) => $table->dropColumn('target_hash'));
    DB::table('waf_logs')->insert([
        'ip_address' => '192.0.2.1', 'url' => '[REDACTED]',
        'type' => 'test', 'category' => 'test',
    ]);

    $migration = require __DIR__.'/../../database/migrations/add_waf_target_hash_table.php.stub';
    $migration->up();
    $migration->up();

    expect(Schema::hasColumn('waf_logs', 'target_hash'))->toBeTrue()
        ->and(DB::table('waf_logs')->value('url'))->toBe('[REDACTED]');
});

it('repairs existing log-derived exclusions and disables unscopable ones', function () {
    Schema::table('waf_logs', fn ($table) => $table->dropIndex(['target_hash']));
    Schema::table('waf_logs', fn ($table) => $table->dropColumn('target_hash'));

    foreach (['http://localhost/', 'http://localhost/a*b', '[REDACTED]'] as $url) {
        $logId = DB::table('waf_logs')->insertGetId([
            'ip_address' => '192.0.2.1', 'url' => $url,
            'type' => '[942100] SQLi', 'category' => 'sqli',
        ]);
        DB::table('waf_exclusion_rules')->insert([
            'match_label' => '942100',
            'path_glob' => $url === '[REDACTED]' ? '[REDACTED]' : (trim((string) parse_url($url, PHP_URL_PATH), '/') ?: null),
            'source_log_id' => $logId,
            'is_active' => true,
        ]);
    }

    $migration = require __DIR__.'/../../database/migrations/add_waf_target_hash_table.php.stub';
    $migration->up();

    $rules = DB::table('waf_exclusion_rules')->orderBy('id')->get();
    expect($rules[0]->path_glob)->toBe('/')
        ->and($rules[1]->path_glob)->toBe('a\\*b')
        ->and((bool) $rules[2]->is_active)->toBeFalse();

    DB::table('waf_exclusion_rules')->where('id', $rules[2]->id)->update([
        'path_glob' => 'sha256:'.str_repeat('a', 64), 'is_active' => true,
    ]);
    $migration->up();
    expect((bool) DB::table('waf_exclusion_rules')->where('id', $rules[2]->id)->value('is_active'))->toBeTrue();
});

it('deactivates ambiguous orphaned exclusions after the target hash upgrade has already run', function () {
    foreach ([null, '', '[REDACTED]', 'search', 'a*b', 'a?b', 'a[b]', 'a\\b'] as $path) {
        DB::table('waf_exclusion_rules')->insert([
            'match_label' => '942100',
            'path_glob' => $path,
            'source_log_id' => null,
            'is_active' => true,
        ]);
    }

    $migration = require __DIR__.'/../../database/migrations/deactivate_orphaned_waf_exclusions_table.php.stub';
    $migration->up();
    $globsMigration = require __DIR__.'/../../database/migrations/deactivate_orphaned_waf_globs_table.php.stub';
    $globsMigration->up();

    $rules = DB::table('waf_exclusion_rules')->orderBy('id')->get();
    expect((bool) $rules[0]->is_active)->toBeFalse()
        ->and((bool) $rules[1]->is_active)->toBeFalse()
        ->and((bool) $rules[2]->is_active)->toBeFalse()
        ->and((bool) $rules[3]->is_active)->toBeTrue()
        ->and((bool) $rules[4]->is_active)->toBeFalse()
        ->and((bool) $rules[5]->is_active)->toBeFalse()
        ->and((bool) $rules[6]->is_active)->toBeFalse()
        ->and((bool) $rules[7]->is_active)->toBeFalse();
});

it('backfills visible targets without guessing the target of legacy redacted findings', function () {
    foreach (['http://localhost/login?user=one', 'http://localhost/login?user=two', '[REDACTED]'] as $url) {
        DB::table('waf_logs')->insert([
            'ip_address' => '192.0.2.1', 'url' => $url,
            'type' => 'test', 'category' => 'test',
        ]);
    }

    $migration = require __DIR__.'/../../database/migrations/backfill_waf_target_hash_table.php.stub';
    $migration->up();
    $migration->up();

    $hashes = DB::table('waf_logs')->orderBy('id')->pluck('target_hash')->all();
    expect($hashes[0])->toBe(TargetHash::fromUrl('http://localhost/login'))
        ->and($hashes[1])->toBe($hashes[0])
        ->and($hashes[2])->toBeNull();
});

it('refuses to mark the target backfill complete without an app key', function () {
    config()->set('app.key', '');
    DB::table('waf_logs')->insert([
        'ip_address' => '192.0.2.1', 'url' => 'http://localhost/login',
        'type' => 'test', 'category' => 'test',
    ]);

    $migration = require __DIR__.'/../../database/migrations/backfill_waf_target_hash_table.php.stub';
    expect(fn () => $migration->up())->toThrow(RuntimeException::class, 'Set APP_KEY');
});
