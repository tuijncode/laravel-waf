<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

$runUpgrade = function (): void {
    $migration = require __DIR__.'/../../database/migrations/upgrade_waf_logs_table.php.stub';
    $migration->up();
};

// Rebuild waf_logs in its pre-1.1 shape: no event_id column, no created_at index.
function rebuildLegacyWafLogs(): void
{
    Schema::dropIfExists('waf_logs');

    Schema::create('waf_logs', function (Blueprint $table) {
        $table->id();
        $table->string('ip_address')->index();
        $table->text('url');
        $table->text('type');
        $table->string('category', 30)->index();
        $table->timestamps();
    });
}

it('adds event_id and keeps the table usable on a legacy schema', function () use ($runUpgrade) {
    rebuildLegacyWafLogs();
    expect(Schema::hasColumn('waf_logs', 'event_id'))->toBeFalse();
    expect(Schema::hasColumn('waf_logs', 'hit_count'))->toBeFalse();

    $runUpgrade();

    expect(Schema::hasColumn('waf_logs', 'event_id'))->toBeTrue()
        ->and(Schema::hasColumn('waf_logs', 'hit_count'))->toBeTrue();

    // The column accepts a UUID and stays unique.
    DB::table('waf_logs')->insert([
        'event_id' => '11111111-1111-1111-1111-111111111111',
        'ip_address' => '203.0.113.1',
        'url' => '/',
        'type' => 't',
        'category' => 'sqli',
    ]);

    expect(DB::table('waf_logs')->where('event_id', '11111111-1111-1111-1111-111111111111')->exists())->toBeTrue();
});

it('is idempotent — safe to run against an already-upgraded table', function () use ($runUpgrade) {
    // The TestCase already creates waf_logs with event_id + the created_at index.
    expect(Schema::hasColumn('waf_logs', 'event_id'))->toBeTrue();

    $runUpgrade(); // must not throw

    expect(Schema::hasColumn('waf_logs', 'event_id'))->toBeTrue();
});

it('preserves upgraded columns and data on rollback', function () use ($runUpgrade) {
    rebuildLegacyWafLogs();
    $runUpgrade();
    expect(Schema::hasColumn('waf_logs', 'event_id'))->toBeTrue();

    DB::table('waf_logs')->insert([
        'event_id' => '22222222-2222-2222-2222-222222222222',
        'ip_address' => '203.0.113.2',
        'url' => '/',
        'type' => 't',
        'category' => 'sqli',
        'hit_count' => 3,
    ]);

    $migration = require __DIR__.'/../../database/migrations/upgrade_waf_logs_table.php.stub';
    $migration->down();

    expect(Schema::hasColumn('waf_logs', 'event_id'))->toBeTrue()
        ->and(Schema::hasColumn('waf_logs', 'hit_count'))->toBeTrue()
        ->and(DB::table('waf_logs')->value('hit_count'))->toBe(3);
});

it('preserves pre-existing columns on rollback', function () use ($runUpgrade) {
    $runUpgrade();

    $migration = require __DIR__.'/../../database/migrations/upgrade_waf_logs_table.php.stub';
    $migration->down();

    expect(Schema::hasColumn('waf_logs', 'event_id'))->toBeTrue()
        ->and(Schema::hasColumn('waf_logs', 'hit_count'))->toBeTrue();
});
