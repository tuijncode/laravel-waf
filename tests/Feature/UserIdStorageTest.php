<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tuijncode\LaravelWaf\Models\WafLog;
use Tuijncode\LaravelWaf\Services\ExclusionRuleService;

it('stores and reads a finding for an authenticated UUID user', function () {
    $uuid = '11111111-1111-4111-8111-111111111111';
    $user = new class extends Authenticatable
    {
        public $incrementing = false;

        protected $keyType = 'string';
    };
    $user->id = $uuid;
    Auth::guard()->setUser($user);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->value('user_id'))->toBe($uuid)
        ->and(WafLog::sole()->user_id)->toBe($uuid);
});

it('widens an existing numeric user ID column without losing values', function () {
    Schema::table('waf_logs', fn (Blueprint $table) => $table->unsignedBigInteger('user_id')->nullable()->change());
    DB::table('waf_logs')->insert([
        'ip_address' => '203.0.113.1',
        'url' => '/',
        'type' => 'test',
        'category' => 'sqli',
        'user_id' => 42,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $migration = require __DIR__.'/../../database/migrations/widen_waf_user_id_table.php.stub';
    $migration->up();
    $migration->up();

    expect(DB::table('waf_logs')->value('user_id'))->toBe('42')
        ->and(Schema::getColumnType('waf_logs', 'user_id', true))->toContain('varchar');

    DB::table('waf_logs')->insert([
        'ip_address' => '203.0.113.2',
        'url' => '/',
        'type' => 'test',
        'category' => 'sqli',
        'user_id' => '22222222-2222-4222-8222-222222222222',
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    expect(WafLog::where('ip_address', '203.0.113.2')->value('user_id'))
        ->toBe('22222222-2222-4222-8222-222222222222');
});

it('stores UUID creators for manual and log-derived exclusions', function () {
    $uuid = '33333333-3333-4333-8333-333333333333';
    $service = app(ExclusionRuleService::class);
    $manual = $service->add('942100', userId: $uuid);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $derived = $service->acceptFromLog(DB::table('waf_logs')->value('id'), userId: $uuid);

    expect($manual->created_by_user_id)->toBe($uuid)
        ->and($derived->created_by_user_id)->toBe($uuid);
});

it('widens the exclusion creator column without losing numeric IDs', function () {
    Schema::table('waf_exclusion_rules', fn (Blueprint $table) => $table->unsignedBigInteger('created_by_user_id')->nullable()->change());
    DB::table('waf_exclusion_rules')->insert([
        'match_label' => '942100',
        'created_by_user_id' => 42,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $migration = require __DIR__.'/../../database/migrations/widen_waf_exclusion_user_id_table.php.stub';
    $migration->up();
    $migration->up();

    expect(DB::table('waf_exclusion_rules')->value('created_by_user_id'))->toBe('42')
        ->and(Schema::getColumnType('waf_exclusion_rules', 'created_by_user_id', true))->toContain('varchar');
    expect(app(ExclusionRuleService::class)->add('941130', userId: '44444444-4444-4444-8444-444444444444')->created_by_user_id)
        ->toBe('44444444-4444-4444-8444-444444444444');
});

it('widens existing text user ID columns that are too short', function () {
    if (DB::connection()->getDriverName() === 'sqlite') {
        $this->markTestSkipped('SQLite does not enforce VARCHAR length');
    }

    Schema::table('waf_logs', fn (Blueprint $table) => $table->string('user_id', 8)->nullable()->change());
    Schema::table('waf_exclusion_rules', fn (Blueprint $table) => $table->string('created_by_user_id', 8)->nullable()->change());

    (require __DIR__.'/../../database/migrations/widen_waf_user_id_table.php.stub')->up();
    (require __DIR__.'/../../database/migrations/widen_waf_exclusion_user_id_table.php.stub')->up();

    expect(Schema::getColumnType('waf_logs', 'user_id', true))->toMatch('/(?:varchar|character varying)\(191\)|nvarchar\(382\)/')
        ->and(Schema::getColumnType('waf_exclusion_rules', 'created_by_user_id', true))->toMatch('/(?:varchar|character varying)\(191\)|nvarchar\(382\)/');
});

it('reports text user ID columns that are too short', function () {
    if (DB::connection()->getDriverName() === 'sqlite') {
        $this->markTestSkipped('SQLite does not enforce VARCHAR length');
    }

    Schema::table('waf_logs', fn (Blueprint $table) => $table->string('user_id', 8)->nullable()->change());
    Schema::table('waf_exclusion_rules', fn (Blueprint $table) => $table->string('created_by_user_id', 8)->nullable()->change());

    $this->artisan('waf:doctor')
        ->expectsOutputToContain("'waf_logs.user_id' cannot store UUID or string user IDs")
        ->expectsOutputToContain("'waf_exclusion_rules.created_by_user_id' cannot store UUID or string user IDs")
        ->assertFailed();
});
