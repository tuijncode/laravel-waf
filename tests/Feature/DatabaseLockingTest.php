<?php

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tuijncode\LaravelWaf\Jobs\RecordWafHit;
use Tuijncode\LaravelWaf\Jobs\StoreWafLog;

it('serializes purge and finding writes across database connections', function () {
    $driver = getenv('WAF_TEST_DB_DRIVER');
    if ($driver !== 'mysql' && $driver !== 'pgsql') {
        $this->markTestSkipped('Requires MySQL or PostgreSQL');
    }

    $this->artisan('waf:purge --days=1')->assertSuccessful();
    config()->set('database.connections.waf_peer', config('database.connections.testing'));
    $main = DB::connection('testing');
    $peer = DB::connection('waf_peer');
    $timeout = $driver === 'mysql' ? 'SET SESSION innodb_lock_wait_timeout = 1' : "SET lock_timeout = '1s'";
    $main->statement($timeout);
    $peer->statement($timeout);

    $main->beginTransaction();
    try {
        $main->table('waf_purge_watermarks')->where('table_name', 'waf_logs')->sharedLock()->first();
        $blocked = false;
        try {
            $peer->table('waf_purge_watermarks')->where('table_name', 'waf_logs')->lockForUpdate()->first();
        } catch (QueryException) {
            $blocked = true;
        }
        expect($blocked)->toBeTrue();
    } finally {
        $main->rollBack();
    }
    expect($peer->table('waf_purge_watermarks')->where('table_name', 'waf_logs')->lockForUpdate()->first())->not->toBeNull();

    $staleRow = [
        'event_id' => (string) Str::uuid(),
        'ip_address' => '203.0.113.1',
        'url' => '/',
        'type' => '[942100] test',
        'category' => 'sqli',
        'created_at' => now()->subDays(2),
        'updated_at' => now()->subDays(2),
    ];
    $staleStore = new StoreWafLog($staleRow);
    $peer->beginTransaction();
    try {
        $peer->table('waf_purge_watermarks')->where('table_name', 'waf_logs')->lockForUpdate()->first();
        $blocked = false;
        try {
            $main->table('waf_purge_watermarks')->where('table_name', 'waf_logs')->sharedLock()->first();
        } catch (QueryException) {
            $blocked = true;
        }
        expect($blocked)->toBeTrue();
        expect(fn () => $staleStore->storeInline())->toThrow(QueryException::class);
    } finally {
        $peer->rollBack();
    }
    expect($main->table('waf_purge_watermarks')->where('table_name', 'waf_logs')->sharedLock()->first())->not->toBeNull();
    expect($staleStore->storeInline())->toBeNull();

    $eventId = (string) Str::uuid();
    $row = [
        'event_id' => $eventId,
        'ip_address' => '203.0.113.1',
        'url' => '/',
        'type' => '[942100] test',
        'category' => 'sqli',
        'created_at' => now(),
        'updated_at' => now(),
    ];
    $store = new StoreWafLog($row);
    expect($store->storeInline())->toBeInt();
    $hit = new RecordWafHit($eventId, (string) Str::uuid(), $row['created_at']->toISOString());

    $this->travel(2)->days();
    $this->artisan('waf:purge --days=1')
        ->expectsConfirmation('Prune 1 finding(s) older than 1 day(s)?', 'yes')
        ->assertSuccessful();
    $store->handle();
    $hit->handle();

    expect(DB::table('waf_logs')->count())->toBe(0)
        ->and(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0);

    $row['event_id'] = (string) Str::uuid();
    $row['created_at'] = $row['updated_at'] = now();
    expect((new StoreWafLog($row))->storeInline())->toBeInt();
});
