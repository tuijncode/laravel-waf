<?php

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tuijncode\LaravelWaf\Jobs\StoreWafLog;
use Tuijncode\LaravelWaf\Services\WafInspector;
use Tuijncode\LaravelWaf\WafServiceProvider;

function seedLog(string $type, DateTimeInterface $createdAt): int
{
    return DB::table('waf_logs')->insertGetId([
        'ip_address' => '10.0.0.1',
        'method' => 'GET',
        'url' => 'http://localhost/',
        'type' => $type,
        'category' => 'sqli',
        'threat_level' => 'critical',
        'confidence_score' => 50,
        'confidence_label' => 'medium',
        'created_at' => $createdAt,
        'updated_at' => $createdAt,
    ]);
}

it('purges logs older than the given number of days', function () {
    seedLog('old', now()->subDays(100));
    seedLog('recent', now()->subDays(5));

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 1 finding(s) older than 90 day(s)?', 'yes')
        ->expectsOutputToContain('Pruned 1 finding(s).')
        ->assertSuccessful();

    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and(DB::table('waf_logs')->value('type'))->toBe('recent');
});

it('keeps standing exclusion rules after pruning their source finding', function () {
    $oldId = seedLog('old', now()->subDays(100));

    DB::table('waf_exclusion_rules')->insert([
        'match_label' => 'old',
        'source_log_id' => $oldId,
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 1 finding(s) older than 90 day(s)?', 'yes')
        ->assertSuccessful();

    expect(DB::table('waf_exclusion_rules')->value('source_log_id'))->toBeNull()
        ->and(DB::table('waf_exclusion_rules')->count())->toBe(1);
});

it('reports when nothing needs purging', function () {
    seedLog('recent', now()->subDays(5));

    $this->artisan('waf:purge --days=90')
        ->expectsOutputToContain('Nothing to prune — no findings predate 90 day(s) ago.')
        ->assertSuccessful();

    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and(DB::table('waf_purge_watermarks')->where('table_name', 'waf_logs')->value('purged_before'))->not->toBeNull();
});

it('does not store an in-flight inline finding after its purge cutoff', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $job = Bus::dispatched(StoreWafLog::class)->first();
    $row = (new ReflectionProperty($job, 'row'))->getValue($job);

    $this->travel(1)->seconds();
    $this->artisan('waf:purge --days=0')->assertSuccessful();
    config()->set('waf.queue.enabled', false);
    $persist = new ReflectionMethod(WafInspector::class, 'persist');

    expect($persist->invoke(app(WafInspector::class), $row, null))->toBeFalse()
        ->and(DB::table('waf_logs')->count())->toBe(0);

    Cache::flush();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('keeps the latest purge horizon and leaves it unset after a cancelled purge', function () {
    seedLog('old', now()->subDays(100));
    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 1 finding(s) older than 90 day(s)?', 'no')
        ->assertSuccessful();
    expect(DB::table('waf_purge_watermarks')->count())->toBe(0);

    $this->artisan('waf:purge --days=30')
        ->expectsConfirmation('Prune 1 finding(s) older than 30 day(s)?', 'yes')
        ->assertSuccessful();
    $first = DB::table('waf_purge_watermarks')->value('purged_before');

    $this->artisan('waf:purge --days=90')->assertSuccessful();
    expect(DB::table('waf_purge_watermarks')->value('purged_before'))->toBe($first);
});

it('requires the purge watermark migration before deleting findings', function () {
    seedLog('old', now()->subDays(100));
    Schema::drop('waf_purge_watermarks');

    $this->artisan('waf:purge --days=90')
        ->expectsOutputToContain('waf_purge_watermarks table is missing')
        ->assertFailed();
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('prunes old durable hit records with the findings', function () {
    $oldEventId = (string) Str::uuid();
    $recentEventId = (string) Str::uuid();
    DB::table('waf_hit_events')->insert([
        ['id' => (string) Str::uuid(), 'event_id' => $oldEventId, 'created_at' => now()->subDays(100)],
        ['id' => (string) Str::uuid(), 'event_id' => $recentEventId, 'created_at' => now()],
    ]);
    DB::table('waf_hit_totals')->insert([
        ['event_id' => $oldEventId, 'hit_count' => 1, 'updated_at' => now()->subDays(100)],
        ['event_id' => $recentEventId, 'hit_count' => 1, 'updated_at' => now()],
    ]);

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 0 finding(s) older than 90 day(s) and 1 old hit record(s) and 1 old hit total(s)?', 'yes')
        ->assertSuccessful();

    expect(DB::table('waf_hit_events')->count())->toBe(1)
        ->and(DB::table('waf_hit_totals')->count())->toBe(1);
});

it('prunes recent hit rows when their finding is old', function () {
    $eventId = (string) Str::uuid();
    $logId = seedLog('old', now()->subDays(100));
    DB::table('waf_logs')->where('id', $logId)->update(['event_id' => $eventId]);
    DB::table('waf_hit_events')->insert(['id' => (string) Str::uuid(), 'event_id' => $eventId, 'created_at' => now()]);
    DB::table('waf_hit_totals')->insert(['event_id' => $eventId, 'hit_count' => 1, 'updated_at' => now()]);

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 1 finding(s) older than 90 day(s)?', 'yes')
        ->assertSuccessful();

    expect(DB::table('waf_logs')->count())->toBe(0)
        ->and(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0);
});

it('rejects an invalid age without deleting findings', function () {
    seedLog('old', now()->subDays(100));

    $this->artisan('waf:purge', ['--days' => 'invalid'])
        ->expectsOutputToContain('--days must be a non-negative whole number.')
        ->assertFailed();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('does not schedule a purge with an invalid retention age', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 'invalid');
    $schedule = app(Schedule::class);
    $before = count($schedule->events());

    (new ReflectionMethod(WafServiceProvider::class, 'registerSchedule'))
        ->invoke(new WafServiceProvider(app()));

    expect($schedule->events())->toHaveCount($before);
});

it('prunes old attempt variants while keeping recent ones', function () {
    DB::table('waf_attempts')->insert([
        ['ip_address' => '10.0.0.1', 'rule_id' => '941100', 'fingerprint' => '1111111111111111', 'variant' => 'aaaaaaaaaaaaaaaa', 'window_id' => 1, 'created_at' => now()->subDays(10)],
        ['ip_address' => '10.0.0.1', 'rule_id' => '941100', 'fingerprint' => '1111111111111111', 'variant' => 'bbbbbbbbbbbbbbbb', 'window_id' => 2, 'created_at' => now()],
    ]);

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 0 finding(s) older than 90 day(s) and 1 old attempt variant(s)?', 'yes')
        ->expectsOutputToContain('Pruned 1 old attempt variant(s).')
        ->assertSuccessful();

    expect(DB::table('waf_attempts')->count())->toBe(1)
        ->and(DB::table('waf_attempts')->value('variant'))->toBe('bbbbbbbbbbbbbbbb');
});

it('uses the default attempt retention when its setting is invalid', function () {
    config()->set('waf.attempts.retention_days', 'invalid');
    DB::table('waf_attempts')->insert([
        ['ip_address' => '10.0.0.1', 'rule_id' => '941100', 'fingerprint' => '1111111111111111', 'variant' => 'aaaaaaaaaaaaaaaa', 'window_id' => 1, 'created_at' => now()->subDays(10)],
        ['ip_address' => '10.0.0.1', 'rule_id' => '941100', 'fingerprint' => '1111111111111111', 'variant' => 'bbbbbbbbbbbbbbbb', 'window_id' => 2, 'created_at' => now()->subDays(3)],
    ]);

    $this->artisan('waf:purge --days=90')
        ->expectsConfirmation('Prune 0 finding(s) older than 90 day(s) and 1 old attempt variant(s)?', 'yes')
        ->assertSuccessful();

    expect(DB::table('waf_attempts')->pluck('variant')->all())->toBe(['bbbbbbbbbbbbbbbb']);
});
