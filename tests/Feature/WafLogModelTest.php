<?php

use Illuminate\Database\Events\ModelsPruned;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tuijncode\LaravelWaf\Jobs\RecordWafHit;
use Tuijncode\LaravelWaf\Jobs\StoreWafLog;
use Tuijncode\LaravelWaf\Models\WafLog;

function seedModelLog(string $ip, $createdAt): void
{
    WafLog::insert([
        'ip_address' => $ip,
        'url' => '/',
        'type' => '[942100] test',
        'category' => 'sqli',
        'threat_level' => 'critical',
        'created_at' => $createdAt,
        'updated_at' => $createdAt,
    ]);
}

it('reads findings through the configured table', function () {
    seedModelLog('203.0.113.1', now());

    expect(WafLog::count())->toBe(1)
        ->and(WafLog::first()->ip_address)->toBe('203.0.113.1')
        ->and(WafLog::first()->confidence_score)->toBeInt();
});

it('prunes findings past the retention horizon', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 30);

    seedModelLog('203.0.113.1', now()->subDays(60)); // stale
    seedModelLog('203.0.113.2', now()->subDay());    // fresh

    (new WafLog)->pruneAll();

    expect(WafLog::count())->toBe(1)
        ->and(WafLog::first()->ip_address)->toBe('203.0.113.2');
});

it('keeps exclusions but clears their source when model pruning removes a finding', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 30);
    seedModelLog('203.0.113.1', now()->subDays(60));
    $source = WafLog::sole();
    DB::table('waf_exclusion_rules')->insert([
        'source_log_id' => $source->id,
        'match_label' => '942100',
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    (new WafLog)->pruneAll();

    expect(WafLog::count())->toBe(0)
        ->and(DB::table('waf_exclusion_rules')->value('source_log_id'))->toBeNull()
        ->and(DB::table('waf_exclusion_rules')->value('is_active'))->toBe(1);
});

it('keeps pruned findings deleted when an old store job arrives later', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 30);
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $oldJob = Bus::dispatched(StoreWafLog::class)->first();
    $oldJob->handle();
    $eventId = DB::table('waf_logs')->value('event_id');
    $oldHit = new RecordWafHit($eventId, (string) Str::uuid(), now()->toISOString());
    DB::table('waf_hit_events')->insert(['id' => (string) Str::uuid(), 'event_id' => $eventId, 'created_at' => now()]);
    DB::table('waf_hit_totals')->insert(['event_id' => $eventId, 'hit_count' => 1, 'updated_at' => now()]);

    $this->travel(60)->days();
    (new WafLog)->pruneAll();
    $oldJob->handle();
    $oldHit->handle();

    expect(DB::table('waf_logs')->count())->toBe(0)
        ->and(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0)
        ->and(DB::table('waf_purge_watermarks')->value('purged_before'))->not->toBeNull();
});

it('keeps a directly pruned recent finding deleted after queued job retries', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $store = Bus::dispatched(StoreWafLog::class)->first();
    $store->handle();
    $eventId = WafLog::sole()->event_id;
    $hit = new RecordWafHit($eventId, (string) Str::uuid(), now()->toISOString());

    WafLog::sole()->prune();
    $store->handle();
    $hit->handle();

    expect(WafLog::count())->toBe(0)
        ->and(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_purge_watermarks')->where('table_name', 'event:'.$eventId)->exists())->toBeTrue();
});

it('keeps a finding and its related records when a deleting observer vetoes pruning', function () {
    $eventId = (string) Str::uuid();
    $id = DB::table('waf_logs')->insertGetId([
        'event_id' => $eventId,
        'ip_address' => '203.0.113.1',
        'url' => '/',
        'type' => '[942100] test',
        'category' => 'sqli',
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    DB::table('waf_hit_events')->insert(['id' => (string) Str::uuid(), 'event_id' => $eventId, 'created_at' => now()]);
    DB::table('waf_hit_totals')->insert(['event_id' => $eventId, 'hit_count' => 1, 'updated_at' => now()]);
    DB::table('waf_exclusion_rules')->insert([
        'source_log_id' => $id,
        'match_label' => '942100',
        'is_active' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    WafLog::deleting(fn () => false);

    expect(WafLog::findOrFail($id)->prune())->toBeFalse()
        ->and(DB::table('waf_logs')->count())->toBe(1)
        ->and(DB::table('waf_hit_events')->count())->toBe(1)
        ->and(DB::table('waf_hit_totals')->count())->toBe(1)
        ->and(DB::table('waf_exclusion_rules')->value('source_log_id'))->toBe($id)
        ->and(DB::table('waf_purge_watermarks')->count())->toBe(0);
});

it('leaves the watermark unchanged when a deleting observer throws', function () {
    seedModelLog('203.0.113.1', now());
    WafLog::deleting(fn () => throw new RuntimeException('observer failed'));

    expect(fn () => WafLog::sole()->prune())->toThrow(RuntimeException::class, 'observer failed');
    expect(WafLog::count())->toBe(1)
        ->and(DB::table('waf_purge_watermarks')->count())->toBe(0);
});

it('rejects invalid retention before a direct prune can advance the watermark', function () {
    config()->set('waf.retention.days', 'invalid');
    seedModelLog('203.0.113.1', now());

    expect(fn () => WafLog::sole()->prune())->toThrow(InvalidArgumentException::class);
    expect(WafLog::count())->toBe(1)
        ->and(DB::table('waf_purge_watermarks')->count())->toBe(0);
});

it('expires a direct prune marker once the global cutoff protects its jobs', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $store = Bus::dispatched(StoreWafLog::class)->first();
    $store->handle();
    $eventId = WafLog::sole()->event_id;
    $hit = new RecordWafHit($eventId, (string) Str::uuid(), now()->toISOString());
    WafLog::sole()->prune();

    $this->artisan('waf:purge --days=0')->assertSuccessful();
    expect(DB::table('waf_purge_watermarks')->where('table_name', 'event:'.$eventId)->exists())->toBeTrue();

    $this->travel(1)->days();
    $this->artisan('waf:purge --days=0')->assertSuccessful();
    expect(DB::table('waf_purge_watermarks')->where('table_name', 'event:'.$eventId)->exists())->toBeFalse();

    $store->handle();
    $hit->handle();
    expect(WafLog::count())->toBe(0)
        ->and(DB::table('waf_hit_events')->count())->toBe(0);
});

it('expires direct prune markers through model pruning too', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 1);
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $eventId = WafLog::sole()->event_id;
    WafLog::sole()->prune();

    $this->travel(2)->days();
    (new WafLog)->pruneAll();

    expect(DB::table('waf_purge_watermarks')->where('table_name', 'event:'.$eventId)->exists())->toBeFalse();
});

it('records the cutoff even when no stored finding needs pruning', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 30);
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $oldJob = Bus::dispatched(StoreWafLog::class)->first();

    $this->travel(60)->days();
    expect((new WafLog)->pruneAll())->toBe(0);
    $oldJob->handle();

    expect(DB::table('waf_logs')->count())->toBe(0)
        ->and(DB::table('waf_purge_watermarks')->value('purged_before'))->not->toBeNull();
});

it('fails the prune command before processing rows when the watermark migration is missing', function () {
    config()->set('waf.retention.enabled', true);
    seedModelLog('203.0.113.1', now()->subDays(100));
    Schema::drop('waf_purge_watermarks');

    expect(fn () => $this->artisan('model:prune', ['--model' => WafLog::class])->run())
        ->toThrow(RuntimeException::class, 'Run the waf-migrations-upgrade migrations');
    expect(WafLog::count())->toBe(1);
});

it('updates the purge cutoff once for a batch of old findings', function () {
    config()->set('waf.retention.enabled', true);
    seedModelLog('203.0.113.1', now()->subDays(100));
    seedModelLog('203.0.113.2', now()->subDays(100));
    $updates = 0;
    DB::listen(function ($query) use (&$updates): void {
        if (str_starts_with($query->sql, 'update ') && str_contains($query->sql, 'waf_purge_watermarks')) {
            $updates++;
        }
    });

    expect((new WafLog)->pruneAll())->toBe(2)
        ->and($updates)->toBe(1);
});

it('prunes in configured chunks while firing individual model events', function () {
    config()->set('waf.retention.enabled', true);
    Event::fake([ModelsPruned::class]);
    $deleted = 0;
    WafLog::deleted(function () use (&$deleted): void {
        $deleted++;
    });
    for ($i = 0; $i < 20; $i++) {
        seedModelLog('203.0.113.1', now()->subDays(100));
    }

    expect((new WafLog)->pruneAll(7))->toBe(20)
        ->and($deleted)->toBe(20);
    Event::assertDispatched(ModelsPruned::class, 3);
    Event::assertDispatched(ModelsPruned::class, fn ($event) => $event->model === WafLog::class && $event->count === 20);
});

it('uses one retention horizon even when the clock advances during pruning', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 30);
    seedModelLog('203.0.113.1', now()->subDays(30)->addSecond());
    $advanced = false;
    DB::listen(function ($query) use (&$advanced): void {
        if (! $advanced && str_starts_with($query->sql, 'update ') && str_contains($query->sql, 'waf_purge_watermarks')) {
            $advanced = true;
            $this->travel(2)->seconds();
        }
    });

    expect((new WafLog)->pruneAll())->toBe(0)
        ->and(WafLog::count())->toBe(1);
});

it('prunes nothing while retention is disabled', function () {
    config()->set('waf.retention.enabled', false);

    seedModelLog('203.0.113.1', now()->subDays(60));

    (new WafLog)->pruneAll();

    expect(WafLog::count())->toBe(1);
});

it('prunes nothing when the configured retention age is invalid', function () {
    config()->set('waf.retention.enabled', true);
    config()->set('waf.retention.days', 'invalid');
    seedModelLog('203.0.113.1', now()->subDays(60));

    (new WafLog)->pruneAll();

    expect(WafLog::count())->toBe(1);
});
