<?php

use Illuminate\Queue\Jobs\FakeJob;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tuijncode\LaravelWaf\Jobs\FlushWafHits;
use Tuijncode\LaravelWaf\Jobs\RecordWafHit;
use Tuijncode\LaravelWaf\Jobs\StoreWafLog;
use Tuijncode\LaravelWaf\Support\DedupCounter;
use Tuijncode\LaravelWaf\Support\MissingWafSchema;

beforeEach(fn () => config()->set('waf.queue.connection', 'database'));

function legacyHitJob(string $eventId, int $queuedAt): RecordWafHit
{
    $hit = new RecordWafHit($eventId, (string) Str::uuid());
    (new ReflectionProperty($hit, 'findingCreatedAt'))->setValue($hit, null);
    $hit->setJob(new class($queuedAt) extends FakeJob
    {
        public function __construct(private readonly int $queuedAt) {}

        public function getRawBody()
        {
            return json_encode(['createdAt' => $this->queuedAt]);
        }
    });

    return $hit;
}

it('dispatches the store job instead of inserting inline when queueing is enabled', function () {
    config()->set('waf.queue.enabled', true);
    config()->set('waf.queue.queue', 'security');
    Bus::fake();

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    // The insert is deferred to the queue, so nothing is written synchronously.
    expect(DB::table('waf_logs')->count())->toBe(0);

    Bus::assertDispatched(StoreWafLog::class);
});

it('does not restore a purged finding from a delayed queue job', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $job = Bus::dispatched(StoreWafLog::class)->first();

    $this->travel(2)->days();
    $this->artisan('waf:purge --days=1')->assertSuccessful();
    $job->handle();

    expect(DB::table('waf_logs')->count())->toBe(0);

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM accounts--"))->assertOk();
    Bus::dispatched(StoreWafLog::class)->last()->handle();
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('discards a delayed hit job after purge while keeping fresh early hits', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    $oldHit = unserialize(serialize(Bus::dispatched(RecordWafHit::class)->first()));

    $this->travel(2)->days();
    $this->artisan('waf:purge --days=1')->assertSuccessful();
    $oldHit->handle();
    expect(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0);

    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    Bus::dispatched(RecordWafHit::class)->last()->handle();
    Bus::dispatched(StoreWafLog::class)->last()->handle();
    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(2);
});

it('keeps an early hit durable after cache loss when a purge cutoff already exists', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->artisan('waf:purge --days=1')->assertSuccessful();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    Cache::flush();

    Bus::dispatched(RecordWafHit::class)->first()->handle();
    Bus::dispatched(StoreWafLog::class)->first()->handle();

    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(2);
});

it('keeps a legacy early hit durable after a purge cutoff and cache loss', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->artisan('waf:purge --days=1')->assertSuccessful();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $store = Bus::dispatched(StoreWafLog::class)->first();
    $row = (new ReflectionProperty($store, 'row'))->getValue($store);
    $hit = legacyHitJob($row['event_id'], now()->timestamp);
    Cache::flush();

    $hit->handle();
    $store->handle();

    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(2)
        ->and(DB::table('waf_hit_events')->count())->toBe(1);
});

it('removes a legacy early hit when its delayed finding is older than the cutoff', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $store = Bus::dispatched(StoreWafLog::class)->first();
    $row = (new ReflectionProperty($store, 'row'))->getValue($store);
    $hit = legacyHitJob($row['event_id'], now()->timestamp);

    $this->travel(2)->days();
    $this->artisan('waf:purge --days=1')->assertSuccessful();
    $hit->handle();
    $store->handle();

    expect(DB::table('waf_logs')->count())->toBe(0)
        ->and(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0);

    $hit->handle();
    expect(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0);
});

it('does not recreate a purged hit from a legacy queued job after storage completed', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $hit = legacyHitJob(DB::table('waf_logs')->value('event_id'), now()->timestamp);

    $this->travel(2)->days();
    $this->artisan('waf:purge --days=1')
        ->expectsConfirmation('Prune 1 finding(s) older than 1 day(s)?', 'yes')
        ->assertSuccessful();
    $hit->handle();

    expect(DB::table('waf_logs')->count())->toBe(0)
        ->and(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0);
});

it('does not retain event markers for rejected old finding jobs', function () {
    $this->artisan('waf:purge --days=1')->assertSuccessful();
    for ($i = 0; $i < 3; $i++) {
        (new StoreWafLog(['event_id' => (string) Str::uuid(), 'created_at' => now()->subDays(2)]))->handle();
    }

    expect(DB::table('waf_purge_watermarks')->where('table_name', 'like', 'event:%')->count())->toBe(0);
});

it('does not recreate a purged hit when its deduplication window is still open', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();

    $this->travel(1)->second();
    $this->artisan('waf:purge --days=0')->assertSuccessful();
    $this->get($url)->assertOk();
    Bus::dispatched(RecordWafHit::class)->first()->handle();

    expect(DB::table('waf_hit_events')->count())->toBe(0)
        ->and(DB::table('waf_hit_totals')->count())->toBe(0);
});

it('inserts inline when queueing is disabled', function () {
    config()->set('waf.queue.enabled', false);
    Bus::fake();

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
    Bus::assertNotDispatched(StoreWafLog::class);
});

it('writes the finding directly when the queue rejects the job', function () {
    config()->set('waf.queue.enabled', true);
    Bus::shouldReceive('dispatch')->once()->andThrow(new RuntimeException('queue unavailable'));

    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('retries a queued finding without losing its dedup slot', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $first = null;

    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $job) use (&$first): bool {
        $first = $job;

        return true;
    });

    $first->failed(new RuntimeException('database unavailable'));
    Bus::assertDispatchedTimes(StoreWafLog::class, 2);
    $this->get($url)->assertOk();
    Bus::assertDispatchedTimes(StoreWafLog::class, 2);

    Bus::dispatched(StoreWafLog::class)->last()->handle();
    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);
});

it('stores a queued finding and its early duplicates after a prolonged outage', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    $first = Bus::dispatched(StoreWafLog::class)->first();
    expect($first->tries)->toBe(0);

    $first->failed(new RuntimeException('database unavailable'));
    $this->travel(3)->days();
    Bus::dispatched(StoreWafLog::class)->last()->handle();
    $eventId = DB::table('waf_logs')->value('event_id');
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);

    Bus::assertDispatchedTimes(FlushWafHits::class, 1);
    Bus::dispatched(FlushWafHits::class)->first()->handle(app(DedupCounter::class));
    expect(Cache::has('laravel-waf|pending|'.$eventId))->toBeFalse();
});

it('keeps pending duplicates when counting fails after a queued write', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $job = null;
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $queued) use (&$job): bool {
        $job = $queued;

        return true;
    });

    $counter = Mockery::mock(DedupCounter::class)->makePartial();
    $counter->shouldReceive('stored')->andThrow(new RuntimeException('counter unavailable'));
    app()->instance(DedupCounter::class, $counter);

    $job->handle();
    $eventId = DB::table('waf_logs')->value('event_id');

    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and(Cache::get('laravel-waf|pending|'.$eventId))->toBe(1);

    app()->instance(DedupCounter::class, new DedupCounter);
    Bus::assertDispatched(FlushWafHits::class, function (FlushWafHits $queued) use (&$flush): bool {
        $flush = $queued;

        return true;
    });
    $flush->handle(app(DedupCounter::class));
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);
});

it('does not count a queued burst twice after a post-update failure', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $job = null;
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $queued) use (&$job): bool {
        $job = $queued;

        return true;
    });

    $fail = true;
    DB::listen(function ($query) use (&$fail): void {
        if ($fail && str_contains($query->sql, 'update "waf_logs"') && str_contains($query->sql, 'hit_count')) {
            $fail = false;
            throw new RuntimeException('after database update');
        }
    });

    $job->handle();
    $eventId = DB::table('waf_logs')->value('event_id');
    expect($fail)->toBeFalse();
    expect(Cache::get('laravel-waf|pending|'.$eventId))->toBe(1);
    $job->handle();

    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);
});

it('keeps the deduplication slot if a stored job later reports a failure', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $job = null;
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $queued) use (&$job): bool {
        $job = $queued;

        return true;
    });

    $job->handle();
    $job->failed(new RuntimeException('worker timed out after insert'));
    $this->get($url)->assertOk();

    Bus::assertDispatchedTimes(StoreWafLog::class, 2);
    Bus::dispatched(StoreWafLog::class)->last()->handle();
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('keeps a failed queued write for retry when the database is unavailable', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $job = null;
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $queued) use (&$job): bool {
        $job = $queued;

        return true;
    });

    $database = DB::getFacadeRoot();
    DB::shouldReceive('table')->andThrow(new RuntimeException('database unavailable'));
    $job->failed(new RuntimeException('database unavailable'));
    DB::swap($database);

    $this->get($url)->assertOk();
    Bus::assertDispatchedTimes(StoreWafLog::class, 2);
    Bus::dispatched(StoreWafLog::class)->last()->handle();
    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('keeps pending hits for reconciliation when a stored row cannot be verified', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $job = null;
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $queued) use (&$job): bool {
        $job = $queued;

        return true;
    });
    $job->handle();
    $this->get($url)->assertOk();
    $eventId = DB::table('waf_logs')->value('event_id');

    $database = DB::getFacadeRoot();
    DB::shouldReceive('table')->andThrow(new RuntimeException('database unavailable'));
    $job->failed(new RuntimeException('worker failed'));
    DB::swap($database);

    expect(Cache::get('laravel-waf|pending|'.$eventId))->toBe(1);
    Bus::assertDispatchedTimes(StoreWafLog::class, 2);
    Bus::assertDispatchedTimes(FlushWafHits::class, 1);
    Bus::dispatched(StoreWafLog::class)->last()->handle();
    Bus::assertDispatched(FlushWafHits::class, function (FlushWafHits $queued) use (&$flush): bool {
        $flush = $queued;

        return true;
    });
    $flush->handle(app(DedupCounter::class));

    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);
});

it('counts duplicates received before the queued finding is stored', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $job = null;

    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();

    Bus::assertDispatchedTimes(StoreWafLog::class, 1);
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $queued) use (&$job): bool {
        $job = $queued;

        return true;
    });

    $job->handle();
    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(3);

    $this->get($url)->assertOk();
    $flush = null;
    Bus::assertDispatched(FlushWafHits::class, function (FlushWafHits $queued) use (&$flush): bool {
        $flush = $queued;

        return true;
    });
    $flush->handle(app(DedupCounter::class));
    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(4);

    $job->handle(); // A retry must not reset the count.
    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(4);
});

it('batches a queued burst into one hit-count update without losing the tail', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $store = null;
    $flush = null;

    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $job) use (&$store): bool {
        $store = $job;

        return true;
    });
    $store->handle();

    for ($i = 0; $i < 20; $i++) {
        $this->get($url)->assertOk();
    }

    Bus::assertDispatchedTimes(FlushWafHits::class, 1);
    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(1);
    Bus::assertDispatched(FlushWafHits::class, function (FlushWafHits $job) use (&$flush): bool {
        $flush = $job;

        return true;
    });
    $flush->handle(app(DedupCounter::class));
    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(21);
});

it('flushes pending hits directly when a queued flush exhausts retries', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $store = null;
    $flush = null;

    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $job) use (&$store): bool {
        $store = $job;

        return true;
    });
    $store->handle();
    $this->get($url)->assertOk();
    Bus::assertDispatched(FlushWafHits::class, function (FlushWafHits $job) use (&$flush): bool {
        $flush = $job;

        return true;
    });

    $flush->failed(new RuntimeException('queue exhausted'));
    expect((int) DB::table('waf_logs')->sole()->hit_count)->toBe(2);
});

it('keeps pending hits through a failed flush until the database recovers', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $store = null;
    $flush = null;

    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $job) use (&$store): bool {
        $store = $job;

        return true;
    });
    $store->handle();
    $this->get($url)->assertOk();
    Bus::assertDispatched(FlushWafHits::class, function (FlushWafHits $job) use (&$flush): bool {
        $flush = $job;

        return true;
    });

    $eventId = DB::table('waf_logs')->value('event_id');
    $database = DB::getFacadeRoot();
    DB::shouldReceive('table')->andThrow(new RuntimeException('database unavailable'));
    $flush->failed(new RuntimeException('queue attempts exhausted'));
    DB::swap($database);

    expect(Cache::get('laravel-waf|pending|'.$eventId))->toBe(1)
        ->and($flush->tries)->toBe(0);
    $this->travel(3)->days();
    expect(Cache::get('laravel-waf|pending|'.$eventId))->toBe(1);
    $flush->handle(app(DedupCounter::class));
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2)
        ->and(Cache::has('laravel-waf|pending|'.$eventId))->toBeFalse();
});

it('still counts a duplicate when its cache lock times out', function () {
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    $eventId = DB::table('waf_logs')->value('event_id');
    Cache::put('waf-test-held', $eventId, 60);
    $lock = Cache::lock('waf-test-held|lock', 5);
    expect($lock->get())->toBeTrue();

    try {
        $start = microtime(true);
        app(DedupCounter::class)->duplicate('waf-test-held');
        expect(microtime(true) - $start)->toBeLessThan(0.5);
    } finally {
        $lock->release();
    }

    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);
});

it('queues a duplicate immediately when its queued counter lock is busy', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $store = null;
    $flush = null;
    $this->get($url)->assertOk();
    Bus::assertDispatched(StoreWafLog::class, function (StoreWafLog $job) use (&$store): bool {
        $store = $job;

        return true;
    });
    $store->handle();
    $eventId = DB::table('waf_logs')->value('event_id');
    Cache::put('waf-test-held', $eventId, 60);
    $lock = Cache::lock('waf-test-held|lock', 5);
    expect($lock->get())->toBeTrue();

    try {
        $start = microtime(true);
        app(DedupCounter::class)->duplicate('waf-test-held');
        app(DedupCounter::class)->duplicate('waf-test-held');
        expect(microtime(true) - $start)->toBeLessThan(0.5);
    } finally {
        $lock->release();
    }

    Bus::assertDispatchedTimes(FlushWafHits::class, 1);
    Bus::assertDispatched(FlushWafHits::class, function (FlushWafHits $job) use (&$flush): bool {
        $flush = $job;

        return true;
    });
    $flush->handle(app(DedupCounter::class));
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(3);
});

it('keeps one flush for a delayed queued burst and cleans up after the dedup window', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $eventId = DB::table('waf_logs')->value('event_id');

    $this->get($url)->assertOk();
    $flush = Bus::dispatched(FlushWafHits::class)->first();
    $flush->withFakeQueueInteractions();
    $this->travel(31)->seconds();
    $this->get($url)->assertOk();
    Bus::assertDispatchedTimes(FlushWafHits::class, 1);

    $flush->handle(app(DedupCounter::class));
    $flush->assertReleased(300);
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(3)
        ->and(Cache::get('laravel-waf|pending|'.$eventId))->toBe(2);
    $this->travel(6)->minutes();
    $flush->handle(app(DedupCounter::class));
    expect(Cache::has('laravel-waf|pending|'.$eventId))->toBeFalse();
});

it('restores queued hit counts from durable jobs after the cache loses pending counts', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");

    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    $store = Bus::dispatched(StoreWafLog::class)->first();
    $hits = Bus::dispatched(RecordWafHit::class);
    expect($hits)->toHaveCount(2);

    Cache::flush();
    $hits->each(fn (RecordWafHit $job) => $job->handle());
    $store->handle();
    $hits->first()->handle(); // A retry cannot count a hit twice.

    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(3)
        ->and(DB::table('waf_hit_events')->count())->toBe(2)
        ->and((int) DB::table('waf_hit_totals')->value('hit_count'))->toBe(2);
});

it('ends a queued flush when its finding has already been purged', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $this->get($url)->assertOk();
    $eventId = DB::table('waf_logs')->value('event_id');
    DB::table('waf_logs')->delete();

    Bus::dispatched(FlushWafHits::class)->first()->handle(app(DedupCounter::class));

    expect(Cache::has('laravel-waf|pending|'.$eventId))->toBeFalse();
});

it('fails a queued finding with a missing storage table instead of retrying forever', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $job = Bus::dispatched(StoreWafLog::class)->first();
    $job->withFakeQueueInteractions();
    Schema::drop('waf_logs');

    $job->handle();

    $job->assertFailedWith(MissingWafSchema::class);
});

it('fails a queued hit with a missing ledger table instead of retrying forever', function () {
    $job = new RecordWafHit((string) Str::uuid(), (string) Str::uuid());
    $job->withFakeQueueInteractions();
    Schema::drop('waf_hit_events');

    $job->handle();

    $job->assertFailedWith(MissingWafSchema::class);
});

it('fails a queued hit with a missing totals table instead of retrying forever', function () {
    $job = new RecordWafHit((string) Str::uuid(), (string) Str::uuid());
    $job->withFakeQueueInteractions();
    Schema::drop('waf_hit_totals');

    $job->handle();

    $job->assertFailedWith(MissingWafSchema::class);
});

it('fails a queued flush with a missing log table instead of retrying forever', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $this->get($url)->assertOk();
    $flush = Bus::dispatched(FlushWafHits::class)->first();
    $flush->withFakeQueueInteractions();
    Schema::drop('waf_logs');

    $flush->handle(app(DedupCounter::class));

    $flush->assertFailedWith(MissingWafSchema::class);
});

it('fails a queued flush when the totals table lacks a required column', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $this->get($url)->assertOk();
    $flush = Bus::dispatched(FlushWafHits::class)->first();
    $flush->withFakeQueueInteractions();
    Schema::table('waf_hit_totals', fn ($table) => $table->dropColumn('hit_count'));

    $flush->handle(app(DedupCounter::class));

    $flush->assertFailedWith(MissingWafSchema::class);
});

it('updates durable totals without recounting every prior hit', function () {
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    $eventId = DB::table('waf_logs')->value('event_id');
    $scans = 0;
    DB::listen(function ($query) use (&$scans): void {
        if (str_contains($query->sql, 'waf_hit_events') && str_contains(strtolower($query->sql), 'count(')) {
            $scans++;
        }
    });

    $first = new RecordWafHit($eventId, (string) Str::uuid());
    $first->handle();
    $first->handle();
    for ($i = 1; $i < 100; $i++) {
        (new RecordWafHit($eventId, (string) Str::uuid()))->handle();
    }
    $observedScans = $scans;

    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(101)
        ->and((int) DB::table('waf_hit_totals')->value('hit_count'))->toBe(100)
        ->and(DB::table('waf_hit_events')->count())->toBe(100)
        ->and($observedScans)->toBe(0);
});

it('expires the pending count after a rejected flush was written directly', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $this->get('/?q='.rawurlencode("' UNION SELECT * FROM users--"))->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $eventId = DB::table('waf_logs')->value('event_id');
    $seenKey = 'waf-test-rejected-flush';
    Cache::put($seenKey, $eventId, 300);
    Cache::put('laravel-waf|stored|'.$eventId, true, 300);

    Bus::shouldReceive('dispatch')->twice()->andThrow(new RuntimeException('queue unavailable'));

    app(DedupCounter::class)->duplicate($seenKey);
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2)
        ->and(DB::table('waf_hit_events')->count())->toBe(1)
        ->and(Cache::has('laravel-waf|pending|'.$eventId))->toBeTrue();

    $this->travel(7)->minutes();
    expect(Cache::has('laravel-waf|pending|'.$eventId))->toBeFalse();
});

it('recovers early duplicates when the store job cannot queue their flush', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    $this->get($url)->assertOk();
    $store = Bus::dispatched(StoreWafLog::class)->first();
    Bus::shouldReceive('dispatch')->once()->andThrow(new RuntimeException('queue unavailable'));

    $store->handle();
    $eventId = DB::table('waf_logs')->value('event_id');
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);

    $this->travel(7)->minutes();
    expect(Cache::has('laravel-waf|pending|'.$eventId))->toBeFalse();
});

it('expires pending hits when retrying a flush is rejected by the queue', function () {
    config()->set('waf.queue.enabled', true);
    Bus::fake();
    $url = '/?q='.rawurlencode("' UNION SELECT * FROM users--");
    $this->get($url)->assertOk();
    Bus::dispatched(StoreWafLog::class)->first()->handle();
    $this->get($url)->assertOk();
    $eventId = DB::table('waf_logs')->value('event_id');
    $flush = Bus::dispatched(FlushWafHits::class)->first();
    Bus::shouldReceive('dispatch')->once()->andThrow(new RuntimeException('queue unavailable'));

    $flush->failed(new RuntimeException('worker exhausted'));
    expect((int) DB::table('waf_logs')->value('hit_count'))->toBe(2);

    $this->travel(7)->minutes();
    expect(Cache::has('laravel-waf|pending|'.$eventId))->toBeFalse();
});
