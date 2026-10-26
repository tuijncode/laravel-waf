<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tuijncode\LaravelWaf\Jobs\RecordWafHit;

it('backfills durable totals from hit records on upgrade', function () {
    $eventId = (string) Str::uuid();
    DB::table('waf_hit_events')->insert([
        ['id' => (string) Str::uuid(), 'event_id' => $eventId, 'created_at' => now()],
        ['id' => (string) Str::uuid(), 'event_id' => $eventId, 'created_at' => now()],
    ]);
    Schema::drop('waf_hit_totals');
    $migration = require __DIR__.'/../../database/migrations/create_waf_hit_totals_table.php.stub';

    // A new worker may have started this finding's total before backfill visits it.
    Schema::create('waf_hit_totals', function ($table): void {
        $table->uuid('event_id')->primary();
        $table->unsignedBigInteger('hit_count')->default(0);
        $table->timestamp('updated_at')->index();
    });
    (new RecordWafHit($eventId, (string) Str::uuid()))->handle();
    $migration->up();
    (new RecordWafHit($eventId, (string) Str::uuid()))->handle();
    $migration->up();

    expect((int) DB::table('waf_hit_totals')->where('event_id', $eventId)->value('hit_count'))->toBe(4);
});
