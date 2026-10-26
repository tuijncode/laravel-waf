<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Tuijncode\LaravelWaf\Services\WafInspector;

it('is opt-in and records unknown AI infrastructure paths', function () {
    $this->get('/api/tags')->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(0);

    config()->set('waf.ai_probes.enabled', true);
    $this->get('/api/tags')->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->type)->toContain('Ollama Model Enumeration')
        ->and($log->category)->toBe('ai_probe');
});

it('does not flag an AI path served by an application route', function () {
    config()->set('waf.ai_probes.enabled', true);
    Route::get('/v1/models', fn () => 'models');

    $result = app(WafInspector::class)->inspect(Request::create('/v1/models'));

    expect($result->matches)->toBe([]);
});

it('can match an encoded path and ignores unrelated paths', function () {
    config()->set('waf.ai_probes.enabled', true);

    $this->get('/m%63p/handshake')->assertOk();
    $this->get('/api/orders')->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1)
        ->and(DB::table('waf_logs')->value('category'))->toBe('ai_probe');
});

it('covers additional model and agent configuration probes', function (string $path, string $label) {
    config()->set('waf.ai_probes.enabled', true);

    $this->get($path)->assertOk();

    expect(str_contains((string) DB::table('waf_logs')->value('type'), $label))->toBeTrue();
})->with([
    ['/api/show', 'Ollama Model Details'],
    ['/.cursor/rules', 'Agent Rules File Probe'],
    ['/litellm/settings', 'LiteLLM Admin Probe'],
    ['/v1beta/models/gemini', 'Gemini Inference Probe'],
]);

it('exempts a newly covered path that the application serves', function () {
    config()->set('waf.ai_probes.enabled', true);
    Route::post('/api/show', fn () => 'ok');

    expect(app(WafInspector::class)->inspect(Request::create('/api/show'))->matches)->toBe([]);
});
