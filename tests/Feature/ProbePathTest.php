<?php

use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Route as LaravelRoute;
use Illuminate\Routing\RouteCollection;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Tuijncode\LaravelWaf\Services\WafInspector;

it('detects an unserved probe path only when enabled', function () {
    $this->get('/swagger')->assertOk();
    expect(DB::table('waf_logs')->count())->toBe(0);

    config()->set('waf.probe_paths.enabled', true);
    $this->get('/SWAGGER')->assertOk();

    $log = DB::table('waf_logs')->sole();
    expect($log->category)->toBe('probe')
        ->and($log->type)->toContain('Swagger UI Probe');
});

it('ignores a probe path served by the app and accepts encoded probes', function () {
    config()->set('waf.probe_paths.enabled', true);
    Route::post('/swagger', fn () => 'docs');

    expect(app(WafInspector::class)->inspect(Request::create('/swagger'))->matches)->toBe([]);

    $this->get('/cp%61nel')->assertOk();
    expect(DB::table('waf_logs')->value('category'))->toBe('probe');
});

it('can disable the optional probe category', function () {
    config()->set('waf.probe_paths.enabled', true);
    config()->set('waf.disabled_categories', ['probe']);

    expect(app(WafInspector::class)->inspect(Request::create('/swagger'))->matches)->toBe([]);
});

it('checks only matching literal routes and sees later registration', function () {
    config()->set('waf.probe_paths.enabled', true);
    $unrelated = new class('GET', '/unrelated', fn () => 'ok') extends LaravelRoute
    {
        public int $checks = 0;

        public int $uriReads = 0;

        public function uri()
        {
            $this->uriReads++;

            return parent::uri();
        }

        public function matches(Request $request, $includingMethod = true)
        {
            $this->checks++;

            return parent::matches($request, $includingMethod);
        }
    };
    Route::getRoutes()->add($unrelated);

    $inspector = app(WafInspector::class);
    expect($inspector->inspect(Request::create('/swagger'))->ruleIds())->toContain('PATH-PROBE')
        ->and($unrelated->checks)->toBe(0);
    $reads = $unrelated->uriReads;
    expect($inspector->inspect(Request::create('/swagger'))->ruleIds())->toContain('PATH-PROBE')
        ->and($unrelated->uriReads)->toBe($reads);

    Route::post('/swagger', fn () => 'docs');
    expect($inspector->inspect(Request::create('/swagger'))->ruleIds())->not->toContain('PATH-PROBE');
});

it('refreshes the probe index after a registered route changes its URI', function () {
    config()->set('waf.probe_paths.enabled', true);
    $route = Route::post('/unrelated', fn () => 'docs');
    $inspector = app(WafInspector::class);
    $request = Request::create('/swagger');

    expect($route->matches(Request::create('/unrelated', 'POST')))->toBeTrue();
    expect($inspector->inspect($request)->ruleIds())->toContain('PATH-PROBE');
    $route->setUri('/swagger');
    $inspector->refreshRouteIndex($route);

    expect($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE')
        ->and($route->matches(Request::create('/swagger', 'POST')))->toBeTrue();
});

it('uses the current dynamic route after a same-key replacement', function () {
    config()->set('waf.probe_paths.enabled', true);
    Route::post('/swagger/{id}', fn () => 'old')->where('id', '[a-z]+');
    $request = Request::create('/swagger/123');
    $inspector = app(WafInspector::class);

    expect($inspector->inspect($request)->ruleIds())->toContain('PATH-PROBE');
    $before = count(Route::getRoutes()->getRoutes());
    Route::post('/swagger/{id}', fn () => 'new')->where('id', '[0-9]+');

    expect(count(Route::getRoutes()->getRoutes()))->toBe($before)
        ->and($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE');
});

it('recognises a constrained one-segment route as a served probe path', function () {
    config()->set('waf.probe_paths.enabled', true);
    Route::post('/{page}', fn () => 'docs')->where('page', 'swagger');
    $request = Request::create('/swagger');
    $inspector = app(WafInspector::class);

    expect($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE');

    $compiled = Route::getRoutes()->compile();
    app(Router::class)->setCompiledRoutes($compiled);
    expect($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE');
});

it('sees a broad root route become constrained under the same route key', function () {
    config()->set('waf.probe_paths.enabled', true);
    Route::post('/{page}', fn () => 'broad')->where('page', '.*');
    $request = Request::create('/swagger');
    $inspector = app(WafInspector::class);

    expect($inspector->inspect($request)->ruleIds())->toContain('PATH-PROBE');
    $before = count(Route::getRoutes()->getRoutes());
    Route::post('/{page}', fn () => 'docs')->where('page', 'swagger');

    expect(count(Route::getRoutes()->getRoutes()))->toBe($before)
        ->and($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE');
});

it('uses the already matched route without scanning a regular collection', function () {
    config()->set('waf.probe_paths.enabled', true);
    $route = Route::post('/swagger', fn () => 'docs');
    $collection = new class extends RouteCollection
    {
        public int $enumerations = 0;

        public function getRoutes()
        {
            $this->enumerations++;

            return parent::getRoutes();
        }
    };
    foreach (Route::getRoutes()->getRoutes() as $existing) {
        $collection->add($existing);
    }
    app(Router::class)->setRoutes($collection);
    $collection->enumerations = 0;
    $request = Request::create('/swagger');
    $request->setRouteResolver(fn () => $route);

    expect(app(WafInspector::class)->inspect($request)->ruleIds())->not->toContain('PATH-PROBE')
        ->and($collection->enumerations)->toBe(0);
});

it('refreshes the index when a route is replaced without changing the route count', function () {
    config()->set('waf.probe_paths.enabled', true);
    Route::get('/swagger', fn () => 'old')->domain('old.test');
    $request = Request::create('http://new.test/swagger');
    $inspector = app(WafInspector::class);

    expect($inspector->inspect($request)->ruleIds())->toContain('PATH-PROBE');
    $before = count(Route::getRoutes()->getRoutes());
    Route::get('/swagger', fn () => 'new')->domain('new.test');

    expect(count(Route::getRoutes()->getRoutes()))->toBe($before)
        ->and($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE');
});

it('enumerates a cached route collection only once across probe requests', function () {
    config()->set('waf.probe_paths.enabled', true);
    Route::post('/swagger', fn () => 'docs');
    $compiled = Route::getRoutes()->compile();
    $collection = new class($compiled['compiled'], $compiled['attributes']) extends CompiledRouteCollection
    {
        public int $enumerations = 0;

        public function getRoutes()
        {
            $this->enumerations++;

            return parent::getRoutes();
        }
    };
    $router = app(Router::class);
    $collection->setRouter($router)->setContainer(app());
    (new ReflectionProperty($router, 'routes'))->setValue($router, $collection);
    app()->instance('routes', $collection);

    $inspector = app(WafInspector::class);
    $request = Request::create('/swagger');
    expect($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE');
    expect($inspector->inspect(Request::create('/cpanel'))->ruleIds())->toContain('PATH-PROBE')
        ->and($collection->enumerations)->toBe(1);
});

it('sees runtime routes added to a cached collection without rebuilding the compiled index', function () {
    config()->set('waf.probe_paths.enabled', true);
    $compiled = Route::getRoutes()->compile();
    $collection = new class($compiled['compiled'], $compiled['attributes']) extends CompiledRouteCollection
    {
        public int $enumerations = 0;

        public function getRoutes()
        {
            $this->enumerations++;

            return parent::getRoutes();
        }
    };
    $router = app(Router::class);
    $collection->setRouter($router)->setContainer(app());
    (new ReflectionProperty($router, 'routes'))->setValue($router, $collection);
    app()->instance('routes', $collection);

    $inspector = app(WafInspector::class);
    $request = Request::create('/swagger/123');
    expect($inspector->inspect($request)->ruleIds())->toContain('PATH-PROBE');

    Route::post('/swagger/{id}', fn () => 'docs')->where('id', '[a-z]+');
    expect($inspector->inspect($request)->ruleIds())->toContain('PATH-PROBE');

    Route::post('/swagger/{id}', fn () => 'docs')->where('id', '[0-9]+');
    expect($inspector->inspect($request)->ruleIds())->not->toContain('PATH-PROBE')
        ->and($collection->enumerations)->toBe(1);
});
