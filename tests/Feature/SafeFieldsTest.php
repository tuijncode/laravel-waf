<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Tuijncode\LaravelWaf\Facades\Waf;

it('does not flag a payload carried in a safe field', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->post('/', [
        'content' => '<script>alert(1)</script>',
        'title' => 'a normal title',
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('still flags a payload in a non-safe field alongside a safe one', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->post('/', [
        'content' => 'harmless rich text',
        'title' => '<script>alert(1)</script>',
    ])->assertOk();

    $log = DB::table('waf_logs')->first();

    expect($log)->not->toBeNull()
        ->and($log->category)->toBe('xss');
});

it('excludes a nested field by dot-notation', function () {
    config()->set('waf.safe_fields', ['post.body']);

    $this->post('/', [
        'post' => ['body' => '<script>alert(1)</script>', 'title' => 'ok'],
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('excludes wildcard field paths', function () {
    config()->set('waf.safe_fields', ['blocks.*.html']);

    $this->post('/', [
        'blocks' => [
            ['html' => '<script>alert(1)</script>'],
            ['html' => '<iframe src=x>'],
        ],
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('excludes everything nested beneath a bare field name', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->post('/', [
        'content' => ['nested' => '<script>alert(1)</script>'],
    ])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('excludes a safe field carried in the query string', function () {
    config()->set('waf.safe_fields', ['q']);

    $this->get('/?q='.rawurlencode('<script>alert(1)</script>'))->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(0);
});

it('inspects duplicate non-safe query values without scanning safe fields', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->get('/?content='.rawurlencode('<script>safe</script>')
        .'&q='.rawurlencode('<script>alert(1)</script>').'&q=ok')->assertOk();

    expect(DB::table('waf_logs')->value('rule_ids'))->toContain('941100');

    $safeRequest = Request::create('/?content='.rawurlencode('<script>safe</script>'));
    expect(Waf::inspect($safeRequest)->ruleIds())->not->toContain('941100');
});

it('honours the actual index of an unnumbered query array element', function () {
    config()->set('waf.safe_fields', ['q.1']);
    $request = Request::create('/?q[]=plain&q[]='.rawurlencode('<script>excluded</script>'));

    expect(Waf::inspect($request)->ruleIds())->not->toContain('941100');

    config()->set('waf.safe_fields', ['q.0']);
    expect(Waf::inspect($request)->ruleIds())->toContain('941100');
});

it('keeps query-syntax rules active for non-safe fields', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->get('/?content=ok&file=http%3A%2F%2Fevil.test')->assertOk();

    expect(DB::table('waf_logs')->value('rule_ids'))->toContain('931100');
});

it('keeps form-syntax rules active for non-safe body fields', function () {
    config()->set('waf.safe_fields', ['content']);

    $this->post('/', ['content' => 'ok', 'file' => 'http://evil.test'])->assertOk();

    expect(DB::table('waf_logs')->value('rule_ids'))->toContain('931100');
});

it('still scans the raw body when no safe fields are configured', function () {
    // Baseline: the same payload without safe_fields is caught.
    $this->post('/', ['content' => '<script>alert(1)</script>'])->assertOk();

    expect(DB::table('waf_logs')->count())->toBe(1);
});

it('honours safe fields in a directly constructed JSON request', function () {
    config()->set('waf.safe_fields', ['content']);
    $server = ['CONTENT_TYPE' => 'application/json', 'HTTP_USER_AGENT' => 'Mozilla/5.0'];
    $safe = Request::create('/', 'POST', [], [], [], $server, json_encode([
        'content' => '<script>alert(1)</script>', 'title' => 'plain',
    ]));
    $unsafe = Request::create('/', 'POST', [], [], [], $server, json_encode([
        'content' => 'plain', 'title' => '<script>alert(1)</script>',
    ]));

    expect(Waf::inspect($safe)->ruleIds())->not->toContain('941100')
        ->and(Waf::inspect($unsafe)->ruleIds())->toContain('941100');
});

it('inspects non-safe JSON field names with empty array values', function () {
    config()->set('waf.safe_fields', ['content']);
    $request = Request::create('/', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode([
        'content' => 'safe',
        '<script>alert(1)</script>' => [],
    ]));

    expect(Waf::inspect($request)->ruleIds())->toContain('941100');
});
