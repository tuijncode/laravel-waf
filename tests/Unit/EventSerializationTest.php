<?php

use Illuminate\Events\CallQueuedListener;
use Illuminate\Http\Request;
use Tuijncode\LaravelWaf\Events\RequestBlocked;
use Tuijncode\LaravelWaf\Events\ThreatDetected;
use Tuijncode\LaravelWaf\Rules\SignatureMatch;
use Tuijncode\LaravelWaf\Services\InspectionResult;

function secretResult(string $secret): InspectionResult
{
    return new InspectionResult(matches: [new SignatureMatch(
        'SECRET', 'custom', 'Token', 'API token', 'critical', 'query', $secret,
    )]);
}

it('keeps secrets out of a queued ThreatDetected listener', function () {
    $secret = 'queue-only-secret-123';
    $event = new ThreatDetected([
        'url' => '/?token='.$secret,
        'payload' => $secret,
        'user_agent' => $secret,
        'event_id' => 'event-1',
    ], secretResult($secret), '192.0.2.1', 'event-1');
    $job = new CallQueuedListener('Listener', 'handle', [$event]);
    $serialized = serialize($job);

    expect($serialized)->not->toContain($secret)
        ->and($event->result->matches[0]->matched)->toBe($secret);

    $queued = unserialize($serialized)->data[0];
    expect($queued->log['url'])->toBe('[REDACTED]')
        ->and($queued->result->matches[0]->matched)->toBe('[REDACTED]')
        ->and($queued->eventId)->toBe('event-1');
});

it('keeps request data out of a queued RequestBlocked listener', function () {
    $secret = 'queue-only-secret-456';
    $request = Request::create('/secret/'.$secret.'?token='.$secret, 'POST', ['password' => $secret]);
    $request->server->set('REMOTE_ADDR', '192.0.2.2');
    $event = new RequestBlocked($request, secretResult($secret));
    $job = new CallQueuedListener('Listener', 'handle', [$event]);
    $serialized = serialize($job);

    expect($serialized)->not->toContain($secret)
        ->and($event->request->request->get('password'))->toBe($secret);

    $queued = unserialize($serialized)->data[0];
    expect($queued->request->getPathInfo())->toBe('/[REDACTED]')
        ->and($queued->request->ip())->toBe('192.0.2.2')
        ->and($queued->result->matches[0]->matched)->toBe('[REDACTED]');
});
