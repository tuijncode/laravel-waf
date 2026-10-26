<?php

namespace Tuijncode\LaravelWaf\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Tuijncode\LaravelWaf\Services\InspectionResult;

/**
 * Fired whenever the WAF logs a threat.
 *
 * Listen for this event to implement your own response — block the request,
 * ban the IP, notify a channel, feed a SIEM, etc.
 *
 * Example:
 *
 *   Event::listen(ThreatDetected::class, function (ThreatDetected $event) {
 *       if ($event->result->confidenceScore() >= 80) {
 *           Firewall::ban($event->ipAddress);
 *       }
 *   });
 */
class ThreatDetected
{
    use Dispatchable;

    /**
     * @param  array<string, mixed>  $log  the row written to the waf_logs table
     * @param  ?string  $eventId  UUID identifying this finding in the log table,
     *                            available even when the insert is queued
     */
    public function __construct(
        public readonly array $log,
        public readonly InspectionResult $result,
        public readonly ?string $ipAddress = null,
        public readonly ?string $eventId = null,
    ) {}

    /** Queued listeners keep the verdict but never persist free-text evidence. */
    public function __serialize(): array
    {
        $log = $this->log;
        foreach (['url', 'payload', 'user_agent'] as $field) {
            if (array_key_exists($field, $log)) {
                $log[$field] = '[REDACTED]';
            }
        }

        return [
            'log' => $log,
            'result' => $this->result->withoutMatchedValues(),
            'ipAddress' => $this->ipAddress,
            'eventId' => $this->eventId,
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->log = $data['log'];
        $this->result = $data['result'];
        $this->ipAddress = $data['ipAddress'];
        $this->eventId = $data['eventId'];
    }
}
