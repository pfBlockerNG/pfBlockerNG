<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Source pin: the query responder's salvage expiry must be loud and parent-observed. */
final class DnsblLogEventQueryAttributionSalvageDiagnosticTest extends TestCase
{
	public function testResponderExpiryIsTypedTrackedAndNotDetached(): void
	{
		$source = file_get_contents(__DIR__ . '/DnsblLogEventQueryAttributionTest.php');
		$this->assertNotFalse($source, 'DnsblLogEventQueryAttributionTest.php must be readable');

		$this->assertStringContainsString(
			"throw new RuntimeException('salvage cap expired / stuck or environment: waiting for the query-channel request marker');",
			$source,
			'query-channel request-marker salvage expiry must be distinguishable from a behavioural failure'
		);
		$this->assertStringNotContainsString(
			'> /dev/null 2>&1 &',
			$source,
			'the responder must be tracked by the parent, not detached through a background shell'
		);
		$this->assertStringContainsString('$this->forkChild(', $source, 'the responder must be a tracked child');
		$this->assertStringContainsString('pcntl_waitpid', $source, 'the parent must observe and reap the responder');
	}
}
