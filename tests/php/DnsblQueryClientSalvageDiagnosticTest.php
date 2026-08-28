<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Source pin: forcing the 30-second reaper would turn this diagnostic test into another wait. */
final class DnsblQueryClientSalvageDiagnosticTest extends TestCase
{
	public function testConcurrentReplyConsumptionExpiryNamesSalvageFailure(): void
	{
		$source = file_get_contents(__DIR__ . '/DnsblQueryClientTest.php');
		$this->assertNotFalse($source, 'DnsblQueryClientTest.php must be readable');

		$start = strpos($source, 'public function testConcurrentCallersAreSerializedAndReceiveOwnReplies()');
		$this->assertNotFalse($start, 'concurrent-callers test must exist');

		$this->assertStringContainsString(
			"throw new RuntimeException('salvage cap expired / stuck or environment: waiting for first caller to consume its reply; reply file still exists');",
			$source,
			'concurrent reply-consumption salvage expiry must be distinguishable from a behavioural failure'
		);
	}
}
