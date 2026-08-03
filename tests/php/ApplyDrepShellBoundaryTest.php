<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** The empty-capable _rep drep token must remain argv[4] at the shell boundary. */
final class ApplyDrepShellBoundaryTest extends TestCase
{
	public function testDrepTokenIsShellQuotedAtTheOnlyEmptyCapableCrossing(): void
	{
		$source = file_get_contents(
			__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		$this->assertIsString($source);
		$this->assertStringContainsString(
			'escapeshellarg($pfb_drep_token)',
			$source,
			'empty drep tokens need shell quoting so argv[4] stays present'
		);
	}
}
