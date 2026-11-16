<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class NativeScriptOutputCapCleanupTest extends TestCase
{
	public function testLocalCleanupProbeKeepsAnAmbiguousUpdateTreeUnsafe(): void
	{
		$fixture = __DIR__ . '/../smoke/fixtures/native_script_output_cap.php';
		exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($fixture) . ' cleanup-probe 2>&1', $output, $status);

		$this->assertSame(0, $status, implode("\n", $output));
		$this->assertSame(['LOCAL_UPDATE_CLEANUP_PROBE_PASS scenarios=4'], $output);
	}
}
