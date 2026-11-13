<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/** Issue #3945: cleanup precedes actions under their lock; a throwing cleanup write must release it too. */
final class GroupsCleanupExceptionTest extends TestCase
{
	public function testAThrowingCleanupWriteReleasesTheActionLockBeforeTheActionRuns(): void
	{
		$dir = sys_get_temp_dir() . '/pfb_cleanup_exception_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($dir, 0700));
		$resultFile = "{$dir}/result.json";
		try {
			$case = ['emptyFirstRow' => TRUE, 'post' => ['act' => 'del', 'type' => 'dnsbl', 'rowid' => '1'], 'ledger' => TRUE];
			$run = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/GroupsPageWorker.php', 'list', 'write_throws', $resultFile, json_encode($case, JSON_THROW_ON_ERROR)], 60.0);
			$this->assertFileExists($resultFile, "worker did not report (exit {$run['exit']}): {$run['stderr']}");
			$result = json_decode((string) file_get_contents($resultFile), TRUE, 512, JSON_THROW_ON_ERROR);

			$this->assertSame(['try_lock', 'read', 'write', 'unlock'], array_column($result['events'], 0), 'the throwing cleanup must release the lock even though an action would otherwise keep it');
			$this->assertFalse($result['lockHeld']);
			$this->assertSame($result['before'], $result['disk'], 'the cleanup and action wrote nothing');
			$this->assertSame(['DNSBL_Bravo/download'], $result['ledger'], 'the action did not close the alias ledger');
		} finally {
			rmdir_recursive($dir);
		}
	}
}
