<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

final class DnsblRefusedSaveTest extends TestCase
{
	public function testARefusedConfigWriteRedisplaysTheSubmittedFormWithoutMarkingPendingOrRedirecting(): void
	{
		$dir = sys_get_temp_dir() . '/pfb_dnsbl_refused_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$resultFile = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/DnsblSaveWorker.php', 'write_refused', $resultFile], 60.0);
			$this->assertFileExists($resultFile, "worker did not report (exit {$process['exit']}): {$process['stderr']}");
			$result = json_decode((string) file_get_contents($resultFile), TRUE, 512, JSON_THROW_ON_ERROR);
			$this->assertNotSame([], $result['inputErrors'], 'a refused write is a save error');
			$this->assertTrue($result['returned'], 'the page renders the errors, rather than exiting through its redirect');
			$this->assertSame('8082', $result['postedPort'], 'the form re-displays the submitted port');
			$this->assertSame('8081', $result['disk']['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_dnsport'],
				'config.xml retains the original port');
			$this->assertFalse($result['pendingMarked'], 'a refused save marks no pending changes');
			$this->assertFalse($result['lockHeld'], 'the lock is released');
		} finally {
			@unlink($resultFile);
			@rmdir($dir);
		}
	}
}
