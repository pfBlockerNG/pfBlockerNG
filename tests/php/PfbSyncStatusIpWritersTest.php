<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 2 — IP-side sync-status writer/clearer pair for the pfctl apply.
 *
 * Wires the IP pfctl apply failure class to the Phase-1 ledger, alongside its
 * EXISTING logging (never replacing it), tested via pfb_pfctl_table_op() itself
 * using the SAME mock-pfctl-binary seam PfctlTableOpTest already established
 * ($pfctl_bin injection).
 *
 * Function under test:
 *   pfb_pfctl_table_op(...) -- ledger open/close added alongside its existing
 *                              pfb_logger(..., 2) call (byte-identical, untouched).
 */
#[CoversFunction('pfb_pfctl_table_op')]
final class PfbSyncStatusIpWritersTest extends TestCase
{
	private string $dir;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	/** @var string[] temp files (mock pfctl scripts, log fixtures) to remove in tearDown */
	private array $tmpfiles = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_sync_status_ip_writers_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		// pfb_pfctl_table_op() reads $pfb['dbdir']/['log']/['errlog'] via `global $pfb;`
		// -- not injectable params -- so they must point at THIS test's private sandbox,
		// never the shared cross-test bootstrap tmp dir (order-independence).
		foreach (['dbdir', 'log', 'errlog'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		$GLOBALS['pfb']['dbdir'] = $this->dir;
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		$this->saved = [];

		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];

		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	/** Write an executable POSIX-sh mock pfctl that exits $rc, emitting $stderr on fd 2.
	 *  Same seam PfctlTableOpTest::mock_pfctl() establishes ($pfctl_bin injection) --
	 *  reimplemented here because PHPUnit test classes cannot share a private method. */
	private function mockPfctl(int $rc, string $stderr): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_pfctl_mock_');
		$this->assertNotFalse($path, 'could not create temp mock pfctl script');
		$this->tmpfiles[] = $path;
		$stderr_esc = str_replace("'", "'\\''", $stderr);
		$this->assertNotFalse(
			file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' '{$stderr_esc}' >&2\nexit {$rc}\n"),
			"could not write mock pfctl script {$path}"
		);
		$this->assertTrue(chmod($path, 0755), "could not chmod mock pfctl script {$path} executable");
		return $path;
	}

	// -----------------------------------------------------------------------
	// IP pfctl apply fail/success (pfb_pfctl_table_op)
	// -----------------------------------------------------------------------

	public function testPfctlApplyFailureOpensEntry(): void
	{
		$pfctl_bin = $this->mockPfctl(1, 'pfctl: EINVAL');

		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $pfctl_bin);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'an attributed pfctl failure must open an apply entry');
		$this->assertSame('pfB_Test_v4', $open[0]['item']);
		$this->assertSame('apply', $open[0]['stage']);
		$this->assertStringContainsString('op=replace', $open[0]['message']);
	}

	public function testPfctlApplySuccessClosesEntry(): void
	{
		$fail_bin = $this->mockPfctl(1, 'pfctl: EINVAL');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $fail_bin);
		// Before-state: genuinely open first.
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		$ok_bin = $this->mockPfctl(0, '');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $ok_bin);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'ip'),
			'a subsequent clean pfctl apply for the SAME table must close the entry');
	}

	public function testPfctlApplyFailureTwiceRefreshesWithoutDuplicating(): void
	{
		$bin1 = $this->mockPfctl(1, 'pfctl: EINVAL');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $bin1);

		$bin2 = $this->mockPfctl(2, 'pfctl: permission denied');
		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $bin2);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, 'two consecutive pfctl failures on the SAME table must refresh, never duplicate');
		$this->assertStringContainsString('permission denied', $open[0]['message'], 'message must be the LATEST refresh');
	}

	public function testPfctlApplyFailureLoggingLevelUnchanged(): void
	{
		// Kill-gate rehearsal: the EXISTING pfb_logger(..., 2) call this phase adds
		// the ledger write alongside must remain untouched (issue #980 / PR #987).
		$log    = tempnam(sys_get_temp_dir(), 'pfb_log_');
		$errlog = tempnam(sys_get_temp_dir(), 'pfb_errlog_');
		$this->tmpfiles[] = $log;
		$this->tmpfiles[] = $errlog;
		$GLOBALS['pfb']['log']    = $log;
		$GLOBALS['pfb']['errlog'] = $errlog;
		$pfctl_bin = $this->mockPfctl(1, 'pfctl: EINVAL');

		pfb_pfctl_table_op('pfB_Test_v4', 'replace', '', $pfctl_bin);

		$this->assertStringContainsString('op=replace', (string) file_get_contents($errlog),
			'the pfctl failure must still reach error.log at level 2, unchanged by this phase');
	}
}
