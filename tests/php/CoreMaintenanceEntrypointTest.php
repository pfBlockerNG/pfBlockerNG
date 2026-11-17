<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

final class CoreMaintenanceEntrypointTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb maintenance \' ' . bin2hex(random_bytes(6));
		foreach (['db/pfblockerng', 'log/pfblockerng', 'tmp'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0755, TRUE));
		}
		file_put_contents("{$this->dir}/pending", 'pending apply');
		file_put_contents("{$this->dir}/log/pfblockerng/pfblockerng.log", "maintenance log must remain unchanged\n");
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	private function runVerb(string $verb, bool $enabled = TRUE): array
	{
		$result = "{$this->dir}/fd3";
		$stdin = "{$this->dir}/stdin";
		file_put_contents($stdin, '{"trigger":"manual","force":true}');
		$command = [PHP_BINARY, __DIR__ . '/bin/core_maintenance_entry.php', $verb, $this->dir, $enabled ? 'on' : ''];
		$process = proc_open($command, [0 => ['file', $stdin, 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'], 3 => ['file', $result, 'w']], $pipes);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);
		$run = pfb_test_finish_process([$process, $pipes, implode(' ', $command)], 30.0);
		$this->assertSame('', file_get_contents($result), 'maintenance never writes Update outcomes on fd 3');
		$this->assertFileExists("{$this->dir}/warnings.json", 'child must publish its warning diagnostics even on guarded exits');
		$run['warnings'] = json_decode((string) file_get_contents("{$this->dir}/warnings.json"), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertIsArray($run['warnings']);
		return $run;
	}

	public static function warningCanaryVerbs(): array
	{
		return ['maintenance CLI' => ['core_maintenance'], 'manual tick' => ['direct-tick']];
	}

	#[DataProvider('warningCanaryVerbs')]
	public function testUnsuppressedBuiltinWarningIsRejectedByRealTickAssertions(string $verb): void
	{
		file_put_contents("{$this->dir}/warning-canary", 'unsuppressed');
		$run = $this->runVerb($verb);
		$this->assertSame("before fopen\n", file_get_contents("{$this->dir}/warning-canary-reached"));
		$this->assertFileDoesNotExist("{$this->dir}/warning-canary-missing");
		$rejected = FALSE;
		try {
			$this->assertRealTickDuties($run);
		} catch (AssertionFailedError $error) {
			$rejected = TRUE;
		}
		$this->assertTrue($rejected, 'the real child/parent tick path must reject an unsuppressed builtin E_WARNING, including warning plus exit 0');
		$this->assertStringContainsString('warning-canary-missing', $run['stdout'] . $run['stderr'], 'rejection must expose the actual builtin warning, not an unrelated child failure');
	}

	#[DataProvider('warningCanaryVerbs')]
	public function testSuppressedBuiltinWarningRemainsSilentAndRunsRealTick(string $verb): void
	{
		file_put_contents("{$this->dir}/warning-canary", 'suppressed');
		$run = $this->runVerb($verb);
		$this->assertSame("before fopen\n", file_get_contents("{$this->dir}/warning-canary-reached"));
		$this->assertFileDoesNotExist("{$this->dir}/warning-canary-missing");
		$this->assertRealTickDuties($run);
		$this->assertStringNotContainsString('warning-canary-missing', $run['stdout'] . $run['stderr'], '@-suppressed builtin warning stays silent');
	}

	public static function sentinelContents(): array
	{
		return ['empty' => [''], 'off is still present' => ['off'], 'binary' => ["\x00\xff"], 'oversized' => [str_repeat('x', 65536)]];
	}

	/** Core decides from `maintenance.scheduledWorkDisabled`; a verb Core did run does its work, whatever the sentinel holds. */
	#[DataProvider('sentinelContents')]
	public function testTheVerbRunsTheTickWithTheSentinelPresent(string $content): void
	{
		file_put_contents("{$this->dir}/db/pfblockerng/.pfb_cron_disable", $content);
		$this->assertRealTickDuties($this->runVerb('core_maintenance'));
	}

	public static function disabledStates(): array
	{
		return [
			'package disabled' => [FALSE, FALSE],
			'package disabled, sentinel present' => [FALSE, TRUE],
			'package enabled, sentinel present' => [TRUE, TRUE],
		];
	}

	/** Core does not call the verb while the package is off or the sentinel is present; if something does, it runs the tick and exits 0. */
	#[DataProvider('disabledStates')]
	public function testTheVerbRunsTheTickAndExitsZeroWhateverTheGatesSay(bool $enabled, bool $sentinel): void
	{
		if ($sentinel) {
			touch("{$this->dir}/db/pfblockerng/.pfb_cron_disable");
		}
		$this->assertRealTickDuties($this->runVerb('core_maintenance', $enabled));
	}

	public function testDirectTickRemainsLiveWhenPackageIsDisabled(): void
	{
		$this->assertRealTickDuties($this->runVerb('direct-tick', FALSE));
	}

	public function testMaintenanceStillAttemptsAFailedFeedRetry(): void
	{
		unlink("{$this->dir}/pending");
		mkdir("{$this->dir}/db/pfblockerng/deny");
		touch("{$this->dir}/db/pfblockerng/deny/maintenance_v4.fail");
		$run = $this->runVerb('core_maintenance');
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertStringContainsString('did not start the retry Update',
			(string) file_get_contents("{$this->dir}/notices.json"), 'failed-feed fixture really reaches retry admission');
		$this->assertFileExists("{$this->dir}/db/pfblockerng/deny/maintenance_v4.fail", 'failed retry admission retains work');
		$this->assertFileExists("{$this->dir}/settings-failed");
		$this->assertDutyLocksTaken();
	}

	/** The tick opened the bounded lock of each of its two duties: SafeSearch refresh and apply reconciliation both ran. */
	private function assertDutyLocksTaken(): void
	{
		foreach (['pfb_ss_refresh.lock', 'pfb_apply_reconcile.lock'] as $lock) {
			$this->assertFileExists("{$this->dir}/db/pfblockerng/{$lock}", "real tick reached {$lock}");
		}
	}

	private function assertRealTickDuties(array $run): void
	{
		$this->assertSame([], $run['warnings'], 'real tick must emit no unsuppressed warnings, regardless of child exit status: ' . json_encode($run['warnings']));
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertFileExists("{$this->dir}/initialized");
		$this->assertFileExists("{$this->dir}/settings-failed", 'the real tick attempted its Core settings notice');
		$this->assertDutyLocksTaken();
		$this->assertFileDoesNotExist("{$this->dir}/db/pfblockerng/pfb_due_ledger.json", 'the tick keeps no SafeSearch or reconciliation ledger entry');
		$notices = (string) file_get_contents("{$this->dir}/notices.json");
		$this->assertStringContainsString('did not start the apply Update', $notices, 'tick-shaped fixture has a real pending apply');
		$this->assertSame('pending apply', file_get_contents("{$this->dir}/pending"), 'failed admission retains pending work');
	}

	public function testAbsentSentinelRunsTheExistingTickWithNoStdinRequest(): void
	{
		$this->assertRealTickDuties($this->runVerb('core_maintenance'));
	}

	public function testDirectoryIsNotASentinel(): void
	{
		mkdir("{$this->dir}/db/pfblockerng/.pfb_cron_disable");
		$this->assertRealTickDuties($this->runVerb('core_maintenance'));
	}

	public function testDirectTickRemainsLiveWithTheSentinelPresent(): void
	{
		touch("{$this->dir}/db/pfblockerng/.pfb_cron_disable");
		$this->assertRealTickDuties($this->runVerb('direct-tick'));
	}

	public function testWrongVerbDoesNotRunMaintenance(): void
	{
		$run = $this->runVerb('core_maintenance_wrong');
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertFileDoesNotExist("{$this->dir}/settings-failed");
		$this->assertFileDoesNotExist("{$this->dir}/db/pfblockerng/pfb_due_ledger.json");
	}

	public function testWrapperExecsOnlyTheProductionMaintenanceVerb(): void
	{
		$path = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfb_core_maintenance.sh';
		$this->assertFileExists($path);
		$this->assertTrue(is_executable($path), 'Core must be able to exec the installed wrapper');
		$lines = file($path, FILE_IGNORE_NEW_LINES);
		$this->assertSame('#!/bin/sh', $lines[0]);
		$this->assertSame('exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_maintenance', $lines[2]);
		$this->assertCount(3, $lines, 'no stdin parser, fd3 protocol or second duty implementation');
	}
}
