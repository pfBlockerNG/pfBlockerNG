<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #973: during a live run (empty($pfb['hook_lifecycle'])), pfb_run_hooks() redirects a
 * hook's stdout/stderr to pfb_run_log_target() -- $pfb['runlog'] while a run is active -- so the
 * Update tab shows it live. But nothing ever copied that output into $pfb['log'], breaking ADR-12's
 * "stdout/stderr captured to the pfBlockerNG log" promise for the persisted Logs tab.
 *
 * pfb_persist_hook_output() closes that gap: it reads back the delta the hook appended to the
 * runlog (offset..EOF, same shape as pfb_mirror_hook_output()) and appends it to $pfb['log']. A
 * plain file read/append, never a pipe/tee -- reintroducing a pipe here would reopen #662 (a
 * daemon the hook spawns inherits the fd and would hang exec() waiting on it).
 *
 * Branch coverage: real delta copied, no-new-bytes silent hook, self-copy guard ($logfile IS
 * $pfb['log'], i.e. outside a run), and the empty-path guard.
 *
 * No hostile-input matrix: this function only ever reads a byte range off a local file it is
 * called with from pfb_run_hooks() -- no external/attacker-controlled string parsing, no regex,
 * no shell metacharacters, no encoding to defend against.
 */
#[CoversFunction('pfb_persist_hook_output')]
final class PfbHookOutputPersistTest extends TestCase
{
	private string $runlog = '';
	private string $origLog = '';

	protected function setUp(): void
	{
		global $pfb;
		$this->runlog = (string) tempnam(sys_get_temp_dir(), 'pfb_hook_persist_run_');
		$this->origLog = $pfb['log'];
		$pfb['log'] = (string) tempnam(sys_get_temp_dir(), 'pfb_hook_persist_log_');
	}

	protected function tearDown(): void
	{
		global $pfb;
		if ($this->runlog !== '') {
			@unlink($this->runlog);
		}
		if ($pfb['log'] !== '') {
			@unlink($pfb['log']);
		}
		$pfb['log'] = $this->origLog;
	}

	/** Write the "framing marker" already there before the hook runs, then return the pre-exec offset. */
	private function seedAndOffset(string $file, string $preamble): int
	{
		@file_put_contents($file, $preamble);
		clearstatcache(TRUE, $file);
		return (int) filesize($file);
	}

	public function testCopiesOnlyTheAppendedDeltaFromRunlogIntoTheCumulativeLog(): void
	{
		global $pfb;
		// Given the runlog already carries a pre-existing header (offset) before the hook runs...
		$offset = $this->seedAndOffset($this->runlog, "[ pfB Hook ] post haproxy (hook_post_haproxy.sh)\n");
		@file_put_contents($this->runlog, "Firing up HAProxy ACL update hook\nNo changes detected. Resuming...\n", FILE_APPEND);
		@file_put_contents($pfb['log'], "prior cumulative-log content\n");

		pfb_persist_hook_output($this->runlog, $offset);

		$logged = (string) @file_get_contents($pfb['log']);
		$this->assertStringContainsString(
			"Firing up HAProxy ACL update hook\nNo changes detected. Resuming...\n",
			$logged,
			'the exact bytes the hook appended past the offset must land in pfblockerng.log'
		);
		$this->assertStringNotContainsString(
			'[ pfB Hook ] post haproxy',
			$logged,
			'the pre-offset header must NOT be duplicated -- only the delta past the offset copies'
		);
		$this->assertStringContainsString('prior cumulative-log content', $logged, 'must APPEND, not overwrite');
	}

	public function testSilentHookWithNoNewBytesLeavesTheCumulativeLogUnchanged(): void
	{
		global $pfb;
		$offset = $this->seedAndOffset($this->runlog, "header only, hook wrote nothing new\n");
		@file_put_contents($pfb['log'], 'unchanged baseline');

		pfb_persist_hook_output($this->runlog, $offset);

		$this->assertSame(
			'unchanged baseline',
			(string) @file_get_contents($pfb['log']),
			'offset === EOF must be a true no-op, not even an empty append'
		);
	}

	public function testSelfCopyGuardSkipsWhenLogfileIsAlreadyTheCumulativeLog(): void
	{
		global $pfb;
		// Outside a run, pfb_run_log_target() already returns $pfb['log'] itself. Even though
		// $offset is behind the current EOF, copying the file onto itself must never happen.
		@file_put_contents($pfb['log'], "already-persisted line one\nalready-persisted line two\n");
		$offset = 0;

		pfb_persist_hook_output($pfb['log'], $offset);

		$this->assertSame(
			"already-persisted line one\nalready-persisted line two\n",
			(string) @file_get_contents($pfb['log']),
			'logfile === $pfb[log] must no-op -- else the tail would duplicate into itself'
		);
	}

	public function testEmptyLogPathIsANoOp(): void
	{
		global $pfb;
		@file_put_contents($pfb['log'], 'baseline');

		pfb_persist_hook_output('', 0);

		$this->assertSame('baseline', (string) @file_get_contents($pfb['log']));
	}
}
