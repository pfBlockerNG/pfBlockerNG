<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_live_punch_run() -- issue #1467/#1470 (CWE-362): the Alerts "+" /
 * Unlock live punch's add-first/delete-last sequence
 * (pfb_live_punch_apply()) could interleave with a concurrent ADR-40
 * replace -- the replace wipes our adds mid-punch (restoring the canonical
 * set), then our delete opens the WHOLE containing CIDR until the next
 * reload. This orchestrator serializes the snapshot-plan-apply sequence
 * inside the existing feed-pass lock (pfblockerng.inc's
 * pfb_feed_pass_acquire()/_release()) so a concurrent feed pass can never
 * observe a half-punched table.
 *
 * Brand-new code (CLAUDE.md Test coverage #1 exception): pfb_live_punch_run()
 * did not exist before this change -- no red run against the void; every
 * test below asserts real behaviour against the finished implementation.
 */
#[CoversFunction('pfb_live_punch_run')]
final class LivePunchRunTest extends TestCase
{
	private string $tmp;
	private string $dbdir;
	private string $aliasdir;
	private string $shim;
	private string $logPath;
	private string $rulesPath;
	private string $showRulePath;
	private string $table = 'pfB_Test_v4';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];

	/** Raw fds opened directly by a test (bypassing pfb_feed_pass_acquire()) -- closed in tearDown. */
	private array $rawFps = [];

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp      = sys_get_temp_dir() . '/pfb_live_punch_run_' . getmypid() . '_' . bin2hex(random_bytes(6));
		$this->dbdir    = "{$this->tmp}/db";
		$this->aliasdir = "{$this->tmp}/alias";
		mkdir($this->dbdir, 0777, TRUE);
		mkdir($this->aliasdir, 0777, TRUE);

		$this->logPath      = "{$this->tmp}/calls.log";
		$this->rulesPath    = "{$this->tmp}/rules.tsv";
		$this->showRulePath = "{$this->tmp}/show_rule.txt";
		putenv("PFB_TEST_LOG={$this->logPath}");
		putenv("PFB_TEST_RULES={$this->rulesPath}");
		putenv("PFB_TEST_SHOW_RULE={$this->showRulePath}");
		$this->shim = $this->writeShim();

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'  => $this->dbdir,
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
		]);
	}

	protected function tearDown(): void
	{
		foreach ($this->rawFps as $fp) {
			if (is_resource($fp)) {
				@flock($fp, LOCK_UN);
				@fclose($fp);
			}
		}
		$this->rawFps = [];

		// Never leave this process holding the lock across tests.
		unset($GLOBALS['pfb_feed_pass_lock']);

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}

		putenv('PFB_TEST_LOG');
		putenv('PFB_TEST_RULES');
		putenv('PFB_TEST_SHOW_RULE');
		rmdir_recursive($this->tmp);
	}

	private function lockPath(): string
	{
		return "{$this->dbdir}/pfb_feed_pass.lock";
	}

	/** Script the '-T show' call: $rc plus the raw stdout lines it prints (the table's membership). */
	private function scriptShow(int $rc, array $lines = []): void
	{
		file_put_contents($this->showRulePath, $rc . "\n" . implode("\n", $lines) . ($lines === [] ? '' : "\n"));
	}

	/** Script a specific '-T add|delete' op+entry pair to fail, extending AlertsLivePunchApplyTest's shim pattern. */
	private function scriptFailure(string $op, string $entry, int $rc, string $err): void
	{
		file_put_contents($this->rulesPath, "{$op}|{$entry}|{$rc}|{$err}\n", FILE_APPEND);
	}

	private function readLog(): array
	{
		$content = trim((string) @file_get_contents($this->logPath));
		return $content === '' ? [] : explode("\n", $content);
	}

	/**
	 * pfctl shim: logs every call as "<op>|<table>|<entry>", answers '-T show'
	 * from $PFB_TEST_SHOW_RULE (rc on line 1, membership lines after -- an
	 * empty table when the file is absent), and answers '-T add'/'-T delete'
	 * successfully unless $PFB_TEST_RULES scripts that exact op+entry to fail
	 * (same shape as AlertsLivePunchApplyTest's shim).
	 */
	private function writeShim(): string
	{
		$shim = "{$this->tmp}/pfctl_shim.sh";
		file_put_contents($shim, <<<'SH'
#!/bin/sh
table=""
op=""
entry=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		-t) table="$2"; shift 2 ;;
		-T) op="$2"; shift 2 ;;
		*) entry="$1"; shift ;;
	esac
done
printf '%s|%s|%s\n' "$op" "$table" "$entry" >> "$PFB_TEST_LOG"

if [ "$op" = "show" ]; then
	if [ -f "$PFB_TEST_SHOW_RULE" ]; then
		rc=$(head -n1 "$PFB_TEST_SHOW_RULE")
		tail -n +2 "$PFB_TEST_SHOW_RULE"
		exit "$rc"
	fi
	exit 0
fi

if [ -z "$entry" ]; then
	printf 'pfctl: no address specified\n' >&2
	exit 1
fi
if [ -f "$PFB_TEST_RULES" ]; then
	while IFS='|' read -r r_op r_entry r_rc r_err; do
		if [ "$r_op" = "$op" ] && [ "$r_entry" = "$entry" ]; then
			if [ -n "$r_err" ]; then
				printf '%s\n' "$r_err" >&2
			fi
			exit "$r_rc"
		fi
	done < "$PFB_TEST_RULES"
fi
if [ "$op" = "add" ]; then
	printf '1/1 addresses added.\n'
else
	printf '1/1 addresses deleted.\n'
fi
exit 0
SH
		);
		chmod($shim, 0755);
		return $shim;
	}

	// -------------------------------------------------------------------
	// 'not_blocked' -- an empty live table: no delete/add execs, no lock
	// left held.
	// -------------------------------------------------------------------

	public function testEmptyTableReturnsNotBlocked(): void
	{
		$result = pfb_live_punch_run($this->shim, $this->aliasdir, $this->dbdir, $this->table, '198.18.0.5');

		$this->assertSame(
			['status' => 'not_blocked', 'fail' => NULL, 'del_cnt' => 0, 'add_cnt' => 0],
			$result
		);
		$this->assertSame(['show|pfB_Test_v4|'], $this->readLog(), 'only the snapshot -T show must run -- no add/delete');
	}

	// -------------------------------------------------------------------
	// 'applied' -- a containing entry is punched, adds-before-deletes,
	// counts reflect the plan.
	// -------------------------------------------------------------------

	public function testContainingEntryReturnsAppliedWithCounts(): void
	{
		$this->scriptShow(0, ['203.0.113.0/24']);

		$result = pfb_live_punch_run($this->shim, $this->aliasdir, $this->dbdir, $this->table, '203.0.113.5');

		$this->assertSame('applied', $result['status']);
		$this->assertNull($result['fail']);
		$this->assertSame(1, $result['del_cnt'], 'one containing entry (the /24) is deleted');
		$this->assertSame(8, $result['add_cnt'], 'a /24 minus one host carves into 8 covering CIDRs (ADR-53 measured bound)');
	}

	// -------------------------------------------------------------------
	// 'failed' -- a scripted pfctl failure surfaces pfb_live_punch_apply()'s
	// fail string unchanged.
	// -------------------------------------------------------------------

	public function testApplyFailureReturnsFailedWithApplyFailString(): void
	{
		$this->scriptShow(0, ['203.0.113.0/24']);
		$this->scriptFailure('delete', '203.0.113.0/24', 1, 'pfctl: forced delete failure');

		$result = pfb_live_punch_run($this->shim, $this->aliasdir, $this->dbdir, $this->table, '203.0.113.5');

		$this->assertSame('failed', $result['status']);
		$this->assertSame('delete 203.0.113.0/24', $result['fail']);
		$this->assertSame(0, $result['del_cnt']);
		$this->assertSame(0, $result['add_cnt']);
	}

	// -------------------------------------------------------------------
	// F2 integration -- a snapshot capture failure (pfb_live_table_snapshot()
	// throwing \RuntimeException) is caught and reported as 'failed', never
	// an uncaught fatal, never misread as an empty/not-blocked table.
	// -------------------------------------------------------------------

	public function testSnapshotThrowIsCaughtAsFailedWithSnapshotPrefix(): void
	{
		$this->scriptShow(1, []); // -T show itself fails -> pfb_live_table_snapshot() throws

		$result = pfb_live_punch_run($this->shim, $this->aliasdir, $this->dbdir, $this->table, '203.0.113.5');

		$this->assertSame('failed', $result['status']);
		$this->assertNotNull($result['fail']);
		$this->assertStringStartsWith('snapshot: ', $result['fail'], "a snapshot-capture failure must be distinguishable from a plan/apply failure");
		$this->assertSame(0, $result['del_cnt']);
		$this->assertSame(0, $result['add_cnt']);
	}

	// -------------------------------------------------------------------
	// 'busy' -- another handle holds the feed-pass lock: no snapshot, no
	// execs at all.
	// -------------------------------------------------------------------

	public function testConcurrentFeedPassReturnsBusyWithZeroExecs(): void
	{
		$holder = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $holder;
		$this->assertTrue(flock($holder, LOCK_EX), 'test setup: failed to flock the holder fd');

		$result = pfb_live_punch_run($this->shim, $this->aliasdir, $this->dbdir, $this->table, '203.0.113.5');

		$this->assertSame(
			['status' => 'busy', 'fail' => NULL, 'del_cnt' => 0, 'add_cnt' => 0],
			$result
		);
		$this->assertSame([], $this->readLog(), 'busy must short-circuit before any pfctl exec -- not even the snapshot');

		// Holder undisturbed.
		$this->assertTrue(flock($holder, LOCK_EX | LOCK_NB),
			'the original holder must remain able to operate on its own lock afterwards');
	}

	// -------------------------------------------------------------------
	// $was_held reentrancy guard -- a nested call inside an already-held
	// lock must NOT release the outer caller's hold.
	// -------------------------------------------------------------------

	public function testReentrantCallDoesNotReleaseAnOuterHold(): void
	{
		$outerHandle = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $outerHandle;
		$this->assertTrue(flock($outerHandle, LOCK_EX), 'test setup: failed to flock the outer handle');
		$GLOBALS['pfb_feed_pass_lock'] = $outerHandle;

		$result = pfb_live_punch_run($this->shim, $this->aliasdir, $this->dbdir, $this->table, '198.18.0.5');

		$this->assertSame('not_blocked', $result['status'], 'test setup: an empty table is the simplest path through the lock scope');

		// A fresh probe fd must still find the lock held -- pfb_live_punch_run()
		// must not have released an outer caller's pre-existing hold.
		$probe = fopen($this->lockPath(), 'c');
		$this->rawFps[] = $probe;
		$this->assertFalse(flock($probe, LOCK_EX | LOCK_NB),
			'the outer hold must still be locked after a reentrant pfb_live_punch_run() call');
	}
}
