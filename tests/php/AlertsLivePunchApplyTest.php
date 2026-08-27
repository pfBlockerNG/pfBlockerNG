<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_live_punch_apply() -- issue #1470: the fail-closed executor for a
 * pfb_live_punch_plan() plan. The two ADR-53 live-punch callers
 * (pfblockerng_alerts.php addsuppress / unlock) used to run `-T delete` then
 * `-T add` with every exec() status ignored: a delete followed by a failed
 * add unblocked the WHOLE containing entry silently.
 *
 * This helper inverts the order -- every add runs first, every delete runs
 * last -- because every 'add' remainder is a covering-CIDR SUBSET of a still
 * -present containing entry (pfb_live_punch_plan()'s contract): adding it
 * first never changes live match behaviour, and no intermediate state after
 * that ever unblocks the host or a sibling.
 *
 * Not unit-drivable via the two POST handlers themselves (they sit behind
 * $_POST guards with header()+exit, verified this session -- AlertsPageLoader
 * only extracts page FUNCTIONS). So these tests target the helper seam via an
 * injectable pfctl shim (extends LiveTableSnapshotTest's writeShim() pattern
 * to log every argv line and to fail on scripted op+entry pairs). The
 * handler wiring itself (savemsg branches, store-write gating) is a JUSTIFIED
 * DEFERRAL -- carried by review + this file's helper coverage, with success/
 * empty-plan paths landing in the next step's Tier-B e2e.
 */
#[CoversFunction('pfb_live_punch_apply')]
final class AlertsLivePunchApplyTest extends TestCase
{
	private string $tmp;
	private string $shim;
	private string $logPath;
	private string $rulesPath;
	private string $table = 'pfB_Test_v4';

	protected function setUp(): void
	{
		global $pfb;

		$this->tmp       = sys_get_temp_dir() . '/pfb_live_punch_apply_' . getmypid() . '_' . bin2hex(random_bytes(6));
		mkdir($this->tmp, 0777, TRUE);
		$this->logPath   = "{$this->tmp}/calls.log";
		$this->rulesPath = "{$this->tmp}/rules.tsv";
		putenv("PFB_TEST_LOG={$this->logPath}");
		putenv("PFB_TEST_RULES={$this->rulesPath}");
		$this->shim = $this->writeShim();

		// pfb_live_punch_apply() calls pfb_logger() on failure (level 2, same as
		// pfb_pfctl_table_op()) -- seed the log dir the same way
		// AliasDeltaApplyTest/LiveLogStdoutTest do.
		@mkdir($pfb['logdir'], 0777, TRUE);
		@file_put_contents($pfb['log'], '');
		@file_put_contents($pfb['errlog'], '');
	}

	protected function tearDown(): void
	{
		putenv('PFB_TEST_LOG');
		putenv('PFB_TEST_RULES');
		rmdir_recursive($this->tmp);
	}

	/**
	 * Write an executable POSIX-sh pfctl shim: parses the fixed
	 * `-t <table> -T <op> <entry>` argv shape pfb_live_punch_apply() execs,
	 * appends one '|'-joined [op, table, entry] row per call to
	 * $PFB_TEST_LOG (the ordering oracle), and consults $PFB_TEST_RULES for
	 * a scripted [op, entry] -> [rc, stderr] failure (one '|'-joined rule
	 * per line). An empty entry always fails (mirrors real pfctl refusing an
	 * empty address) instead of the parser silently doing nothing.
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

	/** Script the shim to fail a specific op+entry call with $rc/$err. */
	private function scriptFailure(string $op, string $entry, int $rc, string $err): void
	{
		file_put_contents($this->rulesPath, "{$op}|{$entry}|{$rc}|{$err}\n", FILE_APPEND);
	}

	/** @return array<int,array{0:string,1:string,2:string}> [op, table, entry] rows, call order. */
	private function readLog(): array
	{
		$content = trim((string) @file_get_contents($this->logPath));
		if ($content === '') {
			return [];
		}
		$rows = [];
		foreach (explode("\n", $content) as $line) {
			$rows[] = explode('|', $line, 3);
		}
		return $rows;
	}

	/** @return string[] "<op> <entry>" per row -- compact assertion shape for ordering tests. */
	private function opEntryRows(array $rows): array
	{
		return array_map(static fn(array $r): string => "{$r[0]} {$r[2]}", $rows);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 1 -- ordering: all adds before any delete
	// -------------------------------------------------------------------

	public function testAllAddsExecuteBeforeAnyDelete(): void
	{
		$plan = [
			'add'    => ['198.18.0.1/32', '198.18.0.2/32', '198.18.0.3/32'],
			'delete' => ['198.18.0.0/30', '198.18.0.4/30'],
		];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertTrue($result['ok'], 'an all-success plan must report ok=TRUE');
		$this->assertNull($result['fail']);
		$this->assertSame(
			['add 198.18.0.1/32', 'add 198.18.0.2/32', 'add 198.18.0.3/32', 'delete 198.18.0.0/30', 'delete 198.18.0.4/30'],
			$this->opEntryRows($this->readLog()),
			'every add must execute before any delete -- fail-closed ordering'
		);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 2 -- argv fidelity (table + entry as single
	// escaped args), including one v6 entry row
	// -------------------------------------------------------------------

	public function testArgvFieldsReachPfctlAsSingleEscapedArgsIncludingV6(): void
	{
		$plan = ['add' => ['2001:db8::/65'], 'delete' => ['2001:db8::/64']];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertTrue($result['ok']);
		$this->assertSame(
			[
				['add', $this->table, '2001:db8::/65'],
				['delete', $this->table, '2001:db8::/64'],
			],
			$this->readLog(),
			'op, table, and entry must each reach pfctl as one literal field'
		);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 3 -- add fails mid-batch: rollback only what
	// THIS call already added, no further adds, no plan deletes
	// -------------------------------------------------------------------

	public function testAddFailureRollsBackOnlyPreviouslyAddedEntries(): void
	{
		$this->scriptFailure('add', '198.18.0.2/32', 1, 'pfctl: forced failure for R2');
		$plan = [
			'add'    => ['198.18.0.1/32', '198.18.0.2/32', '198.18.0.3/32'],
			'delete' => ['198.18.0.0/24'],
		];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertFalse($result['ok']);
		$this->assertSame('add 198.18.0.2/32', $result['fail']);
		$this->assertSame(
			['add 198.18.0.1/32', 'add 198.18.0.2/32', 'delete 198.18.0.1/32'],
			$this->opEntryRows($this->readLog()),
			'only the already-added R1 is rolled back -- R3 is never attempted, the plan deletes never run'
		);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 4 -- rollback delete itself fails: swallowed,
	// no exception, no further ops after the rollback attempt
	// -------------------------------------------------------------------

	public function testRollbackDeleteFailureIsSwallowedWithNoFurtherOps(): void
	{
		$this->scriptFailure('add', '198.18.0.2/32', 1, 'pfctl: forced add failure');
		$this->scriptFailure('delete', '198.18.0.1/32', 1, 'pfctl: forced rollback failure');
		$plan = ['add' => ['198.18.0.1/32', '198.18.0.2/32'], 'delete' => ['198.18.0.0/24']];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertFalse($result['ok']);
		$this->assertSame('add 198.18.0.2/32', $result['fail']);
		$this->assertSame(
			['add 198.18.0.1/32', 'add 198.18.0.2/32', 'delete 198.18.0.1/32'],
			$this->opEntryRows($this->readLog()),
			'the rollback delete is attempted exactly once; its own failure is ignored -- no crash, no further ops'
		);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 5 -- delete fails: stop at first failure, no
	// further deletes, no rollback
	// -------------------------------------------------------------------

	public function testDeleteFailureStopsBeforeRemainingDeletes(): void
	{
		$this->scriptFailure('delete', '198.18.0.0/24', 1, 'pfctl: forced delete failure');
		$plan = ['add' => ['198.18.0.1/32'], 'delete' => ['198.18.0.0/24', '198.19.0.0/24']];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertFalse($result['ok']);
		$this->assertSame('delete 198.18.0.0/24', $result['fail']);
		$this->assertSame(
			['add 198.18.0.1/32', 'delete 198.18.0.0/24'],
			$this->opEntryRows($this->readLog()),
			'the second delete must never run once the first fails -- the failed entry stays fail-closed'
		);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 6 -- predicate integration: rc=0 output still
	// classified as a failure via pfb_pfctl_op_failed()'s string checks
	// -------------------------------------------------------------------

	public function testRcZeroWithPfctlErrorTextIsClassifiedAsFailure(): void
	{
		$this->scriptFailure('add', '198.18.0.1/32', 0, 'pfctl: some odd diagnostic');
		$plan = ['add' => ['198.18.0.1/32'], 'delete' => []];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertFalse($result['ok'], "rc=0 output containing 'pfctl:' must still classify as a failure");
		$this->assertSame('add 198.18.0.1/32', $result['fail']);
	}

	public function testRcZeroWithTableDoesNotExistIsClassifiedAsFailure(): void
	{
		$this->scriptFailure('add', '198.18.0.1/32', 0, 'Table does not exist.');
		$plan = ['add' => ['198.18.0.1/32'], 'delete' => []];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertFalse($result['ok'], "rc=0 output containing 'Table does not exist' must still classify as a failure");
		$this->assertSame('add 198.18.0.1/32', $result['fail']);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 7 -- duplicate-add tolerance: "0/1 addresses
	// added." at rc=0 is NOT a failure
	// -------------------------------------------------------------------

	public function testDuplicateAddZeroOfOneIsNotAFailure(): void
	{
		$this->scriptFailure('add', '198.18.0.1/32', 0, '0/1 addresses added.');
		$plan = ['add' => ['198.18.0.1/32'], 'delete' => []];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertTrue($result['ok'], "rc=0 '0/1 addresses added.' is the idempotent-duplicate case, not a failure");
		$this->assertNull($result['fail']);
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 8 -- empty plan: ok=TRUE, zero execs
	// -------------------------------------------------------------------

	public function testEmptyPlanIsOkWithZeroExecs(): void
	{
		$result = pfb_live_punch_apply($this->shim, $this->table, ['add' => [], 'delete' => []]);

		$this->assertTrue($result['ok']);
		$this->assertNull($result['fail']);
		$this->assertSame([], $this->readLog(), 'an empty plan must exec pfctl zero times');
	}

	// -------------------------------------------------------------------
	// Coverage matrix row 9 -- hostile entries: shell metacharacters,
	// embedded spaces, and an empty string all reach the shim as ONE
	// literal argv (or, for the empty string, a caught pfctl failure) --
	// never a crash, never a second shell word
	// -------------------------------------------------------------------

	public function testShellMetacharacterEntryReachesPfctlAsOneLiteralArgv(): void
	{
		$plan = ['add' => ['198.18.0.1;id'], 'delete' => []];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertTrue($result['ok']);
		$this->assertSame(
			[['add', $this->table, '198.18.0.1;id']],
			$this->readLog(),
			'the metacharacter must ride as one literal argv field, never a second shell command'
		);
	}

	public function testEntryWithSpacesReachesPfctlAsOneLiteralArgv(): void
	{
		$plan = ['add' => ['not a real cidr'], 'delete' => []];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertTrue($result['ok']);
		$this->assertSame(
			[['add', $this->table, 'not a real cidr']],
			$this->readLog(),
			'embedded spaces must not split the entry into multiple argv fields'
		);
	}

	public function testEmptyStringEntryFailsCleanlyInsteadOfCrashing(): void
	{
		$plan = ['add' => [''], 'delete' => []];

		$result = pfb_live_punch_apply($this->shim, $this->table, $plan);

		$this->assertFalse($result['ok'], 'an empty entry must be caught as a pfctl failure, never crash the helper');
		$this->assertSame('add ', $result['fail']);
		$this->assertSame([['add', $this->table, '']], $this->readLog());
	}
}
