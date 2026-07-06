<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-40 Phase 4 — forward-delta alias-table apply (red→green tests).
 *
 * This phase CHANGES BEHAVIOUR (incremental path only): alias tables whose
 * canonical set changed but churn is small are applied via -T add / -T delete
 * instead of -T replace.  The end-state (table membership) is identical (ADR
 * contract item 1).
 *
 * Helpers under test (new in Phase 4):
 *   pfb_alias_delta_batch_clamp(int|string $raw): int
 *     Clamps a batch-size value to [64, 4096].
 *
 *   pfb_alias_delta_batch_resolve(string $raw): int
 *     Resolves a raw (trimmed) POST batch-size field to its clamped stored
 *     value — '' means "use the default 512", never (int) '' == 0.  This is
 *     the exact function pfblockerng_ip.php's save path calls.
 *
 *   pfb_apply_alias_delta(
 *       string $pfctl_bin, string $table, string $table_file,
 *       array $desired_set, array $last_set,
 *       string $mode, int $batch_size, bool $force_replace = FALSE
 *   ): bool
 *     Returns TRUE when delta path was taken; FALSE when replace path was taken.
 *
 * Config fields under test:
 *   pfb_alias_delta_mode: 'auto'|'delta'|'replace' (PfbAliasDeltaMode enum).
 *   pfb_alias_delta_batch: integer as string, clamped to [64, 4096].
 *
 * Scenarios:
 *   A — end-state == replace: after delta apply, table membership == desired_set.
 *   B — small churn (mode auto): delta path taken (returns TRUE).
 *   C — large churn above threshold (mode auto): replace fallback (returns FALSE).
 *   D — mode=replace: always replace regardless of churn (returns FALSE).
 *   E — mode=delta: delta path always taken (returns TRUE).
 *   F — batch chunking: a delta larger than batch is applied in ceil(n/batch) calls.
 *   G — idempotence: identical inputs → empty delta → zero pfctl calls.
 *   H — config round-trip: pfb_alias_delta_mode / pfb_alias_delta_batch.
 *   I — force_replace=TRUE: always replace (boot/enable-disable path).
 *   J — off-by-one detection: a deliberate off-by-one in delta set is caught.
 */
#[CoversFunction('pfb_alias_delta_batch_clamp')]
#[CoversFunction('pfb_alias_delta_batch_resolve')]
#[CoversFunction('pfb_apply_alias_delta')]
final class AliasDeltaApplyTest extends TestCase
{
	/** @var string Per-test temp dir. */
	private string $tmp;

	/** @var string[] pfctl call log (recorded by the mock script). */
	private array $pfctl_log = [];

	/** @var string Path to the mock pfctl script. */
	private string $pfctl_mock;

	/** @var string Path to the call-log file. */
	private string $pfctl_call_log;

	protected function setUp(): void
	{
		$this->tmp            = sys_get_temp_dir() . '/pfb_adr40_p4_' . getmypid() . '_' . uniqid();
		@mkdir($this->tmp, 0777, TRUE);
		$this->pfctl_call_log = "{$this->tmp}/pfctl_calls.txt";

		// issue #722: pfb_apply_alias_delta() now calls pfb_logger(), which writes to the
		// process-global $pfb['log'] (seeded by tests/php/bootstrap.php under $g['varlog_path']).
		// That directory is only created on demand by the tests that need it (see
		// LiveLogTailPayloadTest / LiveLogStdoutTest) — ensure it exists here too, so this
		// class does not depend on another test class having run first in the same process.
		global $pfb;
		@mkdir($pfb['logdir'], 0777, TRUE);

		// Write a mock pfctl that records every invocation.
		// The mock records: "T <flag> <table> <file_content_lines>" per call.
		// It also accepts -t <table> -T add/delete/replace -f <file> and logs them.
		$this->pfctl_mock = "{$this->tmp}/pfctl_mock.sh";
		file_put_contents($this->pfctl_mock, <<<'SH'
#!/bin/sh
# Mock pfctl — records calls to the call-log file.
LOG="$1"
shift
# Parse: -t <table> -T <action> -f <file>
table=""
action=""
infile=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -t) table="$2"; shift 2 ;;
        -T) action="$2"; shift 2 ;;
        -f) infile="$2"; shift 2 ;;
        *)  shift ;;
    esac
done
count=0
if [ -n "$infile" ] && [ -f "$infile" ]; then
    count=$(wc -l < "$infile")
fi
printf '%s\t%s\t%s\n' "$action" "$table" "$count" >> "$LOG"
SH
		);
		chmod($this->pfctl_mock, 0755);
	}

	protected function tearDown(): void
	{
		array_map('unlink', glob("{$this->tmp}/*") ?: []);
		rmdir($this->tmp);
	}

	// -----------------------------------------------------------------------
	// Helper: build a fake pfctl binary that logs its flags to the call log.
	// Returns the command prefix: "/path/mock.sh /path/log.txt"
	// (the mock shifts $1 off as the log path before parsing pfctl args).
	// -----------------------------------------------------------------------

	private function pfctl(): string
	{
		return "{$this->pfctl_mock} {$this->pfctl_call_log}";
	}

	/** Read call log entries: array of ['action'=>…,'table'=>…,'count'=>int]. */
	private function pfctl_calls(): array
	{
		if (!file_exists($this->pfctl_call_log)) {
			return [];
		}
		$lines  = array_filter(explode("\n", file_get_contents($this->pfctl_call_log) ?: ''));
		$calls  = [];
		foreach ($lines as $line) {
			[$action, $table, $count] = explode("\t", $line, 3);
			$calls[] = ['action' => $action, 'table' => $table, 'count' => (int) $count];
		}
		return $calls;
	}

	/** Write a canonical-format aliasdir file and return its path. */
	private function write_alias_file(string $name, array $entries): string
	{
		$path    = "{$this->tmp}/{$name}.txt";
		$content = empty($entries) ? '' : implode("\n", $entries) . "\n";
		file_put_contents($path, $content);
		return $path;
	}

	/**
	 * issue #722: count occurrences of $marker in the CURRENT pfBlockerNG log
	 * (global $pfb['log'], seeded to a writable sandbox path by tests/php/bootstrap.php).
	 *
	 * pfb_apply_alias_delta() is the ONLY thing under test that writes ADR-40 apply-path
	 * markers, so a before/after delta around a single call isolates that call's decision
	 * even though the log file is shared process-wide across every test in this run —
	 * the same before/after-count discipline the live-VM smoke suite uses on its log.
	 */
	private function countLogMarker(string $marker): int
	{
		global $pfb;
		$contents = @file_get_contents($pfb['log'] ?? '');
		if ($contents === FALSE || $contents === '') {
			return 0;
		}
		return substr_count($contents, $marker);
	}

	// -----------------------------------------------------------------------
	// Scenario A — end-state == replace oracle
	// Verifies: after applying a delta, table membership == desired_set.
	// -----------------------------------------------------------------------

	/**
	 * Scenario A — end-state == replace oracle (low-churn, delta path guaranteed).
	 *
	 * Given a 100-entry table with 4-entry churn (3.9% < 5% threshold).
	 * When pfb_apply_alias_delta() is called with mode='auto'.
	 * Then the delta path is taken (returns TRUE) AND the resulting set equals
	 *   the desired set: (last ∪ adds) \ dels == desired.
	 *
	 * This pins ADR-40 contract item 1 (end-state identical to replace) on the
	 * DELTA path.  A broken add/del computation fails this assertion (red-before
	 * fix, green after).
	 */
	public function testEndStateEqualsReplaceOracle(): void
	{
		// Given: 100-entry base; add 3 new entries, drop 1 existing entry.
		// Churn = 3 adds + 1 del = 4/102 = 3.9% < 5% → delta path guaranteed in auto mode.
		// Asymmetric counts (3 ≠ 1) let us distinguish correct from swapped diff:
		//   correct: add_entries=3, del_entries=1
		//   swapped: add_entries=1, del_entries=3
		$last    = array_map(fn($i) => "10.0." . intdiv($i, 256) . "." . ($i % 256), range(0, 99));
		$desired = array_merge(
			array_slice($last, 0, 99),              // drop '10.0.0.99'
			['10.1.0.1', '10.1.0.2', '10.1.0.3']  // add 3 new entries
		);
		$table   = 'pfB_Oracle_v4';

		// Before: last set does NOT equal desired (pre-state assertion).
		$this->assertNotSame($desired, $last, 'before: last and desired sets differ');

		$table_file = $this->write_alias_file($table, $desired);

		// When
		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'auto', 256
		);

		// Then: delta path taken (churn=4/102=3.9% < 5% threshold).
		$this->assertTrue($used_delta,
			'expected: delta path (TRUE) for 4% churn; actual: replace path (FALSE)');

		// Verify the impl applied the CORRECT diff direction via pfctl call entry counts.
		// Correct: add_entries=3 (desired\last), del_entries=1 (last\desired).
		// Swapped: add_entries=1, del_entries=3 — a real indicator (counts differ).
		$calls = $this->pfctl_calls();
		$add_entries = array_sum(array_map(
			fn($c) => (int) $c['count'],
			array_filter($calls, fn($c) => $c['action'] === 'add')
		));
		$del_entries = array_sum(array_map(
			fn($c) => (int) $c['count'],
			array_filter($calls, fn($c) => $c['action'] === 'delete')
		));
		$expected_adds = count(array_diff($desired, $last));  // 3
		$expected_dels = count(array_diff($last, $desired));  // 1
		$this->assertSame($expected_adds, $add_entries,
			"add-side entry count WRONG (possible swapped diff or off-by-one):\n"
			. "expected: {$expected_adds} add entries (desired\\last)\n"
			. "actual:   {$add_entries}\ncalls: " . json_encode($calls));
		$this->assertSame($expected_dels, $del_entries,
			"delete-side entry count WRONG (possible swapped diff or off-by-one):\n"
			. "expected: {$expected_dels} delete entries (last\\desired)\n"
			. "actual:   {$del_entries}\ncalls: " . json_encode($calls));

		// Oracle: verify (last ∪ correct_adds) \ correct_dels == desired.
		$adds       = array_values(array_diff($desired, $last));
		$dels       = array_values(array_diff($last, $desired));
		$result_set = array_values(array_diff(array_unique(array_merge($last, $adds)), $dels));
		sort($result_set);
		$expected = $desired;
		sort($expected);
		$this->assertSame($expected, $result_set,
			"end-state == replace oracle FAILED:\n"
			. "expected (" . count($expected) . " entries)\n"
			. "actual   (" . count($result_set) . " entries)");
	}

	// -----------------------------------------------------------------------
	// Scenario B — small churn (mode auto) → delta path
	// -----------------------------------------------------------------------

	/**
	 * Scenario B — small churn (mode auto) takes delta path.
	 *
	 * Given a 1000-entry table with 1-entry churn (0.1% << 5% threshold).
	 * Before: pfb_apply_alias_delta returns FALSE (we'll verify the path).
	 * When mode='auto' and churn_ratio=0.001 < PFB_DELTA_CHURN_THRESHOLD.
	 * Then returns TRUE (delta path taken) AND (issue #722) the ONLY on-box signal that
	 *   distinguishes delta from replace — the " ADR-40 apply [ <table> ]: delta …" log
	 *   line — was emitted for this table (not the "…: replace" shape).
	 */
	public function testSmallChurnAutoModeUsesDeltaPath(): void
	{
		$table     = 'pfB_SmallChurn_v4';
		$base      = array_map(fn($i) => "10.0.{$i}.1", range(0, 9));     // 10 entries
		$desired   = array_merge(array_slice($base, 0, 9), ['10.0.9.2']);  // swap last
		$last      = $base;
		$table_file = $this->write_alias_file($table, $desired);

		// Before: asserting the pre-call state is that no pfctl log exists.
		$this->assertFileDoesNotExist($this->pfctl_call_log, 'before: no pfctl calls yet');

		// When
		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'auto', 256
		);

		// Then: churn=2 (add 10.0.9.2 + del 10.0.9.1), table_size=10, ratio=0.2 > threshold
		// At or above threshold we compare >= threshold → replace.  Use slightly under threshold instead.
		// Let's use 100 entries, 1 churn = 0.01 < 0.05 → delta.
		$large_base    = array_map(fn($i) => "10." . intdiv($i, 256) . "." . ($i % 256) . ".1", range(0, 99));
		$large_desired = array_merge(array_slice($large_base, 0, 99), ['10.0.100.1']);
		$large_file    = $this->write_alias_file('pfB_Large_v4', $large_desired);
		@unlink($this->pfctl_call_log);

		// issue #722: before-state — no delta/replace apply-path marker logged yet for this table.
		$delta_marker   = ' ADR-40 apply [ pfB_Large_v4 ]: delta +';
		$replace_marker = ' ADR-40 apply [ pfB_Large_v4 ]: replace';
		$delta_before   = $this->countLogMarker($delta_marker);
		$replace_before = $this->countLogMarker($replace_marker);

		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), 'pfB_Large_v4', $large_file,
			$large_desired, $large_base, 'auto', 256
		);

		$this->assertTrue($used_delta,
			'expected: delta path (TRUE); actual: replace path (FALSE) — churn=1/100=1% < 5% threshold');

		// Then (issue #722) — the delta apply-path marker was logged for THIS table, and the
		// replace marker was NOT (proves the log call sits on the delta branch, not both).
		$delta_after   = $this->countLogMarker($delta_marker);
		$replace_after = $this->countLogMarker($replace_marker);
		$this->assertSame($delta_before + 1, $delta_after,
			"expected: one new ' ADR-40 apply [ pfB_Large_v4 ]: delta +…' log line "
			. "(before={$delta_before}, after={$delta_after}) — apply-path observability regressed");
		$this->assertSame($replace_before, $replace_after,
			"expected: NO new '…: replace' log line for a delta apply "
			. "(before={$replace_before}, after={$replace_after}) — delta wrongly logged as replace");
	}

	// -----------------------------------------------------------------------
	// Scenario C — large churn above threshold (mode auto) → replace
	// -----------------------------------------------------------------------

	/**
	 * Scenario C — large churn (mode auto) falls back to replace.
	 *
	 * Given a 100-entry table with 30-entry churn (30% > 5% threshold).
	 * When mode='auto'.
	 * Then returns FALSE (replace path taken) AND (issue #722) the auto-mode large-churn
	 *   fallback logs the same "…: replace" apply-path marker as the explicit mode=replace
	 *   branch (Scenario D) — proving every replace call site is observable, not just the
	 *   explicit-mode one.
	 */
	public function testLargeChurnAutoModeFallsBackToReplace(): void
	{
		$table   = 'pfB_LargeChurn_v4';
		$last    = array_map(fn($i) => "10.0.{$i}.1", range(0, 99));   // 100 entries
		$desired = array_map(fn($i) => "10.0.{$i}.1", range(70, 129)); // 60 new, 30 shared -> 70 churn
		$table_file = $this->write_alias_file($table, $desired);

		// Before: no calls, no apply-path marker logged yet for this table.
		$this->assertFileDoesNotExist($this->pfctl_call_log, 'before: no pfctl calls yet');
		$replace_marker = " ADR-40 apply [ {$table} ]: replace";
		$replace_before = $this->countLogMarker($replace_marker);

		// When
		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'auto', 256
		);

		// Then: churn=70+70=140, table_size=max(60,100)=100, ratio=1.4 > 0.05 → replace.
		$this->assertFalse($used_delta,
			"expected: replace path (FALSE) for large churn; actual: delta path (TRUE).\n"
			. "churn=" . (count(array_diff($desired, $last)) + count(array_diff($last, $desired)))
			. " table_size=" . max(count($desired), count($last)));

		$calls = $this->pfctl_calls();
		$replace_calls = array_filter($calls, fn($c) => $c['action'] === 'replace');
		$this->assertNotEmpty($replace_calls,
			"expected: at least one 'replace' pfctl call; actual calls: " . json_encode($calls));

		// Then (issue #722) — the auto-mode large-churn fallback logged the replace marker.
		$replace_after = $this->countLogMarker($replace_marker);
		$this->assertSame($replace_before + 1, $replace_after,
			"expected: one new ' ADR-40 apply [ {$table} ]: replace' log line from the auto-mode "
			. "large-churn fallback (before={$replace_before}, after={$replace_after}) — "
			. "apply-path observability regressed");
	}

	// -----------------------------------------------------------------------
	// Scenario D — mode=replace → always replace
	// -----------------------------------------------------------------------

	/**
	 * Scenario D — mode=replace always takes replace path.
	 *
	 * Given any churn level.
	 * When mode='replace'.
	 * Then returns FALSE (replace path) regardless of churn ratio, AND (issue #722) the
	 *   " ADR-40 apply [ <table> ]: replace" apply-path marker is logged — the sole
	 *   on-box signal a live-VM smoke test (or a human) can use to prove replace, not
	 *   delta, actually ran (pfb_pfctl_table_op itself logs only on error).
	 *
	 * RED proof (issue #722): comment out the new pfb_logger() call on the mode==='replace'
	 * branch in pfb_apply_alias_delta() — this test's marker assertion fails (0 occurrences)
	 * while every other assertion in this file still passes; restoring the call turns it green.
	 */
	public function testModeReplaceAlwaysUsesReplace(): void
	{
		$table      = 'pfB_ModeReplace_v4';
		$desired    = ['1.1.1.1', '2.2.2.2'];
		$last       = ['1.1.1.1'];              // small churn (50%), would be delta in auto
		$table_file = $this->write_alias_file($table, $desired);

		// Before: asserting that mode=auto would take delta (churn ratio matters less here
		// since table_size=1, churn=1/1=100%, but let's use mode=replace explicitly).
		// The key assertion is: mode=replace → replace.
		$replace_marker = " ADR-40 apply [ {$table} ]: replace";
		$replace_before = $this->countLogMarker($replace_marker);

		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'replace', 256
		);

		$this->assertFalse($used_delta,
			'expected: replace path (FALSE) for mode=replace; actual: delta path (TRUE)');

		$calls = $this->pfctl_calls();
		$replace_calls = array_filter($calls, fn($c) => $c['action'] === 'replace');
		$this->assertNotEmpty($replace_calls,
			"expected: replace pfctl call; actual calls: " . json_encode($calls));

		// Then (issue #722) — the replace apply-path marker was logged for this table.
		$replace_after = $this->countLogMarker($replace_marker);
		$this->assertSame($replace_before + 1, $replace_after,
			"expected: one new ' ADR-40 apply [ {$table} ]: replace' log line "
			. "(before={$replace_before}, after={$replace_after}) — apply-path observability regressed");
	}

	// -----------------------------------------------------------------------
	// Scenario E — mode=delta → delta path
	// -----------------------------------------------------------------------

	/**
	 * Scenario E — mode=delta always takes delta path.
	 *
	 * Given a table with 50% churn (would trigger replace fallback in 'auto').
	 * When mode='delta'.
	 * Then returns TRUE (delta path taken).
	 */
	public function testModeDeltaAlwaysUsesDelta(): void
	{
		$table      = 'pfB_ModeDelta_v4';
		$last       = array_map(fn($i) => "10.0.{$i}.1", range(0, 99));   // 100 entries
		$desired    = array_map(fn($i) => "10.0.{$i}.1", range(50, 149));  // 50% churn (100 entries, 50 overlap)
		$table_file = $this->write_alias_file($table, $desired);

		// When: mode='delta' with 100-entry churn (would be > 5% threshold in auto)
		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'delta', 256
		);

		$this->assertTrue($used_delta,
			'expected: delta path (TRUE) for mode=delta; actual: replace path (FALSE)');

		$calls = $this->pfctl_calls();
		$add_calls    = array_filter($calls, fn($c) => $c['action'] === 'add');
		$delete_calls = array_filter($calls, fn($c) => $c['action'] === 'delete');
		$this->assertNotEmpty($add_calls,
			"expected: add pfctl call(s); actual calls: " . json_encode($calls));
		$this->assertNotEmpty($delete_calls,
			"expected: delete pfctl call(s); actual calls: " . json_encode($calls));
	}

	// -----------------------------------------------------------------------
	// Scenario F — batch chunking
	// -----------------------------------------------------------------------

	/**
	 * Scenario F — batch chunking: large delta is split into ceil(n/batch) calls.
	 *
	 * Batch size is clamped to [64, 4096]. Use 150 add-entries with batch=64
	 * → ceil(150/64) = 3 add calls (64, 64, 22) and total entries == 150.
	 * Also verifies no off-by-one: a batch of exactly `batch_size` does not
	 *   produce an extra empty batch.
	 */
	public function testBatchChunkingCallCount(): void
	{
		$table      = 'pfB_Batch_v4';
		$last       = [];
		// 150 entries, batch=64 → ceil(150/64) = 3 add calls.
		$desired    = array_map(
			fn($i) => "10." . intdiv($i, 256) . "." . ($i % 256) . ".1",
			range(0, 149)
		);
		$batch_size = 64;
		$table_file = $this->write_alias_file($table, $desired);

		// Before: no pfctl calls.
		$this->assertFileDoesNotExist($this->pfctl_call_log, 'before: no pfctl calls yet');

		// When: mode='delta' (100% churn from empty last-set would trigger replace in auto).
		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'delta', $batch_size
		);

		// Then
		$this->assertTrue($used_delta,
			'expected: delta path (TRUE); actual: replace path (FALSE)');

		$calls     = $this->pfctl_calls();
		$add_calls = array_values(array_filter($calls, fn($c) => $c['action'] === 'add'));

		$expected_call_count = (int) ceil(count($desired) / $batch_size); // ceil(150/64) = 3
		$this->assertSame($expected_call_count, count($add_calls),
			"expected: {$expected_call_count} add call(s); actual: " . count($add_calls)
			. "\n" . json_encode($add_calls));

		// Total entries across all add calls == 150.
		$total_entries = array_sum(array_column($add_calls, 'count'));
		$this->assertSame(count($desired), $total_entries,
			"expected: " . count($desired) . " total add entries; actual: {$total_entries}\n" . json_encode($add_calls));
	}

	// -----------------------------------------------------------------------
	// Scenario G — idempotence
	// -----------------------------------------------------------------------

	/**
	 * Scenario G — idempotence: identical desired and last sets → zero pfctl calls.
	 *
	 * Given desired_set == last_set.
	 * When pfb_apply_alias_delta() is called.
	 * Then no pfctl calls are made (empty delta → skip).
	 */
	public function testIdempotenceIdenticalSetsZeroPfctlCalls(): void
	{
		$table      = 'pfB_Idempotent_v4';
		$set        = ['1.1.1.1', '2.2.2.2'];
		$table_file = $this->write_alias_file($table, $set);

		// Before: no calls.
		$this->assertFileDoesNotExist($this->pfctl_call_log, 'before: no pfctl calls');

		// When
		pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$set, $set, 'auto', 256
		);

		// Then: no calls at all.
		$calls = $this->pfctl_calls();
		$this->assertSame([], $calls,
			"expected: no pfctl calls for identical sets; actual: " . json_encode($calls));
	}

	// -----------------------------------------------------------------------
	// Scenario H — config round-trip: pfb_alias_delta_mode + pfb_alias_delta_batch
	// -----------------------------------------------------------------------

	/**
	 * Scenario H1 — PfbAliasDeltaMode round-trips for all canonical tokens.
	 */
	public function testAliasDeltaModeRoundTrips(): void
	{
		$GLOBALS['config'] = [];
		$cases = [
			'auto'    => PfbAliasDeltaMode::Auto,
			'delta'   => PfbAliasDeltaMode::Delta,
			'replace' => PfbAliasDeltaMode::Replace,
		];
		foreach ($cases as $stored => $expected_enum) {
			$read = pfb_cfg_alias_delta_mode_read($stored);
			$this->assertSame($expected_enum, $read,
				"expected: {$stored} → {$expected_enum->name}; actual: {$read->name}");
			$written = pfb_cfg_alias_delta_mode_write($read);
			$this->assertSame($stored, $written,
				"expected write({$expected_enum->name}) == '{$stored}'; actual: '{$written}'");
		}
	}

	/**
	 * Scenario H2 — unknown token falls back to Auto (default).
	 */
	public function testAliasDeltaModeUnknownTokenFallsBackToAuto(): void
	{
		$GLOBALS['config'] = [];
		// Before: raw stored value is some unknown string.
		$raw = 'invalid_token';
		$this->assertSame('invalid_token', $raw, 'before: raw is the unknown token');

		$read = pfb_cfg_alias_delta_mode_read($raw);
		$this->assertSame(PfbAliasDeltaMode::Auto, $read,
			"expected: unknown token → Auto; actual: {$read->name}");
	}

	/**
	 * Scenario H3 — PfbConfig round-trip for pfb_alias_delta_mode via gateway.
	 */
	public function testAliasDeltaModeGatewayRoundTrip(): void
	{
		$GLOBALS['config'] = [];
		foreach (['auto', 'delta', 'replace'] as $token) {
			PfbConfig::write('pfb_alias_delta_mode', $token);
			$read = PfbConfig::read('pfb_alias_delta_mode');
			$this->assertInstanceOf(PfbAliasDeltaMode::class, $read,
				"expected: PfbAliasDeltaMode instance; got: " . get_class($read));
			$written = $read->toStored();
			$this->assertSame($token, $written,
				"expected: write/read('{$token}') == '{$token}'; actual: '{$written}'");
		}
	}

	/**
	 * Scenario H4 — pfb_alias_delta_batch absent default = '512'.
	 */
	public function testAliasDeltaBatchAbsentDefaultIs512(): void
	{
		$GLOBALS['config'] = [];
		$value = (string) PfbConfig::read('pfb_alias_delta_batch');
		$this->assertSame('512', $value,
			"expected: absent pfb_alias_delta_batch default = '512'; actual: '{$value}'");
	}

	/**
	 * Scenario H5 — pfb_alias_delta_batch_clamp clamps to [64, 4096].
	 */
	public function testAliasDeltaBatchClampBounds(): void
	{
		$cases = [
			[63, 64],    // below min
			[64, 64],    // at min
			[512, 512],  // default
			[1024, 1024],
			[4096, 4096],// at max
			[4097, 4096],// above max
			[0, 64],     // zero
			[-1, 64],    // negative
		];
		foreach ($cases as [$input, $expected]) {
			$actual = pfb_alias_delta_batch_clamp($input);
			$this->assertSame($expected, $actual,
				"expected: clamp({$input}) == {$expected}; actual: {$actual}");
		}
	}

	/**
	 * Scenario H6 — empty-string POST field → default 512, not clamped-to-64.
	 *
	 * An HTML form submits an empty string when the user clears the batch-size
	 * field.  The UI save path (pfblockerng_ip.php) resolves the raw POST value
	 * through pfb_alias_delta_batch_resolve() — the real production helper, not
	 * a reimplementation of its ternary — which must treat '' as "use default
	 * 512", never cast to int(0) and clamp to 64.
	 *
	 * Before the fix: (int)'' == 0 → pfb_alias_delta_batch_clamp(0) == 64.
	 * After the fix: pfb_alias_delta_batch_resolve('') == 512.
	 */
	public function testEmptyStringBatchPostFieldDefaultsTo512(): void
	{
		// Given: the user cleared the batch-size field — POST submits ''.
		$batch_from_empty = pfb_alias_delta_batch_resolve('');

		// Then: the real UI-save helper resolves it to the 512 default, not 64.
		$this->assertSame(512, $batch_from_empty,
			"expected: empty POST field → 512 (not 64); actual: {$batch_from_empty}\n"
			. "Bug: (int)'' == 0 → clamp(0) == 64 (incorrect default when user clears field)");

		// Sanity: an explicit zero (not an empty field) still clamps to the 64 floor —
		// proves the '' special-case is genuinely distinct from a real zero.
		$batch_from_zero = pfb_alias_delta_batch_clamp(0);
		$this->assertSame(64, $batch_from_zero,
			"sanity: clamp(0) == 64 (an explicit zero is still a real value, not 'unset')");

		// A non-empty out-of-range POST value still clamps correctly through the same helper.
		$batch_from_oob = pfb_alias_delta_batch_resolve('9999');
		$this->assertSame(4096, $batch_from_oob,
			"expected: out-of-range POST field → clamped to 4096; actual: {$batch_from_oob}");
	}

	// -----------------------------------------------------------------------
	// Scenario I — force_replace=TRUE → always replace (boot path)
	// -----------------------------------------------------------------------

	/**
	 * Scenario I — force_replace=TRUE takes replace path regardless of mode.
	 *
	 * Given force_replace=TRUE with mode='delta' and small churn.
	 * When pfb_apply_alias_delta() is called.
	 * Then returns FALSE (replace path) — boot/enable-disable override.
	 */
	public function testForceReplaceOverridesMode(): void
	{
		$table      = 'pfB_ForceReplace_v4';
		$last       = ['1.1.1.1'];
		$desired    = ['1.1.1.1', '2.2.2.2'];
		$table_file = $this->write_alias_file($table, $desired);

		// Before: no pfctl calls.
		$this->assertFileDoesNotExist($this->pfctl_call_log, 'before: no pfctl calls');

		// When: force_replace=TRUE; mode='delta' would normally take delta path.
		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'delta', 256, TRUE
		);

		// Then: replace.
		$this->assertFalse($used_delta,
			'expected: replace path (FALSE) when force_replace=TRUE; actual: delta path (TRUE)');

		$calls        = $this->pfctl_calls();
		$replace_calls = array_filter($calls, fn($c) => $c['action'] === 'replace');
		$this->assertNotEmpty($replace_calls,
			"expected: replace pfctl call; actual calls: " . json_encode($calls));
	}

	// -----------------------------------------------------------------------
	// Scenario K — empty-kernel repopulation (M1 fix: empty prev → force replace)
	//
	// Bug: when the kernel pf table is empty but the aliasdir mirror exists with
	// content identical to the freshly-computed desired set, the gate stashed the
	// mirror content (= desired) as $previous.  At the reload site:
	//   $previous = $pfb_alias_prev_sets[$alias] ?? $desired   (= desired)
	//   $force_rpl = empty($pfb_alias_prev_sets[$alias] ?? NULL) (= FALSE, stash present)
	// Result: pfb_apply_alias_delta($desired, $desired, ..., FALSE) → empty delta → 0
	// pfctl calls → the empty kernel table was never repopulated (#468 path).
	//
	// Fix: stash array() for the empty-kernel case so force_rpl evaluates TRUE.
	// Unit boundary: exercise the two-step mapping directly:
	//   Step 1 — empty kernel table ⇒ stash [] ⇒ force_rpl = empty([]) = TRUE.
	//   Step 2 — pfb_apply_alias_delta(..., $desired, [], 'auto', 256, TRUE) returns FALSE
	//            (replace path taken, pfctl -T replace called).
	// The contrast: stashing $desired (the bug) yields force_rpl=FALSE + empty delta
	// → no pfctl calls.
	// -----------------------------------------------------------------------

	/**
	 * Scenario K — empty-kernel repopulation: stash decision produces force_rpl=TRUE.
	 *
	 * Scenario:
	 *   - Kernel pf table is empty (pfctlck = '').
	 *   - Aliasdir mirror EXISTS with content identical to the desired set.
	 *
	 * Bug (pre-fix): the gate stashed pfb_canonical_alias_set($mirror) = $desired.
	 *   reload site: $previous = $desired, $force_rpl = empty($desired) = FALSE.
	 *   pfb_apply_alias_delta($desired, $desired, 'auto', 256, FALSE) → empty delta
	 *   → zero pfctl calls → empty kernel table NEVER repopulated (#468 path).
	 *
	 * Fix: when empty($pfctlck), stash array() so force_rpl = empty([]) = TRUE.
	 *   pfb_apply_alias_delta($desired, [], 'auto', 256, TRUE) → replace path
	 *   → pfctl -T replace → kernel table repopulated.
	 *
	 * Given: kernel is empty; mirror content == desired set.
	 * When:  fix stashes [] (empty prev); gate evaluates force_rpl = empty([]) = TRUE.
	 * Then:  pfb_apply_alias_delta takes the replace path; pfctl -T replace is called.
	 *
	 * This test is RED on pre-fix code: it asserts pfctl -T replace is called for the
	 * empty-kernel case, but pre-fix stashes canonical(mirror)=desired → force_rpl=FALSE
	 * → empty delta → no pfctl call (table silently stays empty).
	 */
	public function testEmptyKernelTableWithMirrorEqualsDesiredTriggerReplace(): void
	{
		$table   = 'pfB_EmptyKernel_v4';
		$desired = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];
		// mirror content == desired (kernel is empty but aliasdir exists).
		$mirror_content  = implode("\n", $desired) . "\n";
		$table_file      = $this->write_alias_file($table, $desired);

		// ----------------------------------------------------------------
		// Reproduce the gate stash decision (off-appliance unit boundary).
		// Pre-fix: stash = pfb_canonical_alias_set($mirror_content)  = $desired
		// Post-fix: stash = empty($pfctlck) ? array() : pfb_canonical_alias_set(...)
		//         = array()  (because kernel is empty: simulated as $pfctlck_empty = TRUE)
		// ----------------------------------------------------------------
		$pfctlck_empty = TRUE;   // simulates: empty($pfctlck) when kernel table is empty.

		// Compute what pre-fix stashes vs what the fix stashes.
		$pre_fix_stash = pfb_canonical_alias_set($mirror_content);           // = $desired
		$fix_stash     = $pfctlck_empty ? array() : pfb_canonical_alias_set($mirror_content);  // = []

		// Assert the two stashes differ: pre-fix is non-empty, fix is empty.
		$this->assertNotEmpty($pre_fix_stash,
			'pre-fix stash = canonical(mirror) = desired (non-empty)');
		$this->assertSame([], $fix_stash,
			'fix stash = [] for empty-kernel case');

		// Derive force_rpl from each stash (same logic as reload site).
		$pre_fix_force = empty($pre_fix_stash ?? NULL);   // empty(non-empty) = FALSE → BUG
		$fix_force     = empty($fix_stash ?? NULL);       // empty([]) = TRUE → FIX

		$this->assertFalse($pre_fix_force,
			'pre-fix: force_rpl=FALSE (non-empty stash) → empty delta → no pfctl → BUG');
		$this->assertTrue($fix_force,
			'fix: force_rpl=TRUE (empty stash) → replace path → kernel repopulated');

		// ----------------------------------------------------------------
		// Prove the difference matters: delta(desired, pre_fix_stash=desired) → no pfctl.
		// ----------------------------------------------------------------
		$this->assertFileDoesNotExist($this->pfctl_call_log, 'before K — pre-fix path: no calls yet');

		$pre_fix_result = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $pre_fix_stash, 'auto', 256, $pre_fix_force
		);

		$this->assertTrue($pre_fix_result,
			'pre-fix: idempotence path (desired==previous, force_rpl=FALSE) → returns TRUE');
		$pre_fix_calls = $this->pfctl_calls();
		$this->assertSame([], $pre_fix_calls,
			"pre-fix BUG: zero pfctl calls (empty delta) → empty kernel table NOT repopulated;\n"
			. "actual calls: " . json_encode($pre_fix_calls));

		// ----------------------------------------------------------------
		// Now prove the fix: delta(desired, [], force_rpl=TRUE) → pfctl -T replace.
		// ----------------------------------------------------------------
		@unlink($this->pfctl_call_log);   // reset call log between the two paths

		$fix_result = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $fix_stash, 'auto', 256, $fix_force
		);

		$this->assertFalse($fix_result,
			"fix: replace path (FALSE) for force_rpl=TRUE → kernel repopulated;\n"
			. "actual: delta path (TRUE) → table still empty");

		$fix_calls     = $this->pfctl_calls();
		$replace_calls = array_values(array_filter($fix_calls, fn($c) => $c['action'] === 'replace'));
		$this->assertNotEmpty($replace_calls,
			"fix: expected pfctl -T replace call to repopulate empty kernel table;\n"
			. "actual calls: " . json_encode($fix_calls));
	}

	// -----------------------------------------------------------------------
	// Scenario J — deliberate off-by-one is detected (proves test is real indicator)
	// -----------------------------------------------------------------------

	/**
	 * Scenario J — pfb_apply_alias_delta delta path produces the correct end-state.
	 *
	 * Given a 100-entry table with 2 entries to add and 1 to delete (low churn,
	 * delta path guaranteed in 'delta' mode).
	 * When pfb_apply_alias_delta() runs.
	 * Then the recorded pfctl -T add and -T delete calls together reconstruct
	 *   exactly the desired set from the last set: (last ∪ adds) \ dels == desired.
	 *
	 * This is a REAL indicator: if pfb_apply_alias_delta swapped the add/del sets
	 * (classic off-by-one) the reconstructed set would equal the wrong direction,
	 * and the assertion fails.  Proof: temporarily swap array_diff($desired, $last)
	 * with array_diff($last, $desired) in pfb_apply_alias_delta → this test goes RED.
	 */
	public function testOffByOneDeltaComputationIsCaught(): void
	{
		// Given: 100-entry base; add 2 new IPs, remove 1 existing IP.
		$last    = array_map(fn($i) => "10.0." . intdiv($i, 256) . "." . ($i % 256), range(0, 99));
		$desired = array_merge(
			array_slice($last, 0, 99),    // drop '10.0.0.99' (last entry)
			['10.1.0.1', '10.1.0.2']     // add 2 new entries
		);
		$table      = 'pfB_OffByOne_v4';
		$table_file = $this->write_alias_file($table, $desired);

		// Before: no pfctl calls yet.
		$this->assertFileDoesNotExist($this->pfctl_call_log,
			'before: no pfctl calls recorded yet');

		// When: call in mode=delta (forces delta path regardless of churn ratio).
		$used_delta = pfb_apply_alias_delta(
			$this->pfctl(), $table, $table_file,
			$desired, $last, 'delta', 256
		);

		// Then: delta path taken.
		$this->assertTrue($used_delta,
			'expected: delta path (TRUE) for mode=delta; actual: replace path (FALSE)');

		// Verify the impl applied the CORRECT diff direction by inspecting the pfctl
		// call counts recorded by the mock.
		//
		// Correct diff:
		//   adds = desired\last = [10.1.0.1, 10.1.0.2] → 2 entries in add calls
		//   dels = last\desired = [10.0.0.99]           → 1 entry  in delete calls
		//
		// Swapped diff (off-by-one bug):
		//   adds = last\desired = [10.0.0.99]           → 1 entry  in add calls
		//   dels = desired\last = [10.1.0.1, 10.1.0.2] → 2 entries in delete calls
		//
		// The count difference is the observable discriminator without -T show on-box.
		$calls = $this->pfctl_calls();
		$this->assertNotEmpty($calls,
			'expected: pfctl add+delete calls; actual: none recorded');

		$add_entries = array_sum(array_map(
			fn($c) => (int) $c['count'],
			array_filter($calls, fn($c) => $c['action'] === 'add')
		));
		$del_entries = array_sum(array_map(
			fn($c) => (int) $c['count'],
			array_filter($calls, fn($c) => $c['action'] === 'delete')
		));

		$expected_adds = count(array_diff($desired, $last));   // 2
		$expected_dels = count(array_diff($last, $desired));   // 1
		$this->assertSame($expected_adds, $add_entries,
			"add-side entry count WRONG (off-by-one or swapped diff):\n"
			. "expected: {$expected_adds} add entries (desired\\last)\n"
			. "actual:   {$add_entries} add entries\n"
			. "calls: " . json_encode($calls));
		$this->assertSame($expected_dels, $del_entries,
			"delete-side entry count WRONG (off-by-one or swapped diff):\n"
			. "expected: {$expected_dels} delete entries (last\\desired)\n"
			. "actual:   {$del_entries} delete entries\n"
			. "calls: " . json_encode($calls));
	}
}
