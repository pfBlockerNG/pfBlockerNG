<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Category-edit row-move (anchor) reorder guard (issue #1129).
 *
 * A stale/hostile Lmove or Xmove (a checkbox/anchor left over from a form
 * gone stale in another tab, or a crafted request) let the reorder loop
 * collect checked rows into $move for re-insertion, then never re-insert
 * them because the anchor branch never fired -- the checked rows silently
 * vanished from $final before it was persisted via config_set_path() +
 * write_config(). The fix requires Lmove to be a non-empty array, Xmove to
 * be a scalar that is literally an existing row key, and every checked
 * Lmove key to exist in the row set -- otherwise the whole block is skipped
 * (no move, no save) instead of rebuilding a row list that drops rows.
 *
 * Like CategoryEditPostGuardTest, the page carries top-level execution and
 * cannot be require()d off-appliance: the reorder block is eval-extracted
 * verbatim from the REAL source (anchored on text stable across both the
 * pre-fix and post-fix code, so the same test file proves red on the old
 * code and green on the new) up to the row-array assignment -- stopping
 * before config_set_path()/write_config()/header()/exit() so the extracted
 * function is a pure array transform.
 */
final class CategoryEditRowMoveTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('pfb_category_oracle_row_move')) {
			if (!preg_match(
				'/\/\/ Move selected table row\(s\) to anchor row\n(?:\/\/[^\n]*\n)*'
				. '(if \(isset\(\$Lmove\).*?\$rowdata\[\$rowid\]\[\'row\'\] = \$final;\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: row-move reorder block not found');
			}
			eval(
				'function pfb_category_oracle_row_move(array $rowdata, $rowid, $Lmove, $Xmove): array {'
				. $m[1]
				. '}'
				. ' return $rowdata[$rowid][\'row\']; }'
			);
		}
	}

	private function rowdata(array $rows): array
	{
		return [0 => ['row' => $rows]];
	}

	/**
	 * Runs the extracted reorder oracle, capturing any PHP warning/notice it
	 * triggers instead of letting it escape (the pre-fix code path warns on
	 * an undefined $pre/array key for some hostile inputs -- row 5).
	 *
	 * @return array{0: array<int, string>, 1: array<int, string>}
	 */
	private function runRowMove(array $rowdata, $rowid, $Lmove, $Xmove): array
	{
		$warnings = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return TRUE;
		});
		try {
			$result = pfb_category_oracle_row_move($rowdata, $rowid, $Lmove, $Xmove);
		} finally {
			restore_error_handler();
		}
		return [$result, $warnings];
	}

	// --- Row 1: regression guard -- the pre-existing correct-move behaviour ----

	public function testValidMoveRelocatesCheckedRowNextToAnchor(): void
	{
		// Given: three rows, row1 checked to move to anchor row2 (an existing key).
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		// When: the reorder runs with a valid anchor.
		[$result, ] = $this->runRowMove($rowdata, 0, [1 => '1'], 2);

		// Then: row1 lands adjacent to row2 -- pins the pre-existing, unchanged-by-this-fix
		// placement rule (not a before/after claim; see the UI tooltip vs. actual algorithm
		// discrepancy tracked separately).
		$this->assertSame(['row0', 'row2', 'row1'], $result, 'row1 must land adjacent to the anchor row2, unchanged from pre-fix behaviour');
	}

	// --- Row 2: THE BUG -- a stale/out-of-range anchor must not drop rows ------

	public function testStaleAnchorSkipsReorderInsteadOfDroppingCheckedRow(): void
	{
		// Given: row1 checked, but Xmove references no row key (stale form state).
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		// When: the reorder runs with the stale anchor.
		[$result, ] = $this->runRowMove($rowdata, 0, [1 => '1'], '999');

		// Then: the whole reorder is skipped -- row1 is NOT silently dropped.
		$this->assertSame(
			['row0', 'row1', 'row2'],
			$result,
			'a stale/out-of-range Xmove anchor must skip the reorder, not drop the checked row'
		);
	}

	// --- Row 3: array-valued Xmove (hostile) ------------------------------------

	public function testArrayValuedAnchorSkipsReorderWithoutTypeError(): void
	{
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		try {
			[$result, ] = $this->runRowMove($rowdata, 0, [1 => '1'], ['hostile']);
		} catch (\TypeError $e) {
			$this->fail('an array-valued Xmove must not TypeError: ' . $e->getMessage());
		}

		$this->assertSame(
			['row0', 'row1', 'row2'],
			$result,
			'an array-valued Xmove must skip the reorder, not drop the checked row'
		);
	}

	// --- Row 4: Lmove references a deleted/stale row key ------------------------

	public function testStaleLmoveKeySkipsReorderInsteadOfCorruptingRowSet(): void
	{
		// Given: the checked row key 99 no longer exists in the current row set.
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		// When: the reorder runs with a valid anchor but a stale checked key.
		[$result, ] = $this->runRowMove($rowdata, 0, [99 => '1'], 0);

		// Then: the reorder is skipped -- the row set (including the anchor row0) survives.
		$this->assertSame(
			['row0', 'row1', 'row2'],
			$result,
			'a checked Lmove key absent from the row set must skip the reorder'
		);
	}

	// --- Row 5: empty Lmove -- nothing checked -----------------------------------

	public function testEmptyLmoveSkipsReorderWithoutUndefinedVariableWarning(): void
	{
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		[$result, $warnings] = $this->runRowMove($rowdata, 0, [], 0);

		$this->assertSame([], $warnings, 'an empty Lmove must not reach the undefined-$pre-variable code path');
		$this->assertSame(
			['row0', 'row1', 'row2'],
			$result,
			'an empty Lmove means nothing was checked -- the row set stays unchanged'
		);
	}

	// --- Row 6: non-array Lmove (hostile) ----------------------------------------

	public function testNonArrayLmoveSkipsReorderWithoutCrash(): void
	{
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		try {
			[$result, ] = $this->runRowMove($rowdata, 0, 'x', 0);
		} catch (\Throwable $e) {
			$this->fail('a non-array Lmove must not crash the reorder: ' . get_class($e) . ': ' . $e->getMessage());
		}

		$this->assertSame(
			['row0', 'row1', 'row2'],
			$result,
			'a non-array (hostile) Lmove must skip the reorder, not corrupt the row set'
		);
	}

	// --- Row 7: issue #1135 defect 1 -- ordinary move, anchor not itself checked ---

	public function testOrdinaryMoveToUncheckedAnchorTriggersNoUndefinedKeyWarning(): void
	{
		// Given: row1 checked to move to anchor row2 -- row2 itself is NOT checked,
		// the ordinary case, so $Lmove has no entry for the anchor's own key.
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		// When: the reorder runs.
		[$result, $warnings] = $this->runRowMove($rowdata, 0, [1 => '1'], 2);

		// Then: the move result matches the pre-existing baseline (unchanged by this
		// fix -- pins testValidMoveRelocatesCheckedRowNextToAnchor's outcome), AND no
		// PHP warning fires reading $Lmove[$key] at the unset anchor key (the actual
		// red-to-green signal for this row).
		$this->assertSame(['row0', 'row2', 'row1'], $result, 'row1 must still land adjacent to anchor row2');
		$this->assertSame(
			[],
			$warnings,
			'reading $Lmove at the anchor row\'s own (unchecked) key must not emit an undefined-array-key warning'
		);
	}

	// --- Row 8: issue #1135 defect 2 -- genuine self-click (honest Lmove[key]===key) ---

	public function testGenuineSelfAnchorSkipsReorderCleanly(): void
	{
		// Given: row1 checked with the honest UI-generated value (Lmove[1] === '1',
		// matching its own key) and anchored on itself.
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		// When: the reorder runs with Xmove referencing the same checked row.
		[$result, ] = $this->runRowMove($rowdata, 0, [1 => '1'], '1');

		// Then: the row set is unchanged. This was already a no-duplicate no-op
		// pre-fix (the honest Lmove[key]===key value keeps the merge from
		// duplicating); post-fix the new outer-guard clause additionally makes
		// this a clean whole-block skip. The extracted oracle stops before the
		// side effects (config_set_path/write_config/header/exit) that would
		// distinguish "entered, no-op" from "skipped", so this row's array
		// assertion does not itself flip red-to-green -- it is a behaviour-
		// preservation pin, the same distinction row 1 documents for its own
		// baseline assertion.
		$this->assertSame(
			['row0', 'row1', 'row2'],
			$result,
			'a genuine self-anchored move must not duplicate or drop the checked row'
		);
	}

	// --- Row 9: issue #1135 defect 2 -- THE BUG: crafted self-anchor mismatch ---

	public function testCraftedSelfAnchorMismatchNoLongerDuplicatesRow(): void
	{
		// Given: row1 checked but with a TAMPERED Lmove value ('999', not its own
		// key '1') and Xmove anchoring on that same checked row -- an authenticated
		// attacker crafting Lmove[1]=999&Xmove=1, not a genuine UI click.
		$rowdata = $this->rowdata(['row0', 'row1', 'row2']);

		// When: the reorder runs with the crafted mismatch.
		[$result, ] = $this->runRowMove($rowdata, 0, [1 => '999'], '1');

		// Then: the reorder is skipped entirely -- row1 appears exactly once.
		$this->assertSame(
			['row0', 'row1', 'row2'],
			$result,
			'a crafted Lmove/Xmove self-anchor mismatch must skip the reorder, not duplicate the checked row'
		);
	}
}
