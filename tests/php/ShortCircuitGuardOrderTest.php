<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-28 Phase 6 — Short-circuit / cheap-test-first conditional reordering.
 *
 * Pins the boolean equivalence of the one reordered condition in
 * pfblockerng.inc (inside sync_package_pfblockerng, not unit-reachable
 * directly; proved here via abstract boolean logic + a spy).
 *
 * Reordered condition (pfblockerng.inc ~:12034):
 *
 *   Before:
 *     $continent == $continent_ex && !empty($pfctlck)
 *       && file_exists("{$pfbfolder}/{$cc_alias}.txt") && $pfb['reuse'] == ''
 *       && !file_exists("{$pfb['dbdir']}/geoip.update")
 *
 *   After:
 *     $continent == $continent_ex && !empty($pfctlck)
 *       && $pfb['reuse'] == ''
 *       && file_exists("{$pfbfolder}/{$cc_alias}.txt")
 *       && !file_exists("{$pfb['dbdir']}/geoip.update")
 *
 * Safety proof (ADR-28 §2.3.3):
 *   - No operand performs an assignment or has side effects.
 *   - No later operand depends on an earlier one having run.
 *   - Only the order of operands 3 and 4 changed; 1, 2, 5 are unchanged.
 *
 * Test strategy (condition not unit-reachable):
 *   Part A — Truth-table: for every combination of the five inputs the
 *             old and new expressions must produce the same boolean value.
 *   Part B — Short-circuit proof: when the cheap guard ($reuse != '')
 *             fails, the new expression must NOT call file_exists for the
 *             alias txt — proved via a spy counter.
 *
 * Scenario:
 *   Background: condition gates "compare existing continent data and log no changes".
 *     Given five independent boolean inputs.
 *     When the old expression and the new expression evaluate them.
 *     Then old == new for every input combination (truth-table identity).
 *     And (Part B) the alias-txt file_exists is NOT reached when reuse != ''.
 */
final class ShortCircuitGuardOrderTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Helpers — abstract boolean evaluators matching the before/after forms.
	// -----------------------------------------------------------------------

	/**
	 * Evaluate the BEFORE form of the condition.
	 *
	 * @param bool $eq_continent   $continent == $continent_ex
	 * @param bool $nonempty_ctl   !empty($pfctlck)
	 * @param bool $file_alias     file_exists("{$pfbfolder}/{$cc_alias}.txt")
	 * @param bool $reuse_empty    $pfb['reuse'] == ''
	 * @param bool $no_geo_update  !file_exists("{$pfb['dbdir']}/geoip.update")
	 */
	private function evalBefore(
		bool $eq_continent,
		bool $nonempty_ctl,
		bool $file_alias,
		bool $reuse_empty,
		bool $no_geo_update
	): bool {
		return $eq_continent && $nonempty_ctl && $file_alias && $reuse_empty && $no_geo_update;
	}

	/**
	 * Evaluate the AFTER form — cheap $reuse guard moved before file_alias.
	 */
	private function evalAfter(
		bool $eq_continent,
		bool $nonempty_ctl,
		bool $file_alias,
		bool $reuse_empty,
		bool $no_geo_update
	): bool {
		return $eq_continent && $nonempty_ctl && $reuse_empty && $file_alias && $no_geo_update;
	}

	// -----------------------------------------------------------------------
	// Part A — Truth-table identity across all 32 input combinations.
	// -----------------------------------------------------------------------

	/**
	 * Before-state: the original expression with file_exists before the reuse guard.
	 * Assert it returns true only when all five inputs are true.
	 */
	public function testBeforeFormReturnsTrueOnlyWhenAllInputsTrue(): void
	{
		// Before: must be false when any input is false.
		$this->assertFalse($this->evalBefore(FALSE, TRUE, TRUE, TRUE, TRUE), 'before: eq_continent false');
		$this->assertFalse($this->evalBefore(TRUE, FALSE, TRUE, TRUE, TRUE), 'before: nonempty_ctl false');
		$this->assertFalse($this->evalBefore(TRUE, TRUE, FALSE, TRUE, TRUE), 'before: file_alias false');
		$this->assertFalse($this->evalBefore(TRUE, TRUE, TRUE, FALSE, TRUE), 'before: reuse_empty false');
		$this->assertFalse($this->evalBefore(TRUE, TRUE, TRUE, TRUE, FALSE), 'before: no_geo_update false');

		// Before: true only when all are true.
		$this->assertTrue($this->evalBefore(TRUE, TRUE, TRUE, TRUE, TRUE), 'before: all true');
	}

	/**
	 * After-state: the reordered expression (cheap reuse guard first).
	 * Must produce the same results as the before form for every combination.
	 */
	public function testAfterFormMatchesBeforeFormForAllCombinations(): void
	{
		// Enumerate all 32 combinations of the 5 boolean inputs.
		$bools = [FALSE, TRUE];
		foreach ($bools as $a) {
			foreach ($bools as $b) {
				foreach ($bools as $c) {
					foreach ($bools as $d) {
						foreach ($bools as $e) {
							$before = $this->evalBefore($a, $b, $c, $d, $e);
							$after  = $this->evalAfter($a, $b, $c, $d, $e);
							$this->assertSame(
								$before,
								$after,
								sprintf(
									'truth-table mismatch: eq=%s ctl=%s alias=%s reuse=%s geo=%s',
									var_export($a, TRUE), var_export($b, TRUE),
									var_export($c, TRUE), var_export($d, TRUE),
									var_export($e, TRUE)
								)
							);
						}
					}
				}
			}
		}
	}

	// -----------------------------------------------------------------------
	// Part B — Short-circuit proof: file_exists NOT called when reuse != ''.
	// -----------------------------------------------------------------------

	/**
	 * When the cheap reuse guard ($pfb['reuse'] != '') fails, the new (after)
	 * expression must NOT reach the expensive file_exists for the alias txt.
	 *
	 * Before-state: with the old ordering, file_exists IS called even when
	 * reuse != '' (wasted filesystem call).
	 *
	 * After-state: with the new ordering, file_exists is NOT reached when
	 * reuse != '' (the cheap guard short-circuits).
	 */
	public function testAfterFormSkipsFileExistsWhenReuseIsNotEmpty(): void
	{
		// Given: eq_continent=true, nonempty_ctl=true, reuse_empty=false (reuse='on').
		// The condition must be false, AND (for after form) file_exists should not be called.

		$aliasCallCount_before = 0;
		$aliasCallCount_after  = 0;

		// Spy: a callable that increments a counter, simulating file_exists.
		$spyAlias = static function () use (&$aliasCallCount_before): bool {
			$aliasCallCount_before++;
			return TRUE; // would pass if reached
		};

		// Before form (operand order: eq, ctl, file_alias, reuse, geo).
		// reuse_empty = false, but file_alias evaluated BEFORE reuse in the before form.
		$beforeResult = TRUE && TRUE && $spyAlias() && FALSE && TRUE;

		$this->assertFalse($beforeResult, 'before result must be false (reuse guard fails)');
		$this->assertSame(1, $aliasCallCount_before, 'before: file_exists WAS called even though reuse guard would fail');

		// After form (operand order: eq, ctl, reuse, file_alias, geo).
		// reuse_empty = false — the reuse guard fails before file_alias is reached.
		$spyAlias2 = static function () use (&$aliasCallCount_after): bool {
			$aliasCallCount_after++;
			return TRUE;
		};

		$afterResult = TRUE && TRUE && FALSE && $spyAlias2() && TRUE;
		// Note: PHP short-circuits — $spyAlias2 is NOT called when FALSE already set the && to false.
		// PHP evaluates left-to-right and stops at the first false in an && chain.

		$this->assertFalse($afterResult, 'after result must be false (reuse guard fails)');
		$this->assertSame(0, $aliasCallCount_after, 'after: file_exists was NOT called — cheap guard short-circuited');
	}
}
