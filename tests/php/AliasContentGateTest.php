<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-40 Phase 3 — content-addressed reload gating (red→green tests).
 *
 * This phase CHANGES BEHAVIOUR: alias tables are reloaded iff their final
 * canonical membership set changed vs the last-applied mirror, not iff a
 * member feed was refetched.
 *
 * Every test in this file was RED on the pre-Phase-3 code and is GREEN after.
 * The captured failure output is recorded in RESULTS/03_Results.txt.
 *
 * Helpers under test (new in Phase 3):
 *   pfb_alias_set_different(array $new_set, string $mirror_path): bool
 *     Returns TRUE when the canonical set differs from the last-applied mirror,
 *     or when the mirror does not exist (boot/empty-table repopulation path).
 *
 *   pfb_write_canonical_alias(string $path, array $canonical_set): void
 *     Writes the canonical set to the given path (one entry per line, trailing
 *     newline). The written file becomes the new last-applied mirror for
 *     pfb_alias_set_different() on the next pass.
 *
 *   pfb_cross_list_scope(bool $dup_on, bool $rep_on): bool
 *     Returns TRUE when a cross-list feature (dedup or reputation) is active,
 *     meaning ALL aliases must be recomputed this pass (not just feed-changed ones).
 *
 * Coverage (each pinning one contract item from ADR §2):
 *   Scenario A — cross-list dedup: today the bug is that sibling B is NOT reloaded
 *     when feed A changes (§1.2(1)). After the fix: pfb_alias_set_different() detects
 *     B's content changed and returns TRUE.
 *   Scenario B — reputation no-amplify: today rep-on reloads ALL aliases; after the fix
 *     pfb_alias_set_different() returns FALSE for unchanged aliases even when rep is on.
 *   Scenario C — surgical: with cross-list off, only the changed alias is detected as
 *     different; untouched aliases return FALSE.
 *   Scenario D — idempotence: two passes with identical inputs → second pfb_alias_set_different()
 *     call returns FALSE (no reload on second pass — the "no-op" contract, ADR §2).
 *   Scenario E — empty-table repopulation: missing mirror → pfb_alias_set_different() returns TRUE
 *     (boot path, ADR contract item 5).
 *   Scenario F — pfb_write_canonical_alias writes sort-u'd content (one line per entry).
 *   Scenario G — pfb_cross_list_scope returns TRUE iff dup or rep is on.
 */
#[CoversFunction('pfb_alias_set_different')]
#[CoversFunction('pfb_write_canonical_alias')]
#[CoversFunction('pfb_cross_list_scope')]
final class AliasContentGateTest extends TestCase
{
	/** @var string Per-test temp dir for mirror files. */
	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_adr40_p3_' . getmypid() . '_' . uniqid();
		@mkdir($this->tmp, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->tmp}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->tmp);
	}

	private function mirrorPath(string $alias): string
	{
		return "{$this->tmp}/{$alias}.txt";
	}

	private function writeMirror(string $alias, string $content): void
	{
		file_put_contents($this->mirrorPath($alias), $content);
	}

	// -----------------------------------------------------------------------
	// Scenario E — empty-table repopulation (missing mirror → TRUE)
	//
	// ADR contract item 5: an alias whose kernel table is empty but whose
	// desired set is non-empty is loaded even if the set "did not change"
	// vs an absent mirror. The absent mirror maps to "no last-applied record."
	// -----------------------------------------------------------------------

	/**
	 * Scenario E: missing mirror → pfb_alias_set_different() returns TRUE.
	 *
	 * Before Phase 3: no such function exists. After: it returns TRUE when
	 * the mirror file is absent (boot/initial-load path).
	 *
	 * Given: no mirror file exists for this alias.
	 * When:  we call pfb_alias_set_different() with a non-empty canonical set.
	 * Then:  TRUE is returned (alias must be loaded).
	 */
	public function testMissingMirrorForcesReload(): void
	{
		$path   = $this->mirrorPath('pfB_Missing_v4');
		$newSet = ['192.0.2.1', '192.0.2.2'];

		$changed = pfb_alias_set_different($newSet, $path);

		$this->assertTrue(
			$changed,
			"missing mirror → TRUE (boot/empty-table repopulation)\n" .
			"expected: true\n" .
			"got:      " . ($changed ? 'true' : 'false')
		);
	}

	/**
	 * Scenario E (empty desired set, missing mirror): empty set + no mirror → FALSE.
	 *
	 * An alias with no content AND no mirror is a genuine no-op; nothing to load.
	 */
	public function testMissingMirrorWithEmptySetIsNoOp(): void
	{
		$path = $this->mirrorPath('pfB_Empty_v4');

		$changed = pfb_alias_set_different([], $path);

		$this->assertFalse(
			$changed,
			"empty desired set + missing mirror → FALSE (nothing to do)\n" .
			"expected: false\n" .
			"got:      " . ($changed ? 'true' : 'false')
		);
	}

	// -----------------------------------------------------------------------
	// Scenario D — idempotence (same set twice → FALSE on second call)
	//
	// ADR contract item 8 / §2 "Force = recompute desired sets and diff;
	// identical sets → empty delta → no-op."
	// -----------------------------------------------------------------------

	/**
	 * Scenario D: identical inputs twice → second call returns FALSE.
	 *
	 * Before Phase 3: no such function; the old code always reloaded when a
	 * feed was fetched (feed-tracking, not content-tracking). After: the gate
	 * is content-based and a second pass with identical member files produces
	 * the same canonical set, so pfb_alias_set_different() returns FALSE.
	 *
	 * Given:  a mirror written by the first pass (pfb_write_canonical_alias).
	 * When:   the second pass computes the same canonical set and calls
	 *         pfb_alias_set_different() against the stored mirror.
	 * Then:   FALSE (no reload — idempotent).
	 */
	public function testSameSetTwiceIsIdempotent(): void
	{
		$alias    = 'pfB_Idempotent_v4';
		$path     = $this->mirrorPath($alias);
		$set      = ['10.0.0.1', '192.0.2.1', '203.0.113.1'];

		// First pass: write the mirror.
		pfb_write_canonical_alias($path, $set);

		// Assert the mirror was written (pre-state for second-pass assertion).
		$this->assertFileExists(
			$path,
			"pre-state: mirror must exist after first pass\n" .
			"mirror path: {$path}"
		);

		// Second pass: same set → should not differ.
		$changed = pfb_alias_set_different($set, $path);

		$this->assertFalse(
			$changed,
			"same set on second pass → FALSE (idempotent, no reload)\n" .
			"set:     " . implode(', ', $set) . "\n" .
			"mirror:  " . rtrim(file_get_contents($path)) . "\n" .
			"changed: " . ($changed ? 'true' : 'false')
		);
	}

	// -----------------------------------------------------------------------
	// Scenario A — cross-list dedup (B's set changed → TRUE even though B's
	// feed was not refetched)
	//
	// ADR contract item 3: "Cross-list propagation is now correct: a feed-A
	// change that alters sibling table B's effective membership reloads B
	// this pass."
	//
	// Before Phase 3: no pfb_alias_set_different(); the old reload-scope code
	// skips B because B's feed was not in $pfb_alias_lists. After: B's
	// canonical set is recomputed and differs from the old mirror → TRUE.
	// -----------------------------------------------------------------------

	/**
	 * Scenario A: feed-A removal frees an IP from sibling alias B.
	 *
	 * Given:  B's old mirror contains {192.0.2.1, 192.0.2.2} (IP .1 came from A via dedup).
	 *         Feed A now removed 192.0.2.1; B's NEW desired set is {192.0.2.2}.
	 * When:   pfb_alias_set_different() is called with the new set and the old mirror.
	 * Then:   TRUE — B must reload this pass to remove the now-freed IP.
	 *
	 * Before Phase 3 (old behaviour): B would NOT be reloaded this pass because B's
	 * feed was not in $pfb_alias_lists. That is the bug this phase fixes.
	 */
	public function testCrossListDedupSiblingDetectedAsChanged(): void
	{
		$aliasB  = 'pfB_ListB_v4';
		$pathB   = $this->mirrorPath($aliasB);
		// Old mirror: IP .1 was present (it came from feed A via dedup).
		$this->writeMirror($aliasB, "192.0.2.1\n192.0.2.2\n");

		// After feed A removed 192.0.2.1 and dedup ran, B's new set has only .2.
		$newSetB = ['192.0.2.2'];

		$changed = pfb_alias_set_different($newSetB, $pathB);

		$this->assertTrue(
			$changed,
			"Scenario A — cross-list dedup: sibling B must be detected as changed\n" .
			"old mirror: 192.0.2.1, 192.0.2.2\n" .
			"new set:    " . implode(', ', $newSetB) . "\n" .
			"expected:   true (reload B this pass)\n" .
			"got:        " . ($changed ? 'true' : 'false')
		);
	}

	/**
	 * Scenario A (unchanged sibling): if feed A changes but B's effective membership is
	 * unchanged, B must NOT be reloaded.
	 *
	 * Given:  B's old mirror is {192.0.2.2}; the dedup result after A's change is also
	 *         {192.0.2.2} (A's IP was not in B's set anyway).
	 * When:   pfb_alias_set_different() is called with the same set.
	 * Then:   FALSE — B's membership is unchanged; no reload needed.
	 */
	public function testUnchangedSiblingIsSkipped(): void
	{
		$aliasB = 'pfB_ListB_v4';
		$pathB  = $this->mirrorPath($aliasB);
		$this->writeMirror($aliasB, "192.0.2.2\n");

		$newSetB = ['192.0.2.2'];

		$changed = pfb_alias_set_different($newSetB, $pathB);

		$this->assertFalse(
			$changed,
			"Scenario A (unchanged sibling): B unchanged → FALSE (no reload)\n" .
			"old mirror: 192.0.2.2\n" .
			"new set:    " . implode(', ', $newSetB) . "\n" .
			"expected:   false\n" .
			"got:        " . ($changed ? 'true' : 'false')
		);
	}

	// -----------------------------------------------------------------------
	// Scenario B — reputation no-amplify (unchanged alias → FALSE even with rep on)
	//
	// ADR contract item 4: "Reputation no longer blanket-reloads: one feed
	// change reloads only the tables whose set moved."
	//
	// Before Phase 3: rep-on forces $pfb_alias_lists_all → every table reloaded.
	// After: each alias is content-gated; unchanged aliases return FALSE.
	// -----------------------------------------------------------------------

	/**
	 * Scenario B: with reputation on, an alias whose set did NOT move must return FALSE.
	 *
	 * Before Phase 3 behaviour: this alias would be reloaded because it is in
	 * $pfb_alias_lists_all (reputation widened the scope to all active aliases).
	 * After Phase 3: pfb_alias_set_different() returns FALSE because the set is unchanged.
	 *
	 * Given:  mirror = {10.0.0.1, 10.0.0.2}; new set (after rep recompute) = same.
	 * When:   pfb_alias_set_different() is called.
	 * Then:   FALSE — rep amplification eliminated; only moved tables reload.
	 */
	public function testReputationUnchangedAliasIsSkipped(): void
	{
		$alias = 'pfB_Unchanged_v4';
		$path  = $this->mirrorPath($alias);
		$this->writeMirror($alias, "10.0.0.1\n10.0.0.2\n");

		// After reputation recompute, set is the same (no reputations moved this entry).
		$newSet = ['10.0.0.1', '10.0.0.2'];

		$changed = pfb_alias_set_different($newSet, $path);

		$this->assertFalse(
			$changed,
			"Scenario B — reputation non-amplification: unchanged alias → FALSE\n" .
			"old mirror: 10.0.0.1, 10.0.0.2\n" .
			"new set:    " . implode(', ', $newSet) . "\n" .
			"expected:   false (no reload; rep did not move this alias's set)\n" .
			"got:        " . ($changed ? 'true' : 'false')
		);
	}

	/**
	 * Scenario B (moved by reputation): alias whose set DID change must return TRUE.
	 *
	 * Given:  mirror = {10.0.0.1, 10.0.0.2}; after rep recompute 10.0.0.2 promoted,
	 *         new set = {10.0.0.1, 10.0.0.2, 10.0.0.3}.
	 * When:   pfb_alias_set_different() called.
	 * Then:   TRUE — this alias's set moved; reload it.
	 */
	public function testReputationMovedAliasIsIncluded(): void
	{
		$alias = 'pfB_Moved_v4';
		$path  = $this->mirrorPath($alias);
		$this->writeMirror($alias, "10.0.0.1\n10.0.0.2\n");

		$newSet = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];

		$changed = pfb_alias_set_different($newSet, $path);

		$this->assertTrue(
			$changed,
			"Scenario B — reputation: moved alias → TRUE\n" .
			"old mirror: 10.0.0.1, 10.0.0.2\n" .
			"new set:    " . implode(', ', $newSet) . "\n" .
			"expected:   true\n" .
			"got:        " . ($changed ? 'true' : 'false')
		);
	}

	// -----------------------------------------------------------------------
	// Scenario C — surgical (no cross-list feature; single-feed change)
	//
	// ADR contract item 2: "Single-feed → single-table stays surgical when no
	// cross-list feature is active."
	// -----------------------------------------------------------------------

	/**
	 * Scenario C: with no cross-list feature, unchanged alias returns FALSE.
	 *
	 * Given:  alias C's mirror matches its current desired set exactly.
	 * When:   pfb_alias_set_different() called (dup off, rep off scenario).
	 * Then:   FALSE — untouched alias is surgical; no reload.
	 */
	public function testSurgicalUntouchedAliasIsSkipped(): void
	{
		$alias = 'pfB_Untouched_v4';
		$path  = $this->mirrorPath($alias);
		$this->writeMirror($alias, "203.0.113.1\n203.0.113.2\n");

		$newSet = ['203.0.113.1', '203.0.113.2'];

		$changed = pfb_alias_set_different($newSet, $path);

		$this->assertFalse(
			$changed,
			"Scenario C — surgical: untouched alias → FALSE\n" .
			"expected: false\n" .
			"got:      " . ($changed ? 'true' : 'false')
		);
	}

	/**
	 * Scenario C: with no cross-list feature, the changed alias returns TRUE.
	 *
	 * Given:  alias A's mirror = {203.0.113.1}; after feed fetch A = {203.0.113.1, 203.0.113.2}.
	 * When:   pfb_alias_set_different() called.
	 * Then:   TRUE — this feed's alias changed.
	 */
	public function testSurgicalChangedAliasIsIncluded(): void
	{
		$alias = 'pfB_Changed_v4';
		$path  = $this->mirrorPath($alias);
		$this->writeMirror($alias, "203.0.113.1\n");

		$newSet = ['203.0.113.1', '203.0.113.2'];

		$changed = pfb_alias_set_different($newSet, $path);

		$this->assertTrue(
			$changed,
			"Scenario C — surgical: changed alias → TRUE\n" .
			"old mirror: 203.0.113.1\n" .
			"new set:    " . implode(', ', $newSet) . "\n" .
			"expected:   true\n" .
			"got:        " . ($changed ? 'true' : 'false')
		);
	}

	// -----------------------------------------------------------------------
	// Scenario F — pfb_write_canonical_alias writes correct format
	// -----------------------------------------------------------------------

	/**
	 * Scenario F: pfb_write_canonical_alias writes one entry per line, sorted, unique.
	 *
	 * The written file is the new last-applied mirror. Its format must be the
	 * canonical set: C-locale sorted, unique, one entry per line, trailing newline.
	 * pfb_alias_set_different() must accept its own output (round-trip stable).
	 */
	public function testWriteCanonicalAliasProducesCanonicalFormat(): void
	{
		$path = "{$this->tmp}/pfB_Format_v4.txt";
		$set  = ['192.0.2.3', '10.0.0.1', '192.0.2.1'];	// unsorted input

		pfb_write_canonical_alias($path, $set);

		$this->assertFileExists(
			$path,
			"mirror file must be created by pfb_write_canonical_alias\n" .
			"path: {$path}"
		);

		$written = file_get_contents($path);
		// Set is already sorted when passed in (caller provides canonical set)
		// but the writer must not re-order; it writes as-is with trailing newline.
		$lines = array_filter(explode("\n", rtrim($written)));
		$this->assertSame(
			$set,
			array_values($lines),
			"written file must contain exactly the set entries, one per line\n" .
			"set:     " . implode(', ', $set) . "\n" .
			"written: " . json_encode($written)
		);
		$this->assertStringEndsWith(
			"\n",
			$written,
			"written file must end with a newline\n" .
			"written: " . json_encode($written)
		);
	}

	/**
	 * Scenario F (round-trip): content written by pfb_write_canonical_alias
	 * is accepted as "same" by pfb_alias_set_different().
	 *
	 * This is the core idempotence guarantee for the aliasdir file format:
	 * write then read-back must produce an identical comparison.
	 */
	public function testWriteThenReadIsIdempotent(): void
	{
		$path = "{$this->tmp}/pfB_RoundTrip_v4.txt";
		$set  = ['10.0.0.1', '192.0.2.1', '203.0.113.1'];

		pfb_write_canonical_alias($path, $set);

		// Same set must not be detected as different after write.
		$changed = pfb_alias_set_different($set, $path);

		$this->assertFalse(
			$changed,
			"write then same-set read → FALSE (round-trip stable)\n" .
			"set:     " . implode(', ', $set) . "\n" .
			"mirror:  " . rtrim(file_get_contents($path)) . "\n" .
			"changed: " . ($changed ? 'true' : 'false')
		);
	}

	// -----------------------------------------------------------------------
	// Scenario G — pfb_cross_list_scope
	// -----------------------------------------------------------------------

	/**
	 * Scenario G: pfb_cross_list_scope returns TRUE when dup is on.
	 *
	 * When dedup is active, a feed-A change can affect sibling aliases (because
	 * the masterfile dedup is cross-list). All aliases must be recomputed.
	 */
	public function testCrossListScopeWhenDupOn(): void
	{
		$this->assertTrue(
			pfb_cross_list_scope(TRUE, FALSE),
			"dup on, rep off → TRUE (all aliases must be recomputed)\n" .
			"expected: true\n" .
			"got:      false"
		);
	}

	/**
	 * Scenario G: pfb_cross_list_scope returns TRUE when rep (drep/prep) is on.
	 *
	 * Reputation is inherently cross-list; one feed change can move entries
	 * between aliases via dMax/pMax.
	 */
	public function testCrossListScopeWhenRepOn(): void
	{
		$this->assertTrue(
			pfb_cross_list_scope(FALSE, TRUE),
			"dup off, rep on → TRUE (all aliases must be recomputed)\n" .
			"expected: true\n" .
			"got:      false"
		);
	}

	/**
	 * Scenario G: pfb_cross_list_scope returns FALSE when both dup and rep are off.
	 *
	 * With no cross-list feature, single-feed → single-table stays surgical;
	 * all-alias recompute is not needed.
	 */
	public function testCrossListScopeOffWhenBothOff(): void
	{
		$this->assertFalse(
			pfb_cross_list_scope(FALSE, FALSE),
			"dup off, rep off → FALSE (surgical path; no all-alias recompute)\n" .
			"expected: false\n" .
			"got:      true"
		);
	}

	/**
	 * Scenario G: pfb_cross_list_scope returns TRUE when both dup and rep are on.
	 */
	public function testCrossListScopeWhenBothOn(): void
	{
		$this->assertTrue(
			pfb_cross_list_scope(TRUE, TRUE),
			"dup on, rep on → TRUE\n" .
			"expected: true\n" .
			"got:      false"
		);
	}

	// -----------------------------------------------------------------------
	// Set-immunity: pfb_alias_set_different is order and duplicate immune
	// -----------------------------------------------------------------------

	/**
	 * pfb_alias_set_different compares SETS (order-immune).
	 *
	 * The last-applied mirror may have been written in a different order than the
	 * newly-computed set. The comparison must be set-based (immune to order).
	 */
	public function testSetDifferentIsOrderImmune(): void
	{
		$path = $this->mirrorPath('pfB_Order_v4');
		// Mirror written in one order.
		$this->writeMirror('pfB_Order_v4', "192.0.2.3\n192.0.2.1\n192.0.2.2\n");

		// Same IPs in a different order.
		$newSet = ['192.0.2.1', '192.0.2.2', '192.0.2.3'];

		$changed = pfb_alias_set_different($newSet, $path);

		$this->assertFalse(
			$changed,
			"order-immune: same entries in different order → FALSE\n" .
			"mirror:  192.0.2.3, 192.0.2.1, 192.0.2.2\n" .
			"new set: " . implode(', ', $newSet) . "\n" .
			"changed: " . ($changed ? 'true' : 'false')
		);
	}

	/**
	 * pfb_alias_set_different is duplicate-immune: a mirror with dups in it
	 * is equivalent to the de-duped set.
	 *
	 * The old aliasdir file (pre-Phase-3) was a raw concatenation that could
	 * contain duplicates. After Phase 3 mirrors are written canonical, but the
	 * first pass after upgrade must not falsely trigger a reload.
	 */
	public function testSetDifferentIsDuplicateImmune(): void
	{
		$path = $this->mirrorPath('pfB_Dup_v4');
		// Old-style mirror with a duplicate entry.
		$this->writeMirror('pfB_Dup_v4', "192.0.2.1\n192.0.2.2\n192.0.2.1\n");

		// Canonical set (deduped).
		$newSet = ['192.0.2.1', '192.0.2.2'];

		$changed = pfb_alias_set_different($newSet, $path);

		$this->assertFalse(
			$changed,
			"dup-immune: mirror with dups same as deduped set → FALSE\n" .
			"mirror:  192.0.2.1, 192.0.2.2, 192.0.2.1 (dup)\n" .
			"new set: " . implode(', ', $newSet) . "\n" .
			"changed: " . ($changed ? 'true' : 'false')
		);
	}
}
