<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-40 Phase 1 — oracle-pin the reload-scope selection and final-file construction helpers
 * extracted from sync_package_pfblockerng().
 *
 * This is BEHAVIOUR-PRESERVING prep: the helpers encapsulate today's inline logic.
 * Every test must pass against BOTH the original inline code and the extracted helpers —
 * they are oracle tests, not red→green tests. Any failure here means the extraction
 * changed behaviour, which is a bug.
 *
 * Helpers under test:
 *   pfb_select_reload_aliases($rep_enabled, $alias_lists, $alias_lists_all, $active_aliases=null)
 *   pfb_concat_member_files(array $member_paths): string
 *   pfb_canonical_alias_set(string $member_content): array   [Phase 1: dead in live path]
 *
 * Coverage: every branch of pfb_select_reload_aliases:
 *   - reputation off  → uses $alias_lists
 *   - reputation on   → uses $alias_lists_all
 *   - active_aliases null  → no intersect (file-write and no-rule-change paths)
 *   - active_aliases set   → intersect applied (rule-change path)
 *   - duplicates in inputs → array_unique applied
 *   - empty alias_lists with rep off → empty result
 *   - empty alias_lists_all with rep on → empty result
 *
 * Coverage of pfb_concat_member_files:
 *   - multiple member paths in order → bytes concatenated in order
 *   - a missing path is silently skipped
 *   - single feed
 *
 * Coverage of pfb_canonical_alias_set (Phase 1 dead-code test):
 *   - same input twice → identical bytes (determinism)
 *   - set-equality immune to input order and duplicates
 *   - blank lines and comments stripped
 *   - empty input → []
 */
#[CoversFunction('pfb_select_reload_aliases')]
#[CoversFunction('pfb_concat_member_files')]
#[CoversFunction('pfb_canonical_alias_set')]
final class AliasReloadScopeTest extends TestCase
{
	/** @var string Per-test temp dir for member files. */
	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_adr40_p1_' . getmypid() . '_' . uniqid();
		@mkdir($this->tmp, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->tmp}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->tmp);
	}

	/** Write $content to a temp file and return its path. */
	private function makeFile(string $name, string $content): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, $content);
		return $path;
	}

	// -----------------------------------------------------------------------
	// pfb_select_reload_aliases — reload-scope oracle
	// -----------------------------------------------------------------------

	/**
	 * Oracle: reputation off → reload set = $alias_lists (the changed feeds only).
	 *
	 * Pins the $pfb_alias_lists branch (pfblockerng.inc former lines 14416–14419,
	 * 15013–15015, etc.). Only feeds that were actually (re)fetched this pass are reloaded.
	 * Irrelevant whether the "all" list is populated — with rep off it is ignored.
	 *
	 * Before: code was inline. After: pfb_select_reload_aliases() returns same result.
	 */
	public function testReputationOffUsesAliasList(): void
	{
		$lists    = ['pfB_FeedA_v4', 'pfB_FeedB_v4'];
		$all      = ['pfB_FeedA_v4', 'pfB_FeedB_v4', 'pfB_FeedC_v4'];

		$result = pfb_select_reload_aliases(FALSE, $lists, $all);

		$this->assertSame(
			['pfB_FeedA_v4', 'pfB_FeedB_v4'],
			$result,
			'rep off: only the changed feeds are in the reload set; the "all" list is ignored'
		);
	}

	/**
	 * Oracle: reputation on → reload set = $alias_lists_all (every active alias).
	 *
	 * Pins the $pfb_alias_lists_all branch (pfblockerng.inc former lines 14412–14414, etc.).
	 * One feed change + rep on = all aliases reloaded. The "changed" list is present but ignored.
	 *
	 * Before: code was inline. After: pfb_select_reload_aliases() returns same result.
	 */
	public function testReputationOnUsesAliasListAll(): void
	{
		$lists    = ['pfB_FeedA_v4'];
		$all      = ['pfB_FeedA_v4', 'pfB_FeedB_v4', 'pfB_FeedC_v4'];

		$result = pfb_select_reload_aliases(TRUE, $lists, $all);

		$this->assertSame(
			['pfB_FeedA_v4', 'pfB_FeedB_v4', 'pfB_FeedC_v4'],
			$result,
			'rep on: ALL active aliases are in the reload set even though only one feed changed'
		);
	}

	/**
	 * Oracle (rule-change pfctl path): active_aliases set → result is intersected.
	 *
	 * Pins the array_intersect applied in the rule-change branch (pfblockerng.inc former
	 * lines 14958–14963). Only aliases that are both in the reload set AND in $pfb_active_aliases
	 * survive. An alias in $alias_lists_all but NOT in $pfb_active_aliases is excluded.
	 *
	 * Before: code was inline. After: pfb_select_reload_aliases() returns same result.
	 */
	public function testActiveAliasesIntersectApplied(): void
	{
		$lists   = ['pfB_FeedA_v4'];
		$all     = ['pfB_FeedA_v4', 'pfB_FeedB_v4', 'pfB_FeedC_v4'];
		// Only A and B are in the active (wired firewall rule) set; C was removed.
		$active  = ['pfB_FeedA_v4', 'pfB_FeedB_v4'];

		// rep on + active set = intersect of all ∩ active
		$result = pfb_select_reload_aliases(TRUE, $lists, $all, $active);

		$this->assertNotContains('pfB_FeedC_v4', $result,
			'C is in alias_lists_all but not active — must be excluded by the intersect');
		$this->assertContains('pfB_FeedA_v4', $result);
		$this->assertContains('pfB_FeedB_v4', $result);
		$this->assertSame(2, count($result));
	}

	/**
	 * Rule-change cleanup keeps registered aggregate tables without reviving orphan tables.
	 *
	 * Aggregates are urltable aliases with no firewall rule by design, so they must be kept
	 * separately from the rule-referenced active set while filter_configure() rebuilds tables.
	 */
	public function testRuleChangeKeepsSelectedAggregatesButKillsOrphans(): void
	{
		$registered = [
			'pfB_Deny_Aggregated_v4',
			'pfB_Deny_Aggregated_v6',
			'pfB_Orphan_v4',
			'pfB_Custom_Aggregated_v4',
		];

		$result = pfb_rule_change_keep_aliases($registered);

		$this->assertSame(
			['pfB_Deny_Aggregated_v4', 'pfB_Deny_Aggregated_v6'],
			$result,
			'selected aggregate tables survive cleanup, while non-aggregate tables still require a rule'
		);
	}


	/**
	 * Oracle: active_aliases null → no intersect (file-write and no-rule-change paths).
	 *
	 * The two call sites that do NOT intersect pass null (default). The result is the
	 * full reputation-selected set with no further filtering.
	 */
	public function testNullActiveAliasesSkipsIntersect(): void
	{
		$lists   = ['pfB_FeedA_v4', 'pfB_FeedB_v4'];
		$all     = ['pfB_FeedA_v4', 'pfB_FeedB_v4', 'pfB_FeedC_v4'];

		// rep on, no active filter
		$result = pfb_select_reload_aliases(TRUE, $lists, $all, null);

		$this->assertSame(
			['pfB_FeedA_v4', 'pfB_FeedB_v4', 'pfB_FeedC_v4'],
			$result,
			'null active_aliases = no intersect; all three aliases returned'
		);
	}

	/**
	 * Oracle: duplicates in inputs are collapsed by array_unique.
	 *
	 * The inline code applied array_unique() before the result. The helper must do the same.
	 */
	public function testDuplicatesInInputsAreCollapsed(): void
	{
		// Both $alias_lists and $alias_lists_all have a duplicate entry.
		$lists   = ['pfB_FeedA_v4', 'pfB_FeedA_v4', 'pfB_FeedB_v4'];
		$all     = ['pfB_FeedA_v4', 'pfB_FeedA_v4', 'pfB_FeedC_v4'];

		$resultRep  = pfb_select_reload_aliases(TRUE, $lists, $all);
		$resultNoRep = pfb_select_reload_aliases(FALSE, $lists, $all);

		// Rep on: pfB_FeedA_v4 appears once, not twice.
		$this->assertSame(
			['pfB_FeedA_v4', 'pfB_FeedC_v4'],
			array_values($resultRep),
			'rep on: duplicate in alias_lists_all collapsed'
		);
		// Rep off: pfB_FeedA_v4 appears once, not twice.
		$this->assertSame(
			['pfB_FeedA_v4', 'pfB_FeedB_v4'],
			array_values($resultNoRep),
			'rep off: duplicate in alias_lists collapsed'
		);
	}

	/**
	 * Oracle: empty $alias_lists with rep off → empty result (no aliases to reload).
	 *
	 * A pass where no feeds were fetched and rep is off produces no reload work.
	 */
	public function testEmptyAliasListsWithRepOffYieldsEmpty(): void
	{
		$result = pfb_select_reload_aliases(FALSE, [], ['pfB_FeedA_v4']);

		$this->assertSame(
			[],
			$result,
			'rep off + empty changed-list = nothing to reload (no-change pass)'
		);
	}

	/**
	 * Oracle: empty $alias_lists_all with rep on → empty result.
	 *
	 * No active aliases means nothing to include even when rep is on.
	 */
	public function testEmptyAliasListsAllWithRepOnYieldsEmpty(): void
	{
		$result = pfb_select_reload_aliases(TRUE, ['pfB_FeedA_v4'], []);

		$this->assertSame(
			[],
			$result,
			'rep on + empty all-list = nothing to reload'
		);
	}

	/**
	 * Oracle: rep off with active_aliases set → intersect with changed list, NOT all list.
	 *
	 * Confirms the rep-off branch uses $alias_lists even when $active_aliases is passed.
	 */
	public function testRepOffWithActiveAliasesIntersectsChangedList(): void
	{
		$lists  = ['pfB_FeedA_v4', 'pfB_FeedB_v4'];
		$all    = ['pfB_FeedA_v4', 'pfB_FeedB_v4', 'pfB_FeedC_v4'];
		$active = ['pfB_FeedA_v4'];          // B not in active, C in active (but C not changed)

		$result = pfb_select_reload_aliases(FALSE, $lists, $all, $active);

		// changed ∩ active = [A only]; B changed but not active; C active but not changed.
		$this->assertContains('pfB_FeedA_v4', $result);
		$this->assertNotContains('pfB_FeedB_v4', $result,
			'B is changed but not active — excluded by intersect');
		$this->assertNotContains('pfB_FeedC_v4', $result,
			'C is active but not changed — not in changed list');
		$this->assertSame(1, count($result));
	}

	// -----------------------------------------------------------------------
	// pfb_concat_member_files — final-file construction oracle
	// -----------------------------------------------------------------------

	/**
	 * Oracle: multiple member files concatenated in order, preserving duplicates.
	 *
	 * Pins pfblockerng.inc:14460 / :14481 — $alias_ips .= file_get_contents(...).
	 * Content is joined in iteration order with NO dedup. A moved IP (in both A and B)
	 * appears twice in the output. Order is the source-of-truth for the current aliasdir file.
	 *
	 * Before: inline .= loop. After: pfb_concat_member_files() returns identical bytes.
	 */
	public function testMultipleMemberFilesAreConcatenatedInOrder(): void
	{
		$pA = $this->makeFile('feedA_v4.txt', "192.0.2.1\n192.0.2.2\n");
		$pB = $this->makeFile('feedB_v4.txt', "192.0.2.3\n192.0.2.1\n");	// 192.0.2.1 in both

		$got = pfb_concat_member_files([$pA, $pB]);

		$expected = "192.0.2.1\n192.0.2.2\n192.0.2.3\n192.0.2.1\n";
		$this->assertSame(
			$expected,
			$got,
			"content concatenated in file order; duplicate 192.0.2.1 appears twice (no dedup in current path)\n" .
			"expected: " . json_encode($expected) . "\n" .
			"got:      " . json_encode($got)
		);
	}

	/**
	 * Oracle: a missing member file path is silently skipped.
	 *
	 * The inline code was gated on file_exists() (pfblockerng.inc:14446). A missing file
	 * does not abort; the remaining members are still concatenated.
	 */
	public function testMissingMemberFileIsSilentlySkipped(): void
	{
		$pA      = $this->makeFile('feedA_v4.txt', "10.0.0.1\n");
		$missing = "{$this->tmp}/does_not_exist.txt";
		$pC      = $this->makeFile('feedC_v4.txt', "10.0.0.3\n");

		$got = pfb_concat_member_files([$pA, $missing, $pC]);

		$expected = "10.0.0.1\n10.0.0.3\n";
		$this->assertSame(
			$expected,
			$got,
			"missing path skipped; remaining files present\n" .
			"expected: " . json_encode($expected) . "\n" .
			"got:      " . json_encode($got)
		);
	}

	/**
	 * Oracle: single member file → its content returned verbatim.
	 */
	public function testSingleMemberFileReturnsItsContent(): void
	{
		$p = $this->makeFile('solo_v4.txt', "203.0.113.42\n");

		$this->assertSame("203.0.113.42\n", pfb_concat_member_files([$p]));
	}

	/**
	 * Oracle: no paths → empty string.
	 */
	public function testEmptyPathListReturnsEmptyString(): void
	{
		$this->assertSame('', pfb_concat_member_files([]));
	}

	// -----------------------------------------------------------------------
	// pfb_canonical_alias_set — Phase 1 dead-code tests
	//
	// This helper is NOT wired into the live reload path in Phase 1.
	// These tests pin its contract so Phase 3 can wire it safely.
	// -----------------------------------------------------------------------

	/**
	 * Determinism: identical input → identical output bytes (same-input-twice idempotence).
	 *
	 * A content-addressed gate is only sound if the canonical form is byte-stable for
	 * fixed inputs. Pinning this here guards against future non-determinism.
	 */
	public function testCanonicalSetIsDeterministicForSameInput(): void
	{
		$content = "192.0.2.3\n192.0.2.1\n192.0.2.2\n";

		$first  = pfb_canonical_alias_set($content);
		$second = pfb_canonical_alias_set($content);

		$this->assertSame(
			$first,
			$second,
			"same input → identical canonical set both times\n" .
			"first:  " . implode(', ', $first) . "\n" .
			"second: " . implode(', ', $second)
		);
	}

	/**
	 * Order immunity: input order does not affect the canonical set.
	 *
	 * A set comparison that is immune to order requires that the canonical form is
	 * order-independent. Two inputs that are permutations of each other must produce
	 * the same output.
	 */
	public function testCanonicalSetIsOrderIndependent(): void
	{
		$contentA = "192.0.2.3\n192.0.2.1\n192.0.2.2\n";
		$contentB = "192.0.2.1\n192.0.2.3\n192.0.2.2\n";

		$setA = pfb_canonical_alias_set($contentA);
		$setB = pfb_canonical_alias_set($contentB);

		$this->assertSame(
			$setA,
			$setB,
			"permuted input → same canonical set\n" .
			"setA: " . implode(', ', $setA) . "\n" .
			"setB: " . implode(', ', $setB)
		);
	}

	/**
	 * Duplicate immunity: duplicates in the member content are collapsed to one entry.
	 *
	 * A moved IP (from feed A to feed B, both still in the alias) appears twice in the
	 * concatenated input; the canonical set contains it once.
	 */
	public function testCanonicalSetCollapsesDuplicates(): void
	{
		// 192.0.2.1 appears in both feeds (cross-member dup — the current path preserves it).
		$content = "192.0.2.1\n192.0.2.2\n192.0.2.1\n192.0.2.3\n";

		$set = pfb_canonical_alias_set($content);

		$this->assertSame(
			1,
			count(array_filter($set, static fn($e) => $e === '192.0.2.1')),
			"duplicate 192.0.2.1 collapsed to one entry\n" .
			"canonical set: " . implode(', ', $set)
		);
	}

	/**
	 * C-locale sort: entries are in byte-order (strcmp) ascending order.
	 *
	 * IPs are machine data; LC_ALL=C sort -u (ADR-26) gives byte-stable ordering.
	 * Verified by asserting the concrete sort order for a known input.
	 */
	public function testCanonicalSetIsCLocaleSorted(): void
	{
		// In byte (strcmp) order: '10.0.0.1' < '192.0.2.1' < '9.0.0.1' (because '1' < '9' < '9'+...
		// actually in strcmp: '1' (0x31) < '9' (0x39), so '10.0.0.1' < '192.0.2.1' < '9.0.0.1'
		$content = "9.0.0.1\n192.0.2.1\n10.0.0.1\n";

		$set = pfb_canonical_alias_set($content);

		$this->assertSame(
			['10.0.0.1', '192.0.2.1', '9.0.0.1'],
			$set,
			"entries in C-locale (strcmp) byte order\n" .
			"got: " . implode(', ', $set)
		);
	}

	/**
	 * Blank lines and comments stripped: empty lines and '#'-prefixed lines do not appear.
	 */
	public function testCanonicalSetStripsBlankLinesAndComments(): void
	{
		$content = "# a comment\n192.0.2.1\n\n192.0.2.2\n# another\n";

		$set = pfb_canonical_alias_set($content);

		$this->assertNotContains('', $set, 'blank lines stripped');
		$this->assertNotContains('# a comment', $set, 'comment line stripped');
		$this->assertNotContains('# another', $set, 'second comment stripped');
		$this->assertSame(['192.0.2.1', '192.0.2.2'], $set,
			"only the two real IPs remain\ngot: " . implode(', ', $set));
	}

	/**
	 * Empty input → empty array (nothing to sort or dedup).
	 */
	public function testCanonicalSetEmptyInputYieldsEmptyArray(): void
	{
		$this->assertSame([], pfb_canonical_alias_set(''));
	}
}
