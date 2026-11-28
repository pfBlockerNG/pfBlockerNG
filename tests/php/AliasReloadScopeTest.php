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
 *   pfb_rule_change_keep_aliases(array $registered): array
 *   pfb_concat_member_files(array $member_paths): string
 *   pfb_canonical_alias_set(string $member_content): array   [Phase 1: dead in live path]
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
#[CoversFunction('pfb_rule_change_keep_aliases')]
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
	// pfb_rule_change_keep_aliases — rule-change cleanup scope
	// -----------------------------------------------------------------------

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
