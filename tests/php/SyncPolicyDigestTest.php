<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3450 — pfb_sync_policy_digest(): a stable sha256 of a policy projection, so two
 * nodes holding the same policy compare equal and any policy change moves the digest
 * (docs/specs/xmlrpc-per-field-sync.md, "Policy projection").
 *
 * The digest rebuilds the projection into a tree over the 19 synced sections, canonicalises
 * it (map keys sorted, lists by position, '' for every empty leaf) and hashes serialize().
 * It is order-insensitive for map keys and order-sensitive for row and feed lists, which is
 * exactly the difference between "same settings" and "same rule order". Local content never
 * reaches it because it is not in the projection in the first place (E7 proves the chain).
 */
#[CoversFunction('pfb_sync_policy_digest')]
#[CoversFunction('pfb_sync_policy_projection')]
final class SyncPolicyDigestTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private const SKIPFEED = 'installedpackages/pfblockerng/config/0/skipfeed';

	/** @param array<string,mixed> $projection */
	private function digest(array $projection): string
	{
		return $this->assertNoDiagnostics(static fn (): string => pfb_sync_policy_digest($projection));
	}

	/** @return array<string,mixed> */
	private function project(array $sections): array
	{
		return $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_projection($sections));
	}

	private static function isIntKeyed(array $node): bool
	{
		foreach (array_keys($node) as $key) {
			if (!is_int($key)) {
				return FALSE;
			}
		}
		return TRUE;
	}

	/** Reverses every map's key order; leaves lists (integer-keyed arrays) in position order. */
	private static function reverseMaps(mixed $node): mixed
	{
		if (!is_array($node)) {
			return $node;
		}
		if (!self::isIntKeyed($node)) {
			$node = array_reverse($node, TRUE);
		}
		return array_map(static fn (mixed $child): mixed => self::reverseMaps($child), $node);
	}

	/** @return array<string,mixed> a two-row category section: feed rows carry two feed URLs each */
	private static function rowsSection(array $rows): array
	{
		return ['pfblockernglistsv4' => ['config' => $rows]];
	}

	/** @return array<string,mixed> */
	private static function row(string $name, string $firstFeed, string $secondFeed): array
	{
		return [
			'aliasname' => $name,
			'action'    => 'Deny_Inbound',
			'row'       => [0 => ['url' => $firstFeed], 1 => ['url' => $secondFeed]],
		];
	}

	// E1 -- a 64-character lowercase hex sha256, deterministic.
	public function testDigestIsLowercaseSha256HexAndDeterministic(): void
	{
		$projection = $this->project(self::diskFixture()['sections']);
		$this->assertNotEmpty($projection, 'vacuity guard');

		$digest = $this->digest($projection);

		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $digest);
		$this->assertSame($digest, $this->digest($projection));
	}

	// E1 (pin) -- the canonical form is exactly serialize() of the hand-built section tree.
	public function testDigestEqualsSha256OfTheCanonicalSectionTree(): void
	{
		$projection = [
			'installedpackages/pfblockerng/config/0/skipfeed'          => '3',
			'installedpackages/pfblockerng/config/0/enable_cb'         => 'on',
			'installedpackages/pfblockerngdnsbl/config/1/aliasname'    => 'B',
			'installedpackages/pfblockerngdnsbl/config/0/aliasname'    => 'A',
			'installedpackages/pfblockerngsafesearch/safesearch_enable' => [],
		];

		$tree = array_fill_keys(pfblockerng_sync_sections(TRUE), []);
		// Map keys sorted; the row list keeps position order (config/1 was listed first), indices renumbered.
		$tree['pfblockerng']            = ['config' => [0 => ['enable_cb' => 'on', 'skipfeed' => '3']]];
		$tree['pfblockerngdnsbl']       = ['config' => [0 => ['aliasname' => 'B'], 1 => ['aliasname' => 'A']]];
		$tree['pfblockerngsafesearch']  = ['safesearch_enable' => ''];

		$this->assertSame(hash('sha256', serialize($tree)), $this->digest($projection));
	}

	// E2 -- map key order does not matter, inside config/0 maps or across sections.
	public function testMapKeyOrderDoesNotChangeTheDigest(): void
	{
		$sections = self::diskFixture()['sections'];
		$shuffled = self::reverseMaps($sections);

		$original = $this->project($sections);
		$reordered = $this->project($shuffled);
		$this->assertNotSame($original, $reordered, 'before-state: the shuffled input projects in a different key order');
		$this->assertSame(
			$original,
			array_replace(array_fill_keys(array_keys($original), NULL), $reordered),
			'before-state: the same leaves are present, only their order moved'
		);

		$this->assertSame($this->digest($original), $this->digest($reordered));
	}

	// E2 -- an array that mixes integer and string keys is a map, so its order is irrelevant too.
	public function testMixedIntegerAndStringKeysAreTreatedAsAMap(): void
	{
		$a = [
			'installedpackages/pfblockerngsafesearch/k/0' => 'a',
			'installedpackages/pfblockerngsafesearch/k/x' => 'b',
		];
		$b = array_reverse($a, TRUE);
		$this->assertNotSame($a, $b, 'before-state: the two projections list the leaves in a different order');

		$this->assertSame($this->digest($a), $this->digest($b));
	}

	// E3 -- group row order is significant: the same rows in another order are another policy.
	public function testGroupRowOrderIsSignificant(): void
	{
		$x = self::row('X', 'https://x.example/a', 'https://x.example/b');
		$y = self::row('Y', 'https://y.example/a', 'https://y.example/b');

		$inOrder      = $this->project(self::rowsSection([0 => $x, 1 => $y]));
		$swapped      = $this->project(self::rowsSection([0 => $y, 1 => $x]));
		$storedSwapped = $this->project(self::rowsSection([1 => $y, 0 => $x]));

		$this->assertNotSame($inOrder, $swapped, 'before-state: swapped rows project differently');
		$this->assertNotSame($this->digest($inOrder), $this->digest($swapped));

		$this->assertNotSame($inOrder, $storedSwapped, 'before-state: a stored-order swap projects in another order');
		$this->assertNotSame($this->digest($inOrder), $this->digest($storedSwapped),
			'row order, not only row content, is part of the digest');
	}

	// E3 -- the feed row order inside one group row is significant too.
	public function testFeedRowOrderIsSignificant(): void
	{
		$ab = $this->project(self::rowsSection([0 => self::row('X', 'https://x.example/a', 'https://x.example/b')]));
		$ba = $this->project(self::rowsSection([0 => self::row('X', 'https://x.example/b', 'https://x.example/a')]));

		$this->assertNotSame($ab, $ba, 'before-state: swapped feeds project differently');
		$this->assertNotSame($this->digest($ab), $this->digest($ba));
	}

	// E4 -- gaps in row indices carry no meaning: rows 0 and 2 equal rows 0 and 1.
	public function testIndexGapsAreIgnored(): void
	{
		$x = self::row('X', 'https://x.example/a', 'https://x.example/b');
		$y = self::row('Y', 'https://y.example/a', 'https://y.example/b');

		$gapped  = $this->project(self::rowsSection([0 => $x, 2 => $y]));
		$compact = $this->project(self::rowsSection([0 => $x, 1 => $y]));

		$this->assertNotSame($gapped, $compact, 'before-state: the two projections use different paths');
		$this->assertSame($this->digest($compact), $this->digest($gapped));
	}

	// E5 -- an empty array leaf and an empty string leaf are the same stored element.
	public function testEmptyArrayLeafEqualsEmptyStringLeaf(): void
	{
		$this->assertSame(
			$this->digest([self::SKIPFEED => '']),
			$this->digest([self::SKIPFEED => []])
		);
	}

	// E6 -- a changed value, an added leaf, and '' versus absent each move the digest.
	public function testPolicyChangesMoveTheDigest(): void
	{
		$other = 'installedpackages/pfblockerng/config/0/pfb_agg_types';
		$base  = [self::SKIPFEED => '3', $other => 'Deny'];

		$digests = [
			'base'          => $this->digest($base),
			'value changed' => $this->digest([self::SKIPFEED => '4', $other => 'Deny']),
			'leaf added'    => $this->digest($base + ['installedpackages/pfblockerng/config/0/enable_cb' => 'on']),
			'leaf absent'   => $this->digest([self::SKIPFEED => '3']),
			'leaf empty'    => $this->digest([self::SKIPFEED => '3', $other => '']),
		];

		$this->assertSame($digests['base'], $this->digest($base), 'before-state: the baseline is stable');
		$this->assertCount(5, array_unique($digests), 'every one of these policies must have its own digest: ' . json_encode($digests));
	}

	// E7 -- content that is not policy cannot move the digest, end to end through the projection.
	public function testNonPolicyContentDoesNotMoveTheDigest(): void
	{
		$a = self::diskFixture();
		$b = self::diskFixture('~NODE-B');

		$this->assertNotSame($a['sections'], $b['sections'], 'before-state: the nodes differ in stored content');
		$this->assertNotSame($a['nonpolicy'], $b['nonpolicy'], 'before-state: every local/credential/unknown/hook/sync value differs');
		$this->assertSame($a['policy'], $b['policy'], 'before-state: only non-policy leaves differ');

		$digestA = $this->digest($this->project($a['sections']));
		$this->assertSame($digestA, $this->digest($this->project($b['sections'])));

		$changed = $a['sections'];
		$changed['pfblockerng']['config'][0]['skipfeed'] = 'a-policy-change';
		$this->assertNotSame($digestA, $this->digest($this->project($changed)),
			'control: the same fixture with one policy leaf changed must move the digest');
	}

	// E8 -- no policy at all is one digest, however it arises.
	public function testEmptyProjectionAndProjectionOfEmptySectionsShareOneDigest(): void
	{
		$empty = $this->digest([]);

		$this->assertSame(hash('sha256', serialize(array_fill_keys(pfblockerng_sync_sections(TRUE), []))), $empty);
		$this->assertSame($empty, $this->digest($this->project([
			'pfblockerng'           => [],
			'pfblockerngipsettings' => ['config' => [0 => []]],
			'pfblockernglistsv4'    => '',
			'pfblockerngsafesearch' => NULL,
		])));
		$this->assertNotSame($empty, $this->digest([self::SKIPFEED => '3']), 'control: one leaf must move it');
	}

	// E9 -- paths outside the 19 sections, without the installedpackages root, or without a leaf do not count.
	public function testPathsOutsideTheSyncedSectionsDoNotMoveTheDigest(): void
	{
		$base = [self::SKIPFEED => '3'];
		$noise = [
			'installedpackages/pfblockerngsync/config/0/syncscope'   => 'policy',
			'installedpackages/pfblockerngbogus/config/0/x'          => 'y',
			'pfblockerng/config/0/pfb_agg_types'                     => 'no root',
			'InstalledPackages/pfblockerng/config/0/pfb_agg_types'   => 'wrong case root',
			'installedpackages'                                      => 'single segment',
			'installedpackages/pfblockerng'                          => 'section without a leaf',
			''                                                       => 'empty path',
		];

		$this->assertNotSame($base, $base + $noise, 'before-state: the noisy projection really carries extra paths');
		$this->assertSame($this->digest($base), $this->digest($base + $noise));
		$this->assertSame($this->digest([]), $this->digest($noise), 'on their own the ignored paths equal the empty digest');
	}

	// Hostile values: newlines, binary and 64 KiB strings hash stably, and every byte counts.
	public function testHostileValuesHashStablyAndEveryByteCounts(): void
	{
		$path = 'installedpackages/pfblockerngsafesearch/blob';
		foreach ([
			'newlines' => "line1\nline2\r\n",
			'binary'   => "\x01\x02\xfe\xff\x7f",
			'long'     => str_repeat('A', 65536) . 'tail',
		] as $label => $value) {
			$digest = $this->digest([$path => $value]);
			$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $digest, $label);
			$this->assertSame($digest, $this->digest([$path => $value]), "{$label}: stable");
			$this->assertNotSame($digest, $this->digest([$path => $value . "\n"]), "{$label}: a trailing byte moves it");
		}
		$this->assertNotSame(
			$this->digest([$path => str_repeat('A', 65536) . 'tail']),
			$this->digest([$path => str_repeat('A', 65536) . 'tell']),
			'the last byte of a 64 KiB value is covered'
		);
	}

	// Hostile paths: a path that is both a leaf and a parent is accepted without a diagnostic and hashes stably.
	public function testConflictingLeafAndParentPathsStillHashStably(): void
	{
		$conflict = [
			'installedpackages/pfblockerngsafesearch/a'   => 'x',
			'installedpackages/pfblockerngsafesearch/a/b' => 'y',
		];

		$digest = $this->digest($conflict);

		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $digest);
		$this->assertSame($digest, $this->digest($conflict));
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $this->digest(array_reverse($conflict, TRUE)));
	}
}
