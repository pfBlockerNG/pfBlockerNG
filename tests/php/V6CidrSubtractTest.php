<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-53 Phase 5 -- the pure IPv6 CIDR set-subtraction engine.
 *
 * IPv6 suppression can't carve by host enumeration (a /64 minus a /128 hole is
 * 2^64 hosts) and `iprange` mangles v6 input outright, so this engine performs
 * an exact set subtraction over fixed-width 128-bit binary-string ranges and
 * emits the minimal covering-CIDR remainder via pfSense's own
 * ip_range_to_subnet_array() (a faithful, vector-pinned double stands in for
 * it here -- see pfsense_doubles.php).
 *
 * Functions under test:
 *   pfb_cidr_subtract_v6(array $cidrs, array $holes, ?array &$errors): array
 *   pfb_suppress_file_v6(string $file, string $suppfile): bool
 *
 * All expected covering-CIDR counts/shapes below were independently verified
 * against a from-scratch Python port of the algorithm (arbitrary-precision
 * integers make hand-checking the bit math tractable) before being pinned
 * here -- they are not merely "whatever the code happens to produce".
 */
#[CoversFunction('pfb_cidr_subtract_v6')]
#[CoversFunction('pfb_suppress_file_v6')]
final class V6CidrSubtractTest extends TestCase
{
	// =========================================================================
	// pfb_cidr_subtract_v6 -- known vectors
	// =========================================================================

	/**
	 * The headline ADR-53 §1.2 measurement: subtracting a single /128 host from
	 * a containing /64 costs exactly 64 covering CIDRs (vs 2^64 by host
	 * enumeration) -- the hole itself is absent, but its immediate siblings
	 * remain covered (proving this is a real carve, not an over-broad drop).
	 */
	public function testContainingSlash64MinusSlash128CarvesExactlySixtyFourCoveringCidrs(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8::/64'], ['2001:db8::5353/128'], $errors);

		$this->assertCount(64, $result, 'a /64 minus one /128 hole must decompose into exactly 64 covering CIDRs (ADR-53 §1.2)');
		$this->assertSame([], $errors);

		$this->assertNotContains('2001:db8::5353/128', $result, 'the suppressed host itself must not appear as its own entry');
		$this->assertTrue(
			$this->anyCidrContains($result, '2001:db8::5352'),
			'the sibling just below the hole must still be covered'
		);
		$this->assertTrue(
			$this->anyCidrContains($result, '2001:db8::5354'),
			'the sibling just above the hole must still be covered'
		);
		$this->assertFalse(
			$this->anyCidrContains($result, '2001:db8::5353'),
			'the suppressed host must not be covered by ANY output CIDR'
		);
	}

	/** A hole identical to the entry removes it entirely -- not a partial carve. */
	public function testHoleEqualToEntryRemovesEntryEntirely(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8::/64'], ['2001:db8::/64'], $errors);

		$this->assertSame([], $result);
		$this->assertSame([], $errors);
	}

	/** A hole with no intersection leaves the entry set-wise unchanged. */
	public function testHoleOutsideEveryEntryLeavesInputUnchanged(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8::/64'], ['2001:dba::1/128'], $errors);

		$this->assertSame(['2001:db8::/64'], $result);
		$this->assertSame([], $errors);
	}

	/** Two adjacent /128 holes in the same entry both carve out (63 covering CIDRs), siblings on either side stay covered. */
	public function testTwoAdjacentHolesInOneEntry(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8::/64'], ['2001:db8::10/128', '2001:db8::11/128'], $errors);

		$this->assertCount(63, $result, 'two adjacent /128 holes in one /64 decompose into 63 covering CIDRs');
		$this->assertSame([], $errors);
		$this->assertFalse($this->anyCidrContains($result, '2001:db8::10'));
		$this->assertFalse($this->anyCidrContains($result, '2001:db8::11'));
		$this->assertTrue($this->anyCidrContains($result, '2001:db8::f'), 'the address just before both holes stays covered');
		$this->assertTrue($this->anyCidrContains($result, '2001:db8::12'), 'the address just after both holes stays covered');
	}

	/**
	 * Two holes, each confined to a DIFFERENT entry, act independently: neither
	 * entry's carve is affected by the other entry's hole (128 = 64 + 64).
	 */
	public function testTwoHolesInDifferentEntriesActIndependently(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(
			['2001:db8:1::/64', '2001:db8:2::/64'],
			['2001:db8:1::5353/128', '2001:db8:2::7777/128'],
			$errors
		);

		$this->assertCount(128, $result, 'two independently-suppressed /64 entries yield 64 + 64 covering CIDRs');
		$this->assertSame([], $errors);
		$this->assertFalse($this->anyCidrContains($result, '2001:db8:1::5353'));
		$this->assertFalse($this->anyCidrContains($result, '2001:db8:2::7777'));
		// Cross-check: entry 1's hole address must not "leak" a false exclusion into entry 2's space and vice versa.
		$this->assertTrue($this->anyCidrContains($result, '2001:db8:2::5353'), "entry 2's copy of entry 1's hole address must still be covered");
		$this->assertTrue($this->anyCidrContains($result, '2001:db8:1::7777'), "entry 1's copy of entry 2's hole address must still be covered");
	}

	/** A coarser hole that fully contains a finer entry removes the entry entirely. */
	public function testHoleContainingAnEntryRemovesItEntirely(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8:0:5::/64'], ['2001:db8::/48'], $errors);

		$this->assertSame([], $result, 'a /48 hole containing the /64 feed entry must remove it entirely');
		$this->assertSame([], $errors);
	}

	/** Full suppression across every entry legitimately returns an empty (not a fail-safe) result. */
	public function testFullSuppressionOfEveryEntryYieldsLegitimateEmptyResult(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(
			['2001:db8:1::/64', '2001:db8:2::/64'],
			['2001:db8:1::/64', '2001:db8:2::/64'],
			$errors
		);

		$this->assertSame([], $result);
		$this->assertSame([], $errors);
	}

	/** A malformed feed token is skipped (not thrown) and reported verbatim; the well-formed sibling still carves normally. */
	public function testMalformedCidrTokenSkippedAndReported(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8::/64', 'not-an-ip/64'], [], $errors);

		$this->assertSame(['2001:db8::/64'], $result);
		$this->assertSame(['not-an-ip/64'], $errors);
	}

	/** A malformed suppression token is skipped (not thrown) and reported; the legitimate hole in the same call still carves. */
	public function testMalformedHoleTokenSkippedAndReported(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8::/64'], ['garbage', '2001:db8::5353/128'], $errors);

		$this->assertCount(64, $result, 'the legitimate hole must still carve even though a sibling hole token was malformed');
		$this->assertSame(['garbage'], $errors);
	}

	/** Blank lines and '#'-led comments are silent no-ops -- never reported as malformed (mirrors pfb_validate_suppression_line's tolerance). */
	public function testBlankAndCommentLinesAreSilentNoOps(): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6(['2001:db8::/64', '', '# a note'], ['', '# also a note'], $errors);

		$this->assertSame(['2001:db8::/64'], $result);
		$this->assertSame([], $errors, 'blank/comment lines must never land in the malformed-token report');
	}

	// =========================================================================
	// Set-equivalence property check -- INDEPENDENT representation
	//
	// Per ADR-53 Phase 5 spec: verify result ∪ holes ⊇ input, result ∩ holes = ∅,
	// and result ⊆ input using a representation that shares NO code with the
	// engine under test -- inet_pton()-derived (start,end) HEX strings, raw
	// byte masking, and strcmp(), never pfb_v6_cidr_to_range()/
	// pfb_v6_addr_to_bin() (the engine's own '0'/'1'-binary-string technique).
	// =========================================================================

	/**
	 * @return array<int, array{entries: string[], holes: string[]}> Five fixed
	 *   (deterministic, not random) scenarios exercising different overlap
	 *   shapes: multiple holes in one entry, a half-overlapping hole, two
	 *   independent entries, a hole fully containing an entry, and a hole with
	 *   no overlap at all. Every entry here uses a small (<=4) host-bit count
	 *   so its address space is exhaustively enumerable.
	 */
	public static function propertyScenarios(): array
	{
		return [
			'multiple holes in one entry' => [
				'entries' => ['2001:db8:9000::/124'],
				'holes'   => ['2001:db8:9000::3/128', '2001:db8:9000::c/128'],
			],
			'half-overlapping coarser hole' => [
				'entries' => ['2001:db8:9001::/124'],
				'holes'   => ['2001:db8:9001::/125'],
			],
			'two independent entries, one hole each' => [
				'entries' => ['2001:db8:9002::/125', '2001:db8:9003::/125'],
				'holes'   => ['2001:db8:9002::3/128', '2001:db8:9003::5/128'],
			],
			'hole fully containing the entry' => [
				'entries' => ['2001:db8:9004::/124'],
				'holes'   => ['2001:db8:9000::/108'],
			],
			'hole with no overlap at all' => [
				'entries' => ['2001:db8:9005::/124'],
				'holes'   => ['2001:dead::/32'],
			],
		];
	}

	/**
	 * @param string[] $entries
	 * @param string[] $holes
	 */
	#[DataProvider('propertyScenarios')]
	public function testSetEquivalencePropertyHoldsAcrossFixedScenarios(array $entries, array $holes): void
	{
		$errors = null;
		$result = pfb_cidr_subtract_v6($entries, $holes, $errors);

		$resultRanges = array_map([$this, 'independentHexRange'], $result);
		$holeRanges   = array_map([$this, 'independentHexRange'], $holes);

		// (1) result ∩ holes = ∅ -- no output CIDR may overlap any hole.
		foreach ($resultRanges as $r) {
			foreach ($holeRanges as $h) {
				$this->assertFalse($this->rangesOverlap($r, $h), 'a result CIDR must never overlap a suppression hole');
			}
		}

		// (2) result ⊆ input -- every output CIDR must sit fully inside SOME entry
		// (entries are disjoint by fixture design, so containment-in-any-one is exact).
		$entryRanges = array_map([$this, 'independentHexRange'], $entries);
		foreach ($resultRanges as $r) {
			$this->assertTrue(
				$this->rangeContainedInAny($r, $entryRanges),
				'every result CIDR must be fully contained within some input entry'
			);
		}

		// (3) result ∪ holes ⊇ input -- exhaustively enumerate every address in
		// each (small, host-bits<=4) entry and confirm it is covered by the
		// result OR a hole (nothing may silently vanish).
		foreach ($entries as $entry) {
			foreach ($this->enumerateEntryAddresses($entry) as $addrHex) {
				$covered = $this->addressHexCoveredByAny($addrHex, $resultRanges)
					|| $this->addressHexCoveredByAny($addrHex, $holeRanges);
				$this->assertTrue($covered, "address {$addrHex} from entry {$entry} must be covered by the result or a hole");
			}
		}
	}

	/**
	 * INDEPENDENT (from the engine) expansion of one IPv6 CIDR into its
	 * [start_hex, end_hex] range: inet_pton() + raw per-byte masking + bin2hex().
	 * Deliberately does NOT call pfb_v6_cidr_to_range()/pfb_v6_addr_to_bin() --
	 * a different data representation (hex string vs the engine's '0'/'1'
	 * binary string) so this check can't share a bug with the code under test.
	 *
	 * @return array{0:string,1:string} [start_hex, end_hex].
	 */
	private function independentHexRange(string $cidr): array
	{
		[$addr, $bitsRaw] = explode('/', $cidr, 2);
		$bits = (int) $bitsRaw;
		$packed = inet_pton($addr);
		$this->assertNotFalse($packed, "test fixture CIDR must be a syntactically valid IPv6 address: {$cidr}");

		$fullBytes = intdiv($bits, 8);
		$remBits   = $bits % 8;

		$startBytes = substr($packed, 0, $fullBytes);
		$endBytes   = $startBytes;
		if ($remBits > 0) {
			$byte = ord($packed[$fullBytes]);
			$mask = (0xFF << (8 - $remBits)) & 0xFF;
			$startBytes .= chr($byte & $mask);
			$endBytes   .= chr($byte | (~$mask & 0xFF));
		}
		$startBytes = str_pad($startBytes, 16, "\x00");
		$endBytes   = str_pad($endBytes, 16, "\xFF");

		return [bin2hex($startBytes), bin2hex($endBytes)];
	}

	/** @param array{0:string,1:string} $a @param array{0:string,1:string} $b */
	private function rangesOverlap(array $a, array $b): bool
	{
		return !(strcmp($a[1], $b[0]) < 0 || strcmp($b[1], $a[0]) < 0);
	}

	/**
	 * @param array{0:string,1:string}   $inner
	 * @param array<int,array{0:string,1:string}> $outerSet
	 */
	private function rangeContainedInAny(array $inner, array $outerSet): bool
	{
		foreach ($outerSet as $outer) {
			if (strcmp($inner[0], $outer[0]) >= 0 && strcmp($inner[1], $outer[1]) <= 0) {
				return true;
			}
		}
		return false;
	}

	/** @param array<int,array{0:string,1:string}> $ranges */
	private function addressHexCoveredByAny(string $addrHex, array $ranges): bool
	{
		foreach ($ranges as $r) {
			if (strcmp($addrHex, $r[0]) >= 0 && strcmp($addrHex, $r[1]) <= 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Exhaustively enumerate every address (as an independent hex string) in a
	 * small CIDR (host bits <=4, i.e. <=16 addresses) by varying only the last
	 * nibble of the packed address -- every fixture entry above is host-aligned
	 * within its final hextet, so no cross-byte carry is needed.
	 *
	 * @return string[] hex-encoded 16-byte addresses.
	 */
	private function enumerateEntryAddresses(string $cidr): array
	{
		[$addr, $bitsRaw] = explode('/', $cidr, 2);
		$bits = (int) $bitsRaw;
		$hostBits = 128 - $bits;
		$this->assertLessThanOrEqual(4, $hostBits, 'test fixture entries must stay small enough to enumerate exhaustively');

		$packed = inet_pton($addr);
		$this->assertNotFalse($packed);
		$count = 1 << $hostBits;
		$lastByte = ord($packed[15]);

		$out = [];
		for ($i = 0; $i < $count; $i++) {
			$candidate = substr($packed, 0, 15) . chr(($lastByte + $i) & 0xFF);
			$out[] = bin2hex($candidate);
		}
		return $out;
	}

	/** Membership helper for the plain vector tests (reuses the already-faithful pfSense double, NOT a new representation -- fine outside the dedicated property check above). */
	private function anyCidrContains(array $cidrs, string $addr): bool
	{
		foreach ($cidrs as $cidr) {
			if (ip_in_subnet($addr, $cidr)) {
				return true;
			}
		}
		return false;
	}

	// =========================================================================
	// Vector-pin the ip_range_to_subnet_array() double itself
	//
	// Hand-derivable examples (not dependent on trusting the double's own
	// output): an aligned + a non-aligned range for each family. A stale/wrong
	// double fails these loudly rather than silently corrupting every v6
	// engine test above.
	// =========================================================================

	public function testDoubleVectorV4Aligned(): void
	{
		$this->assertSame(['10.0.0.0/30'], ip_range_to_subnet_array('10.0.0.0', '10.0.0.3'));
	}

	public function testDoubleVectorV4NonAlignedEdgeCase(): void
	{
		// Two adjacent addresses that do NOT share a power-of-2-aligned block
		// (1 = ...01, 2 = ...10) must decompose into two separate /32 hosts.
		$this->assertSame(['10.0.0.1/32', '10.0.0.2/32'], ip_range_to_subnet_array('10.0.0.1', '10.0.0.2'));
	}

	public function testDoubleVectorV6Aligned(): void
	{
		$this->assertSame(['2001:db8::/126'], ip_range_to_subnet_array('2001:db8::', '2001:db8::3'));
	}

	public function testDoubleVectorV6NonAlignedEdgeCase(): void
	{
		$this->assertSame(['2001:db8::1/128', '2001:db8::2/128'], ip_range_to_subnet_array('2001:db8::1', '2001:db8::2'));
	}

	// =========================================================================
	// pfb_suppress_file_v6 -- file-level, fail-safe publish
	// =========================================================================

	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $savedPfb = [];

	protected function setUp(): void
	{
		foreach (['log', 'errlog'] as $k) {
			$this->savedPfb[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		$log = tempnam(sys_get_temp_dir(), 'pfb_v6log_');
		$this->assertNotFalse($log);
		$this->tmpfiles[] = $log;
		$GLOBALS['pfb']['log']    = $log;
		$GLOBALS['pfb']['errlog'] = $log;
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				@unlink($f);
			}
		}
		$this->tmpfiles = [];
	}

	private function makeTempFile(string $contents): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_v6file_');
		$this->assertNotFalse($path);
		$this->tmpfiles[] = $path;
		file_put_contents($path, $contents);
		return $path;
	}

	public function testSuccessfulCarvePublishesCoveringCidrRemainder(): void
	{
		$file     = $this->makeTempFile("2001:db8::/64\n");
		$suppfile = $this->makeTempFile("2001:db8::5353/128\n");

		$ok = pfb_suppress_file_v6($file, $suppfile);

		$this->assertTrue($ok);
		$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		$this->assertCount(64, $lines, 'published member file must hold the 64-entry covering-CIDR remainder');
		$this->assertNotContains('2001:db8::5353/128', $lines);
	}

	public function testMissingMemberFileFailsSafeAndWritesNothing(): void
	{
		$missing  = sys_get_temp_dir() . '/pfb_v6_does_not_exist_' . getmypid();
		$suppfile = $this->makeTempFile("2001:db8::5353/128\n");

		$ok = pfb_suppress_file_v6($missing, $suppfile);

		$this->assertFalse($ok);
		$this->assertFileDoesNotExist($missing, 'a missing member file must never be created by a fail-safe path');
	}

	/**
	 * A missing suppression file is also fail-safe: the member file, asserted
	 * BEFORE the call, is byte-identical AFTER (transition test -- proves the
	 * function truly left it untouched, not merely "still looks similar").
	 */
	public function testMissingSuppressionFileFailsSafeAndLeavesMemberFileIntact(): void
	{
		$original = "2001:db8::/64\n";
		$file     = $this->makeTempFile($original);
		$missingSuppfile = sys_get_temp_dir() . '/pfb_v6_supp_does_not_exist_' . getmypid();

		$this->assertSame($original, file_get_contents($file), 'sanity: member file holds the expected content before the call');

		$ok = pfb_suppress_file_v6($file, $missingSuppfile);

		$this->assertFalse($ok);
		$this->assertSame($original, file_get_contents($file), 'member file must be byte-identical after a fail-safe path');
	}

	public function testFullSuppressionPublishesLegitimateEmptyFile(): void
	{
		$file     = $this->makeTempFile("2001:db8::/64\n");
		$suppfile = $this->makeTempFile("2001:db8::/64\n");

		$ok = pfb_suppress_file_v6($file, $suppfile);

		$this->assertTrue($ok, 'a legitimate full suppression must still return TRUE (a real publish), not FALSE');
		$this->assertSame('', file_get_contents($file), 'the published file must be empty, not left stale');
	}

	public function testMalformedMemberLineDroppedAndLogged(): void
	{
		$file     = $this->makeTempFile("2001:db8::5353/128\nnot-an-ip/64\n");
		$suppfile = $this->makeTempFile('');

		$ok = pfb_suppress_file_v6($file, $suppfile);

		$this->assertTrue($ok);
		$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		$this->assertSame(['2001:db8::5353/128'], $lines, 'the malformed line must be dropped; the valid line publishes unchanged');

		$logged = file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringContainsString('not-an-ip/64', $logged, 'the dropped token must be named in the log');
	}

	public function testAtomicPublishLeavesNoTmpFileBehind(): void
	{
		$file     = $this->makeTempFile("2001:db8::/64\n");
		$suppfile = $this->makeTempFile("2001:db8::5353/128\n");

		$ok = pfb_suppress_file_v6($file, $suppfile);

		$this->assertTrue($ok);
		$this->assertFileDoesNotExist($file . '.tmp', 'the tmp+rename publish must never leave a stray .tmp file behind');
	}
}
