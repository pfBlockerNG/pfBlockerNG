<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_match_reported_cidr() / pfb_ip_render_query() / pfb_ip_render_memos() /
 * pfb_ip_prefetch_grep_lines() / pfb_ip_prefetch_last_match() / pfb_find_reported_headers()
 * / pfb_ip_prefetch() -- the issue #809 Phase 3b batching layer for the Alerts page's
 * per-type IP (Block/Permit/Match) tables.
 *
 * convert_ip_log() (pfblockerng_alerts.php -- a www/ page controller tests/php/bootstrap.php
 * does not load, same boundary DnsblPrefetchTest already established for convert_dnsbl_log())
 * re-validates a reported IP against the CURRENT feed state on every render: one exec() to
 * check the logged IP/CIDR is still in its logged feed file, and, on a miss,
 * find_reported_header() (an exact + prefix/CIDR grep) plus one more exec() against every
 * aliastables file. This phase batches all three into a bounded number of grep passes.
 * Behaviour must stay IDENTICAL to the per-row path for every match shape it supports.
 *
 * Feature: batching the IP validate / miss-header / aliastables grep lookups preserves
 *          per-row semantics
 *
 *   Scenario: pfb_match_reported_cidr() -- the shared CIDR-selection core
 *     direct unit tests, no exec: v4 mask math (both sides), v6 subnet math (both sides,
 *     via the Net_IPv6 double), and an empty $result array.
 *
 *   Scenario: pfb_ip_prefetch_last_match() -- the dual-prefix attribution test
 *     direct unit tests, no exec: an unprefixed (single-file) line, a file-prefixed
 *     ("path:content") line, a genuine miss, AND the grep prefix-match quirk (an anchored
 *     `^1.2.3.4`-style pattern also matching content beginning `1.2.3.45`) in both shapes --
 *     the per-row `exec()` this replaces has the identical quirk, so reproducing it (not an
 *     exact-match) is what keeps this behaviour-identical.
 *
 *   Scenario: find_reported_header() vs the batched pfb_find_reported_headers() sibling
 *     Differential (oracle) scenarios over a real fixture feed dir, real grep/find exec:
 *     exact v4 hit, exact v6 hit, a v4 CIDR hit AND a miss sharing the same first-octet
 *     Round-B query group, a v6 CIDR hit AND a miss sharing the same prefix Round-B group,
 *     the exact-round prefix-match quirk, and two flavours of total miss (no CIDR
 *     candidates at all; CIDR candidates present but none contain the host). A SEPARATE
 *     fixture dir/geoip=TRUE case proves the ccdir-redirect branch too.
 *
 *   Scenario: pfb_ip_prefetch() end-to-end -- seeding pfb_ip_render_memos() for real rows
 *     Rows built via pfb_ip_render_query() (the SAME helper convert_ip_log() itself calls)
 *     over real fixture dirs. Asserts the validate round, the miss round (find_reported_
 *     header() result), and the aliastables round (including the genuine "no match ->
 *     empty string" case) all seed the exact values a per-row exec would have produced.
 *
 *   Scenario: negative-proof -- a covered row never falls through to a live re-exec
 *     After seeding from REAL fixtures, the backing directories are renamed away. The
 *     seeded memo entries must still resolve correctly (pfb_render_memo() consults the
 *     cache, never re-execs) -- against the now-missing directories, a genuine re-exec
 *     could only return empty/'Unknown', never the correct answer asserted here.
 */
#[CoversFunction('pfb_match_reported_cidr')]
#[CoversFunction('pfb_ip_render_query')]
#[CoversFunction('pfb_ip_render_memos')]
#[CoversFunction('pfb_ip_prefetch_grep_lines')]
#[CoversFunction('pfb_ip_prefetch_last_match')]
#[CoversFunction('pfb_find_reported_headers')]
#[CoversFunction('pfb_ip_prefetch')]
#[CoversFunction('find_reported_header')]
final class IpPrefetchTest extends TestCase
{
	private string $fixturesDir;

	/** @var array<string, mixed> */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		$this->savedGlobals['pfb']        = $GLOBALS['pfb'] ?? null;
		$this->savedGlobals['continents'] = $GLOBALS['continents'] ?? null;

		$this->fixturesDir = __DIR__ . '/fixtures/ip_prefetch';

		// pfb_ip_render_query()/find_reported_header()/pfb_ip_prefetch() only ever read
		// these keys; a minimal $pfb is enough (unlike the Alerts page itself, which reads
		// many more unrelated keys at load time).
		$GLOBALS['pfb'] = [
			'grep'       => '/usr/bin/grep',
			'denydir'    => "{$this->fixturesDir}/deny",
			'nativedir'  => "{$this->fixturesDir}/native",
			'permitdir'  => "{$this->fixturesDir}/deny",	// unused by these tests' rows
			'matchdir'   => "{$this->fixturesDir}/deny",	// unused by these tests' rows
			'etdir'      => "{$this->fixturesDir}/deny",	// unused by these tests' rows
			'ccdir'      => "{$this->fixturesDir}/geoip",
			'aliasdir'   => "{$this->fixturesDir}/alias",
		];

		// Same continents registry pfblockerng_alerts.php builds (array_flip of the
		// GeoIP continent alias basenames); pfb_ip_render_query() checks
		// isset($continents[substr($fields[13], 0, -3)]) to detect a GeoIP row.
		$GLOBALS['continents'] = array_flip(array(
			'pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe',
			'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top',
		));
	}

	protected function tearDown(): void
	{
		foreach (['pfb', 'continents'] as $g) {
			if ($this->savedGlobals[$g] === null) {
				unset($GLOBALS[$g]);
			} else {
				$GLOBALS[$g] = $this->savedGlobals[$g];
			}
		}
	}

	// ------------------------------------------------------------------------------
	// pfb_match_reported_cidr()
	// ------------------------------------------------------------------------------

	public function test_cidr_helper_v4_mask_math_both_sides(): void
	{
		// A realistic multi-file grep line: "/full/path/DenyFeed.txt:content" -- matches
		// the shape find_reported_header() actually gets back when more than one file is
		// searched (pfb_parse_query() extracts the basename via strrchr(...,'/')).
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:203.0.113.0/28'];

		// Given: a host INSIDE the /28 (203.0.113.0 - .15).
		$inside = pfb_match_reported_cidr($result, '203.0.113.5', TRUE);
		$this->assertSame(
			['DenyFeed', '203.0.113.0/28'],
			$inside,
			'expected 203.0.113.5 (inside the /28) to match, got ' . var_export($inside, true)
		);

		// Given: a host OUTSIDE the same /28 (.16 onward) -- proves the v4 mask math is a
		// real containment test, not an always-true stub.
		$outside = pfb_match_reported_cidr($result, '203.0.113.55', TRUE);
		$this->assertNull(
			$outside,
			'expected 203.0.113.55 (outside the /28) NOT to match, got ' . var_export($outside, true)
		);
	}

	public function test_cidr_helper_v6_subnet_math_both_sides(): void
	{
		$result = ['/var/db/pfblockerng/deny/DenyFeed.txt:2001:db8:1::/64'];

		// Given: a host INSIDE the /64.
		$inside = pfb_match_reported_cidr($result, '2001:db8:1::5', FALSE);
		$this->assertSame(
			['DenyFeed', '2001:db8:1::/64'],
			$inside,
			'expected 2001:db8:1::5 (inside the /64) to match, got ' . var_export($inside, true)
		);

		// Given: a host OUTSIDE the /64 (different top-64-bits) -- proves the v6
		// gen_subnetv6() + Net_IPv6::isInNetmask() math is a real containment test.
		$outside = pfb_match_reported_cidr($result, '2001:db8:2::5', FALSE);
		$this->assertNull(
			$outside,
			'expected 2001:db8:2::5 (outside the /64) NOT to match, got ' . var_export($outside, true)
		);
	}

	public function test_cidr_helper_empty_input_never_matches(): void
	{
		$result = pfb_match_reported_cidr([], '203.0.113.5', TRUE);
		$this->assertNull($result, 'expected an empty $result array to yield NULL, got ' . var_export($result, true));
	}

	// ------------------------------------------------------------------------------
	// pfb_ip_prefetch_last_match()
	// ------------------------------------------------------------------------------

	public function test_last_match_unprefixed_single_file_shape(): void
	{
		$lines = ['203.0.113.0/28', '198.51.100.16/28'];
		$match = pfb_ip_prefetch_last_match($lines, '203.0.113.0');
		$this->assertSame('203.0.113.0/28', $match, 'expected the unprefixed line to be attributed, got ' . var_export($match, true));
	}

	public function test_last_match_file_prefixed_multi_file_shape(): void
	{
		$lines = ['DenyFeedA.txt:203.0.113.0/28', 'DenyFeedB.txt:198.51.100.16/28'];
		$match = pfb_ip_prefetch_last_match($lines, '198.51.100.16');
		$this->assertSame(
			'DenyFeedB.txt:198.51.100.16/28',
			$match,
			'expected the file-prefixed line (content after the first colon) to be attributed, got ' . var_export($match, true)
		);
	}

	public function test_last_match_returns_null_on_genuine_miss(): void
	{
		$lines = ['DenyFeedA.txt:203.0.113.0/28'];
		$match = pfb_ip_prefetch_last_match($lines, '198.51.100.16');
		$this->assertNull($match, 'expected no attribution for an unrelated prefix, got ' . var_export($match, true));
	}

	public function test_last_match_preserves_the_grep_prefix_match_quirk(): void
	{
		// An anchored `^203\.0\.113\.4` pattern also matches content beginning
		// "203.0.113.45" -- the per-row single-pattern exec() has this exact quirk (it is
		// not `-w`/word-bounded), so the batched attribution must reproduce it, in BOTH
		// output shapes grep can emit.
		$unprefixed = pfb_ip_prefetch_last_match(['203.0.113.45/32'], '203.0.113.4');
		$this->assertSame(
			'203.0.113.45/32',
			$unprefixed,
			'expected the quirk to attribute an unprefixed longer-suffix line, got ' . var_export($unprefixed, true)
		);

		$prefixed = pfb_ip_prefetch_last_match(['DenyFeed.txt:203.0.113.45/32'], '203.0.113.4');
		$this->assertSame(
			'DenyFeed.txt:203.0.113.45/32',
			$prefixed,
			'expected the quirk to attribute a file-prefixed longer-suffix line, got ' . var_export($prefixed, true)
		);

		// And the negative: a prefix that genuinely does not lead the content must NOT
		// match (proves this is a real prefix test, not "contains").
		$noHit = pfb_ip_prefetch_last_match(['203.0.113.99/32'], '203.0.113.4');
		$this->assertNull($noHit, 'expected a non-leading occurrence NOT to match, got ' . var_export($noHit, true));
	}

	// ------------------------------------------------------------------------------
	// find_reported_header() vs pfb_find_reported_headers() -- differential
	// ------------------------------------------------------------------------------

	/**
	 * The oracle: the REAL per-row find_reported_header() and the batched
	 * pfb_find_reported_headers() sibling must agree, for every host, against a concrete
	 * known-correct expectation -- so a regression that breaks BOTH identically still fails.
	 *
	 * @param array<string, array{0:string,1:string}> $expectedByHost
	 */
	private function assertBatchedHeadersMatchPerRow(array $hosts, string $folder, bool $geoip, array $expectedByHost, string $scenario): void
	{
		// When: each host is resolved individually via the REAL per-row function.
		foreach ($hosts as $host) {
			$perRow = find_reported_header($host, $folder, $geoip);
			$this->assertSame(
				$expectedByHost[$host],
				$perRow,
				"[{$scenario}] expected the PER-ROW find_reported_header('{$host}') to be "
					. var_export($expectedByHost[$host], true) . ', got ' . var_export($perRow, true)
			);
		}

		// When: ALL hosts are resolved together via ONE batched call.
		$batched = pfb_find_reported_headers($hosts, $folder, $geoip);

		// Then: every host's batched result matches its own per-row result (and the known
		// expectation) exactly.
		foreach ($hosts as $host) {
			$this->assertSame(
				$expectedByHost[$host],
				$batched[$host],
				"[{$scenario}] expected the BATCHED pfb_find_reported_headers() result for '{$host}' to be "
					. var_export($expectedByHost[$host], true) . ', got ' . var_export($batched[$host], true)
			);
		}
	}

	public function test_batched_headers_match_per_row_for_every_v4_v6_shape(): void
	{
		$folder = "{$this->fixturesDir}/reports/*.txt";

		$hosts = [
			'192.0.2.10',		// exact v4 hit
			'2001:db8:aaaa::10',	// exact v6 hit
			'203.0.113.5',		// v4 CIDR hit (inside 203.0.113.0/28)
			'203.0.113.55',		// v4 CIDR miss -- SAME Round-B "203" group as the hit above
			'2001:db8:1::5',	// v6 CIDR hit (inside 2001:db8:1::/64)
			'2001:db8:9::5',	// v6 CIDR miss -- SAME Round-B "2001" group as the hit above
			'198.51.100.4',		// exact-round prefix-match quirk (-> "198.51.100.45")
			'198.51.100.99',	// CIDR candidates present (198.51.100.16/28), none contain it
			'192.0.2.222',		// no CIDR candidates in its group at all
		];

		$expected = [
			'192.0.2.10'         => ['ReportsFeedA', '192.0.2.10'],
			'2001:db8:aaaa::10'  => ['ReportsFeedA', '2001:db8:aaaa::10'],
			'203.0.113.5'        => ['ReportsFeedA', '203.0.113.0/28'],
			'203.0.113.55'       => ['Unknown', 'Unknown'],
			'2001:db8:1::5'      => ['ReportsFeedA', '2001:db8:1::/64'],
			'2001:db8:9::5'      => ['Unknown', 'Unknown'],
			'198.51.100.4'       => ['ReportsFeedB', '198.51.100.45'],
			'198.51.100.99'      => ['Unknown', 'Unknown'],
			'192.0.2.222'        => ['Unknown', 'Unknown'],
		];

		$this->assertBatchedHeadersMatchPerRow($hosts, $folder, FALSE, $expected, 'reports fixture, non-geoip');
	}

	public function test_batched_headers_match_per_row_for_the_geoip_folder_variant(): void
	{
		// GeoIP redirect quirk (pre-existing, unchanged by this phase): find_reported_
		// header()'s prefix round with $geoip=TRUE always searches $pfb['ccdir']/*.txt,
		// REGARDLESS of the $pfbfolder argument -- so $pfbfolder is set to the SAME dir
		// here to keep the scenario coherent (both rounds target ccdir).
		$folder = "{$this->fixturesDir}/geoip/*.txt";

		$hosts = [
			'203.0.113.20',	// inside 203.0.113.16/28 (CountryFeed.txt) -- via the geoip round
			'203.0.113.99',	// same Round-B group, outside the /28
		];
		$expected = [
			'203.0.113.20' => ['CountryFeed', '203.0.113.16/28'],
			'203.0.113.99' => ['Unknown', 'Unknown'],
		];

		$this->assertBatchedHeadersMatchPerRow($hosts, $folder, TRUE, $expected, 'geoip fixture, geoip=TRUE');
	}

	// ------------------------------------------------------------------------------
	// pfb_ip_prefetch() end-to-end -- seeding pfb_ip_render_memos() for real rows
	// ------------------------------------------------------------------------------

	/**
	 * Build a convert_ip_log()-shaped, POST-REORDER $fields row (the "Final $fields array
	 * reference" convert_ip_log() documents) for a Block event.
	 */
	private function buildBlockFields(string $reportedIp): array
	{
		return [
			0  => 'rule1',			// Rulenum
			1  => 'em0',			// Real Interface
			2  => 'WAN',			// Friendly Interface name
			3  => 'block',			// Action
			4  => 4,			// Version
			5  => 'tcp',			// Protocol ID
			6  => 'TCP',			// Protocol
			7  => $reportedIp,		// SRC IP (direction 'in' reads this)
			8  => '198.51.100.1',		// DST IP
			9  => '12345',			// SRC Port
			10 => '443',			// DST Port
			11 => 'in',			// Direction
			12 => 'US',			// GeoIP code
			13 => 'MyAlias_v4',		// IP Alias Name (substr(...,-3) 'v4' isn't in $continents)
			14 => $reportedIp,		// IP evaluated (as logged at event time)
			15 => 'OldFeed',		// Feed Name (no ':' -- not an ET header)
			16 => '',			// gethostbyaddr resolved hostname
			17 => '',			// Client Hostname
			18 => 'Unknown',		// ASN
		];
	}

	public function test_prefetch_seeds_the_validate_round_and_the_miss_round_for_a_real_row(): void
	{
		$fields = $this->buildBlockFields('192.0.2.77');
		$rq     = pfb_ip_render_query($fields);

		// Given: pfb_ip_render_query() derives the folder/validate command this row's
		// convert_ip_log() call would use -- the deny+native glob, block-branch folder.
		$this->assertSame("{$GLOBALS['pfb']['denydir']}/*.txt {$GLOBALS['pfb']['nativedir']}/*.txt", $rq['folder']);
		$this->assertNotNull($rq['validate_cmd'], 'expected a validate command to be built (fields[14]/[15] are not Unknown)');

		$rows = [[
			'host'              => $rq['host'],
			'folder'            => $rq['folder'],
			'validate_file_cmd' => $rq['validate_file_cmd'],
			'validate_cmd'      => $rq['validate_cmd'],
			'eval_ip_raw'       => $fields[14],
		]];

		// When: the batched prefetch runs.
		pfb_ip_prefetch($rows);
		$memos = &pfb_ip_render_memos();

		// Then: the validate round found NO exact match for '192.0.2.77' in DenyFeed.txt
		// (which holds only the CIDR '192.0.2.0/24', a different string) -- seeded as ''.
		$this->assertSame(
			'',
			$memos['validate'][$rq['validate_cmd']] ?? 'MISSING',
			"expected the validate round to seed '' (no exact hit), got " . var_export($memos['validate'][$rq['validate_cmd']] ?? 'MISSING', true)
		);

		// Then: the miss round resolved via find_reported_header()'s CIDR match against
		// the SAME DenyFeed.txt entry, AND the aliastables round found the identical CIDR
		// string in the alias fixture -- exactly what a per-row exec would have produced.
		$missKey = "{$rq['host']}|{$rq['folder']}";
		$this->assertArrayHasKey($missKey, $memos['miss'], "expected the miss round to seed key '{$missKey}'");
		$this->assertSame(
			[['DenyFeed', '192.0.2.0/24'], '192.0.2.0/24'],
			$memos['miss'][$missKey],
			'expected [pfb_query, raw_validate] to be ' . var_export([['DenyFeed', '192.0.2.0/24'], '192.0.2.0/24'], true)
				. ', got ' . var_export($memos['miss'][$missKey], true)
		);
	}

	public function test_prefetch_seeds_an_empty_aliastables_result_on_a_genuine_total_miss(): void
	{
		$fields = $this->buildBlockFields('198.51.100.222');
		$rq     = pfb_ip_render_query($fields);

		$rows = [[
			'host'              => $rq['host'],
			'folder'            => $rq['folder'],
			'validate_file_cmd' => $rq['validate_file_cmd'],
			'validate_cmd'      => $rq['validate_cmd'],
			'eval_ip_raw'       => $fields[14],
		]];

		pfb_ip_prefetch($rows);
		$memos = &pfb_ip_render_memos();

		// Given/Then: no feed anywhere covers 198.51.100.222 (DenyFeed.txt only has a
		// 192.0.2.0/24 CIDR) -- find_reported_header() itself resolves to Unknown/Unknown,
		// so the aliastables pattern becomes '^Not listed!', which matches nothing in the
		// alias fixture (pfB_SomeAlias_v4.txt holds only '192.0.2.0/24'). This pins the
		// downstream ltrim(strrchr(strstr(...))) chain's no-match input: an empty string,
		// exactly what the per-row exec() yields on silent grep failure (folded via 2>&1).
		$missKey = "{$rq['host']}|{$rq['folder']}";
		$this->assertSame(
			[['Unknown', 'Unknown'], ''],
			$memos['miss'][$missKey] ?? 'MISSING',
			'expected [Unknown/Unknown, \'\'] on a genuine total miss, got ' . var_export($memos['miss'][$missKey] ?? 'MISSING', true)
		);
	}

	// ------------------------------------------------------------------------------
	// Negative proof: a covered row never falls through to a live re-exec
	// ------------------------------------------------------------------------------

	public function test_covered_rows_resolve_without_reexecuting_after_the_backing_dirs_disappear(): void
	{
		$fields = $this->buildBlockFields('192.0.2.77');
		$rq     = pfb_ip_render_query($fields);

		$rows = [[
			'host'              => $rq['host'],
			'folder'            => $rq['folder'],
			'validate_file_cmd' => $rq['validate_file_cmd'],
			'validate_cmd'      => $rq['validate_cmd'],
			'eval_ip_raw'       => $fields[14],
		]];

		// Given: the batched prefetch has already seeded both memo stores from the REAL
		// fixture directories.
		pfb_ip_prefetch($rows);
		$memos   = &pfb_ip_render_memos();
		$missKey = "{$rq['host']}|{$rq['folder']}";
		$this->assertSame([['DenyFeed', '192.0.2.0/24'], '192.0.2.0/24'], $memos['miss'][$missKey]);

		// When: the backing deny/native/alias directories are renamed away -- a FRESH
		// find_reported_header() call (or a fresh aliastables exec) against these paths
		// can now only return 'Unknown'/'' (proving what WOULD happen without the cache).
		$deletedSuffix = '.gone';
		$renamed = [];
		foreach (['denydir', 'nativedir', 'aliasdir'] as $key) {
			$path = $GLOBALS['pfb'][$key];
			$this->assertTrue(rename($path, $path . $deletedSuffix), "precondition: failed to rename {$path}");
			$renamed[$key] = $path;
		}
		try {
			$freshMiss = find_reported_header($rq['host'], $rq['folder']);
			$this->assertSame(
				['Unknown', 'Unknown'],
				$freshMiss,
				'precondition: a genuinely fresh (uncached) lookup against the renamed-away dirs must miss'
			);

			// Then: pfb_render_memo(), consulting the ALREADY-seeded store (exactly as
			// convert_ip_log() does on every render), still returns the correct cached
			// result -- it never re-execs against the now-missing directories.
			list($cachedQuery, $cachedValidate) = pfb_render_memo(
				$memos['miss'],
				$missKey,
				function () {
					$this->fail('the miss-round closure ran again -- the seeded memo entry was not consulted');
				}
			);
			$this->assertSame(
				['DenyFeed', '192.0.2.0/24'],
				$cachedQuery,
				'expected the CACHED pfb_query to survive the directories disappearing, got ' . var_export($cachedQuery, true)
			);
			$this->assertSame(
				'192.0.2.0/24',
				$cachedValidate,
				'expected the CACHED aliastables content to survive the directories disappearing, got ' . var_export($cachedValidate, true)
			);
		} finally {
			foreach ($renamed as $key => $path) {
				rename($path . $deletedSuffix, $path);
			}
		}
	}
}
