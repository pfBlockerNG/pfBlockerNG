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
 *
 *   Scenario: N1 -- pfb_ip_prefetch_last_match()'s colon-fallback false IPv6 attribution
 *     An UNPREFIXED IPv6 content line has ':' inside the address itself, not a grep
 *     "path:content" separator -- the fallback must not misattribute it merely because
 *     the tail after its first ':' happens to equal some host's raw_prefix.
 *
 *   Scenario: B3 -- a failed batched grep pass must never seed a false negative
 *     A child `php` process with `open_basedir` whitelisting only the repo tree (so
 *     sys_get_temp_dir()'s real system temp dir is off-limits) genuinely fails
 *     tempnam() -- the exact pattern-file-creation failure pfb_ip_prefetch_grep_lines()
 *     can hit in production. pfb_ip_prefetch() must leave the affected rows entirely
 *     UNSEEDED rather than caching a wrong/placeholder result.
 *
 *   Scenario: B4 -- a v4 host and a v6 host must not collide in Round-B grouping
 *     Two hosts (one v4, one v6) whose Round-B grouping key -- strstr() up to the first
 *     '.' or ':' -- is the textually IDENTICAL bare string must each still resolve to
 *     their OWN family's real CIDR match, matching the per-row oracle.
 *
 *   R4: after a prefetch pass, no pfb_ip_prefetch_* pattern-file temp file remains --
 *   guards the try/finally cleanup against a future regression.
 */
#[CoversFunction('pfb_match_reported_cidr')]
#[CoversFunction('pfb_ip_render_query')]
#[CoversFunction('pfb_ip_render_memos')]
#[CoversFunction('pfb_ip_render_memos_reset')]
#[CoversFunction('pfb_prefetch_pattern_file_write_ok')]
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

		// T1 (issue #809 review): pfb_ip_render_memos()'s function-static store has NO
		// production reset by design (a page render is one PHP process, and every key is
		// content-derived, so cross-table reuse within that one load is correct -- see
		// its own docblock). PHPUnit, though, runs every test method in ONE process, so
		// without an explicit per-test reset a later test can silently inherit an
		// earlier test's seeded memo entries -- a sibling-order leak that made
		// test_covered_rows_resolve_without_reexecuting_after_the_backing_dirs_disappear()
		// below a no-op: it reused a PRIOR test's seed for the identical row instead of
		// exercising its own pfb_ip_prefetch() call. Also resets the DNSBL-side store
		// (unused by these tests, reset here purely for a clean, uniform per-test
		// baseline) so every test starts from a known-empty baseline regardless of
		// execution order.
		pfb_ip_render_memos_reset();
		pfb_dnsbl_prefetch_store(NULL);
	}

	protected function tearDown(): void
	{
		pfb_ip_render_memos_reset();
		pfb_dnsbl_prefetch_store(NULL);

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
		// Realistic grep multi-file output: an ABSOLUTE path (every folder this module
		// greps is an absolute glob) before the ':' separator -- see N1's docblock for
		// why the '/' matters.
		$lines = ['/var/db/pfblockerng/deny/DenyFeedA.txt:203.0.113.0/28', '/var/db/pfblockerng/deny/DenyFeedB.txt:198.51.100.16/28'];
		$match = pfb_ip_prefetch_last_match($lines, '198.51.100.16');
		$this->assertSame(
			'/var/db/pfblockerng/deny/DenyFeedB.txt:198.51.100.16/28',
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

		// Realistic grep multi-file output: an ABSOLUTE path before the ':' separator.
		$prefixed = pfb_ip_prefetch_last_match(['/var/db/pfblockerng/deny/DenyFeed.txt:203.0.113.45/32'], '203.0.113.4');
		$this->assertSame(
			'/var/db/pfblockerng/deny/DenyFeed.txt:203.0.113.45/32',
			$prefixed,
			'expected the quirk to attribute a file-prefixed longer-suffix line, got ' . var_export($prefixed, true)
		);

		// And the negative: a prefix that genuinely does not lead the content must NOT
		// match (proves this is a real prefix test, not "contains").
		$noHit = pfb_ip_prefetch_last_match(['203.0.113.99/32'], '203.0.113.4');
		$this->assertNull($noHit, 'expected a non-leading occurrence NOT to match, got ' . var_export($noHit, true));
	}

	/**
	 * N1 (issue #809 review): the colon-fallback used to fire on ANY ':' in the line,
	 * which misattributes an UNPREFIXED IPv6 content line (its OWN ':' is part of the
	 * address, not a "path:content" separator) whenever the tail after that first ':'
	 * happens to equal $raw_prefix. Guarded now by requiring the segment before that ':'
	 * to look like a path (contain '/') -- true of every real grep path here, never true
	 * of a bare IPv6 literal.
	 */
	public function test_last_match_does_not_misattribute_an_unprefixed_ipv6_content_line_via_the_colon_fallback(): void
	{
		// Given: an unprefixed IPv6 content line whose tail-after-first-colon equals a
		// host's raw_prefix.
		// When/Then: it must NOT be attributed via the colon-fallback.
		$unprefixed = pfb_ip_prefetch_last_match(['2001:db8::1'], 'db8::1');
		$this->assertNull(
			$unprefixed,
			'expected an unprefixed IPv6 content line NOT to be misattributed via the colon-fallback, got '
				. var_export($unprefixed, true)
		);

		// Given: a GENUINELY file-prefixed line (a real grep path, which always contains
		// '/') for the SAME raw_prefix.
		// When/Then: it still attributes correctly through the identical colon-fallback --
		// proves the '/' guard does not break the real path-prefixed shape.
		$prefixed = pfb_ip_prefetch_last_match(['/path/to/feed.txt:2001:db8::1'], '2001:db8::1');
		$this->assertSame(
			'/path/to/feed.txt:2001:db8::1',
			$prefixed,
			'expected a genuinely path-prefixed line to still attribute correctly, got ' . var_export($prefixed, true)
		);
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

	/**
	 * B4 (issue #809 review): Round B's grouping key used to be the bare strstr() prefix
	 * (e.g. "10"), which collides between a v4 host ("10.0.0.5") and an unrelated v6 host
	 * ("10::1") -- both fall into ONE shared group, and whichever host's entry created it
	 * silently hands its v4_type/grep pattern to the OTHER family's host too. Qualifying
	 * the key by address family ('4|'/'6|') fixes this. RED before the fix (the v6 host
	 * mis-resolves to Unknown/Unknown via the wrong family's CIDR math), GREEN after.
	 */
	public function test_v4_and_v6_hosts_sharing_a_first_segment_do_not_collide_in_round_b_grouping(): void
	{
		// Given: a v4 host and a v6 host whose Round-B grouping key -- strstr() up to the
		// first '.' or ':' -- is the textually IDENTICAL bare string "10", each with a
		// REAL CIDR match in the fixture (fixtures/ip_prefetch/reports/ReportsFeedC.txt).
		$folder = "{$this->fixturesDir}/reports/*.txt";
		$hosts = ['10.0.0.5', '10::1'];
		$expected = [
			'10.0.0.5' => ['ReportsFeedC', '10.0.0.0/24'],
			'10::1'    => ['ReportsFeedC', '10::/32'],
		];

		// When/Then: both the per-row oracle AND the batched result must resolve each
		// host to its OWN family's real CIDR match.
		$this->assertBatchedHeadersMatchPerRow($hosts, $folder, FALSE, $expected, 'v4/v6 first-segment collision ("10")');
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
	// B3 (issue #809 review): a failed batched grep pass must never seed a false
	// negative.
	// ------------------------------------------------------------------------------

	/**
	 * Run a PHP body in a genuinely restricted CHILD process (issue #809 review, B3/R1)
	 * -- see DnsblPrefetchTest::runInRestrictedTempDirSandbox() for the full rationale
	 * (why a child process, why `open_basedir` is the only reliable lever: TMPDIR is
	 * ignored once sys_get_temp_dir() is cached, and tempnam() silently substitutes the
	 * real system temp dir for an invalid hint directory). $phpBody runs AFTER the real
	 * bootstrap.php has loaded the production include; it must `echo json_encode(...)`
	 * its result.
	 *
	 * @return array<string, mixed> the JSON-decoded child-process output
	 */
	private function runInRestrictedTempDirSandbox(string $phpBody): array
	{
		$repo = dirname(__DIR__, 2);
		$cacheDir = "{$repo}/.phpunit.cache";
		@mkdir($cacheDir, 0777, true);
		$probe = tempnam($cacheDir, 'pfb_sandbox_probe_');
		$this->assertNotFalse($probe, 'precondition: failed to create the sandbox probe script');

		try {
			$code = "<?php\nrequire " . var_export("{$repo}/tests/php/bootstrap.php", true) . ";\n" . $phpBody;
			file_put_contents($probe, $code);

			$cmd = 'php -d open_basedir=' . escapeshellarg($repo) . ' ' . escapeshellarg($probe) . ' 2>/dev/null';
			$output = shell_exec($cmd);
		} finally {
			@unlink($probe);
		}

		$decoded = json_decode((string) $output, true);
		$this->assertIsArray(
			$decoded,
			'expected the sandboxed child process to emit valid JSON, got ' . var_export($output, true)
		);
		return $decoded;
	}

	public function test_grep_lines_returns_null_when_the_pattern_file_cannot_be_created(): void
	{
		$body = '$lines = pfb_ip_prefetch_grep_lines(\'/bin/echo\', \'\', [\'^192\\\\.0\\\\.2\\\\.10\']);'
			. 'echo json_encode([\'lines\' => $lines]);';

		$decoded = $this->runInRestrictedTempDirSandbox($body);

		$this->assertArrayHasKey('lines', $decoded);
		$this->assertNull(
			$decoded['lines'],
			'expected pfb_ip_prefetch_grep_lines() to return NULL under a genuinely restricted temp dir, got '
				. var_export($decoded['lines'], true)
		);
	}

	/**
	 * RED before the fix: old code could not distinguish Round A's grep-lines failure
	 * from a genuine no-match, so it fell through to Round B -- which can ONLY find
	 * CIDR-shaped candidates (pfb_match_reported_cidr() discards non-CIDR lines), so an
	 * EXACT match unreachable via Round A silently resolved to Unknown/Unknown and was
	 * then CACHED as a definitive miss, a true false negative for a host that DOES have
	 * a real match. GREEN after: the miss round leaves the row entirely unseeded so
	 * convert_ip_log()'s per-row fallback (unaffected by the sandbox -- it never uses a
	 * pattern file) resolves it live instead.
	 */
	public function test_prefetch_leaves_the_miss_round_unseeded_when_round_a_pattern_file_cannot_be_created(): void
	{
		// Given: a host with a REAL EXACT match in the reports fixture, reachable ONLY
		// via Round A (Round B's CIDR walk ignores non-CIDR lines entirely) -- and the
		// per-row oracle proves that match still exists (it depends on no pattern file).
		$folder = "{$this->fixturesDir}/reports/*.txt";
		$oracle = find_reported_header('192.0.2.10', $folder);
		$this->assertSame(
			['ReportsFeedA', '192.0.2.10'],
			$oracle,
			'precondition: the per-row oracle must find a real exact match, got ' . var_export($oracle, true)
		);

		// When: the batched prefetch runs for this SAME row inside the restricted-
		// temp-dir sandbox.
		$body = ''
			. '$GLOBALS[\'pfb\'][\'grep\'] = \'/usr/bin/grep\';'
			. '$GLOBALS[\'pfb\'][\'denydir\'] = ' . var_export("{$this->fixturesDir}/deny", true) . ';'
			. '$GLOBALS[\'pfb\'][\'nativedir\'] = ' . var_export("{$this->fixturesDir}/native", true) . ';'
			. '$GLOBALS[\'pfb\'][\'ccdir\'] = ' . var_export("{$this->fixturesDir}/geoip", true) . ';'
			. '$GLOBALS[\'pfb\'][\'aliasdir\'] = ' . var_export("{$this->fixturesDir}/alias", true) . ';'
			. '$folder = ' . var_export($folder, true) . ';'
			. '$rows = [[\'host\' => \'192.0.2.10\', \'folder\' => $folder, \'validate_file_cmd\' => NULL, \'validate_cmd\' => NULL, \'eval_ip_raw\' => \'192.0.2.10\']];'
			. 'pfb_ip_prefetch($rows);'
			. '$memos = &pfb_ip_render_memos();'
			. '$missKey = \'192.0.2.10|\' . $folder;'
			. 'echo json_encode(['
			. '\'missSeeded\' => array_key_exists($missKey, $memos[\'miss\']),'
			. '\'missVal\' => $memos[\'miss\'][$missKey] ?? null,'
			. ']);';

		$decoded = $this->runInRestrictedTempDirSandbox($body);

		// Then: the miss round leaves this row entirely UNSEEDED -- never a cached
		// false Unknown/'' miss for a host with a real exact match.
		$this->assertArrayHasKey('missSeeded', $decoded);
		$this->assertFalse(
			$decoded['missSeeded'],
			'expected the miss round to leave this row unseeded when Round A\'s pattern file could not be created, got '
				. var_export($decoded['missVal'], true)
		);
	}

	/**
	 * R4: guards the try/finally pattern-file cleanup in pfb_ip_prefetch_grep_lines()
	 * against a future regression reintroducing a temp-file leak.
	 */
	public function test_prefetch_leaves_no_temp_pattern_files_behind(): void
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

		pfb_ip_prefetch($rows);

		$leftover = glob(sys_get_temp_dir() . '/pfb_ip_prefetch_*') ?: [];
		$this->assertSame(
			[],
			$leftover,
			'expected no pfb_ip_prefetch_* temp files to remain, found ' . var_export($leftover, true)
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
