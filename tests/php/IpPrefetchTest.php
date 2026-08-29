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
 * does not load) re-validates a reported IP against the CURRENT feed state on every render: one exec() to
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
 *   Scenario: pfb_ip_prefetch_last_match() -- complete-entry attribution
 *     direct unit tests, no exec: an unprefixed (single-file) line, a file-prefixed
 *     ("path:content") line, a genuine miss, longer textual prefixes in both shapes,
 *     and last-duplicate semantics. Only complete raw entries are attributed.
 *
 *   Scenario: find_reported_header() vs the batched pfb_find_reported_headers() sibling
 *     Differential (oracle) scenarios over a real fixture feed dir, real grep/find exec:
 *     exact v4 hit, exact v6 hit, a v4 CIDR hit AND a miss sharing the same first-octet
 *     Round-B query group, a v6 CIDR hit AND a miss sharing the same prefix Round-B group,
 *     longer textual prefix collisions, and two flavours of total miss (no CIDR
 *     candidates at all; CIDR candidates present but none contain the host). A SEPARATE
 *     fixture dir/geoip=TRUE case proves the ccdir-redirect branch too.
 *
 *   Scenario: pfb_ip_prefetch() end-to-end -- seeding pfb_ip_render_memos() for real rows
 *     Rows built via pfb_ip_render_query() (the SAME helper pfb_ip_render_attribution() calls)
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
 *     the tail after its first ':' happens to equal some host's raw_entry.
 *
 *   Scenario: B3 -- a failed batched grep pass must never seed a false negative
 *     A child `php` process with `open_basedir` whitelisting the repo tree and its
 *     bootstrap sandbox (but not sys_get_temp_dir()'s real system temp dir) genuinely fails
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
 *
 *   Scenario: issue #833 -- a single-.txt-file folder must resolve EXACT and CIDR
 *             matches correctly, and the aliastables round must force the same
 *             file-prefix output
 *     Pre-fix, grep given exactly one file emits its match UNPREFIXED, so
 *     pfb_parse_query() returns a 1-element array with no [1] -- every consumer
 *     reading result[1] (find_reported_header()'s own return, pfb_match_reported_
 *     cidr()'s CIDR-shape check) silently mishandles it, up to a genuinely
 *     covering CIDR being dropped to Unknown/Unknown. Every find_reported_
 *     header()/pfb_find_reported_headers() exec() (and the aliastables find|xargs
 *     grep pipeline) now appends a trailing /dev/null, forcing grep to always be
 *     given >=2 files -- it always emits the "path:" prefix. The issue #831
 *     skip-seed guard (a defensive no-fatal patch, not a real fix) is now dead
 *     code and removed; its regression test is updated to pin the row being
 *     correctly SEEDED instead of merely left alone.
 */
#[CoversFunction('pfb_match_reported_cidr')]
#[CoversFunction('pfb_ip_match_folders')]
#[CoversFunction('pfb_ip_render_query')]
#[CoversFunction('pfb_ip_render_memos')]
#[CoversFunction('pfb_ip_render_memos_reset')]
#[CoversFunction('pfb_prefetch_pattern_file_write_ok')]
#[CoversFunction('pfb_ip_exact_entry_pattern')]
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
			'grep'        => '/usr/bin/grep',
			'denydir'     => "{$this->fixturesDir}/deny",
			'nativedir'   => "{$this->fixturesDir}/native",
			'permitdir'   => "{$this->fixturesDir}/deny",	// unused by these tests' rows
			'matchdir'    => "{$this->fixturesDir}/deny",	// unused by these tests' rows
			// issue #1250: distinct from matchdir/nativedir so the folder-derivation
			// test below can prove all three are present, not just two.
			'matchgendir' => "{$this->fixturesDir}/deny/generated",
			'etdir'       => "{$this->fixturesDir}/deny",	// unused by these tests' rows
			'ccdir'       => "{$this->fixturesDir}/geoip",
			'aliasdir'    => "{$this->fixturesDir}/alias",
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
		// exercising its own pfb_ip_prefetch() call.
		pfb_ip_render_memos_reset();
	}

	protected function tearDown(): void
	{
		pfb_ip_render_memos_reset();
		unlink_if_exists("{$this->fixturesDir}/geoip/.pfb_generation.lock");

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

	public function test_cidr_helper_skips_stderr_shaped_lines_without_warning(): void
	{
		// Given: $result mixes a non-".txt:"-shaped stderr line (issue #843 -- e.g. a
		// grep stderr message captured via 2>&1; "grep -s" only silences "no such
		// file", not e.g. "Binary file X matches") with a real filename-prefixed match.
		// pfb_parse_query() must absorb the stderr line into its stable 2-element
		// [feed, value] shape (empty value) so no consumer reads past the array.
		$result = [
			'grep: warning: recursive search of stdin',
			'/var/db/pfblockerng/deny/DenyFeed.txt:203.0.113.0/28',
		];

		// A bare E_WARNING is not fatal to PHPUnit by default, so pre-fix this test
		// would pass despite the Undefined array key 1 warning going unnoticed.
		// Escalating it to an exception is what makes the missing-guard regression
		// deterministically red.
		set_error_handler(static function (int $errno, string $errstr): bool {
			throw new \ErrorException($errstr, 0, $errno);
		}, E_WARNING);

		try {
			// When: matching against the real CIDR's host.
			$match = pfb_match_reported_cidr($result, '203.0.113.5', TRUE);
		} finally {
			restore_error_handler();
		}

		// Then: the stderr line is skipped silently and the real match is still found.
		$this->assertSame(
			['DenyFeed', '203.0.113.0/28'],
			$match,
			'expected the stderr-shaped line to be skipped and DenyFeed\'s /28 to still match, got ' . var_export($match, true)
		);
	}

	public function test_cidr_helper_all_stderr_shaped_lines_yield_null_without_warning(): void
	{
		// Given: $result holds ONLY non-".txt:"-shaped lines (issue #843) -- the
		// all-miss input class: no CIDR candidate can be collected at all.
		$result = [
			'grep: warning: recursive search of stdin',
			'Binary file /var/db/pfblockerng/deny/DenyFeed.txt matches',
		];

		// Same E_WARNING escalation as the mixed-line case above: an unguarded read
		// past pfb_parse_query()'s result must fail this test, not pass unnoticed.
		set_error_handler(static function (int $errno, string $errstr): bool {
			throw new \ErrorException($errstr, 0, $errno);
		}, E_WARNING);

		try {
			// When: matching any host against the stderr-only result set.
			$match = pfb_match_reported_cidr($result, '203.0.113.5', TRUE);
		} finally {
			restore_error_handler();
		}

		// Then: no candidates, no warning -- a clean NULL miss.
		$this->assertNull(
			$match,
			'expected an all-stderr-shaped $result to yield a clean NULL, got ' . var_export($match, true)
		);
	}

	// ------------------------------------------------------------------------------
	// pfb_ip_prefetch_last_match()
	// ------------------------------------------------------------------------------

	public function test_last_match_unprefixed_single_file_shape(): void
	{
		$lines = ['203.0.113.0/28', '198.51.100.16/28'];
		$match = pfb_ip_prefetch_last_match($lines, '203.0.113.0/28');
		$this->assertSame('203.0.113.0/28', $match, 'expected the unprefixed line to be attributed, got ' . var_export($match, true));
	}

	public function test_last_match_file_prefixed_multi_file_shape(): void
	{
		// Realistic grep multi-file output: an ABSOLUTE path (every folder this module
		// greps is an absolute glob) before the ':' separator -- see N1's docblock for
		// why the '/' matters.
		$lines = ['/var/db/pfblockerng/deny/DenyFeedA.txt:203.0.113.0/28', '/var/db/pfblockerng/deny/DenyFeedB.txt:198.51.100.16/28'];
		$match = pfb_ip_prefetch_last_match($lines, '198.51.100.16/28');
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

	public function test_last_match_rejects_longer_textual_prefixes(): void
	{
		// Longer entries must not be attributed to a shorter address in either grep
		// output shape.
		$unprefixed = pfb_ip_prefetch_last_match(['203.0.113.45/32'], '203.0.113.4');
		$this->assertNull(
			$unprefixed,
			'expected an unprefixed longer entry not to be attributed, got ' . var_export($unprefixed, true)
		);

		$prefixed = pfb_ip_prefetch_last_match(['/var/db/pfblockerng/deny/DenyFeed.txt:203.0.113.45/32'], '203.0.113.4');
		$this->assertNull(
			$prefixed,
			'expected a file-prefixed longer entry not to be attributed, got ' . var_export($prefixed, true)
		);

		$duplicates = [
			'/var/db/pfblockerng/deny/DenyFeedA.txt:203.0.113.4',
			'/var/db/pfblockerng/deny/DenyFeedB.txt:203.0.113.4',
		];
		$this->assertSame(
			$duplicates[1],
			pfb_ip_prefetch_last_match($duplicates, '203.0.113.4'),
			'expected the last duplicate complete entry to retain exec() last-line semantics'
		);
	}

	/**
	 * N1 (issue #809 review): the colon-fallback used to fire on ANY ':' in the line,
	 * which misattributes an UNPREFIXED IPv6 content line (its OWN ':' is part of the
	 * address, not a "path:content" separator) whenever the tail after that first ':'
	 * happens to equal $raw_entry. Guarded now by requiring the segment before that ':'
	 * to look like a path (contain '/') -- true of every real grep path here, never true
	 * of a bare IPv6 literal.
	 */
	public function test_last_match_does_not_misattribute_an_unprefixed_ipv6_content_line_via_the_colon_fallback(): void
	{
		// Given: an unprefixed IPv6 content line whose tail-after-first-colon equals a
		// host's raw_entry.
		// When/Then: it must NOT be attributed via the colon-fallback.
		$unprefixed = pfb_ip_prefetch_last_match(['2001:db8::1'], 'db8::1');
		$this->assertNull(
			$unprefixed,
			'expected an unprefixed IPv6 content line NOT to be misattributed via the colon-fallback, got '
				. var_export($unprefixed, true)
		);

		// Given: a GENUINELY file-prefixed line (a real grep path, which always contains
		// '/') for the SAME raw_entry.
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
			'198.51.100.4',		// longer textual prefix collision ("198.51.100.45")
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
			'198.51.100.4'       => ['Unknown', 'Unknown'],
			'198.51.100.99'      => ['Unknown', 'Unknown'],
			'192.0.2.222'        => ['Unknown', 'Unknown'],
		];

		$this->assertBatchedHeadersMatchPerRow($hosts, $folder, FALSE, $expected, 'reports fixture, non-geoip');
	}

	public function test_per_row_and_batch_require_complete_v4_v6_entries_across_orders_and_fallbacks(): void
	{
		$cases = [
			['192.0.2.5', ['192.0.2.52', '192.0.2.54'], '192.0.2.0/24'],
			['198.51.100.18', ['198.51.100.188'], '198.51.100.0/24'],
			['203.0.113.4', ['203.0.113.48'], '203.0.113.0/24'],
			['2001:db8::1', ['2001:db8::10', '2001:db8::12'], '2001:db8::/64'],
		];
		$tmp = sys_get_temp_dir() . '/pfb_1367_collisions_' . bin2hex(random_bytes(6));
		mkdir($tmp, 0777, true);
		$savedCcdir = $GLOBALS['pfb']['ccdir'];

		try {
			$GLOBALS['pfb']['ccdir'] = $tmp;
			foreach ($cases as [$host, $collisions, $cidr]) {
				foreach ([FALSE, TRUE] as $geoip) {
					foreach ([FALSE, TRUE] as $collisionFirst) {
						$first = $collisionFirst ? implode("\n", $collisions) : $host;
						$second = $collisionFirst ? $host : implode("\n", $collisions);
						file_put_contents("{$tmp}/A.txt", "{$first}\n");
						file_put_contents("{$tmp}/B.txt", "{$second}\n");

						$expectedFeed = $collisionFirst ? 'B' : 'A';
						$this->assertBatchedHeadersMatchPerRow(
							[$host],
							"{$tmp}/*.txt",
							$geoip,
							[$host => [$expectedFeed, $host]],
							"exact entry with collisions; geoip=" . ($geoip ? 'true' : 'false')
						);

						$first = $collisionFirst ? implode("\n", $collisions) : $cidr;
						$second = $collisionFirst ? $cidr : implode("\n", $collisions);
						file_put_contents("{$tmp}/A.txt", "{$first}\n");
						file_put_contents("{$tmp}/B.txt", "{$second}\n");
						$expectedFeed = $collisionFirst ? 'B' : 'A';
						$this->assertBatchedHeadersMatchPerRow(
							[$host],
							"{$tmp}/*.txt",
							$geoip,
							[$host => [$expectedFeed, $cidr]],
							"CIDR fallback with collisions; geoip=" . ($geoip ? 'true' : 'false')
						);
					}
				}

				file_put_contents("{$tmp}/A.txt", implode("\n", $collisions) . "\n");
				@unlink("{$tmp}/B.txt");
				$this->assertBatchedHeadersMatchPerRow(
					[$host],
					"{$tmp}/*.txt",
					FALSE,
					[$host => ['Unknown', 'Unknown']],
					'single-file forced-prefix collision miss'
				);
			}
		} finally {
			$GLOBALS['pfb']['ccdir'] = $savedCcdir;
			rmdir_recursive($tmp);
		}
	}

	public function test_exact_entry_inputs_preserve_cidr_boundaries_ipv6_forms_and_strict_bytes(): void
	{
		$tmp = sys_get_temp_dir() . '/pfb_1367_entries_' . bin2hex(random_bytes(6));
		mkdir($tmp, 0777, true);
		$folder = "{$tmp}/*.txt";

		try {
			$exact = [
				'192.0.2.5',
				'2001:db8::1',
				'2001:0db8:0:0:0:0:0:2',
			];
			file_put_contents("{$tmp}/Exact.txt", implode("\n", $exact) . "\n");
			foreach ($exact as $host) {
				$this->assertBatchedHeadersMatchPerRow(
					[$host], $folder, FALSE, [$host => ['Exact', $host]], 'exact textual IPv4/IPv6 entry at EOL'
				);
			}

			foreach ([
				['203.0.113.9', '203.0.113.0/0'],
				['192.0.2.5', '192.0.2.4/31'],
				['192.0.2.5', '192.0.2.5/32'],
				['2001:db8::9', '2001:db8::/0'],
				['2001:db8::1', '2001:db8::/127'],
				['2001:db8::1', '2001:db8::1/128'],
			] as [$host, $cidr]) {
				file_put_contents("{$tmp}/Exact.txt", "{$cidr}\n");
				$this->assertBatchedHeadersMatchPerRow(
					[$host], $folder, FALSE, [$host => ['Exact', $cidr]], "legal CIDR fallback {$cidr}"
				);
			}

			file_put_contents("{$tmp}/Exact.txt", "192.0.2.5\r\n192.0.2.5 \n2001:db8::1\r\n2001:db8::1 \n");
			foreach (['192.0.2.5', '2001:db8::1'] as $host) {
				$this->assertBatchedHeadersMatchPerRow(
					[$host], $folder, FALSE, [$host => ['Unknown', 'Unknown']], 'CRLF/trailing whitespace strict miss'
				);
			}
		} finally {
			rmdir_recursive($tmp);
		}
	}

	public function test_invalid_hosts_cannot_expand_as_regex_or_shell_patterns(): void
	{
		$tmp = sys_get_temp_dir() . '/pfb_1367_invalid_' . bin2hex(random_bytes(6));
		mkdir($tmp, 0777, true);
		file_put_contents("{$tmp}/Feed.txt", "192.0.2.5\n2001:db8::1\n");
		$folder = "{$tmp}/*.txt";

		try {
			foreach (['', '.*', '[0-9]', '^$', '\\', '-1', '999.999.999.999', "192.0.2.5\0junk", "2001:db8::1\0junk"] as $host) {
				$this->assertNull(
					pfb_ip_exact_entry_pattern($host),
					"expected invalid host " . var_export($host, true) . ' to produce no exact-entry pattern'
				);
				$this->assertSame(
					['Unknown', 'Unknown'],
					find_reported_header($host, $folder),
					"expected invalid host " . var_export($host, true) . ' to be a safe per-row miss'
				);
				$batched = pfb_find_reported_headers([$host], $folder);
				$this->assertSame(
					['Unknown', 'Unknown'],
					$batched[$host],
					"expected invalid host " . var_export($host, true) . ' to be a safe batched miss'
				);
			}
		} finally {
			rmdir_recursive($tmp);
		}
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
	// issue #833: a folder glob resolving to exactly ONE .txt file must resolve
	// EXACT and CIDR matches correctly, not silently drop them
	// ------------------------------------------------------------------------------

	/**
	 * Scenario: a single-file folder holding an EXACT match for the reported IP.
	 *
	 * Given: pre-fix, grep given exactly one file emits its match UNPREFIXED, so
	 * pfb_parse_query() returns a 1-element array (no [1]) -- find_reported_
	 * header()'s exact-match branch returns that 1-element array VERBATIM (it has
	 * no Unknown/Unknown fallback of its own), corrupting every caller that reads
	 * result[1] (e.g. pfb_ip_render_attribution() builds a degenerate '^' aliastables
	 * pattern from the resulting NULL).
	 * When: the per-row AND batched lookups both run against the single-file
	 * folder.
	 * Then: both resolve the real (feed, ip) pair -- RED before the fix (a
	 * 1-element array), GREEN after (grep's forced /dev/null file-prefix gives
	 * pfb_parse_query() the 2-element shape).
	 */
	public function test_single_file_folder_exact_match_resolves_correctly_per_row_and_batched(): void
	{
		$tmp = sys_get_temp_dir() . '/pfb_833_exact_' . getmypid();
		mkdir($tmp, 0777, true);
		file_put_contents("{$tmp}/LoneFeed.txt", "192.0.2.201\n");
		$folder = "{$tmp}/*.txt";

		try {
			$perRow = find_reported_header('192.0.2.201', $folder);
			$this->assertSame(
				['LoneFeed', '192.0.2.201'],
				$perRow,
				'expected the per-row find_reported_header() to resolve the exact match in the single-file folder, got '
					. var_export($perRow, true)
			);

			$batched = pfb_find_reported_headers(['192.0.2.201'], $folder);
			$this->assertSame(
				['LoneFeed', '192.0.2.201'],
				$batched['192.0.2.201'],
				'expected the batched pfb_find_reported_headers() to resolve the exact match in the single-file folder, got '
					. var_export($batched['192.0.2.201'], true)
			);
		} finally {
			unlink("{$tmp}/LoneFeed.txt");
			rmdir($tmp);
		}
	}

	/**
	 * Scenario: a single-file folder whose ONLY covering entry is a CIDR (no
	 * exact-match line at all) -- the WORST pre-fix failure mode.
	 *
	 * Given: pre-fix, the exact-match round misses (the file has no line equal
	 * to the host), so the prefix/CIDR round runs pfb_match_reported_cidr()
	 * against the single-file $result. Each line goes through pfb_parse_query(),
	 * which -- unprefixed -- returns a 1-element array with no [1]; `strpos($rx[1]
	 * ?? NULL, '/')` then NEVER recognises the line as CIDR-shaped, so the
	 * genuinely-covering CIDR is silently dropped and the host resolves to
	 * Unknown/Unknown ("Not listed!") even though it IS still covered.
	 * When: the per-row AND batched lookups both run against the single-file
	 * folder.
	 * Then: both resolve the real CIDR header -- RED before the fix (silently
	 * "Not listed!"), GREEN after.
	 */
	public function test_single_file_folder_cidr_only_coverage_resolves_correctly_per_row_and_batched(): void
	{
		$tmp = sys_get_temp_dir() . '/pfb_833_cidr_' . getmypid();
		mkdir($tmp, 0777, true);
		file_put_contents("{$tmp}/LoneCidrFeed.txt", "192.0.2.0/24\n");
		$folder = "{$tmp}/*.txt";

		try {
			$perRow = find_reported_header('192.0.2.5', $folder);
			$this->assertSame(
				['LoneCidrFeed', '192.0.2.0/24'],
				$perRow,
				'expected the per-row find_reported_header() to resolve the CIDR match in the single-file folder, got '
					. var_export($perRow, true)
			);

			$batched = pfb_find_reported_headers(['192.0.2.5'], $folder);
			$this->assertSame(
				['LoneCidrFeed', '192.0.2.0/24'],
				$batched['192.0.2.5'],
				'expected the batched pfb_find_reported_headers() to resolve the CIDR match in the single-file folder, got '
					. var_export($batched['192.0.2.5'], true)
			);
		} finally {
			unlink("{$tmp}/LoneCidrFeed.txt");
			rmdir($tmp);
		}
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
		// pfb_ip_render_attribution() call would use -- the deny+native glob, block-branch folder.
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
		// issue #833: the alias fixture dir (fixtures/ip_prefetch/alias) holds exactly
		// ONE .txt file, so the aliastables grep is now forced (via /dev/null) to emit
		// its "path:" prefix -- the shape pfb_ip_render_attribution()'s alias-name parse
		// chain requires.
		$missKey = "{$rq['host']}|{$rq['folder']}";
		$this->assertArrayHasKey($missKey, $memos['miss'], "expected the miss round to seed key '{$missKey}'");
		$expectedRawValidate = "{$GLOBALS['pfb']['aliasdir']}/pfB_SomeAlias_v4.txt:192.0.2.0/24";
		$this->assertSame(
			[['DenyFeed', '192.0.2.0/24'], $expectedRawValidate],
			$memos['miss'][$missKey],
			'expected [pfb_query, raw_validate] to be ' . var_export([['DenyFeed', '192.0.2.0/24'], $expectedRawValidate], true)
				. ', got ' . var_export($memos['miss'][$missKey], true)
		);
	}

	/**
	 * issue #1250: reputation/dMax artifacts relocated to matchgendir -- a 'match'
	 * event's folder set must still search matchdir/nativedir (unchanged) AND now
	 * also matchgendir (widened), or an event caused by a relocated artifact
	 * attributes to nothing on the Alerts page.
	 */
	public function test_match_action_folder_includes_matchdir_matchgendir_and_nativedir(): void
	{
		$fields = $this->buildBlockFields('192.0.2.90');
		$fields[3] = 'match';	// Action -- the branch under test

		$rq = pfb_ip_render_query($fields);

		// Then: the derived folder glob names all three dirs -- dropping matchgendir
		// silences attribution for every reputation-artifact match; dropping matchdir
		// or nativedir would silence the pre-existing two.
		$this->assertSame(
			"{$GLOBALS['pfb']['matchdir']}/*.txt {$GLOBALS['pfb']['matchgendir']}/*.txt {$GLOBALS['pfb']['nativedir']}/*.txt",
			$rq['folder'],
			"expected the 'match' folder to be matchdir+matchgendir+nativedir, got: {$rq['folder']}"
		);
	}

	/**
	 * issue #1250: the match-artifact dirs are defined ONCE, in pfb_ip_match_folders(), and
	 * shared by the Alerts query (above) and pfb_daemon_filterlog()'s live tail. The daemon
	 * copy sits inside an unbounded php://stdin loop that cannot be unit-tested, so pinning
	 * the shared helper is what covers it -- the daemon's correctness reduces to calling this.
	 */
	public function test_match_folders_helper_names_both_match_dirs_and_nothing_else(): void
	{
		$this->assertSame(
			"{$GLOBALS['pfb']['matchdir']}/*.txt {$GLOBALS['pfb']['matchgendir']}/*.txt",
			pfb_ip_match_folders(),
			'expected pfb_ip_match_folders() to name matchdir + matchgendir, got: ' . pfb_ip_match_folders()
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
	 * Run a PHP body in a genuinely restricted CHILD process (issue #809 review, B3/R1):
	 * a child process is the only reliable lever, since TMPDIR is ignored once
	 * sys_get_temp_dir() is cached, and tempnam() silently substitutes the real system
	 * temp dir for an invalid hint directory. $phpBody runs AFTER the real bootstrap.php
	 * has loaded the production include; it must `echo json_encode(...)` its result.
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
			$code = "<?php\nrequire " . var_export("{$repo}/tests/php/bootstrap.php", TRUE) . ";\n"
				. 'ini_set(\'open_basedir\', ' . var_export($repo, TRUE) . ' . PATH_SEPARATOR . $pfb_test_tmp);' . "\n"
				. $phpBody;
			file_put_contents($probe, $code);

			// Apply the restriction after bootstrap creates its own sandbox. Keep that exact
			// tree allowed so its shutdown cleanup works, while sys_get_temp_dir() itself
			// remains outside open_basedir and the body still exercises tempnam() failure.
			// issue #896: stderr routing keeps PHP 8.5's tempnam() warning out of JSON stdout.
			$cmd = 'php -d display_errors=stderr ' . escapeshellarg($probe) . ' 2>/dev/null';
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

	/** issue #1349: migrated pin for the shared write-outcome predicate after DnsblPrefetchTest retired. */
	public function test_write_complete_helper_flags_a_short_write_as_incomplete(): void
	{
		$data = "line-one\nline-two\n";

		$short = pfb_prefetch_pattern_file_write_ok(strlen($data) - 3, $data);
		$this->assertFalse($short, 'expected a short byte count to be flagged as an incomplete write');

		$failed = pfb_prefetch_pattern_file_write_ok(FALSE, $data);
		$this->assertFalse($failed, 'expected FALSE to be flagged as an incomplete write');

		$complete = pfb_prefetch_pattern_file_write_ok(strlen($data), $data);
		$this->assertTrue($complete, 'expected an exact full-length write to be flagged as complete');
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
	 * pfb_ip_render_attribution()'s per-row fallback (unaffected by the sandbox -- it never uses a
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
		$tempDir = sys_get_temp_dir() . '/pfb_ip_prefetch_cleanup_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($tempDir, 0755), "failed to create owned temp dir {$tempDir}");

		$repo = dirname(__DIR__, 2);
		$code = 'require ' . var_export("{$repo}/tests/php/bootstrap.php", TRUE) . ';'
			. '$lines = pfb_ip_prefetch_grep_lines(\'/bin/echo\', \'\', [\'^probe$\']);'
			. 'echo json_encode(['
			. '\'ran\' => is_array($lines),'
			. '\'leftover\' => glob(sys_get_temp_dir() . \'/pfb_ip_prefetch_*\') ?: []'
			. ']);';
		try {
			$cmd = 'TMPDIR=' . escapeshellarg($tempDir) . ' ' . escapeshellarg(PHP_BINARY)
				. ' -d ' . escapeshellarg("sys_temp_dir={$tempDir}") . ' -r ' . escapeshellarg($code);
			$output = shell_exec($cmd);
		} finally {
			rmdir_recursive($tempDir);
		}

		$decoded = json_decode((string) $output, TRUE);
		$this->assertIsArray($decoded, 'expected valid child JSON, got ' . var_export($output, TRUE));
		$this->assertTrue($decoded['ran'] ?? FALSE, 'expected the helper to create and process its pattern file');
		$this->assertSame(
			[],
			$decoded['leftover'] ?? NULL,
			'expected no pfb_ip_prefetch_* temp files to remain in the test-owned temp dir, found '
				. var_export($decoded['leftover'] ?? NULL, TRUE)
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
		// issue #833: see the sibling assertion above -- the single-file alias
		// fixture's raw_validate is now the forced-prefix "path:content" shape.
		$expectedRawValidate = "{$GLOBALS['pfb']['aliasdir']}/pfB_SomeAlias_v4.txt:192.0.2.0/24";
		$this->assertSame([['DenyFeed', '192.0.2.0/24'], $expectedRawValidate], $memos['miss'][$missKey]);

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
			// pfb_ip_render_attribution() does on every render), still returns the correct cached
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
				$expectedRawValidate,
				$cachedValidate,
				'expected the CACHED aliastables content to survive the directories disappearing, got ' . var_export($cachedValidate, true)
			);
		} finally {
			foreach ($renamed as $key => $path) {
				rename($path . $deletedSuffix, $path);
			}
		}
	}

	// ------------------------------------------------------------------------------
	// issue #831 / #833: a single-.txt folder must never fatal, and must resolve
	// its miss round correctly (not merely avoid a crash)
	// ------------------------------------------------------------------------------

	/**
	 * Scenario: a miss-path row whose folder is a SINGLE glob token expanding to
	 * exactly ONE .txt file (a GeoIP row's ccdir here; an ET row's etdir is the
	 * other in-tree shape).
	 *
	 * Given: pre-issue-#833, with exactly one file argument grep emitted its
	 * match UNPREFIXED (no "path:" part), so pfb_parse_query() returned a
	 * one-element array with no [1] -- issue #831's guard caught this and left
	 * the row unseeded (no fatal, but no seed either). issue #833 fixes the ROOT
	 * CAUSE instead: every find_reported_header()/pfb_find_reported_headers()
	 * exec() now appends a trailing /dev/null, forcing grep to always be given
	 * >=2 files -- it always emits the "path:" prefix, so pfb_parse_query()
	 * always returns the 2-element shape and the #831 guard is now dead code
	 * (removed).
	 * (The Block/Permit/Match folders were always immune to the ORIGINAL bug:
	 * their two-token "<dir>/*.txt <nativedir>/*.txt" list already hands grep a
	 * second argument -- even an unexpanded literal counts -- forcing filename
	 * prefixes with no #833 fix needed.)
	 * When: pfb_ip_prefetch() runs its miss + aliastables rounds for that row.
	 * Then: the prefetch completes WITHOUT the issue #831 TypeError, AND the row
	 * is now correctly SEEDED with the real (feed, value) pair -- no longer left
	 * to pfb_ip_render_attribution()'s per-row fallback.
	 */
	public function test_single_file_folder_miss_row_is_correctly_seeded_after_the_833_fix(): void
	{
		// Given: a GeoIP cc dir holding exactly ONE feed file that contains the host.
		$tmp = sys_get_temp_dir() . '/pfb_831_' . getmypid();
		mkdir("{$tmp}/cc", 0777, true);
		file_put_contents("{$tmp}/cc/LoneFeed.txt", "192.0.2.201\n");
		$GLOBALS['pfb']['ccdir'] = "{$tmp}/cc";

		try {
			// Given: a GeoIP-aliased row (continent alias routes folder=ccdir) whose
			// logged feed name has no on-disk file, so the validate round misses and
			// the row enters the miss round against the single-token cc glob.
			$fields     = $this->buildBlockFields('192.0.2.201');
			$fields[13] = 'pfB_Top_v4';
			$fields[15] = 'GoneFeed';
			$rq         = pfb_ip_render_query($fields);

			$rows = [[
				'host'              => $rq['host'],
				'folder'            => $rq['folder'],
				'validate_file_cmd' => $rq['validate_file_cmd'],
				'validate_cmd'      => $rq['validate_cmd'],
				'eval_ip_raw'       => $fields[14],
			]];

			// When: the batched prefetch runs. Pre-#833-fix this reached the #831
			// skip-seed guard (no TypeError, but the row stayed unseeded); reaching
			// the assertions below with a SEEDED, CORRECT entry IS this fix.
			pfb_ip_prefetch($rows);
			$memos = &pfb_ip_render_memos();

			// Then: the validate round itself seeded normally (its miss is genuine).
			$this->assertSame(
				'',
				$memos['validate'][$rq['validate_cmd']] ?? 'MISSING',
				"expected the validate round to seed '' for the single-file row, got "
					. var_export($memos['validate'][$rq['validate_cmd']] ?? 'MISSING', true)
			);

			// Then: the miss round is now SEEDED with the correct exact match --
			// find_reported_header()'s forced-prefix grep resolved 'LoneFeed', and
			// the aliastables round genuinely misses (the class-wide alias fixture
			// only holds an unrelated CIDR), seeding the empty-string no-hit.
			$missKey = "{$rq['host']}|{$rq['folder']}";
			$this->assertSame(
				[['LoneFeed', '192.0.2.201'], ''],
				$memos['miss'][$missKey] ?? 'MISSING',
				"expected miss key '{$missKey}' to be correctly seeded for the single-file match, got "
					. var_export($memos['miss'][$missKey] ?? 'MISSING', true)
			);
		} finally {
			foreach (["{$tmp}/cc/LoneFeed.txt", "{$tmp}/cc", $tmp] as $path) {
				if (is_file($path)) {
					unlink($path);
				} elseif (is_dir($path)) {
					rmdir($path);
				}
			}
		}
	}

	// ------------------------------------------------------------------------------
	// issue #832: an ET/Proofpoint row's validate command must not break `find`
	// with escaped-empty operands
	// ------------------------------------------------------------------------------

	/**
	 * Scenario: an ET/Proofpoint-style row (':' in the logged Feed Name) blanks
	 * $query/$query_host/$query_prefix in pfb_ip_render_query() -- there is no
	 * per-feed filename filter, every file under etdir is a candidate.
	 *
	 * Given: such a row.
	 * When: pfb_ip_render_query() builds its validate_file_cmd.
	 * Then: the command is a plain `find <etdir>/*.txt -type f` with NO escaped
	 * empty-string operands -- pre-fix it appended `{$query_prefix} '' ''`
	 * (all three blanked), which made `find` itself error out ("unknown primary
	 * or operator") and silently emit nothing, so the validate round always
	 * missed for every ET row.
	 */
	public function test_et_header_validate_file_cmd_has_no_empty_find_operands(): void
	{
		$fields     = $this->buildBlockFields('192.0.2.201');
		$fields[15] = 'IQRisk:Category1';	// ':' in the Feed Name -- the ET/Proofpoint branch

		$rq = pfb_ip_render_query($fields);

		$expected = "/usr/bin/find {$GLOBALS['pfb']['etdir']}/*.txt -type f";
		$this->assertSame(
			$expected,
			$rq['validate_file_cmd'],
			"expected an ET row's validate_file_cmd to carry no filename filter, got "
				. var_export($rq['validate_file_cmd'], true)
		);
	}

	/**
	 * Scenario: an ET row whose reported IP is STILL present, verbatim, in its ET
	 * feed file -- the exact real-world case issue #832 reports as broken.
	 *
	 * Given: a real etdir fixture file containing the reported IP.
	 * When: the row's validate_cmd (built by pfb_ip_render_query()) is actually
	 * exec()'d, exactly as pfb_ip_render_attribution() does.
	 * Then: the still-listed line comes back. Pre-fix, `find`'s primary-operator
	 * error left the pipe with nothing for `xargs grep` to search, so this always
	 * came back empty (a false "no longer listed") regardless of the real feed
	 * state.
	 */
	public function test_et_header_still_listed_ip_is_found_by_the_real_validate_exec(): void
	{
		$tmp = sys_get_temp_dir() . '/pfb_832_et_' . getmypid();
		mkdir($tmp, 0777, true);
		file_put_contents("{$tmp}/IQRiskFeed.txt", "192.0.2.201\n");
		$savedEtdir = $GLOBALS['pfb']['etdir'];
		$GLOBALS['pfb']['etdir'] = $tmp;

		try {
			$fields     = $this->buildBlockFields('192.0.2.201');
			$fields[15] = 'IQRisk:Category1';

			$rq = pfb_ip_render_query($fields);
			$this->assertNotNull($rq['validate_cmd'], 'expected a validate command to be built for a known IP/feed');

			exec($rq['validate_cmd'], $output, $exitCode);

			$this->assertNotEmpty(
				$output,
				"expected the real validate exec to find the still-listed IP via '{$rq['validate_cmd']}', "
					. 'got empty output (exit ' . $exitCode . ') -- this is the issue #832 symptom: '
					. "find errors out on the escaped-empty operands and the row silently reads as delisted"
			);
			$this->assertStringContainsString(
				'192.0.2.201',
				implode("\n", $output),
				'expected the matched line to contain the reported IP, got ' . var_export($output, true)
			);
		} finally {
			$GLOBALS['pfb']['etdir'] = $savedEtdir;
			unlink("{$tmp}/IQRiskFeed.txt");
			rmdir($tmp);
		}
	}

	/**
	 * Regression guard: the issue #832 fix only special-cases the ET branch's
	 * blanked $query/$query_host/$query_prefix -- a normal (non-ET) Block row's
	 * validate_file_cmd must stay byte-for-byte the command it was before.
	 */
	public function test_non_et_validate_file_cmd_shape_is_unchanged(): void
	{
		$fields = $this->buildBlockFields('192.0.2.77');
		$rq     = pfb_ip_render_query($fields);

		$queryEsc     = escapeshellarg($GLOBALS['pfb']['grep']);
		$queryHostEsc = escapeshellarg('OldFeed.txt');	// buildBlockFields()'s fields[15]
		$expected     = "/usr/bin/find {$rq['folder']} -type f | {$queryEsc} {$queryHostEsc}";

		$this->assertSame(
			$expected,
			$rq['validate_file_cmd'],
			"expected a non-ET row's validate_file_cmd shape to stay unchanged, got "
				. var_export($rq['validate_file_cmd'], true)
		);
	}
}
