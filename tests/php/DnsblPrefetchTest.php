<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_prefetch() / pfb_dnsbl_prefetch_grep() / pfb_dnsbl_prefetch_store() -- the
 * issue #809 Phase 3a batching layer for the Alerts page's per-type DNSBL table.
 *
 * pfb_dnsbl_parse_compute() (the real work behind pfb_dnsbl_parse()) greps the DNSBL
 * data/zone files per row on a dnsblcache miss. This phase adds a page-scope prefetch
 * pass that runs those same greps ONCE, batched, for a whole page's worth of domains,
 * plus two consult sites inside pfb_dnsbl_parse_compute() that -- IFF a prefetch store
 * is seeded and covers the domain/suffix being looked up -- serve the batched answer
 * instead of re-exec'ing. Behaviour must be IDENTICAL to the per-row path for every
 * match shape the real code supports.
 *
 * Feature: batching the DNSBL data/zone grep lookups preserves per-row semantics
 *   Background:
 *     Given the real DNSBL data/zone file formats (",{domain-or-suffix},,{log},{feed},{group}")
 *     And a small fixture of each (tests/php/fixtures/dnsbl_prefetch_{data,zone}.txt)
 *
 *   Differential (oracle) scenarios -- an unseeded per-row exec and a prefetch-seeded
 *   consult, for the SAME domain, must both equal the SAME known-correct result:
 *     - an exact data-file hit
 *     - a zone-file hit at label-walk depth 1 / 2 / 3
 *     - a total miss (no data hit, no zone hit at any depth)
 *     - two domains sharing one zone suffix, prefetched together (suffix dedup)
 *     - a domain repeated in the data file / a suffix repeated in the zone file
 *       (first-in-file wins, matching the per-row `grep -m1` semantics)
 *
 *   Negative-proof (the red<->green evidence a consult, not a fallback exec, ran): seed
 *   the store from the REAL fixtures, then swap the data/zone file globals to paths
 *   that do not exist, and assert the seeded domains STILL resolve correctly -- a
 *   covered domain must never fall through to a per-row exec, which against a missing
 *   file can only return empty/'Unknown', never the correct non-'Unknown' answer.
 */
#[CoversFunction('pfb_dnsbl_prefetch')]
#[CoversFunction('pfb_dnsbl_prefetch_grep')]
#[CoversFunction('pfb_dnsbl_prefetch_store')]
#[CoversFunction('pfb_dnsbl_parse_compute')]
final class DnsblPrefetchTest extends TestCase
{
	private string $dataFile;
	private string $zoneFile;
	private string $missingDataFile;
	private string $missingZoneFile;
	private string $cacheDb;

	/** @var array<string, mixed> */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		$this->savedGlobals['pfb'] = $GLOBALS['pfb'] ?? null;

		$this->dataFile = __DIR__ . '/fixtures/dnsbl_prefetch_data.txt';
		$this->zoneFile = __DIR__ . '/fixtures/dnsbl_prefetch_zone.txt';

		// A stable-per-process sandbox dir. pfb_dnsbl_parse_compute()'s 'alerts' mode
		// caches its SQLite3 handle in a function-static var for the life of the PHP
		// process, so every setUp() in this class must agree on the same cache-db path
		// -- whichever test method runs first is the one that actually opens it.
		$tmp_dir = sys_get_temp_dir() . '/pfb_dnsbl_prefetch_test_' . getmypid();
		@mkdir($tmp_dir, 0777, true);

		$this->missingDataFile = "{$tmp_dir}/does-not-exist-data.txt";
		$this->missingZoneFile = "{$tmp_dir}/does-not-exist-zone.txt";
		$this->cacheDb = "{$tmp_dir}/dnsblcache.sqlite";

		$GLOBALS['pfb'] = [
			'grep'            => '/usr/bin/grep',
			'extdns'          => '203.0.113.53', // TEST-NET-3 (RFC 5737); drill is absent off-appliance anyway
			'unbound_py_data' => $this->dataFile,
			'unbound_py_zone' => $this->zoneFile,
			'dnsbl_cache'     => $this->cacheDb,
			'errlog'          => "{$tmp_dir}/error.log",
			'sqlite_timeout'  => 2000,
		];

		pfb_dnsbl_prefetch_store(NULL);
	}

	protected function tearDown(): void
	{
		pfb_dnsbl_prefetch_store(NULL);
		if ($this->savedGlobals['pfb'] === null) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedGlobals['pfb'];
		}
	}

	/**
	 * Delete a single domain's row from the shared dnsblcache SQLite file via an
	 * INDEPENDENT connection -- the 'alerts'-mode static handle inside
	 * pfb_dnsbl_parse_compute() cannot be reset from outside it. Needed between an
	 * unseeded and a seeded call for the SAME domain in the differential scenarios
	 * below, so the second call cannot short-circuit through the row the first call
	 * just inserted: both calls must reach the real data/zone lookup logic (once via
	 * exec, once via the seeded store) for the comparison to mean anything.
	 */
	private function clearDnsblCacheRow(string $domain): void
	{
		$db = @new SQLite3($this->cacheDb);
		if (!$db) {
			return;
		}
		// @ -- the very first call in the process can race ahead of the 'alerts'-mode
		// CREATE TABLE IF NOT EXISTS (run by pfb_open_sqlite() inside the first
		// pfb_dnsbl_parse_compute() call), so the table may not exist yet; prepare()
		// then raises a PHP warning as well as returning FALSE. Both are expected and
		// harmless here -- the guard below is what actually matters.
		$stmt = @$db->prepare('DELETE FROM dnsblcache WHERE domain = :domain');
		if ($stmt) {
			$stmt->bindValue(':domain', $domain, SQLITE3_TEXT);
			$stmt->execute();
		}
		$db->close();
	}

	/**
	 * Call pfb_dnsbl_parse_compute('alerts', ...) for $domain. A genuine total-miss
	 * domain falls through to the CNAME/drill chase, which has a pre-existing (Phase
	 * 3a out-of-scope) "Undefined variable $cname_cnt" notice when drill is absent
	 * (true of this environment) and no CNAME is found -- @ keeps that unrelated
	 * legacy noise out of this phase's test output without masking the return value
	 * under test.
	 */
	private function parse(string $domain): array
	{
		return @pfb_dnsbl_parse_compute('alerts', $domain, '', '');
	}

	/**
	 * The oracle: an unseeded per-row lookup and a prefetch-seeded consult for the SAME
	 * domain, against the SAME real fixture files, must both equal $expected --
	 * asserting against a concrete known value (not just "both sides agree with each
	 * other") so a regression that breaks BOTH paths identically still fails this test.
	 */
	private function assertPrefetchMatchesPerRow(string $domain, array $expected, string $scenario): void
	{
		// Given: the store is unseeded and this domain's cache row is clear.
		pfb_dnsbl_prefetch_store(NULL);
		$this->clearDnsblCacheRow($domain);

		// When: pfb_dnsbl_parse_compute() runs the real per-row exec (no store seeded).
		$unseeded = $this->parse($domain);

		// Then: it matches the known-correct fixture result.
		$this->assertSame(
			$expected,
			$unseeded,
			"[{$scenario}] expected the UNSEEDED per-row lookup for '{$domain}' to be "
				. var_export($expected, true) . ', got ' . var_export($unseeded, true)
		);

		// When: the row (a) just wrote is cleared, the SAME domain is prefetched from
		// the SAME real fixture files, and looked up again.
		$this->clearDnsblCacheRow($domain);
		pfb_dnsbl_prefetch([$domain]);
		$seeded = $this->parse($domain);

		// Then: the prefetch-seeded consult reproduces the identical, correct result.
		$this->assertSame(
			$expected,
			$seeded,
			"[{$scenario}] expected the PREFETCH-SEEDED lookup for '{$domain}' to be "
				. var_export($expected, true) . ', got ' . var_export($seeded, true)
		);

		pfb_dnsbl_prefetch_store(NULL);
	}

	public function test_exact_data_file_hit(): void
	{
		$domain = 'uuid-exact-hit-8f2a.example.com';
		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'DNSBL',
			'pfb_group' => 'ExactGroup',
			'pfb_final' => $domain,
			'pfb_feed'  => 'ExactFeed',
		], 'exact data-file hit');
	}

	public function test_zone_hit_at_label_walk_depth_1(): void
	{
		$domain = 'www.uuid-zone-d1-8f2a.example.com';
		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'TLD',
			'pfb_group' => 'ZoneGroup1',
			'pfb_final' => 'uuid-zone-d1-8f2a.example.com',
			'pfb_feed'  => 'ZoneFeed1',
		], 'zone hit, depth 1 (one leftmost label stripped)');
	}

	public function test_zone_hit_at_label_walk_depth_2(): void
	{
		$domain = 'www.sub.uuid-zone-d2-8f2a.example.com';
		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'TLD',
			'pfb_group' => 'ZoneGroup2',
			'pfb_final' => 'uuid-zone-d2-8f2a.example.com',
			'pfb_feed'  => 'ZoneFeed2',
		], 'zone hit, depth 2 (two leftmost labels stripped)');
	}

	public function test_zone_hit_at_label_walk_depth_3(): void
	{
		$domain = 'www.sub.deep.uuid-zone-d3-8f2a.example.com';
		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'TLD',
			'pfb_group' => 'ZoneGroup3',
			'pfb_final' => 'uuid-zone-d3-8f2a.example.com',
			'pfb_feed'  => 'ZoneFeed3',
		], 'zone hit, depth 3 (three leftmost labels stripped)');
	}

	public function test_total_miss_no_data_no_zone_hit_at_any_depth(): void
	{
		$domain = 'uuid-totalmiss-8f2a.example.com';
		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'Unknown',
			'pfb_group' => 'Unknown',
			'pfb_final' => 'Unknown',
			'pfb_feed'  => 'Unknown',
		], 'total miss');
	}

	public function test_first_occurrence_wins_when_a_domain_repeats_in_the_data_file(): void
	{
		$domain = 'uuid-firsthit-8f2a.example.com';
		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'DNSBL',
			'pfb_group' => 'FirstGroup',
			'pfb_final' => $domain,
			'pfb_feed'  => 'FirstFeed',
		], 'data-file first-hit-wins');
	}

	public function test_first_occurrence_wins_when_a_suffix_repeats_in_the_zone_file(): void
	{
		$domain = 'x.uuid-zonedup-8f2a.example.com';
		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'TLD',
			'pfb_group' => 'ZoneDupFirstGroup',
			'pfb_final' => 'uuid-zonedup-8f2a.example.com',
			'pfb_feed'  => 'ZoneDupFirstFeed',
		], 'zone-file first-hit-wins');
	}

	public function test_two_domains_sharing_a_zone_suffix_both_resolve_via_one_prefetch_pass(): void
	{
		$domainA  = 'one.uuid-shared-8f2a.example.com';
		$domainB  = 'two.uuid-shared-8f2a.example.com';
		$expected = [
			'pfb_mode'  => 'TLD',
			'pfb_group' => 'SharedGroup',
			'pfb_final' => 'uuid-shared-8f2a.example.com',
			'pfb_feed'  => 'SharedFeed',
		];

		// Given: each domain resolves correctly on its own, unseeded.
		foreach ([$domainA, $domainB] as $domain) {
			pfb_dnsbl_prefetch_store(NULL);
			$this->clearDnsblCacheRow($domain);
			$unseeded = $this->parse($domain);
			$this->assertSame(
				$expected,
				$unseeded,
				"expected the unseeded per-row lookup for '{$domain}' to hit the shared zone suffix, got " . var_export($unseeded, true)
			);
		}

		// When: BOTH domains are prefetched TOGETHER in one pfb_dnsbl_prefetch() call --
		// exercising suffix de-duplication (one zone pattern/store entry serves the
		// suffix both domains share).
		pfb_dnsbl_prefetch_store(NULL);
		$this->clearDnsblCacheRow($domainA);
		$this->clearDnsblCacheRow($domainB);
		pfb_dnsbl_prefetch([$domainA, $domainB]);

		// Then: both consult the same batched entry and resolve identically to the
		// unseeded lookups above.
		foreach ([$domainA, $domainB] as $domain) {
			$seeded = $this->parse($domain);
			$this->assertSame(
				$expected,
				$seeded,
				"expected the prefetch-seeded lookup for '{$domain}' to match the per-row result via the shared suffix, got " . var_export($seeded, true)
			);
		}

		pfb_dnsbl_prefetch_store(NULL);
	}

	public function test_covered_domains_resolve_without_reading_the_files(): void
	{
		// Given: a data-file hit and a zone-file hit, prefetched from the REAL fixture
		// files.
		$dataHitDomain = 'uuid-exact-hit-8f2a.example.com';
		$zoneHitDomain = 'www.sub.uuid-zone-d2-8f2a.example.com';

		pfb_dnsbl_prefetch_store(NULL);
		$this->clearDnsblCacheRow($dataHitDomain);
		$this->clearDnsblCacheRow($zoneHitDomain);
		pfb_dnsbl_prefetch([$dataHitDomain, $zoneHitDomain]);

		// When: the backing data/zone file globals are swapped for paths that do NOT
		// exist -- any per-row exec that still reached them would hit grep's silent
		// (-s) "no such file" failure and return empty, same as a genuine miss.
		$this->assertFileDoesNotExist($this->missingDataFile, 'precondition: the swapped-in data path must not exist');
		$this->assertFileDoesNotExist($this->missingZoneFile, 'precondition: the swapped-in zone path must not exist');
		$GLOBALS['pfb']['unbound_py_data'] = $this->missingDataFile;
		$GLOBALS['pfb']['unbound_py_zone'] = $this->missingZoneFile;
		$this->clearDnsblCacheRow($dataHitDomain);
		$this->clearDnsblCacheRow($zoneHitDomain);

		// Then: pfb_dnsbl_parse_compute() STILL resolves both correctly from the seeded
		// prefetch store -- this is the proof the covered path never re-execs: a
		// fallen-through exec against a missing file can only return empty/'Unknown',
		// never the correct non-'Unknown' feed/group asserted below.
		$dataResult = $this->parse($dataHitDomain);
		$this->assertSame(
			['pfb_mode' => 'DNSBL', 'pfb_group' => 'ExactGroup', 'pfb_final' => $dataHitDomain, 'pfb_feed' => 'ExactFeed'],
			$dataResult,
			'expected the data-file hit to resolve from the seeded prefetch store with the data file missing, got ' . var_export($dataResult, true)
		);

		$zoneResult = $this->parse($zoneHitDomain);
		$this->assertSame(
			['pfb_mode' => 'TLD', 'pfb_group' => 'ZoneGroup2', 'pfb_final' => 'uuid-zone-d2-8f2a.example.com', 'pfb_feed' => 'ZoneFeed2'],
			$zoneResult,
			'expected the zone-file hit to resolve from the seeded prefetch store with the zone file missing, got ' . var_export($zoneResult, true)
		);

		pfb_dnsbl_prefetch_store(NULL);
	}

	public function test_prefetch_store_bare_read_never_resets_only_an_explicit_null_does(): void
	{
		// Given: the store already holds a seeded value.
		pfb_dnsbl_prefetch_store(['covered' => ['x' => TRUE], 'data' => [], 'zone_covered' => [], 'zone' => []]);

		// When: read with no arguments (NOT an explicit NULL) twice in a row,
		$first  = pfb_dnsbl_prefetch_store();
		$second = pfb_dnsbl_prefetch_store();

		// Then: the seeded value comes back unchanged both times -- a bare read never resets.
		$this->assertNotNull($first, 'expected a bare read to return the seeded value, not NULL');
		$this->assertSame($first, $second, 'expected two consecutive bare reads to return the identical value');

		// And: an explicit NULL argument DOES reset -- this is how the Alerts page
		// clears the store once its DNSBL table render pass finishes.
		pfb_dnsbl_prefetch_store(NULL);
		$this->assertNull(pfb_dnsbl_prefetch_store(), 'expected an explicit NULL argument to reset the store to "no prefetch ran"');
	}
}
