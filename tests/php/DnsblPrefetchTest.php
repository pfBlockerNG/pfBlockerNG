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
 *
 *   B2 (issue #809 review): a domain carrying a live BRE metacharacter (anything besides
 *   '.') is excluded from prefetch coverage entirely -- the per-row site's BRE only ever
 *   escapes '.', so such a domain can false-match a DIFFERENT literal line under the
 *   per-row exec that a batched `-F` fixed-string match never would. Proven by a
 *   differential: the unseeded AND "seeded" (never actually covered) lookups must agree,
 *   both landing on the per-row BRE path.
 *
 *   B3/R1 (issue #809 review): a batched grep pass whose pattern file cannot be created
 *   or fully written returns a NULL sentinel -- distinct from a genuine empty-array
 *   no-match result -- and pfb_dnsbl_prefetch() must leave its store entirely unseeded
 *   on that failure (never seed a false negative from a partial/failed batch).
 *
 *   R4: after a prefetch pass, no pfb_dnsbl_prefetch_* pattern-file temp file remains --
 *   guards the try/finally cleanup against a future regression.
 */
#[CoversFunction('pfb_dnsbl_prefetch')]
#[CoversFunction('pfb_dnsbl_prefetch_grep')]
#[CoversFunction('pfb_dnsbl_prefetch_store')]
#[CoversFunction('pfb_dnsbl_parse_compute')]
#[CoversFunction('pfb_prefetch_pattern_file_write_ok')]
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

	/**
	 * B2 (issue #809 review): a domain outside PFB_FILTER_DOMAIN's charset carries a live
	 * BRE metacharacter into the per-row site's regex (which escapes ONLY '.'), so it can
	 * false-match a DIFFERENT literal data-file line under the per-row BRE that a batched
	 * `-F` fixed-string match never would. Excluding such a domain from prefetch coverage
	 * entirely means BOTH the unseeded and "seeded" lookups fall through to the identical
	 * per-row BRE path and therefore agree -- RED before the fix (the seeded consult
	 * diverged to Unknown while the per-row BRE false-matched RealFeed/RealGroup), GREEN
	 * after.
	 */
	public function test_a_domain_with_a_live_bre_metacharacter_is_excluded_from_prefetch_coverage(): void
	{
		$domain = 'evil.[0-9].example.com';

		$this->assertPrefetchMatchesPerRow($domain, [
			'pfb_mode'  => 'DNSBL',
			'pfb_group' => 'RealGroup',
			'pfb_final' => 'evil.5.example.com',
			'pfb_feed'  => 'RealFeed',
		], 'BRE metacharacter domain false-matches a different literal domain via the per-row BRE path');
	}

	/**
	 * Run a PHP body in a genuinely restricted CHILD process (issue #809 review, B3/R1).
	 *
	 * Why a child process: `sys_get_temp_dir()` caches its resolved value for the life
	 * of a PHP process (a real engine behaviour, confirmed empirically -- a bad TMPDIR
	 * set via putenv() AFTER anything has already called sys_get_temp_dir() once, which
	 * PHPUnit's own bootstrap does, is silently ignored). And even freshly, tempnam()
	 * silently substitutes the real system temp dir for an invalid hint directory, so
	 * neither lever can force a genuine failure once a real writable temp dir exists.
	 * The one remaining, fully deterministic lever: `open_basedir`, set via the `php`
	 * CLI's `-d` flag BEFORE the interpreter starts, whitelisting ONLY the repo tree --
	 * excluding sys_get_temp_dir()'s real system temp directory -- so
	 * tempnam(sys_get_temp_dir(), ...) genuinely fails inside it. This MUST run in a
	 * separate `php` invocation, never inline in this PHPUnit process: `open_basedir`
	 * can only ever be NARROWED for the life of a process, never widened back, so
	 * setting it here would permanently break every following test in this same
	 * PHPUnit run. $phpBody runs AFTER the real bootstrap.php has loaded the production
	 * include; it must `echo json_encode(...)` its result.
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

	/**
	 * Given: a domain that WOULD hit the real data-file fixture (a genuine positive,
	 * proving this pins a false-negative regression and is not a tautology).
	 * When: the pattern-file grep helper -- and then the whole prefetch pass -- run
	 * inside the restricted-temp-dir sandbox.
	 * Then: the helper signals failure via the NULL sentinel (not an empty-array
	 * "no match"), and pfb_dnsbl_prefetch() leaves its store entirely unseeded rather
	 * than caching a false negative for a domain that DOES have a real hit. RED before
	 * the fix (verified directly: the pre-fix code returns `[]` from the grep helper
	 * and seeds the store with 'covered' => TRUE / empty 'data' -- a real false
	 * negative), GREEN after.
	 */
	public function test_prefetch_leaves_the_store_unseeded_when_a_grep_pass_pattern_file_cannot_be_created(): void
	{
		$domain = 'uuid-exact-hit-8f2a.example.com';

		$body = ''
			. '$GLOBALS[\'pfb\'][\'grep\'] = \'/usr/bin/grep\';'
			. '$GLOBALS[\'pfb\'][\'unbound_py_data\'] = ' . var_export($this->dataFile, true) . ';'
			. '$GLOBALS[\'pfb\'][\'unbound_py_zone\'] = ' . var_export($this->zoneFile, true) . ';'
			. '$domain = ' . var_export($domain, true) . ';'
			. '$direct = pfb_dnsbl_prefetch_grep([\',\' . $domain . \',,\'], $GLOBALS[\'pfb\'][\'unbound_py_data\']);'
			. 'pfb_dnsbl_prefetch([$domain]);'
			. '$store = pfb_dnsbl_prefetch_store();'
			. 'echo json_encode([\'direct\' => $direct, \'store\' => $store]);';

		$decoded = $this->runInRestrictedTempDirSandbox($body);

		$this->assertArrayHasKey('direct', $decoded);
		$this->assertNull(
			$decoded['direct'],
			'expected pfb_dnsbl_prefetch_grep() to return NULL under a genuinely restricted temp dir, got '
				. var_export($decoded['direct'], true)
		);
		$this->assertArrayHasKey('store', $decoded);
		$this->assertNull(
			$decoded['store'],
			'expected pfb_dnsbl_prefetch() to leave the store NULL when a grep pass fails, got '
				. var_export($decoded['store'], true)
		);
	}

	/**
	 * R1: the write-outcome predicate must flag a SHORT (partial, non-FALSE) write as
	 * incomplete -- not just a bare `=== FALSE` failure. A genuine disk-full short write
	 * cannot be forced deterministically/portably in a unit test (verified: `open_basedir`
	 * fails the CREATE step, never a partial WRITE), so this pins the extracted decision
	 * predicate directly with fabricated byte counts -- exactly the "testable shape"
	 * fallback for an unforceable OS failure. The predicate is new code: it does not
	 * exist pre-fix (calling it errors on the old source), so red<->green here is "did
	 * not exist / wrong verdict" -> "exists and rules correctly" for every input shape.
	 */
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

	/**
	 * B3 regression guard: a genuine total miss (real files, zero grep hits -- NOT a
	 * pattern-file failure) must still SEED the store, marking the domain covered with an
	 * empty 'data' entry. Distinguishes the real "ran successfully, found nothing" state
	 * from the NULL "did not run at all" sentinel the B3 fix introduces -- pins existing
	 * behaviour, so this stays green both before and after that fix.
	 */
	public function test_prefetch_still_seeds_a_genuine_total_miss_domain_as_covered(): void
	{
		$domain = 'uuid-totalmiss-8f2a.example.com';
		pfb_dnsbl_prefetch_store(NULL);

		pfb_dnsbl_prefetch([$domain]);

		$store = pfb_dnsbl_prefetch_store();
		$this->assertNotNull($store, 'expected a successful prefetch pass (even with zero hits) to seed a non-NULL store');
		$this->assertArrayHasKey($domain, $store['covered'], "expected '{$domain}' to be marked covered despite the total miss");
		$this->assertArrayNotHasKey(
			$domain,
			$store['data'],
			"expected no 'data' entry for a genuine miss, found " . var_export($store['data'][$domain] ?? null, true)
		);

		pfb_dnsbl_prefetch_store(NULL);
	}

	/**
	 * R4: guards the try/finally pattern-file cleanup in pfb_dnsbl_prefetch_grep() against
	 * a future regression reintroducing a temp-file leak.
	 */
	public function test_prefetch_leaves_no_temp_pattern_files_behind(): void
	{
		pfb_dnsbl_prefetch_store(NULL);
		pfb_dnsbl_prefetch(['uuid-exact-hit-8f2a.example.com']);

		// is_file() filters out this class's OWN per-process sandbox directories
		// (setUp()'s "pfb_dnsbl_prefetch_test_<pid>", never cleaned up by design -- a
		// stable-per-process path, not a pattern-file leak) -- only a REGULAR FILE
		// under this prefix can be a leaked tempnam() pattern file.
		$leftover = array_values(array_filter(glob(sys_get_temp_dir() . '/pfb_dnsbl_prefetch_*') ?: [], 'is_file'));
		$this->assertSame(
			[],
			$leftover,
			'expected no pfb_dnsbl_prefetch_* temp files to remain, found ' . var_export($leftover, true)
		);

		pfb_dnsbl_prefetch_store(NULL);
	}
}
