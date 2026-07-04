<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_parse_compute() -- issue #837: the per-row DNSBL data/zone grep sites build a
 * BRE pattern that escapes ONLY the dot metacharacter (str_replace('.', '\.', $domain)).
 * Any OTHER BRE metachar in the query domain rides into the regex live:
 *   - a query domain carrying a metachar can FALSE-MATCH a different, unrelated literal
 *     domain already in the data/zone file (e.g. 'a*b837.com' as BRE means zero-or-more
 *     'a' then literal 'b837.com' -- matches the line for plain 'b837.com');
 *   - conversely, a domain that itself carries a metachar and IS present verbatim in the
 *     data/zone file can fail to be found by its own mis-escaped pattern.
 *
 * Fix: both per-row grep sites match with `-F` (fixed string) against the raw, unescaped
 * domain/suffix -- the same shape the batched prefetch pass (pfb_dnsbl_prefetch_grep())
 * already uses.
 *
 * Feature: the per-row DNSBL data/zone lookup treats the query domain as a literal string
 *   Background:
 *     Given the real DNSBL data/zone file line shape ",{domain-or-suffix},,{log},{feed},{group}"
 *     And pfb_dnsbl_parse_compute() run in a mode that is neither 'alerts' (which caches
 *       ONE SQLite3 handle for the life of the PHP process) nor 'daemon' (which returns a
 *       packed CSV string instead of the assoc array asserted below) -- a fresh SQLite3
 *       cache handle opens and closes on every call, so a distinct cache-db path per test
 *       is real isolation.
 */
#[CoversFunction('pfb_dnsbl_parse_compute')]
final class DnsblParseComputeMetacharTest extends TestCase
{
	/** @var array<string, mixed>|null */
	private ?array $savedPfb = null;

	private ?string $tmpDir = null;

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? null;
		pfb_dnsbl_prefetch_store(NULL);
	}

	protected function tearDown(): void
	{
		pfb_dnsbl_prefetch_store(NULL);
		if ($this->savedPfb === null) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		if ($this->tmpDir !== null) {
			rmdir_recursive($this->tmpDir);	// the util.inc double from pfsense_doubles.php
			$this->tmpDir = null;
		}
	}

	/**
	 * Fresh per-test sandbox: its own tmp dir, data/zone fixture files, and SQLite cache
	 * path. Because parse() below never runs in 'alerts' mode, every call opens/closes its
	 * own SQLite3 handle against THIS test's cache path -- no state leaks between tests.
	 */
	private function seedSandbox(string $dataContent, string $zoneContent): void
	{
		$tmpDir = sys_get_temp_dir() . '/pfb_dnsbl_metachar_test_' . bin2hex(random_bytes(8));
		mkdir($tmpDir, 0777, true);
		$this->tmpDir = $tmpDir;

		$dataFile = "{$tmpDir}/data.txt";
		$zoneFile = "{$tmpDir}/zone.txt";
		file_put_contents($dataFile, $dataContent);
		file_put_contents($zoneFile, $zoneContent);

		$GLOBALS['pfb'] = [
			'grep'            => '/usr/bin/grep',
			'extdns'          => '127.0.0.1', // deterministic: no drill CNAME answers on any machine
			'unbound_py_data' => $dataFile,
			'unbound_py_zone' => $zoneFile,
			'dnsbl_cache'     => "{$tmpDir}/dnsblcache.sqlite",
			'errlog'          => "{$tmpDir}/error.log",
			'sqlite_timeout'  => 2000,
		];
	}

	/**
	 * mode='test' -- neither 'alerts' nor 'daemon', so pfb_dnsbl_parse_compute() opens and
	 * closes a fresh SQLite3 handle per call and returns the assoc-array shape. @ suppresses
	 * the pre-existing (out-of-scope) "Undefined variable $cname_cnt" notice a total miss
	 * raises when drill finds no CNAME -- unrelated legacy noise, not the value under test.
	 */
	private function parse(string $domain): array
	{
		return @pfb_dnsbl_parse_compute('test', $domain, '', '');
	}

	/**
	 * Given a data-file line for a domain that itself carries a live BRE metachar ('*').
	 * When looked up by its own literal value.
	 * Then it is found -- RED pre-fix (the query's own metachar breaks its own escaped-BRE
	 * pattern, so it comes back 'Unknown' instead of its real feed/group), GREEN post-fix.
	 */
	public function test_metachar_domain_present_in_data_file_is_found(): void
	{
		$domain = 'rv837*m1.com';
		$this->seedSandbox(",{$domain},,A,FeedX,GroupX\n", '');

		$result = $this->parse($domain);

		$this->assertSame(
			['pfb_mode' => 'DNSBL', 'pfb_group' => 'GroupX', 'pfb_final' => $domain, 'pfb_feed' => 'FeedX'],
			$result,
			"expected the metachar domain '{$domain}' to be found by its own literal data-file entry, got " . var_export($result, true)
		);
	}

	/**
	 * Given a data-file line for a DIFFERENT, unrelated literal domain ('b837.com').
	 * When a domain carrying a live BRE metachar ('a*b837.com', BRE = zero-or-more 'a' then
	 * 'b837.com') is looked up.
	 * Then it does NOT match that unrelated entry -- RED pre-fix (the per-row BRE
	 * false-matches, mis-attributing FeedB/GroupB to a domain that was never listed),
	 * GREEN post-fix ('-F' treats '*' as a literal character, so no match -> 'Unknown').
	 */
	public function test_metachar_domain_cannot_false_match_a_different_literal_domain(): void
	{
		$queryDomain = 'a*b837.com';
		$this->seedSandbox(",b837.com,,A,FeedB,GroupB\n", '');

		$result = $this->parse($queryDomain);

		$this->assertSame(
			['pfb_mode' => 'Unknown', 'pfb_group' => 'Unknown', 'pfb_final' => 'Unknown', 'pfb_feed' => 'Unknown'],
			$result,
			"expected the metachar query '{$queryDomain}' NOT to false-match the unrelated data-file entry for 'b837.com', got " . var_export($result, true)
		);
	}

	/**
	 * Regression pin: an ordinary (metachar-free) domain is found in the data file both
	 * before and after the fix -- the common path is undisturbed.
	 */
	public function test_plain_domain_still_found_in_data_file(): void
	{
		$domain = 'plain837.com';
		$this->seedSandbox(",{$domain},,A,PlainFeed,PlainGroup\n", '');

		$result = $this->parse($domain);

		$this->assertSame(
			['pfb_mode' => 'DNSBL', 'pfb_group' => 'PlainGroup', 'pfb_final' => $domain, 'pfb_feed' => 'PlainFeed'],
			$result,
			"expected the plain domain '{$domain}' to be found in the data file, got " . var_export($result, true)
		);
	}

	/**
	 * Given a zone-file line for a metachar TLD/suffix ('rv837*z1.com') present verbatim.
	 * When a subdomain of it is looked up via the label-walk.
	 * Then the label-walk finds the suffix and reports it as the evaluated TLD -- RED
	 * pre-fix (the zone site has the identical escaped-BRE bug, so its own suffix is never
	 * found at any label-walk depth), GREEN post-fix. $pfb_final is asserted to equal the
	 * exact literal suffix, proving the fix's `$pfb_final = $suffix` replacement (no
	 * escape/unescape round-trip needed once the pattern is a plain literal).
	 */
	public function test_metachar_suffix_present_in_zone_file_is_found_as_tld(): void
	{
		$suffix = 'rv837*z1.com';
		$queryDomain = "sub.{$suffix}";
		$this->seedSandbox('', ",{$suffix},,A,FeedZ,GroupZ\n");

		$result = $this->parse($queryDomain);

		$this->assertSame(
			['pfb_mode' => 'TLD', 'pfb_group' => 'GroupZ', 'pfb_final' => $suffix, 'pfb_feed' => 'FeedZ'],
			$result,
			"expected the metachar suffix '{$suffix}' to be found via the zone label-walk for '{$queryDomain}', got " . var_export($result, true)
		);
	}

	/**
	 * Regression pin: an ordinary (metachar-free) suffix is still found via the zone
	 * label-walk both before and after the fix.
	 */
	public function test_plain_suffix_zone_walk_still_found(): void
	{
		$suffix = 'plainzone837.com';
		$queryDomain = "sub.{$suffix}";
		$this->seedSandbox('', ",{$suffix},,A,PlainZoneFeed,PlainZoneGroup\n");

		$result = $this->parse($queryDomain);

		$this->assertSame(
			['pfb_mode' => 'TLD', 'pfb_group' => 'PlainZoneGroup', 'pfb_final' => $suffix, 'pfb_feed' => 'PlainZoneFeed'],
			$result,
			"expected the plain suffix '{$suffix}' to be found via the zone label-walk for '{$queryDomain}', got " . var_export($result, true)
		);
	}
}
