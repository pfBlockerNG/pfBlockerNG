<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #149 — pin the off-appliance contract of the SafeSearch CNAME glue that
 * feeds pfb_unbound.py's CNAME redirect (duckduckgo.com / pixabay.com):
 *
 *   - pfb_ss_csv_rows()      : formats one host's python CSV row(s). The CSV is the
 *                             boundary pfb_unbound.py parses, so its column contract
 *                             (3-col rewrite/nxdomain vs 5-col cname) is load-bearing.
 *   - pfb_ss_refresh_lines() : the pure transform behind the 15-min freshness cron —
 *                             re-bakes the #2 fallback IPs on CNAME rows in place.
 *   - pfb_ss_resolve_target(): the empty-target guard (the live drill resolution is
 *                             smoke-covered, not unit — it execs an external tool).
 *
 * The live legs (real drill resolution, the on-box cron rewrite + reload, and the
 * Python redirect itself) are the issue #149 live smoke.
 *
 * Feature: SafeSearch CNAME CSV + fallback freshness
 *   Background:
 *     Given the SafeSearch python CSV uses 3 columns for A/AAAA/nxdomain rows
 *           (domain,A,AAAA) and 5 columns for a CNAME redirect
 *           (domain,cname,target,baked_v4,baked_v6)
 *
 * Branch coverage (every condition, both sides):
 *   csv_rows:      nxdomain row;  A/AAAA rewrite row (+ www variant);
 *                  cname row with baked IPs (+ www);  cname row with empty baked IPs.
 *   refresh_lines: a CNAME row whose target resolves to NEW IPs -> changed + updated;
 *                  resolves to the SAME IPs -> unchanged;
 *                  fails to resolve (empty) -> KEEPS prior IPs, unchanged;
 *                  non-CNAME / malformed rows preserved verbatim;
 *                  each distinct target resolved exactly once (memo).
 *   resolve_target: empty target -> ['',''] without calling the resolver.
 *
 * PFBL-01 boundary (both sides): a target failing pfb_filter(PFB_FILTER_DOMAIN) is
 * rejected BEFORE any command is composed — logged + the same ['',''] shape as the
 * empty-target guard (so the refresh keeps prior baked IPs); a domain-valid target
 * passes the boundary with no rejection logged and proceeds to resolution.
 */
#[CoversFunction('pfb_ss_csv_rows')]
#[CoversFunction('pfb_ss_refresh_lines')]
#[CoversFunction('pfb_ss_resolve_target')]
final class SafeSearchCnameTest extends TestCase
{
	private string $tmp;
	private array $savedPfbKeys = [];
	private array $hadPfbKeys = [];

	protected function setUp(): void
	{
		// Per-test log + extdns sandbox for the resolve_target boundary assertions.
		$this->tmp = sys_get_temp_dir() . '/pfb_ss_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);
		foreach (['log', 'errlog', 'extdns'] as $key) {
			$this->hadPfbKeys[$key]   = array_key_exists($key, $GLOBALS['pfb'] ?? []);
			$this->savedPfbKeys[$key] = $GLOBALS['pfb'][$key] ?? null;
		}
		$GLOBALS['pfb']['log']    = "{$this->tmp}/log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/errlog";
		// Loopback resolver: never generates external traffic off-appliance.
		$GLOBALS['pfb']['extdns'] = '127.0.0.1';
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfbKeys as $key => $value) {
			if ($this->hadPfbKeys[$key]) {
				$GLOBALS['pfb'][$key] = $value;
			} else {
				unset($GLOBALS['pfb'][$key]);
			}
		}
		rmdir_recursive($this->tmp);
	}

	private function logContents(): string
	{
		$path = $GLOBALS['pfb']['log'];
		return file_exists($path) ? (string) file_get_contents($path) : '';
	}
	// --- pfb_ss_csv_rows -------------------------------------------------------

	public function test_csv_rows_nxdomain_is_single_three_col_row(): void
	{
		// Given an nxdomain SafeSearch entry, Then a single domain,nxdomain,nxdomain row.
		$this->assertSame(
			"bad.example.com,nxdomain,nxdomain\n",
			pfb_ss_csv_rows('bad.example.com', ['nxdomain' => ''])
		);
	}

	public function test_csv_rows_a_rewrite_emits_host_and_www(): void
	{
		// Given an A/AAAA rewrite entry, Then a 3-col row for the host AND its www variant.
		$this->assertSame(
			"forcesafe.example.com,1.2.3.4,\n" .
			"www.forcesafe.example.com,1.2.3.4,\n",
			pfb_ss_csv_rows('forcesafe.example.com', ['A' => '1.2.3.4', 'AAAA' => ''])
		);
	}

	public function test_csv_rows_cname_emits_five_col_with_baked_ips_and_www(): void
	{
		// Given a CNAME entry with baked fallback IPs, Then a 5-col cname row for the
		// host AND its www variant, carrying target + baked v4/v6.
		$this->assertSame(
			"duckduckgo.com,cname,safe.duckduckgo.com,203.0.113.7,2001:db8::7\n" .
			"www.duckduckgo.com,cname,safe.duckduckgo.com,203.0.113.7,2001:db8::7\n",
			pfb_ss_csv_rows(
				'duckduckgo.com',
				['A' => 'cname', 'AAAA' => 'safe.duckduckgo.com'],
				'203.0.113.7',
				'2001:db8::7'
			)
		);
	}

	public function test_csv_rows_cname_without_baked_ips_keeps_empty_columns(): void
	{
		// The without-baked side: a CNAME row is still 5 columns, with empty baked
		// fields, so the column count never varies between cname rows.
		$this->assertSame(
			"pixabay.com,cname,safesearch.pixabay.com,,\n" .
			"www.pixabay.com,cname,safesearch.pixabay.com,,\n",
			pfb_ss_csv_rows('pixabay.com', ['A' => 'cname', 'AAAA' => 'safesearch.pixabay.com'])
		);
	}

	// --- pfb_ss_refresh_lines --------------------------------------------------

	public function test_refresh_updates_cname_row_when_target_resolves_to_new_ip(): void
	{
		// Given a CNAME row with stale baked IPs, When the target resolves to NEW IPs,
		// Then the row's baked columns are rewritten and changed is TRUE. The before
		// (stale IPs in the input) and after (new IPs in the output) are both asserted.
		$lines = ['duckduckgo.com,cname,safe.duckduckgo.com,9.9.9.9,2001:db8::old'];
		$resolver = fn (string $t): array => ['203.0.113.7', '2001:db8::7'];

		[$out, $changed] = pfb_ss_refresh_lines($lines, $resolver);

		$this->assertTrue($changed);
		$this->assertSame(['duckduckgo.com,cname,safe.duckduckgo.com,203.0.113.7,2001:db8::7'], $out);
	}

	public function test_refresh_no_change_when_target_resolves_to_same_ip(): void
	{
		// When the target resolves to the SAME IPs already baked, Then changed is FALSE
		// (the cron will not rewrite the file or trigger a reload).
		$lines = ['duckduckgo.com,cname,safe.duckduckgo.com,203.0.113.7,2001:db8::7'];
		$resolver = fn (string $t): array => ['203.0.113.7', '2001:db8::7'];

		[$out, $changed] = pfb_ss_refresh_lines($lines, $resolver);

		$this->assertFalse($changed);
		$this->assertSame($lines, $out);
	}

	public function test_refresh_keeps_prior_ip_when_resolution_fails(): void
	{
		// When re-resolution FAILS (empty result), Then the prior baked IP is KEPT
		// (never blanked) and changed is FALSE — a transient DNS failure must not strip
		// a good fallback IP.
		$lines = ['duckduckgo.com,cname,safe.duckduckgo.com,203.0.113.7,2001:db8::7'];
		$resolver = fn (string $t): array => ['', ''];

		[$out, $changed] = pfb_ss_refresh_lines($lines, $resolver);

		$this->assertFalse($changed);
		$this->assertSame($lines, $out);
	}

	public function test_refresh_preserves_non_cname_rows_verbatim(): void
	{
		// 3-col rewrite/nxdomain rows (and any malformed row) are passed through
		// untouched; only 5-col cname rows are re-resolved.
		$lines = [
			'forcesafe.example.com,1.2.3.4,',
			'bad.example.com,nxdomain,nxdomain',
			'',
		];
		$called = 0;
		$resolver = function (string $t) use (&$called): array {
			$called++;
			return ['9.9.9.9', ''];
		};

		[$out, $changed] = pfb_ss_refresh_lines($lines, $resolver);

		$this->assertFalse($changed);
		$this->assertSame($lines, $out);
		$this->assertSame(0, $called, 'resolver must not be called for non-cname rows');
	}

	public function test_refresh_resolves_each_distinct_target_once(): void
	{
		// The host and its www. variant share one target -> the resolver is memoized
		// and invoked exactly once per distinct target.
		$lines = [
			'duckduckgo.com,cname,safe.duckduckgo.com,9.9.9.9,',
			'www.duckduckgo.com,cname,safe.duckduckgo.com,9.9.9.9,',
		];
		$targets = [];
		$resolver = function (string $t) use (&$targets): array {
			$targets[] = $t;
			return ['203.0.113.7', ''];
		};

		[$out, $changed] = pfb_ss_refresh_lines($lines, $resolver);

		$this->assertTrue($changed);
		$this->assertSame(['safe.duckduckgo.com'], $targets, 'target resolved exactly once');
		$this->assertSame(
			[
				'duckduckgo.com,cname,safe.duckduckgo.com,203.0.113.7,',
				'www.duckduckgo.com,cname,safe.duckduckgo.com,203.0.113.7,',
			],
			$out
		);
	}

	// --- pfb_ss_resolve_target -------------------------------------------------

	public function test_resolve_target_empty_returns_empty_pair(): void
	{
		// The empty-target guard returns ['',''] without attempting resolution.
		$this->assertSame(['', ''], pfb_ss_resolve_target(''));
	}

	public function test_resolve_target_rejects_non_domain_value_with_log(): void
	{
		// Given a target that is not a valid domain, and an empty log
		$this->assertSame('', $this->logContents(), 'log must start empty');

		// When resolution is requested
		$result = pfb_ss_resolve_target('safe.example.com;ls');

		// Then it returns the same empty-pair shape as the empty-target guard
		// (so pfb_ss_refresh_lines keeps prior baked IPs) and logs the rejection.
		$this->assertSame(['', ''], $result);
		$log = $this->logContents();
		$this->assertStringContainsString('pfb_ss_resolve_target', $log);
		$this->assertStringContainsString('failed validation', $log);
		$this->assertStringContainsString(htmlspecialchars('safe.example.com;ls'), $log);
	}

	public function test_resolve_target_valid_domain_passes_boundary_unlogged(): void
	{
		// The accept side of the same branch: a domain-valid target proceeds past
		// the validation boundary to the resolution stage with no rejection logged.
		// The resolver exec is STUBBED (#723): the old form ran a real
		// `drill A safe.duckduckgo.com @127.0.0.1`, which succeeds on any box with
		// a loopback resolver (failing the empty-pair assertion) and emits real DNS
		// traffic from a unit test. The live resolution leg stays smoke territory.
		$this->assertSame('', $this->logContents(), 'log must start empty');

		$stub = tempnam(sys_get_temp_dir(), 'pfb_drill_stub_');
		file_put_contents($stub, "#!/bin/sh\nexit 0\n");
		chmod($stub, 0755);
		$GLOBALS['pfb']['drill'] = $stub;
		try {
			$result = pfb_ss_resolve_target('safe.duckduckgo.com');
		} finally {
			unset($GLOBALS['pfb']['drill']);
			@unlink($stub);
		}

		$this->assertSame(['', ''], $result);
		$this->assertStringNotContainsString('failed validation', $this->logContents());
	}
}
