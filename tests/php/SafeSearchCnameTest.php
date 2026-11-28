<?php

declare(strict_types=1);

require_once __DIR__ . '/CutShortWrite.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #149 — pin the off-appliance contract of the SafeSearch CNAME glue that
 * feeds pfb_unbound.py's CNAME redirect (duckduckgo.com / pixabay.com):
 *
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
#[CoversFunction('pfb_ss_refresh_lines')]
#[CoversFunction('pfb_ss_resolve_target')]
#[CoversFunction('pfb_ss_publish')]
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
		foreach (['log', 'errlog', 'extdns', 'drill', 'timeout', 'unbound_py_ss'] as $key) {
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

	private function makeFixture(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	/** @return array{timeoutLog:string, drillLog:string} */
	private function installLookupFixtures(bool $expire): array
	{
		$timeoutLog = "{$this->tmp}/timeout args.log";
		$drillLog = "{$this->tmp}/drill args.log";
		$timeoutLogEsc = escapeshellarg($timeoutLog);
		$drillLogEsc = escapeshellarg($drillLog);

		if ($expire) {
			$timeoutBody = "printf '%s\\n' --CALL-- >> {$timeoutLogEsc}\nprintf '%s\\n' \"$@\" >> {$timeoutLogEsc}\nprintf '%b\\n' 'partial.example.com.\\t300\\tIN\\tA\\t192.0.2.99' 'partial.example.com.\\t300\\tIN\\tAAAA\\t2001:db8::99'\nexit 124";
		} else {
			$timeoutBody = "printf '%s\\n' --CALL-- >> {$timeoutLogEsc}\nprintf '%s\\n' \"$@\" >> {$timeoutLogEsc}\nshift 5\nexec \"$@\"";
		}
		$timeout = $this->makeFixture('timeout fixture.sh', $timeoutBody);
		$drill = $this->makeFixture('drill fixture.sh',
			"printf '%s\\n' \"$@\" >> {$drillLogEsc}\n"
			. "case \"$1\" in\n"
			. "A) printf '%b\\n' 'safe.duckduckgo.com.\\t300\\tIN\\tA\\t192.0.2.10' ;;\n"
			. "AAAA) printf '%b\\n' 'safe.duckduckgo.com.\\t300\\tIN\\tAAAA\\t2001:db8::10' ;;\n"
			. "esac");

		$GLOBALS['pfb']['timeout'] = $timeout;
		$GLOBALS['pfb']['drill'] = $drill;
		$GLOBALS['pfb']['extdns'] = '127.0.0.1; echo no';
		return ['timeoutLog' => $timeoutLog, 'drillLog' => $drillLog];
	}

	/** @return list<list<string>> */
	private function timeoutCalls(string $path): array
	{
		if (!is_file($path)) {
			return [];
		}
		$lines = file($path, FILE_IGNORE_NEW_LINES);
		$calls = [];
		$call = [];
		foreach ($lines ?: [] as $line) {
			if ($line === '--CALL--') {
				if ($call !== []) {
					$calls[] = $call;
					$call = [];
				}
				continue;
			}
			$call[] = $line;
		}
		if ($call !== []) {
			$calls[] = $call;
		}
		return $calls;
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

	/** Issue #4201: a refreshed SafeSearch CSV whose write is cut short leaves the previous CSV whole for the gateway to load. */
	public function test_refresh_whose_write_is_cut_short_keeps_the_previous_csv(): void
	{
		if (!CutShortWrite::available()) {
			$this->markTestSkipped('pcntl and posix are required to cut a write short.');
		}
		$this->installLookupFixtures(FALSE);
		$GLOBALS['pfb']['unbound_py_ss'] = $csv = "{$this->tmp}/pfb_py_ss.txt";
		$previous = "duckduckgo.com,cname,safe.duckduckgo.com,9.9.9.9,2001:db8::old\n";
		file_put_contents($csv, $previous);

		$this->assertSame('NULL', CutShortWrite::run(16, static fn (): mixed => pfblockerng_ss_refresh()));

		$this->assertSame($previous, file_get_contents($csv), 'the stale baked IPs stay until a whole CSV replaces them');
	}

	/** Issue #4201: the SafeSearch CSV is published whole when there is none yet. */
	public function test_publish_writes_a_csv_when_there_is_none(): void
	{
		$GLOBALS['pfb']['unbound_py_ss'] = $csv = "{$this->tmp}/pfb_py_ss.txt";

		$this->assertTrue(pfb_ss_publish("a.example,1.2.3.4\n"));
		$this->assertSame("a.example,1.2.3.4\n", file_get_contents($csv));
	}

	/** Issue #4201: a CSV that differs is replaced, so changed SafeSearch hosts reach the gateway. */
	public function test_publish_replaces_a_csv_that_differs(): void
	{
		$GLOBALS['pfb']['unbound_py_ss'] = $csv = "{$this->tmp}/pfb_py_ss.txt";
		file_put_contents($csv, "old.example,9.9.9.9\n");

		$this->assertTrue(pfb_ss_publish("a.example,1.2.3.4\n"));
		$this->assertSame("a.example,1.2.3.4\n", file_get_contents($csv));
	}

	/** Issue #4201: the same rows publish nothing and signal nothing: no reload for an unchanged CSV. */
	public function test_publish_leaves_the_same_csv_alone(): void
	{
		$GLOBALS['pfb']['unbound_py_ss'] = $csv = "{$this->tmp}/pfb_py_ss.txt";
		file_put_contents($csv, "a.example,1.2.3.4\n");
		$inode = fileinode($csv);

		$this->assertFalse(pfb_ss_publish("a.example,1.2.3.4\n"));
		clearstatcache();
		$this->assertSame($inode, fileinode($csv), 'not rewritten');
	}

	/** Issue #4201: rows whose write is cut short leave the previous CSV whole, and signal nothing. */
	public function test_publish_cut_short_keeps_the_previous_csv(): void
	{
		if (!CutShortWrite::available()) {
			$this->markTestSkipped('pcntl and posix are required to cut a write short.');
		}
		$GLOBALS['pfb']['unbound_py_ss'] = $csv = "{$this->tmp}/pfb_py_ss.txt";
		file_put_contents($csv, "old.example,9.9.9.9\n");

		$this->assertSame('false', CutShortWrite::run(16, static fn (): bool => pfb_ss_publish("a.example,cname,safe.example,1.2.3.4,2001:db8::1\n")));
		$this->assertSame("old.example,9.9.9.9\n", file_get_contents($csv));
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
		$this->installLookupFixtures(false);
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

	public function test_resolve_target_a_result_runs_through_default_reaper_timeout(): void
	{
		$logs = $this->installLookupFixtures(false);

		$result = pfb_ss_resolve_target('safe.duckduckgo.com');

		$this->assertSame(['192.0.2.10', '2001:db8::10'], $result);
		$calls = $this->timeoutCalls($logs['timeoutLog']);
		$this->assertCount(2, $calls);
		$this->assertSame(['-s', 'TERM', '-k', '5', '30', '/bin/sh', '-c'], array_slice($calls[0], 0, 7));
		$this->assertNotContains('--foreground', $calls[0]);
		$this->assertSame(
			['A', 'safe.duckduckgo.com', '@127.0.0.1; echo no', 'AAAA', 'safe.duckduckgo.com', '@127.0.0.1; echo no'],
			file($logs['drillLog'], FILE_IGNORE_NEW_LINES)
		);
	}

	public function test_resolve_target_aaaa_result_runs_through_default_reaper_timeout(): void
	{
		$this->installLookupFixtures(false);
		// The fixture serves both families; isolate the AAAA leg by using a drill fixture
		// whose A output is intentionally not an IPv4 answer.
		$GLOBALS['pfb']['drill'] = $this->makeFixture('aaaa drill fixture.sh',
			"case \"$1\" in\n"
			. "A) exit 0 ;;\n"
			. "AAAA) printf '%b\\n' 'safe.duckduckgo.com.\\t300\\tIN\\tAAAA\\t2001:db8::10' ;;\n"
			. "esac");

		$result = pfb_ss_resolve_target('safe.duckduckgo.com');

		$this->assertSame(['', '2001:db8::10'], $result);
	}

	public function test_resolve_target_timeout_discards_partial_a_and_aaaa_results_and_logs_both_expiries(): void
	{
		$logs = $this->installLookupFixtures(true);

		$result = pfb_ss_resolve_target('safe.duckduckgo.com');

		$this->assertSame(['', ''], $result);
		$log = $this->logContents();
		$this->assertStringContainsString('A lookup TIMED OUT', $log);
		$this->assertStringContainsString('AAAA lookup TIMED OUT', $log);
		$calls = $this->timeoutCalls($logs['timeoutLog']);
		$this->assertCount(2, $calls);
		foreach ($calls as $call) {
			$this->assertSame(['-s', 'TERM', '-k', '5', '30', '/bin/sh', '-c'], array_slice($call, 0, 7));
			$this->assertNotContains('--foreground', $call);
		}
	}

	public function test_resolve_target_uses_injected_resolver_binary(): void
	{
		// Seam proof (#723): a stub resolver that EMITS a drill-shaped answer must have
		// its answer consumed -- red on any build where the exec still hard-codes
		// /usr/bin/drill (the stub is then dead code and this returns ['','']), on every
		// platform, with or without a real resolver present.
		$stub = tempnam(sys_get_temp_dir(), 'pfb_drill_stub_');
		file_put_contents($stub, "#!/bin/sh\n[ \"\$1\" = \"A\" ] && printf 'stub.example.com.\\t300\\tIN\\tA\\t192.0.2.99\\n'\nexit 0\n");
		chmod($stub, 0755);
		$this->installLookupFixtures(false);
		$GLOBALS['pfb']['drill'] = $stub;
		try {
			$result = pfb_ss_resolve_target('safe.duckduckgo.com');
		} finally {
			unset($GLOBALS['pfb']['drill']);
			@unlink($stub);
		}

		$this->assertSame(['192.0.2.99', ''], $result,
			'expected: the stubbed resolver binary answers the A lookup (proving the exec uses $pfb[drill])');
	}
}
