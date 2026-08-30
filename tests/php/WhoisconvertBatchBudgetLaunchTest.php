<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2877: the whole-batch deadline of whoisconvert() must bound BOTH
 * synchronous PHP producer paths that launch it, not only direct shell calls:
 *
 *   1. src/usr/local/pkg/pfblockerng/pfblockerng.inc pfb_download_fetch() --
 *      WHOIS/ASN feed conversion. Executed here for real: pfb_download_fetch()
 *      composes and exec()s the launch against a deterministic stand-in script
 *      that sources the REAL pfblockerng.sh and runs the REAL whoisconvert()
 *      with the launched argv, over a fake host(1) whose per-entry calls stay
 *      individually bounded while the entry's lookup exceeds the batch budget.
 *
 *   2. src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc
 *      sync_package_pfblockerng() -- persisted custom Domain/ASN list. The
 *      enclosing sync pass is not off-appliance executable, so this site is
 *      pinned two ways: its exact exec() statement is asserted in the shipped
 *      source (whole statement, so composition drift fails), and the site's
 *      composed command is EXECUTED with the site's own variable bindings
 *      through the same stand-in, driving the same bounded batch red->green.
 *
 * Both rows go red while the batch is unbounded (the lookup/batch exceeds the
 * budget, no clipping/expiry happens) and green once the deadline bounds it.
 */
#[CoversFunction('pfb_download_fetch')]
final class WhoisconvertBatchBudgetLaunchTest extends TestCase
{
	private const PFB_SH = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.sh';
	private const PFB_INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';
	private const APPLY_INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	/** The launch statements, exactly as shipped (whole statements). */
	private const SITE1_EXEC = 'exec("{$pfb[\'script\']} whoisconvert {$header_esc} {$vtype} {$list_url_esc} {$elog}");';
	private const SITE2_EXEC = 'exec("{$pfb[\'script\']} whoisconvert {$header_esc} {$list[\'vtype\']} {$custom_list} {$elog}");';

	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_whoisbatch_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		mkdir("{$this->tmp}/orig", 0700, TRUE);
		file_put_contents("{$this->tmp}/timeout.args", '');
		file_put_contents("{$this->tmp}/host.count", '0');
	}

	protected function tearDown(): void
	{
		foreach (array_reverse(glob("{$this->tmp}/*") ?: []) as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->tmp);
	}

	/** Real timeout(1) from PATH. A gate whose tool is missing is a failure, never a skip. */
	private function realTimeout(): string
	{
		$out = [];
		$rc  = 0;
		exec('command -v timeout 2>/dev/null', $out, $rc);
		$path = trim((string) ($out[0] ?? ''));
		if ($path === '' || !is_executable($path)) {
			$this->fail('no timeout(1) on PATH: the executed producer-path rows need a real one');
		}
		return $path;
	}

	/**
	 * The deterministic fake helper both producer paths launch: it reproduces
	 * the script argv contract (alias=$2, max=$3, dedup=$4), sources the REAL
	 * pfblockerng.sh, and calls the REAL whoisconvert() with test-seam fakes.
	 */
	private function writeShim(): string
	{
		$shim = "{$this->tmp}/pfblockerng-shim";
		file_put_contents($shim, <<<'SH'
			#!/bin/sh
			alias="$2"
			max="$3"
			dedup="$4"
			pfborig="${PFB_TEST_ORIG}/"
			pathhost="${PFB_TEST_HOST}"
			pathtimeout="${PFB_TEST_TIMEOUT}"
			pathasncsv="${PFB_TEST_ASNCSV}"
			errorlog="${PFB_TEST_ERRLOG}"
			PFB_SOURCED=1 . "${PFB_TEST_PFB_SH}"
			whoisconvert
			SH);
		chmod($shim, 0755);
		return $shim;
	}

	/** timeout(1) stand-in: records its argv (one space-joined line per call), enforces for real. */
	private function writeTimeout(): string
	{
		$real = $this->realTimeout();
		$faux = "{$this->tmp}/timeout";
		file_put_contents($faux, "#!/bin/sh\nprintf '%s\n' \"\$*\" >> \"\${TIMEOUT_ARGS}\"\nexec '{$real}' \"\$@\"\n");
		chmod($faux, 0755);
		return $faux;
	}

	/** host(1) stand-in: sleeps HOST_SLEEP, then answers a unique 203.0.113.<n> address. */
	private function writeHost(): string
	{
		$faux = "{$this->tmp}/host";
		file_put_contents($faux, <<<'SH'
			#!/bin/sh
			sleep "${HOST_SLEEP}"
			n="$(cat "${HOST_COUNT}")"
			n=$((n + 1))
			echo "$n" > "${HOST_COUNT}"
			echo "$3 has address 203.0.113.$n"
			SH);
		chmod($faux, 0755);
		return $faux;
	}

	/** Export the seams the shim and its fakes read, mirroring the PHP-launched env. */
	private function exportSeams(string $budget, string $hostSleep): void
	{
		putenv("PFB_TEST_ORIG={$this->tmp}/orig");
		putenv("PFB_TEST_HOST={$this->tmp}/host");
		putenv("PFB_TEST_TIMEOUT={$this->tmp}/timeout");
		putenv("PFB_TEST_ASNCSV={$this->tmp}/asn.csv");
		putenv("PFB_TEST_ERRLOG={$this->tmp}/error.log");
		putenv("PFB_TEST_PFB_SH=" . self::PFB_SH);
		putenv("TIMEOUT_ARGS={$this->tmp}/timeout.args");
		putenv("HOST_COUNT={$this->tmp}/host.count");
		putenv("HOST_SLEEP={$hostSleep}");
		// The shim reads the budget from the shell-level seam, exactly like the
		// nested re-entry seam reads its configured budget.
		putenv("whoisbatchtimeout={$budget}");
	}

	private function log(): string
	{
		return (string) @file_get_contents("{$this->tmp}/pfblockerng.log");
	}

	/**
	 * Producer path 1 -- pfblockerng.inc pfb_download_fetch(), WHOIS feed
	 * conversion. A feed whose single Domain lookup stays individually bounded
	 * (a slow-but-finite host) yet exceeds the whole-batch budget must be
	 * CLIPPED to the budget and follow the existing failure/restore path, not
	 * wait out the unbounded 30-second-per-entry bound. (A single-entry list
	 * leaves no entries to skip, so the batch-expiry line belongs to the
	 * multi-entry producer path below.)
	 */
	public function test_pfblockerng_inc_whois_site_launches_the_bounded_batch(): void
	{
		$this->assertNotFalse(strpos((string) file_get_contents(self::PFB_INC), self::SITE1_EXEC),
			'pfblockerng.inc must keep its exact whoisconvert launch statement');

		$GLOBALS['pfb']['log']    = "{$this->tmp}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/error.log";
		$GLOBALS['pfb']['script'] = $this->writeShim();
		$this->writeTimeout();
		$this->writeHost();
		$this->exportSeams('2', '3');
		// A prior .orig proves the timed-out single-entry launch follows the
		// existing #2015 failure/restore path.
		file_put_contents("{$this->tmp}/orig/SiteOne.orig", "198.51.100.7\n");

		$request = new PfbDownloadRequest(
			listUrl: 'd1.example',
			downloadPath: "{$this->tmp}/d1",
			flex: FALSE,
			header: 'SiteOne',
			format: 'whois',
			logType: 1,
			versionType: '_v4',
		);

		$start = hrtime(TRUE);
		$result = pfb_download_fetch($request);
		$elapsed = (hrtime(TRUE) - $start) / 1e9;

		$this->assertTrue($result->success, 'the whois branch must treat the bounded batch as the launch outcome');
		// The launched lookup was clipped to the budget (entry 1 at elapsed 0:
		// modulo a date(1) second boundary, 1 is also a clipped value), not the
		// bare 30-second bound of issue #2015.
		$args = (string) file_get_contents("{$this->tmp}/timeout.args");
		$this->assertSame(1, preg_match('/ -k 5 [12] .* -t A d1\.example/', $args),
			"the launched lookup must be clipped to the 2s batch budget, got: {$args}");
		$this->assertFileExists("{$this->tmp}/orig/SiteOne.fail");
		$this->assertSame("198.51.100.7\n", (string) file_get_contents("{$this->tmp}/orig/SiteOne.orig"),
			'the timed-out single-entry launch restores the prior data (found stays false)');
		$this->assertLessThan(2.85, $elapsed,
			"the bounded batch must end at the budget, took {$elapsed}s (unbounded wait is 3s)");
	}

	/**
	 * Producer path 2 -- pfblockerng_apply.inc sync_package_pfblockerng(),
	 * persisted custom Domain/ASN list. The site's composed command is executed
	 * with the site's own bindings: a twenty-entry custom list whose per-entry
	 * lookups are each 0.2s (individually bounded, 4s total) must end at the
	 * 2s batch budget with the resolved prefix kept and the remainder skipped.
	 */
	public function test_apply_inc_whois_site_launches_the_bounded_batch(): void
	{
		$this->assertNotFalse(strpos((string) file_get_contents(self::APPLY_INC), self::SITE2_EXEC),
			'pfblockerng_apply.inc must keep its exact whoisconvert launch statement');

		$GLOBALS['pfb']['log']    = "{$this->tmp}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/error.log";
		$shim = $this->writeShim();
		$this->writeTimeout();
		$this->writeHost();
		$this->exportSeams('2', '0.2');

		// The site's bindings: $header_esc = escapeshellarg(header),
		// $list['vtype'], $custom_list (comma-joined), $elog from $pfb['log'].
		$header_esc  = escapeshellarg('CustomList');
		$vtype       = '_v4';
		$custom_list = implode(',', array_map(
			static fn (int $i): string => "d{$i}.example",
			range(1, 20)
		));
		$elog = ">> {$GLOBALS['pfb']['log']} 2>&1";

		$start = hrtime(TRUE);
		exec("{$shim} whoisconvert {$header_esc} {$vtype} {$custom_list} {$elog}");
		$elapsed = (hrtime(TRUE) - $start) / 1e9;

		$this->assertStringContainsString(
			'WHOIS batch [ CustomList ] TIMED OUT after 2s total; remaining Domain/AS entries skipped',
			$this->log(),
			'the batch deadline must name its expiry in the launch log'
		);
		$orig = (string) @file_get_contents("{$this->tmp}/orig/CustomList.orig");
		$this->assertStringContainsString('203.0.113.3', $orig,
			'entries that resolved before the deadline are kept (append semantics)');
		$this->assertStringNotContainsString('203.0.113.20', $orig,
			'the skipped remainder must not be published (an unbounded batch runs all twenty)');
		$this->assertFileExists("{$this->tmp}/orig/CustomList.fail");
		$this->assertLessThan(3.0, $elapsed,
			"the bounded batch must end at the budget, took {$elapsed}s (the unbounded batch is 4s)");
	}
}
