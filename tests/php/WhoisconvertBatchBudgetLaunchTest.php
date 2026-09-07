<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Execute the real WHOIS feed producer and the custom-list CLI argument shape.
 * The complete sync_package_pfblockerng() pass is not run off-appliance.
 * External lookup outcomes and date(1) are controlled; batch logic stays real.
 */
#[CoversFunction('pfb_download_fetch')]
final class WhoisconvertBatchBudgetLaunchTest extends TestCase
{
	private const PFB_SH = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.sh';

	/** putenv() seams this test exports; teardown must restore every one. */
	private const SEAMS = [
		'PFB_TEST_ORIG', 'PFB_TEST_HOST', 'PFB_TEST_TIMEOUT', 'PFB_TEST_ASNCSV',
		'PFB_TEST_ERRLOG', 'PFB_TEST_PFB_SH', 'PFB_TEST_CLOCK',
		'TIMEOUT_ARGS', 'HOST_COUNT', 'whoisbatchtimeout',
	];

	private string $tmp;
	private array $environment = [];
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		foreach (self::SEAMS as $seam) {
			$this->environment[$seam] = getenv($seam);
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_whoisbatch_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		mkdir("{$this->tmp}/orig", 0700, TRUE);
		file_put_contents("{$this->tmp}/timeout.args", '');
		file_put_contents("{$this->tmp}/host.count", '0');
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		foreach ($this->environment as $seam => $value) {
			putenv($value === FALSE ? $seam : "{$seam}={$value}");
		}
		foreach (glob("{$this->tmp}/orig/*") ?: [] as $path) {
			unlink($path);
		}
		foreach (array_reverse(glob("{$this->tmp}/*") ?: []) as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->tmp);
	}

	/**
	 * The deterministic fake helper both producer paths launch: it reproduces
	 * the script argv contract (alias=$2, max=$3, dedup=$4), puts this
	 * directory first on PATH (so the fake date(1) below intercepts
	 * whoisconvert()'s unqualified `date +%s` calls), sources the REAL
	 * pfblockerng.sh, and calls the REAL whoisconvert() with test-seam fakes.
	 */
	private function writeShim(): string
	{
		$shim = "{$this->tmp}/pfblockerng-shim";
		$body = <<<'SH'
			#!/bin/sh
			PATH="__BIN__:${PATH}"
			export PATH
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
			SH;
		file_put_contents($shim, str_replace('__BIN__', $this->tmp, $body));
		chmod($shim, 0755);
		return $shim;
	}

	/** Only the batch's date +%s reads use the controlled clock. */
	private function writeDate(int $start): void
	{
		file_put_contents("{$this->tmp}/clock", (string) $start);
		$faux = "{$this->tmp}/date";
		file_put_contents($faux, <<<'SH'
			#!/bin/sh
			if [ "$1" = '+%s' ]; then
				cat "${PFB_TEST_CLOCK}"
				exit 0
			fi
			exec /bin/date "$@"
			SH);
		chmod($faux, 0755);
	}

	/** Model a timed-out lookup without depending on timeout(1)'s scheduler. */
	private function writeTimeoutThatExpires(): void
	{
		$faux = "{$this->tmp}/timeout";
		file_put_contents($faux, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> \"\${TIMEOUT_ARGS}\"\nexit 124\n");
		chmod($faux, 0755);
	}

	/** Completed lookups execute directly under the controlled clock. */
	private function writeTimeoutPassthrough(): void
	{
		$faux = "{$this->tmp}/timeout";
		file_put_contents($faux, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> \"\${TIMEOUT_ARGS}\"\nshift 5\nexec \"\$@\"\n");
		chmod($faux, 0755);
	}

	/** Each completed lookup publishes one address and advances logical time. */
	private function writeHost(int $advanceClockBy = 0): void
	{
		$faux = "{$this->tmp}/host";
		$script = <<<'SH'
			#!/bin/sh
			n="$(cat "${HOST_COUNT}")"
			n=$((n + 1))
			echo "$n" > "${HOST_COUNT}"
			echo "$3 has address 203.0.113.$n"
			SH;
		if ($advanceClockBy > 0) {
			$script .= "\nnow=\"\$(cat \"\${PFB_TEST_CLOCK}\")\"\necho \$((now + {$advanceClockBy})) > \"\${PFB_TEST_CLOCK}\"\n";
		}
		file_put_contents($faux, $script);
		chmod($faux, 0755);
	}

	/** Export the seams the shim and its fakes read, mirroring the PHP-launched env. */
	private function exportSeams(string $budget): void
	{
		putenv("PFB_TEST_ORIG={$this->tmp}/orig");
		putenv("PFB_TEST_HOST={$this->tmp}/host");
		putenv("PFB_TEST_TIMEOUT={$this->tmp}/timeout");
		putenv("PFB_TEST_ASNCSV={$this->tmp}/asn.csv");
		putenv("PFB_TEST_ERRLOG={$this->tmp}/error.log");
		putenv("PFB_TEST_PFB_SH=" . self::PFB_SH);
		putenv("TIMEOUT_ARGS={$this->tmp}/timeout.args");
		putenv("HOST_COUNT={$this->tmp}/host.count");
		putenv("PFB_TEST_CLOCK={$this->tmp}/clock");
		// The shim reads the budget from the shell-level seam, exactly like the
		// nested re-entry seam reads its configured budget.
		putenv("whoisbatchtimeout={$budget}");
	}

	private function log(): string
	{
		return (string) @file_get_contents("{$this->tmp}/pfblockerng.log");
	}

	/** A clipped lookup failure must restore the previous feed data. */
	public function test_pfblockerng_inc_whois_site_launches_the_bounded_batch(): void
	{
		$GLOBALS['pfb']['log']    = "{$this->tmp}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/error.log";
		$GLOBALS['pfb']['script'] = $this->writeShim();
		$this->writeHost();
		$this->writeDate(1000);
		$this->writeTimeoutThatExpires();
		$this->exportSeams('2');
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

		$result = pfb_download_fetch($request);

		$this->assertTrue($result->success, 'the whois branch must treat the bounded batch as the launch outcome');
		// Clipping is an external-command contract, not a wall-clock verdict.
		$args = (string) file_get_contents("{$this->tmp}/timeout.args");
		$this->assertSame(1, preg_match('/ -k 5 2 .* -t A d1\.example/', $args),
			"the launched lookup must be clipped to the 2s batch budget, got: {$args}");
		$this->assertFileExists("{$this->tmp}/orig/SiteOne.fail");
		$this->assertSame("198.51.100.7\n", (string) file_get_contents("{$this->tmp}/orig/SiteOne.orig"),
			'the timed-out single-entry launch restores the prior data (found stays false)');
	}

	/** Exhausting the batch budget keeps the completed prefix, never the remainder. */
	public function test_apply_inc_whois_site_launches_the_bounded_batch(): void
	{
		$GLOBALS['pfb']['log']    = "{$this->tmp}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/error.log";
		$shim = $this->writeShim();
		$this->writeHost(advanceClockBy: 1);
		$this->writeDate(1000);
		$this->writeTimeoutPassthrough();
		$this->exportSeams('3');

		// The site's bindings: $header_esc = escapeshellarg(header),
		// $list['vtype'], $custom_list (comma-joined), $elog from $pfb['log'].
		$header_esc  = escapeshellarg('CustomList');
		$vtype       = '_v4';
		$custom_list = implode(',', array_map(
			static fn (int $i): string => "d{$i}.example",
			range(1, 20)
		));
		$elog = ">> {$GLOBALS['pfb']['log']} 2>&1";

		exec("{$shim} whoisconvert {$header_esc} {$vtype} {$custom_list} {$elog}");

		$this->assertStringContainsString(
			'WHOIS batch [ CustomList ] TIMED OUT after 3s total; remaining Domain/AS entries skipped',
			$this->log(),
			'the batch deadline must name its expiry in the launch log'
		);
		$orig = (string) @file_get_contents("{$this->tmp}/orig/CustomList.orig");
		$addresses = array_values(array_filter(explode("\n", $orig),
			static fn (string $line): bool => $line !== '' && !str_starts_with($line, '#')));
		$this->assertSame(['203.0.113.1', '203.0.113.2', '203.0.113.3'], $addresses,
			'the batch must publish exactly the three entries completed before expiry');
		$this->assertFileExists("{$this->tmp}/orig/CustomList.fail");
	}
}
