<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_py_swap() master .raw -> Python py_data/py_zone publish (issue #1097/#1127).
 *
 * Extracted verbatim from the concat-success branch in sync_package_pfblockerng() so the
 * !dnsbl_tld gate (drop the stale py_data/py_zone, rename the freshly-assembled .raw into
 * py_data) is unit-testable without a live sync run.
 *
 * Feature: master .raw publish gate
 *   Branch coverage (dnsbl_tld TRUE/FALSE) + the pre-existing/absent py_data+py_zone axis:
 *     * dnsbl_tld=TRUE  -> no-op: .raw, py_data, py_zone all untouched
 *     * dnsbl_tld=FALSE, py_data/py_zone pre-existing -> both dropped, .raw renamed in
 *     * dnsbl_tld=FALSE, py_data/py_zone absent -> unlink_if_exists no-ops, rename still lands
 *     * issue #1241: dnsbl_tld=FALSE, rename() FAILS (py_data occupied by a directory,
 *       EISDIR) -> py_zone/.raw must survive untouched, whether py_zone pre-exists or not
 */
#[CoversFunction('pfb_dnsbl_py_swap')]
final class PfbDnsblPySwapTest extends TestCase
{
	private string $workdir = '';

	protected function setUp(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfbpyswap');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;
	}

	protected function tearDown(): void
	{
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				$f = (string) $f;
				is_dir($f) ? @rmdir($f) : @unlink($f);
			}
			rmdir($this->workdir);
		}
	}

	public function testTldEnabledIsANoOpLeavingRawPyDataAndPyZoneUntouched(): void
	{
		$raw    = "{$this->workdir}/dnsbl_file.raw";
		$pyData = "{$this->workdir}/py_data";
		$pyZone = "{$this->workdir}/py_zone";
		file_put_contents($raw, 'RAW-CONTENT');
		file_put_contents($pyData, 'OLD-PY-DATA');
		file_put_contents($pyZone, 'OLD-PY-ZONE');

		pfb_dnsbl_py_swap(TRUE, $raw, $pyData, $pyZone);

		$this->assertSame(
			'RAW-CONTENT',
			file_get_contents($raw),
			'TLD mode must leave the .raw untouched (byte-exact)'
		);
		$this->assertSame(
			'OLD-PY-DATA',
			file_get_contents($pyData),
			'TLD mode must leave py_data untouched'
		);
		$this->assertSame(
			'OLD-PY-ZONE',
			file_get_contents($pyZone),
			'TLD mode must leave py_zone untouched'
		);
	}

	public function testTldDisabledWithExistingPyDataAndZoneRenamesRawInAndRemovesZone(): void
	{
		$raw    = "{$this->workdir}/dnsbl_file.raw";
		$pyData = "{$this->workdir}/py_data";
		$pyZone = "{$this->workdir}/py_zone";
		file_put_contents($raw, 'FRESH-RAW-CONTENT');
		file_put_contents($pyData, 'OLD-PY-DATA');
		file_put_contents($pyZone, 'OLD-PY-ZONE');

		pfb_dnsbl_py_swap(FALSE, $raw, $pyData, $pyZone);

		$this->assertFileDoesNotExist($raw, 'the .raw must be consumed by rename(), not left behind');
		$this->assertFileDoesNotExist($pyZone, 'py_zone must be removed to let the Python init rebuild it');
		$this->assertSame(
			'FRESH-RAW-CONTENT',
			file_get_contents($pyData),
			'py_data must hold the byte-exact .raw content after the swap'
		);
	}

	public function testTldDisabledWithAbsentPyDataAndZoneStillSwapsWithoutError(): void
	{
		$raw    = "{$this->workdir}/dnsbl_file.raw";
		$pyData = "{$this->workdir}/py_data";
		$pyZone = "{$this->workdir}/py_zone";
		file_put_contents($raw, 'RAW-ONLY');
		$this->assertFileDoesNotExist($pyData);
		$this->assertFileDoesNotExist($pyZone);

		pfb_dnsbl_py_swap(FALSE, $raw, $pyData, $pyZone);

		$this->assertFileDoesNotExist($raw);
		$this->assertSame(
			'RAW-ONLY',
			file_get_contents($pyData),
			'rename must still succeed when py_data/py_zone never existed'
		);
	}

	/**
	 * Run the swap and record every diagnostic it lets ESCAPE unsuppressed. PHP calls a
	 * custom handler even for a '@'-suppressed diagnostic, so suppression is read off
	 * error_reporting()'s mask -- which only discriminates under E_ALL, because PHPUnit's
	 * own runtime mask already excludes E_WARNING.
	 *
	 * @return list<string> the escaped diagnostics, one "<errno>: <message>" per entry
	 */
	private function swapCapturingEscapedDiagnostics(
		bool $dnsblTld,
		string $raw,
		string $pyData,
		string $pyZone
	): array {
		$escaped  = [];
		$prevMask = error_reporting(E_ALL);
		set_error_handler(static function (int $errno, string $errstr) use (&$escaped): bool {
			if ((error_reporting() & $errno) !== 0) {
				$escaped[] = "{$errno}: {$errstr}";
			}
			return TRUE;
		});
		try {
			pfb_dnsbl_py_swap($dnsblTld, $raw, $pyData, $pyZone);
		} finally {
			restore_error_handler();
			error_reporting($prevMask);
		}
		return $escaped;
	}

	/**
	 * issue #1241: a FAILED rename() must never have already destroyed py_zone, and must
	 * not leak a raw PHP warning to the caller. Force a real, unmocked rename() failure by
	 * occupying the destination py_data path with a directory -- rename(file, existing dir)
	 * fails EISDIR/ENOTDIR even as root.
	 */
	public function testRenameFailurePreservesPyZoneAndRawWhenPyDataOccupiedByDirectory(): void
	{
		$raw    = "{$this->workdir}/dnsbl_file.raw";
		$pyData = "{$this->workdir}/py_data";
		$pyZone = "{$this->workdir}/py_zone";
		file_put_contents($raw, 'FRESH-RAW-CONTENT-ROW4');
		file_put_contents($pyZone, 'LIVE-PY-ZONE-ROW4');
		$this->assertTrue(mkdir($pyData, 0700), 'setup: occupy py_data with a directory');

		$escaped = $this->swapCapturingEscapedDiagnostics(FALSE, $raw, $pyData, $pyZone);

		$this->assertSame(
			'LIVE-PY-ZONE-ROW4',
			file_get_contents($pyZone),
			'a failed rename must leave py_zone byte-identical, not pre-deleted'
		);
		$this->assertFileExists($raw, 'a failed rename must not consume the .raw source');
		$this->assertDirectoryExists($pyData, 'the occupying py_data directory must survive a failed rename');
		$this->assertSame(
			[],
			$escaped,
			'a failed rename must be handled + logged by the swap, never leak a PHP warning'
		);
	}

	/** issue #1241: same failed-rename path with py_zone absent -- must stay absent, not fabricated. */
	public function testRenameFailureWithAbsentPyZoneStaysAbsentAndRawSurvives(): void
	{
		$raw    = "{$this->workdir}/dnsbl_file.raw";
		$pyData = "{$this->workdir}/py_data";
		$pyZone = "{$this->workdir}/py_zone";
		file_put_contents($raw, 'FRESH-RAW-CONTENT-ROW5');
		$this->assertTrue(mkdir($pyData, 0700), 'setup: occupy py_data with a directory');
		$this->assertFileDoesNotExist($pyZone, 'before-state: no py_zone');

		$escaped = $this->swapCapturingEscapedDiagnostics(FALSE, $raw, $pyData, $pyZone);

		$this->assertFileDoesNotExist($pyZone, 'py_zone must not be fabricated by a failed swap');
		$this->assertFileExists($raw, 'a failed rename must not consume the .raw source');
		$this->assertSame(
			[],
			$escaped,
			'a failed rename must be handled + logged by the swap, never leak a PHP warning'
		);
	}
}
