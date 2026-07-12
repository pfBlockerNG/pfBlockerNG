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
				@unlink((string) $f);
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
}
