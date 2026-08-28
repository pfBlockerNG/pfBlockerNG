<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 -- pfb_dnsbl_manifest_missing(): the DNSBL health check re-keyed
 * onto the manifest boundary. TRUE iff the per-feed manifest (pfb_py_sources.json)
 * is absent, OR the ADR-61 reload/applied marker generations disagree (a stuck
 * zero-downtime apply). Brand-new function (CLAUDE.md brand-new-code carve-out --
 * no pre-existing behaviour to red-prove; every branch below asserts real
 * behaviour, paired FALSE/TRUE where the shape allows).
 *
 * Functions under test: pfb_dnsbl_manifest_missing(array $pfb): bool (pfblockerng.inc).
 */
#[CoversFunction('pfb_dnsbl_manifest_missing')]
final class DnsblManifestMissingTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_manifest_missing_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			@chmod($file, 0644);
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function makePfb(): array
	{
		return [
			'unbound_py_sources' => "{$this->dir}/pfb_py_sources.json",
			'dnsbldir'           => $this->dir,
		];
	}

	private function writeSentinel(string $content): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload", $content);
	}

	private function writeApplied(string $content): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload.applied", $content);
	}

	private function writeManifest(): void
	{
		file_put_contents("{$this->dir}/pfb_py_sources.json", '{"version":1,"feeds":[]}');
	}

	public function testManifestAbsentIsMissingRegardlessOfMarkers(): void
	{
		$this->writeSentinel("3\n");
		$this->writeApplied("3\n");
		// No manifest written.

		$this->assertTrue(pfb_dnsbl_manifest_missing($this->makePfb()), 'an absent manifest is missing even with agreeing markers');
	}

	public function testManifestPresentZeroByteWithAgreeingMarkersIsNotMissing(): void
	{
		// Presence-only by design -- content validity is the ADR-61 parse
		// ledger's job (pfb_dnsbl_manifest_failure_notice), not this health check.
		file_put_contents("{$this->dir}/pfb_py_sources.json", '');
		$this->writeSentinel("3\n");
		$this->writeApplied("3\n");

		$this->assertFalse(pfb_dnsbl_manifest_missing($this->makePfb()), 'a present-but-empty manifest with agreeing markers is not missing');
	}

	public function testBothMarkersAbsentIsFreshBoxBaselineNotMissing(): void
	{
		$this->writeManifest();
		// Neither pfb_py_reload nor .applied exists -- shared 0 == 0 baseline.

		$this->assertFalse(pfb_dnsbl_manifest_missing($this->makePfb()), 'a never-flipped sentinel/applied pair (both absent) is not missing');
	}

	public function testStuckApplyWithMismatchedGenerationsIsMissing(): void
	{
		$this->writeManifest();
		$this->writeSentinel("5\n");
		$this->writeApplied("4\n");

		$this->assertTrue(pfb_dnsbl_manifest_missing($this->makePfb()), 'sentinel ahead of applied (a stuck apply) must trigger a rebuild');
	}

	/**
	 * @return list<array{0:string,1:string}> [sentinel content, applied content]
	 */
	public static function garbageMarkerProvider(): array
	{
		return [
			'blank sentinel'      => ['', '0'],
			'empty-string sentinel' => ['', "0\n"],
			'whitespace sentinel' => ["  \n", '0'],
			'non-digit sentinel'  => ['abc', '0'],
		];
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('garbageMarkerProvider')]
	public function testGarbageMarkerNormalisesToZeroAndMatchesZeroApplied(string $sentinel, string $applied): void
	{
		$this->writeManifest();
		$this->writeSentinel($sentinel);
		$this->writeApplied($applied);

		$this->assertFalse(
			pfb_dnsbl_manifest_missing($this->makePfb()),
			'garbage/blank sentinel reads as generation 0, matching an applied of "0" -- not missing'
		);
	}

	public function testMultilineSentinelUsesFirstLineOnly(): void
	{
		$this->writeManifest();
		$this->writeSentinel("7\ngarbage\n9\n");
		$this->writeApplied("7\n");

		$this->assertFalse(
			pfb_dnsbl_manifest_missing($this->makePfb()),
			'a multiline sentinel must parse its FIRST line only (7), matching an applied of 7'
		);
	}

	public function testMarkerUnreadableReadsAsZero(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions -- cannot simulate an unreadable file.');
		}

		$this->writeManifest();
		$this->writeSentinel("5\n");
		chmod("{$this->dir}/pfb_py_reload", 0000);
		// .applied absent -> reads as 0 too, so an unreadable sentinel (-> 0) must agree.

		try {
			$this->assertFalse(
				pfb_dnsbl_manifest_missing($this->makePfb()),
				'an unreadable sentinel reads as generation 0, matching an absent applied (also 0) -- not missing'
			);
		} finally {
			chmod("{$this->dir}/pfb_py_reload", 0644);
		}
	}

	public function testOversizedDigitStringMarkersCompareEqual(): void
	{
		$this->writeManifest();
		$huge = str_repeat('9', 25);
		$this->writeSentinel("{$huge}\n");
		$this->writeApplied("{$huge}\n");

		$this->assertFalse(
			pfb_dnsbl_manifest_missing($this->makePfb()),
			'identical oversized digit-string markers must compare equal regardless of int-cast overflow behaviour'
		);
	}

	/** Paired twin of testStuckApplyWithMismatchedGenerationsIsMissing -- proves the FALSE assertions above can fail. */
	public function testAgreeingNonZeroGenerationsAreNotMissing(): void
	{
		$this->writeManifest();
		$this->writeSentinel("10\n");
		$this->writeApplied("10\n");

		$this->assertFalse(pfb_dnsbl_manifest_missing($this->makePfb()), 'matching non-zero generations must not be missing');
	}
}
