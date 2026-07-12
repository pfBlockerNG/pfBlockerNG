<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsblip_finalize() DNSBLIP v4/v6 post-build bookkeeping gate (issue #1097/#1127).
 *
 * Extracted verbatim from the two identical finalize blocks in sync_package_pfblockerng()
 * (the v4 and v6 DNSBLIP call sites) so the $built gate -- .fp fingerprint stamp,
 * ip_cache flush, reprocess marker -- is unit-testable without a live sync run. The
 * $built=FALSE branch pins the PR#1114 fix: a failed rebuild must leave the .fp and
 * ip_cache untouched, or the stale output would look current and suppress every retry.
 *
 * Feature: DNSBLIP finalize gate
 *   Branch coverage (built TRUE/FALSE) + suffix + overwrite + missing-cache no-op:
 *     * built=TRUE  -> .fp stamped, ip_cache flushed, '.update' marker written
 *     * built=FALSE -> ip_cache/.fp/marker all untouched (before-state asserted first)
 *     * missing ip_cache pre-call -> unlink_if_exists no-ops, rest of the gate still runs
 *     * pre-existing .fp content -> overwritten, not appended
 *     * '_v4' vs '_v6' -> each drives the identically-shaped marker suffix
 *     * empty-string fingerprint -> .fp written empty, no crash
 */
#[CoversFunction('pfb_dnsblip_finalize')]
final class PfbDnsblipFinalizeTest extends TestCase
{
	private string $workdir = '';
	private string $denydir = '';
	private string $nativedir = '';

	/** @var array<string,array{bool,mixed}> Saved globals to restore. */
	private array $saved = [];

	protected function setUp(): void
	{
		$workdir = tempnam(sys_get_temp_dir(), 'pfbfinalize');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['pfb', 'pfbarr', 'config'] as $g) {
			$this->saved[$g] = [array_key_exists($g, $GLOBALS), $GLOBALS[$g] ?? null];
		}

		// Real, isolated temp dirs so the reprocess-marker assertions see the actual
		// on-disk location (mirrors DnsblipMarkerFolderTest's setup).
		$this->denydir   = "{$this->workdir}/deny";
		$this->nativedir = "{$this->workdir}/native";
		mkdir($this->denydir, 0o777, TRUE);
		mkdir($this->nativedir, 0o777, TRUE);

		$GLOBALS['pfb']['denydir']   = $this->denydir;
		$GLOBALS['pfb']['nativedir'] = $this->nativedir;
		$GLOBALS['pfb']['origdir']   = "{$this->workdir}/orig";
		$GLOBALS['pfb']['reuse']     = '';

		// Advanced keys present but OFF, so the "Invert -> force Native" override never fires.
		$off = [];
		foreach (['autoproto', 'autonot', 'autoaddrnot', 'agateway', 'autoports', 'autoaddr'] as $k) {
			$off["{$k}_in"]  = '';
			$off["{$k}_out"] = '';
		}
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsblsettings' => ['config' => [0 => $off]]]];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $g => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$g] = $value;
			} else {
				unset($GLOBALS[$g]);
			}
		}
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			$this->rmrf($this->workdir);
		}
	}

	private function rmrf(string $dir): void
	{
		foreach ((array) glob("{$dir}/*") as $entry) {
			is_dir((string) $entry) ? $this->rmrf((string) $entry) : @unlink((string) $entry);
		}
		@rmdir($dir);
	}

	public function testBuiltTrueWritesFingerprintFlushesCacheAndMarksReprocess(): void
	{
		$dnsblip = "{$this->workdir}/DNSBLIP_v4.txt";
		$ipCache = "{$this->workdir}/ip_cache.sqlite";
		file_put_contents($ipCache, 'cache-bytes');

		pfb_dnsblip_finalize($dnsblip, 'FPBYTES123', TRUE, $ipCache, 'Alias_Native', '_v4');

		$this->assertSame(
			'FPBYTES123',
			file_get_contents("{$dnsblip}.fp"),
			'the .fp must hold the exact fingerprint bytes'
		);
		$this->assertFileDoesNotExist($ipCache, 'ip_cache must be flushed on a successful build');
		$this->assertFileExists(
			"{$this->nativedir}/DNSBLIP_v4.update",
			'a reprocess marker must land in the action-resolved folder'
		);
	}

	public function testBuiltFalseLeavesCacheFpAndMarkerUntouched(): void
	{
		$dnsblip = "{$this->workdir}/DNSBLIP_v4.txt";
		$ipCache = "{$this->workdir}/ip_cache.sqlite";
		file_put_contents($ipCache, 'cache-bytes');

		// Before: ip_cache exists prior to the call -- assert it so green proves the
		// FALSE gate PRESERVED it, not merely that it ended up present by coincidence.
		$this->assertFileExists($ipCache);

		pfb_dnsblip_finalize($dnsblip, 'SHOULD-NOT-WRITE', FALSE, $ipCache, 'Alias_Native', '_v4');

		// After: unchanged -- a failed rebuild must not advance the bookkeeping (#1097).
		$this->assertFileExists($ipCache, 'ip_cache must survive a failed rebuild ($built=FALSE)');
		$this->assertFileDoesNotExist("{$dnsblip}.fp", 'no .fp must be written on a failed rebuild');
		$this->assertFileDoesNotExist(
			"{$this->nativedir}/DNSBLIP_v4.update",
			'no reprocess marker on a failed rebuild'
		);
	}

	public function testMissingIpCacheIsANoOpNotAnError(): void
	{
		$dnsblip = "{$this->workdir}/DNSBLIP_v4.txt";
		$ipCache = "{$this->workdir}/does-not-exist.sqlite";
		$this->assertFileDoesNotExist($ipCache);

		pfb_dnsblip_finalize($dnsblip, 'FP', TRUE, $ipCache, 'Alias_Native', '_v4');

		$this->assertSame('FP', file_get_contents("{$dnsblip}.fp"), 'the rest of the gate must still run');
		$this->assertFileExists("{$this->nativedir}/DNSBLIP_v4.update");
	}

	public function testPreExistingFpContentIsOverwrittenNotAppended(): void
	{
		$dnsblip = "{$this->workdir}/DNSBLIP_v4.txt";
		file_put_contents("{$dnsblip}.fp", 'OLD-FINGERPRINT-LONGER-THAN-NEW');
		$ipCache = "{$this->workdir}/ip_cache.sqlite";

		pfb_dnsblip_finalize($dnsblip, 'NEW', TRUE, $ipCache, 'Alias_Native', '_v4');

		$this->assertSame(
			'NEW',
			file_get_contents("{$dnsblip}.fp"),
			'the .fp must be overwritten, not appended to'
		);
	}

	public function testV4SuffixWritesV4MarkerOnly(): void
	{
		pfb_dnsblip_finalize(
			"{$this->workdir}/DNSBLIP_v4.txt",
			'FP',
			TRUE,
			"{$this->workdir}/nope",
			'Alias_Native',
			'_v4'
		);

		$this->assertFileExists("{$this->nativedir}/DNSBLIP_v4.update");
		$this->assertFileDoesNotExist("{$this->nativedir}/DNSBLIP_v6.update");
	}

	public function testV6SuffixWritesV6MarkerOnly(): void
	{
		pfb_dnsblip_finalize(
			"{$this->workdir}/DNSBLIP_v6.txt",
			'FP',
			TRUE,
			"{$this->workdir}/nope",
			'Alias_Native',
			'_v6'
		);

		$this->assertFileExists("{$this->nativedir}/DNSBLIP_v6.update");
		$this->assertFileDoesNotExist("{$this->nativedir}/DNSBLIP_v4.update");
	}

	public function testEmptyFingerprintWithBuiltTrueWritesEmptyFpWithoutCrashing(): void
	{
		$dnsblip = "{$this->workdir}/DNSBLIP_v4.txt";

		pfb_dnsblip_finalize($dnsblip, '', TRUE, "{$this->workdir}/nope", 'Alias_Native', '_v4');

		$this->assertSame(
			'',
			file_get_contents("{$dnsblip}.fp"),
			'an empty fingerprint must still write an empty .fp file'
		);
	}
}
