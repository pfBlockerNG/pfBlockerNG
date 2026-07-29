<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_live_table_snapshot() -- issue #1467: the live `pfctl -T show` capture
 * is the SOLE source of a pf table's membership. The ADR-40 mirror file
 * (issue #1412's original mirror-or-pfctl-fallback design) is never read --
 * a live punch never rewrites the mirror, so a second punch inside the same
 * containing entry would otherwise read a stale set and silently revert the
 * first punch. $aliasdir stays in the signature (unused) for call-site and
 * red-proof stability.
 *
 * Issue #1471: the snapshot streams as a \Generator instead of slurping
 * every line into an array -- a Deny table can hold millions of entries, and
 * materialising the whole set as a PHP string array would exhaust the web-UI
 * PHP process's memory.
 */
#[CoversFunction('pfb_live_table_snapshot')]
final class LiveTableSnapshotTest extends TestCase
{
	private string $tmpDir;
	private string $aliasdir;
	private string $dbdir;

	protected function setUp(): void
	{
		$this->tmpDir   = sys_get_temp_dir() . '/pfb_live_table_snapshot_' . bin2hex(random_bytes(6));
		$this->aliasdir = "{$this->tmpDir}/alias";
		$this->dbdir    = "{$this->tmpDir}/db";
		mkdir($this->aliasdir, 0777, TRUE);
		mkdir($this->dbdir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmpDir);
	}

	/**
	 * Collect a snapshot result into a plain array -- iteration-agnostic, so
	 * the same frozen assertion works whether pfb_live_table_snapshot()
	 * returns an array (red, pre-#1471) or a \Generator (green, post-#1471).
	 */
	private static function collect(iterable $entries): array
	{
		$out = [];
		foreach ($entries as $entry) {
			$out[] = $entry;
		}
		return $out;
	}

	private function writeShim(string $body): string
	{
		$shim = "{$this->tmpDir}/pfctl-shim-" . bin2hex(random_bytes(4)) . '.sh';
		file_put_contents($shim, "#!/bin/sh\n{$body}\n");
		chmod($shim, 0755);
		return $shim;
	}

	/**
	 * pfctl's own '-T show' output is parsed -- a tiny shell shim stands in
	 * for pfctl (off-appliance has no real pf).
	 */
	public function testPfctlOutputIsParsed(): void
	{
		$shim = $this->writeShim("printf '203.0.113.0/28\\n203.0.113.99\\n'");

		$entries = self::collect(pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Test_v4'));

		$this->assertSame(['203.0.113.0/28', '203.0.113.99'], $entries);
	}

	/**
	 * A pfctl invocation that cannot run at all (nonexistent binary) is no
	 * longer indistinguishable from an empty table -- it throws
	 * \RuntimeException instead of failing soft, so an orchestrator can tell
	 * "genuinely empty" from "snapshot capture failed" (a fail-soft empty
	 * result here used to read as -- and be acted on as -- "not currently
	 * blocked"). Supersedes the prior fail-soft spec. The throw fires
	 * lazily, on the generator's first iteration.
	 */
	public function testBrokenPfctlThrowsRuntimeException(): void
	{
		$this->expectException(\RuntimeException::class);

		foreach (pfb_live_table_snapshot('/nonexistent/pfctl-binary-xyz', $this->aliasdir, $this->dbdir, 'pfB_NoTable_v4') as $entry) {
			// the throw fires lazily -- iterating is what triggers the generator body
		}
	}

	/**
	 * Issue #1852: a table absent from the loaded ruleset (a fresh alias not
	 * yet referenced by any rule/reload -- exactly the state a user hits
	 * clicking Alerts "+" right after creating a Suppression/DNSBL alias)
	 * must NOT throw -- it is "no live members", not a capture failure.
	 * Stderr text probed for real on a leased pfSense CE 2.8 pool box (PHP
	 * 8.3.19): `pfctl -t <absent> -T show` exits rc=255 with stderr
	 * "pfctl: Table does not exist.". This shim reproduces that exact rc +
	 * stderr pairing.
	 */
	public function testAbsentTableYieldsEmptyInsteadOfThrowing(): void
	{
		$shim = $this->writeShim("printf 'pfctl: Table does not exist.\\n' 1>&2\nexit 255");

		$entries = self::collect(pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Absent_v4'));

		$this->assertSame([], $entries, 'an absent table must yield an empty membership set, not throw');
	}

	/**
	 * Issue #1852: the absent-table carve-out is narrow -- ANY other
	 * non-zero exit (a genuine pfctl failure, distinguished by stderr NOT
	 * matching "Table does not exist") still throws loudly, same as before.
	 */
	public function testGenuinePfctlFailureStillThrows(): void
	{
		$this->expectException(\RuntimeException::class);
		$this->expectExceptionMessageMatches('/pfctl -T show exited rc=1/');

		$shim = $this->writeShim("printf 'pfctl: some other genuine failure\\n' 1>&2\nexit 1");

		foreach (pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_GenuineFail_v4') as $entry) {
			// the throw fires lazily -- iterating is what triggers the generator body
		}
	}

	/**
	 * Issue #1467: a mirror file present does NOT win -- it is never read at
	 * all. The mirror holds a stale set A; live pfctl reports a different
	 * set B, exactly as it would after a first live punch that never
	 * rewrote the mirror. The snapshot must reflect B, the live truth, not
	 * the stale mirror.
	 */
	public function testMirrorPresentIsIgnoredLivePfctlIsTheSoleSource(): void
	{
		file_put_contents("{$this->aliasdir}/pfB_Test_v4.txt", "198.18.0.0/16\n");

		$shim = $this->writeShim("printf '198.18.0.0/17\\n198.18.128.0/18\\n198.18.192.0/19\\n'");

		$entries = self::collect(pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Test_v4'));

		$this->assertSame(
			['198.18.0.0/17', '198.18.128.0/18', '198.18.192.0/19'],
			$entries,
			'the live pfctl set (post-punch remainder) must win -- the stale mirror is never consulted'
		);
	}

	/** Blank and '#'-comment lines in pfctl's output are returned raw -- untouched, un-filtered. */
	public function testPfctlBlankAndCommentLinesReturnedRaw(): void
	{
		$shim = $this->writeShim("printf '10.0.0.1\\n\\n# a comment\\n10.0.0.2\\n'");

		$entries = self::collect(pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Raw_v4'));

		$this->assertSame(['10.0.0.1', '', '# a comment', '10.0.0.2'], $entries);
	}

	/** Issue #1471: the snapshot is a \Generator -- never a fully materialised array. */
	public function testSnapshotIsAGenerator(): void
	{
		$shim = $this->writeShim("printf '10.0.0.1\\n'");

		$result = pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Gen_v4');

		$this->assertInstanceOf(\Generator::class, $result);
	}

	/**
	 * A large table (~200k entries) must stream through with a bounded
	 * memory footprint. A 200k-string PHP array costs roughly 15-20 MiB;
	 * the generator must cost well under that. The threshold is set safely
	 * above the PHP 8.5 memory_get_peak_usage() ~2 MiB quantization step.
	 */
	public function testLargeTableStreamsWithBoundedMemory(): void
	{
		$shim = $this->writeShim(
			"awk 'BEGIN { for (i = 0; i < 200000; i++) printf \"10.%d.%d.%d/32\\n\", int(i / 65536) % 256, int(i / 256) % 256, i % 256 }'"
		);

		// Reset the process-wide peak immediately before the measured consumption
		// (CountLinesTest precedent) -- otherwise an earlier test's higher peak in
		// this same process can mask a regression here.
		memory_reset_peak_usage();
		$before = memory_get_peak_usage();
		$count  = 0;
		foreach (pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Big_v4') as $entry) {
			$count++;
		}
		$after = memory_get_peak_usage();

		$this->assertSame(200000, $count);
		$this->assertLessThan(
			8 * 1024 * 1024,
			$after - $before,
			"peak memory delta must stay well under a 200k-element array's cost"
		);
	}

	/** After a full iteration, the pfctl-show scratch temp file is cleaned up. */
	public function testTempFileCleanedUpAfterFullIteration(): void
	{
		$shim = $this->writeShim("printf '10.0.0.1\\n10.0.0.2\\n'");

		foreach (pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Clean_v4') as $entry) {
			// drain fully
		}

		$this->assertSame([], glob("{$this->dbdir}/pfb_punch_*"), 'the scratch temp file must not survive a full iteration');
	}

	/** An abandoned (partially-iterated, then destroyed) generator still cleans up its temp file. */
	public function testTempFileCleanedUpAfterAbandonedIteration(): void
	{
		$shim = $this->writeShim("printf '10.0.0.1\\n10.0.0.2\\n10.0.0.3\\n'");

		$gen = pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_Abandon_v4');
		foreach ($gen as $entry) {
			break; // take exactly one entry, then abandon
		}
		unset($gen);

		$this->assertSame(
			[],
			glob("{$this->dbdir}/pfb_punch_*"),
			'the scratch temp file must be cleaned up even when the generator is abandoned mid-iteration'
		);
	}
}
