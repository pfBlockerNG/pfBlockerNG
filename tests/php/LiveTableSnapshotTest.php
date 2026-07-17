<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_live_table_snapshot() -- issue #1412: the ADR-40 mirror-or-pfctl-fallback
 * table-membership read, extracted from the Alerts "+" (addsuppress) handler
 * so the temporary Unlock icon's live punch shares the exact same read
 * instead of re-deriving it (pfblockerng_extra.inc).
 *
 * These tests pin the extraction's two real branches directly: the
 * ADR-40 mirror file wins when readable (no pfctl needed at all -- proven by
 * pointing $pfctl at a binary that does not exist), and a missing/unreadable
 * mirror falls back to the pfctl path, failing SOFT (empty array, no
 * warning/fatal) when that pfctl invocation itself cannot run.
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
	 * The mirror file wins when readable -- and pfctl is never even invoked:
	 * $pfctl here is a nonexistent binary, so if the function fell through to
	 * the pfctl branch it would return an EMPTY array (a failed exec()
	 * produces no output), never the mirror's real content.
	 */
	public function testMirrorFileWinsAndPfctlIsNeverInvoked(): void
	{
		file_put_contents("{$this->aliasdir}/pfB_Test_v4.txt", "10.0.0.0/24\n198.51.100.7\n");

		$entries = pfb_live_table_snapshot('/nonexistent/pfctl-binary-xyz', $this->aliasdir, $this->dbdir, 'pfB_Test_v4');

		$this->assertSame(['10.0.0.0/24', '198.51.100.7'], $entries);
	}

	/** Blank and '#'-comment lines in the mirror are returned raw -- untouched, un-filtered. */
	public function testMirrorBlankAndCommentLinesReturnedRaw(): void
	{
		file_put_contents("{$this->aliasdir}/pfB_Raw_v4.txt", "10.0.0.1\n\n# a comment\n10.0.0.2\n");

		$entries = pfb_live_table_snapshot('/nonexistent/pfctl-binary-xyz', $this->aliasdir, $this->dbdir, 'pfB_Raw_v4');

		$this->assertSame(['10.0.0.1', '', '# a comment', '10.0.0.2'], $entries);
	}

	/**
	 * No mirror file -> falls back to the pfctl path; a pfctl invocation that
	 * cannot run at all (nonexistent binary) fails SOFT -- an empty array,
	 * never a warning or fatal.
	 */
	public function testMissingMirrorFallsBackToPfctlAndFailsSoftOnBrokenPfctl(): void
	{
		$entries = pfb_live_table_snapshot('/nonexistent/pfctl-binary-xyz', $this->aliasdir, $this->dbdir, 'pfB_NoMirror_v4');

		$this->assertSame([], $entries);
	}

	/**
	 * No mirror file, but a WORKING pfctl-shaped command -- proves the
	 * fallback path genuinely execs and parses $pfctl's own '-T show' output,
	 * not just "returns empty no matter what". A tiny shell shim stands in
	 * for pfctl (off-appliance has no real pf).
	 */
	public function testMissingMirrorFallsBackToPfctlAndParsesItsOutput(): void
	{
		$shim = "{$this->tmpDir}/pfctl-shim.sh";
		file_put_contents($shim, "#!/bin/sh\nprintf '203.0.113.0/28\\n203.0.113.99\\n'\n");
		chmod($shim, 0755);

		$entries = pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_NoMirror_v4');

		$this->assertSame(['203.0.113.0/28', '203.0.113.99'], $entries);
	}
}
