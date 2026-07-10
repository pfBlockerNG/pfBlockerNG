<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1084 — the recompute snapshot store's path/seed/write/forget helpers:
 *   pfb_ip_recompute_snapshot_path()  path convention (basename strip-at-first-'.' round-trip)
 *   pfb_ip_recompute_seed_snapshot()  memberlist entry: existing snapshot, or seed from the
 *                                     live deny .txt (upgrade/first-run fallback -- load-bearing)
 *   pfb_ip_recompute_write_snapshot() persist a fresh snapshot + its .aggcount sidecar
 *   pfb_ip_recompute_forget_header()  drop a header's snapshot + sidecar on removal
 *
 * Feature: snapshot store lifecycle
 *   Branch coverage: snapshot present (no seed) vs missing+live-present (seeded) vs
 *   missing+live-missing (stays missing, benign); write skips a nonexistent source; aggcount
 *   counts every line (parity with duplicate()'s `grep -c ^`, including blank lines); forget
 *   is idempotent on an absent pair.
 */
#[CoversFunction('pfb_ip_recompute_snapshot_path')]
#[CoversFunction('pfb_ip_recompute_seed_snapshot')]
#[CoversFunction('pfb_ip_recompute_write_snapshot')]
#[CoversFunction('pfb_ip_recompute_forget_header')]
final class IpRecomputeSnapshotTest extends TestCase
{
	private string $root;
	private string $snapdir;
	private string $denydir;
	private string $origdir;

	protected function setUp(): void
	{
		$this->root    = sys_get_temp_dir() . '/pfb_rec_snap_' . getmypid() . '_' . uniqid();
		$this->snapdir = "{$this->root}/snapshot";
		$this->denydir = "{$this->root}/deny";
		$this->origdir = "{$this->root}/original";
		foreach ([$this->snapdir, $this->denydir, $this->origdir] as $d) {
			$this->assertTrue(@mkdir($d, 0777, true), "could not create {$d}");
		}
	}

	protected function tearDown(): void
	{
		foreach ([$this->snapdir, $this->denydir, $this->origdir] as $d) {
			foreach (@glob("{$d}/*") ?: [] as $f) {
				@unlink($f);
			}
			@rmdir($d);
		}
		@rmdir($this->root);
	}

	public function testSnapshotPathIsBasenameDotSnapAndRoundTripsTheHeader(): void
	{
		$path = pfb_ip_recompute_snapshot_path($this->snapdir, 'FeedA_v4');
		$this->assertSame("{$this->snapdir}/FeedA_v4.snap", $path);

		// pfb_recompute()'s own derivation: strip dir, then strip from the first '.' onward.
		$base  = basename($path);
		$alias = substr($base, 0, (int) strpos($base, '.'));
		$this->assertSame('FeedA_v4', $alias, 'basename strip-at-first-dot must recover the header');
	}

	public function testSeedSnapshotReturnsExistingSnapshotUnchanged(): void
	{
		$snap = "{$this->snapdir}/FeedA_v4.snap";
		file_put_contents($snap, "198.51.100.1\n");

		$got = pfb_ip_recompute_seed_snapshot('FeedA_v4', $this->snapdir, $this->denydir);

		$this->assertSame($snap, $got);
		$this->assertSame("198.51.100.1\n", file_get_contents($snap), 'an existing snapshot must not be overwritten by the seed fallback');
	}

	public function testSeedSnapshotFallsBackToLiveDenyFileWhenSnapshotMissing(): void
	{
		file_put_contents("{$this->denydir}/FeedB_v4.txt", "203.0.113.9\n");

		$got = pfb_ip_recompute_seed_snapshot('FeedB_v4', $this->snapdir, $this->denydir);

		$this->assertSame("{$this->snapdir}/FeedB_v4.snap", $got);
		$this->assertFileExists($got, 'upgrade fallback: a never-snapshotted header seeds from the live deny .txt');
		$this->assertSame("203.0.113.9\n", file_get_contents($got));
	}

	public function testSeedSnapshotStaysMissingWhenNeitherSnapshotNorLiveFileExist(): void
	{
		$got = pfb_ip_recompute_seed_snapshot('Ghost_v4', $this->snapdir, $this->denydir);

		$this->assertSame("{$this->snapdir}/Ghost_v4.snap", $got, 'the path is still returned (Stage A silently skips a missing file)');
		$this->assertFileDoesNotExist($got);
	}

	public function testWriteSnapshotCopiesSourceAndWritesAggcountSidecar(): void
	{
		$src = "{$this->denydir}/FeedC_v4.txt";
		file_put_contents($src, "198.51.100.1\n198.51.100.2\n198.51.100.3\n");

		pfb_ip_recompute_write_snapshot($src, 'FeedC_v4', $this->snapdir, $this->origdir);

		$this->assertFileEquals($src, "{$this->snapdir}/FeedC_v4.snap");
		$this->assertSame("3\n", file_get_contents("{$this->origdir}/FeedC_v4.aggcount"));
	}

	public function testWriteSnapshotAggcountCountsBlankLinesLikeGrepCAnchor(): void
	{
		// duplicate()'s original `grep -c ^` counts every line, blank ones included --
		// the sidecar must match that count, not a "non-empty lines" count.
		$src = "{$this->denydir}/FeedD_v4.txt";
		file_put_contents($src, "198.51.100.1\n\n198.51.100.2\n");

		pfb_ip_recompute_write_snapshot($src, 'FeedD_v4', $this->snapdir, $this->origdir);

		$this->assertSame("3\n", file_get_contents("{$this->origdir}/FeedD_v4.aggcount"), 'blank line counted, matching grep -c ^');
	}

	public function testWriteSnapshotIsANoOpWhenSourceMissing(): void
	{
		pfb_ip_recompute_write_snapshot("{$this->denydir}/DoesNotExist_v4.txt", 'DoesNotExist_v4', $this->snapdir, $this->origdir);

		$this->assertFileDoesNotExist("{$this->snapdir}/DoesNotExist_v4.snap");
		$this->assertFileDoesNotExist("{$this->origdir}/DoesNotExist_v4.aggcount");
	}

	public function testForgetHeaderRemovesSnapshotAndAggcount(): void
	{
		file_put_contents("{$this->snapdir}/FeedE_v4.snap", "198.51.100.1\n");
		file_put_contents("{$this->origdir}/FeedE_v4.aggcount", "1\n");

		pfb_ip_recompute_forget_header('FeedE_v4', $this->snapdir, $this->origdir);

		$this->assertFileDoesNotExist("{$this->snapdir}/FeedE_v4.snap");
		$this->assertFileDoesNotExist("{$this->origdir}/FeedE_v4.aggcount");
	}

	public function testForgetHeaderIsIdempotentWhenNothingExists(): void
	{
		// Must not warn/throw on an absent pair (the download-failure call site calls this
		// unconditionally whenever a header is removed, snapshotted or not).
		pfb_ip_recompute_forget_header('NeverSnapshotted_v4', $this->snapdir, $this->origdir);
		$this->assertFileDoesNotExist("{$this->snapdir}/NeverSnapshotted_v4.snap");
	}
}
