<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1250 — pin pfb_matchdir_apply_moves(), the upgrade-time application of the
 * migration plan's renames. Its return value (the OLD basenames actually renamed) feeds
 * the stale-Localfile warning and the 'Moved:' banner, so it must report real outcomes:
 * a rename skipped by the live no-clobber guard (destination appeared between the plan's
 * snapshot and the rename) or failed outright leaves the old file live and valid — warning
 * the admin to "repoint" such a file would break a working list.
 *
 * Feature: migration plan application
 *   Scenario outline: T1 clean rename applied+reported; T2 no-clobber race skips + keeps
 *   both files; T3 vanished source not reported; T4 mixed batch reports only successes;
 *   T5 end-to-end with pfb_matchdir_stale_localfile_refs(): a never-moved file is not
 *   flagged even though the plan wanted to move it.
 */
#[CoversFunction('pfb_matchdir_apply_moves')]
final class MatchdirApplyMovesTest extends TestCase
{
	private string $matchdir;
	private string $matchgendir;

	protected function setUp(): void
	{
		$this->matchdir = sys_get_temp_dir() . '/pfb_applymoves_' . getmypid() . '_' . uniqid();
		$this->matchgendir = "{$this->matchdir}/generated";
		mkdir($this->matchgendir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach ((glob("{$this->matchgendir}/*") ?: []) as $pfb_f) {
			@unlink($pfb_f);
		}
		@rmdir($this->matchgendir);
		foreach ((glob("{$this->matchdir}/*") ?: []) as $pfb_f) {
			@unlink($pfb_f);
		}
		@rmdir($this->matchdir);
	}

	/** T1: a clean planned rename is applied and reported. */
	public function testCleanRenameIsAppliedAndReported(): void
	{
		file_put_contents("{$this->matchdir}/matchSpam_v4.txt", "192.0.2.0/24\n");

		$applied = pfb_matchdir_apply_moves(
			['matchSpam_v4.txt' => 'pfB_Match_Rep_Spam_v4.txt'], $this->matchdir, $this->matchgendir);

		$this->assertSame(['matchSpam_v4.txt'], $applied);
		$this->assertFileDoesNotExist("{$this->matchdir}/matchSpam_v4.txt");
		$this->assertSame("192.0.2.0/24\n", file_get_contents("{$this->matchgendir}/pfB_Match_Rep_Spam_v4.txt"));
	}

	/**
	 * T2: the live no-clobber guard — destination appeared AFTER the plan's snapshot.
	 * The rename is skipped, NOT reported as applied, and both files keep their content.
	 */
	public function testNoClobberRaceSkipsAndKeepsBothFiles(): void
	{
		file_put_contents("{$this->matchdir}/matchSpam_v4.txt", "192.0.2.0/24\n");
		file_put_contents("{$this->matchgendir}/pfB_Match_Rep_Spam_v4.txt", "198.51.100.0/24\n");

		$applied = pfb_matchdir_apply_moves(
			['matchSpam_v4.txt' => 'pfB_Match_Rep_Spam_v4.txt'], $this->matchdir, $this->matchgendir);

		$this->assertSame([], $applied, 'a no-clobber skip must not be reported as moved');
		$this->assertSame("192.0.2.0/24\n", file_get_contents("{$this->matchdir}/matchSpam_v4.txt"));
		$this->assertSame("198.51.100.0/24\n", file_get_contents("{$this->matchgendir}/pfB_Match_Rep_Spam_v4.txt"));
	}

	/** T3: a source that vanished between plan and apply fails the rename and is not reported. */
	public function testVanishedSourceIsNotReported(): void
	{
		$applied = pfb_matchdir_apply_moves(
			['matchGone_v4.txt' => 'pfB_Match_Rep_Gone_v4.txt'], $this->matchdir, $this->matchgendir);

		$this->assertSame([], $applied);
		$this->assertFileDoesNotExist("{$this->matchgendir}/pfB_Match_Rep_Gone_v4.txt");
	}

	/** T4: a mixed batch reports only the renames that actually succeeded, in plan order. */
	public function testMixedBatchReportsOnlySuccesses(): void
	{
		file_put_contents("{$this->matchdir}/matchA_v4.txt", "192.0.2.0/24\n");
		file_put_contents("{$this->matchdir}/matchB_v4.txt", "192.0.2.128/25\n");
		file_put_contents("{$this->matchgendir}/pfB_Match_Rep_B_v4.txt", "198.51.100.0/24\n");
		file_put_contents("{$this->matchdir}/ETMatch.txt", "203.0.113.0/24\n");

		$applied = pfb_matchdir_apply_moves([
			'matchA_v4.txt' => 'pfB_Match_Rep_A_v4.txt',
			'matchB_v4.txt' => 'pfB_Match_Rep_B_v4.txt',
			'ETMatch.txt'   => 'pfB_Match_ET_v4.txt',
		], $this->matchdir, $this->matchgendir);

		$this->assertSame(['matchA_v4.txt', 'ETMatch.txt'], $applied);
	}

	/**
	 * T5: the false-alarm regression, end-to-end through both real functions. The plan
	 * wants to move matchSpam_v4.txt, the no-clobber guard skips it, and the admin's
	 * Localfile row pointing at the still-live old path must NOT be flagged as stale.
	 */
	public function testSkippedRenameNeverFlagsTheStillValidLocalfileRef(): void
	{
		file_put_contents("{$this->matchdir}/matchSpam_v4.txt", "192.0.2.0/24\n");
		file_put_contents("{$this->matchgendir}/pfB_Match_Rep_Spam_v4.txt", "198.51.100.0/24\n");
		$pfb_rows = [['list' => 'MyAlias', 'header' => 'matchSpam', 'url' => "{$this->matchdir}/matchSpam_v4.txt"]];

		$applied = pfb_matchdir_apply_moves(
			['matchSpam_v4.txt' => 'pfB_Match_Rep_Spam_v4.txt'], $this->matchdir, $this->matchgendir);
		$stale = pfb_matchdir_stale_localfile_refs($pfb_rows, $this->matchdir, $applied);

		$this->assertSame([], $stale, sprintf(
			'a never-moved file must not trigger the repoint warning; applied=%s stale=%s',
			var_export($applied, TRUE), var_export($stale, TRUE)));
		$this->assertFileExists("{$this->matchdir}/matchSpam_v4.txt");
	}
}
