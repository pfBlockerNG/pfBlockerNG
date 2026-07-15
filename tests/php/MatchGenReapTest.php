<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1250 — pin pfb_matchgen_reap(), the matchgendir orphan sweep extracted so it is
 * unit-testable outside sync_package_pfblockerng(). matchgendir holds ONLY machine-generated
 * Reputation/ET artifacts (never a user Match-list file), so its keep-list is built from
 * config state (Deny aliases, ccwhite action), not from Match-type list headers.
 *
 * Feature: matchgendir orphan reaping
 *   Background:
 *     Given matchgendir holds 'pfB_Match_Rep_<Header>_<fam>.txt' / 'pfB_Match_Exempt_v4.txt' /
 *           'pfB_Match_ET_v4.txt' files
 *     And   the sweep keeps a file iff its owning config state still exists
 *
 * Branch/hostile-input coverage (brief section 5, H1-H7):
 *   H1 live Deny alias artifact kept; H2 removed Deny alias artifact reaped (the leak this
 *   fix prevents); H3 ccwhite='match' exempt file kept; H4 ET file always kept (issue #1269);
 *   H5 no cross-directory reach (a matchdir user file is untouched); H6 a stray artifact with
 *   no owning alias is reaped; H7 both v4 and v6 families are enumerated, not just v4.
 *   R1-R3: the ET/Exempt keep-list is family-complete (v4 AND v6), not v4-only.
 *   H8 stale .txt.new staging is reaped without touching a configured alias's live artifact.
 */
#[CoversFunction('pfb_matchgen_reap')]
final class MatchGenReapTest extends TestCase
{
	/** @var string Per-test sandbox root; one fresh dir tree per test. */
	private string $root;
	private string $matchgendir;
	private string $matchdir;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_matchgen_' . getmypid() . '_' . uniqid();
		$this->matchgendir = "{$this->root}/generated";
		$this->matchdir = $this->root;
		@mkdir($this->matchgendir, 0777, true);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->matchgendir}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->matchgendir);
		foreach (glob("{$this->matchdir}/*.txt") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->matchdir);
	}

	/** Drop an empty file at <matchgendir>/<name>.txt, asserting the write succeeded. */
	private function touchGen(string $name): string
	{
		$path = "{$this->matchgendir}/{$name}.txt";
		$this->assertNotFalse(@file_put_contents($path, ''), "could not create {$path}");
		return $path;
	}

	/** Drop an empty file at <matchdir>/<name>.txt (the SIBLING top-level dir), for H5. */
	private function touchMatch(string $name): string
	{
		$path = "{$this->matchdir}/{$name}.txt";
		$this->assertNotFalse(@file_put_contents($path, ''), "could not create {$path}");
		return $path;
	}

	/**
	 * H1: a Deny alias's own reputation artifact survives while the alias is still configured.
	 *
	 *   Given Deny alias 'Spam_v4' is configured and its artifact exists
	 *   When  the sweep runs
	 *   Then  the artifact is KEPT and NOT reported as reaped.
	 */
	public function testKeepsLiveDenyAliasArtifact(): void
	{
		$artifact = $this->touchGen('pfB_Match_Rep_Spam_v4');

		$reaped = pfb_matchgen_reap(['Spam_v4'], FALSE, $this->matchgendir);

		$this->assertFileExists($artifact, 'a live Deny alias artifact must survive the sweep');
		$this->assertNotContains('pfB_Match_Rep_Spam_v4', $reaped);
	}

	/**
	 * H2: the leak this fix exists to close — once a Deny alias is removed from config, its
	 * orphaned reputation artifact is reaped instead of living forever in matchgendir.
	 *
	 *   Given Deny alias 'Spam_v4' was configured (artifact on disk) but is REMOVED from config
	 *   When  the sweep runs with an existing-deny list that no longer names it
	 *   Then  the before-state (file present) is asserted first, then the file is gone and
	 *         reported as reaped.
	 */
	public function testReapsArtifactOfRemovedDenyAlias(): void
	{
		$artifact = $this->touchGen('pfB_Match_Rep_Spam_v4');
		$this->assertFileExists($artifact, 'precondition: the orphan artifact exists before the sweep');

		$reaped = pfb_matchgen_reap([], FALSE, $this->matchgendir);

		$this->assertFileDoesNotExist($artifact, 'a removed Deny alias leaves an orphan the sweep must reap');
		$this->assertContains('pfB_Match_Rep_Spam_v4', $reaped);
	}

	/**
	 * H8: a pass aborted after writing a staging sibling can outlive its removed Deny alias.
	 * The orphan sweep removes that machine-owned staging file while preserving live artifacts.
	 */
	public function testReapsStaleNewArtifactWithoutTouchingLiveArtifact(): void
	{
		$live = $this->touchGen('pfB_Match_Rep_Live_v4');
		$staged = "{$this->matchgendir}/pfB_Match_Rep_GONE_v4.txt.new";
		$this->assertNotFalse(file_put_contents($staged, 'stale'));
		$this->assertFileExists($staged, 'precondition: the orphan staging artifact exists');

		$reaped = pfb_matchgen_reap(['Live_v4'], FALSE, $this->matchgendir);

		$this->assertFileDoesNotExist($staged, 'a removed alias must not strand its staging artifact');
		$this->assertFileExists($live, 'the configured alias live artifact must survive');
		$this->assertContains('pfB_Match_Rep_GONE_v4.txt.new', $reaped);
		$this->assertNotContains('pfB_Match_Rep_Live_v4', $reaped);
	}

	/**
	 * H3: the ccwhite consolidated exempt file is kept ONLY while ccwhite is the 'match' action
	 * — the sole config state that can produce it.
	 *
	 *   Given the exempt file exists and ccwhite IS 'match'
	 *   When  the sweep runs
	 *   Then  it is kept.
	 *   But   (contrast) when ccwhite is NOT 'match', the same file is reaped — proving the
	 *         gate is real, not a permanent keep.
	 */
	public function testKeepsExemptFileOnlyWhenCcwhiteIsMatch(): void
	{
		$artifact = $this->touchGen('pfB_Match_Exempt_v4');

		$reaped = pfb_matchgen_reap([], TRUE, $this->matchgendir);
		$this->assertFileExists($artifact, 'ccwhite=match must keep the consolidated exempt file');
		$this->assertNotContains('pfB_Match_Exempt_v4', $reaped);

		// Recreate for the contrast leg (the prior call left it in place).
		$reaped = pfb_matchgen_reap([], FALSE, $this->matchgendir);
		$this->assertFileDoesNotExist($artifact, 'ccwhite off must reap a now-orphaned exempt file');
		$this->assertContains('pfB_Match_Exempt_v4', $reaped);
	}

	/**
	 * H4 / issue #1269: the ET/Proofpoint match file is ALWAYS kept, regardless of Deny/ccwhite
	 * state — the reaper runs before processet() in sync_package_pfblockerng(), so gating this
	 * on "did ET run this pass" reaped a live file on every pass ET did not execute.
	 *
	 *   Given the ET match file exists and NO Deny alias / ccwhite state names it
	 *   When  the sweep runs
	 *   Then  it is kept unconditionally.
	 */
	public function testAlwaysKeepsEtMatchFile(): void
	{
		$artifact = $this->touchGen('pfB_Match_ET_v4');

		$reaped = pfb_matchgen_reap([], FALSE, $this->matchgendir);

		$this->assertFileExists($artifact, 'the ET match file must survive every pass, ET-enabled or not');
		$this->assertNotContains('pfB_Match_ET_v4', $reaped);
	}

	/**
	 * H5: issue #1250's exact collision, now benign — a user Match-list file named 'matchSpam'
	 * (matchdir) and a Deny alias 'Spam' (matchgendir) coexist; the sweep only ever touches
	 * matchgendir, so the sibling matchdir file is untouched regardless of what it is named.
	 *
	 *   Given matchdir holds 'matchSpam_v4.txt' (a genuine user Match list) and matchgendir
	 *         holds 'pfB_Match_Rep_Spam_v4.txt' (Deny alias 'Spam_v4' artifact)
	 *   When  the sweep runs
	 *   Then  BOTH survive, each in its own directory.
	 */
	public function testDoesNotReachIntoMatchdirForACollidingUserListName(): void
	{
		$userList = $this->touchMatch('matchSpam_v4');
		$repArtifact = $this->touchGen('pfB_Match_Rep_Spam_v4');

		$reaped = pfb_matchgen_reap(['Spam_v4'], FALSE, $this->matchgendir);

		$this->assertFileExists($userList, 'a matchdir user list must never be touched by the matchgendir sweep');
		$this->assertFileExists($repArtifact, "the Deny alias's own artifact must survive");
		$this->assertSame([], $reaped, 'nothing should be reaped when both owners are live');
	}

	/**
	 * H6: a stray artifact with no owning Deny alias at all is reaped.
	 *
	 *   Given 'pfB_Match_Rep_GONE_v4.txt' exists and no Deny alias named it, ever
	 *   When  the sweep runs
	 *   Then  it is reaped.
	 */
	public function testReapsStrayArtifactWithNoOwningDenyAlias(): void
	{
		$artifact = $this->touchGen('pfB_Match_Rep_GONE_v4');

		$reaped = pfb_matchgen_reap(['Spam_v4'], FALSE, $this->matchgendir);

		$this->assertFileDoesNotExist($artifact);
		$this->assertContains('pfB_Match_Rep_GONE_v4', $reaped);
	}

	/**
	 * H7: the family axis is enumerated — a v6-only configured Deny alias keeps its OWN v6
	 * artifact without needing a v4 sibling to exist.
	 *
	 *   Given Deny alias 'Spam_v6' is configured (existing-deny names it with the '_v6' suffix)
	 *         and its artifact exists; NO 'Spam_v4' artifact exists
	 *   When  the sweep runs
	 *   Then  the v6 artifact is kept.
	 */
	public function testKeepsV6FamilyArtifactForAV6OnlyConfiguredAlias(): void
	{
		$artifact = $this->touchGen('pfB_Match_Rep_Spam_v6');

		$reaped = pfb_matchgen_reap(['Spam_v6'], FALSE, $this->matchgendir);

		$this->assertFileExists($artifact, 'the v6 family axis must be enumerated, not just v4');
		$this->assertNotContains('pfB_Match_Rep_Spam_v6', $reaped);
	}

	/**
	 * R1 / issue #1250 P2: pfB_Match_ET_v6.txt -- the keep-list was v4-only, so the day a v6 ET
	 * writer lands its first artifact was silently unlinked. Same unconditional keep as v4 (H4).
	 *
	 *   Given the ET v6 match file exists and NO Deny alias / ccwhite state names it
	 *   When  the sweep runs
	 *   Then  it is kept unconditionally.
	 */
	public function testAlwaysKeepsEtMatchFileV6Family(): void
	{
		$artifact = $this->touchGen('pfB_Match_ET_v6');

		$reaped = pfb_matchgen_reap([], FALSE, $this->matchgendir);

		$this->assertFileExists($artifact, 'the v6 ET match file must survive too, not just v4');
		$this->assertNotContains('pfB_Match_ET_v6', $reaped);
	}

	/**
	 * R2 + R3 / issue #1250 P2: the ccwhite exempt file's v6 family gets the SAME gate as v4
	 * (H3) -- kept while ccwhite='match', reaped once ccwhite stops being 'match'.
	 *
	 *   Given the v6 exempt file exists and ccwhite IS 'match'
	 *   When  the sweep runs
	 *   Then  it is kept.
	 *   But   (contrast) when ccwhite is NOT 'match', the same v6 file is reaped.
	 */
	public function testKeepsExemptFileOnlyWhenCcwhiteIsMatchV6Family(): void
	{
		$artifact = $this->touchGen('pfB_Match_Exempt_v6');

		$reaped = pfb_matchgen_reap([], TRUE, $this->matchgendir);
		$this->assertFileExists($artifact, 'ccwhite=match must keep the v6 consolidated exempt file too');
		$this->assertNotContains('pfB_Match_Exempt_v6', $reaped);

		// Recreate for the contrast leg (the prior call left it in place).
		$reaped = pfb_matchgen_reap([], FALSE, $this->matchgendir);
		$this->assertFileDoesNotExist($artifact, 'ccwhite off must reap a now-orphaned v6 exempt file');
		$this->assertContains('pfB_Match_Exempt_v6', $reaped);
	}
}
