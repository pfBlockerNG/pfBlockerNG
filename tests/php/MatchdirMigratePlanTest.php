<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1250 — pin pfb_matchdir_migrate_plan(), the upgrade-time decision of which
 * top-level matchdir *.txt files are machine-owned artifacts (move into matchgendir under
 * their new pfB_Match_* name) vs a same-named user Match-list file (leave in place). A
 * user's own Match-list file always carries a family suffix ('<header>_v4'/'_v6' — the
 * Download/Collect header build in pfblockerng.inc), so the un-suffixed 'ETMatch.txt' is
 * unreachable by any user list and always the ET artifact; 'matchdedup_*' and
 * 'match<Header>_<fam>' can collide with a same-named user list and are cross-referenced
 * against the configured Deny/Match header sets. Pure: no filesystem I/O.
 *
 * Feature: matchdir->matchgendir migration planning
 *   Background:
 *     Given a top-level listing of matchdir's *.txt files
 *     And   the configured Deny-action and Match-action header sets (per family)
 *     And   the ccwhite='match' flag (the exempt file's only writer)
 *   Scenario outline: decision table (brief section 4), one row each M1-M14
 *
 * Never delete: every case either moves, leaves, or marks undecidable — never drops a file.
 */
#[CoversFunction('pfb_matchdir_migrate_plan')]
final class MatchdirMigratePlanTest extends TestCase
{
	/** M1: ETMatch.txt has no family suffix — unreachable by any user list, always moved. */
	public function testM1EtMatchAlwaysMoves(): void
	{
		$plan = pfb_matchdir_migrate_plan(['ETMatch.txt'], [], [], FALSE, []);

		$this->assertSame(['ETMatch.txt' => 'pfB_Match_ET_v4.txt'], $plan['move']);
		$this->assertSame([], $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/**
	 * M2: the fact that makes ETMatch unambiguous — a user Match list headed 'ETMatch'
	 * produces 'ETMatch_v4.txt' (WITH the family suffix), never a collision with the
	 * un-suffixed machine artifact. Both files present: ETMatch.txt moves, ETMatch_v4.txt
	 * (the user's file) is left, even though a Match list named 'ETMatch' is configured.
	 */
	public function testM2EtMatchMovesWhileUserListOfSameNameIsLeft(): void
	{
		$plan = pfb_matchdir_migrate_plan(
			['ETMatch.txt', 'ETMatch_v4.txt'],
			[],
			['ETMatch_v4'],
			FALSE,
			[]
		);

		$this->assertSame(['ETMatch.txt' => 'pfB_Match_ET_v4.txt'], $plan['move']);
		$this->assertContains('ETMatch_v4.txt', $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** M3: a Deny list's reputation artifact, no colliding Match list -> moved. */
	public function testM3RepArtifactMovesWhenOnlyDenyHeaderConfigured(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchSpam_v4.txt'], ['Spam_v4'], [], FALSE, []);

		$this->assertSame(['matchSpam_v4.txt' => 'pfB_Match_Rep_Spam_v4.txt'], $plan['move']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** M4: only the colliding Match list is configured -> it is the user's own file, left. */
	public function testM4LeftWhenOnlyMatchHeaderConfigured(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchSpam_v4.txt'], [], ['matchSpam_v4'], FALSE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('matchSpam_v4.txt', $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** M5: BOTH a Deny list 'Spam' and a Match list 'matchSpam' configured -> undecidable, needs a human. */
	public function testM5BothConfiguredIsUndecidableNotMoved(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchSpam_v4.txt'], ['Spam_v4'], ['matchSpam_v4'], FALSE, []);

		$this->assertArrayNotHasKey('matchSpam_v4.txt', $plan['move']);
		$this->assertCount(1, $plan['undecidable']);
		$this->assertSame('matchSpam_v4.txt', $plan['undecidable'][0]['file']);
		$this->assertStringContainsString('Spam', $plan['undecidable'][0]['candidate_a']);
		$this->assertStringContainsString('matchSpam', $plan['undecidable'][0]['candidate_b']);
	}

	/** M6: neither configured -> an orphan; left for the matchgendir reaper's problem, never re-homed. */
	public function testM6NeitherConfiguredIsLeftAsOrphan(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchSpam_v4.txt'], [], [], FALSE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('matchSpam_v4.txt', $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** M7: the ccwhite consolidated exempt write, no colliding Match list -> moved. */
	public function testM7ExemptFileMovesWhenNoCollidingMatchList(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchdedup_v4.txt'], [], [], TRUE, []);

		$this->assertSame(['matchdedup_v4.txt' => 'pfB_Match_Exempt_v4.txt'], $plan['move']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** M8: ccwhite='match' AND a Match list literally headed 'matchdedup' -> undecidable. */
	public function testM8DedupBothConfiguredIsUndecidable(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchdedup_v4.txt'], [], ['matchdedup_v4'], TRUE, []);

		$this->assertSame([], $plan['move']);
		$this->assertCount(1, $plan['undecidable']);
		$this->assertSame('matchdedup_v4.txt', $plan['undecidable'][0]['file']);
		$this->assertStringContainsString('matchdedup', $plan['undecidable'][0]['candidate_b']);
	}

	/** M9: ccwhite is NOT 'match' -> only the user's file is possible, left silently. */
	public function testM9DedupLeftWhenCcwhiteIsNotMatch(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchdedup_v4.txt'], [], ['matchdedup_v4'], FALSE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('matchdedup_v4.txt', $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** M10: the family axis — a v6 Deny header's reputation artifact moves too, not just v4. */
	public function testM10RepArtifactMovesForV6Family(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchSpam_v6.txt'], ['Spam_v6'], [], FALSE, []);

		$this->assertSame(['matchSpam_v6.txt' => 'pfB_Match_Rep_Spam_v6.txt'], $plan['move']);
	}

	/** M11: an ordinary user Match list, no 'match' prefix shape at all -> always left. */
	public function testM11OrdinaryUserListAlwaysLeft(): void
	{
		$plan = pfb_matchdir_migrate_plan(['Ads_v4.txt'], ['Ads_v4'], ['Ads_v4'], TRUE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('Ads_v4.txt', $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** M12: no-clobber — the destination already exists in matchgendir; source is left + skipped, never overwritten. */
	public function testM12NoClobberLeavesSourceWhenDestinationExists(): void
	{
		$plan = pfb_matchdir_migrate_plan(
			['matchSpam_v4.txt'],
			['Spam_v4'],
			[],
			FALSE,
			['pfB_Match_Rep_Spam_v4.txt']
		);

		$this->assertSame([], $plan['move']);
		$this->assertContains('matchSpam_v4.txt', $plan['leave']);
	}

	/** M13: an empty matchdir listing -> an entirely empty plan (a fresh install prints no banner). */
	public function testM13EmptyMatchdirYieldsEmptyPlan(): void
	{
		$plan = pfb_matchdir_migrate_plan([], ['Spam_v4'], ['matchSpam_v4'], TRUE, []);

		$this->assertSame([], $plan['move']);
		$this->assertSame([], $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/**
	 * M14: idempotence — re-running the plan against the POST-migration matchdir listing
	 * (the moved file is physically gone; only orphans/user files remain) moves nothing.
	 */
	public function testM14SecondRunAgainstPostMigrationStateIsEmpty(): void
	{
		$first = pfb_matchdir_migrate_plan(['matchSpam_v4.txt'], ['Spam_v4'], [], FALSE, []);
		$this->assertNotEmpty($first['move'], 'precondition: the first pass actually planned a move');

		// The file named in $first['move'] no longer exists in matchdir after the real
		// rename(); the caller's listing on the next run reflects that directly.
		$second = pfb_matchdir_migrate_plan([], ['Spam_v4'], [], FALSE, array_values($first['move']));

		$this->assertSame(['move' => [], 'leave' => [], 'undecidable' => []], $second);
	}

	// --- Hostile-input rows: the stem parser is a parser, treat it as one. ---

	/** H-a: stem exactly 'match_v4' (empty header) with neither side configured -> parses cleanly, left as an orphan. */
	public function testHostileEmptyHeaderStemNeitherConfiguredIsLeft(): void
	{
		$plan = pfb_matchdir_migrate_plan(['match_v4.txt'], [], [], FALSE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('match_v4.txt', $plan['leave']);
		$this->assertSame([], $plan['undecidable']);
	}

	/** H-e: the same empty-header stem, but the empty Deny header IS configured -> moves correctly (no crash on H=""). */
	public function testHostileEmptyHeaderStemMovesWhenEmptyDenyHeaderConfigured(): void
	{
		$plan = pfb_matchdir_migrate_plan(['match_v4.txt'], ['_v4'], [], FALSE, []);

		$this->assertSame(['match_v4.txt' => 'pfB_Match_Rep__v4.txt'], $plan['move']);
	}

	/** H-b: stem 'match' with no family suffix at all -> does not match the pattern, left untouched. */
	public function testHostileMatchWithNoFamilySuffixIsLeft(): void
	{
		$plan = pfb_matchdir_migrate_plan(['match.txt'], ['match'], ['match'], FALSE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('match.txt', $plan['leave']);
	}

	/** H-c: stem 'matchdedup' with no family suffix -> does not match the dedup special-case either, left. */
	public function testHostileMatchdedupWithNoFamilySuffixIsLeft(): void
	{
		$plan = pfb_matchdir_migrate_plan(['matchdedup.txt'], [], [], TRUE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('matchdedup.txt', $plan['leave']);
	}

	/**
	 * H-d: a header containing an underscore — the '_v4' split must come from the RIGHT
	 * (string end), never the first underscore, or 'Spam_Feed' would be mis-split.
	 */
	public function testHostileUnderscoreInHeaderSplitsFromTheRight(): void
	{
		$plan = pfb_matchdir_migrate_plan(['match_Spam_Feed_v4.txt'], ['_Spam_Feed_v4'], [], FALSE, []);

		$this->assertSame(['match_Spam_Feed_v4.txt' => 'pfB_Match_Rep__Spam_Feed_v4.txt'], $plan['move']);
	}

	/** H-f: a file with no .txt extension at all -> never treated as a candidate, always left. */
	public function testHostileNonTxtFileIsLeft(): void
	{
		$plan = pfb_matchdir_migrate_plan(['ETMatch'], [], [], FALSE, []);

		$this->assertSame([], $plan['move']);
		$this->assertContains('ETMatch', $plan['leave']);
	}
}
