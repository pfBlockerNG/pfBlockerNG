<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1250 — pin pfb_matchdir_stale_localfile_refs(), the BREAKING CHANGE detector: the
 * GUI once instructed admins to point a Match alias's Localfile at e.g.
 * '/var/db/pfblockerng/match/ETMatch.txt' — an OLD machine-generated artifact path. The
 * migration does NOT rewrite that config for them, so every list row whose 'url' still
 * points at a file THIS RUN ACTUALLY MOVED is surfaced instead. Pure.
 *
 * Feature: stale Localfile-reference detection
 *   Given a flattened list of configured IP-list rows (any action, any state)
 *   And   the basenames the migration actually moved this run
 *   When  a row's 'url' resolves to matchdir + one of those basenames
 *   Then  that row is reported; anything else — including a same-shaped file that was NOT
 *         moved (a live user list) — is not (issue #1250: shape-keying false-flagged a
 *         working, never-moved user list).
 */
#[CoversFunction('pfb_matchdir_stale_localfile_refs')]
final class MatchdirStaleLocalfileRefsTest extends TestCase
{
	private const MATCHDIR = '/var/db/pfblockerng/match';

	/** S2: a row whose Localfile points at the OLD ETMatch.txt artifact, WHICH WAS MOVED, is reported. */
	public function testRowPointingAtOldEtMatchPathIsReported(): void
	{
		$row = array('list' => 'MyETConsumer', 'header' => 'MyETConsumer', 'url' => self::MATCHDIR . '/ETMatch.txt');

		$hits = pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['ETMatch.txt']);

		$this->assertSame([$row], $hits);
	}

	/** A row pointing anywhere else (its OWN matchdir-stored user list) is NOT reported. */
	public function testRowPointingAtAPlainUserListIsNotReported(): void
	{
		$row = array('list' => 'Ads', 'header' => 'Ads', 'url' => self::MATCHDIR . '/Ads_v4.txt');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['ETMatch.txt']));
	}

	/** A row pointing at an unrelated path entirely (not under matchdir) is NOT reported. */
	public function testRowPointingOutsideMatchdirIsNotReported(): void
	{
		$row = array('list' => 'Other', 'header' => 'Other', 'url' => '/root/mylist.txt');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['ETMatch.txt']));
	}

	/** S4: a row pointing at matchdedup_v4.txt IS reported once that file was actually moved this run. */
	public function testRowPointingAtOldDedupPathIsReported(): void
	{
		$row = array('list' => 'ExemptConsumer', 'header' => 'ExemptConsumer', 'url' => self::MATCHDIR . '/matchdedup_v4.txt');

		$this->assertSame([$row], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['matchdedup_v4.txt']));
	}

	/** An empty url is skipped without error, never a stray match. */
	public function testRowWithEmptyUrlIsNotReported(): void
	{
		$row = array('list' => 'Blank', 'header' => 'Blank', 'url' => '');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['ETMatch.txt']));
	}

	/**
	 * S1 / issue #1250: a user's OWN never-moved 'matchFoo_v4.txt' Localfile ref must
	 * NOT be flagged just because its NAME has the old machine-artifact shape -- only an
	 * actually-moved basename triggers the warning. The pre-fix shape-regex flagged this and
	 * sent the admin to break a working list by repointing it at a path that never existed.
	 */
	public function testRowPointingAtShapedButNeverMovedUserFileIsNotReported(): void
	{
		$row = array('list' => 'Foo', 'header' => 'Foo', 'url' => self::MATCHDIR . '/matchFoo_v4.txt');

		$hits = pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['ETMatch.txt', 'pfB_Match_Rep_Spam_v4.txt']);

		$this->assertSame([], $hits, 'a shaped-but-never-moved file must not trigger the repoint warning');
	}

	/** S5: the synthetic custom-list url 'custom' is not under matchdir at all -- never flagged. */
	public function testCustomListSyntheticUrlIsNotReported(): void
	{
		$row = array('list' => 'Stuff', 'header' => 'Stuff_custom', 'url' => 'custom');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['Stuff_custom_v4.txt']));
	}

	/**
	 * S6: this pure function does not look at row/list state at all -- a row config marks
	 * disabled is still reported if its url matches a moved basename (the "regardless of
	 * state" guarantee is enforced by the CALLER collecting disabled rows too, tested at the
	 * pfb_matchdir_config_headers level).
	 */
	public function testDisabledRowStillReportedWhenItsFileWasMoved(): void
	{
		$row = array('list' => 'Old', 'header' => 'Old', 'url' => self::MATCHDIR . '/ETMatch.txt', 'state' => 'Disabled');

		$this->assertSame([$row], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['ETMatch.txt']));
	}

	/**
	 * Hostile: a directory-traversal-shaped url. dirname() is a pure string operation (no
	 * realpath, no filesystem) -- comparison against matchdir is intentionally exact-string,
	 * so a '..'-laden path never resolves to a matchdir hit even though it points there.
	 */
	public function testHostileDirectoryTraversalUrlIsNotReported(): void
	{
		$row = array('list' => 'Sneaky', 'header' => 'Sneaky', 'url' => self::MATCHDIR . '/../match/ETMatch.txt');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR, ['ETMatch.txt']));
	}
}
