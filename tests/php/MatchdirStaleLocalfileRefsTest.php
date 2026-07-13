<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1250 — pin pfb_matchdir_stale_localfile_refs(), the BREAKING CHANGE detector: the
 * GUI once instructed admins to point a Match alias's Localfile at e.g.
 * '/var/db/pfblockerng/match/ETMatch.txt' — an OLD machine-generated artifact path. The
 * migration does NOT rewrite that config for them, so every list row whose 'url' still
 * points there is surfaced instead. Pure.
 *
 * Feature: stale Localfile-reference detection
 *   Given a flattened list of configured IP-list rows (any action)
 *   When  a row's 'url' resolves to matchdir + an OLD artifact filename shape
 *   Then  that row is reported; anything else is not.
 */
#[CoversFunction('pfb_matchdir_stale_localfile_refs')]
final class MatchdirStaleLocalfileRefsTest extends TestCase
{
	private const MATCHDIR = '/var/db/pfblockerng/match';

	/** A row whose Localfile points at the OLD ETMatch.txt artifact path is reported. */
	public function testRowPointingAtOldEtMatchPathIsReported(): void
	{
		$row = array('list' => 'MyETConsumer', 'header' => 'MyETConsumer', 'url' => self::MATCHDIR . '/ETMatch.txt');

		$hits = pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR);

		$this->assertSame([$row], $hits);
	}

	/** A row pointing anywhere else (its OWN matchdir-stored user list) is NOT reported. */
	public function testRowPointingAtAPlainUserListIsNotReported(): void
	{
		$row = array('list' => 'Ads', 'header' => 'Ads', 'url' => self::MATCHDIR . '/Ads_v4.txt');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR));
	}

	/** A row pointing at an unrelated path entirely (not under matchdir) is NOT reported. */
	public function testRowPointingOutsideMatchdirIsNotReported(): void
	{
		$row = array('list' => 'Other', 'header' => 'Other', 'url' => '/root/mylist.txt');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR));
	}

	/** The ccwhite exempt artifact's OLD name is also caught by the general 'match*_v4/6.txt' shape. */
	public function testRowPointingAtOldDedupPathIsReported(): void
	{
		$row = array('list' => 'ExemptConsumer', 'header' => 'ExemptConsumer', 'url' => self::MATCHDIR . '/matchdedup_v4.txt');

		$this->assertSame([$row], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR));
	}

	/** An empty url is skipped without error, never a stray match. */
	public function testRowWithEmptyUrlIsNotReported(): void
	{
		$row = array('list' => 'Blank', 'header' => 'Blank', 'url' => '');

		$this->assertSame([], pfb_matchdir_stale_localfile_refs([$row], self::MATCHDIR));
	}
}
