<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pure helpers extracted from sync_package_pfblockerng()'s download loop.
 *
 * pfb_prune_failed_bl_lists() — issue #711. On a Blacklist download failure the
 * cleanup used to unset($lists[$key]) with $key being the child's STDOUT LINE index,
 * not a $lists index. pfblockerng_download_extras processes only the not-yet-downloaded
 * types and silently skips some feeds (Shallalist), so the two index spaces do not
 * correspond: a positional unset() dropped the WRONG category (often a healthy,
 * already-downloaded one) while the failed feed stayed. The helper matches by feed
 * NAME in the child's "\t{name} ... Failed" line instead.
 *
 * pfb_list_section_for_vtype() — issue #709. Maps a list's vtype to its config
 * section so the download loop reads the correct per-family section rather than the
 * stale $ip_type (the caller-level fix is proven by live-VM smoke; this pins the map).
 */
#[CoversFunction('pfb_prune_failed_bl_lists')]
#[CoversFunction('pfb_list_section_for_vtype')]
final class DownloadLoopHelpersTest extends TestCase
{
	/**
	 * @param array<int, array<string, mixed>> $lists
	 * @return string[] the surviving aliasnames, in order
	 */
	private static function survivingNames(array $lists): array
	{
		return array_values(array_map(static fn(array $l): string => $l['aliasname'], $lists));
	}

	// -----------------------------------------------------------------------
	// #711 — pfb_prune_failed_bl_lists()
	// -----------------------------------------------------------------------

	/**
	 * The canonical desync: a healthy already-downloaded feed A precedes a failed
	 * new feed B. Only B is in the child's output, at stdout index 0. The positional
	 * code unset($lists[0]) and dropped HEALTHY A; the name match drops only B.
	 */
	public function testHealthyFirstFailedSecondRemovesOnlyTheFailed(): void
	{
		// Given: A already-downloaded/healthy, B new and failed.
		$lists = [
			['aliasname' => 'AlphaFeed', 'row' => [['url' => 'u']]],
			['aliasname' => 'BetaFeed',  'row' => [['url' => 'u']]],
		];
		// The child processed only B (the not-yet-downloaded one) and it Failed.
		$pfb_return = ["\tBetaFeed ... Failed"];

		// Before: both present.
		$this->assertSame(['AlphaFeed', 'BetaFeed'], self::survivingNames($lists));

		// When.
		$result = pfb_prune_failed_bl_lists($lists, $pfb_return);

		// Then: only BetaFeed removed; AlphaFeed (the healthy one) survives.
		$this->assertSame(['AlphaFeed'], self::survivingNames($result),
			'Only the FAILED feed (BetaFeed) must be dropped; the healthy AlphaFeed must survive');
	}

	/**
	 * A skipped feed (Shallalist emits no line) shifts the stdout offset, so the
	 * positional code dropped the skipped/neighbouring entry. Name-matching removes
	 * exactly the failed feed regardless of the offset.
	 */
	public function testSkippedFeedOffsetRemovesOnlyTheFailed(): void
	{
		$lists = [
			['aliasname' => 'Alpha',      'row' => [['url' => 'u']]],
			['aliasname' => 'Shallalist', 'row' => [['url' => 'u']]],
			['aliasname' => 'Beta',       'row' => [['url' => 'u']]],
		];
		// Shallalist is skipped (no line); Alpha completed, Beta failed.
		$pfb_return = ["\tAlpha ... Completed", "\tBeta ... Failed"];

		$result = pfb_prune_failed_bl_lists($lists, $pfb_return);

		$this->assertSame(['Alpha', 'Shallalist'], self::survivingNames($result),
			'Only Beta must be removed; the skipped Shallalist and completed Alpha must survive');
	}

	/**
	 * The " ... " delimiter after the name prevents a prefix collision: a failed
	 * "FeedExtra" must not also drop "Feed".
	 */
	public function testPrefixCollisionMatchesWholeNameOnly(): void
	{
		$lists = [
			['aliasname' => 'Feed',      'row' => [['url' => 'u']]],
			['aliasname' => 'FeedExtra', 'row' => [['url' => 'u']]],
		];
		$pfb_return = ["\tFeedExtra ... Failed"];

		$result = pfb_prune_failed_bl_lists($lists, $pfb_return);

		$this->assertSame(['Feed'], self::survivingNames($result),
			'FeedExtra must be removed; the prefix Feed must NOT be collaterally dropped');
	}

	/**
	 * A "Failed" line whose name is not in $lists (e.g. an item with no rows) removes
	 * nothing — the old blind index unset() could still drop an unrelated entry.
	 */
	public function testFailedNameAbsentFromListsIsNoOp(): void
	{
		$lists = [
			['aliasname' => 'Alpha', 'row' => [['url' => 'u']]],
			['aliasname' => 'Beta',  'row' => [['url' => 'u']]],
		];
		$pfb_return = ["\tGamma ... Failed"]; // Gamma is not in $lists

		$result = pfb_prune_failed_bl_lists($lists, $pfb_return);

		$this->assertSame(['Alpha', 'Beta'], self::survivingNames($result),
			'A Failed line for a name absent from $lists must remove nothing');
	}

	/**
	 * All-completed output removes nothing (guards against over-eager matching on
	 * the "Completed" lines).
	 */
	public function testAllCompletedRemovesNothing(): void
	{
		$lists = [
			['aliasname' => 'Alpha', 'row' => [['url' => 'u']]],
			['aliasname' => 'Beta',  'row' => [['url' => 'u']]],
		];
		$pfb_return = ["\tAlpha ... Completed", "\tBeta ... Completed"];

		$result = pfb_prune_failed_bl_lists($lists, $pfb_return);

		$this->assertSame(['Alpha', 'Beta'], self::survivingNames($result),
			'No Failed line -> no removal');
	}

	// -----------------------------------------------------------------------
	// #709 — pfb_list_section_for_vtype()
	// -----------------------------------------------------------------------

	public function testVtypeV4MapsToV4Section(): void
	{
		$this->assertSame('pfblockernglistsv4', pfb_list_section_for_vtype('_v4'));
	}

	public function testVtypeV6MapsToV6Section(): void
	{
		$this->assertSame('pfblockernglistsv6', pfb_list_section_for_vtype('_v6'));
	}

	public function testNonV6VtypeDefaultsToV4Section(): void
	{
		// Anything that is not the exact '_v6' token is treated as v4 (fail-safe).
		$this->assertSame('pfblockernglistsv4', pfb_list_section_for_vtype(''));
	}
}
