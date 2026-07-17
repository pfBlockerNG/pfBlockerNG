<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1323 -- pins the invariant pfb_dnsbl_hold_stale_rebuild_skip()'s
 * safety rests on: a synthesized custom-DNSBL row can never be Hold. Every
 * site that builds one (all three live inside sync_package_pfblockerng(),
 * which has no PHPUnit harness -- issue #993, confirmed by
 * DnsblStagingGenerationGuardTest's docblock) hardcodes 'state' => 'Enabled'
 * at row-construction time, so the call-site check $row['state'] == 'Hold'
 * (pfblockerng.inc:17326 pairs it with pfb_dnsbl_hold_stale_rebuild_skip())
 * is unreachable for a custom row. This is a source-inspection pin (last
 * resort per CLAUDE.md, mirrors PfbSyncStatusDnsblWritersTest's
 * testDnsblDownloadCallSitesKeyOnTheAliasNotTheHeader) -- a future edit that
 * flips any synthesis site away from hardcoded Enabled must fail this test.
 */
#[CoversFunction('pfb_dnsbl_hold_stale_rebuild_skip')]
final class DnsblCustomRowStateEnabledInvariantTest extends TestCase
{
	private function pfblockerngSource(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertNotFalse($source, 'pfblockerng.inc must be readable');
		return $source;
	}

	/**
	 * Every synthesis site builds the row as one array-literal block, in the
	 * SAME key order: header, custom, state, url. Matching that exact block
	 * (not just a bare 'state' => 'Enabled' anywhere near 'url' => 'custom')
	 * means a reordered/dropped 'state' key fails this regex even if some
	 * other 'state' => 'Enabled' happens to sit nearby in the file.
	 */
	private const SITE_BLOCK_PATTERN = "/'header'\\s*=>\\s*\"\\{\\\$list\\['aliasname'\\]\\}_custom\",\\s*"
		. "'custom'\\s*=>\\s*\\\$list\\['custom'\\],\\s*"
		. "'state'\\s*=>\\s*'Enabled',\\s*"
		. "'url'\\s*=>\\s*'custom'/";

	/**
	 * Site-count tripwire: issue #1323 (re-derived by grepping the tree this
	 * session) enumerates exactly 3 synthesis sites (~pfblockerng.inc:16403,
	 * 17158, 18580). A different count means a site was added or removed --
	 * this test's coverage matrix (and SITE_BLOCK_PATTERN below) needs a look
	 * before the block-shape assertion can be trusted.
	 */
	public function testCustomDnsblRowSynthesisSiteCountMatchesKnownEnumeration(): void
	{
		$siteCount = preg_match_all("/'url'\\s*=>\\s*'custom'/", $this->pfblockerngSource());
		$this->assertSame(3, $siteCount,
			'expected exactly 3 custom-DNSBL row synthesis sites (issue #1323 enumeration) -- '
			. 'update this test\'s coverage matrix if a site was added or removed');
	}

	/**
	 * The actual pin: every one of those sites must hardcode 'state' =>
	 * 'Enabled' in the header/custom/state/url block. RED if any site drops,
	 * reorders past, or flips that literal (verified by temporarily flipping
	 * one site to 'Hold' in-session and observing this assertion fail).
	 */
	public function testEveryCustomDnsblRowSynthesisSiteHardcodesStateEnabled(): void
	{
		$matchCount = preg_match_all(self::SITE_BLOCK_PATTERN, $this->pfblockerngSource());
		$this->assertSame(3, $matchCount,
			"every custom-DNSBL row synthesis site must build 'header'/'custom'/'state'/'url' in that exact "
			. "order with 'state' hardcoded to 'Enabled' -- a mismatch means some site diverged (dropped, "
			. "reordered, or flipped the 'state' => 'Enabled' literal)");
	}

	/**
	 * Guard linkage: because 'state' is always 'Enabled' (pinned above), the
	 * real call-site expression $row['state'] == 'Hold' (pfblockerng.inc:17326)
	 * can never be TRUE for a custom row, so the pure guard
	 * pfb_dnsbl_hold_stale_rebuild_skip() -- called directly here, no
	 * refactoring needed -- can never fire its skip branch for one, regardless
	 * of the other two inputs.
	 */
	public function testCustomRowStateEnabledNeverTriggersHoldStaleRebuildSkip(): void
	{
		$customRow = ['header' => 'Some_custom', 'custom' => 'example.com', 'state' => 'Enabled', 'url' => 'custom'];
		$isHold = $customRow['state'] == 'Hold'; // exact call-site expression, pfblockerng.inc:17326
		$this->assertFalse($isHold, 'a synthesized custom row must never read as Hold');

		foreach ([TRUE, FALSE] as $staleGenerationRebuild) {
			foreach ([TRUE, FALSE] as $origExists) {
				$this->assertFalse(
					pfb_dnsbl_hold_stale_rebuild_skip($staleGenerationRebuild, $isHold, $origExists),
					"a custom row (state=Enabled) must never trigger the Hold-skip guard "
					. "(stale_rebuild={$staleGenerationRebuild}, orig_exists={$origExists})"
				);
			}
		}
	}
}
