<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1323 -- pins the invariant pfb_dnsbl_hold_stale_rebuild_skip()'s
 * safety rests on: a synthesized custom-DNSBL row can never be Hold. The
 * guard's single call site ($row['state'] == 'Hold' paired with
 * pfb_dnsbl_hold_stale_rebuild_skip(), pfblockerng_apply.inc ~:1377) consumes
 * rows built by ONE synthesis site: the DNSBL download loop's $lists
 * (~:1256). The other two custom-row sites never reach it -- ~:501 feeds
 * a per-type normalization pass whose $lists is discarded after use, and
 * ~:2682 feeds the separate IP-alias download loop -- and are pinned as
 * defense-in-depth: every custom-row literal in the file keeps the same
 * hardcoded-Enabled shape. All three live inside sync_package_pfblockerng(),
 * which has no PHPUnit harness (issue #993, confirmed by
 * DnsblStagingGenerationGuardTest's docblock), so this is a
 * source-inspection pin (last resort per CLAUDE.md, mirrors
 * PfbSyncStatusDnsblWritersTest's
 * testDnsblDownloadCallSitesKeyOnTheAliasNotTheHeader) -- a future edit
 * that flips any synthesis site away from hardcoded Enabled must fail this
 * test.
 */
#[CoversFunction('pfb_dnsbl_hold_stale_rebuild_skip')]
final class DnsblCustomRowStateEnabledInvariantTest extends TestCase
{
	private function pfblockerngSource(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertNotFalse($source, 'pfblockerng_apply.inc must be readable');
		return $source;
	}

	/**
	 * Every synthesis site builds the row as one array-literal block, in the
	 * SAME key order: header, custom, state, url. Matching that exact block
	 * (not just a bare 'state' => 'Enabled' anywhere near 'url' => 'custom')
	 * means a reordered/dropped 'state' key fails this regex even if some
	 * other 'state' => 'Enabled' happens to sit nearby in the file. Known
	 * brittleness, accepted for a source pin: a comment inserted between the
	 * keys also fails the match (keep the block contiguous or update this
	 * pattern), and a NEW site built in a different shape (helper call,
	 * per-key assignments) evades both this pattern and the count tripwire.
	 */
	private const SITE_BLOCK_PATTERN = "/'header'\\s*=>\\s*\"\\{\\\$list\\['aliasname'\\]\\}_custom\",\\s*"
		. "'custom'\\s*=>\\s*\\\$list\\['custom'\\],\\s*"
		. "'state'\\s*=>\\s*'Enabled',\\s*"
		. "'url'\\s*=>\\s*'custom'/";

	/** 1-based line numbers of every $pattern match, for failure diagnostics. */
	private function matchLines(string $pattern): array
	{
		$source = $this->pfblockerngSource();
		preg_match_all($pattern, $source, $matches, PREG_OFFSET_CAPTURE);
		return array_map(
			static fn(array $hit): int => substr_count($source, "\n", 0, $hit[1]) + 1,
			$matches[0]
		);
	}

	/**
	 * Site-count tripwire: issue #1323 (re-derived by grepping the tree this
	 * session) enumerates exactly 3 synthesis sites (~pfblockerng_apply.inc:501,
	 * 1256, 2682). A different count means a site was added or removed --
	 * this test's coverage matrix (and SITE_BLOCK_PATTERN below) needs a look
	 * before the block-shape assertion can be trusted.
	 */
	public function testCustomDnsblRowSynthesisSiteCountMatchesKnownEnumeration(): void
	{
		$lines = $this->matchLines("/'url'\\s*=>\\s*'custom'/");
		$this->assertCount(3, $lines,
			'expected exactly 3 custom-DNSBL row synthesis sites (issue #1323 enumeration), '
			. 'found matches at pfblockerng_apply.inc lines [' . implode(', ', $lines) . '] -- '
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
		$lines = $this->matchLines(self::SITE_BLOCK_PATTERN);
		$this->assertCount(3, $lines,
			"every custom-DNSBL row synthesis site must build 'header'/'custom'/'state'/'url' in that exact "
			. "order with 'state' hardcoded to 'Enabled'; Enabled-shaped blocks found at pfblockerng_apply.inc "
			. 'lines [' . implode(', ', $lines) . '] -- the site missing from that list diverged (dropped, '
			. "reordered, or flipped the 'state' => 'Enabled' literal)");
	}

	/**
	 * Guard linkage: because 'state' is always 'Enabled' (pinned above), the
	 * real call-site expression $row['state'] == 'Hold' (pfblockerng_apply.inc:1377)
	 * can never be TRUE for a custom row, so the pure guard
	 * pfb_dnsbl_hold_stale_rebuild_skip() -- called directly here, no
	 * refactoring needed -- can never fire its skip branch for one, regardless
	 * of the other two inputs.
	 */
	public function testCustomRowStateEnabledNeverTriggersHoldStaleRebuildSkip(): void
	{
		$customRow = ['header' => 'Some_custom', 'custom' => 'example.com', 'state' => 'Enabled', 'url' => 'custom'];
		$isHold = $customRow['state'] == 'Hold'; // exact call-site expression, pfblockerng_apply.inc:1377
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
