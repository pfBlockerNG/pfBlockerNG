<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Render pins for pfb_feeds_render_predefined_type()'s per-row "feed status" icon
 * (issue #1330). url_compare() used to mutate `global $icon` directly from inside a
 * sibling function call -- a PHPStan blind spot the ESCALATE evidence comment on the
 * issue proved is NOT dead code: three `empty($icon)` guards downstream (:452, :460,
 * :489) rely on that mutation to skip re-assigning the icon once url_compare() has
 * already set the "feed exists" checkmark, so a feed already added to an alias keeps
 * its checkmark instead of getting clobbered by the "add feed" icon. This file pins
 * that behaviour byte-for-byte across the return-based refactor:
 *
 *   - existing feed, no alternates (guard :489)             -- checkmark, not add-icon
 *   - existing feed, with alternates, header pre-selected
 *     (guard :452, the in_array()+empty($icon) precedence)  -- checkmark, not add-icon
 *   - brand-new feed, no existing alias match (guard :489,
 *     empty-icon side)                                      -- add-icon, not checkmark
 *
 * pfblockerng_feeds.php carries top-level execution and cannot be require()d
 * off-appliance; see FeedsPredefinedTypeLoader.php for the eval-extraction mechanics
 * (same pattern as AlertsPageLoader.php).
 */
final class FeedsUrlCompareIconRenderTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/FeedsPredefinedTypeLoader.php';
		pfb_test_load_feeds_predefined_type_functions();
	}

	/** @param array<string, mixed> $extra */
	private function buildFeed(string $header, string $url, string $website, array $extra = []): array
	{
		return array_merge([
			'feed'     => $header,
			'website'  => $website,
			'url'      => $url,
			'header'   => $header,
			'register' => '',
		], $extra);
	}

	/**
	 * Seeds every global pfb_feeds_render_predefined_type()/url_compare() read
	 * (page-scope state normally set up by pfblockerng_feeds.php itself) and
	 * captures the rendered HTML for one $ftype/$info pair.
	 *
	 * @param array<string, mixed>   $info
	 * @param list<array<string, mixed>> $exFeedsForType
	 * @param list<string>           $feedAltSelected
	 */
	private function renderType(string $ftype, array $info, array $exFeedsForType, array $feedAltSelected = []): string
	{
		$GLOBALS['ex_feeds']          = [$ftype => $exFeedsForType];
		$GLOBALS['alt_feeds']         = [];
		$GLOBALS['fconfig']           = [];
		$GLOBALS['feed_alt_selected'] = $feedAltSelected;
		$GLOBALS['alt_selected']      = '';
		$GLOBALS['feed_info_row']     = 0;
		$GLOBALS['aliasname_found']   = [];

		ob_start();
		pfb_feeds_render_predefined_type($ftype, $info);
		return (string) ob_get_clean();
	}

	/**
	 * Isolates the rendered <tr> row whose HTML contains $needle, then returns the
	 * content of that row's LAST <td> -- the `<td><?=$icon;?></td>` cell (:593).
	 * The row's OTHER cells can also carry a "fa-solid fa-check" (the separate
	 * $status "Alias/Group exists" icon at :340), so scoping strictly to the last
	 * <td> is what makes the assertion sensitive to $icon specifically.
	 */
	private function iconCellForRow(string $html, string $needle): string
	{
		$this->assertNotFalse(
			preg_match_all('/<tr[^>]*>.*?<\/tr>/s', $html, $matches),
			'no <tr> rows found in rendered HTML'
		);
		foreach ($matches[0] as $row) {
			if (str_contains($row, $needle)) {
				$tdPos = strrpos($row, '<td>');
				$this->assertNotFalse($tdPos, 'icon <td> not found in matched row');
				$cell = substr($row, $tdPos + strlen('<td>'));
				return (string) preg_replace('/<\/td>\s*\z/', '', $cell);
			}
		}
		$this->fail("no rendered <tr> contains marker: {$needle}");
	}

	// Scenario 1 (ESCALATE evidence comment): a feed whose URL already matches an
	// existing alias row, no 'alternate' URLs configured -- guard :489.
	public function testExistingFeedNoAlternatesRendersCheckmarkNotAddIcon(): void
	{
		$url  = 'https://example.test/pin-no-alt/list.txt';
		$feed = $this->buildFeed('PinFeedNoAlt', $url, 'https://example.test/pin-no-alt/');
		$info = ['PinAlias1' => ['action' => 'permit', 'info' => 'Pin alias info', 'feeds' => [$feed]]];
		$exFeeds = [[
			'aliasname' => 'PinAlias1',
			'action'    => 'permit',
			'state'     => 'Enabled',
			'url'       => $url,
			'header'    => 'PinFeedNoAlt',
			'rowid'     => 101,
		]];

		$cell = $this->iconCellForRow($this->renderType('ipv4', $info, $exFeeds), $url);

		$this->assertStringContainsString('fa-solid fa-check', $cell, 'existing feed must render the checkmark icon');
		$this->assertStringNotContainsString('fa-solid fa-plus-circle', $cell, 'existing feed must NOT render the add icon');
	}

	// Scenario 2 (ESCALATE evidence comment): same as above, PLUS an 'alternate' URL
	// that also matches an existing row, with the primary header pre-selected in
	// $feed_alt_selected -- this forces in_array($feed['header'], $feed_alt_selected)
	// TRUE at :452, so only the `&& empty($icon)` term stops re-assignment. This is
	// the acceptance-criteria #3 precedence pin: drop that guard term and this
	// assertion fails (see the handoff's throwaway-mutation proof).
	public function testExistingFeedWithAlternatesSelectedRendersCheckmarkNotAddIcon(): void
	{
		$primaryUrl = 'https://example.test/pin-with-alt/list.txt';
		$altUrl     = 'https://alt.example.test/pin-with-alt-secondary.txt';
		$feed = $this->buildFeed('PinFeedWithAlt', $primaryUrl, 'https://example.test/pin-with-alt/', [
			'alternate' => [
				['url' => $altUrl, 'header' => 'PinFeedWithAltAlt'],
			],
		]);
		$info = ['PinAlias2' => ['action' => 'permit', 'info' => 'Pin alias info', 'feeds' => [$feed]]];
		$exFeeds = [
			[
				'aliasname' => 'PinAlias2',
				'action'    => 'permit',
				'state'     => 'Enabled',
				'url'       => $primaryUrl,
				'header'    => 'PinFeedWithAlt',
				'rowid'     => 201,
			],
			[
				'aliasname' => 'PinAlias2',
				'action'    => 'permit',
				'state'     => 'Enabled',
				'url'       => $altUrl,
				'header'    => 'PinFeedWithAltAlt',
				'rowid'     => 202,
			],
		];

		$html = $this->renderType('ipv4', $info, $exFeeds, ['PinFeedWithAlt']);
		$cell = $this->iconCellForRow($html, $primaryUrl);

		$this->assertStringContainsString('fa-solid fa-check', $cell, 'existing feed must render the checkmark icon');
		$this->assertStringNotContainsString(
			'fa-solid fa-plus-circle',
			$cell,
			'existing feed must NOT render the add icon even when its header is in feed_alt_selected'
		);
	}

	// Contrast case: a feed with no existing alias/row match at all renders the
	// "add feed" icon -- pins the OTHER side of the :489 guard (empty($icon) TRUE),
	// and that the refactored url_compare() call site does not clobber $icon with an
	// empty return value on a non-match.
	public function testNewFeedNoAlternatesRendersAddIcon(): void
	{
		$url  = 'https://example.test/pin-new/list.txt';
		$feed = $this->buildFeed('PinFeedNew', $url, 'https://example.test/pin-new/');
		$info = ['PinAlias3' => ['action' => 'permit', 'info' => 'Pin alias info', 'feeds' => [$feed]]];
		$exFeeds = [[
			'aliasname' => 'OtherAlias',
			'action'    => 'permit',
			'state'     => 'Enabled',
			'url'       => 'https://example.test/unrelated/other.txt',
			'header'    => 'OtherHeader',
			'rowid'     => 301,
		]];

		$cell = $this->iconCellForRow($this->renderType('ipv4', $info, $exFeeds), $url);

		$this->assertStringContainsString('fa-solid fa-plus-circle', $cell, 'a feed with no existing alias match must render the add icon');
		$this->assertStringNotContainsString('fa-solid fa-check', $cell, 'a feed with no existing alias match must NOT render the checkmark icon');
	}

	// Issue #1657 coverage-matrix row 5: url_compare()'s $a_key moved from
	// trailing (after $alternate/$alt_header/$alt_info/$alt_register) to just
	// before $alternate, so the required parameter no longer sits after four
	// optional ones. $a_key is the literal array key url_compare() stores an
	// alternate's match state under, at
	// $alt_feeds[$ftype][$aliasname][$feed_header][$a_key] (:272, :285) -- so
	// this pins the STORED KEY ITSELF, not just the rendered icon, which is
	// what makes it sensitive to a one-slot shift at the alternates call site
	// (:363-365) that the three render-pin tests above are not (proven by
	// mutation: swapping the $a_key/$alternate argument order there leaves all
	// three green, because $alternate silently receives $a_key's value (0,
	// int-falsy) instead of TRUE, which skips the alt_feeds store entirely
	// without touching the primary-URL row those tests inspect).
	//
	// A single alternate ($a_key === 0 from `foreach ($feed['alternate'] as
	// $a_key => $alt)` on a one-element array) that matches an existing row
	// must be stored under array key 0 specifically: if the reorder shifts
	// $a_key into $alternate's slot, $alternate becomes falsy and the whole
	// store is skipped -- array_key_exists(0, ...) then fails against a
	// missing parent array, not merely a wrong key.
	public function testAlternateMatchIsStoredUnderItsForeachKey(): void
	{
		$primaryUrl = 'https://example.test/pin-a-key/list.txt';
		$altUrl     = 'https://alt.example.test/pin-a-key-secondary.txt';
		$primaryHeader = 'PinFeedAKey';
		$feed = $this->buildFeed($primaryHeader, $primaryUrl, 'https://example.test/pin-a-key/', [
			'alternate' => [
				['url' => $altUrl, 'header' => 'PinFeedAKeyAlt'],
			],
		]);
		$info = ['PinAlias5' => ['action' => 'permit', 'info' => 'Pin alias info', 'feeds' => [$feed]]];
		$exFeeds = [[
			'aliasname' => 'PinAlias5',
			'action'    => 'permit',
			'state'     => 'Enabled',
			'url'       => $altUrl,
			'header'    => 'PinFeedAKeyAlt',
			'rowid'     => 501,
		]];

		$this->renderType('ipv4', $info, $exFeeds);

		$this->assertArrayHasKey('ipv4', $GLOBALS['alt_feeds']);
		$this->assertArrayHasKey('PinAlias5', $GLOBALS['alt_feeds']['ipv4']);
		$this->assertArrayHasKey($primaryHeader, $GLOBALS['alt_feeds']['ipv4']['PinAlias5']);
		$this->assertArrayHasKey(
			0,
			$GLOBALS['alt_feeds']['ipv4']['PinAlias5'][$primaryHeader],
			'the single alternate must be stored under its foreach key (0), the $a_key argument -- '
				. 'if $a_key landed in $alternate\'s call-site slot instead, $alternate would be falsy '
				. 'and this store would be skipped entirely'
		);
		$this->assertStringContainsString(
			'fa-solid fa-check',
			$GLOBALS['alt_feeds']['ipv4']['PinAlias5'][$primaryHeader][0]['icon'],
			'the stored alternate entry must carry the checkmark match icon'
		);
	}

	public function testNonContiguousAlternateBucketRendersEveryRowWithoutWarning(): void
	{
		$primaryUrl   = 'https://example.test/non-contiguous/primary.txt';
		$matchedUrl   = 'https://example.test/non-contiguous/matched.txt';
		$primaryHeader = 'NonContiguousPrimary';
		$feed = $this->buildFeed($primaryHeader, $primaryUrl, 'https://example.test/non-contiguous/', [
			'alternate' => [
				1 => ['url' => $matchedUrl, 'header' => 'FirstRenderedAlternate'],
				2 => ['url' => 'https://example.test/non-contiguous/later.txt', 'header' => 'SecondRenderedAlternate'],
			],
		]);
		$info = ['NonContiguousAlias' => [
			'action' => 'permit',
			'info'   => 'Non-contiguous alias info',
			'feeds'  => [$feed],
		]];
		$exFeeds = [
			[
				'aliasname' => 'NonContiguousAlias',
				'action'    => 'permit',
				'state'     => 'Enabled',
				'url'       => 'https://example.test/non-contiguous/later.txt',
				'header'    => 'SecondRenderedAlternate',
				'rowid'     => 602,
			],
			[
				'aliasname' => 'NonContiguousAlias',
				'action'    => 'permit',
				'state'     => 'Enabled',
				'url'       => $matchedUrl,
				'header'    => 'FirstRenderedAlternate',
				'rowid'     => 601,
			],
		];
		$diagnostics = [];
		set_error_handler(
			static function (int $errno, string $errstr) use (&$diagnostics): bool {
				$diagnostics[] = [$errno, $errstr];
				return TRUE;
			},
			E_ALL
		);
		try {
			$html = $this->renderType('ipv4', $info, $exFeeds);
		} finally {
			restore_error_handler();
		}

		$this->assertSame(
			[2, 1],
			array_keys($GLOBALS['alt_feeds']['ipv4']['NonContiguousAlias'][$primaryHeader]),
			'test setup must exercise a non-contiguous bucket inserted out of source order'
		);
		$undefinedKeyDiagnostics = array_values(array_filter(
			$diagnostics,
			static fn(array $diagnostic): bool => str_contains($diagnostic[1], 'Undefined array key')
		));
		$this->assertSame([], $undefinedKeyDiagnostics, var_export($diagnostics, TRUE));

		$firstRow  = strpos($html, 'value="alt_FirstRenderedAlternate"');
		$secondRow = strpos($html, 'value="alt_SecondRenderedAlternate"');
		$this->assertNotFalse($firstRow, 'first alternate row must render');
		$this->assertNotFalse($secondRow, 'second alternate row must render');
		$this->assertTrue(
			$firstRow < $secondRow,
			"alternate rows must preserve source order; positions: {$firstRow}, {$secondRow}"
		);
	}
}
