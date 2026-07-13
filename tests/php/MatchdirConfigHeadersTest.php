<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1250 — pin pfb_matchdir_config_headers(), the migration's header-set builder. It
 * mirrors sync_package_pfblockerng()'s own composition (Download/Collect: \W-stripped
 * "{header}{vtype}"; the '<alias>_custom' / DNSBLIP / GeoIP-continent synthetic rows) so the
 * install-time migration plan is fed the SAME names the disk actually contains — under- or
 * over-enumerating either set mis-routes a real machine artifact. Pure, brand-new function
 * (no pre-existing behaviour to pin — CLAUDE.md Test coverage #1 exception 2).
 *
 * Feature: matchdir migration config-header enumeration
 *   Given the raw pfblockernglistsv4/v6 config, the DNSBL settings section, and a map of
 *         continent alias -> its config section
 *   When  the helper walks every configured list/row + synthetic source
 *   Then  it returns the deny set, the match set, and the flattened real-row list the
 *         migration plan and stale-ref detector need.
 */
#[CoversFunction('pfb_matchdir_config_headers')]
final class MatchdirConfigHeadersTest extends TestCase
{
	/** One list config entry with a single row, minimal shape. */
	private function list(string $alias, string $action, string $header, string $url = '/x', string $rowState = 'Enabled', string $custom = ''): array
	{
		$list = array('aliasname' => $alias, 'action' => $action, 'row' => array(
			array('header' => $header, 'url' => $url, 'state' => $rowState),
		));
		if ($custom !== '') {
			$list['custom'] = $custom;
		}
		return $list;
	}

	/** H1: an enabled Deny list's row header lands in BOTH sets, and the row is collected. */
	public function testH1DenyListRowInBothSets(): void
	{
		$v4 = array($this->list('Spam', 'Deny', 'Spam'));
		$v6 = array($this->list('Spam', 'Deny', 'Spam'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4, '_v6' => $v6), [], []);

		$this->assertContains('Spam_v4', $out['deny']);
		$this->assertContains('Spam_v6', $out['deny']);
		$this->assertContains('Spam_v4', $out['match']);
		$this->assertContains('Spam_v6', $out['match']);
		$this->assertCount(2, $out['rows']);
	}

	/** H2: an enabled Match list's row header lands in the match set ONLY. */
	public function testH2MatchListRowInMatchSetOnly(): void
	{
		$v4 = array($this->list('Ads', 'Match', 'Ads'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('Ads_v4', $out['match']);
		$this->assertNotContains('Ads_v4', $out['deny']);
	}

	/** H3 / issue #1250 F3: a Disabled LIST's row still counts toward the match set (a stale user file must never adopt), but not deny. */
	public function testH3DisabledListRowInMatchSetOnlyRowsStillCollected(): void
	{
		$v4 = array($this->list('Spam', 'Disabled', 'Spam'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('Spam_v4', $out['match']);
		$this->assertNotContains('Spam_v4', $out['deny']);
		$this->assertCount(1, $out['rows']);
	}

	/** H4 / issue #1250 F3: a Disabled ROW inside an ENABLED Deny list still counts toward BOTH sets and is still collected. */
	public function testH4DisabledRowInsideEnabledDenyListStillCounted(): void
	{
		$v4 = array($this->list('Spam', 'Deny', 'Spam', '/x', 'Disabled'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('Spam_v4', $out['deny']);
		$this->assertContains('Spam_v4', $out['match']);
		$this->assertCount(1, $out['rows']);
	}

	/** H5: a header with punctuation is \W-stripped the SAME way sync_package_pfblockerng() strips it; the raw header survives in rows[]. */
	public function testH5PunctuatedHeaderIsNormalisedInSetsButRawInRows(): void
	{
		$v4 = array($this->list('DD', 'Deny', 'de-dup'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('dedup_v4', $out['deny']);
		$this->assertContains('dedup_v4', $out['match']);
		$this->assertSame('de-dup', $out['rows'][0]['header']);
	}

	/** H6: custom text on a Deny list lands the '<alias>_custom<vtype>' name in BOTH sets; a Match list's custom lands in match only. */
	public function testH6CustomTextRoutedByListAction(): void
	{
		$denyList = $this->list('Blk', 'Deny', 'Blk', '/x', 'Enabled', 'custom-text');
		$matchList = $this->list('Wht', 'Match', 'Wht', '/x', 'Enabled', 'custom-text');

		$out = pfb_matchdir_config_headers(array('_v4' => array($denyList, $matchList)), [], []);

		$this->assertContains('Blk_custom_v4', $out['deny']);
		$this->assertContains('Blk_custom_v4', $out['match']);
		$this->assertNotContains('Wht_custom_v4', $out['deny']);
		$this->assertContains('Wht_custom_v4', $out['match']);
	}

	/** H7 hostile: an aliasname with spaces/punctuation is \W-stripped before '_custom' is appended. */
	public function testH7PunctuatedAliasnameNormalisedBeforeCustomSuffix(): void
	{
		$list = $this->list('my alias!', 'Match', 'x', '/x', 'Enabled', 'custom-text');

		$out = pfb_matchdir_config_headers(array('_v4' => array($list)), [], []);

		$this->assertContains('myalias_custom_v4', $out['match']);
	}

	/** H8: the DNSBL IP-blocking action gates a synthetic 'DNSBLIP_v4'/'_v6' pair in the deny set. */
	public function testH8DnsblDenyActionAddsDnsblipBothFamilies(): void
	{
		$out = pfb_matchdir_config_headers([], array('action' => 'Deny_Both'), []);

		$this->assertContains('DNSBLIP_v4', $out['deny']);
		$this->assertContains('DNSBLIP_v6', $out['deny']);
	}

	/** H8 contrast: a non-Deny (or absent) DNSBL action adds nothing. */
	public function testH8DnsblNonDenyActionAddsNothing(): void
	{
		$this->assertSame([], pfb_matchdir_config_headers([], array('action' => 'Match_Both'), [])['deny']);
		$this->assertSame([], pfb_matchdir_config_headers([], [], [])['deny']);
	}

	/**
	 * H9: a continent whose config action contains 'Deny' adds its OWN alias, both families --
	 * exercised on two distinct fabricated aliases to prove the enumeration is caller-supplied,
	 * not a hardcoded 9-continent list inside the helper.
	 */
	public function testH9ContinentDenyActionAddsBothFamiliesForCallerSuppliedAliases(): void
	{
		$out = pfb_matchdir_config_headers([], [], array(
			'pfB_Africa' => array('action' => 'Deny'),
			'pfB_FakeContinent' => array('action' => 'Deny'),
		));

		$this->assertContains('pfB_Africa_v4', $out['deny']);
		$this->assertContains('pfB_Africa_v6', $out['deny']);
		$this->assertContains('pfB_FakeContinent_v4', $out['deny']);
		$this->assertContains('pfB_FakeContinent_v6', $out['deny']);
	}

	/** H9 contrast: Match / Disabled / empty continent config adds nothing for that alias. */
	public function testH9ContinentNonDenyActionAddsNothing(): void
	{
		$out = pfb_matchdir_config_headers([], [], array(
			'pfB_Europe' => array('action' => 'Match'),
			'pfB_Asia'   => array('action' => 'Disabled'),
			'pfB_Top'    => [],
		));

		$this->assertSame([], $out['deny']);
	}

	/** H10 hostile: a normalised-empty header ('!!!' strips to '') contributes to NEITHER set, even though the row (url present) is still collected. */
	public function testH10EmptyNormalisedHeaderContributesToNeitherSet(): void
	{
		$v4 = array($this->list('X', 'Deny', '!!!'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertSame([], $out['deny'], 'an empty-header row must never widen the deny set to a bare "_v4"');
		$this->assertSame([], $out['match'], 'an empty-header row must never widen the match set to a bare "_v4"');
		$this->assertCount(1, $out['rows']);
	}

	/** H11: a row with no url at all is never added to rows[], but its header still counts toward the sets. */
	public function testH11RowWithoutUrlSkipsRowsButStillCountsHeader(): void
	{
		$v4 = array($this->list('X', 'Deny', 'Spam', ''));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertSame([], $out['rows']);
		$this->assertContains('Spam_v4', $out['deny']);
		$this->assertContains('Spam_v4', $out['match']);
	}

	/** H12: nothing configured anywhere -> a fully empty result on all three keys. */
	public function testH12EmptyInputYieldsEmptyResult(): void
	{
		$out = pfb_matchdir_config_headers([], [], []);

		$this->assertSame(array('deny' => [], 'match' => [], 'rows' => []), $out);
	}
}
