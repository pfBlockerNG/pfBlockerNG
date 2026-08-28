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
	private function list(string $alias, mixed $action, string $header, string $url = '/x', string $rowState = 'Enabled', string $custom = ''): array
	{
		$list = array('aliasname' => $alias, 'action' => $action, 'row' => array(
			array('header' => $header, 'url' => $url, 'state' => $rowState),
		));
		if ($custom !== '') {
			$list['custom'] = $custom;
		}
		return $list;
	}

	/** Run the helper with every PHP diagnostic promoted into an assertion failure. */
	private function headersWithoutDiagnostics(array $lists, array $dnsbl, array $continents): array
	{
		$diagnostics = array();
		set_error_handler(static function (int $severity, string $message) use (&$diagnostics): bool {
			$diagnostics[] = "{$severity}:{$message}";
			return TRUE;
		});
		try {
			$out = pfb_matchdir_config_headers($lists, $dnsbl, $continents);
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $diagnostics, 'action classification must emit no diagnostics');
		return $out;
	}

	/** H1: an enabled Deny list's row header lands in BOTH sets, and the row is collected. */
	public function testH1DenyListRowInBothSets(): void
	{
		$v4 = array($this->list('Spam', 'Deny_Both', 'Spam'));
		$v6 = array($this->list('Spam', 'Deny_Both', 'Spam'));

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
		$v4 = array($this->list('Ads', 'Match_Both', 'Ads'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('Ads_v4', $out['match']);
		$this->assertNotContains('Ads_v4', $out['deny']);
	}

	/** H3 / issue #1250: a Disabled LIST's row still counts toward the match set (a stale user file must never adopt), but not deny. */
	public function testH3DisabledListRowInMatchSetOnlyRowsStillCollected(): void
	{
		$v4 = array($this->list('Spam', 'Disabled', 'Spam'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('Spam_v4', $out['match']);
		$this->assertNotContains('Spam_v4', $out['deny']);
		$this->assertCount(1, $out['rows']);
	}

	/** H4 / issue #1250: a Disabled ROW inside an ENABLED Deny list still counts toward BOTH sets and is still collected. */
	public function testH4DisabledRowInsideEnabledDenyListStillCounted(): void
	{
		$v4 = array($this->list('Spam', 'Deny_Both', 'Spam', '/x', 'Disabled'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('Spam_v4', $out['deny']);
		$this->assertContains('Spam_v4', $out['match']);
		$this->assertCount(1, $out['rows']);
	}

	/** H5: a header with punctuation is \W-stripped the SAME way sync_package_pfblockerng() strips it; the raw header survives in rows[]. */
	public function testH5PunctuatedHeaderIsNormalisedInSetsButRawInRows(): void
	{
		$v4 = array($this->list('DD', 'Deny_Both', 'de-dup'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertContains('dedup_v4', $out['deny']);
		$this->assertContains('dedup_v4', $out['match']);
		$this->assertSame('de-dup', $out['rows'][0]['header']);
	}

	/** H6: custom text on a Deny list lands the '<alias>_custom<vtype>' name in BOTH sets; a Match list's custom lands in match only. */
	public function testH6CustomTextRoutedByListAction(): void
	{
		$denyList = $this->list('Blk', 'Deny_Both', 'Blk', '/x', 'Enabled', 'custom-text');
		$matchList = $this->list('Wht', 'Match_Both', 'Wht', '/x', 'Enabled', 'custom-text');

		$out = pfb_matchdir_config_headers(array('_v4' => array($denyList, $matchList)), [], []);

		$this->assertContains('Blk_custom_v4', $out['deny']);
		$this->assertContains('Blk_custom_v4', $out['match']);
		$this->assertNotContains('Wht_custom_v4', $out['deny']);
		$this->assertContains('Wht_custom_v4', $out['match']);
	}

	/** H7 hostile: an aliasname with spaces/punctuation is \W-stripped before '_custom' is appended. */
	public function testH7PunctuatedAliasnameNormalisedBeforeCustomSuffix(): void
	{
		$list = $this->list('my alias!', 'Match_Both', 'x', '/x', 'Enabled', 'custom-text');

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
			'pfB_Africa' => array('action' => 'Deny_Both'),
			'pfB_FakeContinent' => array('action' => 'Deny_Both'),
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
			'pfB_Europe' => array('action' => 'Match_Both'),
			'pfB_Asia'   => array('action' => 'Disabled'),
			'pfB_Top'    => [],
		));

		$this->assertSame([], $out['deny']);
	}

	/** H10 hostile: a normalised-empty header ('!!!' strips to '') contributes to NEITHER set, even though the row (url present) is still collected. */
	public function testH10EmptyNormalisedHeaderContributesToNeitherSet(): void
	{
		$v4 = array($this->list('X', 'Deny_Both', '!!!'));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertSame([], $out['deny'], 'an empty-header row must never widen the deny set to a bare "_v4"');
		$this->assertSame([], $out['match'], 'an empty-header row must never widen the match set to a bare "_v4"');
		$this->assertCount(1, $out['rows']);
	}

	/** H11: a row with no url at all is never added to rows[], but its header still counts toward the sets. */
	public function testH11RowWithoutUrlSkipsRowsButStillCountsHeader(): void
	{
		$v4 = array($this->list('X', 'Deny_Both', 'Spam', ''));

		$out = pfb_matchdir_config_headers(array('_v4' => $v4), [], []);

		$this->assertSame([], $out['rows']);
		$this->assertContains('Spam_v4', $out['deny']);
		$this->assertContains('Spam_v4', $out['match']);
	}

	/** Every exact IP action is accepted; only the four Deny-class actions enter deny sets. */
	public function testExactIpActionDomainClassifiesAllThreeMigrationSources(): void
	{
		$denyActions = array('Deny_Inbound', 'Deny_Outbound', 'Deny_Both', 'Alias_Deny');
		$actions = array(
			'Disabled',
			'Deny_Inbound', 'Deny_Outbound', 'Deny_Both',
			'Permit_Inbound', 'Permit_Outbound', 'Permit_Both',
			'Match_Inbound', 'Match_Outbound', 'Match_Both',
			'Alias_Deny', 'Alias_Permit', 'Alias_Match', 'Alias_Native',
		);
		$allDenyHeaders = array(
			'List_custom_v4', 'List_v4',
			'DNSBLIP_v4', 'DNSBLIP_v6',
			'pfB_Continent_v4', 'pfB_Continent_v6',
		);

		foreach ($actions as $action) {
			$out = $this->headersWithoutDiagnostics(
				array('_v4' => array($this->list('List', $action, 'List', '/x', 'Enabled', 'custom'))),
				array('action' => $action),
				array('pfB_Continent' => array('action' => $action))
			);

			$this->assertSame(in_array($action, $denyActions, TRUE) ? $allDenyHeaders : [], $out['deny'], $action);
			$this->assertSame(array('List_custom_v4', 'List_v4'), $out['match'], $action);
			$this->assertSame(array(array('list' => 'List', 'header' => 'List', 'url' => '/x')), $out['rows'], $action);
		}
	}

	/** Malformed, non-string, and cross-domain actions fail closed without warnings. */
	public function testHostileActionsNeverEnterAnyDenySet(): void
	{
		$actions = array(
			'Deny', 'Match', 'Deny_malformed', 'unbound',
			'deny_both', 'Deny_both', ' Deny_Both', 'Deny_Both ',
			'', '0', 0, NULL, FALSE, TRUE, array('Deny_Both'),
		);

		$observed = array('cases' => array(), 'diagnostics' => array());
		$expected = array('cases' => array(), 'diagnostics' => array());
		set_error_handler(static function (int $severity, string $message) use (&$observed): bool {
			$observed['diagnostics'][] = "{$severity}:{$message}";
			return TRUE;
		});
		try {
			foreach ($actions as $action) {
				$label = var_export($action, TRUE);
				$observed['cases'][$label] = pfb_matchdir_config_headers(
					array('_v4' => array($this->list('List', $action, 'List', '/x', 'Enabled', 'custom'))),
					array('action' => $action),
					array('pfB_Continent' => array('action' => $action))
				);
				$expected['cases'][$label] = array(
					'deny' => array(),
					'match' => array('List_custom_v4', 'List_v4'),
					'rows' => array(array('list' => 'List', 'header' => 'List', 'url' => '/x')),
				);
			}
		} finally {
			restore_error_handler();
		}

		$this->assertSame($expected, $observed);
	}

	/** H12: nothing configured anywhere -> a fully empty result on all three keys. */
	public function testH12EmptyInputYieldsEmptyResult(): void
	{
		$out = pfb_matchdir_config_headers([], [], []);

		$this->assertSame(array('deny' => [], 'match' => [], 'rows' => []), $out);
	}
}
