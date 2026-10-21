<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3539 — the DNSBL VIP/webserver is only needed while some effective DNSBL block still
 * answers with it (mechanism 'enabled'). One predicate decides that from the raw DNSBL settings,
 * the raw DNSBL groups and the raw Blacklist section; every mechanism it consults is resolved
 * through the existing policy resolver, so Default/Override behave exactly as in the apply.
 */
#[CoversFunction('pfb_dnsbl_vip_demand')]
#[CoversFunction('pfb_dnsbl_blacklist_logging')]
final class DnsblVipDemandTest extends TestCase
{
	private const NON_VIP_MECHANISMS = ['disabled_log', 'disabled', 'nxdomain_log', 'nxdomain', 'nodata_log', 'nodata'];

	/** Current (post-migration) policy section. */
	private static function policy(string $mode, string $mechanism, array $extra = []): array
	{
		return ['global_log_mode' => $mode, 'global_log' => $mechanism] + $extra;
	}

	/** A DNSBL group the apply loop would process as deny; $over replaces any key. */
	private static function group(mixed $logging, array $over = []): array
	{
		return array_replace([
			'aliasname' => 'G1',
			'action'    => 'unbound',
			'logging'   => $logging,
			'row'       => [['url' => 'https://example.com/list.txt', 'state' => 'Enabled', 'header' => 'G1_a', 'format' => 'auto']],
		], $over);
	}

	/** An enabled Blacklist category the apply builds a list from: shalla is selected and its item carries a category selection. */
	private static function blacklist(array $over = []): array
	{
		return array_replace([
			'blacklist_enable'   => 'Enable',
			'blacklist_selected' => 'shalla',
			'item'               => [['xml' => 'shalla', 'title' => 'Shalla', 'selected' => 'adult,gambling']],
		], $over);
	}

	// -----------------------------------------------------------------------
	// 1 - groups
	// -----------------------------------------------------------------------

	public function testNoConfigurationAtAllHasNoDemand(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand([], [], []));
	}

	public function testUnboundGroupWithFeedRowAndEffectiveEnabledDemandsVip(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log'), [self::group('enabled')], []));
	}

	#[DataProvider('nonVipMechanismProvider')]
	public function testEveryNonVipMechanismHasNoDemand(string $mechanism): void
	{
		// Global 'enabled' proves the group's own explicit mechanism wins over the global one.
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group($mechanism)], []));
	}

	/** @return array<string,array{0:string}> */
	public static function nonVipMechanismProvider(): array
	{
		return array_combine(self::NON_VIP_MECHANISMS, array_map(static fn(string $m): array => [$m], self::NON_VIP_MECHANISMS));
	}

	public function testDisabledGroupHasNoDemand(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('enabled', ['action' => 'Disabled'])], []));
	}

	#[DataProvider('invalidActionProvider')]
	public function testJunkOrAbsentActionHasNoDemand(mixed $action): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('enabled', ['action' => $action])], []));
	}

	/** @return array<string,array{0:mixed}> NULL reads exactly like an absent key. */
	public static function invalidActionProvider(): array
	{
		return [
			'absent'          => [NULL],
			'empty string'    => [''],
			'IP-style action' => ['Deny_Inbound'],
			'case variant'    => ['Unbound'],
			'array'           => [['unbound']],
		];
	}

	public function testGroupWithoutRowsOrCustomListHasNoDemand(): void
	{
		$policy = self::policy('default', 'enabled');
		$absent = self::group('enabled');
		unset($absent['row']);

		$this->assertFalse(pfb_dnsbl_vip_demand($policy, [$absent], []), 'no row key at all');
		$this->assertFalse(pfb_dnsbl_vip_demand($policy, [self::group('enabled', ['row' => []])], []), 'empty row list');
	}

	public function testOnlyDisabledRowsHaveNoDemand(): void
	{
		$row = ['url' => 'https://example.com/list.txt', 'state' => 'Disabled', 'header' => 'G1_a'];
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('enabled', ['row' => [$row]])], []));
	}

	public function testOnlyEmptyUrlRowsHaveNoDemand(): void
	{
		$row = ['url' => '', 'state' => 'Enabled', 'header' => ''];
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('enabled', ['row' => [$row]])], []));
	}

	public function testFeedDemandRequiresTheHeaderTheApplyCanConsumeAfterNormalization(): void
	{
		$policy = self::policy('default', 'enabled');
		foreach ([NULL, '', '!!!'] as $header) {
			$row = ['url' => 'https://example.com/list.txt', 'state' => 'Enabled'];
			if ($header !== NULL) {
				$row['header'] = $header;
			}
			$this->assertFalse(pfb_dnsbl_vip_demand($policy, [self::group('enabled', ['row' => [$row]])], []), 'unusable header: ' . json_encode($header));
		}
		$group = self::group('enabled', ['aliasname' => '!!!']);
		$group['row'][0]['header'] = 'G1-a!';
		$this->assertTrue(pfb_dnsbl_vip_demand($policy, [$group], []), 'the apply normalizes the header to G1a and the alias to an empty suffix of DNSBL_');
	}

	public function testTldBlacklistDemandRequiresAnEntryAfterCanonicalCommentDecoding(): void
	{
		foreach (["# ignored\n", " \n\t\n", "example # real TLD\n"] as $text) {
			$policy = self::policy('default', 'enabled', ['tld_wildcard' => 'on', 'tld_wildcard_blacklist' => base64_encode($text)]);
			$this->assertSame(str_starts_with($text, 'example'), pfb_dnsbl_vip_demand($policy, [], []), 'TLD text: ' . json_encode($text));
		}
	}

	public function testOnlyPermitRowsHaveNoDemand(): void
	{
		$permit = ['url' => 'https://example.com/allow.txt', 'state' => 'Enabled', 'header' => 'G1_p', 'action' => 'Permit'];
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('enabled', ['row' => [$permit]])], []));
	}

	public function testOneDenyRowAmongPermitRowsDemandsVip(): void
	{
		$permit = ['url' => 'https://example.com/allow.txt', 'state' => 'Enabled', 'header' => 'G1_p', 'action' => 'Permit'];
		$deny   = ['url' => 'https://example.com/deny.txt', 'state' => 'Enabled', 'header' => 'G1_d', 'action' => 'Deny'];
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('enabled', ['row' => [$permit, $deny]])], []));
	}

	public function testCustomListAloneDemandsVip(): void
	{
		$policy = self::policy('default', 'enabled');
		$bare   = self::group('enabled', ['custom' => 'ZXhhbXBsZS5jb20K']);
		unset($bare['row']);

		$this->assertTrue(pfb_dnsbl_vip_demand($policy, [$bare], []), 'custom list, no row key');

		$placeholder = self::group('enabled', ['custom' => 'ZXhhbXBsZS5jb20K', 'row' => [['url' => '', 'state' => 'Enabled', 'header' => '']]]);
		$this->assertTrue(pfb_dnsbl_vip_demand($policy, [$placeholder], []), 'custom list beside the blank placeholder row the editor saves');
	}

	public function testFirstRowWithoutUrlDropsEveryRowLikeTheApply(): void
	{
		// The apply loop discards the whole row list when row[0] has no url, so a later deny row never runs.
		$blank = ['url' => '', 'state' => 'Enabled', 'header' => ''];
		$deny  = ['url' => 'https://example.com/deny.txt', 'state' => 'Enabled', 'header' => 'G1_d'];
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('enabled', ['row' => [$blank, $deny]])], []));
	}

	public function testNonArrayGroupEntriesAreIgnored(): void
	{
		$policy = self::policy('default', 'enabled');

		$this->assertFalse(pfb_dnsbl_vip_demand($policy, ['junk', 5, NULL], []), 'only junk entries');
		$this->assertTrue(pfb_dnsbl_vip_demand($policy, ['junk', self::group('enabled')], []), 'junk beside a qualifying group');
	}

	// -----------------------------------------------------------------------
	// 2 - Default / Override policy and legacy markers
	// -----------------------------------------------------------------------

	public function testDefaultGroupInheritsGlobalEnabled(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('default')], []));
	}

	public function testDefaultGroupInheritsGlobalNonVip(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log'), [self::group('default')], []));
	}

	public function testExplicitEnabledGroupBeatsDefaultGlobalNonVip(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log'), [self::group('enabled')], []));
	}

	public function testOverrideGlobalNonVipBeatsExplicitEnabledGroup(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('override', 'disabled_log'), [self::group('enabled')], []));
	}

	public function testOverrideGlobalEnabledBeatsExplicitNonVipGroup(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('override', 'enabled'), [self::group('disabled_log')], []));
	}

	#[DataProvider('vipMarkerProvider')]
	public function testLegacyEmptyOrAbsentGroupLoggingIsTheVipMarker(mixed $logging): void
	{
		// Legacy policy: no global_log_mode and an empty global_log (no override).
		$this->assertTrue(pfb_dnsbl_vip_demand(['global_log' => ''], [self::group($logging)], []));
	}

	#[DataProvider('vipMarkerProvider')]
	public function testCurrentPolicyEmptyOrAbsentGroupLoggingIsTheHistoricalVipMarker(mixed $logging): void
	{
		// Even under a non-VIP global mechanism: the marker predates Default/Override.
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log'), [self::group($logging)], []));
	}

	/** @return array<string,array{0:mixed}> NULL reads exactly like an absent key. */
	public static function vipMarkerProvider(): array
	{
		return ['empty string' => [''], 'absent' => [NULL]];
	}

	public function testJunkGroupTokenFailsSafeToNoDemand(): void
	{
		// Global 'enabled' proves a junk token neither inherits the global mechanism nor means VIP.
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [self::group('bogus')], []));
	}

	// -----------------------------------------------------------------------
	// 3 - Blacklist category
	// -----------------------------------------------------------------------

	public function testBlacklistLoggingProjectionAbsentIsDefaultAndEmptyStaysTheVipMarker(): void
	{
		$this->assertSame('default', pfb_dnsbl_blacklist_logging([]));
		$this->assertSame('default', pfb_dnsbl_blacklist_logging(['blacklist_enable' => 'Enable']));
		$this->assertSame('', pfb_dnsbl_blacklist_logging(['blacklist_logging' => '']));
		$this->assertSame('enabled', pfb_dnsbl_blacklist_logging(['blacklist_logging' => 'enabled']));
		$this->assertSame('disabled', pfb_dnsbl_blacklist_logging(['blacklist_logging' => 'disabled']));
	}

	public function testApplyBuildsTheBlacklistListLoggingThroughTheProjection(): void
	{
		// The apply loop is too large to drive here; pin its single Blacklist projection call site.
		$src = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');

		$this->assertStringContainsString("\$list['logging']\t= pfb_dnsbl_blacklist_logging(\$pfb['blconfig']);", $src);
		$this->assertStringNotContainsString("blacklist_logging'] ?: 'enabled'", $src, 'the old falsy fallback made an absent value the VIP');
	}

	public function testExplicitEnabledBlacklistDemandsVipEvenUnderDefaultGlobalNonVip(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log'), [], self::blacklist(['blacklist_logging' => 'enabled'])));
	}

	public function testAbsentBlacklistLoggingInheritsTheGlobalMechanism(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log'), [], self::blacklist()), 'global disabled_log');
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [], self::blacklist()), 'global enabled');
	}

	public function testEmptyBlacklistLoggingIsTheLegacyVipMarker(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log'), [], self::blacklist(['blacklist_logging' => ''])));
	}

	public function testDisabledBlacklistLoggingHasNoDemand(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [], self::blacklist(['blacklist_logging' => 'disabled'])));
	}

	public function testJunkBlacklistLoggingFailsSafeToNoDemand(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [], self::blacklist(['blacklist_logging' => 'bogus'])));
	}

	public function testDefaultBlacklistLoggingFollowsOverrideGlobalEnabled(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('override', 'enabled'), [], self::blacklist(['blacklist_logging' => 'default'])));
	}

	public function testOverrideGlobalNonVipBeatsExplicitEnabledBlacklist(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('override', 'disabled_log'), [], self::blacklist(['blacklist_logging' => 'enabled'])));
	}

	#[DataProvider('inactiveBlacklistProvider')]
	public function testInactiveBlacklistHasNoDemand(array $over): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled'), [], self::blacklist($over + ['blacklist_logging' => 'enabled'])));
	}

	/** @return array<string,array{0:array<string,string>}> */
	public static function inactiveBlacklistProvider(): array
	{
		return [
			'blacklist disabled'     => [['blacklist_enable' => 'Disable']],
			'nothing selected'       => [['blacklist_selected' => '']],
			'selected, no item'      => [['item' => []]],
			'item without selection' => [['item' => [['xml' => 'shalla', 'title' => 'Shalla', 'selected' => '']]]],
			'selection of only empty categories' => [['item' => [['xml' => 'shalla', 'title' => 'Shalla', 'selected' => ',,0']]]],
			'item not in blacklist_selected' => [['item' => [['xml' => 'ut1', 'title' => 'UT1', 'selected' => 'adult']]]],
		];
	}

	public function testAbsentOrEmptyBlacklistEnableCountsAsEnabledLikeTheApply(): void
	{
		// The apply gates on `blacklist_enable != 'Disable'`: only an explicit 'Disable' switches the category off.
		$policy = self::policy('default', 'disabled_log');
		$absent = self::blacklist(['blacklist_logging' => 'enabled']);
		unset($absent['blacklist_enable']);

		$this->assertTrue(pfb_dnsbl_vip_demand($policy, [], $absent), 'absent blacklist_enable');
		$this->assertTrue(pfb_dnsbl_vip_demand($policy, [], $absent + ['blacklist_enable' => '']), 'empty blacklist_enable');
		$this->assertFalse(pfb_dnsbl_vip_demand($policy, [], $absent + ['blacklist_enable' => 'Disable']), 'explicit Disable');
	}

	public function testBlacklistSelectedCategoryWithoutAnItemRowHasNoDemand(): void
	{
		// The apply builds a Blacklist list only from an `item` row; a selected category alone builds none.
		$policy = self::policy('default', 'enabled');
		$bare   = ['blacklist_enable' => 'Enable', 'blacklist_selected' => 'shalla', 'blacklist_logging' => 'enabled'];

		$this->assertFalse(pfb_dnsbl_vip_demand($policy, [], $bare), 'no item key');
		$this->assertTrue(pfb_dnsbl_vip_demand($policy, [], self::blacklist(['blacklist_logging' => 'enabled'])), 'the same category with its item row');
	}

	public function testBlacklistItemWithAnEmptySelectionHasNoDemand(): void
	{
		$policy = self::policy('default', 'enabled');
		$item   = ['xml' => 'shalla', 'title' => 'Shalla', 'selected' => ''];

		$this->assertFalse(pfb_dnsbl_vip_demand($policy, [], self::blacklist(['item' => [$item], 'blacklist_logging' => 'enabled'])));
		$this->assertTrue(pfb_dnsbl_vip_demand($policy, [], self::blacklist(['item' => [['selected' => 'adult'] + $item], 'blacklist_logging' => 'enabled'])), 'the same item with a selection');
	}

	// -----------------------------------------------------------------------
	// 4 - built-in blocks (regex, IDN, TLD Allow, TLD Blacklist) resolve to the global mechanism
	// -----------------------------------------------------------------------

	/** @return array<string,array{0:array<string,string>,1:bool}> built-in fields => demand at global 'enabled' */
	public static function builtinProvider(): array
	{
		return [
			'regex on, list'            => [['pfb_regex' => 'on', 'pfb_regex_list' => 'cmVnZXgK'], TRUE],
			'regex on, empty list'      => [['pfb_regex' => 'on', 'pfb_regex_list' => ''], FALSE],
			'regex on, absent list'     => [['pfb_regex' => 'on'], FALSE],
			'regex off, list'           => [['pfb_regex' => '', 'pfb_regex_list' => 'cmVnZXgK'], FALSE],
			'idn all'                   => [['pfb_idn' => 'on'], TRUE],
			'idn confusable'            => [['pfb_idn' => 'confusable'], TRUE],
			'idn off token'             => [['pfb_idn' => 'off'], FALSE],
			'idn empty'                 => [['pfb_idn' => ''], FALSE],
			'idn absent'                => [[], FALSE],
			'tld allow on, gtld'        => [['tld_allow' => 'on', 'tld_allow_gtld' => 'com'], TRUE],
			'tld allow on, cctld'       => [['tld_allow' => 'on', 'tld_allow_cctld' => 'uk'], TRUE],
			'tld allow on, itld'        => [['tld_allow' => 'on', 'tld_allow_itld' => 'xn--p1ai'], TRUE],
			'tld allow on, bgtld'       => [['tld_allow' => 'on', 'tld_allow_bgtld' => 'app'], TRUE],
			'tld allow on, no buckets'  => [['tld_allow' => 'on'], FALSE],
			'tld allow off, bucket'     => [['tld_allow' => '', 'tld_allow_gtld' => 'com'], FALSE],
			'tld wildcard, blacklist'   => [['tld_wildcard' => 'on', 'tld_wildcard_blacklist' => 'Y29tCg=='], TRUE],
			'tld wildcard, empty list'  => [['tld_wildcard' => 'on', 'tld_wildcard_blacklist' => ''], FALSE],
			'tld wildcard off, list'    => [['tld_wildcard' => '', 'tld_wildcard_blacklist' => 'Y29tCg=='], FALSE],
		];
	}

	/** @param array<string,string> $fields */
	#[DataProvider('builtinProvider')]
	public function testBuiltinDemandUnderGlobalEnabled(array $fields, bool $expected): void
	{
		$this->assertSame($expected, pfb_dnsbl_vip_demand(self::policy('default', 'enabled', $fields), [], []));
	}

	/** @param array<string,string> $fields */
	#[DataProvider('builtinDemandProvider')]
	public function testBuiltinNeverDemandsUnderANonVipGlobal(array $fields): void
	{
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'disabled_log', $fields), [], []));
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('override', 'nxdomain', $fields), [], []));
	}

	/** @return array<string,array{0:array<string,string>}> the built-in configurations that demand the VIP at global 'enabled' */
	public static function builtinDemandProvider(): array
	{
		$demanding = array_filter(self::builtinProvider(), static fn(array $case): bool => $case[1]);
		return array_map(static fn(array $case): array => [$case[0]], $demanding);
	}

	public function testBuiltinDemandFollowsOverrideGlobalEnabled(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('override', 'enabled', ['tld_allow' => 'on', 'tld_allow_gtld' => 'com']), [], []));
	}

	public function testHstsNeverChangesTheResult(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_demand(self::policy('default', 'enabled', ['pfb_hsts' => 'on', 'tld_allow' => 'on', 'tld_allow_gtld' => 'com']), [], []), 'HSTS on does not remove demand');
		$this->assertFalse(pfb_dnsbl_vip_demand(self::policy('default', 'enabled', ['pfb_hsts' => 'on']), [], []), 'HSTS on does not create demand');
	}
}
