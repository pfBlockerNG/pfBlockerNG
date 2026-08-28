<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1921 (S2) — pfb_registry_pass(): the one registry-driven install/upgrade pass
 * that replaces the seeding pass, the scalar rename migration, and the four
 * grandfather/preservation migrations. For every registered key, in registry order:
 * rename -> grandfather-map -> seed, with mode (OLDCFG/NEWCFG) computed once per section
 * before any mutation.
 *
 * Pure function: takes the section-path => blob map the driver read, returns only the
 * sections whose blob actually changed. No config_*_path/write_config side effects --
 * the caller (pfblockerng_install.inc) persists the result.
 */
#[CoversFunction('pfb_registry_pass')]
#[CoversFunction('pfb_registry_section_modes')]
final class RegistryPassTest extends TestCase
{
	private const GEN_SECTION   = 'installedpackages/pfblockerng/config/0';
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const SS_SECTION    = 'installedpackages/pfblockerngsafesearch';
	private const IP_SECTION    = 'installedpackages/pfblockerngipsettings/config/0';
	private const REP_SECTION   = 'installedpackages/pfblockerngreputation/config/0';
	// issue #2123.
	private const GLOBAL_SECTION = 'installedpackages/pfblockerngglobal';
	private const SYNC_SECTION   = 'installedpackages/pfblockerngsync/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config']                = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	private function noticeText(): string
	{
		$out = '';
		foreach ($GLOBALS['pfb_test_file_notices'] ?? [] as $notice) {
			$out .= (string) ($notice['notice'] ?? '') . "\n";
		}
		return $out;
	}

	/**
	 * issue #1921 verification 4: apply the pass's own output back over its input and run
	 * again -- the second pass must report no section as changed.
	 *
	 * @param array<string,array<string,mixed>> $sections
	 */
	private function assertSecondPassIsEmpty(array $sections, string $message = ''): void
	{
		$first  = pfb_registry_pass($sections);
		$merged = $sections;
		foreach ($first as $section => $blob) {
			$merged[$section] = $blob;
		}
		$second = pfb_registry_pass($merged);
		$this->assertSame([], $second, $message !== '' ? $message : 'a second pass over the first pass\'s own output must change nothing');
	}

	// -----------------------------------------------------------------------
	// 1 -- Mode / seed
	// -----------------------------------------------------------------------

	public function testSectionModesUseOperatorViewAcrossEveryRegisteredSection(): void
	{
		$modes = pfb_registry_section_modes([
			self::GEN_SECTION    => [],
			self::DNSBL_SECTION  => ['settings_family' => '4.0'],
			self::SS_SECTION     => ['safesearch' => 'on'],
			self::IP_SECTION     => 'not-an-array',
			self::REP_SECTION    => ['enable_rep' => 'on'],
			// issue #2123: two sections joined PFB_SECTIONS. A supplied-but-empty blob
			// and an absent one both read NEWCFG; real operator data reads OLDCFG.
			self::GLOBAL_SECTION => ['pfbpageload' => 'unified'],
		]);

		$this->assertSame([
			self::GEN_SECTION    => 'NEWCFG',
			self::DNSBL_SECTION  => 'NEWCFG',
			self::SS_SECTION     => 'OLDCFG',
			self::IP_SECTION     => 'NEWCFG',
			self::REP_SECTION    => 'OLDCFG',
			self::GLOBAL_SECTION => 'OLDCFG',
			self::SYNC_SECTION   => 'NEWCFG',
		], $modes);
	}

	public function testFreshMigrationUsesCapturedRegistryModes(): void
	{
		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$modes = pfb_registry_section_modes($sections);

		pfb_run_migrations();
		$this->assertSame('on', config_get_path(self::GEN_SECTION . '/pfb_scheduled_feed_updates'),
			'the schedule migration must seed General before registry reconciliation');

		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$result = pfb_registry_pass($sections, NULL, $modes);

		$this->assertSame('auto', $result[self::GEN_SECTION]['pfb_alias_delta_mode'] ?? NULL);
	}

	/** Row 1: every registered field seeded at default on a genuinely fresh install. */
	public function testFreshEmptySectionsSeedEveryRegisteredFieldAtDefault(): void
	{
		$sections = [
			self::GEN_SECTION    => [],
			self::DNSBL_SECTION  => [],
			self::SS_SECTION     => [],
			self::IP_SECTION     => [],
			self::REP_SECTION    => [],
			// issue #2123: the two sections that joined PFB_SECTIONS.
			self::GLOBAL_SECTION => [],
			self::SYNC_SECTION   => [],
		];

		$result = pfb_registry_pass($sections);

		$this->assertSame('on', $result[self::GEN_SECTION]['pfb_keep'] ?? NULL);
		foreach (['pfb_interval', 'pfb_min', 'pfb_hour', 'pfb_dailystart'] as $retired) {
			$this->assertArrayNotHasKey($retired, $result[self::GEN_SECTION]);
		}
		$this->assertSame('tranco', $result[self::DNSBL_SECTION]['top1m_source'] ?? NULL);
		// issue #2371: the pass's own NEWCFG default for these two is the registered
		// default '' (-> Honor), NEVER 'apex' -- the fresh-install apex/apex seed is a
		// separate, later, install-time write (pfb_psl_feed_policy_is_fresh_install()),
		// not something pfb_registry_pass() itself performs.
		$this->assertSame('', $result[self::DNSBL_SECTION]['pfb_psl_feed_private_policy'] ?? NULL);
		$this->assertSame('', $result[self::DNSBL_SECTION]['pfb_psl_feed_icann_policy'] ?? NULL);
		$this->assertSame('Disable', $result[self::SS_SECTION]['safesearch_enable'] ?? NULL);
		$this->assertSame('', $result[self::IP_SECTION]['v6suppression'] ?? NULL);
		$this->assertSame('', $result[self::REP_SECTION]['enable_rep'] ?? NULL);
		// issue #2123: alertrefresh is the only default-ON key among the seventeen, so a
		// fresh install must seed 'on' there and '' for syncinterfaces.
		$this->assertSame('on', $result[self::GLOBAL_SECTION]['alertrefresh'] ?? NULL);
		$this->assertSame('', $result[self::SYNC_SECTION]['syncinterfaces'] ?? NULL);
		$this->assertSame('', $result[self::IP_SECTION]['enable_dup'] ?? NULL);
		$this->assertSame('', $result[self::DNSBL_SECTION]['autoaddrnot_in'] ?? NULL);

		// settings_family is never written by the pass -- absent from input, absent from output.
		$this->assertArrayNotHasKey('settings_family', $result[self::GEN_SECTION]);

		$this->assertSecondPassIsEmpty($sections);
	}

	/** Row 1 (continued): a settings_family already present in the input is left untouched. */
	public function testFreshInstallLeavesAPresentSettingsFamilyUntouched(): void
	{
		$sections = [self::GEN_SECTION => ['settings_family' => '4.0']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('4.0', $result[self::GEN_SECTION]['settings_family'] ?? NULL);
	}

	/**
	 * Row 2: a marker-only gen section (settings_family only) is NEWCFG -- registered
	 * defaults must win over any OLDCFG-only grandfather decisions.
	 */
	public function testMarkerOnlyGenSectionIsNewcfgAndTakesRegistryDefaults(): void
	{
		$sections = [self::GEN_SECTION => ['settings_family' => '4.0']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('on', $result[self::GEN_SECTION]['pfb_feed_internal_filter'] ?? NULL,
			'NEWCFG must take the registry default for the feed filter');
		$this->assertSame('auto', $result[self::GEN_SECTION]['pfb_alias_delta_mode'] ?? NULL,
			'NEWCFG must take the registry default, not the OLDCFG absent-grandfather (replace)');
	}

	/** Row 3: mixed state -- gen populated (OLDCFG), dnsbl empty (NEWCFG). */
	public function testMixedStateGenPopulatedDnsblEmpty(): void
	{
		$sections = [
			self::GEN_SECTION   => ['pfb_interval' => '4'],
			self::DNSBL_SECTION => [],
		];

		$result = pfb_registry_pass($sections);

		$this->assertSame('on', $result[self::GEN_SECTION]['pfb_feed_internal_filter'] ?? NULL,
			'gen is OLDCFG (populated) -- feed-filter absent uses registered default');
		$this->assertSame('tranco', $result[self::DNSBL_SECTION]['top1m_source'] ?? NULL,
			'dnsbl is NEWCFG (empty) -- fields seed at their registry default');

		$this->assertSecondPassIsEmpty($sections);
	}

	/** Row 3 mirror: gen marker-only (NEWCFG), dnsbl populated (OLDCFG). */
	public function testMixedStateGenMarkerOnlyDnsblPopulated(): void
	{
		$sections = [
			self::GEN_SECTION   => ['settings_family' => '4.0'],
			self::DNSBL_SECTION => ['pfb_dnsbl' => 'on'],
		];

		$result = pfb_registry_pass($sections);

		$this->assertSame('on', $result[self::GEN_SECTION]['pfb_feed_internal_filter'] ?? NULL,
			'gen is NEWCFG (marker-only) -- feed filter seeds the registry default');
		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_dnsbl_lenient'] ?? NULL,
			'dnsbl is OLDCFG (populated) -- the lenient grandfather must fire');
	}

	// -----------------------------------------------------------------------
	// 2 -- Grandfathers (OLDCFG, per key x state)
	// -----------------------------------------------------------------------

	/** Row 4: gen/pfb_keep -- absent -> 'on'; empty remains empty; canonical tokens unchanged. */
	public function testGrandfatherPfbKeep(): void
	{
		$populated = ['pfb_interval' => '4']; // OLDCFG discriminator

		$absent = pfb_registry_pass([self::GEN_SECTION => $populated]);
		$this->assertSame('on', $absent[self::GEN_SECTION]['pfb_keep'] ?? NULL);

		$empty = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_keep' => '']]);
		$this->assertSame('', $empty[self::GEN_SECTION]['pfb_keep'] ?? NULL);

		$on = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_keep' => 'on']]);
		$this->assertSame('on', $on[self::GEN_SECTION]['pfb_keep'] ?? NULL,
			'an already-canonical value must be left untouched');

		$off = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_keep' => 'off']]);
		$this->assertSame('off', $off[self::GEN_SECTION]['pfb_keep'] ?? NULL);

		$this->assertSecondPassIsEmpty([self::GEN_SECTION => $populated]);
		$this->assertSecondPassIsEmpty([self::GEN_SECTION => $populated + ['pfb_keep' => '']]);
	}

	/** Row 5: gen/pfb_feed_internal_filter -- absent -> registered default 'on'; empty stays empty. */
	public function testGrandfatherFeedInternalFilter(): void
	{
		$populated = ['pfb_interval' => '4'];

		$absent = pfb_registry_pass([self::GEN_SECTION => $populated]);
		$this->assertSame('on', $absent[self::GEN_SECTION]['pfb_feed_internal_filter'] ?? NULL);

		$empty = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_feed_internal_filter' => '']]);
		$this->assertSame('', $empty[self::GEN_SECTION]['pfb_feed_internal_filter'] ?? NULL,
			'present empty must stay the canonical Off token'
		);

		$on = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_feed_internal_filter' => 'on']]);
		$this->assertSame('on', $on[self::GEN_SECTION]['pfb_feed_internal_filter'] ?? NULL);

		$off = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_feed_internal_filter' => 'off']]);
		$this->assertSame('off', $off[self::GEN_SECTION]['pfb_feed_internal_filter'] ?? NULL);

		$this->assertSecondPassIsEmpty([self::GEN_SECTION => $populated + ['pfb_feed_internal_filter' => '']]);
		$this->assertSecondPassIsEmpty([self::GEN_SECTION => $populated]);
	}

	/** Row 6: gen/pfb_alias_delta_mode -- absent -> 'replace'; 'auto' -> 'auto'; 'delta' -> 'delta'. */
	public function testGrandfatherAliasDeltaMode(): void
	{
		$populated = ['pfb_interval' => '4'];

		$absent = pfb_registry_pass([self::GEN_SECTION => $populated]);
		$this->assertSame('replace', $absent[self::GEN_SECTION]['pfb_alias_delta_mode'] ?? NULL);

		$auto = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_alias_delta_mode' => 'auto']]);
		$this->assertSame('auto', $auto[self::GEN_SECTION]['pfb_alias_delta_mode'] ?? NULL);

		$delta = pfb_registry_pass([self::GEN_SECTION => $populated + ['pfb_alias_delta_mode' => 'delta']]);
		$this->assertSame('delta', $delta[self::GEN_SECTION]['pfb_alias_delta_mode'] ?? NULL);

		$this->assertSecondPassIsEmpty([self::GEN_SECTION => $populated]);
	}

	/** Row 7: dnsbl/pfb_dnsbl_lenient -- absent -> 'on'; 'on' -> 'on'; 'off' -> 'off'. */
	public function testGrandfatherDnsblLenient(): void
	{
		$populated = ['pfb_dnsbl' => 'on'];

		$absent = pfb_registry_pass([self::DNSBL_SECTION => $populated]);
		$this->assertSame('on', $absent[self::DNSBL_SECTION]['pfb_dnsbl_lenient'] ?? NULL);

		$on = pfb_registry_pass([self::DNSBL_SECTION => $populated + ['pfb_dnsbl_lenient' => 'on']]);
		$this->assertSame('on', $on[self::DNSBL_SECTION]['pfb_dnsbl_lenient'] ?? NULL);

		$off = pfb_registry_pass([self::DNSBL_SECTION => $populated + ['pfb_dnsbl_lenient' => 'off']]);
		$this->assertSame('off', $off[self::DNSBL_SECTION]['pfb_dnsbl_lenient'] ?? NULL);

		$this->assertSecondPassIsEmpty([self::DNSBL_SECTION => $populated]);
	}

	/** Row 8: dnsbl/pfb_idn_block_malicious -- empty remains empty; absent -> 'on'; 'on' -> 'on'. */
	public function testGrandfatherIdnBlockMalicious(): void
	{
		$populated = ['pfb_dnsbl' => 'on'];

		$empty = pfb_registry_pass([self::DNSBL_SECTION => $populated + ['pfb_idn_block_malicious' => '']]);
		$this->assertSame('', $empty[self::DNSBL_SECTION]['pfb_idn_block_malicious'] ?? NULL);

		$absent = pfb_registry_pass([self::DNSBL_SECTION => $populated]);
		$this->assertSame('on', $absent[self::DNSBL_SECTION]['pfb_idn_block_malicious'] ?? NULL,
			'absent has no ABSENT grandfather entry for this key -- it seeds the registry default');

		$on = pfb_registry_pass([self::DNSBL_SECTION => $populated + ['pfb_idn_block_malicious' => 'on']]);
		$this->assertSame('on', $on[self::DNSBL_SECTION]['pfb_idn_block_malicious'] ?? NULL);

		$this->assertSecondPassIsEmpty([self::DNSBL_SECTION => $populated + ['pfb_idn_block_malicious' => '']]);
		$this->assertSecondPassIsEmpty([self::DNSBL_SECTION => $populated]);
	}

	/**
	 * Row 9: dnsbl/pfb_cache, dnsbl/pfb_py_reply, dnsbl/pfb_hsts, ip/suppression --
	 * issue #1907 owner decision: default flipped to 'on' (the de-facto page default
	 * since 3.2). Present empty remains canonical Off; 'on' remains On; absent (OLDCFG
	 * and NEWCFG alike) seeds the registered On default. No grandfather arm remains.
	 */
	public function testDefaultOnGroupPreservesEmptyAndSeedsAbsent(): void
	{
		$cases = [
			[self::DNSBL_SECTION, 'pfb_cache',    ['pfb_dnsbl' => 'on']],
			[self::DNSBL_SECTION, 'pfb_py_reply', ['pfb_dnsbl' => 'on']],
			[self::DNSBL_SECTION, 'pfb_hsts',     ['pfb_dnsbl' => 'on']],
			[self::IP_SECTION,    'suppression',  ['v6suppression' => 'x']],
		];

		foreach ($cases as [$section, $key, $populated]) {
			$empty = pfb_registry_pass([$section => $populated + [$key => '']]);
			$this->assertSame('', $empty[$section][$key] ?? NULL, "{$key}: '' must remain empty");

			$oldcfg_absent = pfb_registry_pass([$section => $populated]);
			$this->assertSame('on', $oldcfg_absent[$section][$key] ?? '__missing__',
				"{$key}: OLDCFG absent must seed the registry default 'on'");

			$newcfg_absent = pfb_registry_pass([$section => []]);
			$this->assertSame('on', $newcfg_absent[$section][$key] ?? '__missing__',
				"{$key}: NEWCFG absent (fresh install) must seed the registry default 'on'");

			$on = pfb_registry_pass([$section => $populated + [$key => 'on']]);
			$this->assertSame('on', $on[$section][$key] ?? NULL, "{$key}: 'on' must be left untouched");

			$this->assertSecondPassIsEmpty([$section => $populated + [$key => '']]);
			$this->assertSecondPassIsEmpty([$section => $populated]);
			$this->assertSecondPassIsEmpty([$section => []]);
		}
	}

	/**
	 * Row 10: ip/v4suppression -- absent -> seeded '' (the former seed-exclusion is gone,
	 * issue #1921); a stored value is untouched (no grandfather map on this key at all).
	 */
	public function testGrandfatherV4Suppression(): void
	{
		$populated = ['v6suppression' => 'x'];

		$absent = pfb_registry_pass([self::IP_SECTION => $populated]);
		$this->assertSame('', $absent[self::IP_SECTION]['v4suppression'] ?? '__missing__');

		$stored = pfb_registry_pass([self::IP_SECTION => $populated + ['v4suppression' => 'YmFzZTY0']]);
		$this->assertSame('YmFzZTY0', $stored[self::IP_SECTION]['v4suppression'] ?? NULL);

		$this->assertSecondPassIsEmpty([self::IP_SECTION => $populated]);
	}

	// -----------------------------------------------------------------------
	// 3 -- Rename branch (real registry rows, dnsbl section fixtures)
	// -----------------------------------------------------------------------

	/** Row 11: old-only moves verbatim (RAW, not adapter-canonicalised) to the new key. */
	public function testRenameOldOnlyMovesVerbatim(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'alexa_type' => 'alexa']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('alexa', $result[self::DNSBL_SECTION]['top1m_source'] ?? NULL,
			'the pass moves the RAW value -- adapter canonicalisation is the gateway write\'s job');
		$this->assertArrayNotHasKey('alexa_type', $result[self::DNSBL_SECTION]);

		$this->assertSecondPassIsEmpty($sections);
	}

	public function testPslPolicyNewAndOldConfigAbsenceSeedsDefaultsIdempotently(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on']];
		$result = pfb_registry_pass($sections);
		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_psl_include_private'] ?? NULL);
		$this->assertSame('', $result[self::DNSBL_SECTION]['pfb_psl_allow_private'] ?? NULL);
		$this->assertSecondPassIsEmpty($result);

		$new = pfb_registry_pass([self::DNSBL_SECTION => []]);
		$this->assertSame('on', $new[self::DNSBL_SECTION]['pfb_psl_include_private'] ?? NULL);
		$this->assertSame('', $new[self::DNSBL_SECTION]['pfb_psl_allow_private'] ?? NULL);
		$this->assertSecondPassIsEmpty($new);
	}

	/** Row 12: old-only with '' moves as '' -- '' is a stored value, never absence. */
	public function testRenameOldOnlyEmptyStringMoves(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'pfb_pytld_sort' => '']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('', $result[self::DNSBL_SECTION]['tld_allow_sort'] ?? '__missing__');
		$this->assertArrayNotHasKey('pfb_pytld_sort', $result[self::DNSBL_SECTION]);

		$this->assertSecondPassIsEmpty($sections);
	}

	/** Row 13: old-only with '0' moves as '0' -- the falsy-value trap. */
	public function testRenameOldOnlyZeroStringMoves(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'pfb_pytlds_bgtld' => '0']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('0', $result[self::DNSBL_SECTION]['tld_allow_bgtld'] ?? NULL);
		$this->assertArrayNotHasKey('pfb_pytlds_bgtld', $result[self::DNSBL_SECTION]);

		$this->assertSecondPassIsEmpty($sections);
	}

	/** Row 14: both present, identical -- old dropped, new kept, no notice. */
	public function testRenameBothPresentIdenticalDropsOldSilently(): void
	{
		$sections = [self::DNSBL_SECTION => [
			'pfb_dnsbl'    => 'on',
			'pfb_tld'      => 'on',
			'tld_wildcard' => 'on',
		]];

		$result = pfb_registry_pass($sections);

		$this->assertSame('on', $result[self::DNSBL_SECTION]['tld_wildcard'] ?? NULL);
		$this->assertArrayNotHasKey('pfb_tld', $result[self::DNSBL_SECTION]);
		$this->assertSame('', $this->noticeText());

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * Row 15: both present, different -- new kept, OLD LEFT IN PLACE, a per-key notice
	 * naming both keys (never values), and every OTHER key in the section still
	 * processed (a sibling absent key is still seeded).
	 */
	public function testRenameBothPresentDifferentLeavesOldAndNoticesWithoutAbortingSiblings(): void
	{
		$sections = [self::DNSBL_SECTION => [
			'pfb_dnsbl'    => 'on',
			'pfb_tld'      => 'on',
			'tld_wildcard' => 'off',
		]];

		$result = pfb_registry_pass($sections);

		$this->assertSame('off', $result[self::DNSBL_SECTION]['tld_wildcard'] ?? NULL,
			'the new key\'s value is kept as-is on conflict');
		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_tld'] ?? NULL,
			'the old key is LEFT IN PLACE on conflict, not dropped');

		$text = $this->noticeText();
		$this->assertStringContainsString('pfb_tld', $text);
		$this->assertStringContainsString('tld_wildcard', $text);
		$this->assertStringNotContainsString("'on'", $text, 'notice must never echo stored values');
		$this->assertStringNotContainsString("'off'", $text, 'notice must never echo stored values');

		// Per-key rule, not all-or-nothing: a sibling absent key must still be seeded.
		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_dnsbl_lenient'] ?? NULL,
			'a sibling key must still be processed when another key in the same section conflicts');
	}

	/**
	 * Row 17: issue #1921 owner directive -- the DNSBL whitelist blob's registry key
	 * (dnsbl alias, bare key renamed suppression -> whitelist) carries 'old_name' =>
	 * 'suppression'. Old-only (base64-ish blob) moves verbatim to 'whitelist', old key
	 * gone; idempotent second pass.
	 */
	public function testRenameDnsblSuppressionToWhitelistMovesVerbatim(): void
	{
		$blob = base64_encode("example.com\r\n.blocked.net\r\n");
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'suppression' => $blob]];

		$result = pfb_registry_pass($sections);

		$this->assertSame($blob, $result[self::DNSBL_SECTION]['whitelist'] ?? NULL,
			'the pass moves the RAW blob verbatim to the new whitelist key');
		$this->assertArrayNotHasKey('suppression', $result[self::DNSBL_SECTION],
			'the old suppression key must be gone after the rename');

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * Row 16: fixture registry -- old_name + [''=>'x'] map: old-only stored '' moves then
	 * maps to 'x' (grandfather maps apply to values the rename JUST moved).
	 */
	public function testFixtureRegistryOldOnlyMovesThenMaps(): void
	{
		$registry = [
			'gen/new_key' => [
				'default'     => 'z',
				'old_name'    => 'old_key',
				'grandfather' => ['' => 'x'],
			],
		];
		$sections = [self::GEN_SECTION => ['old_key' => '']];

		$result = pfb_registry_pass($sections, $registry);

		$this->assertSame('x', $result[self::GEN_SECTION]['new_key'] ?? NULL);
		$this->assertArrayNotHasKey('old_key', $result[self::GEN_SECTION]);
	}

	/**
	 * Row 16 (continued): old_name + [PFB_GF_ABSENT=>'y'] -- old-only stored value moves
	 * and ABSENT does NOT fire (the key is no longer absent once the rename moved it in).
	 */
	public function testFixtureRegistryOldOnlyMoveNeverTriggersAbsentGrandfather(): void
	{
		$registry = [
			'gen/new_key2' => [
				'default'     => 'z',
				'old_name'    => 'old_key2',
				'grandfather' => [PFB_GF_ABSENT => 'y'],
			],
		];
		$sections = [self::GEN_SECTION => ['old_key2' => 'foo']];

		$result = pfb_registry_pass($sections, $registry);

		$this->assertSame('foo', $result[self::GEN_SECTION]['new_key2'] ?? NULL,
			'the moved value must survive unmapped -- ABSENT must not fire on a key the rename just populated');
		$this->assertArrayNotHasKey('old_key2', $result[self::GEN_SECTION]);
	}

	// -----------------------------------------------------------------------
	// 4 -- Hostile rows
	// -----------------------------------------------------------------------

	/** Row 18: a non-array section blob is treated as empty (NEWCFG), no crash/warning. */
	public function testNonArraySectionBlobIsTreatedAsEmpty(): void
	{
		$result = pfb_registry_pass([self::GEN_SECTION => 'not-an-array']);

		$this->assertSame('on', $result[self::GEN_SECTION]['pfb_keep'] ?? NULL,
			'a non-array blob must be treated as empty and take the NEWCFG default');
	}

	/** Row 19: a registered key holding an array value is left untouched, no crash. */
	public function testArrayValuedRegisteredKeyIsUntouched(): void
	{
		$populated = ['pfb_interval' => '4', 'pfb_keep' => ['nested' => 'array']];

		$result = pfb_registry_pass([self::GEN_SECTION => $populated]);

		$this->assertSame(['nested' => 'array'], $result[self::GEN_SECTION]['pfb_keep'] ?? NULL,
			'an array value must never be looked up as a grandfather-map key, and must be left as-is');
	}

	/** Row 20: a registered key holding '0' is kept '0' -- never re-seeded. */
	public function testZeroStringValueIsNeverReseeded(): void
	{
		$populated = ['pfb_interval' => '0'];

		$result = pfb_registry_pass([self::GEN_SECTION => $populated]);

		$this->assertSame('0', $result[self::GEN_SECTION]['pfb_interval'] ?? NULL,
			'array_key_exists discipline: a present \'0\' must never be treated as absent and re-seeded');
	}
}
