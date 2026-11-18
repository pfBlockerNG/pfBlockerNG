<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4053: the WebServer/VIP blocking response is removed. Every stored VIP marker becomes Null Blocking (logging),
 * on upgrade and in the resolver, and nothing renders or emits the VIP mechanism any more.
 */
#[CoversFunction('pfb_dnsbl_vip_mechanism_migrate')]
#[CoversFunction('pfb_dnsbl_group_logging')]
#[CoversFunction('pfb_dnsbl_mechanism_normalize')]
#[CoversFunction('pfb_dnsbl_policy_config')]
#[CoversFunction('pfb_dnsbl_mechanism_labels')]
#[CoversFunction('pfb_dnsbl_mechanism_help')]
#[CoversFunction('pfb_migration_registry')]
#[CoversFunction('pfb_run_migrations')]
final class DnsblVipMechanismRemovalTest extends TestCase
{
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const GROUPS = 'installedpackages/pfblockerngdnsbl/config';
	private const BLACKLIST = 'installedpackages/pfblockerngblacklist';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	public static function vipMarkers(): array
	{
		return ['absent' => [NULL], 'empty' => [''], 'enabled' => ['enabled'], 'upper case' => ['ENABLED'], 'mixed' => ['Enabled']];
	}

	#[DataProvider('vipMarkers')]
	public function testAGroupVipMarkerMigratesToNullBlockingWithLogging(?string $marker): void
	{
		$group = ['name' => 'Ads', 'action' => 'unbound'];
		if ($marker !== NULL) {
			$group['logging'] = $marker;
		}
		$result = pfb_dnsbl_vip_mechanism_migrate([
			self::DNSBL => ['global_log_mode' => 'default', 'global_log' => 'disabled_log'],
			self::GROUPS => [$group, ['name' => 'Kept', 'action' => 'unbound', 'logging' => 'nxdomain']],
			self::BLACKLIST => [],
		]);
		$this->assertNotNull($result);
		$this->assertSame('disabled_log', $result[self::GROUPS][0]['logging']);
		$this->assertSame('nxdomain', $result[self::GROUPS][1]['logging'], 'an explicit non-VIP choice is untouched');
		$this->assertSame('Ads', $result[self::GROUPS][0]['name'], 'bystander keys stay');
	}

	public function testAGroupThatInheritsStaysDefault(): void
	{
		$result = pfb_dnsbl_vip_mechanism_migrate([
			self::DNSBL => ['global_log_mode' => 'default', 'global_log' => 'enabled'],
			self::GROUPS => [['name' => 'Ads', 'logging' => 'default']],
			self::BLACKLIST => [],
		]);
		$this->assertSame('disabled_log', $result[self::DNSBL]['global_log']);
		$this->assertSame('default', $result[self::GROUPS][0]['logging']);
	}

	/** An absent or empty global mechanism is the registry default after #3288's migration, not a VIP marker. */
	#[DataProvider('globalMarkers')]
	public function testTheGlobalVipMechanismMigrates(string $marker): void
	{
		foreach (['default', 'override'] as $mode) {
			$result = pfb_dnsbl_vip_mechanism_migrate([
				self::DNSBL => ['global_log_mode' => $mode, 'global_log' => $marker, 'pfb_regex' => 'on'],
				self::GROUPS => [],
				self::BLACKLIST => [],
			]);
			$this->assertSame('disabled_log', $result[self::DNSBL]['global_log'], $mode);
			$this->assertSame($mode, $result[self::DNSBL]['global_log_mode']);
			$this->assertSame('on', $result[self::DNSBL]['pfb_regex']);
		}
	}

	public static function globalMarkers(): array
	{
		return ['enabled' => ['enabled'], 'upper case' => ['ENABLED'], 'mixed' => ['Enabled']];
	}

	public static function blacklistMarkers(): array
	{
		return ['empty' => [''], 'enabled' => ['enabled'], 'upper case' => ['ENABLED']];
	}

	#[DataProvider('blacklistMarkers')]
	public function testAnExplicitBlacklistVipMarkerMigrates(string $marker): void
	{
		$result = pfb_dnsbl_vip_mechanism_migrate([
			self::DNSBL => ['global_log_mode' => 'default', 'global_log' => 'disabled_log'],
			self::GROUPS => [],
			self::BLACKLIST => ['blacklist_logging' => $marker, 'blacklist_selected' => 'ut1'],
		]);
		$this->assertSame('disabled_log', $result[self::BLACKLIST]['blacklist_logging']);
		$this->assertSame('ut1', $result[self::BLACKLIST]['blacklist_selected']);
	}

	public function testABlacklistWithoutLoggingFollowsThePolicyAndIsUntouched(): void
	{
		$this->assertNull(pfb_dnsbl_vip_mechanism_migrate([
			self::DNSBL => ['global_log_mode' => 'default', 'global_log' => 'disabled_log'],
			self::GROUPS => [['name' => 'Ads', 'logging' => 'nodata']],
			self::BLACKLIST => ['blacklist_selected' => 'ut1'],
		]));
	}

	public function testAFreshInstallHasNothingToMigrate(): void
	{
		$this->assertNull(pfb_dnsbl_vip_mechanism_migrate([self::DNSBL => [], self::GROUPS => [], self::BLACKLIST => []]));
	}

	public function testTheMigrationIsIdempotent(): void
	{
		$sections = [
			self::DNSBL => ['global_log_mode' => 'override', 'global_log' => 'enabled'],
			self::GROUPS => [['name' => 'Ads', 'logging' => 'enabled']],
			self::BLACKLIST => ['blacklist_logging' => 'enabled'],
		];
		$once = pfb_dnsbl_vip_mechanism_migrate($sections);
		$this->assertNull(pfb_dnsbl_vip_mechanism_migrate(array_replace($sections, $once)));
	}

	public function testItRunsAfterTheDefaultOverrideMigration(): void
	{
		$ids = array_column(pfb_migration_registry(), 'id');
		$policy = array_search('issue3288-dnsbl-policy-migrate', $ids, TRUE);
		$vip = array_search('issue4053-remove-vip-mechanism', $ids, TRUE);
		$this->assertNotFalse($vip, 'the VIP removal is a registered migration');
		$this->assertGreaterThan($policy, $vip, 'legacy markers are folded into Default/Override first');
	}

	public function testALegacyVipConfigEndsOnNullBlockingAfterTheMigrations(): void
	{
		// A released config: no Default/Override pair, no global mechanism (the VIP), groups without logging (the VIP).
		config_set_path(self::DNSBL, ['pfb_dnsbl' => 'on']);
		config_set_path(self::GROUPS, [['name' => 'Ads', 'action' => 'unbound'], ['name' => 'Quiet', 'logging' => 'disabled']]);
		config_set_path(self::BLACKLIST, ['blacklist_logging' => 'enabled']);

		pfb_run_migrations();

		$dnsbl = config_get_path(self::DNSBL);
		$groups = config_get_path(self::GROUPS);
		$this->assertSame('disabled_log', $dnsbl['global_log']);
		$this->assertSame('disabled_log', pfb_dnsbl_effective_logging($groups[0]['logging'] ?? NULL, $dnsbl['global_log'],
			PfbDnsblGlobalMode::fromStored($dnsbl['global_log_mode']), FALSE));
		$this->assertSame('disabled', $groups[1]['logging']);
		$this->assertSame('disabled_log', config_get_path(self::BLACKLIST . '/blacklist_logging'));
	}

	public function testTheResolverNeverAnswersTheVip(): void
	{
		foreach ([NULL, '', 'enabled', 'ENABLED'] as $stored) {
			$this->assertSame('disabled_log', pfb_dnsbl_group_logging($stored, FALSE), var_export($stored, TRUE));
		}
		$this->assertSame('default', pfb_dnsbl_group_logging(NULL, TRUE), 'a legacy absent value still inherits');
		$this->assertSame('disabled_log', pfb_dnsbl_mechanism_normalize('enabled'));
		$this->assertNotContains('enabled', PFB_DNSBL_CONCRETE_MECHANISMS);
		$legacy = pfb_dnsbl_policy_config(['pfb_dnsbl' => 'on'], [['name' => 'Ads']]);
		$this->assertSame('disabled_log', $legacy['mechanism'], 'a legacy config without an override no longer means the VIP');
	}

	public function testNoPageOffersTheVip(): void
	{
		$this->assertArrayNotHasKey('enabled', pfb_dnsbl_mechanism_labels());
		$this->assertStringNotContainsStringIgnoringCase('VIP', implode(' ', pfb_dnsbl_mechanism_labels()));
		$this->assertStringNotContainsStringIgnoringCase('VIP', pfb_dnsbl_mechanism_help());
		$this->assertStringNotContainsStringIgnoringCase('block page', pfb_dnsbl_mechanism_help());
	}
}
