<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_settings_migrate')]
#[CoversFunction('pfb_run_migrations')]
#[CoversFunction('pfb_install_registry_writeback')]
#[CoversFunction('pfb_dns_proxy_seed')]
final class SyncDnsUnseededUpgradeTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		config_set_path('unbound', ['active_interface' => 'lan', 'enablessl' => '', 'tlsport' => '8853']);
	}

	/** @return array<string,array> */
	private static function sections(): array
	{
		$sections = [];
		foreach (PFB_SECTIONS as $path) {
			$sections[$path] = PfbConfig::readSection($path);
		}
		return $sections;
	}

	/** @return iterable<string,array{?string,bool}> */
	public static function oldInterfaces(): iterable
	{
		yield 'interface key absent' => [NULL, TRUE];
		yield 'installer empty interface' => ['', TRUE];
		yield 'already seeded interface' => ['lan', FALSE];
	}

	#[DataProvider('oldInterfaces')]
	public function testUpgradeKeepsEffectiveResolverInheritanceInsteadOfPromotingUnseededDefaults(?string $interface, bool $unseeded): void
	{
		// The old installer materialized these DoT defaults even before first page load.
		$old = ['pfb_dns' => '', 'pfb_dns_saved' => '', 'pfb_dns_dot' => '', 'pfb_dns_dot_port' => '853'];
		if ($interface !== NULL) {
			$old['pfb_dns_interface'] = $interface;
		}
		config_set_path(PFB_SECTIONS['dns'], $old);
		$this->assertSame($unseeded ? PfbToggle::On : PfbToggle::Off, pfb_dns_proxy_setting('pfb_dns_dot'), 'effective before migration');
		$this->assertSame($unseeded ? '8853' : '853', pfb_dns_proxy_setting('pfb_dns_dot_port'), 'effective port before migration');
		$modes = pfb_registry_section_modes(self::sections());
		pfb_run_migrations();
		$this->assertSame($interface ?? '', PfbConfig::read('dns/pfb_dns_interface'), 'migration never seeds interfaces');
		$this->assertSame('', PfbConfig::read('dns/pfb_dns_saved'), 'migration never touches recovery state');
		pfb_install_registry_writeback(self::sections(), $modes);
		pfb_dns_proxy_seed();
		$this->assertSame($unseeded ? PfbToggle::On : PfbToggle::Off, pfb_dns_proxy_setting('pfb_dns_dot'), 'upgrade must preserve effective DoT choice');
		$this->assertSame($unseeded ? '8853' : '853', pfb_dns_proxy_setting('pfb_dns_dot_port'), 'upgrade must preserve effective DoT port');
		$this->assertArrayNotHasKey('pfb_dns_dot', PfbConfig::readSection(PFB_SECTIONS['dns']));
		$this->assertArrayNotHasKey('pfb_dns_dot_port', PfbConfig::readSection(PFB_SECTIONS['dns']));
	}

	public function testReceivedExplicitOffAndEmptyPortStillWinOnAnUnseededUpgrade(): void
	{
		config_set_path(PFB_SECTIONS['dns'], ['pfb_dns_interface' => '', 'pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '8853']);
		$received = ['pfb_dns_dot' => '', 'pfb_dns_dot_port' => ''];
		config_set_path(PFB_SECTIONS['dns_shared'], $received);
		$modes = pfb_registry_section_modes(self::sections());
		pfb_run_migrations();
		$this->assertSame($received, PfbConfig::readSection(PFB_SECTIONS['dns_shared']), 'received explicit values win before writeback');
		pfb_install_registry_writeback(self::sections(), $modes);
		pfb_dns_proxy_seed();
		$this->assertSame(PfbToggle::Off, pfb_dns_proxy_setting('pfb_dns_dot'));
		$this->assertSame('', PfbConfig::readSection(PFB_SECTIONS['dns_shared'])['pfb_dns_dot_port'], 'received empty port remains explicit');
	}
}
