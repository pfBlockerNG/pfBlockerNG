<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * A pre-split configuration backup restored onto this package never passes through pfb_run_migrations():
 * its transport settings are still in the pfB-DNS section, and the shared section does not exist.
 */
final class SyncDnsRestoredBackupTest extends TestCase
{
	private const RESTORED = [
		'pfb_dns_interface' => 'lan',
		'pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '8853',
		'pfb_dns_doh' => 'on', 'pfb_dns_doh_port' => '8448',
		'pfb_dns_doq' => 'on', 'pfb_dns_doq_port' => '8855',
		'pfb_dns_ddr' => 'on', 'pfb_dns_ddr_doh_443' => 'on',
	];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		config_set_path('unbound', ['active_interface' => 'lan', 'tlsport' => '853']);
	}

	public function testRestoredSettingsStayEffectiveUntilTheSharedSectionHoldsThem(): void
	{
		config_set_path(PFB_SECTIONS['dns'], self::RESTORED);

		$this->assertSame(PfbToggle::On, PfbConfig::read('dns_shared/pfb_dns_doh'), 'restored DoH must stay on');
		$this->assertSame('8448', PfbConfig::read('dns_shared/pfb_dns_doh_port'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns_shared/pfb_dns_doq'));
		$this->assertSame('8855', PfbConfig::read('dns_shared/pfb_dns_doq_port'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns_shared/pfb_dns_ddr_doh_443'));
		$this->assertSame(PfbToggle::On, pfb_dns_proxy_setting('pfb_dns_dot'), 'restored DoT must stay on');
		$this->assertSame('8853', pfb_dns_proxy_setting('pfb_dns_dot_port'));

		// A value stored in the shared section is the newer choice, including an explicit Off.
		config_set_path(PFB_SECTIONS['dns_shared'], ['pfb_dns_doh' => '']);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns_shared/pfb_dns_doh'));
		$this->assertSame('8448', PfbConfig::read('dns_shared/pfb_dns_doh_port'), 'other restored values still apply');
	}

	public function testUnseededRestoredDotDefaultsDoNotOverrideResolverInheritance(): void
	{
		config_set_path('unbound', ['active_interface' => 'lan', 'enablessl' => '', 'tlsport' => '8853']);
		config_set_path(PFB_SECTIONS['dns'], ['pfb_dns_interface' => '', 'pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '9853', 'pfb_dns_doh' => 'on']);

		$this->assertSame(PfbToggle::On, pfb_dns_proxy_setting('pfb_dns_dot'), 'unseeded node inherits the Resolver DoT');
		$this->assertSame('8853', pfb_dns_proxy_setting('pfb_dns_dot_port'));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns_shared/pfb_dns_dot'), 'an unseeded installer default is not a restored choice');
		$this->assertSame('853', PfbConfig::read('dns_shared/pfb_dns_dot_port'));
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns_shared/pfb_dns_doh'), 'other restored choices still apply');
	}
}
