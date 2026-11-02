<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_registry_pass')]
#[CoversFunction('pfb_install_registry_writeback')]
#[CoversFunction('pfb_dns_proxy_seed')]
final class SyncDnsInstallTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
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

	public function testInstallerCapturedModesDoNotReplaceMigratedTransportChoices(): void
	{
		$expected = ['pfb_dns_dot' => 'on', 'pfb_dns_dot_port' => '8853', 'pfb_dns_doh_port' => '443',
			'pfb_dns_doh_trusted' => '192.0.2.20', 'pfb_dns_ddr' => 'on'];
		config_set_path(PFB_SECTIONS['dns'], $expected + ['pfb_dns' => 'on', 'pfb_dns_interface' => 'lan']);
		$modes = pfb_registry_section_modes(self::sections());
		pfb_run_migrations();
		$this->assertSame($expected, PfbConfig::readSection(PFB_SECTIONS['dns_shared']), 'migration has preserved raw values');
		pfb_install_registry_writeback(self::sections(), $modes);
		foreach ($expected as $key => $value) {
			$this->assertSame($value, PfbConfig::readSection(PFB_SECTIONS['dns_shared'])[$key], "installer overwrote {$key}");
		}
	}

	public function testFreshInstallerStillInheritsTheResolversDotSettingsOnce(): void
	{
		config_set_path('unbound', ['active_interface' => 'lan', 'enablessl' => '', 'tlsport' => '8853']);
		pfb_install_registry_writeback(self::sections());
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns_shared/pfb_dns_dot'), 'unconfigured reads the default before seed');
		$this->assertTrue(pfb_dns_proxy_seed());
		$this->assertSame(PfbToggle::On, pfb_dns_proxy_setting('pfb_dns_dot'));
		$this->assertSame('8853', pfb_dns_proxy_setting('pfb_dns_dot_port'));
	}
}
