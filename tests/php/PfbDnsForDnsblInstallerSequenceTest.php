<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3770 -- the installer captures each section's registry mode BEFORE pfb_run_migrations(), so an upgrade with no
 * (or an empty) pfB-DNS section has it captured NEWCFG. The migration then turns pfB-DNS on, and the registry pass must
 * keep that value instead of re-seeding the registered default over it. The sequence below is pfblockerng_install.inc's:
 * read sections, capture modes, migrate, re-read sections, write back.
 */
#[CoversFunction('pfb_registry_pass')]
#[CoversFunction('pfb_install_registry_writeback')]
#[CoversFunction('pfb_dns_dnsbl_migrate')]
final class PfbDnsForDnsblInstallerSequenceTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const DNS_SECTION   = 'installedpackages/pfblockerngdns/config/0';
	private const MARKER        = 'pfb_dns_dnsbl_migrated';

	protected function setUp(): void
	{
		$GLOBALS['config']                      = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices']       = [];
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

	/** @return array<string,string> the pre-migration modes the installer hands to the write-back */
	private static function installerOrder(): array
	{
		$modes = pfb_registry_section_modes(self::sections(), PfbConfig::readSection('installedpackages/pfblockerngdnsbl/config'));
		pfb_run_migrations();
		pfb_install_registry_writeback(self::sections(), $modes);
		return $modes;
	}

	/** @return iterable<string,array{0:bool}> */
	public static function noPfbDnsSettingsProvider(): iterable
	{
		yield 'pfB-DNS section absent (3.x upgrade or never saved)' => [FALSE];
		yield 'pfB-DNS section present but empty'                   => [TRUE];
	}

	#[DataProvider('noPfbDnsSettingsProvider')]
	public function testDnsblOnWithNoPfbDnsSettingsKeepsTheMigratedPfbDnsThroughTheRegistryPass(bool $emptySection): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		if ($emptySection) {
			config_set_path(self::DNS_SECTION, []);
		}
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'before: pfB-DNS reads Off');

		$modes = self::installerOrder();

		$this->assertSame('NEWCFG', $modes[PFB_SECTIONS['dns']], 'the installer captured the pfB-DNS section as new');
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns'), 'pfB-DNS reads On after the installer order');
		$this->assertSame('on', config_get_path(self::DNS_SECTION)['pfb_dns'] ?? NULL, 'and is stored On');
		$this->assertArrayHasKey('pfb_dns_saved', config_get_path(self::DNS_SECTION), 'the registry pass still seeds the other pfB-DNS keys');
		$this->assertSame('on', config_get_path(self::DNS_SECTION)[self::MARKER] ?? NULL, 'and the run-once marker survives the NEWCFG seeding');
	}

	public function testDnsblOffWithNoPfbDnsSectionSeedsTheDefaultOff(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'off']);

		$modes = self::installerOrder();

		$this->assertSame('NEWCFG', $modes[PFB_SECTIONS['dns']]);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'));
		$this->assertArrayHasKey('pfb_dns', config_get_path(self::DNS_SECTION), 'the registered default is seeded');
		$this->assertSame('on', config_get_path(self::DNS_SECTION)[self::MARKER] ?? NULL, 'the run is recorded even with DNSBL off');
	}

	public function testFreshInstallLeavesPfbDnsOff(): void
	{
		$modes = self::installerOrder();

		$this->assertSame('NEWCFG', $modes[PFB_SECTIONS['dns']]);
		$this->assertSame('NEWCFG', $modes[PFB_SECTIONS['dnsbl']]);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'));
		$this->assertArrayHasKey('pfb_dns', config_get_path(self::DNS_SECTION), 'the registered default is seeded');
		$this->assertSame('on', config_get_path(self::DNS_SECTION)[self::MARKER] ?? NULL, 'a fresh install is marked: it never lived in the Unbound-hosted DNSBL world');
	}

	/** Coverage, not the reproduction: pins the case-insensitive DNSBL read in the migration (an `=== 'on'` test fails it). */
	public function testDnsblStoredInUpperCaseTurnsPfbDnsOn(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'ON']);

		pfb_run_migrations();

		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns'));
	}

	/** The Codex P2 on PR #3792: the second install runs the same sequence over the section the first one wrote. */
	public function testAReinstallAfterTheAdministratorSavedPfbDnsOffKeepsItOff(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		self::installerOrder();
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns'), 'before: the first upgrade turned pfB-DNS on');
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'before: the administrator saved pfB-DNS off');

		self::installerOrder();

		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'the reinstall leaves pfB-DNS off');
		$this->assertSame('on', config_get_path(self::DNS_SECTION)[self::MARKER] ?? NULL, 'and keeps the marker');
	}
}
