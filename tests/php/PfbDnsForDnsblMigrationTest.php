<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3770 -- DNSBL runs only through pfB-DNS. The FIRST run of the migration on an install base (the upgrade out of the
 * v3.2 / pre-#3770 Unbound-hosted DNSBL world) turns pfB-DNS on where DNSBL is on, so the Resolver is not left with DNSBL
 * enabled but no host, and records the node-local marker `pfb_dns_dnsbl_migrated`. Every later run -- each reinstall or
 * upgrade -- is a no-op, so an administrator who then saves pfB-DNS off keeps it off. Everything else in the pfB-DNS section is
 * left as stored.
 */
#[CoversFunction('pfb_dns_dnsbl_migrate')]
#[CoversFunction('pfb_migration_registry')]
#[CoversFunction('pfb_run_migrations')]
final class PfbDnsForDnsblMigrationTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const DNS_SECTION   = 'installedpackages/pfblockerngdns/config/0';
	private const MIGRATION_ID  = 'issue3770-pfb-dns-for-dnsbl';
	private const MARKER        = 'pfb_dns_dnsbl_migrated';
	private const MARKER_KEY    = 'dns/pfb_dns_dnsbl_migrated';
	private const MESSAGE       = 'pfBlockerNG: migrated the pfB-DNS enable, because DNSBL runs only through pfB-DNS (issue #3770)';

	protected function setUp(): void
	{
		$GLOBALS['config']                      = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices']       = [];
	}

	/**
	 * Node-local pfB-DNS keys that must survive untouched; $pfb_dns is merged in unless NULL (key absent).
	 *
	 * @return array<string,mixed>
	 */
	private static function dnsSection(?string $pfb_dns): array
	{
		$section = ['pfb_dns_interface' => 'lan', 'pfb_dns_saved' => 'c2F2ZWQ='];
		return $pfb_dns === NULL ? $section : ['pfb_dns' => $pfb_dns] + $section;
	}

	/** The pfB-DNS section as the migration leaves it: the keys as stored, plus the run-once marker. */
	private static function markedDnsSection(?string $pfb_dns): array
	{
		return self::dnsSection($pfb_dns) + [self::MARKER => 'on'];
	}

	/** @return list<string> the write_config() messages this migration produced (other migrations may flush too) */
	private static function flushes(): array
	{
		return array_values(array_filter(
			$GLOBALS['pfb_test_write_config_calls'],
			static fn (string $message): bool => str_contains($message, 'issue #3770')
		));
	}

	// --- pure migration -----------------------------------------------------

	/** @return iterable<string,array{0:?string}> */
	public static function pfbDnsNotOnProvider(): iterable
	{
		yield 'pfB-DNS key absent' => [NULL];
		yield "pfB-DNS ''"         => [''];
		yield "pfB-DNS 'off'"      => ['off'];
		yield "pfB-DNS 'OFF'"      => ['OFF'];
		yield "pfB-DNS junk 'yes'" => ['yes'];
	}

	#[DataProvider('pfbDnsNotOnProvider')]
	public function testFirstRunWithDnsblOnTurnsPfbDnsOnMarksTheMigrationAndChangesNothingElse(?string $pfb_dns): void
	{
		$dns = self::dnsSection($pfb_dns);

		$migrated = pfb_dns_dnsbl_migrate([
			self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'pfb_py_reply' => 'on'],
			self::DNS_SECTION   => $dns,
		]);

		$this->assertNotNull($migrated, 'DNSBL on with pfB-DNS not on must migrate');
		$this->assertSame([self::DNS_SECTION], array_keys($migrated), 'only the pfB-DNS section is rewritten');
		$this->assertSame('on', $migrated[self::DNS_SECTION]['pfb_dns']);
		$this->assertSame('on', $migrated[self::DNS_SECTION][self::MARKER] ?? NULL, 'the run-once marker is recorded');
		unset($migrated[self::DNS_SECTION]['pfb_dns'], $migrated[self::DNS_SECTION][self::MARKER]);
		$this->assertSame(self::dnsSection(NULL), $migrated[self::DNS_SECTION], 'every other key survives byte for byte');
	}

	public function testFirstRunWithDnsblOnCreatesJustThePfbDnsEnableAndTheMarker(): void
	{
		$migrated = pfb_dns_dnsbl_migrate([self::DNSBL_SECTION => ['pfb_dnsbl' => 'on'], self::DNS_SECTION => []]);

		$this->assertSame([self::DNS_SECTION => ['pfb_dns' => 'on', self::MARKER => 'on']], $migrated);
	}

	#[DataProvider('pfbDnsNotOnProvider')]
	public function testOnceMarkedADeliberatePfbDnsOffWithDnsblOnIsLeftAlone(?string $pfb_dns): void
	{
		$this->assertNull(pfb_dns_dnsbl_migrate([
			self::DNSBL_SECTION => ['pfb_dnsbl' => 'on'],
			self::DNS_SECTION   => self::markedDnsSection($pfb_dns),
		]));
	}

	/** @return iterable<string,array{0:mixed}> */
	public static function dnsblNotOnProvider(): iterable
	{
		yield 'DNSBL key absent'      => [NULL];
		yield "DNSBL ''"              => [''];
		yield "DNSBL 'off'"           => ['off'];
		yield "DNSBL junk 'yes'"      => ['yes'];
		yield 'DNSBL non-scalar'      => [['on']];
	}

	#[DataProvider('dnsblNotOnProvider')]
	public function testFirstRunWithDnsblNotOnMarksTheMigrationAndLeavesPfbDnsAlone(mixed $stored): void
	{
		$dnsbl = $stored === NULL ? ['pfb_py_reply' => 'on'] : ['pfb_dnsbl' => $stored];

		$migrated = pfb_dns_dnsbl_migrate([self::DNSBL_SECTION => $dnsbl, self::DNS_SECTION => self::dnsSection('')]);

		$this->assertSame([self::DNS_SECTION => self::markedDnsSection('')], $migrated, 'only the marker is added: a later DNSBL On finds the run recorded');
	}

	/** A fresh install never lived in the Unbound-hosted DNSBL world: it is marked too, so a later deliberate Off survives. */
	public function testFirstRunOnAFreshInstallOnlyMarksTheMigration(): void
	{
		$this->assertSame(
			[self::DNS_SECTION => [self::MARKER => 'on']],
			pfb_dns_dnsbl_migrate([self::DNSBL_SECTION => [], self::DNS_SECTION => []])
		);
	}

	/** @return iterable<string,array{0:string}> */
	public static function pfbDnsOnProvider(): iterable
	{
		yield "'on'" => ['on'];
		yield "'ON' (case)" => ['ON'];
	}

	#[DataProvider('pfbDnsOnProvider')]
	public function testFirstRunWithPfbDnsAlreadyOnMarksTheMigrationAndKeepsTheStoredToken(string $stored): void
	{
		$this->assertSame(
			[self::DNS_SECTION => self::markedDnsSection($stored)],
			pfb_dns_dnsbl_migrate([self::DNSBL_SECTION => ['pfb_dnsbl' => 'on'], self::DNS_SECTION => self::dnsSection($stored)])
		);
	}

	public function testNonArraySectionsCountAsEmpty(): void
	{
		$this->assertSame(
			[self::DNS_SECTION => ['pfb_dns' => 'on', self::MARKER => 'on']],
			pfb_dns_dnsbl_migrate([self::DNSBL_SECTION => ['pfb_dnsbl' => 'on'], self::DNS_SECTION => 'junk'])
		);
		$this->assertSame(
			[self::DNS_SECTION => [self::MARKER => 'on']],
			pfb_dns_dnsbl_migrate([self::DNSBL_SECTION => 'junk', self::DNS_SECTION => []])
		);
	}

	// --- registry wiring ----------------------------------------------------

	public function testMigrationIsRegisteredLastAgainstTheDnsblAndDnsSections(): void
	{
		$registry = pfb_migration_registry();
		$last     = $registry[array_key_last($registry)];

		$this->assertSame(self::MIGRATION_ID, $last['id'], 'it runs after the #3649 split and every other migration');
		$this->assertSame([self::DNSBL_SECTION, self::DNS_SECTION], $last['sections']);
		$this->assertSame('pfb_dns_dnsbl_migrate', $last['apply']);
		$this->assertSame(self::MESSAGE, $last['message']);
		$this->assertSame('4.1.0', $last['since'], 'this work does not ship in 4.0');
		$this->assertCount(1, array_filter($registry, static fn (array $entry): bool => $entry['id'] === self::MIGRATION_ID));
	}

	public function testPfbDnsRegistryReasonNamesTheCrossSectionMigration(): void
	{
		$entry = pfb_cfg_registry()['dns/pfb_dns'];

		$this->assertStringContainsString('issue3770', $entry['no_grandfather'], 'the reason must cite the migration that decides it');
		$this->assertStringNotContainsString('nothing is migrated', $entry['no_grandfather'], 'a migration now exists');
	}

	public function testTheMigrationMarkerIsRegisteredAsNodeLocalState(): void
	{
		$entry = pfb_cfg_registry()[self::MARKER_KEY] ?? NULL;

		$this->assertIsArray($entry, 'the marker is registered through the gateway');
		$this->assertSame('', $entry['default'], 'absent means the migration has not run');
		$this->assertSame('local', $entry['sync'], 'a node-local marker never leaves the node');
		$this->assertStringContainsString('issue3770', $entry['no_grandfather'], 'the reason cites the migration it records');
		$this->assertSame(PfbToggle::Off, PfbConfig::read(self::MARKER_KEY), 'absent reads Off');
	}

	// --- end to end through pfb_run_migrations() ------------------------------

	#[DataProvider('pfbDnsNotOnProvider')]
	public function testRunMigrationsTurnsPfbDnsOnOnceAndASecondRunIsANoOp(?string $pfb_dns): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::DNS_SECTION, self::dnsSection($pfb_dns));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'before: pfB-DNS reads Off');

		pfb_run_migrations();

		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns'));
		$stored = config_get_path(self::DNS_SECTION);
		$this->assertSame('on', $stored['pfb_dns']);
		$this->assertSame('on', $stored[self::MARKER] ?? NULL, 'the run-once marker is recorded');
		unset($stored['pfb_dns'], $stored[self::MARKER]);
		$this->assertSame(self::dnsSection(NULL), $stored, 'the other pfB-DNS keys are unchanged');
		$this->assertSame('on', config_get_path(self::DNSBL_SECTION)['pfb_dnsbl'], 'DNSBL is left on');
		$this->assertSame([self::MESSAGE], self::flushes(), 'exactly one flush, with the migration message');

		$section_after_first = config_get_path(self::DNS_SECTION);
		$all_flushes         = count($GLOBALS['pfb_test_write_config_calls']);

		pfb_run_migrations();

		$this->assertSame($section_after_first, config_get_path(self::DNS_SECTION), 'a second run changes nothing');
		$this->assertSame($all_flushes, count($GLOBALS['pfb_test_write_config_calls']), 'a second run flushes nothing at all');
	}

	public function testRunMigrationsCreatesAnAbsentPfbDnsSectionOnAnUpgradeWithDnsblOn(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		$this->assertNull(config_get_path(self::DNS_SECTION, NULL), 'before: no pfB-DNS section');

		pfb_run_migrations();

		$this->assertSame(['pfb_dns' => 'on', self::MARKER => 'on'], config_get_path(self::DNS_SECTION));
		$this->assertSame([self::MESSAGE], self::flushes());
	}

	/** @return iterable<string,array{0:?array<string,string>}> */
	public static function dnsblNotOnSectionProvider(): iterable
	{
		yield 'DNSBL section absent (fresh install)' => [NULL];
		yield 'DNSBL section empty'                  => [[]];
		yield "DNSBL ''"                             => [['pfb_dnsbl' => '']];
		yield "DNSBL 'off'"                          => [['pfb_dnsbl' => 'off']];
	}

	/** @param ?array<string,string> $dnsbl */
	#[DataProvider('dnsblNotOnSectionProvider')]
	public function testRunMigrationsMarksButLeavesPfbDnsAsStoredWhenDnsblIsNotOn(?array $dnsbl): void
	{
		if ($dnsbl !== NULL) {
			config_set_path(self::DNSBL_SECTION, $dnsbl);
		}
		config_set_path(self::DNS_SECTION, self::dnsSection('off'));

		pfb_run_migrations();

		$this->assertSame(self::markedDnsSection('off'), config_get_path(self::DNS_SECTION), 'pfB-DNS stays as stored, and the run is recorded');
		$this->assertSame([self::MESSAGE], self::flushes());
	}

	public function testRunMigrationsMarksAFreshInstallWithNoSectionsAndWritesNothingElse(): void
	{
		pfb_run_migrations();

		$this->assertSame([self::MARKER => 'on'], config_get_path(self::DNS_SECTION, NULL));
		$this->assertSame([self::MESSAGE], self::flushes());
	}

	#[DataProvider('pfbDnsOnProvider')]
	public function testRunMigrationsMarksPfbDnsAlreadyOnWithoutRewritingIt(string $stored): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::DNS_SECTION, self::dnsSection($stored));

		pfb_run_migrations();

		$this->assertSame(self::markedDnsSection($stored), config_get_path(self::DNS_SECTION), "the stored token {$stored} is not rewritten, and the run is recorded");
		$this->assertSame([self::MESSAGE], self::flushes());
	}

	/** The Codex P2 on PR #3792: each reinstall re-ran the migration and turned back on what the administrator had saved off. */
	#[DataProvider('pfbDnsNotOnProvider')]
	public function testAReinstallKeepsPfbDnsOffWhenTheAdministratorSavedItOffAfterTheFirstUpgrade(?string $pfb_dns): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::DNS_SECTION, self::dnsSection($pfb_dns));
		pfb_run_migrations();
		$this->assertSame(PfbToggle::On, PfbConfig::read('dns/pfb_dns'), 'before: the first upgrade turned pfB-DNS on');
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'before: the administrator saved pfB-DNS off');
		$flushes = count($GLOBALS['pfb_test_write_config_calls']);

		pfb_run_migrations();

		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'the reinstall leaves pfB-DNS off');
		$this->assertSame($flushes, count($GLOBALS['pfb_test_write_config_calls']), 'and writes nothing');
	}

	public function testDnsblTurnedOnAfterAFirstRunWithDnsblOffLeavesAStoredPfbDnsOffAlone(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => '']);
		config_set_path(self::DNS_SECTION, self::dnsSection('off'));
		pfb_run_migrations();
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'before: the first run, with DNSBL off, left pfB-DNS off');
		config_set_path(self::DNSBL_SECTION . '/pfb_dnsbl', 'on');
		$this->assertSame(PfbToggle::On, PfbConfig::read('dnsbl/pfb_dnsbl'), 'before: DNSBL is on now');

		pfb_run_migrations();

		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'a later DNSBL On with pfB-DNS Off is the administrator\'s choice');
	}

	public function testAFreshInstallKeepsALaterDeliberatePfbDnsOffThroughAReinstall(): void
	{
		pfb_run_migrations();
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::DNS_SECTION . '/pfb_dns', 'off');
		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'before: pfB-DNS is off with DNSBL on');

		pfb_run_migrations();

		$this->assertSame(PfbToggle::Off, PfbConfig::read('dns/pfb_dns'), 'the reinstall leaves it off');
	}

	/** The installer runs the registry pass after the migrations; its default must not undo the migrated value. */
	public function testInstallerSequenceKeepsTheMigratedPfbDns(): void
	{
		config_set_path(self::DNSBL_SECTION, ['pfb_dnsbl' => 'on']);
		config_set_path(self::DNS_SECTION, self::dnsSection(''));
		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$modes = pfb_registry_section_modes($sections);

		pfb_run_migrations();

		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$result = pfb_registry_pass($sections, NULL, $modes);

		$stored = $result[self::DNS_SECTION] ?? $sections[self::DNS_SECTION];
		$this->assertSame('on', $stored['pfb_dns'] ?? NULL);
		$this->assertSame('on', $stored[self::MARKER] ?? NULL, 'and so does the run-once marker');
	}
}
