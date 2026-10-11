<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3413 -- the global Suppression CIDR Limit defaults.
 *
 * A fresh install seeds IPv4 8 and IPv6 32; an existing install leaves the keys unseeded, so they read
 * Disabled and the upgrade changes no alias. The seed follows issue #2371's PSL policy fields: a seam
 * (pfb_install_suppression_cidr_seed) the installer calls AFTER the registry pass, never a
 * pfb_migration_registry() entry or a grandfather map. Freshness is the installer's own pre-migration
 * section mode (pfb_registry_section_modes), which the General-to-IP settings migration corrects to
 * OLDCFG, so an install upgrading from the General-tab layout is never seeded.
 *
 * pfblockerng_install.inc cannot be include()d off-appliance, so runInstallSequence() re-implements its
 * call order with the real functions and testInstallerCallsTheSeedAfterTheRegistryWriteback pins the
 * real file's order.
 */
#[CoversFunction('pfb_install_suppression_cidr_seed')]
#[CoversFunction('pfb_registry_section_modes')]
#[CoversFunction('pfb_registry_pass')]
final class SuppressionCidrLimitInstallTest extends TestCase
{
	private const IP = 'installedpackages/pfblockerngipsettings/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	/** The installer's order for the IP section: capture modes, run migrations, registry pass, then the seed. */
	private function runInstallSequence(): array
	{
		$sections = [];
		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		$modes = pfb_registry_section_modes($sections);

		pfb_run_migrations();

		foreach (PFB_SECTIONS as $section) {
			$sections[$section] = PfbConfig::readSection($section);
		}
		foreach (pfb_registry_pass($sections, NULL, $modes) as $section => $blob) {
			PfbConfig::writeSectionRawSystem($section, $blob);
		}

		pfb_install_suppression_cidr_seed($modes);

		return PfbConfig::readSection(self::IP);
	}

	/**
	 * Scenario: a fresh install seeds the defaults.
	 *   Given no IP settings were ever stored, When the install sequence runs,
	 *   Then the global limits are 8 (IPv4) and 32 (IPv6), stored and read back.
	 */
	public function testFreshInstallSeedsEightAndThirtyTwo(): void
	{
		$this->assertSame([], PfbConfig::readSection(self::IP), 'before: nothing stored');

		$ip = $this->runInstallSequence();

		$this->assertSame('8', $ip['suppression_cidr'] ?? NULL);
		$this->assertSame('32', $ip['suppression_cidr_v6'] ?? NULL);
		$this->assertSame(['8', '32'], [PfbConfig::read('ip/suppression_cidr'), PfbConfig::read('ip/suppression_cidr_v6')]);
	}

	/**
	 * The seed runs after the registry pass: a fresh install must still take the NEWCFG default of a sibling
	 * IP field whose grandfather map only an existing install may apply (autorule_suffix: fresh 'autorule').
	 */
	public function testFreshInstallDoesNotDisturbSiblingFieldDefaults(): void
	{
		$ip = $this->runInstallSequence();

		$this->assertSame('autorule', $ip['autorule_suffix'] ?? NULL);
	}

	/**
	 * Scenario: an upgrade changes nothing.
	 *   Given an existing install whose IP section never had the keys,
	 *   When the install sequence runs, Then the limits are never seeded and both read Disabled.
	 */
	public function testUpgradeNeverSeedsTheLimitsAndReadsThemDisabled(): void
	{
		PfbConfig::writeSectionRawSystem(self::IP, ['enable_dup' => 'on', 'suppression' => 'on', 'ip_placeholder' => '10.1.1.1']);

		$ip = $this->runInstallSequence();

		$this->assertNotSame('8', $ip['suppression_cidr'] ?? NULL, 'an upgrade must never be seeded 8');
		$this->assertNotSame('32', $ip['suppression_cidr_v6'] ?? NULL, 'an upgrade must never be seeded 32');
		$this->assertSame(['Disabled', 'Disabled'], [PfbConfig::read('ip/suppression_cidr'), PfbConfig::read('ip/suppression_cidr_v6')]);
		$this->assertSame('10.1.1.1', $ip['ip_placeholder'], 'a stored value is never replaced');
	}

	/** An upgrade keeps the limits an operator already stored. */
	public function testUpgradeKeepsAStoredLimit(): void
	{
		PfbConfig::writeSectionRawSystem(self::IP, ['enable_dup' => 'on', 'suppression_cidr' => '12', 'suppression_cidr_v6' => '48']);

		$ip = $this->runInstallSequence();

		$this->assertSame(['12', '48'], [$ip['suppression_cidr'] ?? NULL, $ip['suppression_cidr_v6'] ?? NULL]);
	}

	/** A package reinstall over an already-seeded box never re-seeds over the operator's own change. */
	public function testReinstallOverASeededBoxKeepsTheOperatorsValues(): void
	{
		$this->runInstallSequence();
		PfbConfig::writeSectionRawSystem(self::IP, ['suppression_cidr' => '5', 'suppression_cidr_v6' => '40'] + PfbConfig::readSection(self::IP));

		$ip = $this->runInstallSequence();

		$this->assertSame(['5', '40'], [$ip['suppression_cidr'] ?? NULL, $ip['suppression_cidr_v6'] ?? NULL]);
	}

	/** Seam, fresh: writes both keys in order, then flushes once with the documented message. */
	public function testSeamWritesBothKeysThenFlushesWhenTheIpSectionIsNew(): void
	{
		$order = [];
		pfb_install_suppression_cidr_seed(
			[self::IP => 'NEWCFG'],
			static function (string $key, mixed $value) use (&$order): void {
				$order[] = "write:{$key}={$value}";
			},
			static function (string $message) use (&$order): void {
				$order[] = "flush:{$message}";
			}
		);
		$this->assertSame([
			'write:ip/suppression_cidr=8',
			'write:ip/suppression_cidr_v6=32',
			'flush:pfBlockerNG: seeded the global Suppression CIDR Limit defaults for fresh install (issue #3413)',
		], $order);
	}

	/** @return iterable<string,array{0:array<string,string>}> */
	public static function notNewModes(): iterable
	{
		yield 'existing IP section'          => [[self::IP => 'OLDCFG']];
		yield 'only another section is new'  => [[self::IP => 'OLDCFG', 'installedpackages/pfblockerngdnsblsettings/config/0' => 'NEWCFG']];
		yield 'IP section absent from modes' => [['installedpackages/pfblockerngdnsblsettings/config/0' => 'NEWCFG']];
		yield 'no modes'                     => [[]];
	}

	/**
	 * Seam, not fresh: writes and flushes nothing (an unknown mode counts as existing, fail-safe).
	 *
	 * @param array<string,string> $modes
	 */
	#[DataProvider('notNewModes')]
	public function testSeamIsANoOpUnlessTheIpSectionIsNew(array $modes): void
	{
		$order = [];
		pfb_install_suppression_cidr_seed(
			$modes,
			static function (string $key) use (&$order): void {
				$order[] = "write:{$key}";
			},
			static function (string $message) use (&$order): void {
				$order[] = "flush:{$message}";
			}
		);
		$this->assertSame([], $order);
	}

	/**
	 * The wizard rebuilds the IP section from scratch (it wipes every pfBlockerNG section first), so it must
	 * write the fresh-install limits itself or the seed is lost the first time a user runs it.
	 */
	public function testWizardIpSectionCarriesTheFreshInstallLimits(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc');
		$start  = $source === FALSE ? FALSE : strpos($source, "\t\$new_config['pfblockerngipsettings']['config'][0]['enable_dup']");
		$end    = $start === FALSE ? FALSE : strpos($source, "\n\n\t// foreign section", $start);
		if ($source === FALSE || $start === FALSE || $end === FALSE) {
			throw new RuntimeException('test bootstrap: wizard IP section region not found');
		}

		$GLOBALS['config'] = ['pfblockerng_wizard' => ['step2' => ['inbound_interface' => 'wan', 'outbound_interface' => 'lan']]];
		$new_config = [];
		eval(substr($source, $start, $end - $start));
		$section = $new_config['pfblockerngipsettings']['config'][0] ?? NULL;
		$this->assertIsArray($section, 'vacuity guard: the wizard region built the IP section');
		$this->assertSame('wan', $section['inbound_interface'], 'vacuity guard: the region ran against the seeded wizard step');

		$GLOBALS['config'] = [];
		config_set_path(self::IP, $section);
		$this->assertSame(['8', '32'], [PfbConfig::read('ip/suppression_cidr'), PfbConfig::read('ip/suppression_cidr_v6')]);

		$pass = pfb_registry_pass([self::IP => $section])[self::IP] ?? $section;
		$this->assertSame(['8', '32'], [$pass['suppression_cidr'], $pass['suppression_cidr_v6']], 'the upgrade pass must keep the wizard defaults');
	}

	/**
	 * Wiring proof (pattern: PslFeedPolicyPipelineOrderingTest): the real installer calls the seed exactly once,
	 * after the registry write-back and before the section modes are discarded.
	 */
	public function testInstallerCallsTheSeedAfterTheRegistryWriteback(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$this->assertNotSame('', $source, 'installer source must be readable');

		$writeback = strpos($source, 'pfb_install_registry_writeback($pfb_registry_sections, $pfb_registry_modes);');
		$this->assertNotFalse($writeback, 'installer must write the registry pass back through its seam');
		$this->assertSame(1, substr_count($source, 'pfb_install_suppression_cidr_seed('), 'the installer must call the seed exactly once');
		$seed = strpos($source, 'pfb_install_suppression_cidr_seed($pfb_registry_modes);');
		$this->assertNotFalse($seed, 'the seed must be handed the installer\'s section modes');
		$this->assertGreaterThan($writeback, $seed, 'the seed must run AFTER the registry pass write-back');

		$discard = strpos($source, 'unset($pfb_registry_sections, $pfb_registry_section, $pfb_registry_modes);', $writeback);
		$this->assertNotFalse($discard);
		$this->assertLessThan($discard, $seed, 'the seed must read the modes before they are discarded');
	}
}
