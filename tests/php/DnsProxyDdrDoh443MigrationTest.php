<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694 -- upgrading from the two per-family "Advertise DoH on port 443" checkboxes (`pfb_dns_ddr_doh_443`, `pfb_dns_ddr_doh_443_6`) to
 * the per-interface selection `dns/pfb_dns_ddr_doh_443_interfaces`: the migration `issue3694-ddr-doh-443-interfaces` selects every DoH
 * interface (Localhost excepted) when either old toggle was on, in either section it may still be stored in, files one notice that says
 * so, and removes both old keys whenever they are stored, on or off. A second run changes nothing and says nothing.
 */
#[CoversFunction('pfb_dns_ddr_doh_443_migrate')]
#[CoversFunction('pfb_run_migrations')]
final class DnsProxyDdrDoh443MigrationTest extends TestCase
{
	private const NOTICE = 'pfB-DNS: Advertise DoH on port 443 is now chosen per interface. The old option was on, so every DoH interface is selected; review the selection on the pfB-DNS page.';
	private const NEW = 'pfb_dns_ddr_doh_443_interfaces';

	/** @var array<string,array{0:bool,1:mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb_test_file_notices', 'pfb_test_write_config_calls'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $name => [$exists, $value]) {
			if ($exists) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	/**
	 * @param array<string,mixed> $dns the pfB-DNS section as stored
	 * @param array<string,mixed> $shared the shared transport section as stored
	 * @return array<string,array<string,mixed>>|null
	 */
	private function migrate(array $dns, array $shared): ?array
	{
		return pfb_dns_ddr_doh_443_migrate([PFB_SECTIONS['dns'] => $dns, PFB_SECTIONS['dns_shared'] => $shared]);
	}

	/** @return list<array{id:string,notice:string,category:string,url:string,priority:int}> */
	private function notices(): array
	{
		return array_map(
			static fn (array $notice): array => array_intersect_key($notice, array_flip(['id', 'notice', 'category', 'url', 'priority'])),
			$GLOBALS['pfb_test_file_notices']
		);
	}

	private static function notice(): array
	{
		return ['id' => 'pfBlockerNG DNS', 'notice' => self::NOTICE, 'category' => 'pfBlockerNG', 'url' => '/pfblockerng/pfblockerng_dns.php', 'priority' => 2];
	}

	// -----------------------------------------------------------------------
	// the registry
	// -----------------------------------------------------------------------

	public function testTheMigrationIsLastInTheRegistryAndReadsBothDnsSections(): void
	{
		$registry = pfb_migration_registry();
		$entry = end($registry);

		$this->assertSame('issue3694-ddr-doh-443-interfaces', $entry['id']);
		$this->assertSame([PFB_SECTIONS['dns'], PFB_SECTIONS['dns_shared']], $entry['sections']);
		$this->assertSame('pfb_dns_ddr_doh_443_migrate', $entry['apply']);
		$this->assertArrayNotHasKey('section', $entry);
		$this->assertNotSame('', $entry['message']);
		$this->assertSame('issue3649-dns-settings-split', $registry[count($registry) - 2]['id'], 'it follows the split that moved the old keys');
	}

	// -----------------------------------------------------------------------
	// a toggle that was on selects every DoH interface
	// -----------------------------------------------------------------------

	/** @return array<string,array{array<string,mixed>,array<string,mixed>,string}> the pfB-DNS section, the shared section, the selection stored */
	public static function togglesThatWereOn(): array
	{
		$doh = ['pfb_dns_doh_interface' => 'lan,opt1'];
		return [
			'the IPv4 toggle' => [$doh, ['pfb_dns_ddr_doh_443' => 'on'], 'lan,opt1'],
			'the IPv6 toggle' => [$doh, ['pfb_dns_ddr_doh_443_6' => 'on'], 'lan,opt1'],
			'both' => [$doh, ['pfb_dns_ddr_doh_443' => 'on', 'pfb_dns_ddr_doh_443_6' => 'on'], 'lan,opt1'],
			'capitals' => [$doh, ['pfb_dns_ddr_doh_443' => 'ON'], 'lan,opt1'],
			'the toggle still in the pfB-DNS section (a configuration from before the split)' => [$doh + ['pfb_dns_ddr_doh_443' => 'on'], [], 'lan,opt1'],
			'on in one section, off in the other' => [$doh + ['pfb_dns_ddr_doh_443' => ''], ['pfb_dns_ddr_doh_443' => 'on'], 'lan,opt1'],
			'Localhost is not selected' => [['pfb_dns_doh_interface' => 'lo0,lan'], ['pfb_dns_ddr_doh_443' => 'on'], 'lan'],
			'Localhost alone leaves nothing to select' => [['pfb_dns_doh_interface' => 'lo0'], ['pfb_dns_ddr_doh_443' => 'on'], ''],
			'an empty DoH list (not seeded yet) selects nothing, but the notice is still filed' => [['pfb_dns_doh_interface' => ''], ['pfb_dns_ddr_doh_443' => 'on'], ''],
			'no DoH list at all' => [[], ['pfb_dns_ddr_doh_443' => 'on'], ''],
			'a list with spaces and a repeat' => [['pfb_dns_doh_interface' => 'lan, opt1 lan'], ['pfb_dns_ddr_doh_443' => 'on'], 'lan,opt1'],
			'the All token' => [['pfb_dns_doh_interface' => 'all'], ['pfb_dns_ddr_doh_443' => 'on'], 'all'],
		];
	}

	/**
	 * @param array<string,mixed> $dns
	 * @param array<string,mixed> $shared
	 */
	#[DataProvider('togglesThatWereOn')]
	public function testEitherOldToggleOnSelectsEveryDohInterfaceFilesTheNoticeAndRemovesBothKeys(array $dns, array $shared, string $selected): void
	{
		$result = $this->migrate($dns, $shared);

		$this->assertNotNull($result);
		$this->assertSame($selected, $result[PFB_SECTIONS['dns']][self::NEW] ?? NULL);
		foreach ([PFB_SECTIONS['dns'], PFB_SECTIONS['dns_shared']] as $path) {
			$this->assertArrayNotHasKey('pfb_dns_ddr_doh_443', $result[$path]);
			$this->assertArrayNotHasKey('pfb_dns_ddr_doh_443_6', $result[$path]);
		}
		$this->assertSame([self::notice()], $this->notices());
	}

	public function testBystanderKeysOfBothSectionsAreLeftExactlyAsStored(): void
	{
		$dns = ['pfb_dns' => 'on', 'pfb_dns_saved' => 'SNAPSHOT', 'pfb_dns_interface' => 'lan', 'pfb_dns_doh_interface' => 'lan', 'pfb_dns_name' => 'FW.Example.lan'];
		$shared = ['pfb_dns_doh' => 'on', 'pfb_dns_doh_port' => '4443', 'pfb_dns_ddr' => 'on', 'pfb_dns_ddr_doh_443' => 'on', 'pfb_dns_ddr_doh_443_6' => ''];

		$result = $this->migrate($dns, $shared);

		$this->assertSame($dns + [self::NEW => 'lan'], $result[PFB_SECTIONS['dns']]);
		$this->assertSame(['pfb_dns_doh' => 'on', 'pfb_dns_doh_port' => '4443', 'pfb_dns_ddr' => 'on'], $result[PFB_SECTIONS['dns_shared']]);
	}

	// -----------------------------------------------------------------------
	// a toggle that was off (or junk) is removed and selects nothing
	// -----------------------------------------------------------------------

	/** @return array<string,array{array<string,mixed>}> the shared section */
	public static function togglesThatWereNotOn(): array
	{
		return [
			'both off, stored empty' => [['pfb_dns_ddr_doh_443' => '', 'pfb_dns_ddr_doh_443_6' => '']],
			'off' => [['pfb_dns_ddr_doh_443' => 'off']],
			'yes is no toggle value' => [['pfb_dns_ddr_doh_443' => 'yes', 'pfb_dns_ddr_doh_443_6' => '1']],
			'an array' => [['pfb_dns_ddr_doh_443' => ['on']]],
			'only the IPv6 key, empty' => [['pfb_dns_ddr_doh_443_6' => '']],
		];
	}

	/** @param array<string,mixed> $shared */
	#[DataProvider('togglesThatWereNotOn')]
	public function testAToggleThatWasNotOnIsRemovedSelectsNothingAndFilesNoNotice(array $shared): void
	{
		$result = $this->migrate(['pfb_dns_doh_interface' => 'lan'], $shared);

		$this->assertNotNull($result, 'the retired key is removed');
		$this->assertSame(['pfb_dns_doh_interface' => 'lan'], $result[PFB_SECTIONS['dns']], 'nothing is selected');
		$this->assertSame([], $result[PFB_SECTIONS['dns_shared']]);
		$this->assertSame([], $this->notices());
	}

	public function testNothingToMigrateIsNull(): void
	{
		$dns = ['pfb_dns_doh_interface' => 'lan'];
		$shared = ['pfb_dns_doh' => 'on'];

		$this->assertNull($this->migrate($dns, $shared));
		$this->assertNull($this->migrate([], []));
		$this->assertSame([], $this->notices());
	}

	public function testASelectionThatIsAlreadyStoredIsKeptAndNoNoticeIsFiled(): void
	{
		$result = $this->migrate(['pfb_dns_doh_interface' => 'lan,opt1', self::NEW => 'opt1'], ['pfb_dns_ddr_doh_443' => 'on']);

		$this->assertSame('opt1', $result[PFB_SECTIONS['dns']][self::NEW], 'the operator\'s own choice wins');
		$this->assertArrayNotHasKey('pfb_dns_ddr_doh_443', $result[PFB_SECTIONS['dns_shared']]);
		$this->assertSame([], $this->notices(), 'nothing was selected for them');
	}

	public function testASecondRunWritesNothingAndSaysNothing(): void
	{
		$first = $this->migrate(['pfb_dns_doh_interface' => 'lan,opt1'], ['pfb_dns_ddr_doh_443' => 'on']);
		$this->assertNotNull($first, 'before: the first run migrates');
		$this->assertCount(1, $this->notices());

		$this->assertNull($this->migrate($first[PFB_SECTIONS['dns']], $first[PFB_SECTIONS['dns_shared']]));
		$this->assertCount(1, $this->notices(), 'no second notice');
	}

	// -----------------------------------------------------------------------
	// through the driver
	// -----------------------------------------------------------------------

	public function testTheDriverPersistsTheSelectionRawInOneWriteAndIsIdempotent(): void
	{
		config_set_path(PFB_SECTIONS['dns'], ['pfb_dns' => 'on', 'pfb_dns_interface' => 'lan', 'pfb_dns_doh_interface' => 'lo0,lan,opt1']);
		config_set_path(PFB_SECTIONS['dns_shared'], ['pfb_dns_doh' => 'on', 'pfb_dns_ddr_doh_443' => 'on', 'pfb_dns_ddr_doh_443_6' => 'on']);

		pfb_run_migrations();

		$this->assertSame(
			['pfb_dns' => 'on', 'pfb_dns_interface' => 'lan', 'pfb_dns_doh_interface' => 'lo0,lan,opt1', self::NEW => 'lan,opt1'],
			PfbConfig::readSection(PFB_SECTIONS['dns'])
		);
		$this->assertSame(['pfb_dns_doh' => 'on'], PfbConfig::readSection(PFB_SECTIONS['dns_shared']));
		$this->assertSame([self::notice()], $this->notices());
		$writes = $GLOBALS['pfb_test_write_config_calls'];
		$before = $GLOBALS['config'];

		pfb_run_migrations();

		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame($writes, $GLOBALS['pfb_test_write_config_calls'], 'a second run writes nothing');
		$this->assertCount(1, $this->notices());
	}

	public function testTheDriverRemovesAnOffToggleWithoutANotice(): void
	{
		config_set_path(PFB_SECTIONS['dns'], ['pfb_dns_doh_interface' => 'lan']);
		config_set_path(PFB_SECTIONS['dns_shared'], ['pfb_dns_ddr_doh_443' => '', 'pfb_dns_ddr_doh_443_6' => '']);

		pfb_run_migrations();

		$this->assertSame(['pfb_dns_doh_interface' => 'lan'], PfbConfig::readSection(PFB_SECTIONS['dns']));
		$this->assertSame([], PfbConfig::readSection(PFB_SECTIONS['dns_shared']));
		$this->assertSame([], $this->notices());
	}
}
