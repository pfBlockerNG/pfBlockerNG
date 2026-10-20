<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- pfSense's delete_package_xml() deletes the package's menu entry and its three service registrations BEFORE the
 * package's pre-deinstall hook runs, and persists that. A removal the hook then aborts keeps the package installed, so the
 * hook must register them again or nothing can start the proxy and a retry can never stop it.
 *
 * No narrow pfSense routine does it (install_package_xml() also runs the install and resync commands), so
 * pfb_package_registration_restore() repeats install_package_xml()'s two blocks (pkg-utils.inc: "sidebar items" and "services"):
 * append what the package XML lists unless an entry of the same name is registered (menu: same name and section), over
 * the config.xml pfSense left, never over a stale in-memory copy.
 *
 * Intent pinned here:
 *   - the XML's menu and services come back, after every other package's entries, which are untouched;
 *   - nothing is ever registered twice, and an entry already there keeps its own fields;
 *   - it works on config.xml read afresh under the config lock, so a save another process made since this one read it is kept;
 *   - a lock that stays taken, a config.xml that does not read, or a package file that lists nothing writes nothing,
 *     releases the lock and says why (NULL is the only success).
 */
#[CoversFunction('pfb_package_registration_restore')]
final class PackageRegistrationRestoreTest extends TestCase
{
	private const LOCK = 'pfb_dns_config';
	private const DOUBLE_GLOBALS = ['pfb_test_lock_events', 'pfb_test_lock_held', 'pfb_test_try_lock_fail', 'pfb_test_try_lock_busy_for',
		'pfb_test_config_read_hook', 'pfb_test_config_read_fails', 'pfb_test_config_read_fails_for', 'pfb_test_config_read_calls',
		'pfb_test_config_read_lock_held', 'pfb_test_write_config_hook', 'pfb_test_write_config_calls', 'pfb_test_file_notices'];

	private const SQUID = [
		'name' => 'squid', 'rcfile' => 'squid.sh', 'executable' => 'squid', 'description' => 'Squid proxy',
		'custom_php_service_status_command' => 'return TRUE;',
	];
	private const SQUID_MENU = ['name' => 'Squid', 'section' => 'Services', 'url' => '/pkg_edit.php?xml=squid.xml'];

	private string $tmp;
	private bool $hadPfb = FALSE;
	private bool $hadConfig = FALSE;
	private array $originalPfb = [];
	private array $originalConfig = [];
	/** @var list<array<string,mixed>> config.xml as write_config() persisted it, one entry per write */
	private array $written = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		foreach (self::DOUBLE_GLOBALS as $name) {
			unset($GLOBALS[$name]);
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_pkg_registration_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, ['logdir' => $this->tmp, 'log' => "{$this->tmp}/pfb.log", 'errlog' => "{$this->tmp}/pfb.err"]);
		// config.xml as pfSense's removal left it: the package's entries gone, another package's there
		$GLOBALS['config'] = ['installedpackages' => ['service' => [self::SQUID], 'menu' => [self::SQUID_MENU]]];
		$this->written = [];
		$GLOBALS['pfb_test_write_config_hook'] = function (string $desc): void {
			$this->written[] = $GLOBALS['config'];
		};
	}

	protected function tearDown(): void
	{
		foreach (self::DOUBLE_GLOBALS as $name) {
			unset($GLOBALS[$name]);
		}
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		rmdir_recursive($this->tmp);
	}

	/** @return list<string> */
	private function serviceNames(): array
	{
		return array_values(array_map(static fn (array $s): string => (string) $s['name'], config_get_path('installedpackages/service', [])));
	}

	/** @return list<string> */
	private function menuNames(): array
	{
		return array_values(array_map(static fn (array $m): string => "{$m['section']}:{$m['name']}", config_get_path('installedpackages/menu', [])));
	}

	private function lockHeld(): bool
	{
		return !empty($GLOBALS['pfb_test_lock_held']);
	}

	public function testRegistersTheMenuAndServicesThePackageXmlListsAfterEveryOtherPackagesAndLeavesThoseAlone(): void
	{
		$this->assertSame(['squid'], $this->serviceNames(), 'before: only another package\'s service is registered');

		$why = pfb_package_registration_restore();

		$this->assertNull($why);
		$this->assertSame(['squid', 'pfb_dnsbl', 'pfb_dns_proxy', 'pfb_filter'], $this->serviceNames(), 'the XML\'s services, in its order, after the other package\'s');
		$this->assertSame(['Services:Squid', 'Firewall:pfBlockerNG'], $this->menuNames());
		$services = config_get_path('installedpackages/service');
		$this->assertSame(self::SQUID, $services[0], 'the other package\'s service is untouched, field for field');
		$this->assertSame(self::SQUID_MENU, config_get_path('installedpackages/menu/0'), 'and so is its menu entry');
		$this->assertSame([
			'name' => 'pfb_dns_proxy', 'rcfile' => 'pfb_dns_proxy.sh',
			'custom_php_service_status_command' => "isvalidpid('/var/run/pfb_dns_proxy.pid')", 'description' => 'pfBlockerNG DNS proxy (experimental)',
		], $services[2], 'an entry is exactly what the XML lists, status command included: that is what Status > Services reads');
		$this->assertSame(['name' => 'pfBlockerNG', 'section' => 'Firewall', 'url' => '/pfblockerng/pfblockerng_general.php'], config_get_path('installedpackages/menu/1'));
	}

	public function testPersistsTheRegistrationOnceAndTheFileHoldsIt(): void
	{
		pfb_package_registration_restore();

		$this->assertCount(1, $this->written, 'config.xml is written once');
		$this->assertSame(['squid', 'pfb_dnsbl', 'pfb_dns_proxy', 'pfb_filter'],
			array_column($this->written[0]['installedpackages']['service'], 'name'), 'and what is written holds the registration');
	}

	public function testRegisteringAgainAddsNothing(): void
	{
		pfb_package_registration_restore();
		$once = config_get_path('installedpackages');

		$why = pfb_package_registration_restore();

		$this->assertNull($why);
		$this->assertSame($once, config_get_path('installedpackages'), 'nothing is added twice: neither a service nor the menu entry');
		$this->assertSame(['squid', 'pfb_dnsbl', 'pfb_dns_proxy', 'pfb_filter'], $this->serviceNames());
	}

	public function testAnEntryAlreadyRegisteredKeepsItsOwnFieldsAndOnlyTheMissingOnesAreAdded(): void
	{
		// Given another save registered the filter service with fields of its own, and a menu entry of the package's name.
		$filter = ['name' => 'pfb_filter', 'rcfile' => 'pfb_filter.sh', 'executable' => 'php_pfb', 'description' => 'registered earlier', 'starts_on_sync' => ''];
		$menu = ['name' => 'pfBlockerNG', 'section' => 'Firewall', 'url' => '/pfblockerng/other.php'];
		$GLOBALS['config']['installedpackages']['service'][] = $filter;
		$GLOBALS['config']['installedpackages']['menu'][] = $menu;

		$why = pfb_package_registration_restore();

		$this->assertNull($why);
		$this->assertSame(['squid', 'pfb_filter', 'pfb_dnsbl', 'pfb_dns_proxy'], $this->serviceNames(), 'the other two come in after it, it is not added again');
		$this->assertSame($filter, config_get_path('installedpackages/service/1'), 'and it keeps the fields it was registered with');
		$this->assertSame(['Services:Squid', 'Firewall:pfBlockerNG'], $this->menuNames(), 'the menu entry is matched by name and section');
		$this->assertSame($menu, config_get_path('installedpackages/menu/1'), 'and kept as it was');
	}

	public function testAMenuEntryOfTheSameNameInAnotherSectionDoesNotCountAsRegistered(): void
	{
		// Given a menu entry named like the package's, in the Services section (pfSense matches a menu by name and section)
		$GLOBALS['config']['installedpackages']['menu'][] = ['name' => 'pfBlockerNG', 'section' => 'Services', 'url' => '/pfblockerng/other.php'];

		$why = pfb_package_registration_restore();

		$this->assertNull($why);
		$this->assertSame(['Services:Squid', 'Services:pfBlockerNG', 'Firewall:pfBlockerNG'], $this->menuNames(),
			'the package entry is added beside the one in another section');
	}

	/** @return array<string,array{mixed}> pfSense's write_config() answers for a write it did not make: -1 (config.xml not written), FALSE (refused) */
	public static function refusedWrites(): array
	{
		return ['config.xml could not be written' => [-1], 'the write is refused' => [FALSE]];
	}

	#[\PHPUnit\Framework\Attributes\DataProvider('refusedWrites')]
	public function testAWriteThatPfSenseRefusesIsNotReportedAsARegistration(mixed $answer): void
	{
		// Given pfSense does not write config.xml for the registration
		$GLOBALS['pfb_test_write_config_result'] = $answer;
		try {
			// When the registration is written
			$why = pfb_package_registration_restore();
		} finally {
			unset($GLOBALS['pfb_test_write_config_result']);
		}

		// Then it is not reported as registered
		$this->assertIsString($why, 'the registration is not written, so it is not registered');
		$this->assertStringContainsString('could not be written', $why);
	}

	public function testKeepsASaveAnotherProcessMadeSinceThisOneReadConfigXml(): void
	{
		// Given config.xml on disk holds a service another process registered after this process read it.
		$onDisk = $GLOBALS['config'];
		$onDisk['installedpackages']['service'][] = ['name' => 'redis', 'rcfile' => 'redis.sh', 'description' => 'Redis'];
		$GLOBALS['pfb_test_config_read_hook'] = static function () use ($onDisk): void {
			if (end($GLOBALS['pfb_test_config_read_calls']) === [FALSE, FALSE]) {
				$GLOBALS['config'] = $onDisk;
			}
		};
		$this->assertNotContains('redis', $this->serviceNames(), 'before: this process has not seen it');

		$why = pfb_package_registration_restore();

		$this->assertNull($why);
		$this->assertSame(['squid', 'redis', 'pfb_dnsbl', 'pfb_dns_proxy', 'pfb_filter'], array_column($this->written[0]['installedpackages']['service'], 'name'),
			'what was written is the fresh copy plus the registration: the other process\'s save is not erased');
	}

	public function testTakesTheConfigLockBeforeTheFreshReadAndReleasesItAfterTheWrite(): void
	{
		$order = [];
		$GLOBALS['pfb_test_config_read_hook'] = static function () use (&$order): void {
			if (end($GLOBALS['pfb_test_config_read_calls']) === [FALSE, FALSE]) {
				$order[] = 'fresh read' . (!empty($GLOBALS['pfb_test_lock_held']) ? ':locked' : ':unlocked');
			}
		};
		$GLOBALS['pfb_test_write_config_hook'] = static function (string $desc) use (&$order): void {
			$order[] = 'write' . (!empty($GLOBALS['pfb_test_lock_held']) ? ':locked' : ':unlocked');
		};

		pfb_package_registration_restore();

		$this->assertSame(['fresh read:locked', 'write:locked'], $order, 'one fresh read and the write, both under the lock');
		$this->assertSame(['try_lock', self::LOCK], array_slice($GLOBALS['pfb_test_lock_events'][0], 0, 2));
		$this->assertSame(['unlock'], $GLOBALS['pfb_test_lock_events'][1], 'released right after');
		$this->assertFalse($this->lockHeld());
	}

	public function testALockThatStaysTakenWritesNothingAndSaysWhy(): void
	{
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$before = $GLOBALS['config'];

		$why = pfb_package_registration_restore();

		$this->assertIsString($why);
		$this->assertStringContainsString('locked by another save', $why);
		$this->assertSame($before, $GLOBALS['config'], 'the in-memory copy is untouched');
		$this->assertSame([], $this->written, 'nothing is written: a stale copy must never be saved over what the lock holder is writing');
		$this->assertSame([], $GLOBALS['pfb_test_config_read_calls'] ?? [], 'and config.xml is not read without the lock');
	}

	public function testAConfigXmlThatCannotBeReadAgainWritesNothingAndReleasesTheLock(): void
	{
		$GLOBALS['pfb_test_config_read_fails'] = TRUE;

		$why = pfb_package_registration_restore();

		$this->assertIsString($why);
		$this->assertStringContainsString('could not be re-read', $why);
		$this->assertSame([], $this->written, 'a copy that could not be refreshed is not written back');
		$this->assertSame(['squid'], $this->serviceNames());
		$this->assertFalse($this->lockHeld(), 'the lock is released');
	}

	public function testAPackageFileThatListsNothingIsReportedAndNothingIsWritten(): void
	{
		$empty = "{$this->tmp}/empty.xml";
		file_put_contents($empty, "<?xml version=\"1.0\"?>\n<packagegui><name>pfblockerng</name></packagegui>\n");

		foreach ([$empty, "{$this->tmp}/missing.xml"] as $file) {
			$why = pfb_package_registration_restore($file);

			$this->assertIsString($why, $file);
			$this->assertStringContainsString($file, (string) $why, 'the operator is told which file');
		}
		$this->assertSame([], $this->written);
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'] ?? [], 'and no lock is taken for nothing');
	}
}
