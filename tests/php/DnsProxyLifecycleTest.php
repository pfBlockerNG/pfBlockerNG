<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- when the proxy daemon is started and stopped, relative to the Resolver:
 *
 *   - the proxy is stopped BEFORE the Resolver is restored, so Unbound's regeneration finds port 53 free
 *     (pfb_dns_proxy_resolver(FALSE), the one place every "turn it off" path goes through);
 *   - package removal always hands the Resolver back and stops the proxy, whatever the disable pass
 *     returned (pfb_dns_proxy_deinstall(), called right after the pass);
 *   - a Resolver that is still moved while the saved copy is lost or malformed cannot be put back
 *     automatically: the operator is told through a notice naming the keys to check, not only a log line;
 *   - the installer regenerates the rc script and restarts the proxy while the Resolver is moved, stops it
 *     otherwise (pfb_dns_proxy_service_sync());
 *   - pfblockerng.xml registers the service with a pidfile-based status command.
 */
#[CoversFunction('pfb_dns_proxy_resolver')]
#[CoversFunction('pfb_dns_proxy_deinstall')]
#[CoversFunction('pfb_dns_proxy_service_sync')]
final class DnsProxyLifecycleTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dns_proxy_saved';
	private const LINE  = 'proxy-protocol-port: 5353';
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_service_hook', 'pfb_test_write_config_calls',
		'pfb_test_unbound_configure_calls', 'pfb_test_file_notices', 'pfb_test_rcfiles', 'pfb_test_rcfile_writes',
		'pfb_test_valid_pids',
	];

	private string $tmp;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			unset($GLOBALS[$name]);
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_proxy_life_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->tmp,
			'log'    => "{$this->tmp}/pfb.log",
			'errlog' => "{$this->tmp}/pfb.err",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_unbound_configure_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->tmp);
	}

	/** The user's Resolver before the proxy touched it. */
	private static function originalResolver(): array
	{
		return [
			'enable'           => '',
			'sslcertref'       => 'cert123',
			'tlsport'          => '853',
			'port'             => '53',
			'active_interface' => 'lan,opt1',
			'enablessl'        => '',
			'custom_options'   => base64_encode("do-ip6: no\nprefetch: yes"),
		];
	}

	/** The same Resolver as the proxy leaves it. */
	private static function movedResolver(): array
	{
		$moved = self::originalResolver();
		$moved['port'] = '5353';
		$moved['active_interface'] = 'lo0';
		unset($moved['enablessl']);
		$moved['custom_options'] = base64_encode(self::LINE . "\ndo-ip6: no\nprefetch: yes");
		return $moved;
	}

	private static function snapshotOfOriginal(): string
	{
		$original = self::originalResolver();
		$keys = [];
		foreach (['port', 'active_interface', 'enablessl', 'custom_options'] as $key) {
			$keys[$key] = ['present' => TRUE, 'value' => $original[$key]];
		}
		return base64_encode((string) json_encode($keys));
	}

	/** config.xml exactly as a proxy-On apply leaves it: moved Resolver plus its saved copy. */
	private function seedMovedResolver(): void
	{
		$GLOBALS['config']['unbound'] = self::movedResolver();
		config_set_path(self::SAVED, self::snapshotOfOriginal());
	}

	private static function sorted(array $unbound): array
	{
		ksort($unbound);
		return $unbound;
	}

	/** @return list<array{string,string}> service calls (function, service) in order */
	private function serviceCalls(): array
	{
		return $GLOBALS['pfb_test_service_calls'];
	}

	// -----------------------------------------------------------------------
	// S5 -- the restore stops the proxy first
	// -----------------------------------------------------------------------

	public function testRestoreStopsTheProxyBeforeAnyRestoreWrite(): void
	{
		// Given a moved Resolver, and a hook that snapshots config.xml at the instant the proxy is stopped
		$this->seedMovedResolver();
		$atStop = [];
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn, string $service) use (&$atStop): void {
			$atStop[] = [
				'call'    => [$fn, $service],
				'unbound' => config_get_path('unbound'),
				'marker'  => (string) config_get_path(self::SAVED, ''),
				'writes'  => count($GLOBALS['pfb_test_write_config_calls'] ?? []),
			];
		};

		// When the Resolver is restored
		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));

		// Then the proxy was stopped exactly once, while the Resolver was still moved, the marker still
		// held the snapshot and nothing had been written: Unbound's regeneration finds port 53 free
		$this->assertCount(1, $atStop, 'the proxy is stopped exactly once');
		$this->assertSame(['stop_service', 'pfb_dns_proxy'], $atStop[0]['call']);
		$this->assertSame(self::sorted(self::movedResolver()), self::sorted($atStop[0]['unbound']),
			'the stop must precede the first restore write');
		$this->assertNotSame('', $atStop[0]['marker'], 'the stop must precede clearing the snapshot');
		$this->assertSame(0, $atStop[0]['writes'], 'the stop must precede write_config');

		// ... and the restore then happened
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
		$this->assertSame('', (string) config_get_path(self::SAVED, ''));
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testRestoreWithNoSnapshotNeverTouchesTheProxy(): void
	{
		// Given an untouched Resolver (every apply with the toggle off asks for the restore)
		$GLOBALS['config']['unbound'] = self::originalResolver();

		$this->assertFalse(pfb_dns_proxy_resolver(FALSE));

		$this->assertSame([], $this->serviceCalls(), 'a box that never moved the Resolver must not stop anything');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'and is not alarmed');
	}

	public function testMovingTheResolverDoesNotStopOrRestartTheProxy(): void
	{
		// Given the toggle is turned on: the proxy is started after Unbound is rebound, never here
		$GLOBALS['config']['unbound'] = self::originalResolver();

		$this->assertTrue(pfb_dns_proxy_resolver(TRUE));

		$this->assertSame([], $this->serviceCalls());
	}

	// -----------------------------------------------------------------------
	// F4 -- a Resolver stuck on loopback 5353 with no usable saved copy
	// -----------------------------------------------------------------------

	/** @return array<string,array{?string}> the marker as stored; NULL = absent */
	public static function unusableMarkers(): array
	{
		return [
			'marker lost'              => [NULL],
			'marker not base64'        => ['!!! not base64 !!!'],
			'marker not a snapshot'    => [base64_encode('{"port":1}')],
		];
	}

	#[DataProvider('unusableMarkers')]
	public function testAMovedResolverWithoutAUsableSnapshotRaisesAnOperatorNoticeNamingTheKeysToCheck(?string $marker): void
	{
		// Given the toggle is off (or DNSBL disabled) while the Resolver still sits on loopback 5353
		$GLOBALS['config']['unbound'] = self::movedResolver();
		if ($marker !== NULL) {
			config_set_path(self::SAVED, $marker);
		}

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then nothing could be restored, but the operator is told through a notice, not only a log line
		$this->assertFalse($changed);
		$this->assertSame(self::sorted(self::movedResolver()), self::sorted(config_get_path('unbound')),
			'the Resolver is not guessed at');
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'exactly one operator-visible notice');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		foreach (['Network Interfaces', 'Listen Port', 'Enable SSL/TLS Service', 'Custom Options', self::LINE] as $needle) {
			$this->assertStringContainsString($needle, $notice['notice'], "the notice names {$needle}");
		}
		$this->assertSame('/services_unbound.php', $notice['url'], 'it points at the Resolver page');
		$this->assertSame(2, $notice['priority'], 'it is a warning, like the other DNSBL notices');
		$this->assertStringContainsString('DNS proxy', (string) @file_get_contents($GLOBALS['pfb']['errlog']),
			'the error log says so too');
	}

	/** @return array<string,array{array<string,string>}> Resolver values that are NOT the moved state */
	public static function notMovedResolvers(): array
	{
		$orig = self::originalResolver();
		return [
			'untouched Resolver'                    => [$orig],
			'own port 5353 on the LAN'              => [['port' => '5353'] + $orig],
			'own loopback listener on port 53'      => [['active_interface' => 'lo0'] + $orig],
			'own lo0:5353 Resolver, no proxy line'  => [['port' => '5353', 'active_interface' => 'lo0'] + $orig],
		];
	}

	/** @param array<string,string> $resolver */
	#[DataProvider('notMovedResolvers')]
	public function testAResolverThatIsNotMovedWithNoSnapshotRaisesNoNotice(array $resolver): void
	{
		$GLOBALS['config']['unbound'] = $resolver;

		pfb_dns_proxy_resolver(FALSE);

		$this->assertSame([], $GLOBALS['pfb_test_file_notices'],
			'no snapshot is the normal state of a box that never turned the proxy on');
	}

	public function testAMovedResolverWithAValidSnapshotIsRestoredWithoutANotice(): void
	{
		$this->seedMovedResolver();

		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));

		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	// -----------------------------------------------------------------------
	// F4 -- package removal
	// -----------------------------------------------------------------------

	public function testRemovalRestoresTheMovedResolverRegeneratesOnceAndStopsTheProxyFirst(): void
	{
		// Given a moved Resolver the disable pass never got to (it returned early)
		$this->seedMovedResolver();
		$atStop = [];
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn, string $service) use (&$atStop): void {
			$atStop[] = [$fn, $service, count($GLOBALS['pfb_test_unbound_configure_calls']), config_get_path('unbound/port')];
		};

		// When the package is removed
		pfb_dns_proxy_deinstall();

		// Then the proxy was stopped before anything was restored or regenerated ...
		$this->assertSame([['stop_service', 'pfb_dns_proxy', 0, '5353']], array_slice($atStop, 0, 1));
		// ... and the Resolver is back as the user had it, with unbound.conf regenerated once
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
		$this->assertSame('', (string) config_get_path(self::SAVED, ''));
		$this->assertCount(1, $GLOBALS['pfb_test_unbound_configure_calls']);
	}

	public function testRemovalOfABoxThatNeverMovedTheResolverStopsTheProxyAndChangesNothingElse(): void
	{
		$GLOBALS['config']['unbound'] = self::originalResolver();

		pfb_dns_proxy_deinstall();

		$this->assertSame([['stop_service', 'pfb_dns_proxy']], $this->serviceCalls());
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], 'nothing to regenerate');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testRemovalWithALostSnapshotStillStopsTheProxyAndTellsTheOperator(): void
	{
		$GLOBALS['config']['unbound'] = self::movedResolver();

		pfb_dns_proxy_deinstall();

		$this->assertSame([['stop_service', 'pfb_dns_proxy']], $this->serviceCalls());
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], 'nothing was restored, so nothing to regenerate');
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
	}

	/** The removal hook runs the restore unconditionally after the disable pass, whatever the pass returned. */
	public function testThePreDeinstallHookRunsTheRestoreAfterTheDisablePassWhateverItReturns(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$start = strpos($source, 'function pfblockerng_php_pre_deinstall_command');
		$this->assertNotFalse($start, 'pre-deinstall controller must remain defined');
		$hook = substr($source, (int) $start);

		$pass = strpos($hook, 'sync_package_pfblockerng();');
		$restore = strpos($hook, 'pfb_dns_proxy_deinstall();');
		$this->assertNotFalse($pass, 'the disable pass is a plain statement: its result is not consulted');
		$this->assertNotFalse($restore, 'package removal must restore the Resolver');
		$this->assertGreaterThan($pass, $restore, 'the restore follows the disable pass');
		$between = substr($hook, (int) $pass, (int) $restore - (int) $pass);
		$this->assertDoesNotMatchRegularExpression('~\bif\b|\{|\}|\breturn\b|\belse\b~', $between,
			'nothing conditional or early between the pass and the restore: it runs whatever the pass returned');
	}

	// -----------------------------------------------------------------------
	// S7 -- the installer
	// -----------------------------------------------------------------------

	public function testWhileTheResolverIsMovedTheInstallerRegeneratesTheScriptAndRestartsTheProxy(): void
	{
		$this->seedMovedResolver();
		$atRestart = [];
		$GLOBALS['pfb_test_service_hook'] = static function () use (&$atRestart): void {
			$atRestart[] = $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0;
		};

		pfb_dns_proxy_service_sync();

		$this->assertSame([['restart_service', 'pfb_dns_proxy']], $this->serviceCalls());
		$this->assertSame([1], $atRestart, 'the rc script was (re)generated before the restart');
	}

	public function testWithoutAMovedResolverTheInstallerStopsTheProxyAndStillWritesTheScript(): void
	{
		$GLOBALS['config']['unbound'] = self::originalResolver();

		pfb_dns_proxy_service_sync();

		$this->assertSame([['stop_service', 'pfb_dns_proxy']], $this->serviceCalls(), 'never restarted outside proxy mode');
		$this->assertSame(1, $GLOBALS['pfb_test_rcfile_writes']['pfb_dns_proxy.sh'] ?? 0, 'the script exists for later starts and stops');
	}

	public function testTheInstallerCallsTheSyncAfterTheDnsblServiceBlock(): void
	{
		$install = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$dnsbl = strpos($install, 'pfb_dnsbl_service();');
		$sync = strpos($install, 'pfb_dns_proxy_service_sync();');
		$this->assertNotFalse($dnsbl, 'test bootstrap: the DNSBL service block is found');
		$this->assertNotFalse($sync, 'the installer must sync the DNS proxy service');
		$this->assertGreaterThan($dnsbl, $sync, 'after the DNSBL service block');
	}

	// -----------------------------------------------------------------------
	// S8 -- the package XML registers the service
	// -----------------------------------------------------------------------

	public function testTheServiceIsRegisteredWithAPidfileStatusCommand(): void
	{
		$xml = simplexml_load_file(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng.xml');
		$this->assertNotFalse($xml, 'pfblockerng.xml parses');
		$services = [];
		foreach ($xml->service as $service) {
			$services[(string) $service->name] = $service;
		}

		$this->assertArrayHasKey('pfb_dns_proxy', $services);
		$this->assertArrayHasKey('pfb_dnsbl', $services, 'the existing services are still registered');
		$this->assertArrayHasKey('pfb_filter', $services);
		$proxy = $services['pfb_dns_proxy'];
		$this->assertSame('pfb_dns_proxy.sh', (string) $proxy->rcfile);
		$this->assertSame('pfBlockerNG DNS proxy (experimental)', (string) $proxy->description);
		$status = (string) $proxy->custom_php_service_status_command;
		$this->assertSame("isvalidpid('" . PFB_DNS_PROXY_PIDFILE . "')", $status, 'util.inc alone is loaded where pfSense evals it');

		// pfSense evaluates it as `$rc = <command>;`: it must follow the pidfile in both directions
		$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => TRUE];
		eval("\$rc = {$status};");
		$this->assertTrue($rc);
		$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => FALSE];
		eval("\$rc = {$status};");
		$this->assertFalse($rc);
	}
}
