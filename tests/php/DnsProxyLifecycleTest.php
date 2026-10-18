<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- when the proxy daemon is started and stopped, relative to the Resolver:
 *
 *   - the proxy is stopped BEFORE the Resolver is restored, so Unbound's regeneration finds port 53 free
 *     (pfb_dns_proxy_resolver(FALSE), the one place every "turn it off" path goes through), and the restore is
 *     abandoned, snapshot kept and the operator told, when the proxy outlived its stop (stop_service() reports
 *     nothing, so the pidfiles are the only witness): the proxy is then restarted, so the moved Resolver stays
 *     served until a later apply restores it;
 *   - package removal always hands the Resolver back, stops the proxy and removes its rc script, whatever the
 *     disable pass returned (pfb_dns_proxy_deinstall(), called right after the pass), but never stops the proxy
 *     first: a restore that cannot take the config lock would leave the moved Resolver with nothing serving it. It
 *     reports FALSE while a snapshot survives (rc script kept), and the hook then stops the removal
 *     (DnsProxyUninstallAbortTest);
 *   - a Resolver that is still moved while the saved copy is lost or malformed cannot be put back
 *     automatically: the operator is told through a notice naming the keys to check, not only a log line --
 *     but only for a Resolver carrying OUR marked block, never for an admin's own PROXYv2 setup;
 *   - the installer regenerates the rc script and restarts the proxy while the Resolver is moved, stops it
 *     otherwise;
 *   - pfblockerng.xml registers the service with a pidfile-based status command.
 */
#[CoversFunction('pfb_dns_proxy_resolver')]
#[CoversFunction('pfb_dns_proxy_deinstall')]
final class DnsProxyLifecycleTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const MARKER = '# pfBlockerNG DNS proxy';
	private const BLOCK = "server:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
		. "proxy-protocol-port: 5353\n# end pfBlockerNG DNS proxy";
	private const GLOBALS = [
		'pfb', 'config', 'pfb_test_service_calls', 'pfb_test_service_hook', 'pfb_test_write_config_calls',
		'pfb_test_unbound_configure_calls', 'pfb_test_file_notices', 'pfb_test_rcfiles', 'pfb_test_rcfile_writes',
		'pfb_test_valid_pids', 'pfb_test_try_lock_fail', 'pfb_test_lock_held', 'pfb_test_lock_events',
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
		$GLOBALS['pfb_test_valid_pids'] = [];
		@unlink(PFB_DNS_PROXY_RCFILE);
	}

	protected function tearDown(): void
	{
		@unlink(PFB_DNS_PROXY_RCFILE);
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

	/** The same Resolver as the proxy leaves it: still on port 53, on loopback, our block appended. */
	private static function movedResolver(): array
	{
		$moved = self::originalResolver();
		$moved['active_interface'] = 'lo0';
		unset($moved['enablessl']);
		$moved['custom_options'] = base64_encode("do-ip6: no\nprefetch: yes\n" . self::BLOCK);
		return $moved;
	}

	private static function snapshotOfOriginal(): string
	{
		$original = self::originalResolver();
		$keys = [];
		foreach (['active_interface', 'enablessl', 'custom_options'] as $key) {
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
	// S5b -- a proxy that outlives its stop keeps the Resolver where it is
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> the pidfile that still names a live process after the stop */
	public static function survivors(): array
	{
		return [
			'the proxy itself'  => [PFB_DNS_PROXY_PIDFILE],
			'only its supervisor' => [PFB_DNS_PROXY_DAEMON_PIDFILE],
		];
	}

	#[DataProvider('survivors')]
	public function testARestoreIsAbandonedWhileTheProxyIsStillAliveAfterItsStop(string $pidfile): void
	{
		// Given a moved Resolver and a proxy process that survived stop_service() (the rc script gave up after KILL)
		$this->seedMovedResolver();
		$GLOBALS['pfb_test_valid_pids'] = [$pidfile => TRUE];
		$moved = $GLOBALS['config'];

		// When the Resolver is to be restored
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then nothing moved back: the Resolver stays on loopback, the snapshot is kept for the next attempt ...
		$this->assertFalse($changed);
		$this->assertSame($moved, $GLOBALS['config'], 'port 53 is not handed to Unbound while the proxy still holds it');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot survives, so the next apply can retry');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);

		// ... and the operator is told what to do, in a notice, not only in the log.
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertStringContainsString('still running', $notice['notice']);
		$this->assertStringContainsString('Status > Services', $notice['notice']);
		$this->assertSame(2, $notice['priority']);
		$this->assertStringContainsString('DNS proxy', (string) @file_get_contents($GLOBALS['pfb']['errlog']));

		// ... and the proxy that serves the moved Resolver was stopped and then restarted, so DNS stays available
		$this->assertSame([['stop_service', 'pfb_dns_proxy'], ['restart_service', 'pfb_dns_proxy']], $this->serviceCalls());
	}

	public function testARestoreProceedsWhenNeitherPidfileNamesALiveProcessAfterTheStop(): void
	{
		// Given the same moved Resolver, with both pidfiles dead (the normal outcome of a stop)
		$this->seedMovedResolver();
		$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => FALSE, PFB_DNS_PROXY_DAEMON_PIDFILE => FALSE];

		$this->assertTrue(pfb_dns_proxy_resolver(FALSE));

		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testTheRestoreRetriesOnTheNextApplyAndSucceedsOnceTheProxyIsGone(): void
	{
		// Given an abandoned restore ...
		$this->seedMovedResolver();
		$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => TRUE];
		$this->assertFalse(pfb_dns_proxy_resolver(FALSE), 'before: the first attempt is abandoned');

		// When the proxy has exited by the next apply
		$GLOBALS['pfb_test_valid_pids'] = [];
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the retry restores the Resolver from the kept snapshot
		$this->assertTrue($changed);
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
		$this->assertNull(pfb_dns_proxy_saved());
	}

	// -----------------------------------------------------------------------
	// F4 -- a Resolver stuck on loopback with OUR block and no usable saved copy
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
		// Given the toggle is off (or DNSBL disabled) while the Resolver still carries our block
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
		foreach (['Network Interfaces', 'Enable SSL/TLS Service', 'Custom Options', self::MARKER] as $needle) {
			$this->assertStringContainsString($needle, $notice['notice'], "the notice names {$needle}");
		}
		$this->assertStringNotContainsString('Listen Port', $notice['notice'], 'the move never changes the port');
		$this->assertSame('/services_unbound.php', $notice['url'], 'it points at the Resolver page');
		$this->assertSame(2, $notice['priority'], 'it is a warning, like the other DNSBL notices');
		$this->assertStringContainsString('DNS proxy', (string) @file_get_contents($GLOBALS['pfb']['errlog']),
			'the error log says so too');
	}

	/** @return array<string,array{array<string,string>}> Resolver values that do NOT carry our block */
	public static function notMovedResolvers(): array
	{
		$orig = self::originalResolver();
		return [
			'untouched Resolver'                    => [$orig],
			'own port 5353 on the LAN'              => [['port' => '5353'] + $orig],
			'own loopback listener on port 53'      => [['active_interface' => 'lo0'] + $orig],
			'own lo0 Resolver with its own PROXYv2 line' => [[
				'port' => '5353', 'active_interface' => 'lo0',
				'custom_options' => base64_encode("server:\nproxy-protocol-port: 5353"),
			] + $orig],
			'a commented-out copy of our marker'    => [['custom_options' => base64_encode("# # pfBlockerNG DNS proxy\ndo-ip6: no")] + $orig],
		];
	}

	/** @param array<string,string> $resolver */
	#[DataProvider('notMovedResolvers')]
	public function testAResolverWithoutOurBlockAndNoSnapshotRaisesNoNotice(array $resolver): void
	{
		$GLOBALS['config']['unbound'] = $resolver;

		pfb_dns_proxy_resolver(FALSE);

		$this->assertSame([], $GLOBALS['pfb_test_file_notices'],
			'no snapshot is the normal state of a box that never turned the proxy on, and an admin\'s own '
			. 'PROXYv2 front end is none of our business');
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
			$atStop[] = [$fn, $service, count($GLOBALS['pfb_test_unbound_configure_calls']), config_get_path('unbound/active_interface')];
		};

		// When the package is removed
		$this->assertTrue(pfb_dns_proxy_deinstall(), 'the Resolver was put back: the removal goes on');

		// Then the proxy was stopped before anything was restored or regenerated ...
		$this->assertSame([['stop_service', 'pfb_dns_proxy', 0, 'lo0']], array_slice($atStop, 0, 1));
		// ... and the Resolver is back as the user had it, with unbound.conf regenerated once
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
		$this->assertSame('', (string) config_get_path(self::SAVED, ''));
		$this->assertCount(1, $GLOBALS['pfb_test_unbound_configure_calls']);
	}

	public function testRemovalWhileTheConfigIsLockedNeverStopsTheProxyThatServesTheMovedResolver(): void
	{
		// Given a moved Resolver, and another save holding the config lock for the whole bounded wait
		$this->seedMovedResolver();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When the package is removed
		$this->assertFalse(pfb_dns_proxy_deinstall(), 'the Resolver stayed moved: the removal must stop');

		// Then the Resolver could not be put back, so the proxy that serves it was not stopped first
		$this->assertSame([], $this->serviceCalls());
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], 'nothing was restored, so nothing to regenerate');
	}

	public function testRemovalKeepsTheProxyRcScriptWhileASnapshotSurvivesTheRestore(): void
	{
		// Given a moved Resolver that cannot be put back (another save holds the config lock) and the rc script on disk
		$this->seedMovedResolver();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n");

		// When the package is removed
		$this->assertFalse(pfb_dns_proxy_deinstall(), 'the snapshot survived: the removal must stop');

		// Then the script stays: the proxy keeps serving the moved Resolver, and the operator's notice says to stop it
		// from Status > Services, which can only run a script that exists
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the snapshot is kept');
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE);
	}

	public function testRemovalOfABoxThatNeverMovedTheResolverStopsTheProxyAndChangesNothingElse(): void
	{
		$GLOBALS['config']['unbound'] = self::originalResolver();

		$this->assertTrue(pfb_dns_proxy_deinstall(), 'nothing was moved: the removal goes on');

		$this->assertSame([['stop_service', 'pfb_dns_proxy']], $this->serviceCalls());
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], 'nothing to regenerate');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testRemovalWithALostSnapshotStillStopsTheProxyAndTellsTheOperator(): void
	{
		$GLOBALS['config']['unbound'] = self::movedResolver();

		$this->assertTrue(pfb_dns_proxy_deinstall(), 'no snapshot to restore from: the removal goes on, with the operator told');

		$this->assertSame([['stop_service', 'pfb_dns_proxy']], $this->serviceCalls());
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], 'nothing was restored, so nothing to regenerate');
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
	}

	/** @return array<string,array{bool}> whether the Resolver was moved when the package is removed */
	public static function removalStates(): array
	{
		return ['a moved Resolver' => [TRUE], 'a Resolver that was never moved' => [FALSE]];
	}

	#[DataProvider('removalStates')]
	public function testRemovalDeletesTheProxyRcScriptAfterStoppingTheProxy(bool $moved): void
	{
		// Given the proxy's rc script on disk (the installer wrote it) and the Resolver in this state
		if ($moved) {
			$this->seedMovedResolver();
		} else {
			$GLOBALS['config']['unbound'] = self::originalResolver();
		}
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n");
		$atStop = [];
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn) use (&$atStop): void {
			$atStop[] = [$fn, file_exists(PFB_DNS_PROXY_RCFILE)];
		};

		// When the package is removed
		$this->assertTrue(pfb_dns_proxy_deinstall(), 'the Resolver is back (or was never moved): the removal goes on');

		// Then every stop found the script still there (stop_service() can only run an existing script) ...
		$this->assertNotSame([], $atStop, 'before: the proxy was stopped');
		foreach ($atStop as [$fn, $existed]) {
			$this->assertTrue($existed, "{$fn}: the script is deleted only after the proxy was stopped");
		}
		// ... and the script is gone afterwards, as pfb_filter.sh and pfb_dnsbl.sh are on removal
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE);
	}

	/** The removal hook runs the restore unconditionally after the disable pass, whatever the pass returned. */
	public function testThePreDeinstallHookRunsTheRestoreAfterTheDisablePassWhateverItReturns(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$start = strpos($source, 'function pfblockerng_php_pre_deinstall_command');
		$this->assertNotFalse($start, 'pre-deinstall controller must remain defined');
		$hook = substr($source, (int) $start);

		$pass = strpos($hook, 'sync_package_pfblockerng();');
		$restore = strpos($hook, 'if (!pfb_dns_proxy_deinstall()) {');
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

	public function testTheInstallerSyncsTheProxyServiceRightAfterStagingItsRuntimeFiles(): void
	{
		// The installer is a script that runs at include time, so its wiring is pinned in the source. The proxy
		// reads its module, lists and ini only at start: it is restarted (or stopped) only once the staging
		// command has copied the new modules into /var/unbound. While the Resolver is moved the proxy is
		// restarted (which regenerates its script first); otherwise the script is still written, for later
		// starts and stops, and the proxy is stopped.
		$install = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$stage = "exec('/usr/local/pkg/pfblockerng/pfblockerng.sh dnsbl_cache stage >/dev/null 2>&1');";
		$this->assertSame(1, substr_count($install, $stage), 'test bootstrap: the installer stages the module files once');

		$sync = "update_status(\"Creating DNS proxy service...\"); if (pfb_dns_proxy_saved() !== NULL) { pfb_dns_proxy_restart(); } else { pfb_dns_proxy_service(); stop_service('pfb_dns_proxy'); }";
		$this->assertSame(1, substr_count($install, $sync), 'the installer must restart the proxy while moved, else write its script and stop it');
		$this->assertStringContainsString($stage . ' ' . $sync, $install, 'the proxy block follows the staging command, with nothing in between');
		$this->assertStringNotContainsString('pfb_dns_proxy_service_sync', $install, 'the one-caller wrapper is gone');
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
