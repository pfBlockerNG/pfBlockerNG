<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyMovedResolverFixtureTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- what a moved Resolver does and does not lose while pfB-DNS runs: the restore the admin asks for (pfB-DNS off, pfBlockerNG
 * disabled, a Resolver restore that config.xml refuses or a proxy that outlives its stop), the installer's restart, and the
 * passes that find a proxy ready, unready or its backend gone and change nothing. What must never restore the Resolver by itself is
 * pinned by DnsProxyNeverRollsBackTest.
 */
#[CoversFunction('pfb_dns_proxy_resolver')]
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_restart')]
#[CoversFunction('pfblockerng_tick')]
final class DnsProxyMovedResolverTest extends TestCase
{
	use DnsProxyMovedResolverFixtureTrait;

	public function testAnUpgradeInstallRestartsTheProxyThatPfSenseUnregisteredBeforeTheInstallCommand(): void
	{
		// Given a moved Resolver and a proxy that serves once started, in the state an upgrade runs the install command in
		$this->activate(TRUE);
		$this->behaviour = 'serves';
		$this->upgradeInstallState();

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the proxy was restarted and serves: pfB-DNS stays on, the Resolver stays moved, nothing is restored
		$this->assertSame(['restart_service'], $this->proxyCalls, 'the restart reached a registered service');
		$this->assertTrue(pfb_dns_proxy_ready());
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is not turned off');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the Resolver stays moved');
		$this->assertSame([], $this->notices());
		$this->assertContains('pfb_dns_proxy', array_column($this->onDisk('installedpackages/service', []), 'name'),
			'the registration is in config.xml, so a fresh read keeps it');
		$this->assertSame([['pfBlockerNG: registered the package services before the DNS proxy restart', FALSE, TRUE]],
			$GLOBALS['pfb_test_write_config_args'], 'one write, of config.xml only: no backup, CARP sync or package plugins');
	}

	public function testAnUpgradeInstallWhoseProxyNeverServesLeavesItRunningAndTheResolverMoved(): void
	{
		// Given the same upgrade, and a proxy that lives and never publishes its marker
		$this->activate(TRUE);
		$this->upgradeInstallState();
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the restart reaches the service and nothing stops the proxy or gives the Resolver back
		$this->assertSame(['restart_service'], $this->proxyCalls, 'the restart reached the service and nothing stopped it');
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the snapshot is kept');
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'the Resolver stays moved');
	}

	#[DataProvider('refusedWrites')]
	public function testAnUpgradeInstallWhoseRegistrationIsNotWrittenStillRestartsTheProxyAndSaysSo(mixed $answer): void
	{
		// Given the same upgrade, a proxy that serves once started, and config.xml refusing the registration's write
		$this->activate(TRUE);
		$this->behaviour = 'serves';
		$this->upgradeInstallState();
		$this->configXmlOnDisk($answer, 'registered the package services');

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the restart still reaches the service this process registered (stopping instead would leave the moved Resolver
		// unserved), and the log says the registration is not in config.xml, so a restore could not stop the proxy
		$this->assertSame(['restart_service'], $this->proxyCalls);
		$this->assertSame('on', $this->toggleStored());
		$this->assertStringContainsString('the package services could not be written to config.xml', $this->pfbLog());
	}

	public function testAnUpgradeInstallWithTheResolverNotMovedStopsTheProxyService(): void
	{
		// Given no Resolver snapshot (pfB-DNS off), in the state an upgrade runs the install command in
		$this->activate(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		config_set_path(self::SAVED, '');
		$this->upgradeInstallState();

		// When the installer's DNS proxy block runs
		$this->runInstallProxyBlock();

		// Then the proxy's rc script is written and its service stopped, nothing started
		$this->assertSame(['stop_service'], $this->proxyCalls);
		$this->assertArrayHasKey('pfb_dns_proxy.sh', $GLOBALS['pfb_test_rcfile_writes'] ?? [], 'the rc script is written');
	}

	public function testNothingIsWaitedOnUnderTheConfigLock(): void
	{
		// Given a proxy that lives and never serves: every liveness probe while PHP waits notes whether the lock is held
		$this->activate(TRUE);

		pfb_dns_proxy_ensure_running();

		$this->assertNotEmpty($this->lockHeldWhileWaiting, 'before: PHP did probe the proxy while waiting');
		$this->assertSame([], array_keys(array_filter($this->lockHeldWhileWaiting)), 'the lock was free at every probe of the wait');
		$this->assertFalse((bool) $GLOBALS['pfb_test_lock_held'], 'and none is still held');
		$this->assertSame([], $GLOBALS['pfb_test_lock_holders'], 'and no other lock is held');
	}

	/** @return array<string,array{bool,mixed}> whether pfSense has a service entry for the proxy, and write_config()'s answer to the refused write */
	public static function entryAndRefusedWrite(): array
	{
		$rows = [];
		foreach (['the service entry is registered' => TRUE, 'the service entry is absent' => FALSE] as $entry => $registered) {
			foreach (self::refusedWrites() as $write => [$answer]) {
				$rows["{$entry}, {$write}"] = [$registered, $answer];
			}
		}
		return $rows;
	}

	#[DataProvider('entryAndRefusedWrite')]
	public function testARestoreThatConfigXmlRefusesLeavesTheProxyServingTheMovedResolver(bool $registered, mixed $answer): void
	{
		// Given a moved Resolver, the healthy proxy that serves it, and a config.xml that refuses the restore's write
		$this->activate(TRUE);
		$this->registered = $registered;
		$this->behaviour = 'serves';
		$this->proxyServes();
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		$this->configXmlOnDisk($answer, 'Restored the DNS Resolver');
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));
		$this->assertTrue(pfb_dns_proxy_ready(), 'before: the proxy serves');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'before: config.xml holds the snapshot');

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore is reported as no change, config.xml keeps the snapshot and the moved Resolver, and the proxy the
		// restore stopped serves them again
		$this->assertFalse($changed);
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'config.xml keeps the snapshot');
		$this->assertSame($moved, self::sorted($this->onDisk('unbound')), 'and the moved Resolver');
		$this->assertTrue(pfb_dns_proxy_ready(), 'the proxy serves the moved Resolver again');
	}

	public function testTheRecoveryDoesNotReplaceAProxyThatOutlivedItsStop(): void
	{
		// Given a moved Resolver, no service entry, and a healthy proxy (child 7001) that its stop does not remove
		$this->activate(TRUE);
		$this->registered = FALSE;
		$this->survivesStop = TRUE;
		$this->proxyServes('7001');
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore is refused (the proxy still holds the port) and the same child and supervisor serve it
		$this->assertFalse($changed);
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the snapshot is kept');
		$this->assertSame($moved, self::sorted(config_get_path('unbound')), 'the Resolver stays moved');
		$this->assertSame("7001\n", (string) file_get_contents($this->proxyPidfile()), 'the same child serves');
		$this->assertSame("7001\n", (string) file_get_contents($this->proxyMarker()), 'with the marker it published');
		$this->assertTrue(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), 'under the same supervisor');
		$this->assertTrue(pfb_dns_proxy_ready());
	}

	public function testARestoreOnABoxThatNeverMovedTheResolverRunsNeitherAStopNorAStart(): void
	{
		// Given a Resolver pfB-DNS never touched: no snapshot, no block of ours, no proxy
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertNull(pfb_dns_proxy_saved(), 'before: no snapshot');
		$this->assertFalse(pfb_dns_proxy_block_present(), 'before: no block of ours');

		// When the restore is asked for
		$this->assertFalse(pfb_dns_proxy_resolver(FALSE));

		// Then nothing was stopped or started
		$this->assertSame([], $this->proxyCalls, 'no rc stop, no rc start, no service call');
		$this->assertFalse(pfb_dns_proxy_running(), 'and no proxy exists');
	}

	/** @return array<string,array{bool,int}> whether a healthy proxy runs, and how many writes the restore makes before it ends */
	public static function recoveryWithNoRcScript(): array
	{
		return [
			'a healthy proxy that cannot be stopped without the script: abandoned before any write' => [TRUE, 0],
			'no proxy running: the restore reaches its write and config.xml refuses it' => [FALSE, 1],
		];
	}

	#[DataProvider('recoveryWithNoRcScript')]
	public function testTheRecoveryWritesTheRcScriptItStartsTheProxyWith(bool $healthy, int $writes): void
	{
		// Given a moved Resolver, no service entry, no rc script on disk (a /var that came up empty), and a config.xml that refuses the restore's write
		$this->activate(TRUE);
		$this->registered = FALSE;
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		unlink(PFB_DNS_PROXY_RCFILE);
		if ($healthy) {
			$this->proxyServes();
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		}
		$this->configXmlOnDisk(FALSE, 'Restored the DNS Resolver');
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'before: no rc script');
		$this->assertSame($healthy, pfb_dns_proxy_ready(), 'before: only the healthy row has a ready gateway');
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'before: the missing rc script prevents confirming the actual upstream');

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore changed nothing, and the script the start runs was written first, so the proxy serves the moved Resolver
		$this->assertFalse($changed);
		$this->assertCount($writes, $GLOBALS['pfb_test_write_config_calls'], 'the path the row stands for ran');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'config.xml keeps the snapshot');
		$this->assertSame($moved, self::sorted($this->onDisk('unbound')), 'and the moved Resolver');
		$this->assertFileExists(PFB_DNS_PROXY_RCFILE, 'the recovery regenerated the rc script');
		$this->assertNotContains('rc start (no script)', $this->proxyCalls, 'so its start found the script');
		$this->assertTrue(pfb_dns_proxy_ready(), 'the proxy serves the moved Resolver');
	}

	#[DataProvider('recoveryWithNoRcScript')]
	public function testTheRecoveryRunsNoRcScriptThatAListenPortConflictLeftUnwritten(bool $healthy, int $writes): void
	{
		// Given a moved Resolver whose Listen Port the admin set to the proxy's own port after the move (the generator then writes no
		// script), no service entry, no rc script on disk, and a config.xml that refuses the restore's write
		$this->activate(TRUE);
		$this->registered = FALSE;
		config_set_path('unbound/port', '5353');
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		unlink(PFB_DNS_PROXY_RCFILE);
		if ($healthy) {
			$this->proxyServes();
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		}
		$this->configXmlOnDisk(FALSE, 'Restored the DNS Resolver');
		$snapshot = (string) config_get_path(self::SAVED, '');
		$moved = self::sorted(config_get_path('unbound'));
		$this->assertSame('5353', $this->onDisk('unbound/port'), 'before: config.xml holds the conflicting Listen Port');
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'before: no rc script');

		// When the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then the restore changed nothing, no script was written, and nothing was run against the script that is not there
		$this->assertFalse($changed);
		$this->assertCount($writes, $GLOBALS['pfb_test_write_config_calls'], 'the path the row stands for ran');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'config.xml keeps the snapshot');
		$this->assertSame($moved, self::sorted($this->onDisk('unbound')), 'and the moved Resolver');
		$this->assertFileDoesNotExist(PFB_DNS_PROXY_RCFILE, 'the generator wrote no script');
		$this->assertSame([], $this->proxyCalls, 'no stop and no start was run against a missing script');
	}

	public function testAProxyThatBecomesReadyIsLeftAloneAndTheObserverStaysInUnbound(): void
	{
		// Given a first activation whose proxy publishes its marker once started
		$this->activate(TRUE);
		$this->behaviour = 'serves';

		// When the apply starts it and waits for it
		$ok = pfb_dns_proxy_ensure_running();

		// Then the activation stands: no toggle write, no stop, no notice, the Resolver stays moved and Unbound keeps the
		// observer, never the matcher
		$this->assertTrue($ok, 'before: a ready proxy is success');
		$this->assertSame('on', $this->toggleStored(), 'no false Off');
		$this->assertSame(['start_service'], $this->proxyCalls);
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'));
		$this->assertSame([], $this->notices());
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testAHealthyProxyThatIsAlreadyServingNeedsNoStartAndIsLeftAlone(): void
	{
		// Given a proxy that serves since before this apply, with the Resolver's certificate it was given (nothing to push to it)
		$this->activate(TRUE);
		pfb_dns_proxy_service();
		$this->proxyServes();
		$this->seedRunningGateway();
		file_put_contents(pfb_dns_proxy_certificate_pushed_path(), hash('sha256', (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert'])));
		$GLOBALS['pfb_test_service_calls'] = [];

		$ok = pfb_dns_proxy_ensure_running();

		$this->assertTrue($ok);
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame([], $this->notices());
	}

	public function testOwnershipOnlyCommandChangeReconcilesLiveWithoutRestart(): void
	{
		$this->activate(TRUE);
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'LAN', 'opt1' => 'OPT'];
		pfb_dns_proxy_service();
		$this->proxyServes();
		$this->seedRunningGateway();
		file_put_contents(pfb_dns_proxy_certificate_pushed_path(), hash('sha256', (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert'])));
		$served = [];
		foreach (pfb_dns_proxy_command_listeners() as $kind => $addresses) {
			foreach ($addresses as $at) {
				$served[] = "{$kind} {$at}";
			}
		}
		$this->standInsStop();
		$record = $this->standIn($this->controlSocket(), [], ['listening' => $served]);
		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'before: gateway serves without changing its sockets');
		$GLOBALS['pfb_test_interfaces'] = ['lan' => 'Renamed,"\\', 'opt1' => 'OPT'];
		$this->assertTrue(pfb_dns_proxy_ensure_running());
		$this->assertSame([], $this->proxyCalls, 'ownership rename must not restart DNS');
		$frames = self::changeFrames($record);
		$this->assertNotEmpty($frames, 'ownership snapshot must be sent live');
		$table = end($frames);
		$this->assertSame('fffffffb', $table['head']);
		$this->assertStringContainsString('listener-interface 192.0.2.1=' . base64_encode('Renamed,"\\'), $table['body']);
	}

	public function testAnUnchangedLiveProxyWithoutAReadyMarkerIsReportedAndLeftAlone(): void
	{
		// Given a live proxy whose script is unchanged (the old check was: the pidfile names a live process), no marker
		$this->activate(TRUE);
		pfb_dns_proxy_service();
		$this->proxyLivesButNeverServes();
		$GLOBALS['pfb_test_service_calls'] = [];
		$resolver = config_get_path('unbound');
		$saved = PfbConfig::read('dns/pfb_dns_saved');

		// When the apply checks it
		$ok = pfb_dns_proxy_ensure_running();

		// Then it is reported as unready, but a pass that started nothing leaves the gateway and Resolver untouched
		$this->assertFalse($ok);
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame($resolver, config_get_path('unbound'));
		$this->assertSame($saved, PfbConfig::read('dns/pfb_dns_saved'));
		$this->assertTrue(pfb_dns_proxy_running());
		$this->assertSame([], $this->proxyCalls);
		$startup = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy startup'));
		$this->assertCount(1, $startup);
		$this->assertStringContainsString('did not become ready', $startup[0]['notice']);
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
	}

	public function testALockedConfigCannotMoveTheGatewayOntoAListenPortSetAfterTheMove(): void
	{
		// Given a moved Resolver whose gateway serves the port it had at the move, and an admin who then sets the Listen Port to 5353
		// while another save holds config.xml for the whole apply
		$this->activate(TRUE);
		$this->proxyServes();
		$served = $this->servedPort();
		config_set_path('unbound/port', '5353');
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When the apply runs its Resolver pass and then its proxy check
		pfb_unbound_python('enabled', TRUE);
		pfb_dns_proxy_ensure_running();

		// Then the gateway still serves the port it had: its rc script is not rewritten onto the Listen Port, and nothing restarts it
		$this->assertSame('53', $served, 'before: the gateway serves the port the Resolver had');
		$this->assertSame('53', $this->servedPort(), 'the gateway keeps serving the port it had');
		$this->assertSame([], $this->proxyCalls, 'the proxy is neither stopped nor restarted');
		$this->assertSame('on', $this->toggleStored(), 'the lock changed nothing');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
	}

	public function testADisabledPfBlockerNgIsAnOrdinaryRestoreThatLeavesTheToggleAlone(): void
	{
		// Given pfB-DNS on and a moved Resolver, with pfBlockerNG itself disabled and the Resolver disabled too
		$this->activate(TRUE);
		$this->proxyServes();
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::Off);
		$this->disableTheResolver();

		// When the pass runs
		pfb_unbound_python('disabled');

		// Then the Resolver is restored as for any disabled package: the toggle the admin set stays, and there is no stand-down notice
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame([], $this->notices());
	}

	public function testAPassNeverStartsAResolverTheAdminDisabled(): void
	{
		// Given a Resolver with nothing of ours moved, and Unbound stopped; first enabled: a restart starts it once
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$before = $this->startAttempts();
		$started = pfb_stop_start_unbound('');
		$this->assertSame(0, $started['retval']);
		$this->assertSame($before + 1, $this->startAttempts(), 'before: an enabled Resolver is started by the restart');

		// When the admin disables the Resolver (the stand-down above leaves it so) and a pass restarts Unbound again
		config_del_path('unbound/enable');
		$disabled = pfb_stop_start_unbound('');

		// Then nothing is started, and the restart reports no failure
		$this->assertSame($before + 1, $this->startAttempts(), 'a disabled Resolver is not started');
		$this->assertTrue($disabled['start_completed']);
		$this->assertSame(0, $disabled['retval']);
		$this->assertStringContainsString('disabled', $this->pfbLog());
	}

	public function testADnsblReloadWithPfbDnsOffRestartsAnEnabledResolverAndLeavesADisabledOneStopped(): void
	{
		// Given pfB-DNS off and nothing moved (the DNSBL-only path), and Unbound stopped
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertSame('', $this->toggleStored(), 'before: pfB-DNS is off');
		$this->assertNull(pfb_dns_proxy_saved(), 'before: nothing is moved');
		$before = $this->startAttempts();

		// When the DNSBL reload restarts Unbound with the Resolver enabled, then again with it disabled
		pfb_reload_unbound('enabled', TRUE);
		$enabled = $this->startAttempts();
		config_del_path('unbound/enable');
		pfb_reload_unbound('', TRUE);

		// Then only the enabled Resolver was started
		$this->assertSame($before + 1, $enabled, 'an enabled Resolver is restarted as before');
		$this->assertSame($enabled, $this->startAttempts(), 'a disabled Resolver is left stopped');
	}

	public function testTheProxysRcScriptNamesTheSnapshotWhenUnboundIsRegeneratedForTheMove(): void
	{
		// Given Unbound regenerated for the move: pfSense's boot hook runs the proxy's rc script at that moment
		$seen = NULL;
		$GLOBALS['pfb_test_unbound_configure_hook'] = static function () use (&$seen): void {
			$seen ??= $GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh'] ?? NULL;
		};

		// When the proxy takes the Resolver
		$this->activate(TRUE);
		unset($GLOBALS['pfb_test_unbound_configure_hook']);

		// Then the script that Unbound's boot hook runs names the snapshot: generated for it, not the install-time one that
		// refuses to start ("not a valid snapshot")
		$this->assertNotNull($seen, 'Unbound was regenerated for the move with the proxy\'s rc script already written');
		pfb_dns_proxy_service();
		$this->assertSame($GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh'], $seen, 'the script is the one for the moved Resolver\'s snapshot');
	}

	#[DataProvider('refusedWrites')]
	public function testAnUnsafeLineWhoseKeepWriteIsRefusedLeavesTheAdminsLineAndTheSnapshotAsTheyWere(mixed $answer): void
	{
		// Given a moved Resolver, an admin who then added an unsafe line, and a config.xml that refuses the write that keeps
		// that line in the saved settings (it takes every other: the saved copy would lack the line the admin may restore later)
		$this->activate(TRUE);
		$this->proxyServes();
		$this->adminAppends('port: 5300');
		$this->configXmlOnDisk($answer, 'kept the admin');
		$text = $this->customText();
		$snapshot = (string) config_get_path(self::SAVED, '');
		$this->assertStringContainsString('port: 5300', $text, 'before: the admin\'s line is in Custom Options');

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then the admin's line was not dropped by a restore from a snapshot that does not hold it, and nothing was restored
		$this->assertSame('on', $this->onDisk(self::TOGGLE), 'pfB-DNS is still requested');
		$this->assertSame($snapshot, $this->onDisk(self::SAVED), 'the snapshot is kept');
		$this->assertSame($text, $this->customText(), 'the Resolver\'s Custom Options are as the admin saved them');
		$this->assertSame([], $this->proxyCalls, 'the proxy is not stopped');
		$joined = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringContainsString('could not be written', $joined, 'the operator is told why nothing was changed');
		$this->assertStringNotContainsString('was turned off', $joined);
	}

	public function testTurningPfbDnsOffRestoresTheResolverAndTheStatusSaysPfbDnsIsOff(): void
	{
		// Given a moved Resolver whose proxy serves
		$this->activate(TRUE);
		$this->proxyServes();

		// When the admin turns pfB-DNS off and the next apply runs
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		pfb_unbound_python('enabled');

		// Then the Resolver is back as it was, no failure is on record, and the status says pfB-DNS is off
		$this->assertResolverIsTheOriginal('turned off by the admin');
		pfb_global();
		$this->assertSame('Off: the DNS Resolver serves clients itself', pfb_dns_status()['mode']);
	}

	public function testASuccessfulActivationShowsAWorkingProxyInTheStatus(): void
	{
		// Given a first activation whose proxy serves once started
		$this->activate(TRUE);
		$this->behaviour = 'serves';

		// When the apply starts it and waits for it
		$this->assertTrue(pfb_dns_proxy_ensure_running());

		// Then no failure is on record and the status shows a working proxy
		pfb_global();
		$this->assertSame('On, with DNSBL: the proxy answers DNSBL blocks and forwards everything else', pfb_dns_status()['mode']);
		$this->assertSame('on', $this->toggleStored());
	}

	/** @return array<string,array{string}> the gateway process that lives and never publishes its marker */
	public static function aliveGateways(): array
	{
		return [
			'the child lives and never publishes its marker' => ['child'],
			'only the supervisor lives, its child between restarts' => ['supervisor'],
		];
	}

	#[DataProvider('aliveGateways')]
	public function testTheTickReportsAnUnreadyGatewayAndLeavesTheResolverMovedForAStartItDidNotMake(string $alive): void
	{
		// Given pfB-DNS on with the Resolver moved, and a gateway process alive that never becomes ready
		$this->activate(TRUE);
		if ($alive === 'child') {
			$this->proxyLivesButNeverServes();
			$this->assertTrue(pfb_dns_proxy_running(), 'before: the child is alive');
		} else {
			// The supervisor is alive between starts; this tick did not launch it.
			$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
			$this->assertTrue(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), 'before: the supervisor is alive');
		}
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is requested');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the snapshot is stored');
		$resolver = config_get_path('unbound');
		$saved = PfbConfig::read('dns/pfb_dns_saved');

		// When the cron tick runs
		$this->tick();

		// Then the existing startup notice reports the unready gateway, without a stop or Resolver restore
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame($resolver, config_get_path('unbound'));
		$this->assertSame($saved, PfbConfig::read('dns/pfb_dns_saved'));
		$this->assertSame([], $this->proxyCalls);
		$this->assertContains('pfBlockerNG DNS Proxy startup', array_column($this->notices(), 'id'));
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
		if ($alive === 'child') {
			$this->assertTrue(pfb_dns_proxy_running());
		} else {
			$this->assertTrue(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE));
		}
	}

	public function testTheTickWaitsForNothingAndChangesNothingWhenNoGatewayProcessLives(): void
	{
		// Given pfB-DNS on with the Resolver moved, and no gateway process alive; the readiness predicate counts its probes
		$this->activate(TRUE);
		$probes = 0;
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = static function () use (&$probes): bool {
			$probes++;
			return FALSE;
		};

		// When the cron tick runs
		$this->tick();

		// Then the tick neither waits for the proxy nor files or changes anything
		// the certificate sync looks at readiness once on every tick (a single probe, no wait); a start-budget wait would poll again
		$this->assertSame(1, $probes, 'the certificate sync looks at readiness once per tick; a start-budget wait would poll again');
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is still requested');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testTheTickLeavesAReadyProxyAlone(): void
	{
		// Given pfB-DNS on with the Resolver moved, and a proxy that serves
		$this->activate(TRUE);
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->assertSame('on', $this->toggleStored(), 'before: pfB-DNS is requested');

		// When the cron tick runs
		$this->tick();

		// Then nothing is restored and no Resolver notice is filed
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is still on');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
		$this->assertSame([], $this->proxyCalls, 'the proxy is neither stopped nor started');
	}

	public function testTheTickKeepsAReadyGatewayAndResolverWhenUnboundIsMissing(): void
	{
		// Given a ready gateway left by an earlier pass, with its Resolver backend now missing
		$this->activate(TRUE);
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->seedUnbound(alive: FALSE);
		file_put_contents($GLOBALS['pfb_test_sockstat_output'], '');
		$this->assertNull(pfb_dns_proxy_certificate_export());
		file_put_contents(pfb_dns_proxy_certificate_pushed_path(), hash('sha256', (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert'])));
		$resolver = config_get_path('unbound');
		$saved = PfbConfig::read('dns/pfb_dns_saved');

		// When the tick checks a gateway it did not start
		$this->tick();

		// Then nothing is restored: the existing gateway and Resolver stay untouched, with Service visibly not Running
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame($resolver, config_get_path('unbound'));
		$this->assertSame($saved, PfbConfig::read('dns/pfb_dns_saved'));
		$this->assertTrue(pfb_dns_proxy_running());
		$this->assertTrue(pfb_dns_proxy_ready());
		$this->assertFalse(pfb_dns_proxy_serving_ready());
		$this->assertSame('Starting', pfb_dns_status()['service']);
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
	}

	public function testTheTickKeepsItsGatewayWhenUnboundAndAppliedStatusAreBothUnavailable(): void
	{
		// Given a gateway left running, a missing Unbound and an unanswered status, even if a socket inventory could name another holder
		$this->activate(TRUE);
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->seedUnbound(alive: FALSE);
		file_put_contents($GLOBALS['pfb_test_sockstat_output'], "root nc 6161 3 tcp4 127.0.0.1:5353 *:*\nroot nc 6161 4 udp4 127.0.0.1:5353 *:*\n");
		$this->standInsStop();
		$this->assertNull(pfb_dns_proxy_certificate_export());
		file_put_contents(pfb_dns_proxy_certificate_pushed_path(), hash('sha256', (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert'])));
		$resolver = config_get_path('unbound');
		$saved = PfbConfig::read('dns/pfb_dns_saved');

		// When the tick has no positive evidence of foreign upstream ownership
		$this->tick();

		// Then absence and unknown status cannot trigger the foreign-owner exception
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame($resolver, config_get_path('unbound'));
		$this->assertSame($saved, PfbConfig::read('dns/pfb_dns_saved'));
		$this->assertTrue(pfb_dns_proxy_running());
		$this->assertSame('Starting', pfb_dns_status()['service']);
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
	}

	public function testTheBootCheckDoesNothingWithoutASnapshot(): void
	{
		// Given a box whose pfB-DNS was turned off and its Resolver restored since, so no snapshot is stored
		$this->activate(TRUE);
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		pfb_unbound_python('enabled', FALSE);
		$this->assertNull(pfb_dns_proxy_saved(), 'before: nothing is stored to roll back to');
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$this->proxyCalls = [];

		// When the boot check runs
		$this->dnsCheckArm('0');

		// Then nothing is written, stopped or reported
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testTheBootCheckLeavesAReadyProxyAlone(): void
	{
		// Given pfB-DNS on with the Resolver moved, and a proxy that serves
		$this->activate(TRUE);
		$this->proxyServes();
		$this->seedRunningGateway();

		// When the boot check runs
		$this->dnsCheckArm('0');

		// Then nothing is restored and no Resolver notice is filed
		$this->assertSame('on', $this->toggleStored(), 'pfB-DNS is still on');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the snapshot is kept');
		$this->assertNotContains('pfBlockerNG DNS Proxy', array_column($this->notices(), 'id'));
		$this->assertSame([], $this->proxyCalls, 'the proxy is neither stopped nor started');
	}

	/** @return array<string,array{string,string,int,string}> the gateway lines an older start logged, the lines this start logged after the size was taken, the quote its notice carries */
	public static function gatewayErrorsAroundTheStart(): array
	{
		return [
			'an error of an older start and none from this start' => [['pfb_dns_gateway: old error'], ['listening udp+tcp 127.0.0.1:53'], ''],
			'an error of an older start and this start\'s own' => [['pfb_dns_gateway: old error'], ['pfb_dns_gateway: this start'], ' (last gateway error: pfb_dns_gateway: this start)'],
		];
	}

	#[DataProvider('gatewayErrorsAroundTheStart')]
	public function testAFailedConfirmationQuotesOnlyTheGatewayErrorOfItsOwnStartAndLeavesTheResolverMoved(array $before, array $after, string $quote): void
	{
		// Given a log with an error of an older start, the size taken, and what this start logged after it
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$log = $GLOBALS['pfb']['dns_proxy_log'];
		try {
			file_put_contents($log, implode("\n", $before) . "\n");
			$since = pfb_dns_proxy_log_size();
			file_put_contents($log, implode("\n", $after) . "\n", FILE_APPEND);

			// When the confirmation of this start finds the proxy not ready
			$ready = pfb_dns_proxy_confirm_ready($since);
		} finally {
			@unlink($log);
		}

		// Then the Resolver stays moved, and the startup notice names only this start's own gateway error
		$this->assertFalse($ready);
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the Resolver stays moved');
		$this->assertSame([], array_values(array_intersect($this->proxyCalls, ['stop_service', 'rc stop'])), 'the proxy is not stopped');
		$startup = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy startup'));
		$this->assertCount(1, $startup, 'one startup notice');
		$this->assertStringNotContainsString('old error', $startup[0]['notice'], 'an older start\'s error is never blamed on this one');
		if ($quote === '') {
			$this->assertStringNotContainsString('last gateway error', $startup[0]['notice']);
		} else {
			$this->assertStringContainsString($quote, $startup[0]['notice']);
		}
	}

	public function testAFailedStartReportsSnapshotDependentListenerWarnings(): void
	{
		// Given a valid snapshot that names lan and opt1, a proxy that never serves, and opt1 now configured with no address
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		$this->configXmlOnDisk();
		$GLOBALS['pfb_test_interface_ip']['opt1'] = '';
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the snapshot is stored');

		// When the activation confirms the start, which fails
		$this->assertFalse(pfb_dns_proxy_confirm_ready());

		// Then the startup notice names the interface whose listener only the snapshot defines, and the Resolver is restored
		$startup = array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === 'pfBlockerNG DNS Proxy startup'));
		$this->assertCount(1, $startup, 'one startup notice');
		$this->assertStringContainsString('opt1', $startup[0]['notice'], 'the startup notice names the interface whose listener the snapshot defines');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'the Resolver stays moved after the diagnosis');
	}
}
