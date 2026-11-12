<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyMovedResolverFixtureTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- pfB-DNS never fails to start, and nothing but the admin gives the Resolver back (owner decisions, 2026-11-11).
 *
 * With a valid snapshot, `dns/pfb_dns` On and `gen/enable_cb` On, none of what used to roll pfB-DNS back may restore the Resolver any
 * more: a proxy that does not become ready, a gateway whose Unbound backend does not serve, a foreign holder of Unbound's loopback
 * port, a Resolver the admin disabled, an interface:/port:/include: line added after the move and a Listen Port on a proxy port. Each
 * is driven through the entry point that used to roll back, and the box must keep the snapshot byte for byte, the Resolver moved, the
 * proxy running, config.xml unwritten and Unbound unregenerated, with a notice instead. What still restores: pfB-DNS turned off,
 * pfBlockerNG disabled, the package removed (the setup wizard's reset is pinned by WizardDnsProxyResetGuardTest).
 */
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
#[CoversFunction('pfb_dns_proxy_confirm_started')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_restart')]
#[CoversFunction('pfb_unbound_python')]
#[CoversFunction('pfblockerng_tick')]
final class DnsProxyNeverRollsBackTest extends TestCase
{
	use DnsProxyMovedResolverFixtureTrait;

	/** @return array{marker:string,resolver:array<string,mixed>} what a restore would change */
	private function movedBox(): array
	{
		return ['marker' => (string) config_get_path(self::SAVED, ''), 'resolver' => self::sorted(config_get_path('unbound'))];
	}

	/**
	 * What every case below holds, whatever else it changes: the Resolver was not given back. pfB-DNS stays on and active, the snapshot is
	 * byte for byte what the move stored, the keys the takeover changed stay as it left them, the proxy was never stopped and no notice or
	 * status says the Resolver was restored or the activation failed.
	 *
	 * @param array{marker:string,resolver:array<string,mixed>} $before
	 */
	private function assertResolverNotGivenBack(array $before, string $why): void
	{
		$this->assertSame('on', $this->toggleStored(), "{$why}: pfB-DNS stays on");
		$this->assertNotNull(pfb_dns_proxy_saved(), "{$why}: the Resolver is still moved");
		$this->assertSame($before['marker'], (string) config_get_path(self::SAVED, ''), "{$why}: the snapshot is kept byte for byte");
		foreach (['active_interface', 'enablessl'] as $key) {
			$this->assertSame($before['resolver'][$key] ?? NULL, config_get_path("unbound/{$key}"), "{$why}: {$key} stays as the move left it");
		}
		$this->assertSame([], array_values(array_intersect($this->proxyCalls, ['stop_service', 'rc stop'])), "{$why}: the proxy was not stopped");
		$texts = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringNotContainsStringIgnoringCase('restored', $texts, "{$why}: no notice says the Resolver was given back");
		$this->assertStringNotContainsStringIgnoringCase('activation failed', $texts, "{$why}: no notice says the activation failed");
		pfb_global();
		$status = pfb_dns_status();
		$this->assertStringNotContainsString('Activation failed', $status['mode'], "{$why}: the status knows no failed activation");
		$this->assertTrue($status['active'], "{$why}: the status keeps pfB-DNS active");
	}

	/** @param array{marker:string,resolver:array<string,mixed>} $before */
	private function assertNothingWasRestored(array $before, string $why): void
	{
		$this->assertResolverNotGivenBack($before, $why);
		$this->assertSame($before['resolver'], self::sorted(config_get_path('unbound')), "{$why}: every Resolver key stays as the move left it");
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$why}: nothing was written to config.xml");
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], "{$why}: Unbound was not regenerated");
	}

	/** Every port the backend pair's search could pick from is taken (5355..5419), whatever else sockstat lists: there is no free pair to move to. */
	private function takeEveryBackendPair(): void
	{
		file_put_contents($GLOBALS['pfb_test_sockstat_output'],
			implode('', array_map(static fn (int $port): string => "root nc 6162 3 udp4 127.0.0.1:{$port} *:*\n", range(5355, 5419))), FILE_APPEND);
	}

	/** The gateway already holds the certificate it serves (the fixture an earlier apply leaves), so no pass pushes one to it. */
	private function gatewayHoldsItsCertificate(): void
	{
		$this->assertNull(pfb_dns_proxy_certificate_export(), 'before: the certificate the gateway holds is exported');
		file_put_contents(pfb_dns_proxy_certificate_pushed_path(), hash('sha256', (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert'])));
	}

	/** @return list<array<string,mixed>> the notices filed under $id */
	private function noticesOf(string $id): array
	{
		return array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === $id));
	}

	// -----------------------------------------------------------------------
	// (a) a proxy that does not become ready after a start
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,bool}> the call that starts or confirms a start (it used to roll back), and whether DNSBL is on */
	public static function startsOfAProxyThatNeverServes(): array
	{
		return [
			'the apply starts a dead proxy' => ['apply start', TRUE],
			'the apply starts a dead proxy with DNSBL off' => ['apply start', FALSE],
			'the apply restarts a live proxy' => ['apply restart', TRUE],
			'the installer or reload restarts the proxy' => ['restart', TRUE],
			'the DNSBL reload restarts the proxy' => ['reload', TRUE],
			'the cron tick restarts a gateway that refuses a live change' => ['tick restart', TRUE],
			'the boot check confirms a start' => ['boot check', TRUE],
		];
	}

	#[DataProvider('startsOfAProxyThatNeverServes')]
	public function testAProxyThatNeverBecomesReadyLeavesTheResolverMovedAndSaysSo(string $entry, bool $dnsbl): void
	{
		// Given pfB-DNS on with the Resolver moved, and a proxy that lives and never publishes its ready marker
		$this->activate($dnsbl);
		if (!$dnsbl) {
			$this->useMountState(FALSE);
		}
		$before = $this->movedBox();
		$expectedCalls = ['start_service'];
		switch ($entry) {
			case 'apply restart':
				$this->proxyLivesButNeverServes();
				file_put_contents($GLOBALS['pfb']['dns_proxy_restart_pending'], "a restart was deferred\n");
				$expectedCalls = ['restart_service'];
				break;
			case 'restart':
			case 'reload':
				$expectedCalls = ['restart_service'];
				break;
			case 'tick restart':
				$this->proxyServes();
				$this->gatewayHoldsItsCertificate();
				$this->standInsStop();
				$this->standIn($this->controlSocket(), ['error: refused'], ['listening' => [...$this->commandListeners(), 'udp+tcp 198.51.100.77:53']]);
				$this->assertTrue(pfb_dns_proxy_ready(), 'before: the gateway is ready');
				$expectedCalls = ['restart_service'];
				break;
			case 'boot check':
				$this->proxyLivesButNeverServes();
				$expectedCalls = [];
				break;
		}

		// When the entry point runs
		try {
			match ($entry) {
				'apply start', 'apply restart' => $this->assertFalse(pfb_dns_proxy_ensure_running(), 'the proxy never serves'),
				'restart' => $this->assertFalse(pfb_dns_proxy_restart(), 'the proxy never serves'),
				'reload' => pfb_reload_unbound('enabled', TRUE),
				'tick restart' => $this->tick(),
				'boot check' => $this->dnsCheckArm('0'),
			};
		} finally {
			@unlink($GLOBALS['pfb']['dns_proxy_restart_pending']);
		}

		// Then nothing gave the Resolver back: it stays moved for the proxy, pfB-DNS stays on, and the startup notice says why it is not serving
		$this->assertSame($expectedCalls, $this->proxyCalls, 'the proxy was only started or restarted, never stopped');
		$this->assertNothingWasRestored($before, $entry);
		$startup = $this->noticesOf('pfBlockerNG DNS Proxy startup');
		$this->assertNotEmpty($startup, "{$entry}: the operator is told");
		$this->assertStringContainsString('the DNS proxy did not become ready', $startup[array_key_last($startup)]['notice']);
		$this->assertSame('/pfblockerng/pfblockerng_dns_general.php', $startup[array_key_last($startup)]['url']);
		$this->assertSame(['pfBlockerNG DNS Proxy startup'], array_values(array_unique(array_column($this->notices(), 'id'))), 'and only that notice is filed');
	}

	public function testAPendingRestartIsStillSatisfiedByTheRestartThatNeverBecameReady(): void
	{
		// Given a deferred restart and a proxy that never serves once restarted
		$this->activate(TRUE);
		$this->proxyLivesButNeverServes();
		file_put_contents($GLOBALS['pfb']['dns_proxy_restart_pending'], "a restart was deferred\n");

		// When the apply restarts it
		$this->assertFalse(pfb_dns_proxy_ensure_running());

		// Then the restart counts as made: the next apply does not restart it again for the same reason
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_restart_pending']);
		$calls = $this->proxyCalls;
		$this->assertFalse(pfb_dns_proxy_ensure_running(), 'the proxy is still not ready');
		$this->assertSame($calls, $this->proxyCalls, 'and is left alone by the next apply');
	}

	// -----------------------------------------------------------------------
	// (b) a ready gateway whose Unbound backend does not serve, (c) a foreign holder of Unbound's port
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function entriesThatConfirmAReadyGateway(): array
	{
		return [
			'the apply starts the proxy' => ['apply start'],
			'the installer or reload restarts the proxy' => ['restart'],
			'the boot check' => ['boot check'],
		];
	}

	#[DataProvider('entriesThatConfirmAReadyGateway')]
	public function testAReadyGatewayWhoseBackendDoesNotServeKeepsTheResolverMoved(string $entry): void
	{
		// Given a moved Resolver, a gateway that becomes ready, and an Unbound backend that is dead: its process is gone and so are its sockets
		$this->activate(TRUE);
		$this->seedUnbound(alive: FALSE);
		file_put_contents($GLOBALS['pfb_test_sockstat_output'], "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n");
		$this->behaviour = 'serves';
		if ($entry === 'boot check') {
			$this->proxyServes();
			$this->seedRunningGateway();
			$this->gatewayHoldsItsCertificate();
		}
		$before = $this->movedBox();

		// When the entry point confirms the start
		match ($entry) {
			'apply start' => $this->assertFalse(pfb_dns_proxy_ensure_running(), 'a dead backend does not serve'),
			'restart' => $this->assertFalse(pfb_dns_proxy_restart(), 'a dead backend does not serve'),
			'boot check' => $this->dnsCheckArm('0'),
		};

		// Then the gateway stays up with the Resolver moved, the Service line says the backend does not answer, and nothing was restored
		$this->assertTrue(pfb_dns_proxy_ready(), 'the gateway is ready');
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the backend is not');
		$this->assertNothingWasRestored($before, $entry);
		$this->assertSame('Resolver backend not answering: Unbound does not answer on 127.0.0.1:5353', pfb_dns_status()['service']);
	}

	/** @return array<string,array{string}> */
	public static function entriesWithNoStart(): array
	{
		return ['the cron tick' => ['tick'], 'the apply' => ['apply']];
	}

	#[DataProvider('entriesWithNoStart')]
	public function testAForeignHolderOfUnboundsLoopbackPortMovesUnboundsPairAndNeverGivesTheResolverBack(string $entry): void
	{
		// Given a serving gateway, and another process that holds Unbound's loopback port while Unbound lives
		$this->activate(TRUE);
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'before: the gateway and its Unbound upstream serve');
		$this->seedUnbound();
		file_put_contents($GLOBALS['pfb_test_sockstat_output'], "root nc 6161 3 tcp4 127.0.0.1:5353 *:*\nroot nc 6161 4 udp4 127.0.0.1:5353 *:*\n");
		$this->assertSame('foreign', pfb_dns_proxy_upstream_state(), 'before: the port is held by a foreign process');
		$this->gatewayHoldsItsCertificate();
		$before = $this->movedBox();

		// When the pass that started nothing checks the gateway
		if ($entry === 'tick') {
			$this->tick();
		} else {
			pfb_dns_proxy_ensure_running();
		}

		// Then Unbound's pair moved off the stranger's port (DnsProxyBackendMoveTest pins how), and the Resolver is not given back
		$this->assertSame('5355', pfb_dns_proxy_backend_port(), 'Unbound moved to a free pair');
		$this->assertNotSame($before['resolver']['custom_options'], config_get_path('unbound/custom_options'), 'with the new pair in its clause');
		$this->assertResolverNotGivenBack($before, $entry);
		$this->assertStringContainsString('nc (pid 6161) on 127.0.0.1:5353', implode("\n", array_column($this->notices(), 'notice')), 'the notice names the holder');
	}

	// -----------------------------------------------------------------------
	// (d) a Resolver the admin disabled
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function passesThatSeeADisabledResolver(): array
	{
		return ['the apply' => ['apply'], 'the cron tick' => ['tick']];
	}

	#[DataProvider('passesThatSeeADisabledResolver')]
	public function testADisabledResolverKeepsPfbDnsAndTheMovedResolverAndSaysThereIsNoBackend(string $pass): void
	{
		// Given pfB-DNS serving, and the Resolver then disabled in Services > DNS Resolver
		$this->activate(TRUE);
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->disableTheResolver();
		$this->gatewayHoldsItsCertificate();
		$before = $this->movedBox();
		$run = fn () => ($pass === 'tick') ? $this->tick() : pfb_unbound_python('');

		// When the pass runs, twice
		$run();
		$run();

		// Then nothing is restored and the proxy keeps running, and one notice says what is wrong and what ends it
		$this->assertNothingWasRestored($before, "{$pass} with a disabled Resolver");
		$this->assertTrue(pfb_dns_proxy_ready(), 'the proxy keeps serving its clients');
		$this->assertFalse(config_path_enabled('unbound'), 'the Resolver stays as the admin left it: disabled');
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices, 'one notice, not one per pass');
		$this->assertSame('/services_unbound.php', $notices[0]['url']);
		$this->assertStringContainsString('the DNS Resolver is disabled in Services > DNS Resolver', $notices[0]['notice']);
		$this->assertStringContainsString('pfB-DNS has no backend and DNS queries fail', $notices[0]['notice']);
		$this->assertStringContainsString('until the Resolver is enabled or pfB-DNS is turned off', $notices[0]['notice']);
	}

	// -----------------------------------------------------------------------
	// (e) an interface:, port: or include: line added to Custom Options after the move
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,bool}> the admin's lines that can take a listener, a second port or another file, with DNSBL on and off */
	public static function unsafeLines(): array
	{
		return [
			'a port line' => ['port: 5300', TRUE],
			'an interface on the Listen Port' => ['interface: 0.0.0.0@53', TRUE],
			'an interface on the proxy port' => ['interface: 192.0.2.1@5353', TRUE],
			'an include' => ['include: /tmp/extra.conf', TRUE],
			'a port line with DNSBL off' => ['port: 5300', FALSE],
		];
	}

	#[DataProvider('unsafeLines')]
	public function testAnUnsafeLineAddedAfterTheMoveKeepsPfbDnsServingKeepsTheLineAndSaysSo(string $line, bool $dnsbl): void
	{
		// Given a moved Resolver, a proxy that serves, and an admin who then adds an unsafe line to Custom Options
		$this->activate($dnsbl);
		if (!$dnsbl) {
			$this->useMountState(FALSE);
		}
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->adminAppends($line);
		$saved = pfb_dns_proxy_saved();
		$resolver = self::sorted(config_get_path('unbound'));
		$starts = $this->startAttempts();
		$mode = $dnsbl ? 'enabled' : 'disabled';

		// When the next apply runs, twice
		pfb_unbound_python($mode, TRUE);
		pfb_unbound_python($mode, TRUE);

		// Then the Resolver stays moved with the admin's line in it, and the proxy keeps serving
		$this->assertSame('on', $this->toggleStored());
		$this->assertSame($resolver, self::sorted(config_get_path('unbound')), 'the moved Resolver is untouched');
		$this->assertContains($line, $this->customLines(), 'the admin\'s line stands in Custom Options');
		$this->assertSame([], array_values(array_intersect($this->proxyCalls, ['stop_service', 'rc stop'])), 'the proxy was not stopped');
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], 'Unbound was not regenerated');
		$this->assertSame($starts, $this->startAttempts(), 'Unbound was not restarted');
		$this->assertTrue(pfb_dns_proxy_ready(), 'the proxy keeps serving');

		// ... the snapshot gained the admin's line, so that a later restore by the admin keeps it, and is otherwise what the move saved,
		// written once, not once per apply
		$kept = pfb_dns_proxy_saved();
		$this->assertNotNull($kept, 'the snapshot stands');
		$this->assertStringContainsString($line, (string) base64_decode($kept['custom_options']['value'], TRUE));
		$this->assertSame(array_diff_key($saved, ['custom_options' => 1]), array_diff_key($kept, ['custom_options' => 1]), 'every other saved key is as the move saved it');
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls'], 'config.xml was written once');
		$this->assertStringContainsString('kept the admin', $GLOBALS['pfb_test_write_config_calls'][0]);

		// ... and one notice names the line, says pfB-DNS keeps serving and what to do
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices, 'one notice, not one per apply');
		$this->assertSame('/services_unbound.php', $notices[0]['url']);
		$this->assertStringContainsString($line, $notices[0]['notice']);
		$this->assertStringContainsString('Custom Options', $notices[0]['notice']);
		$this->assertStringContainsString('pfB-DNS keeps serving', $notices[0]['notice']);
		$this->assertStringContainsString('remove the line in Services > DNS Resolver', $notices[0]['notice']);
		$this->assertStringNotContainsStringIgnoringCase('restored', $notices[0]['notice']);
		pfb_global();
		$this->assertStringNotContainsString('Activation failed', pfb_dns_status()['mode']);

		// When the admin turns pfB-DNS off, the saved settings come back with the line kept
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		pfb_unbound_python($mode);
		$this->assertNull(pfb_dns_proxy_saved(), 'the admin\'s off consumes the snapshot');
		$this->assertSame(['do-ip6: no', 'prefetch: yes', 'server:', $line], $this->customLines(), 'and the line is still the admin\'s');
		$this->assertSame('lan,opt1', config_get_path('unbound/active_interface'));
	}

	public function testALineThatIsNotUnsafeAddedAfterTheMoveSaysNothing(): void
	{
		// Given a moved Resolver and an admin who adds a harmless line to Custom Options
		$this->activate(TRUE);
		$this->proxyServes();
		$this->adminAppends('local-data: "x.example. A 192.0.2.1"');

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then pfB-DNS keeps the Resolver and there is nothing to say
		$this->assertSame('on', $this->toggleStored());
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
	}

	// -----------------------------------------------------------------------
	// (f) a Listen Port on a proxy port after the move
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,bool}> the proxy's own loopback ports, each with DNSBL on and off */
	public static function reservedListenPorts(): array
	{
		return [
			'5353 with DNSBL on' => ['5353', TRUE],
			'5353 with DNSBL off' => ['5353', FALSE],
			'5354 with DNSBL on' => ['5354', TRUE],
			'5354 with DNSBL off' => ['5354', FALSE],
		];
	}

	#[DataProvider('reservedListenPorts')]
	public function testAListenPortSetOnAProxyPortAfterTheMoveWithNoFreePairKeepsPfbDnsServingAndSaysSo(string $port, bool $dnsbl): void
	{
		// Given a moved Resolver whose proxy serves on the port the Resolver had, no free pair to move Unbound's backend to, and an admin who then sets the
		// Listen Port to a proxy port (with a free pair it moves instead: DnsProxyBackendMoveTest)
		$this->activate($dnsbl);
		if (!$dnsbl) {
			$this->useMountState(FALSE);
		}
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->takeEveryBackendPair();
		$served = $this->servedPort();
		$this->gatewayHoldsItsCertificate();
		config_set_path('unbound/port', $port);
		$before = $this->movedBox();
		$starts = $this->startAttempts();
		$mode = $dnsbl ? 'enabled' : 'disabled';

		// When the next apply runs, its Resolver pass and then its proxy check, twice
		pfb_unbound_python($mode, TRUE);
		$this->assertTrue(pfb_dns_proxy_ensure_running(), 'the proxy check finds the proxy ready');
		pfb_unbound_python($mode, TRUE);

		// Then the Resolver stays moved with the admin's Listen Port, the gateway keeps serving the port it had and nothing is restarted
		$this->assertNothingWasRestored($before, "Listen Port {$port}");
		$this->assertSame('53', $served, 'before: the gateway serves the port the Resolver had');
		$this->assertSame($served, $this->servedPort(), 'the gateway keeps serving the port it had');
		$this->assertSame([], $this->proxyCalls, 'the proxy was neither stopped nor restarted');
		$this->assertSame($port, config_get_path('unbound/port'), 'the Listen Port stays as the admin set it');
		$this->assertSame($starts, $this->startAttempts(), 'Unbound was not restarted');

		// ... and one notice names the Listen Port and says pfB-DNS keeps serving
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices, 'one notice, not one per apply');
		$this->assertSame('/services_unbound.php', $notices[0]['url']);
		$this->assertStringContainsString("Listen Port is {$port}", $notices[0]['notice']);
		$this->assertStringContainsString('pfB-DNS keeps serving', $notices[0]['notice']);
		$this->assertStringContainsString('set the Listen Port to another port', $notices[0]['notice']);
		$this->assertStringNotContainsString('Custom Options', $notices[0]['notice']);

		// When the admin turns pfB-DNS off, the saved settings come back and the Listen Port is still the admin's
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		pfb_unbound_python($mode);
		$this->assertNull(pfb_dns_proxy_saved(), 'the admin\'s off consumes the snapshot');
		$this->assertSame('lan,opt1', config_get_path('unbound/active_interface'));
		$this->assertSame($port, config_get_path('unbound/port'));
	}

	public function testAValidListenPortSetAfterTheMoveSaysNothing(): void
	{
		// Given a moved Resolver and an admin who sets its Listen Port to 5300, a port the proxy does not use
		$this->activate(TRUE);
		$this->proxyServes();
		config_set_path('unbound/port', '5300');

		// When the next apply runs
		pfb_unbound_python('enabled', TRUE);

		// Then pfB-DNS keeps the Resolver with the admin's port and there is nothing to say
		$this->assertSame('on', $this->toggleStored());
		$this->assertNotNull(pfb_dns_proxy_saved());
		$this->assertSame('5300', config_get_path('unbound/port'));
		$this->assertSame([], $this->notices());
		$this->assertSame([], $this->proxyCalls);
	}

	// -----------------------------------------------------------------------
	// What still gives the Resolver back: the admin's own switches
	// -----------------------------------------------------------------------

	public function testTurningPfbDnsOffRestoresTheResolverAfterADegradedStart(): void
	{
		// Given a moved Resolver whose proxy never became ready, so the Resolver stayed moved
		$this->activate(TRUE);
		$this->assertFalse(pfb_dns_proxy_ensure_running(), 'before: the proxy never serves');
		$this->assertNotNull(pfb_dns_proxy_saved(), 'before: the Resolver stays moved');

		// When the admin turns pfB-DNS off and the next apply runs
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		pfb_unbound_python('enabled');

		// Then the Resolver is back as it was, and the status says pfB-DNS is off
		$this->assertResolverIsTheOriginal('turned off by the admin');
		$this->assertContains('rc stop', $this->proxyCalls, 'the proxy is stopped');
		pfb_global();
		$this->assertSame('Off: the DNS Resolver serves clients itself', pfb_dns_status()['mode']);
	}

	public function testTurningPfbDnsOffRestoresADisabledResolverWithoutANotice(): void
	{
		// Given a disabled Resolver that pfB-DNS keeps moved, and the admin who then turns pfB-DNS off
		$this->activate(TRUE);
		$this->proxyServes();
		$this->disableTheResolver();
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);

		// When the next apply runs
		pfb_unbound_python('');

		// Then the Resolver has its saved settings and stays disabled, and the disabled-Resolver notice does not fire
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertFalse(config_path_enabled('unbound'), 'the Resolver stays disabled');
		$this->assertSame([], $this->noticesOf('pfBlockerNG DNS Proxy'));
	}

	public function testDisablingPfBlockerNgRestoresTheResolverAndLeavesThePfbDnsToggleAlone(): void
	{
		// Given a moved Resolver, and the admin who disables pfBlockerNG
		$this->activate(TRUE);
		$this->proxyServes();
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::Off);

		// When the pass runs
		pfb_unbound_python('disabled');

		// Then the Resolver is restored as for any disabled package, and the toggle the admin set stays
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertSame('on', $this->toggleStored());
		$this->assertContains('rc stop', $this->proxyCalls);
	}

	public function testRemovingThePackageRestoresTheResolver(): void
	{
		// Given a moved Resolver whose proxy serves
		$this->activate(TRUE);
		$this->proxyServes();

		// When the package is removed
		$removed = pfb_dns_proxy_deinstall();

		// Then the Resolver has its saved settings back and the removal goes on
		$this->assertTrue($removed);
		$this->assertResolverIsTheOriginal('package removal');
	}

	// -----------------------------------------------------------------------
	// Structure: nothing else can bring a restore back
	// -----------------------------------------------------------------------

	/**
	 * @return array{calls:list<string>,functions:list<string>} "<file>::<enclosing function>" of each use of pfb_dns_proxy_resolver (a call, or
	 *         its name as a string), and the name of every function or method defined under src/
	 */
	private function sourceScan(): array
	{
		$calls = [];
		$functions = [];
		$root = dirname(__DIR__, 2) . '/src';
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if (!in_array($file->getExtension(), ['php', 'inc'], TRUE)) {
				continue;
			}
			$tokens = token_get_all((string) file_get_contents($file->getPathname()));
			$relative = substr($file->getPathname(), strlen($root) + 1);
			$stack = [];		// [function name, brace depth its body opened at]
			$depth = 0;
			$pending = NULL;
			foreach ($tokens as $index => $token) {
				if (!is_array($token)) {
					if ($token === '{') {
						$depth++;
						if ($pending !== NULL) {
							$stack[] = [$pending, $depth];
							$pending = NULL;
						}
					} elseif ($token === '}') {
						if ($stack !== [] && end($stack)[1] === $depth) {
							array_pop($stack);
						}
						$depth--;
					} elseif ($token === ';') {
						$pending = NULL;
					}
					continue;
				}
				if ($token[0] === T_CURLY_OPEN || $token[0] === T_DOLLAR_OPEN_CURLY_BRACES) {
					$depth++;
					continue;
				}
				if ($token[0] === T_FUNCTION) {
					for ($next = $index + 1; isset($tokens[$next]); $next++) {
						if (is_array($tokens[$next]) && $tokens[$next][0] === T_STRING) {
							$functions[] = $tokens[$next][1];
							$pending = $tokens[$next][1];
							break;
						}
						if ($tokens[$next] === '(') {
							break;		// a closure: it has no name of its own
						}
					}
				} elseif ($token[0] === T_STRING && $token[1] === 'pfb_dns_proxy_resolver') {
					$previous = $index - 1;
					while (is_array($tokens[$previous]) && $tokens[$previous][0] === T_WHITESPACE) {
						$previous--;
					}
					if (!(is_array($tokens[$previous]) && $tokens[$previous][0] === T_FUNCTION)) {
						$calls[] = "{$relative}::" . ($stack === [] ? '' : end($stack)[0]);
					}
				} elseif ($token[0] === T_CONSTANT_ENCAPSED_STRING && trim($token[1], '\'"') === 'pfb_dns_proxy_resolver') {
					$calls[] = "{$relative}::" . ($stack === [] ? '' : end($stack)[0]) . ' (as a callable)';
				}
			}
		}
		sort($calls);
		return ['calls' => $calls, 'functions' => $functions];
	}

	public function testOnlyTheAdminsSwitchesTheRemovalAndTheWizardCallTheRestore(): void
	{
		// When every use of the restore under src/ is collected from the tokens
		$scan = $this->sourceScan();

		// Then the only callers are the Resolver pass (which restores only while pfB-DNS is not wanted), the package removal, the wizard's reset and the
		// backend port move, which calls it with TRUE and a port: it rewrites Unbound's clause and restores nothing
		$this->assertSame([
			'usr/local/pkg/pfblockerng/pfblockerng.inc::pfb_dns_proxy_backend_move',
			'usr/local/pkg/pfblockerng/pfblockerng.inc::pfb_dns_proxy_deinstall',
			'usr/local/pkg/pfblockerng/pfblockerng.inc::pfb_unbound_python',
			'usr/local/www/wizards/pfblockerng_wizard.inc::step4_submitphpaction',
		], $scan['calls'], 'a new caller of the restore is an automatic restore');
	}

	public function testNoFunctionNamedRollBackRollbackOrStandDownExists(): void
	{
		// When every function defined under src/ is collected from the tokens
		$names = $this->sourceScan()['functions'];

		// Then none says it rolls pfB-DNS back or stands it down
		$this->assertContains('pfb_dns_proxy_resolver', $names, 'test bootstrap: the scan saw the restore\'s own definition');
		$offenders = array_values(array_filter($names, static fn (string $name): bool => preg_match('/roll_?back|stand_?down/i', $name) === 1));
		$this->assertSame([], $offenders);
	}
}
