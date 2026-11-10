<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3566 -- pfB-DNS keeps running across a package upgrade, and the next update restarts only what changed.
 *
 * Outside a package operation (this process has no pkg ancestor; the rows under one are DnsProxyKeepRunningPkgTest's):
 *   - a pending restart that an upgrade deferred is consumed by ONE whole-pair restart, and a restart that PHP does performs it;
 *   - the gateway's record of the binary it runs (C1) is compared with every installed pfb-dns binary: no match, no record or an
 *     unreadable one is a whole-pair restart; a match, or no installed binary, is no signal;
 *   - a proxy that is not ready is not restarted for a changed gateway binary: it has no running gateway to judge; a quiet box restarts
 *     nothing and sends the gateway nothing but its list request: the one binary decides in-process, so no frame asks it to restart a decider;
 *   - a running gateway the Python-decider package launched (`--` and a decider command on its rc line) is restarted whole by the next
 *     pass, because its rc script changed beyond the listen addresses; under a package operation that is deferred first (DnsProxyKeepRunningPkgTest);
 *   - the listen-address rows (a start's refused address, a pending marker, the tick) are DnsProxyLiveListenersTest's.
 *
 * Every row starts from the quiet box (nothing differs: nothing restarts) and changes one thing.
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_restart')]
#[CoversFunction('pfb_reload_unbound')]
#[CoversFunction('pfblockerng_tick')]
final class DnsProxyKeepRunningTest extends TestCase
{
	use KeepRunningScenario;
	use LiveListenerStandIn;

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::krGlobals() as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_keep_running_' . getmypid() . '_' . bin2hex(random_bytes(4)));
	}

	protected function tearDown(): void
	{
		$this->standInsStop();
		$this->clearProxyFiles();
		@unlink(PFB_DNS_PROXY_RCFILE);
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->krDir);
	}

	private function pair(): array
	{
		return ['restart_service pfb_dns_proxy'];
	}

	public function testAQuietBoxRestartsNothing(): void
	{
		// Given the box with nothing different since the proxy started
		$this->krApply([]);

		// When the apply's pass with nothing to reload runs
		$ready = $this->krEnsure();

		// Then the proxy is left alone
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertNull($this->krMarker());
	}

	public function testAPlainUpdateRollsBackAReadyGatewayWhoseBackendIsDead(): void
	{
		// Given a ready gateway whose Unbound backend is dead, with nothing changed and no package operation
		$this->krApply(['serving' => FALSE]);
		$this->assertTrue(pfb_dns_proxy_ready(), 'before: the gateway is ready');
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'before: the backend is dead');

		// When the apply's pass runs
		$ready = $this->krEnsure();

		// Then the full confirmation judges the upstream: the activation is rolled back and the notice says why
		$this->assertFalse($ready);
		$this->assertStringContainsString('did not become ready', $this->krLog());
	}

	public function testTheChangeGateStaysStrictWhileTheBackendIsDead(): void
	{
		// Given a ready gateway whose Unbound backend is dead, and a gateway binary that differs from the installed one
		$this->krApply(['serving' => FALSE, 'gateway' => 'different']);
		$this->assertTrue(pfb_dns_proxy_ready(), 'before: the gateway is ready');

		// When the apply's pass runs
		$this->krEnsure();

		// Then the change is seen on the gateway's readiness alone: the pair is restarted
		$this->assertContains('restart_service pfb_dns_proxy', $this->krProxyCalls());
	}

	public function testAReloadOutsideAPackageOperationRestartsTheProxyAndConsumesAPendingRestart(): void
	{
		// Given a restart an upgrade deferred, and a reload that restarts Resolver and proxy
		$this->krApply(['marker' => 'the DNSBL module host must reload its lists']);
		$this->assertNotNull($this->krMarker(), 'before: a restart is pending');

		// When the reload runs outside a package operation
		pfb_reload_unbound('enabled', TRUE);

		// Then the proxy was restarted once and the pending restart is gone
		$this->assertSame($this->pair(), $this->krProxyCalls());
		$this->assertNull($this->krMarker(), 'the restart satisfied the pending one');
	}

	public function testAChangedRcScriptOutsideAPackageOperationRestartsTheProxyAndConsumesAPendingRestart(): void
	{
		// Given a running proxy whose rc script differs from the one the pass writes, and a restart already pending
		$this->krApply(['rc' => 'stale', 'marker' => 'the DNSBL module host must reload its lists']);
		$this->assertNotNull($this->krMarker(), 'before: a restart is pending');

		// When the pass runs
		$ready = $this->krEnsure();

		// Then one restart ran and the marker is gone
		$this->assertTrue($ready);
		$this->assertSame($this->pair(), $this->krProxyCalls());
		$this->assertNull($this->krMarker());
	}

	public function testAPendingRestartIsPerformedOnceByTheNextPass(): void
	{
		// Given a quiet box with a restart pending
		$this->krApply(['marker' => 'the package changed its rc script']);
		$this->assertNotNull($this->krMarker(), 'before: a restart is pending');

		// When the pass runs, and then runs again
		$this->assertTrue($this->krEnsure());
		$afterFirst = $this->krProxyCalls();
		$this->assertTrue($this->krEnsure());

		// Then the first restarted the proxy once and consumed the marker; the second restarted nothing
		$this->assertSame($this->pair(), $afterFirst);
		$this->assertNull($this->krMarker());
		$this->assertSame($this->pair(), $this->krProxyCalls(), 'the second pass restarts nothing');
	}

	public function testADeadProxyIsStartedAndItsPendingRestartConsumed(): void
	{
		// Given a proxy that is not running and a restart pending
		$this->krApply(['proxy' => 'dead', 'marker' => 'the package changed its rc script']);
		$this->assertFalse(pfb_dns_proxy_running(), 'before: the proxy is down');

		// When the pass runs
		$ready = $this->krEnsure();

		// Then it is started (not restarted) and nothing stays pending
		$this->assertTrue($ready);
		$this->assertSame(['start_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertNull($this->krMarker());
	}

	public static function gatewayRestarts(): array
	{
		return [
			'record different from every installed binary' => ['different'],
			'no record' => ['absent'],
			'record that cannot be read' => ['unreadable'],
		];
	}

	#[DataProvider('gatewayRestarts')]
	public function testAGatewayRecordThatDoesNotMatchAnInstalledBinaryRestartsTheWholePair(string $gateway): void
	{
		// Given the quiet box, but for the gateway's record of the binary it runs
		$this->krApply(['gateway' => $gateway]);

		// When the pass runs
		$ready = $this->krEnsure();

		// Then both sides restart
		$this->assertTrue($ready);
		$this->assertSame($this->pair(), $this->krProxyCalls());
	}

	public function testAGatewayRecordEqualToAnyInstalledBinaryIsNoSignal(): void
	{
		// Given two installed binaries and the record of the second: one machine runs only its own
		$this->krApply(['gateway' => 'equal_one_of_two']);

		// When the pass runs
		$this->assertTrue($this->krEnsure());

		// Then nothing restarts
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testNoInstalledBinaryIsNoGatewaySignal(): void
	{
		// Given a record that matches nothing, and no installed binary to match it against
		$this->krApply(['gateway' => 'none']);

		// When the pass runs
		$this->assertTrue($this->krEnsure());

		// Then nothing restarts
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testALeftoverDeciderRecordThatDiffersFromTheInstalledCodeRestartsNothingAndSendsNoDeciderRestartFrame(): void
	{
		// Given a gateway that is current and lists exactly what the rc script serves on its control socket, and the code record the
		// Python decider left beside it, which differs from the decider files still on disk (what a decider-only restart once acted on)
		$socket = "{$this->krDir}/ctl.sock";
		$record = $this->standIn($socket, [], ['listening' => ['udp+tcp 192.0.2.1:53', 'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53']]);
		$this->krApply(['ctl' => $socket]);
		file_put_contents("{$this->krDir}/pfb_dns_proxy.py", 'the decider as the package installed it');
		file_put_contents("{$this->krDir}/decider.applied", str_repeat('0', 32));
		$GLOBALS['pfb']['dns_proxy_decider_src'] = ["{$this->krDir}/pfb_dns_proxy.py"];
		$GLOBALS['pfb']['dns_proxy_decider_applied'] = "{$this->krDir}/decider.applied";
		$this->assertTrue(pfb_dns_proxy_ready(), 'before: the gateway is ready');

		// When the pass runs
		$ready = $this->krEnsure();
		$this->standInsStop();

		// Then nothing restarts and no frame is the four 0xFF bytes that once asked the gateway to restart its decider
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([], array_values(array_filter(self::frames($record), static fn (array $frame): bool => $frame['head'] === 'ffffffff')));
		$this->assertNull($this->krMarker());
	}

	public function testAProxyThatIsAliveButNotReadyIsNotRestartedForADifferingGateway(): void
	{
		// Given a live proxy that never published its marker, with a gateway binary that differs; the rollback its failed
		// readiness leads to finds the config locked
		$this->krApply(['gateway' => 'different']);
		$this->proxyLivesButNeverServes();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$this->assertFalse(pfb_dns_proxy_ready(), 'before: the proxy is alive and not ready');

		// When the pass runs
		$this->krEnsure();

		// Then the gateway it has no running record of is not restarted
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testARunningGatewayStartedByTheOldPythonDeciderLineIsRestartedByTheNextPass(): void
	{
		// Given a running gateway whose rc script is the one the Python-decider package wrote (`-- ... pfb_dns_proxy.py ...`)
		$this->krApply(['rc' => 'python_decider']);
		$this->assertStringContainsString('--decision-fd 3', (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the script launches a decider');

		// When the pass runs outside a package operation
		$ready = $this->krEnsure();

		// Then the whole pair restarts onto the one-binary line, for the changed script
		$this->assertTrue($ready);
		$this->assertSame($this->pair(), $this->krProxyCalls());
		$this->assertStringContainsString('Restarting the DNS proxy: its launch line changed to the one-binary gateway', $this->krLog());
		$this->assertStringNotContainsString('its ports or DoT/DoH/DoQ/DDR settings changed', $this->krLog());
		$this->assertStringNotContainsString('--decision-fd', (string) file_get_contents(PFB_DNS_PROXY_RCFILE));
	}

	public function testTheRestartAPackageOperationDeferredForTheOldPythonDeciderLineIsPerformedByTheNextPass(): void
	{
		// Given the pending restart a package operation recorded for that old script (DnsProxyKeepRunningPkgTest), and the new script written since
		$this->krApply(['marker' => 'its listen addresses or DoH/DoQ/DDR settings changed']);
		$this->assertNotNull($this->krMarker(), 'before: a restart is pending');

		// When the next pass runs outside the operation
		$ready = $this->krEnsure();

		// Then it restarts the whole pair once and consumes the marker
		$this->assertTrue($ready);
		$this->assertSame($this->pair(), $this->krProxyCalls());
		$this->assertNull($this->krMarker());
	}

	/** @return array<string,array{string}> every function that only the separate Python decider's lifecycle needed */
	public static function removedFunctions(): array
	{
		return [
			'the decider restart on the control socket' => ['pfb_dns_proxy_decider_restart'],
			'the changed-decider-code check' => ['pfb_dns_proxy_decider_changed'],
			'the second-decider memory check' => ['pfb_dns_proxy_decider_restart_fits_ram'],
			"the decider's code fingerprint" => ['pfb_unbound_py_module_fingerprint'],
		];
	}

	#[DataProvider('removedFunctions')]
	public function testNoPathExistsForTheSeparateDecider(string $function): void
	{
		$this->assertFalse(function_exists($function), "{$function} served only the separate Python decider, which pfB-DNS no longer runs");
	}
}
