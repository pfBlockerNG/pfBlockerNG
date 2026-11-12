<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3566 -- while a package operation (pkg install, upgrade or reinstall) runs, pfB-DNS is not restarted: the restart is
 * deferred, one pending-restart marker records it, and the next pass outside the operation performs it once.
 *
 * "Under a package operation" is what pfb_pkg_operation() reads from the live process table, so each row runs in a child process
 * (support/KeepRunningWorker.php) that is a descendant of a process whose command line is `pkg upgrade`: the test starts
 * `exec -a pkg /bin/sh upgrade`, whose script runs the worker. Nothing is stubbed; every row asserts the worker really saw the
 * operation (before-state), so a seam that stopped reaching it fails loudly instead of passing the rows vacuously.
 *
 * Intent pinned here:
 *   - the Resolver reload's proxy restart, an rc script that changed and a proxy that must reload its lists are deferred, never
 *     performed, and each records its reason in the marker;
 *   - a proxy that is down is still started (and nothing stays pending);
 *   - a pending restart and a gateway that differs are left for the next pass: no restart, the marker kept;
 *   - an address-only change of the rc script (issue #3599) and a start that could not assign an address the box can bind now (issue
 *     #3598) are neither made live nor restarted by the update pass or the cron tick under one: no add or remove is sent on the control
 *     socket (the gateway is only asked what it serves), the first is recorded as a pending restart (DnsProxyLiveListenersTest has the live changes outside one);
 *   - with pfB-DNS off nothing is deferred and no marker is written, whatever the operation.
 */
#[CoversFunction('pfb_dns_proxy_restart_deferred')]
#[CoversFunction('pfb_dns_proxy_defer_restart')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfblockerng_tick')]
#[CoversFunction('pfb_reload_unbound')]
final class DnsProxyKeepRunningPkgTest extends TestCase
{
	use LiveListenerStandIn;

	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_keep_running_pkg_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		$this->standInsStop();
		rmdir_recursive($this->dir);
	}

	/** @return array<string,mixed> what the worker saw and did, run as a descendant of `pkg upgrade` */
	private function runUnderPkg(array $scenario): array
	{
		$resultFile = "{$this->dir}/result.json";
		// The script runs the worker as a child (no exec): the process the table shows as `pkg upgrade` is the worker's ancestor
		file_put_contents("{$this->dir}/upgrade", '#!/bin/sh' . "\n" . implode(' ', array_map('escapeshellarg', [
			PHP_BINARY, __DIR__ . '/support/KeepRunningWorker.php', json_encode($scenario, JSON_THROW_ON_ERROR), $resultFile,
		])) . "\n");
		$run = pfb_test_run_process(['bash', '-c', 'cd "$1" && exec -a pkg /bin/sh upgrade', '_', $this->dir], 120.0);
		$this->assertSame(0, $run['exit'], "the worker failed:\n{$run['stdout']}\n{$run['stderr']}");
		$result = json_decode((string) file_get_contents($resultFile), TRUE, 8, JSON_THROW_ON_ERROR);
		$this->assertSame('upgrade', $result['operation'], 'before: the worker runs under a package upgrade');
		return $result;
	}

	public function testTheReloadsProxyRestartIsDeferredAndRecordsItsReason(): void
	{
		// Given a quiet box and a Resolver reload that restarts the proxy, run under a package upgrade
		$result = $this->runUnderPkg(['op' => 'reload']);

		// Then the proxy was not restarted, and a pending restart says why
		$this->assertSame([], $result['calls']);
		$this->assertIsString($result['marker']);
		$this->assertStringContainsString('reload its lists', $result['marker']);
		$this->assertStringContainsString('deferred', $result['log']);
	}

	public function testAChangedRcScriptIsDeferredWhileTheProxyKeepsRunning(): void
	{
		// Given a running proxy whose rc script the package changed
		$result = $this->runUnderPkg(['op' => 'ensure', 'rc' => 'stale']);

		// Then it is not restarted, and a pending restart records it
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertNotNull($result['marker']);
		$this->assertStringContainsString('deferred', $result['log']);
	}

	public function testADeadProxyIsStillStartedAndNothingStaysPending(): void
	{
		// Given a proxy that is down, with a restart already pending, and an Unbound backend that answers
		$result = $this->runUnderPkg(['op' => 'ensure', 'proxy' => 'dead', 'marker' => 'the package changed its rc script', 'serving' => TRUE]);

		// Then it is started, and the start satisfies the pending restart
		$this->assertTrue($result['returned']);
		$this->assertSame(['start_service pfb_dns_proxy'], $result['calls']);
		$this->assertNull($result['marker']);
	}

	public function testADeadProxyStartedUnderAPackageOperationLeavesTheResolverMovedWhenItsBackendIsDead(): void
	{
		// Given a proxy that is down with a restart pending, and no Unbound answering behind the gateway it starts
		$result = $this->runUnderPkg(['op' => 'ensure', 'proxy' => 'dead', 'marker' => 'the package changed its rc script']);

		// Then the start is judged in full: the gateway serves, but its upstream does not, so it is not ready, and nothing is given back
		$this->assertFalse($result['returned']);
		$this->assertFalse($result['stopped'], 'the gateway is not stopped');
		$this->assertSame($result['saved_before'], $result['saved_after'], 'the snapshot is kept');
		$this->assertSame($result['resolver_before'], $result['resolver_after'], 'the Resolver stays moved');
		$this->assertTrue($result['running']);
	}

	public function testADeferredPassLeavesAnUnreadyGatewayAndItsResolverUntouchedWhenItStartsNothing(): void
	{
		// Given a live gateway that never publishes its marker, and an rc script the package changed
		$result = $this->runUnderPkg(['op' => 'ensure', 'proxy' => 'lives', 'rc' => 'stale']);

		// Then the existing startup notice reports it as unready, but this pass never stops it or restores the Resolver
		$this->assertFalse($result['returned']);
		$this->assertStringContainsString('did not become ready', $result['log']);
		$this->assertSame([], $result['calls']);
		$this->assertFalse($result['stopped']);
		$this->assertSame($result['saved_before'], $result['saved_after']);
		$this->assertSame($result['resolver_before'], $result['resolver_after']);
		$this->assertTrue($result['running']);
	}

	public function testAReloadStartsADeadProxyEvenUnderAPackageOperation(): void
	{
		// Given a proxy that is down when the Resolver reload ends
		$result = $this->runUnderPkg(['op' => 'reload', 'proxy' => 'dead']);

		// Then it is started again (deferring would leave the module host down) and nothing stays pending
		$this->assertSame(['restart_service pfb_dns_proxy'], $result['calls']);
		$this->assertNull($result['marker']);
	}

	public function testADeferredPassStillFilesAListenerTheGatewayDidNotReport(): void
	{
		// Given a quiet box under a package upgrade, a DoT listener on lan, and a gateway that lists every listener but that one
		$this->standIn("{$this->dir}/live.sock", [], ['listening' => [
			'udp+tcp 192.0.2.1:53', 'udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53', 'dot 127.0.0.1:853', 'dot [::1]:853',
		]]);
		$result = $this->runUnderPkg(['op' => 'ensure', 'dot' => TRUE, 'ctl' => "{$this->dir}/live.sock"]);

		// Then nothing restarts and the pass returns ready, and the missing listener is still filed as a startup problem
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertStringContainsString('pfB-DNS started with problems', $result['log']);
		$this->assertStringContainsString('DoT is not served on 192.0.2.1:853', $result['log']);
	}

	public function testAPendingRestartAndADifferingGatewayAreLeftForTheNextPass(): void
	{
		// Given a pending restart and a gateway binary that differs
		$result = $this->runUnderPkg(['op' => 'ensure', 'marker' => 'the package changed its rc script', 'gateway' => 'different']);

		// Then nothing restarted, and the pending restart is still there
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertSame('the package changed its rc script', $result['marker']);
	}

	public function testAGatewayStartedByTheOldPythonDeciderLineKeepsRunningAndItsRestartIsDeferred(): void
	{
		// Given a running gateway whose rc script still has the Python decider after `--`, and the package's one-binary line to write
		$result = $this->runUnderPkg(['op' => 'ensure', 'rc' => 'python_decider']);

		// Then it is not restarted under the package operation, and a pending restart records it for the next pass
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertSame('its listen addresses, upstream port or DoH/DoQ/DDR settings changed', $result['marker']);
		$this->assertStringContainsString('deferred', $result['log']);
	}

	/**
	 * What the gateway serves after a start that could not assign 127.0.0.1 (this host binds it now), the other two addresses listening,
	 * with the rc script's port at $port: a live add would be sent here, were it not for the package operation.
	 *
	 * @return array{listening:list<string>,refused:array<string,string>}
	 */
	private static function refusedStart(int $port): array
	{
		return [
			'listening' => ["udp+tcp 192.0.2.1:{$port}", "udp+tcp [::1]:{$port}"],
			'refused' => ["udp+tcp 127.0.0.1:{$port}" => "bind: can't assign requested address"],
		];
	}

	public function testAnAddressTheStartCouldNotAssignIsNeitherAddedNorRestartedByTheUpdatePassUnderAPackageOperation(): void
	{
		// Given a quiet box whose latest start refused an address that can be bound now, run under a package upgrade, and a gateway that would take the add
		$port = self::freePort();
		$record = $this->standIn("{$this->dir}/live.sock", [], self::refusedStart($port));
		$result = $this->runUnderPkg(['op' => 'ensure', 'port' => (string) $port, 'ctl' => "{$this->dir}/live.sock"]);

		// Then the proxy is left running: no frame is sent, and no restart is made or announced
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertSame([], self::changeFrames($record));
		$this->assertStringNotContainsString('Restarting the DNS proxy', $result['log']);
	}

	public function testAnAddressTheStartCouldNotAssignIsNeitherAddedNorRestartedByTheCronTickUnderAPackageOperation(): void
	{
		// Given a serving proxy whose latest start refused an address that can be bound now, the cron tick run under a package upgrade, and a gateway that would take the add
		$port = self::freePort();
		$record = $this->standIn("{$this->dir}/live.sock", [], self::refusedStart($port));
		$result = $this->runUnderPkg(['op' => 'tick', 'serving' => TRUE, 'port' => (string) $port, 'ctl' => "{$this->dir}/live.sock"]);

		// Then the proxy is left running: no frame is sent, and no restart is made or announced
		$this->assertSame([], $result['calls']);
		$this->assertSame([], self::changeFrames($record));
		$this->assertStringNotContainsString('Restarting the DNS proxy', $result['log']);
	}

	public function testAnAddressOnlyChangeOfTheRcScriptIsRecordedAsAPendingRestartAndSendsNothingUnderAPackageOperation(): void
	{
		// Given a running proxy whose rc script differs from the one the pass writes only in a listen address (the gateway served 192.0.2.1,
		// the interface has 0.0.0.0 now), run under a package upgrade, and a gateway that would take the change
		$port = self::freePort();
		$served = ['listening' => ["udp+tcp 192.0.2.1:{$port}", "udp+tcp 127.0.0.1:{$port}", "udp+tcp [::1]:{$port}"]];
		$record = $this->standIn("{$this->dir}/live.sock", [], $served);
		$result = $this->runUnderPkg(['op' => 'ensure', 'port' => (string) $port, 'lan' => '0.0.0.0', 'ctl' => "{$this->dir}/live.sock"]);

		// Then nothing was sent or restarted, and the restart is pending as it is for any other change of the script
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertSame([], self::changeFrames($record));
		$this->assertIsString($result['marker']);
		$this->assertStringContainsString('listen addresses', $result['marker']);
		$this->assertStringContainsString('deferred', $result['log']);
	}

	public static function passes(): array
	{
		return [
			'the apply with nothing to reload' => ['ensure'],
			'the Resolver reload' => ['reload'],
		];
	}

	#[DataProvider('passes')]
	public function testWithPfbDnsOffNothingIsDeferredAndNoMarkerIsWritten(string $op): void
	{
		// Given no snapshot (pfB-DNS off), a proxy that is not running and an rc script that differs
		$result = $this->runUnderPkg(['op' => $op, 'snapshot' => FALSE, 'proxy' => 'dead', 'rc' => 'stale']);

		// Then the proxy is not touched and nothing is recorded as pending
		$this->assertSame([], $result['calls']);
		$this->assertNull($result['marker']);
	}

	public static function foreignOwnershipUnderPackage(): array
	{
		return ['the update pass' => ['ensure', FALSE], 'the cron tick' => ['tick', NULL]];
	}

	#[DataProvider('foreignOwnershipUnderPackage')]
	public function testAForeignHolderUnderAPackageOperationStopsTheGatewayMovesNothingAndRestoresNothing(string $op, ?bool $returned): void
	{
		// Given a serving gateway whose Unbound port a stranger holds, the DNS Resolver enabled and a free pair above it, in a pass that runs as a descendant of pkg(8): nothing restarts under one
		$result = $this->runUnderPkg(['op' => $op, 'serving' => TRUE, 'foreign_upstream' => TRUE]);
		$this->assertTrue($result['unbound_before'], 'the live Unbound exists despite the foreign port holder');
		$this->assertTrue($result['gateway_before']);
		$this->assertFalse($result['serving_before']);
		$this->assertSame($returned, $result['returned']);

		// Then the pair is not moved and Unbound is not restarted (the package operation defers both), but the gateway is not left
		// forwarding to the stranger either: it is stopped and the status says who holds the port; the Resolver and the snapshot are kept
		$this->assertSame(['stop_service pfb_dns_proxy'], $result['calls'], 'the gateway was stopped once and nothing was restarted');
		$this->assertSame(0, $result['configures'], 'Unbound was not regenerated or restarted');
		$this->assertFalse($result['running'], 'the gateway is not running');
		$this->assertIsString($result['blocked'], 'the stopped state stands for the next pass outside the package operation');
		$this->assertStringStartsWith("holder\n5353\nnc (pid 6161) on 127.0.0.1:5353\n", $result['blocked'], 'a holder that no move cleared, not a lack of pairs');
		$this->assertSame('Not serving: nc (pid 6161) on 127.0.0.1:5353 holds the Resolver backend port 5353', $result['service']);
		$this->assertCount(1, $result['notices'], 'one notice');
		$this->assertStringContainsString("Unbound's backend cannot be moved (a package operation is running)", $result['notices'][0], 'the package operation is why, not a disabled Resolver');
		$this->assertFalse($result['stopped'], 'the Resolver restore\'s rc stop never ran');
		$this->assertSame($result['saved_before'], $result['saved_after'], 'the snapshot is kept');
		$this->assertSame($result['resolver_before'], $result['resolver_after'], 'the Resolver stays moved');
	}
}
