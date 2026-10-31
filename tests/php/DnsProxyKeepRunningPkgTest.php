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
 *   - a pending restart, a gateway or a decider that differs are left for the next pass: no restart, no decider restart on the control
 *     socket (the gateway is only asked what it serves), the marker kept;
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
	use LiveListenerStandIn {
		frames as private everyFrame;
	}

	private string $dir = '';
	/** @var list<array{resource,array<int,resource>}> */
	private array $servers = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_keep_running_pkg_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		$this->finish();
		$this->standInsStop();
		rmdir_recursive($this->dir);
	}

	/** Let the stand-in gateways go (their stdin closes) so that what they recorded is complete. */
	private function finish(): void
	{
		foreach ($this->servers as [$proc, $pipes]) {
			@fclose($pipes[0]);
			@fclose($pipes[1]);
			@fclose($pipes[2]);
			proc_close($proc);
		}
		$this->servers = [];
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

	/** A gateway that listens on the control socket and records what it is sent but for the list request, which it answers as an older gateway does; returns the socket and the record's paths. */
	private function listen(): array
	{
		$socket = "{$this->dir}/ctl.sock";
		$record = "{$this->dir}/ctl.request";
		$proc = proc_open(
			[PHP_BINARY, __DIR__ . '/support/DeciderControlServer.php', $socket, $record, bin2hex("ok\n")],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
			$pipes
		);
		$this->assertIsResource($proc);
		$read = [$pipes[1]];
		$write = $except = NULL;
		$this->assertSame(1, stream_select($read, $write, $except, 15), 'the stand-in gateway did not start listening');
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$proc, $pipes];
		return [$socket, $record];
	}

	/** @return list<array{head:string,body:string,fds:list<array{type:string,name:string,listening:bool}>}> the frames that change the gateway: the pass's own listener-list request (issue #3625) is not one */
	private static function frames(string $record): array
	{
		return array_values(array_filter(self::everyFrame($record), static fn (array $frame): bool => $frame['head'] !== 'fffffffc'));
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

	public function testADeadProxyStartedUnderAPackageOperationIsRolledBackWhenItsBackendIsDead(): void
	{
		// Given a proxy that is down with a restart pending, and no Unbound answering behind the gateway it starts
		$result = $this->runUnderPkg(['op' => 'ensure', 'proxy' => 'dead', 'marker' => 'the package changed its rc script']);

		// Then the start is judged in full: the gateway serves, but its upstream does not, so the start is rolled back
		$this->assertFalse($result['returned']);
		$this->assertStringContainsString('did not become ready', $result['log']);
	}

	public function testADeferredPassWhoseGatewayIsNotReadyGetsTheFullConfirmation(): void
	{
		// Given a live gateway that never publishes its marker, and an rc script the package changed
		$result = $this->runUnderPkg(['op' => 'ensure', 'proxy' => 'lives', 'rc' => 'stale']);

		// Then the pass is not taken as quiet: the full confirmation runs and, the gateway never ready, rolls the start back
		$this->assertFalse($result['returned']);
		$this->assertStringContainsString('did not become ready', $result['log']);
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

	public function testAPendingRestartAndADifferingGatewayAndDeciderAreLeftForTheNextPass(): void
	{
		// Given a pending restart, a gateway binary and a decider that both differ, and a gateway that would take a decider restart
		[$socket, $record] = $this->listen();
		$result = $this->runUnderPkg([
			'op' => 'ensure', 'marker' => 'the package changed its rc script', 'gateway' => 'different', 'decider' => 'different', 'ctl' => $socket,
		]);
		$this->finish();

		// Then nothing restarted, no decider restart was sent on the control socket, and the pending restart is still there
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertFileDoesNotExist($record, 'no decider restart was sent');
		$this->assertSame('the package changed its rc script', $result['marker']);
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
		$this->assertSame([], self::frames($record));
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
		$this->assertSame([], self::frames($record));
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
		$this->assertSame([], self::frames($record));
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
}
