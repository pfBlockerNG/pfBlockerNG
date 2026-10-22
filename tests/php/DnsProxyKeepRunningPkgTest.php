<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

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
 *   - a pending restart, a gateway or a decider that differs are left for the next pass: no restart, no control-socket request,
 *     the marker kept;
 *   - with pfB-DNS off nothing is deferred and no marker is written, whatever the operation.
 */
#[CoversFunction('pfb_dns_proxy_restart_deferred')]
#[CoversFunction('pfb_dns_proxy_defer_restart')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_reload_unbound')]
final class DnsProxyKeepRunningPkgTest extends TestCase
{
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

	/** A gateway that listens on the control socket and records what it is sent; returns the socket and the record's paths. */
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

	public function testAPendingRestartAndADifferingGatewayAndDeciderAreLeftForTheNextPass(): void
	{
		// Given a pending restart, a gateway binary and a decider that both differ, and a gateway that would take a decider restart
		[$socket, $record] = $this->listen();
		$result = $this->runUnderPkg([
			'op' => 'ensure', 'marker' => 'the package changed its rc script', 'gateway' => 'different', 'decider' => 'different', 'ctl' => $socket,
		]);
		$this->finish();

		// Then nothing restarted, nothing was sent on the control socket, and the pending restart is still there
		$this->assertTrue($result['returned']);
		$this->assertSame([], $result['calls']);
		$this->assertFileDoesNotExist($record, 'no decider restart was sent');
		$this->assertSame('the package changed its rc script', $result['marker']);
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
