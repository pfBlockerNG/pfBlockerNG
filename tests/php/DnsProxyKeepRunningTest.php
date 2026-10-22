<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';

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
 *   - the decider's record of its code (C2) is compared with the installed files: a different or absent record is a decider-only
 *     restart on the control socket (four 0xFF bytes), answered `ok`; any other answer, or no socket, is a whole-pair restart;
 *     files that cannot be read are no signal;
 *   - a proxy that is not ready is never asked for either restart, and a due whole-pair restart never also sends the decider's.
 *
 * Every row starts from the quiet box (nothing differs: nothing restarts) and changes one thing.
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_decider_restart')]
#[CoversFunction('pfb_dns_proxy_restart')]
#[CoversFunction('pfb_reload_unbound')]
final class DnsProxyKeepRunningTest extends TestCase
{
	use KeepRunningScenario;

	private array $savedGlobals = [];
	/** @var list<array{resource,array<int,resource>}> */
	private array $servers = [];

	protected function setUp(): void
	{
		foreach (self::krGlobals() as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_keep_running_' . getmypid() . '_' . bin2hex(random_bytes(4)));
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as [$proc, $pipes]) {
			@fclose($pipes[0]);
			@fclose($pipes[1]);
			@fclose($pipes[2]);
			proc_close($proc);
		}
		$this->servers = [];
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

	/** A gateway that listens on the control socket for the decider restart; returns the file its request is recorded in. */
	private function listen(string $reply = "ok\n"): string
	{
		$socket = "{$this->krDir}/ctl.sock";
		$record = "{$this->krDir}/ctl.request." . count($this->servers);
		$proc = proc_open(
			[PHP_BINARY, __DIR__ . '/support/DeciderControlServer.php', $socket, $record, $reply === '' ? '-' : bin2hex($reply)],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
			$pipes
		);
		$this->assertIsResource($proc);
		$read = [$pipes[1]];
		$write = $except = NULL;
		$this->assertSame(1, stream_select($read, $write, $except, 15), 'the stand-in gateway did not start listening');
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$proc, $pipes];
		return $record;
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

	public function testAReloadOutsideAPackageOperationRestartsTheProxyAndConsumesAPendingRestart(): void
	{
		// Given a restart an upgrade deferred, and a reload that restarts Resolver and proxy
		$this->krApply(['marker' => 'the DNSBL module host must reload its lists']);
		$this->assertNotNull($this->krMarker(), 'before: a restart is pending');

		// When the reload runs outside a package operation
		pfb_reload_unbound('enabled', FALSE, TRUE);

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

		// Then both sides restart, and the decider alone is never asked to
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

	public static function deciderRestarts(): array
	{
		return [
			'record different from the installed files' => ['different'],
			'no record' => ['absent'],
		];
	}

	#[DataProvider('deciderRestarts')]
	public function testAChangedDeciderIsRestartedAloneOnTheControlSocket(string $decider): void
	{
		// Given a gateway that is current and a decider whose record is not, and a gateway that takes the restart
		$this->krApply(['decider' => $decider]);
		$record = $this->listen("ok\n");

		// When the pass runs
		$ready = $this->krEnsure();
		$this->finish();

		// Then the gateway got exactly the four 0xFF bytes, and the proxy was not restarted
		$this->assertTrue($ready);
		$this->assertSame("\xFF\xFF\xFF\xFF", (string) @file_get_contents($record));
		$this->assertSame([], $this->krProxyCalls());
		$this->assertNull($this->krMarker());
	}

	public function testADeciderRestartTheGatewayRefusesFallsBackToARestartOfTheWholePair(): void
	{
		// Given a changed decider and a gateway that answers with an error
		$this->krApply(['decider' => 'different']);
		$record = $this->listen("error: no READY from the new decider\n");

		// When the pass runs
		$ready = $this->krEnsure();
		$this->finish();

		// Then the request was sent, the error is in the log, and the whole pair restarted
		$this->assertTrue($ready);
		$this->assertSame("\xFF\xFF\xFF\xFF", (string) @file_get_contents($record));
		$this->assertStringContainsString('no READY from the new decider', $this->krLog());
		$this->assertSame($this->pair(), $this->krProxyCalls());
	}

	public function testADeciderRestartWithNoControlSocketFallsBackToARestartOfTheWholePair(): void
	{
		// Given a changed decider and nothing listening on the control socket
		$this->krApply(['decider' => 'different']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_ctl'], 'before: no control socket');

		// When the pass runs
		$ready = $this->krEnsure();

		// Then the whole pair restarted
		$this->assertTrue($ready);
		$this->assertSame($this->pair(), $this->krProxyCalls());
	}

	public function testDeciderFilesThatCannotBeReadAreNoSignal(): void
	{
		// Given a changed decider record, but an installed file that is missing: no fingerprint to compare
		$this->krApply(['decider' => 'unreadable_member']);
		$record = $this->listen("ok\n");

		// When the pass runs
		$ready = $this->krEnsure();
		$this->finish();

		// Then nothing is sent and nothing restarts
		$this->assertTrue($ready);
		$this->assertFileDoesNotExist($record, 'nothing connected to the control socket');
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAProxyThatIsAliveButNotReadyIsNeitherRestartedNorAskedOnTheControlSocket(): void
	{
		// Given a live proxy that never published its marker, with a gateway and a decider that both differ; the rollback its
		// failed readiness leads to finds the config locked
		$this->krApply(['gateway' => 'different', 'decider' => 'different']);
		$this->proxyLivesButNeverServes();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$record = $this->listen("ok\n");
		$this->assertFalse(pfb_dns_proxy_ready(), 'before: the proxy is alive and not ready');

		// When the pass runs
		$this->krEnsure();
		$this->finish();

		// Then neither restart was asked for
		$this->assertFileDoesNotExist($record, 'no decider restart was sent');
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testADueWholePairRestartNeverAlsoSendsTheDeciderRestart(): void
	{
		// Given a restart pending and a decider that differs too
		$this->krApply(['marker' => 'the package changed its rc script', 'decider' => 'different']);
		$record = $this->listen("ok\n");

		// When the pass runs
		$ready = $this->krEnsure();
		$this->finish();

		// Then the whole pair restarted and the control socket was not used
		$this->assertTrue($ready);
		$this->assertSame($this->pair(), $this->krProxyCalls());
		$this->assertFileDoesNotExist($record, 'no decider restart was sent');
		$this->assertNull($this->krMarker());
	}

	public function testADeciderRestartIsBoundedWhenTheGatewayNeverAnswers(): void
	{
		// Given a gateway that takes the request and never replies
		$record = $this->listen('');
		$start = hrtime(TRUE);

		// When the restart waits 0.3 s for the reply
		$why = pfb_dns_proxy_decider_restart("{$this->krDir}/ctl.sock", 0.3);
		$seconds = (hrtime(TRUE) - $start) / 1e9;
		$this->finish();

		// Then it gives up with a reason, soon, after sending the request
		$this->assertIsString($why);
		$this->assertStringContainsString('no reply', $why);
		$this->assertLessThan(5.0, $seconds, 'the wait is bounded by the timeout');
		$this->assertSame("\xFF\xFF\xFF\xFF", (string) @file_get_contents($record));
	}

	public function testADeciderRestartTheGatewayAnswersOkIsDoneAndAnErrorIsItsReason(): void
	{
		// Given gateways that answer `ok` and an error
		$record = $this->listen("ok\n");
		$ok = pfb_dns_proxy_decider_restart("{$this->krDir}/ctl.sock", 3.0);
		$this->finish();
		$this->assertSame("\xFF\xFF\xFF\xFF", (string) @file_get_contents($record));
		$this->listen("error: the gateway is stopping\n");
		$refused = pfb_dns_proxy_decider_restart("{$this->krDir}/ctl.sock", 3.0);
		$this->finish();

		// Then ok is NULL and the error comes back as the reason
		$this->assertNull($ok);
		$this->assertIsString($refused);
		$this->assertStringContainsString('the gateway is stopping', $refused);
	}
}
