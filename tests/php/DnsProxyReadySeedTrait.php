<?php

declare(strict_types=1);

require_once __DIR__ . '/support/PfbFlockClockFixture.php';

/**
 * issue #3515 -- seeds the two files the DNS proxy's readiness is read from, as real files, and answers liveness through the
 * isvalidpid() double (a test never starts a process): the daemon's child pidfile ($pfb['dns_proxy_pidfile'], what
 * `daemon -p` writes) and the listener-ready marker ($pfb['dns_proxy_ready'], what the proxy's --ready-file writes).
 * The bootstrap points both at its own sandbox, so a test never reads or writes the appliance's /var/run or /var/unbound.
 */
trait DnsProxyReadySeedTrait
{
	/** @var array<string,string|false> */
	private array $upstreamFiles = [];
	private array $upstreamPidState = [];
	private array $upstreamRcDirState = [];

	private function unboundPidfile(): string
	{
		return $GLOBALS['g']['varrun_path'] . '/unbound.pid';
	}

	private function setUpUpstreamFixture(): void
	{
		$this->upstreamRcDirState = [
			array_key_exists('pfb_test_rcfile_dir', $GLOBALS),
			$GLOBALS['pfb_test_rcfile_dir'] ?? NULL,
		];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		foreach ([$this->unboundPidfile(), $GLOBALS['pfb_test_sockstat_output'], $GLOBALS['pfb_test_sockstat_status'], PFB_DNS_PROXY_RCFILE] as $file) {
			$this->upstreamFiles[$file] = is_file($file) ? file_get_contents($file) : FALSE;
		}
		$this->upstreamPidState = [
			array_key_exists($this->unboundPidfile(), $GLOBALS['pfb_test_valid_pids'] ?? []),
			$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] ?? NULL,
		];
		$this->seedUnbound();
	}

	private function tearDownUpstreamFixture(): void
	{
		foreach ($this->upstreamFiles as $file => $contents) {
			if ($contents === FALSE) {
				@unlink($file);
			} else {
				file_put_contents($file, $contents);
			}
		}
		[$existed, $value] = $this->upstreamPidState;
		if ($existed) {
			$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = $value;
		} else {
			unset($GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()]);
		}
		$this->upstreamFiles = [];
		[$existed, $value] = $this->upstreamRcDirState;
		if ($existed) {
			$GLOBALS['pfb_test_rcfile_dir'] = $value;
		} else {
			unset($GLOBALS['pfb_test_rcfile_dir']);
		}
	}

	/** Backend health is independent of the gateway's marker: failed-backend tests never get it from proxyServes(). */
	private function seedUnbound(string $endpoint = '127.0.0.1:5353', string $pid = '5151', bool $alive = TRUE): void
	{
		file_put_contents($this->unboundPidfile(), "{$pid}\n");
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = $alive;
		$family = str_starts_with($endpoint, '[') ? '6' : '4';
		file_put_contents($GLOBALS['pfb_test_sockstat_output'],
			"USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n"
			. "unbound unbound {$pid} 3 tcp{$family} {$endpoint} *:*\n"
			. "unbound unbound {$pid} 4 udp{$family} {$endpoint} *:*\n");
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "0\n");
	}

	private function proxyPidfile(): string
	{
		return (string) $GLOBALS['pfb']['dns_proxy_pidfile'];
	}

	private function proxyMarker(): string
	{
		return (string) $GLOBALS['pfb']['dns_proxy_ready'];
	}

	/** A proxy whose child is $child: its pidfile names it and the double says it lives; the marker is $marker ('' = absent). */
	private function seedProxy(string $child, ?string $marker, bool $alive = TRUE): void
	{
		// The process table lists no gateway until a test seeds its command line (seedRunningGateway())
		file_put_contents($GLOBALS['pfb_test_ps_output'], '');
		file_put_contents($this->proxyPidfile(), "{$child}\n");
		if ($marker === NULL) {
			@unlink($this->proxyMarker());
		} else {
			file_put_contents($this->proxyMarker(), $marker);
		}
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = $alive;
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_PIDFILE] = $alive;
	}

	/** The proxy as the real one comes up: child 4242, and the marker it publishes once it serves. */
	private function proxyServes(string $child = '4242'): void
	{
		$this->seedProxy($child, "{$child}\n");
	}

	/** A process that lives and never publishes the marker: a listener that failed to bind or to initialize. */
	private function proxyLivesButNeverServes(string $child = '4242'): void
	{
		$this->seedProxy($child, NULL);
	}

	/**
	 * The running gateway's command line in the process table, for child $child: the installed binary the wrapper execs, with its
	 * --upstream ($upstream = NULL: none). The running argv names the endpoint the gateway forwards to, not the rc script.
	 */
	private function seedRunningGateway(string $child = '4242', ?string $upstream = '127.0.0.1:5353'): void
	{
		$flag = $upstream === NULL ? '' : " --upstream {$upstream}";
		file_put_contents($GLOBALS['pfb_test_ps_output'], "{$child} " . PFB_DNS_PROXY_DIR
			. "/bin/freebsd-amd64/pfb-dns --listen 127.0.0.1 --port 53 --ready-file /var/unbound/pfb_dns_ready{$flag}\n");
	}

	private function clearProxyFiles(): void
	{
		@unlink($this->proxyPidfile());
		@unlink($this->proxyMarker());
		unset($GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()], $GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_PIDFILE]);
		file_put_contents($GLOBALS['pfb_test_ps_output'], '');
	}

	/**
	 * A proxy as a running box has it: child and supervisor pidfiles valid, the marker naming the child. Every stop the proxy is
	 * asked for (the rc script's own, through mwexec(), and stop_service()) clears all of it, so a test that must not stop the
	 * proxy reads that state back instead of counting calls.
	 */
	private function seedLiveProxyThatAStopClears(): void
	{
		$this->proxyServes();
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE] = TRUE;
		$stop = function (): void {
			$this->clearProxyFiles();
			unset($GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_DAEMON_PIDFILE]);
		};
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn, string $service) use ($stop): void {
			if ($fn === 'stop_service' && $service === 'pfb_dns_proxy') {
				$stop();
			}
		};
		$GLOBALS['pfb_test_mwexec_hook'] = static function (string $command) use ($stop): int {
			if ($command === PFB_DNS_PROXY_RCFILE . ' stop') {
				$stop();
			}
			return 0;
		};
	}

	/** The proxy seeded by seedLiveProxyThatAStopClears() is untouched: both pids live, the marker names the child. */
	private function assertProxyStillServes(string $why): void
	{
		$this->assertTrue(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), "{$why}: the supervisor still lives");
		$this->assertTrue(pfb_dns_proxy_running(), "{$why}: the child still lives");
		$this->assertSame("4242\n", (string) @file_get_contents($this->proxyPidfile()), "{$why}: the child pidfile is kept");
		$this->assertSame("4242\n", (string) @file_get_contents($this->proxyMarker()), "{$why}: the ready marker is kept");
		$this->assertTrue(pfb_dns_proxy_ready(), "{$why}: the proxy still serves");
	}

	/** The proxy seeded by seedLiveProxyThatAStopClears() is gone: no supervisor, no child, no pidfile, no marker. */
	private function assertProxyWasStopped(string $why): void
	{
		$this->assertFalse(isvalidpid(PFB_DNS_PROXY_DAEMON_PIDFILE), "{$why}: the supervisor is gone");
		$this->assertFalse(pfb_dns_proxy_running(), "{$why}: the child is gone");
		$this->assertFileDoesNotExist($this->proxyPidfile(), "{$why}: the child pidfile is gone");
		$this->assertFileDoesNotExist($this->proxyMarker(), "{$why}: the ready marker is gone");
		$this->assertFalse(pfb_dns_proxy_ready(), "{$why}: the proxy no longer serves");
	}

	/**
	 * pfb_reload_unbound() with the waits it reaches loaded onto a virtual clock: the proxy's readiness wait (restart, confirm,
	 * await) and the DNSBL swap wait (wait applied, wait marker). Their polls are ticks, so no test waits on the host.
	 *
	 * @return array{0: PfbFlockClockFixture, 1: string} the clock, and the reload's name in the namespace it was loaded into
	 */
	private function clockedReload(): array
	{
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(
			['pfb_reload_unbound', 'pfb_unbound_py_wait_applied', 'pfb_unbound_py_wait_marker', 'pfb_dns_proxy_restart', 'pfb_dns_proxy_confirm_ready', 'pfb_dns_proxy_await_ready'],
			['PFB_DNS_PROXY_START_WAIT' => 1]
		);

		return [$clock, $namespace . '\\pfb_reload_unbound'];
	}
}
