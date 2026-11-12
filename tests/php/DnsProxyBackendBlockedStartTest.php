<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyRcSandboxTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- a gateway stopped because a stranger holds Unbound's loopback port and no pair could take its place must not be started
 * again by any path that does not look at that: the boot hook (DnsProxyBootTest pins its side), a Resolver restart from the GUI, or the
 * Start button of Status > Services. The generated rc script's start therefore refuses while the marker pfb_dns_proxy_backend_move() left
 * stands: it logs one line and exits 0, launches nothing and takes no lock. The tick and the update pass that find the port free clear the
 * marker before they start the gateway, so what is refused here is only a start nobody checked. The real generated script runs under dash
 * over the sandbox's command doubles (DnsProxyRcSandboxTrait).
 */
#[CoversFunction('pfb_dns_proxy_service')]
final class DnsProxyBackendBlockedStartTest extends TestCase
{
	use DnsProxyRcSandboxTrait;

	protected function setUp(): void
	{
		$this->sandboxUp();
	}

	protected function tearDown(): void
	{
		$this->sandboxDown();
	}

	private function marker(): string
	{
		return "{$this->dir}/run/pfb_dns_proxy_backend_blocked";
	}

	private function standMarker(): void
	{
		file_put_contents($this->marker(), "holder\n5353\nnc (pid 6161) on 127.0.0.1:5353\n");
	}

	/** @return list<string> */
	private function recorded(string $file): array
	{
		return array_values(array_filter(explode("\n", (string) file_get_contents("{$this->dir}/state/{$file}"))));
	}

	public function testTheGeneratedStartRefusesFirstOfAllWhileTheMarkerStands(): void
	{
		// Given the generated script
		$this->moveResolver();
		pfb_dns_proxy_service();
		$start = (string) $GLOBALS['pfb_test_rcfiles']['pfb_dns_proxy.sh']['start'];

		// Then its start checks the marker before it takes the start lock or launches anything
		$check = "[ -e '/var/run/pfb_dns_proxy_backend_blocked' ]";
		$this->assertStringContainsString($check, $start);
		$this->assertLessThan(strpos($start, 'lockf'), strpos($start, $check), 'before the lock');
		$this->assertLessThan(strpos($start, '/usr/sbin/daemon'), strpos($start, $check), 'before the launch');
	}

	public function testAStartWhileTheMarkerStandsLaunchesNothingLogsOneLineAndSucceeds(): void
	{
		// Given a stranger's marker and a stopped gateway
		$this->moveResolver();
		pfb_dns_proxy_service();
		$this->arrange();
		$this->standMarker();

		// When something starts the proxy (the boot hook, a Resolver restart, Status > Services)
		[$status, $output] = $this->rc('start');

		// Then nothing launches and no lock is taken; one warning says why; the status is 0 so no caller reads it as a failed start
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events(), 'nothing was launched');
		$this->assertSame([], $this->recorded('lockf.calls'), 'no start lock was taken');
		$logged = $this->recorded('logger');
		$this->assertCount(1, $logged, 'one line');
		$this->assertStringContainsString('not started', $logged[0]);
		$this->assertStringContainsString("holds Unbound's loopback backend port", $logged[0]);
		$this->assertFileExists($this->marker(), 'the start never clears it: only the pass that checked for the stranger does');
	}

	public function testARestartIsRefusedAtItsStartToo(): void
	{
		$this->moveResolver();
		pfb_dns_proxy_service();
		$this->arrange();
		$this->standMarker();

		[$status, $output] = $this->rc('restart');

		$this->assertSame(0, $status, "rc restart failed: {$output}");
		$this->assertSame([], $this->events(), 'the stop found nothing and the start launched nothing');
	}

	public function testAStartWithNoMarkerLaunchesAsBefore(): void
	{
		$this->moveResolver();
		pfb_dns_proxy_service();
		$this->arrange();

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
	}

	/** The sockets sockstat lists, as the double answers it: the header and the rows. */
	private function sockets(string ...$rows): void
	{
		file_put_contents("{$this->dir}/state/sockstat.out", "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n" . implode('', array_map(static fn (string $row): string => "{$row}\n", $rows)));
	}

	/** A box whose script was generated with the gateway's upstream on $port, and a stopped gateway. */
	private function armed(string $port = '5353'): void
	{
		$this->moveResolver();
		if ($port !== '5353') {
			$plain = (int) $port + 1;
			config_set_path('unbound/custom_options', base64_encode("server:\n# pfBlockerNG DNS proxy\nport: {$plain}\ninterface: 127.0.0.1@{$port}\n"
				. "interface: ::1@{$port}\nproxy-protocol-port: {$port}\n# end pfBlockerNG DNS proxy"));
		}
		pfb_dns_proxy_service();
		$this->arrange();
	}

	public function testAStrangerOnTheUpstreamPortRefusesTheStartWritesTheMarkerAndLogsOneLine(): void
	{
		// Given a process that is not Unbound listening on the port the script forwards to, and nothing on the marker yet (a boot with Unbound
		// not up, a restart from the apply, a restore's start: no PHP pass looked)
		$this->armed();
		$this->sockets('root nc 6161 3 tcp4 127.0.0.1:5353 *:*', 'root nc 6161 4 udp4 127.0.0.1:5353 *:*');

		// When the proxy is started
		[$status, $output] = $this->rc('start');

		// Then nothing launches and no lock is taken, the marker names the stranger in the format PHP reads, and one line says why; the status is 0
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events());
		$this->assertSame([], $this->recorded('lockf.calls'));
		$this->assertSame(['-46lw -p 5353'], array_values(array_unique($this->recorded('sockstat.calls'))), 'a scan of the script\'s own upstream port');
		$this->assertSame("holder\n5353\nnc (pid 6161) on 127.0.0.1:5353\n", (string) file_get_contents($this->marker()));
		$logged = $this->recorded('logger');
		$this->assertCount(1, $logged);
		$this->assertStringContainsString('nc (pid 6161) on 127.0.0.1:5353', $logged[0]);
		$this->assertStringContainsString('not started', $logged[0]);
	}

	/** @return array<string,array{string,bool}> a listening row, and whether the start is refused for it */
	public static function listeningRows(): array
	{
		return [
			'a TCP listener on loopback' => ['root nc 6161 3 tcp4 127.0.0.1:5353 *:*', TRUE],
			'a UDP socket on loopback' => ['root dnsmasq 777 3 udp4 127.0.0.1:5353 *:*', TRUE],
			'a wildcard listener' => ['root nc 6161 3 tcp4 *:5353 *:*', TRUE],
			'an IPv6 wildcard listener' => ['root nc 6161 3 tcp6 *:5353 *:*', TRUE],
			'an IPv6 loopback listener' => ['root nc 6161 3 tcp6 ::1:5353 *:*', TRUE],
			'an IPv6 loopback listener in brackets' => ['root nc 6161 3 udp6 [::1]:5353 *:*', TRUE],
			'Unbound itself' => ['unbound unbound 5151 3 tcp4 127.0.0.1:5353 *:*', FALSE],
			'a LAN address does not meet the loopback port' => ['root nc 6161 3 tcp4 192.0.2.1:5353 *:*', FALSE],
			'another port' => ['root nc 6161 3 tcp4 127.0.0.1:5354 *:*', FALSE],
			'a row that is not a socket' => ['root nc notapid 3 tcp4 127.0.0.1:5353 *:*', FALSE],
			'another protocol' => ['root nc 6161 3 sctp4 127.0.0.1:5353 *:*', FALSE],
		];
	}

	#[DataProvider('listeningRows')]
	public function testOnlyAListenerThatIsNotUnboundOnLoopbackOrTheWildcardOfThePortRefusesTheStart(string $row, bool $refused): void
	{
		$this->armed();
		$this->sockets($row);

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame($refused ? [] : ['launch'], $this->events());
		$this->assertSame($refused, file_exists($this->marker()));
	}

	public function testASockstatThatFailsOrListsNothingRefusesNothing(): void
	{
		// Given a scan that fails, with rows that would name a stranger had it worked: a failed scan is no holder, as in PHP
		$this->armed();
		$this->sockets('root nc 6161 3 tcp4 127.0.0.1:5353 *:*');
		file_put_contents("{$this->dir}/state/sockstat.status", "1\n");

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertFileDoesNotExist($this->marker());
	}

	public function testTheScanIsOfThePortThisScriptWasGeneratedWith(): void
	{
		// Given a clause that names the pair 5400/5401 and a stranger on 5353, which is nobody's port now
		$this->armed('5400');
		$this->sockets('root nc 6161 3 tcp4 127.0.0.1:5353 *:*');
		[$status, $output] = $this->rc('start');
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['-46lw -p 5400'], array_values(array_unique($this->recorded('sockstat.calls'))), 'only that port is scanned (the locked inner run scans again)');
		$this->assertSame(['launch'], $this->events(), 'a stranger on 5353 is no business of a script that forwards to 5400');
	}

	public function testARestartIsRefusedForAStrangerToo(): void
	{
		$this->armed();
		$this->sockets('root nc 6161 3 tcp4 127.0.0.1:5353 *:*');

		[$status, $output] = $this->rc('restart');

		$this->assertSame(0, $status, "rc restart failed: {$output}");
		$this->assertSame([], $this->events());
		$this->assertFileExists($this->marker());
	}
}
