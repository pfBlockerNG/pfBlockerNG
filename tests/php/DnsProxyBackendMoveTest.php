<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyMovedResolverFixtureTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- Unbound's loopback backend pair (PROXYv2 on P, plain on P+1, from 5353/5354) moves instead of failing: when another process
 * holds a port of the pair, or the Resolver's Listen Port is P or P+1, pfBlockerNG picks a free pair, stores it in the clause, writes
 * it into Unbound's clause and the gateway's --upstream, restarts Unbound and the gateway, and waits for the live Unbound to own the new P. A notice
 * names the holder (or the Listen Port). Nothing here restores the Resolver, and the gateway is never started or left forwarding to a port the live
 * Unbound does not own when the pass can see that.
 *
 * The box: the real takeover pass moved the Resolver; the sockets are the sockstat double's rows, which the configure hook rewrites the way a restarted
 * Unbound would (it binds the pair its regenerated clause names); the gateway is the stand-in whose upstream follows the rc script a restart runs.
 */
#[CoversFunction('pfb_dns_proxy_backend_move')]
#[CoversFunction('pfb_dns_proxy_backend_holder')]
#[CoversFunction('pfb_dns_proxy_backend_problem')]
#[CoversFunction('pfb_dns_proxy_confirm_ready')]
#[CoversFunction('pfb_dns_proxy_confirm_started')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_resolver')]
#[CoversFunction('pfb_dns_proxy_service')]
#[CoversFunction('pfb_unbound_python')]
final class DnsProxyBackendMoveTest extends TestCase
{
	use DnsProxyMovedResolverFixtureTrait;

	/** @var list<string> what asked for Unbound or the gateway to (re)start, in order: `configure` is services_unbound_configure() */
	private array $events = [];
	/** @var list<?string> the --upstream the rc script carried at each start or restart of the gateway */
	private array $upstreamAtStart = [];
	/** @var list<string> sockstat rows of processes that are not Unbound */
	private array $foreign = [];
	/** @var list<int> the ports the live Unbound listens on (TCP and UDP, 127.0.0.1) */
	private array $unboundPorts = [];
	private int $unboundPid = 5151;
	/** Whether a start or restart makes the gateway serve what its rc script says; FALSE leaves it as it was, so it never follows a move. */
	private bool $gatewayFollows = TRUE;

	// -----------------------------------------------------------------------
	// The box
	// -----------------------------------------------------------------------

	/** The moved Resolver, Unbound on the default pair, and the doubles that carry a move through: Unbound binds its clause's pair, the gateway its rc script's upstream. */
	private function box(bool $dnsbl = TRUE, array $resolver = [], bool $takeover = TRUE): void
	{
		$this->activate($dnsbl, $resolver, $takeover);
		if (!$dnsbl) {
			$this->useMountState(FALSE);
		}
		$this->behaviour = 'serves';
		$fixture = $GLOBALS['pfb_test_service_hook'];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use ($fixture): void {
			if ($service !== 'pfb_dns_proxy' || !in_array($fn, ['start_service', 'restart_service'], TRUE)) {
				$fixture($fn, $service);
				return;
			}
			$this->events[] = $fn;
			$this->proxyCalls[] = $fn;
			$this->upstreamAtStart[] = $this->rcUpstream();
			if ($this->gatewayFollows) {
				// A gateway that comes up serves what its rc script names: that upstream, and those listeners
				$this->proxyServes();
				$this->standInsStop();
				$this->seedRunningGateway('4242', $this->rcUpstream());
			}
		};
		$GLOBALS['pfb_test_unbound_configure_hook'] = function (): void {
			$this->events[] = 'configure';
			$port = $this->clausePort();
			if ($port !== NULL) {
				$this->unboundPid++;
				$this->unboundPorts = [$port, $port + 1];
			}
			$this->publishSockets();
		};
		$this->unboundPorts = [5353, 5354];
		$this->publishSockets();
	}

	/** The Unbound pid and the sockets as the doubles show them: the foreign rows, and the live Unbound's own on its ports. */
	private function publishSockets(): void
	{
		$rows = $this->foreign;
		foreach ($this->unboundPorts as $port) {
			foreach (['tcp4', 'udp4'] as $protocol) {
				$rows[] = "unbound unbound {$this->unboundPid} 3 {$protocol} 127.0.0.1:{$port} *:*";
			}
		}
		file_put_contents($GLOBALS['pfb_test_sockstat_output'],
			"USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n" . implode('', array_map(static fn (string $row): string => "{$row}\n", $rows)));
		file_put_contents($this->unboundPidfile(), "{$this->unboundPid}\n");
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = TRUE;
	}

	/** The pair the Resolver's clause asks Unbound to bind (its `proxy-protocol-port:` line), NULL when the clause is gone. */
	private function clausePort(): ?int
	{
		return preg_match('/^proxy-protocol-port: (\d+)$/m', $this->customText(), $match) === 1 ? (int) $match[1] : NULL;
	}

	/** The --upstream of the rc script the gateway would start with. */
	private function rcUpstream(): ?string
	{
		return preg_match("/ --upstream '([^']+)'/", (string) @file_get_contents(PFB_DNS_PROXY_RCFILE), $match) === 1 ? $match[1] : NULL;
	}

	private static function row(string $command, int $pid, string $protocol, string $local): string
	{
		return "root {$command} {$pid} 3 {$protocol} {$local} *:*";
	}

	/** Another process holds sockets; Unbound, which could not bind where they are, holds none (its process lives on). */
	private function foreignHolds(string ...$rows): void
	{
		$this->foreign = $rows;
		$this->unboundPorts = [];
		$this->publishSockets();
	}

	/** The gateway runs, forwards to the default pair and holds the certificate it serves with. */
	private function gatewayRuns(): void
	{
		$this->proxyServes();
		$this->seedRunningGateway();
		$this->assertNull(pfb_dns_proxy_certificate_export(), 'before: the certificate the gateway holds is exported');
		file_put_contents(pfb_dns_proxy_certificate_pushed_path(), hash('sha256', (string) file_get_contents($GLOBALS['pfb']['dns_proxy_cert'])));
	}

	/** @return list<array<string,mixed>> the notices filed under $id */
	private function noticesOf(string $id): array
	{
		return array_values(array_filter($this->notices(), static fn (array $notice): bool => $notice['id'] === $id));
	}

	/** Unbound's backend lives on $port/$port+1 now: stored, in the clause, in the rc script, and the live Unbound owns it. */
	private function assertBackendOn(int $port, string $why): void
	{
		$this->assertSame((string) $port, pfb_dns_proxy_backend_port(), "{$why}: the clause is where the pair is stored, and read back from");
		$lines = $this->customLines();
		foreach (['port: ' . ($port + 1), "interface: 127.0.0.1@{$port}", "interface: ::1@{$port}", "proxy-protocol-port: {$port}"] as $line) {
			$this->assertContains($line, $lines, "{$why}: the clause carries '{$line}'");
		}
		$this->assertSame("127.0.0.1:{$port}", $this->rcUpstream(), "{$why}: the gateway's --upstream names it");
	}

	/** Nothing gave the Resolver back: the snapshot is byte for byte what the takeover stored and the Resolver stays moved onto loopback. */
	private function assertStillMoved(string $snapshot, string $why, bool $proxyMayBeStopped = FALSE): void
	{
		$this->assertSame('on', $this->toggleStored(), "{$why}: pfB-DNS stays on");
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), "{$why}: the snapshot is kept byte for byte");
		$this->assertNotNull(pfb_dns_proxy_saved(), "{$why}: the Resolver is still moved");
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), "{$why}: and on loopback");
		if (!$proxyMayBeStopped) {
			$this->assertSame([], array_values(array_intersect($this->proxyCalls, ['stop_service', 'rc stop'])), "{$why}: the proxy was never stopped");
		}
		$this->assertNotContains('rc stop', $this->proxyCalls, "{$why}: the rc script's own stop is the Resolver restore's, which never ran");
		$texts = implode("\n", array_column($this->notices(), 'notice'));
		$this->assertStringNotContainsStringIgnoringCase('restored', $texts, "{$why}: no notice says the Resolver was given back");
	}

	/** The next apply, tick or boot check: its own process, so it may try one move of its own. */
	private function newPass(): void
	{
		unset($GLOBALS['pfb']['dns_proxy_backend_move']);
	}

	private const NO_PAIR_STATUS = 'Not serving: no free loopback port pair for the Resolver backend';

	/** @return list<string> a stranger on Unbound's port, and a socket on every port the search could pick from: nothing is left to move to */
	private static function strangerAndEveryPairTaken(): array
	{
		return [self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'), self::row('nc', 6161, 'udp4', '127.0.0.1:5353'),
			...array_map(static fn (int $port): string => self::row('nc', 6162, 'udp4', "127.0.0.1:{$port}"), range(5355, 5419))];
	}

	/** The stranger still holds 5353, but the pairs above are free again. */
	private function everyPairFreeButTheStrangerStays(): void
	{
		$this->foreignHolds(...array_slice(self::strangerAndEveryPairTaken(), 0, 2));
	}

	/** The operator-visible facts of a cannot-serve pass: stopped, nothing started or moved, the Resolver kept, the holder named, the status line. */
	private function assertCannotServe(string $snapshot, string $why): void
	{
		$this->assertFalse(pfb_dns_proxy_running(), "{$why}: the gateway is not running");
		$this->assertSame([], $this->events, "{$why}: nothing was started, restarted or regenerated");
		$this->assertSame('5353', pfb_dns_proxy_backend_port(), "{$why}: the pair was not moved");
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$why}: config.xml was not written");
		$this->assertStillMoved($snapshot, $why, TRUE);
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices, "{$why}: one notice");
		$this->assertSame('/services_unbound.php', $notices[0]['url']);
		$this->assertStringContainsString('nc (pid 6161) on 127.0.0.1:5353', $notices[0]['notice'], "{$why}: it names the holder, its pid and endpoint");
		$this->assertStringContainsString('DNS is not served on port 53 until a loopback port pair is free or pfB-DNS is turned off', $notices[0]['notice']);
		pfb_global();
		$this->assertSame(self::NO_PAIR_STATUS, pfb_dns_status()['service'], "{$why}: the Service line");
	}

	// -----------------------------------------------------------------------
	// (a) the update pass: a holder on the pair moves Unbound first
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> the sockets a stranger holds, and how the notice names them */
	public static function holdersOfThePair(): array
	{
		return [
			'a TCP listener on P' => [self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'), 'nc (pid 6161) on 127.0.0.1:5353'],
			'a UDP socket on P' => [self::row('dnsmasq', 777, 'udp4', '127.0.0.1:5353'), 'dnsmasq (pid 777) on 127.0.0.1:5353'],
			'a listener on P+1' => [self::row('nc', 6161, 'tcp4', '127.0.0.1:5354'), 'nc (pid 6161) on 127.0.0.1:5354'],
			'a wildcard listener' => [self::row('nc', 6161, 'tcp4', '*:5353'), 'nc (pid 6161) on *:5353'],
			'an IPv6 loopback listener' => [self::row('nc', 6161, 'tcp6', '[::1]:5353'), 'nc (pid 6161) on [::1]:5353'],
		];
	}

	#[DataProvider('holdersOfThePair')]
	public function testAHolderOfThePairMovesUnboundToAFreePairAndTheRunningGatewayFollows(string $socket, string $named): void
	{
		// Given a serving gateway on the default pair, and another process that holds a port of it, so Unbound owns nothing there
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds($socket);
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'before: Unbound does not serve the gateway');
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the update pass checks the proxy
		$this->assertTrue(pfb_dns_proxy_ensure_running(), 'the proxy serves in the end');

		// Then Unbound's backend is on the lowest free pair above, in every place it is written, restarted once and followed by the gateway once
		$this->assertBackendOn(5355, 'after the move');
		$this->assertSame(['configure', 'restart_service'], $this->events, 'Unbound first, then the gateway');
		$this->assertCount(1, $GLOBALS['pfb_test_unbound_configure_calls'], 'Unbound was regenerated once');
		$this->assertSame(['127.0.0.1:5355'], $this->upstreamAtStart, 'the gateway restarted with the new --upstream');
		$this->assertSame('ready', pfb_dns_proxy_upstream_state(), 'the live Unbound owns TCP and UDP on the new P');
		$this->assertTrue(pfb_dns_proxy_serving_ready());
		$this->assertStillMoved($snapshot, 'after the move');

		// ... one notice names the holder and the move, and nothing else is filed
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices);
		$this->assertSame('/services_unbound.php', $notices[0]['url']);
		$this->assertStringContainsString($named, $notices[0]['notice']);
		$this->assertStringContainsString("so Unbound's backend moved from ports 5353/5354 to 5355/5356", $notices[0]['notice']);
		$this->assertStringNotContainsString('not forwarding', $notices[0]['notice'], 'the gateway followed');
		$this->assertSame(['pfBlockerNG DNS Proxy'], array_values(array_unique(array_column($this->notices(), 'id'))), 'no startup problem is left');
	}

	public function testALaterPassKeepsTheMovedPairAndMovesNothingAgain(): void
	{
		// Given a move that happened
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'));
		pfb_dns_proxy_ensure_running();
		$this->assertBackendOn(5355, 'before');
		$writes = count($GLOBALS['pfb_test_write_config_calls']);
		$events = $this->events;

		// When later passes run: the update pass, the Resolver pass and the cron tick, with the stranger still on the old pair
		$this->assertTrue(pfb_dns_proxy_ensure_running());
		pfb_unbound_python('enabled', TRUE);
		$this->tick();

		// Then the pair stays, config.xml is not written, and neither Unbound nor the gateway is restarted
		$this->assertBackendOn(5355, 'after later passes');
		$this->assertCount($writes, $GLOBALS['pfb_test_write_config_calls'], 'config.xml was not written again');
		$this->assertSame($events, $this->events, 'nothing was restarted again');
		$this->assertCount(1, $this->noticesOf('pfBlockerNG DNS Proxy'), 'and the notice is not filed again');
	}

	public function testAHolderBeforeTheGatewayStartsMovesUnboundFirstAndTheGatewayStartsWithTheNewUpstream(): void
	{
		// Given no gateway running yet, and a stranger on Unbound's port
		$this->box();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'));
		$this->assertFalse(pfb_dns_proxy_running(), 'before: no gateway');

		// When the update pass starts the proxy
		$this->assertTrue(pfb_dns_proxy_ensure_running());

		// Then it starts once, after Unbound moved, with the new --upstream: never onto a port the live Unbound does not own
		$this->assertSame(['configure', 'start_service'], $this->events);
		$this->assertSame(['127.0.0.1:5355'], $this->upstreamAtStart);
		$this->assertBackendOn(5355, 'after the start');
		$this->assertTrue(pfb_dns_proxy_serving_ready());
	}

	public function testAMoveCarriesTheSavedMarkerAndEveryOtherKeyOfTheMovedResolverThrough(): void
	{
		// Given a moved Resolver with the admin's own Custom Options, and a stranger on the pair
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'));
		$before = config_get_path('unbound');
		$snapshot = (string) config_get_path(self::SAVED, '');

		pfb_dns_proxy_ensure_running();

		// Then only the clause inside the pair's markers changed: the admin's lines, the keys, and the snapshot are as they were
		$after = config_get_path('unbound');
		$this->assertSame(array_diff_key($before, ['custom_options' => 1]), array_diff_key($after, ['custom_options' => 1]), 'every other Resolver key');
		$admin = static fn (string $options): string => (string) preg_replace('/^server:\n# pfBlockerNG DNS proxy\n.*?^# end pfBlockerNG DNS proxy$/ms', '', (string) base64_decode($options, TRUE));
		$this->assertSame($admin($before['custom_options']), $admin($after['custom_options']), 'the admin\'s Custom Options outside our block');
		$this->assertNotSame($before['custom_options'], $after['custom_options'], 'and the block moved');
		$this->assertSame($snapshot, (string) config_get_path(self::SAVED, ''), 'the snapshot');
	}

	/** @return array<string,array{bool}> whether the gateway runs when the pass finds the stranger */
	public static function gatewayStates(): array
	{
		return ['a running gateway' => [TRUE], 'a stopped gateway' => [FALSE]];
	}

	private const HOLDER_STATUS = 'Not serving: nc (pid 6161) on 127.0.0.1:5353 holds the Resolver backend port 5353';

	/**
	 * The facts of a gateway stopped for a stranger on its upstream that no move could clear: nothing started, moved or restored, the holder named, and the
	 * marker one of kind `holder` (not `nopair`: a pair was never found missing). $writes: the config.xml writes the pass attempted (a move whose write was refused).
	 *
	 * @param list<string> $writes
	 */
	private function assertStoppedForAHolder(string $snapshot, string $whyNoMove, string $why, string $status = self::HOLDER_STATUS, array $writes = []): void
	{
		$this->assertFalse(pfb_dns_proxy_running(), "{$why}: the gateway is not running");
		$this->assertSame([], $this->events, "{$why}: nothing was started, restarted or regenerated");
		$this->assertSame('5353', pfb_dns_proxy_backend_port(), "{$why}: the pair was not moved");
		$this->assertSame($writes, $GLOBALS['pfb_test_write_config_calls'], "{$why}: config.xml was written only as the pass attempted");
		$this->assertSame("holder\n5353\nnc (pid 6161) on 127.0.0.1:5353\n", (string) @file_get_contents($GLOBALS['pfb']['dns_proxy_backend_blocked']), "{$why}: the marker names the holder");
		$this->assertStillMoved($snapshot, $why, TRUE);
		$texts = array_column($this->noticesOf('pfBlockerNG DNS Proxy'), 'notice');
		$this->assertNotEmpty($texts, "{$why}: a notice is filed");
		$this->assertStringContainsString('nc (pid 6161) on 127.0.0.1:5353', end($texts), "{$why}: it names the holder");
		$this->assertStringContainsString($whyNoMove, end($texts), "{$why}: and why nothing could be moved");
		$this->assertStringContainsString('DNS is not served on port 53 until', end($texts));
		pfb_global();
		$this->assertSame($status, pfb_dns_status()['service'], "{$why}: the Service line");
	}

	#[DataProvider('gatewayStates')]
	public function testAHolderWhileTheResolverIsDisabledStopsTheGatewayAndNeverForwardsToIt(bool $running): void
	{
		// Given a stranger on Unbound's port and the Resolver disabled by the admin: nothing would take a new pair
		$this->box();
		if ($running) {
			$this->gatewayRuns();
		}
		$this->foreignHolds(...array_slice(self::strangerAndEveryPairTaken(), 0, 2));
		$this->disableTheResolver();
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the update pass runs
		$this->assertFalse(pfb_dns_proxy_ensure_running());

		// Then the gateway is stopped (or stays stopped), the Resolver is kept, and the status names the holder
		$this->assertSame($running ? ['stop_service'] : [], $this->proxyCalls);
		$this->assertStoppedForAHolder($snapshot, 'the DNS Resolver is disabled', 'a disabled Resolver');
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_backend_blocked']);

		// ... and once the admin enables the Resolver again, the next tick moves Unbound and starts the gateway
		config_set_path('unbound/enable', '');
		$this->newPass();
		$this->tick();
		$this->assertSame(['configure', 'start_service'], $this->events);
		$this->assertBackendOn(5355, 'after the Resolver is enabled again');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked']);
		$this->assertTrue(pfb_dns_proxy_serving_ready());
	}

	/** Runs $pass with sockstat failing for a port range (the free-pair search's scan) and answering the pair's own ports (the holder's scan) as ever. */
	private function withTheFreePairScanFailing(callable $pass): void
	{
		$original = (string) file_get_contents(PFB_DNS_PROXY_SOCKSTAT);
		$failing = str_replace("\ncat ", "\ncase \"\$3\" in *-*) exit 1 ;; esac\ncat ", $original);
		$this->assertNotSame($original, $failing, 'test bootstrap: the sockstat double has its cat line');
		file_put_contents(PFB_DNS_PROXY_SOCKSTAT, $failing);
		try {
			$pass();
		} finally {
			file_put_contents(PFB_DNS_PROXY_SOCKSTAT, $original);
		}
	}

	#[DataProvider('gatewayStates')]
	public function testAProvenStrangerWhoseFreePairScanFailsStopsTheGatewayAndNeverRestoresTheResolver(bool $running): void
	{
		// Given a stranger on Unbound's port, and a sockstat that lists that pair but cannot list the ports above it
		$this->box();
		if ($running) {
			$this->gatewayRuns();
		}
		$this->foreignHolds(...array_slice(self::strangerAndEveryPairTaken(), 0, 2));
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the update pass runs
		$this->withTheFreePairScanFailing(function () use (&$served): void {
			$this->assertSame('nc (pid 6161) on 127.0.0.1:5353', pfb_dns_proxy_backend_holder($proven), 'before: the stranger is proven on the pair');
			$this->assertTrue($proven);
			$this->assertNull(pfb_dns_proxy_backend_pick($seen), 'before: no pair is known free');
			$this->assertFalse($seen, 'before: because the sockets above the pair could not be listed');
			$served = pfb_dns_proxy_ensure_running();
		});

		// Then the gateway is stopped (or stays stopped), the Resolver is kept, and the status names the holder, not a missing pair
		$this->assertFalse($served, 'nothing serves');
		$this->assertSame($running ? ['stop_service'] : [], $this->proxyCalls);
		$this->assertStoppedForAHolder($snapshot, 'the sockets could not be listed to find a free pair', 'a failed free-pair scan');
	}

	#[DataProvider('refusedWrites')]
	public function testAProvenStrangerWithAFreePairButARefusedClauseWriteStopsTheGatewayAndNeverRestoresTheResolver(mixed $answer): void
	{
		// Given a serving gateway, a stranger on Unbound's port, a free pair above it, and a config.xml that does not take the write that would move the pair
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(...array_slice(self::strangerAndEveryPairTaken(), 0, 2));
		$this->configXmlOnDisk($answer);
		$snapshot = (string) config_get_path(self::SAVED, '');
		$this->assertSame('5355', pfb_dns_proxy_backend_pick(), 'before: a pair is free');

		// When the update pass runs
		$this->assertFalse(pfb_dns_proxy_ensure_running(), 'nothing serves');

		// Then the gateway is stopped, the pair stays where it was, the Resolver is kept, and the status names the holder
		$this->assertSame(['stop_service'], $this->proxyCalls, 'the gateway was stopped, once');
		$this->assertStoppedForAHolder($snapshot, 'the Resolver settings could not be written', 'a refused clause write', writes: ['pfBlockerNG: Moved the DNS Resolver onto loopback for the DNS proxy']);
	}

	public function testNoFreePairStopsARunningGatewayRaisesTheNoticeAndNeverRestoresTheResolver(): void
	{
		// Given a serving gateway, a stranger on Unbound's pair and a socket on every port the search could use
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(...self::strangerAndEveryPairTaken());
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the update pass runs
		$this->assertFalse(pfb_dns_proxy_ensure_running(), 'nothing serves');

		// Then the gateway is stopped, the Resolver is kept, and the notice and the Service line say why DNS is down
		$this->assertSame(['stop_service'], $this->proxyCalls, 'the gateway was stopped, once');
		$this->assertCannotServe($snapshot, 'a running gateway');
		$this->assertSame(1, substr_count((string) @file_get_contents($GLOBALS['pfb']['errlog']), 'so the DNS proxy is stopped'), 'one attempt in a pass: the notice is logged once');
		$this->assertSame(['pfBlockerNG DNS Proxy'], array_values(array_unique(array_column($this->notices(), 'id'))), 'no startup problem is filed on top');
	}

	public function testNoFreePairDoesNotStartAStoppedGateway(): void
	{
		// Given no gateway running, and the same stranger with no free pair
		$this->box();
		$this->foreignHolds(...self::strangerAndEveryPairTaken());
		$snapshot = (string) config_get_path(self::SAVED, '');
		$this->assertFalse(pfb_dns_proxy_running(), 'before: no gateway');

		// When the update pass runs
		$this->assertFalse(pfb_dns_proxy_ensure_running());

		// Then nothing starts (and nothing needs stopping)
		$this->assertSame([], $this->proxyCalls, 'the gateway was neither started nor stopped');
		$this->assertCannotServe($snapshot, 'a stopped gateway');
	}

	public function testATickWithAStrangerAndNoFreePairStopsTheGatewayWithoutAStartupProblemOnTop(): void
	{
		// Given a serving gateway whose upstream a stranger owns, and no free pair
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(...self::strangerAndEveryPairTaken());
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the cron tick checks the gateway
		$this->tick();

		// Then it stops, the Resolver is kept, and the only notice is the cannot-serve one
		$this->assertSame(['stop_service'], $this->proxyCalls);
		$this->assertCannotServe($snapshot, 'the tick');
		$this->assertSame(['pfBlockerNG DNS Proxy'], array_values(array_unique(array_column($this->notices(), 'id'))));
	}

	public function testTheNextTickRetriesTheSearchAndServesAgainAsSoonAsAPairIsFree(): void
	{
		// Given a gateway stopped because no pair was free
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(...self::strangerAndEveryPairTaken());
		$snapshot = (string) config_get_path(self::SAVED, '');
		pfb_dns_proxy_ensure_running();
		$this->assertCannotServe($snapshot, 'before');
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_backend_blocked'], 'before: the state stands for the next process');

		// When the next tick runs with the pairs still taken, nothing changes and nothing is filed twice
		$this->newPass();
		$this->tick();
		$this->assertCannotServe($snapshot, 'a tick that finds the pairs still taken');

		// ... and when a pair frees up, the next tick moves Unbound and starts the gateway
		$this->newPass();
		$this->everyPairFreeButTheStrangerStays();
		$this->tick();
		$this->assertSame(['configure', 'start_service'], $this->events, 'Unbound moved, then the gateway started (it was stopped)');
		$this->assertBackendOn(5355, 'after the retry');
		$this->assertSame(['127.0.0.1:5355'], $this->upstreamAtStart);
		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'DNS is served again');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked'], 'the state is cleared');
		$this->assertStillMoved($snapshot, 'after the retry', TRUE);
		pfb_global();
		$this->assertSame('Running', pfb_dns_status()['service']);
		$texts = array_column($this->noticesOf('pfBlockerNG DNS Proxy'), 'notice');
		$this->assertStringContainsString("so Unbound's backend moved from ports 5353/5354 to 5355/5356", end($texts));
	}

	public function testTheNextUpdateRetriesTheSearchToo(): void
	{
		// Given a gateway stopped because no pair was free, and then a pair that frees up
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(...self::strangerAndEveryPairTaken());
		pfb_dns_proxy_ensure_running();
		$this->newPass();
		$this->everyPairFreeButTheStrangerStays();

		// When the update pass runs
		$this->assertTrue(pfb_dns_proxy_ensure_running());

		// Then it moves Unbound and starts the gateway, and the stopped state is gone
		$this->assertSame(['configure', 'start_service'], $this->events);
		$this->assertBackendOn(5355, 'after the update');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked']);
	}

	public function testTheStoppedStateEndsWhenTheStrangerLeavesTheirPort(): void
	{
		// Given a gateway stopped because no pair was free, and then the stranger exits (Unbound binds the pair as it does at its restart)
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(...self::strangerAndEveryPairTaken());
		pfb_dns_proxy_ensure_running();
		$this->newPass();
		$this->foreign = [];
		$this->unboundPorts = [5353, 5354];
		$this->publishSockets();

		// When the update pass runs
		$this->assertTrue(pfb_dns_proxy_ensure_running());

		// Then the gateway starts on the pair it had, nothing moved, and the stopped state is gone
		$this->assertSame(['start_service'], $this->events);
		$this->assertSame('5353', pfb_dns_proxy_backend_port());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked']);
		pfb_global();
		$this->assertSame('Running', pfb_dns_status()['service']);
	}

	public function testAnUnboundNamedListenerWithNoValidPidfileIsNotAStrangerAndMovesNothing(): void
	{
		// Given a serving gateway and Unbound mid-restart: its pidfile names no live process, and sockets named unbound sit on its ports
		$this->box();
		$this->gatewayRuns();
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = FALSE;
		$this->assertNull(pfb_dns_proxy_backend_holder());

		// When the update pass and the tick run
		pfb_dns_proxy_ensure_running();
		$this->tick();

		// Then there is no move, no restart, no notice
		$this->assertSame('5353', pfb_dns_proxy_backend_port());
		$this->assertSame([], $this->events);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $this->noticesOf('pfBlockerNG DNS Proxy'), 'no move, so no move notice (the startup notice may say Unbound does not answer yet)');

		// ... while a stranger of another name is one even then
		$this->foreign = [self::row('nc', 6161, 'tcp4', '127.0.0.1:5353')];
		$this->publishSockets();
		$GLOBALS['pfb_test_valid_pids'][$this->unboundPidfile()] = FALSE;
		$this->assertSame('nc (pid 6161) on 127.0.0.1:5353', pfb_dns_proxy_backend_holder());
	}

	public function testAListenPortMoveCountsAsThePassesOneMoveAndAHolderAfterItStopsTheGateway(): void
	{
		// Given a moved Resolver whose proxy serves, and a Listen Port set to a port of Unbound's pair
		$this->box();
		$this->gatewayRuns();
		config_set_path('unbound/port', '5353');
		pfb_unbound_python('enabled', TRUE);
		$this->assertBackendOn(5355, 'after the Listen Port move');
		$events = $this->events;
		$configures = count($GLOBALS['pfb_test_unbound_configure_calls']);

		// When the same pass finds a stranger on the new pair, which asks for another move
		$this->assertFalse(pfb_dns_proxy_backend_move('nc (pid 6161) on 127.0.0.1:5355'));

		// Then no second move is made, Unbound is not restarted again, and the gateway is not left forwarding to the stranger
		$this->assertSame('5355', pfb_dns_proxy_backend_port());
		$this->assertSame($events, $this->events);
		$this->assertCount($configures, $GLOBALS['pfb_test_unbound_configure_calls']);
		$this->assertContains('stop_service', $this->proxyCalls);
		$this->assertFalse(pfb_dns_proxy_running());
		$text = (string) array_column($this->noticesOf('pfBlockerNG DNS Proxy'), 'notice')[1];
		$this->assertStringContainsString('a move was already made in this pass', $text);
		pfb_global();
		$this->assertSame('Not serving: nc (pid 6161) on 127.0.0.1:5355 holds the Resolver backend port 5355', pfb_dns_status()['service']);

		// ... and the next pass may make its own
		$this->newPass();
		config_set_path('unbound/port', '53');
		$this->assertTrue(pfb_dns_proxy_backend_move('nc (pid 6161) on 127.0.0.1:5355'));
		$this->assertSame('5357', pfb_dns_proxy_backend_port());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked']);
	}

	public function testAScanThatCannotBeMadeMovesNothing(): void
	{
		// Given a stranger on the pair but a sockstat that fails: no pair is known to be free
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'));
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");

		pfb_dns_proxy_ensure_running();

		$this->assertSame('5353', pfb_dns_proxy_backend_port());
		$this->assertSame([], $this->events);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $this->proxyCalls, 'a scan that fails is no holder: the gateway is not stopped');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked']);
	}

	/** The failed-scan lines the pfB log holds (the error log repeats them, so it is not read). */
	private function scanFailureLines(): int
	{
		return substr_count((string) @file_get_contents($GLOBALS['pfb']['log']), "The sockstat scan of Unbound's backend ports");
	}

	public function testAFailedBackendScanIsLoggedOncePerStreakAndAgainAfterAScanThatAnswers(): void
	{
		// Given a box whose sockstat fails: the first failed scan is logged, and a second one in a row adds no line
		$this->box();
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");
		$this->assertSame(0, $this->scanFailureLines(), 'before: nothing is logged');

		$this->assertNull(pfb_dns_proxy_backend_holder($scanned));
		$this->assertFalse($scanned, 'the scan failed: nothing was seen');
		$this->assertNull(pfb_dns_proxy_backend_holder());
		$this->assertSame(1, $this->scanFailureLines(), 'two failed scans in a row are one streak: one line');

		// When a scan answers, and then the next one fails
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "0\n");
		pfb_dns_proxy_backend_holder($scanned);
		$this->assertTrue($scanned, 'the scan answered');
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");
		pfb_dns_proxy_backend_holder();

		// Then the new streak is logged once more
		$this->assertSame(2, $this->scanFailureLines(), 'a failure after a scan that answered starts a new streak: one more line');
	}

	/** @return array<string,array{bool}> whether a free pair is left for the stranger on Unbound's port to move to */
	public static function holderAfterAFailedScan(): array
	{
		return ['a free pair is left' => [TRUE], 'no free pair is left' => [FALSE]];
	}

	#[DataProvider('holderAfterAFailedScan')]
	public function testAFailedScanWhileAHolderStandsStartsTheGatewayAndTheNextGoodScanMovesOrStopsIt(bool $freePair): void
	{
		// Given a stopped gateway, a stranger on Unbound's port, and a sockstat that fails: no scan sees the stranger, so nothing holds the start back
		$this->box();
		$stranger = $freePair ? [self::row('nc', 6161, 'tcp4', '127.0.0.1:5353')] : self::strangerAndEveryPairTaken();
		$this->foreignHolds(...$stranger);
		$snapshot = (string) config_get_path(self::SAVED, '');
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");

		// When the update pass runs
		pfb_dns_proxy_ensure_running();

		// Then the gateway starts (a scan that failed names nobody), and nothing is moved or stopped on the way
		$this->assertSame(['start_service'], $this->events, 'a failed scan is no holder: the gateway starts');
		$this->assertSame('5353', pfb_dns_proxy_backend_port(), 'nothing moved');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked']);

		// When a later tick's scan answers and sees the stranger
		$this->events = [];
		$this->proxyCalls = [];
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "0\n");
		$this->newPass();
		$this->tick();

		// Then the tick moves Unbound off it when a pair is free, and stops the gateway when none is; the Resolver is not given back either way
		if ($freePair) {
			$this->assertBackendOn(5355, 'the tick moved Unbound off the stranger');
			$this->assertSame(['configure', 'restart_service'], $this->events, 'Unbound first, then the gateway');
			$this->assertStillMoved($snapshot, 'the tick');
		} else {
			$this->assertFileExists($GLOBALS['pfb']['dns_proxy_backend_blocked'], 'with no free pair the marker is left');
			$this->assertContains('stop_service', $this->proxyCalls, 'the tick stopped the gateway');
			$this->assertStillMoved($snapshot, 'the tick', TRUE);
		}
	}

	public function testATickWhoseBackendScanFailsStopsNothingAndMovesNothing(): void
	{
		// Given a serving gateway, a stranger on Unbound's port, and a sockstat that fails: a failed scan is unknown, not foreign
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'));
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the cron tick checks the gateway
		$this->tick();

		// Then it neither stops the gateway nor moves Unbound's pair, and leaves no marker
		$this->assertSame([], $this->events, 'nothing was restarted, moved or regenerated');
		$this->assertSame([], $this->proxyCalls, 'a scan that fails is not a holder: the gateway is not stopped');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'config.xml was not written');
		$this->assertSame('5353', pfb_dns_proxy_backend_port(), 'the pair was not moved');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dns_proxy_backend_blocked']);
		$this->assertTrue(pfb_dns_proxy_running(), 'the gateway keeps running');
		$this->assertStillMoved($snapshot, 'the tick');
	}

	// -----------------------------------------------------------------------
	// A move the gateway does not follow
	// -----------------------------------------------------------------------

	public function testAGatewayThatDoesNotFollowIsSaidNotToForwardYetAndTheStatusNamesTheNewSituation(): void
	{
		// Given a stranger on the pair, and a gateway that does not come back on the new one
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'), self::row('nc', 6161, 'udp4', '127.0.0.1:5353'));
		$this->gatewayFollows = FALSE;
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the update pass runs
		pfb_dns_proxy_ensure_running();

		// Then Unbound moved, the pass restarted the gateway once and no move was made twice, though the stranger still holds the old pair
		$this->assertBackendOn(5355, 'after the move');
		$this->assertSame(['configure', 'restart_service'], $this->events);
		$this->assertCount(1, $GLOBALS['pfb_test_unbound_configure_calls']);
		$this->assertStillMoved($snapshot, 'after the move');
		$move = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $move);
		$this->assertStringContainsString("so Unbound's backend moved from ports 5353/5354 to 5355/5356, but the gateway is not forwarding to it yet; the next update retries", $move[0]['notice']);

		// ... and neither the Service line nor the startup notice says the stranger holds Unbound's port: Unbound is not there any more
		pfb_global();
		$service = pfb_dns_status()['service'];
		$this->assertSame("Resolver backend not answering: the gateway still forwards to port 5353, but Unbound's backend moved to port 5355; the next update restarts the gateway", $service);
		$startup = $this->noticesOf('pfBlockerNG DNS Proxy startup');
		$this->assertCount(1, $startup);
		$this->assertStringContainsString("the gateway still forwards to port 5353, but Unbound's backend moved to port 5355", $startup[0]['notice']);
		$this->assertStringNotContainsString("holds Unbound's port 5353", $startup[0]['notice'] . $service);

		// When the next update pass runs, with the gateway now able to follow
		$this->gatewayFollows = TRUE;
		$this->assertTrue(pfb_dns_proxy_ensure_running());

		// Then the gateway is restarted onto the new pair, and Unbound is not moved again
		$this->assertSame(['configure', 'restart_service', 'restart_service'], $this->events);
		$this->assertSame('127.0.0.1:5355', $this->upstreamAtStart[1]);
		$this->assertCount(1, $GLOBALS['pfb_test_unbound_configure_calls'], 'Unbound is not regenerated again');
		$this->assertBackendOn(5355, 'after the retry');
		$this->assertTrue(pfb_dns_proxy_serving_ready());
		$this->assertSame('Running', pfb_dns_status()['service']);
	}

	// -----------------------------------------------------------------------
	// (b) a gateway whose upstream a stranger owns: the no-start passes
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> the passes that find a ready gateway whose Unbound upstream a stranger owns */
	public static function passesThatFindAForeignUpstream(): array
	{
		return ['the cron tick' => ['tick'], 'the boot check' => ['boot check']];
	}

	#[DataProvider('passesThatFindAForeignUpstream')]
	public function testAForeignOwnerOfTheGatewaysUpstreamMovesUnboundOnAPassThatStartedNothing(string $entry): void
	{
		// Given a serving gateway, a live Unbound, and another process that owns Unbound's upstream endpoint
		$this->box();
		$this->gatewayRuns();
		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'before: the gateway and its Unbound upstream serve');
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'), self::row('nc', 6161, 'udp4', '127.0.0.1:5353'));
		$this->assertSame('foreign', pfb_dns_proxy_upstream_state(), 'before: the stranger owns it');
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the pass that started nothing checks the gateway
		if ($entry === 'tick') {
			$this->tick();
		} else {
			$this->dnsCheckArm('0');
		}

		// Then Unbound moved to a free pair, the gateway follows, and the Resolver is still moved
		$this->assertBackendOn(5355, $entry);
		$this->assertSame(['configure', 'restart_service'], $this->events);
		$this->assertTrue(pfb_dns_proxy_serving_ready());
		$this->assertStillMoved($snapshot, $entry);
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('nc (pid 6161) on 127.0.0.1:5353', $notices[0]['notice']);
		$this->assertStringContainsString("so Unbound's backend moved from ports 5353/5354 to 5355/5356", $notices[0]['notice']);
	}

	// -----------------------------------------------------------------------
	// (c) the Listen Port on a pair port
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function pairPorts(): array
	{
		return ['the PROXYv2 port' => ['5353'], 'the plain port' => ['5354']];
	}

	#[DataProvider('pairPorts')]
	public function testAListenPortOnAPairPortBeforeTheTakeoverMovesTheBackendInsteadOfRefusing(string $listen): void
	{
		// Given pfB-DNS on and a Resolver that has not been taken over, whose Listen Port is a port of our pair
		$this->box(TRUE, ['port' => $listen], FALSE);
		$this->assertNull(pfb_dns_proxy_saved(), 'before: not taken over');

		// When the apply's Resolver pass runs, and then the update pass starts the proxy
		pfb_unbound_python('enabled', TRUE);
		$this->assertTrue(pfb_dns_proxy_ensure_running());

		// Then the Resolver was taken over, with Unbound's pair moved off the Listen Port, which the proxy serves
		$this->assertNotNull(pfb_dns_proxy_saved(), 'taken over, not refused');
		$this->assertBackendOn(5355, 'after the takeover');
		$this->assertSame($listen, config_get_path('unbound/port'), 'the Listen Port is the admin\'s, as set');
		$this->assertSame($listen, $this->servedPort(), 'and the proxy serves it');
		$this->assertTrue(pfb_dns_proxy_serving_ready());
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices);
		$this->assertStringContainsString("the DNS Resolver's Listen Port is {$listen}", $notices[0]['notice']);
		$this->assertStringContainsString("so Unbound's backend moved from ports 5353/5354 to 5355/5356", $notices[0]['notice']);
		$this->assertStringNotContainsString('pfB-DNS is not active', $notices[0]['notice'], 'not a refusal');
	}

	#[DataProvider('pairPorts')]
	public function testAListenPortSetOnAPairPortAfterTheTakeoverMovesTheBackendAndTheGatewayFollows(string $listen): void
	{
		// Given a moved Resolver whose proxy serves on 53, and an admin who then sets the Listen Port to a port of our pair
		$this->box();
		$this->gatewayRuns();
		$snapshot = (string) config_get_path(self::SAVED, '');
		config_set_path('unbound/port', $listen);

		// When the apply runs: its Resolver pass, then its update pass
		pfb_unbound_python('enabled', TRUE);
		$this->assertTrue(pfb_dns_proxy_ensure_running());

		// Then Unbound moved, the regenerated rc script serves the Listen Port and forwards to the new pair, and the gateway was restarted onto it
		$this->assertBackendOn(5355, 'after the apply');
		$this->assertSame($listen, config_get_path('unbound/port'), 'the Listen Port stays as set');
		$this->assertSame($listen, $this->servedPort(), 'the proxy serves it');
		$this->assertSame(['configure', 'restart_service'], $this->events, 'Unbound once, then the gateway once');
		$this->assertSame(['127.0.0.1:5355'], $this->upstreamAtStart);
		$this->assertTrue(pfb_dns_proxy_serving_ready());
		$this->assertStillMoved($snapshot, 'after the apply');
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices);
		$this->assertStringContainsString("the DNS Resolver's Listen Port is {$listen}", $notices[0]['notice']);
		$this->assertStringContainsString("so Unbound's backend moved from ports 5353/5354 to 5355/5356", $notices[0]['notice']);
		$this->assertStringNotContainsString('set after pfB-DNS took the Resolver', $notices[0]['notice'], 'not the old "keeps serving, set another port" notice');

		// ... and a second apply changes nothing
		pfb_unbound_python('enabled', TRUE);
		$this->assertTrue(pfb_dns_proxy_ensure_running());
		$this->assertSame(['configure', 'restart_service'], $this->events);
		$this->assertCount(1, $this->noticesOf('pfBlockerNG DNS Proxy'));

		// ... and when the admin turns pfB-DNS off, the saved Resolver comes back with the Listen Port the admin set
		PfbConfig::writeSystem('dns/pfb_dns', PfbToggle::Off);
		pfb_unbound_python('enabled');
		$this->assertNull(pfb_dns_proxy_saved());
		$this->assertSame($listen, config_get_path('unbound/port'));
		$this->assertSame('lan,opt1', config_get_path('unbound/active_interface'));
	}

	public function testTheMovedPairAvoidsTheListenPortAndTheTransportPortsItWouldMeet(): void
	{
		// Given a Listen Port on P, a DoT port on the pair the picker would take first, and a DoH port on the next
		$this->box(TRUE, ['port' => '5353'], FALSE);
		PfbConfig::writeSystem(pfb_dns_config_key('pfb_dns_dot_port'), '5355');
		PfbConfig::writeSystem(pfb_dns_config_key('pfb_dns_doh_port'), '5357');

		pfb_unbound_python('enabled', TRUE);

		// Then the pair starts where neither port is in it
		$this->assertSame('5358', pfb_dns_proxy_backend_port(), '5355 is the DoT port, 5356/5357 meets the DoH port, 5357 is it');
	}

	/** @return array<string,array{bool}> whether the box was already taken over */
	public static function takenOverOrNot(): array
	{
		return ['before the takeover' => [FALSE], 'after the takeover' => [TRUE]];
	}

	#[DataProvider('takenOverOrNot')]
	public function testAListenPortOnAPairPortWithNoFreePairKeepsTheOldNotices(bool $takenOver): void
	{
		// Given a Listen Port of 5353 and a socket on every port the search could use
		$this->box(TRUE, $takenOver ? [] : ['port' => '5353'], $takenOver);
		$this->foreign = array_map(static fn (int $port): string => self::row('nc', 6162, 'udp4', "127.0.0.1:{$port}"), range(5355, 5419));
		$this->publishSockets();
		if ($takenOver) {
			$this->proxyServes();
			$this->seedRunningGateway();
			config_set_path('unbound/port', '5353');
		}

		// When the apply's Resolver pass runs
		pfb_unbound_python('enabled', TRUE);

		// Then nothing moved and the notice is the one the situation had before there was a move to make
		$this->assertSame('5353', pfb_dns_proxy_backend_port());
		$this->assertSame([], $this->events, 'nothing was restarted');
		$notices = $this->noticesOf('pfBlockerNG DNS Proxy');
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('Listen Port is 5353', $notices[0]['notice']);
		$this->assertStringContainsString($takenOver ? 'pfB-DNS keeps serving' : 'pfB-DNS is not active', $notices[0]['notice']);
		$this->assertSame($takenOver, pfb_dns_proxy_saved() !== NULL);
	}

	// -----------------------------------------------------------------------
	// The status and the notices name what is now, not what was
	// -----------------------------------------------------------------------

	public function testAStrangerOnTheNewPairIsNamedAsHoldingUnboundsPortThere(): void
	{
		// Given Unbound moved to 5355 and a gateway that follows, and then a stranger takes 5355 from Unbound
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'));
		pfb_dns_proxy_ensure_running();
		$this->assertBackendOn(5355, 'before');
		$this->foreignHolds(self::row('nc', 6163, 'tcp4', '127.0.0.1:5355'), self::row('nc', 6163, 'udp4', '127.0.0.1:5355'));

		// Then the status names the holder of the port Unbound is on now
		pfb_global();
		$this->assertSame("Resolver backend not answering: nc (pid 6163) holds Unbound's port 5355", pfb_dns_status()['service']);
	}

	public function testATickMovesUnboundOffAWildcardHolderOfItsPort(): void
	{
		// Given a serving gateway and a stranger bound to the wildcard address on Unbound's port: no 127.0.0.1:5353 row names it
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '*:5353'));
		$snapshot = (string) config_get_path(self::SAVED, '');

		// When the cron tick checks the gateway
		$this->tick();

		// Then it moves Unbound off it, as the update pass does
		$this->assertBackendOn(5355, 'after the tick');
		$this->assertSame(['configure', 'restart_service'], $this->events);
		$this->assertTrue(pfb_dns_proxy_serving_ready());
		$this->assertStillMoved($snapshot, 'the tick');
		$texts = array_column($this->noticesOf('pfBlockerNG DNS Proxy'), 'notice');
		$this->assertStringContainsString('nc (pid 6161) on *:5353', $texts[0]);
	}

	public function testAClauseTheResolverSyncCopiedFromThePrimaryMakesTheNextTickFollowItWithoutRestoringAnything(): void
	{
		// Given a secondary whose gateway forwards to 5353, and the Resolver sync that copied the primary's clause (P = 5355) into Custom Options
		$this->box();
		$this->gatewayRuns();
		$snapshot = (string) config_get_path(self::SAVED, '');
		$synced = preg_replace(['/@5353\b/', '/proxy-protocol-port: 5353/', '/^port: 5354$/m'], ['@5355', 'proxy-protocol-port: 5355', 'port: 5356'], $this->customText());
		config_set_path('unbound/custom_options', base64_encode((string) $synced));
		$this->unboundPorts = [5355, 5356];
		$this->publishSockets();
		$this->assertSame('5355', pfb_dns_proxy_backend_port(), 'before: the clause names the primary\'s pair');
		$this->assertSame('127.0.0.1:5353', $this->rcUpstream(), 'before: the gateway\'s script still says 5353');

		// When one tick runs
		$this->tick();

		// Then the gateway was restarted onto 5355 with a script that says so; Unbound was not touched and nothing was restored
		$this->assertSame(['restart_service'], $this->events);
		$this->assertSame(['127.0.0.1:5355'], $this->upstreamAtStart);
		$this->assertSame('127.0.0.1:5355', $this->rcUpstream());
		$this->assertSame([], $GLOBALS['pfb_test_unbound_configure_calls'], 'Unbound was not regenerated');
		$this->assertTrue(pfb_dns_proxy_serving_ready());
		$this->assertStillMoved($snapshot, 'the tick', FALSE);
		$this->assertSame([], $this->noticesOf('pfBlockerNG DNS Proxy'));

		// ... and a second tick has nothing to do
		$this->tick();
		$this->assertSame(['restart_service'], $this->events);
	}

	public function testATickDoesNotRestartTheGatewayOntoAPairAStrangerHolds(): void
	{
		// Given the synced clause again, and a stranger on the primary's pair
		$this->box();
		$this->gatewayRuns();
		$synced = preg_replace(['/@5353\b/', '/proxy-protocol-port: 5353/', '/^port: 5354$/m'], ['@5355', 'proxy-protocol-port: 5355', 'port: 5356'], $this->customText());
		config_set_path('unbound/custom_options', base64_encode((string) $synced));
		$this->foreignHolds(self::row('nc', 6161, 'tcp4', '127.0.0.1:5355'));

		// When one tick runs
		$this->tick();

		// Then it is not followed onto the stranger: the holder is moved off (a free pair above 5355)
		$this->assertNotSame('127.0.0.1:5355', $this->rcUpstream());
		$this->assertSame('5357', pfb_dns_proxy_backend_port());
	}

	public function testAScanThatFailsWhileTheMarkerStandsKeepsItAndStartsNothing(): void
	{
		// Given a gateway stopped because no pair was free, and then a sockstat that fails: no scan proves the stranger gone
		$this->box();
		$this->gatewayRuns();
		$this->foreignHolds(...self::strangerAndEveryPairTaken());
		pfb_dns_proxy_ensure_running();
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_backend_blocked']);
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");
		$this->events = [];
		$this->proxyCalls = [];

		// When the update pass and then the tick run
		$this->newPass();
		$this->assertFalse(pfb_dns_proxy_ensure_running());
		$this->newPass();
		$this->tick();

		// Then the marker stands, nothing started, and the Service line still says why
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_backend_blocked']);
		$this->assertSame([], $this->proxyCalls, 'the gateway was not started onto a stranger nobody could see');
		$this->assertSame([], $this->events);
		$this->assertFalse(pfb_dns_proxy_running());
		pfb_global();
		$this->assertSame(self::NO_PAIR_STATUS, pfb_dns_status()['service']);
	}

	public function testAQuietSkipOfTheMoveNeverFallsThroughToAStartOntoAKnownHolder(): void
	{
		// Given a stopped gateway, a stranger on Unbound's port, and a move already made in this pass
		$this->box();
		$this->foreignHolds(...array_slice(self::strangerAndEveryPairTaken(), 0, 2));
		$GLOBALS['pfb']['dns_proxy_backend_move'] = 'tried';

		// When the update pass would start the gateway
		$this->assertFalse(pfb_dns_proxy_ensure_running());

		// Then it is not started
		$this->assertSame([], $this->proxyCalls);
		$this->assertSame([], $this->events);
		$this->assertFileExists($GLOBALS['pfb']['dns_proxy_backend_blocked']);
	}

	public function testTheMarkerTheRcScriptWritesIsTheOnePhpReads(): void
	{
		// Given the three lines the rc script's start writes for a stranger it found itself, on a Resolver that is moved
		$this->box();
		file_put_contents($GLOBALS['pfb']['dns_proxy_backend_blocked'], "holder\n5353\nnc (pid 6161) on 127.0.0.1:5353\n");

		// Then PHP reads it: the gateway cannot serve, and the Service line names the holder and the port
		$this->assertTrue(pfb_dns_proxy_cannot_serve());
		pfb_global();
		$this->assertSame(self::HOLDER_STATUS, pfb_dns_status()['service']);
	}
}
