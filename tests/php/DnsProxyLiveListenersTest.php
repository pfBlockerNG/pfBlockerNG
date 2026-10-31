<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';
require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3599 (which replaces the whole-pair restart of issue #3598) -- the running pfB-DNS gateway gains and loses listen addresses
 * without a restart: root PHP binds the socket and hands it over on the gateway's control socket, and the gateway's log is the
 * record of what is served (docs/specs/pfb-dns-live-listen-addresses.md, D1, D4, D5). The stand-in gateway is
 * support/ListenerControlServer.php, a real process on a real Unix socket that records every frame and its descriptors.
 *
 *   - an rc script that differs only in its listen addresses, with the proxy READY and its log holding a complete start, is
 *     reconciled live by the update pass: the gone addresses removed, the new ones added, nothing restarted; any other difference
 *     (a port, a TLS group on or off, DDR, a module flag), a proxy that is not READY and a log with no complete start restart the pair;
 *   - an address the box cannot assign yet (in the words of Linux and of FreeBSD) is left for a later pass with nothing sent, logged or
 *     restarted; one that fails to bind otherwise is logged and skipped, a restart pending or not; a change the gateway does not take
 *     (an older gateway's error, a hang-up, no socket) restarts the pair once and sends no further frame;
 *   - the reconcile acts on the record of the gateway that published the ready marker (its pid) only: while the log's latest complete
 *     start is an earlier gateway's it sends nothing, and an address-only change restarts the pair;
 *   - the cron tick adds an address the start refused and the box binds now, and removes one the command no longer names, live;
 *     with a restart pending it changes nothing live and restarts once for a missing listener that binds (the update pass keeps the
 *     marker); under an update pass it does nothing. A package operation's rows are DnsProxyKeepRunningPkgTest's.
 *   - the sync takes no gap in what it reads for a change: an rc script that names no plain listener (missing, empty, no command) or a
 *     log window that cut off the latest start's `starting pid` line changes nothing; a host the gateway prints differently (an
 *     IPv4-mapped one) is spelled as it prints it; one TLS kind's address changes live by itself; and the wait for the log ends
 *     as soon as the log shows the change, and confirms a remove too.
 *
 * Every row that binds uses a port above 1024 picked free at runtime and configured as the rc script's port, so that it runs as a
 * user that is not root too. Every row starts from the quiet box (nothing differs: nothing is sent or restarted).
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_listeners_sync')]
#[CoversFunction('pfb_dns_proxy_listener_bind')]
#[CoversFunction('pfb_dns_proxy_listener_add')]
#[CoversFunction('pfb_dns_proxy_listener_remove')]
#[CoversFunction('pfb_dns_proxy_listeners')]
#[CoversFunction('pfblockerng_tick')]
final class DnsProxyLiveListenersTest extends TestCase
{
	use KeepRunningScenario;
	use LiveListenerStandIn {
		frames as private everyFrame;
	}

	private const READY = 'ready upstream 127.0.0.1:5353 pid 4242';
	/** The ready line of the gateway before the one whose pid the ready marker names (4242). */
	private const PREVIOUS = 'ready upstream 127.0.0.1:5353 pid 4141';
	private const CANT = "bind: can't assign requested address";
	private const STARTUP = 'pfBlockerNG DNS Proxy startup';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	/** The hosts the rc script's command listens on in this fixture (lan is 192.0.2.1), as the gateway logs them. */
	private const ADDRESSES = ['192.0.2.1', '127.0.0.1', '[::1]'];
	private const OLD_GATEWAY = 'error: a message of 4294967294 bytes is not between 1 and 65536';

	private array $savedGlobals = [];
	private int $port = 0;
	private string $socket = '';

	protected function setUp(): void
	{
		foreach (self::krGlobals() as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_live_listeners_' . getmypid() . '_' . bin2hex(random_bytes(4)));
		$this->port = self::freePort();
		$this->socket = "{$this->krDir}/ctl.sock";
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

	/**
	 * The gateway's log of one start: it listens on $served (hosts as the gateway spells them, IPv6 bracketed), refuses $refused
	 * (host => the reason) and ends with $ready, the ready line of the gateway of the pid the ready marker names unless a row says otherwise.
	 *
	 * @param list<string> $served
	 * @param array<string,string> $refused
	 * @return list<string>
	 */
	private function started(array $served, array $refused = [], string $ready = self::READY): array
	{
		$lines = [];
		foreach ($served as $host) {
			$lines[] = "listening udp+tcp {$host}:{$this->port}";
		}
		foreach ($refused as $host => $reason) {
			$lines[] = "cannot listen on {$host}:{$this->port}: {$reason}";
		}
		return [...$lines, $ready];
	}

	/** A ready proxy whose rc script names 192.0.2.1, loopback and ::1 at the free port, and whose log says all three serve. */
	private function quiet(array $extra = []): void
	{
		$this->krApply($extra + ['port' => (string) $this->port, 'gatewayLog' => $this->started(self::ADDRESSES)]);
	}

	/** A ready proxy whose start could not assign 192.0.2.1: only loopback and ::1 serve. */
	private function quietWithoutLan(array $extra = []): void
	{
		$this->quiet($extra + ['gatewayLog' => $this->started(['127.0.0.1', '[::1]'], ['192.0.2.1' => self::CANT])]);
	}

	/**
	 * The stand-in gateway on the control socket, serving what the gateway's log says it serves now (the listener list the startup check
	 * asks for); returns the file its frames are recorded in.
	 *
	 * @param list<string|null> $replies
	 */
	private function gateway(array $replies = []): string
	{
		$log = "{$this->krDir}/dns_proxy.log";
		$listening = [];
		$refused = [];
		foreach (is_file($log) ? (array) file($log, FILE_IGNORE_NEW_LINES) : [] as $line) {
			if (preg_match('/^listening (\S+ \S+)$/', $line, $m) === 1) {
				$listening[$m[1]] = TRUE;
			} elseif (preg_match('/^stopped listening (\S+ \S+)$/', $line, $m) === 1) {
				unset($listening[$m[1]]);
			} elseif (preg_match('/^cannot listen on (\S+): (.+)$/', $line, $m) === 1) {
				$refused["udp+tcp {$m[1]}"] = $m[2];
			}
		}
		return $this->standIn($this->socket, $log, $replies, ['listening' => array_keys($listening), 'refused' => array_diff_key($refused, $listening)]);
	}

	/** From now on a restart of the proxy replaces the stand-in gateway: the old one stops, and the new one ($answers) serves what the log then says. */
	private function restartReplacesTheGateway(bool $answers): void
	{
		$serviceHook = $GLOBALS['pfb_test_service_hook'];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use ($serviceHook, $answers): void {
			$serviceHook($fn, $service);
			if ($fn === 'restart_service') {
				$this->standInsStop();
				if ($answers) {
					$this->gateway();
				}
			}
		};
	}

	/** @return list<array{head:string,body:string,fds:list<array{type:string,name:string,listening:bool}>}> the frames that change the gateway: the pass's own listener-list request (issue #3625) is not one */
	private static function frames(string $record): array
	{
		return array_values(array_filter(self::everyFrame($record), static fn (array $frame): bool => $frame['head'] !== 'fffffffc'));
	}

	/** The rc script the next pass would write, as the update pass has written it already (for the rows that call the sync alone). */
	private function rewriteRc(): void
	{
		pfb_dns_proxy_service($this->krProxyDir);
	}

	/** @return list<string> each frame the stand-in got as "add <kind> <host:port>" or "remove <kind> <host:port>" */
	private static function verbs(string $record): array
	{
		return array_map(
			static fn (array $frame): string => (['fffffffe' => 'add ', 'fffffffd' => 'remove '][$frame['head']] ?? "{$frame['head']} ") . $frame['body'],
			self::frames($record)
		);
	}

	/** @return list<array{string,string,bool}> [type, host:port, listening] of each descriptor frame $index carried */
	private static function fdsOf(string $record, int $index): array
	{
		return array_map(
			static fn (array $fd): array => [$fd['type'], $fd['name'], $fd['listening']],
			self::frames($record)[$index]['fds'] ?? []
		);
	}

	/** How many lines of the pfB log mention $text. */
	private function linesWith(string $text): int
	{
		return count(array_filter(explode("\n", $this->pfbLog()), static fn (string $line): bool => str_contains($line, $text)));
	}

	/** The pfB log alone (krLog() joins it to the error log, which pfb_logger() writes the same lines to). */
	private function pfbLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	/** The text of every notice filed under the startup check's id, as it stands. */
	private function startupNotices(): array
	{
		return array_column(array_filter($GLOBALS['pfb_test_file_notices'], static fn (array $notice): bool => $notice['id'] === self::STARTUP), 'notice');
	}

	// -----------------------------------------------------------------------
	// The update pass: an address-only change is live (D1, D4)
	// -----------------------------------------------------------------------

	public function testAnAddressOnlyChangeOfTheRcScriptIsMadeLiveAndRestartsNothing(): void
	{
		// Given a ready proxy that started on 192.0.2.1, and an interface that has 0.0.0.0 by the time the update pass runs
		$this->quiet(['lan' => '0.0.0.0']);
		$record = $this->gateway();
		$this->assertStringContainsString("--listen '192.0.2.1'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the rc script the gateway runs names 192.0.2.1');
		$this->assertSame([], self::frames($record), 'before: the gateway has been sent nothing');

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then the gone address was removed and the new one added, in that order, with the socket pair the gateway wants; nothing restarted
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["remove udp+tcp 192.0.2.1:{$this->port}", "add udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
		$this->assertSame([], self::fdsOf($record, 0), 'a remove carries no descriptor');
		$this->assertSame([['dgram', "0.0.0.0:{$this->port}", FALSE], ['stream', "0.0.0.0:{$this->port}", TRUE]], self::fdsOf($record, 1), 'the UDP socket, then the listening TCP socket');
		// and the rc script is the new one, each change is one line of the pfB log, and nothing is reported as unserved
		$rc = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);
		$this->assertStringContainsString("--listen '0.0.0.0'", $rc);
		$this->assertStringNotContainsString("--listen '192.0.2.1'", $rc);
		$this->assertSame(1, $this->linesWith("0.0.0.0:{$this->port}"));
		$this->assertSame(1, $this->linesWith("192.0.2.1:{$this->port}"));
		$this->assertMatchesRegularExpression('/Plain DNS[^\n]*0\.0\.0\.0:' . $this->port . '/', $this->pfbLog());
		$this->assertSame([], $this->startupNotices());
	}

	public function testAnIPv6AddressThatAppearsIsAddedLive(): void
	{
		// Given a ready proxy, and an interface that gained a wildcard IPv6 address (before: this host binds it)
		$this->assertTrue(self::binds("[::]:{$this->port}"), 'before: this host binds [::]');
		$this->quiet(['lan6' => '::']);
		$record = $this->gateway();

		// When the update pass runs
		$this->krEnsure();

		// Then only that listener is added, as an IPv6 pair, and nothing restarted
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["add udp+tcp [::]:{$this->port}"], self::verbs($record));
		$this->assertSame([['dgram', "[::]:{$this->port}", FALSE], ['stream', "[::]:{$this->port}", TRUE]], self::fdsOf($record, 0));
	}

	public function testSeveralChangesAreSentOneFramePerListenerRemovesFirst(): void
	{
		// Given a ready proxy that serves 192.0.2.1 and ::1 but not 127.0.0.1, and an interface that has 0.0.0.0 now
		$this->quiet(['lan' => '0.0.0.0', 'gatewayLog' => $this->started(['192.0.2.1', '[::1]'])]);
		$record = $this->gateway();

		// When the update pass runs
		$this->krEnsure();

		// Then the gone address is removed first, then each address the command names and nothing serves is added, in the command's order
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([
			"remove udp+tcp 192.0.2.1:{$this->port}", "add udp+tcp 0.0.0.0:{$this->port}", "add udp+tcp 127.0.0.1:{$this->port}",
		], self::verbs($record));
	}

	/** @return array<string,array{string}> the TLS transports: each has its own `--<kind>-listen` flag and its own port */
	public static function tlsKinds(): array
	{
		return ['DoT' => ['dot'], 'DoH' => ['doh'], 'DoQ' => ['doq']];
	}

	#[DataProvider('tlsKinds')]
	public function testAnAddressChangeOfOnlyOneTlsKindIsMadeLiveAndRestartsNothing(string $kind): void
	{
		// Given plain DNS on lan and the kind on opt1 at a port of its own, all served, and an opt1 that has 0.0.0.0 by the time the pass runs
		[$this->port, $port] = self::freePorts(2);
		foreach (['' => 'on', '_port' => (string) $port, '_interface' => 'opt1'] as $suffix => $value) {
			config_set_path(self::SETTINGS . "pfb_dns_{$kind}{$suffix}", $value);
		}
		config_set_path(self::SETTINGS . 'pfb_dns_interface', 'lan');
		$GLOBALS['pfb_test_interface_ip'] = ['lan' => '192.0.2.1', 'opt1' => '198.51.100.1'];
		$GLOBALS['pfb_test_interface_info']['opt1'] = ['status' => 'up', 'enable' => TRUE];
		$GLOBALS['pfb_test_interfaces']['opt1'] = '';
		$tls = array_map(static fn (string $host): string => "listening {$kind} {$host}:{$port}", ['198.51.100.1', '127.0.0.1', '[::1]']);
		$this->quiet(['gatewayLog' => [...array_slice($this->started(self::ADDRESSES), 0, -1), ...$tls, self::READY]]);
		$record = $this->gateway();
		$this->assertStringContainsString("--{$kind}-listen '198.51.100.1'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the rc script names opt1\'s address for the kind');
		$GLOBALS['pfb_test_interface_ip']['opt1'] = '0.0.0.0';

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then only that kind's address changed, live, with the kind's own socket; nothing restarted and plain DNS was left alone
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["remove {$kind} 198.51.100.1:{$port}", "add {$kind} 0.0.0.0:{$port}"], self::verbs($record));
		$this->assertSame([[($kind === 'doq') ? 'dgram' : 'stream', "0.0.0.0:{$port}", $kind !== 'doq']], self::fdsOf($record, 1));
		$this->assertSame([], $this->startupNotices());
	}

	public function testAQuietBoxSendsNothing(): void
	{
		// Given a ready proxy that serves every address of its command
		$this->quiet();
		$record = $this->gateway();

		// When the update pass runs
		$this->assertTrue($this->krEnsure());

		// Then nothing is sent and nothing restarts
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
	}

	// -----------------------------------------------------------------------
	// Everything else restarts the whole pair (D1)
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,bool}> the setting that changes between the rc script the gateway runs and the pass, and whether an address changes with it */
	public static function settingsThatRestartThePair(): array
	{
		$rows = [];
		foreach (['the port', 'a TLS group turned on', 'a TLS group turned off', 'DDR', 'the module turned off', 'the observer'] as $what) {
			$rows[$what] = [$what, FALSE];
			$rows["{$what}, with an address change"] = [$what, TRUE];
		}
		return $rows;
	}

	#[DataProvider('settingsThatRestartThePair')]
	public function testAnyOtherChangeOfTheRcScriptRestartsTheWholePairAndSendsNoFrame(string $what, bool $withAddress): void
	{
		// Given a ready proxy, and a setting that differs from what the running gateway was started with
		$this->quiet(['dot' => $what === 'a TLS group turned off', 'restartLog' => $this->started(self::ADDRESSES)]);
		$record = $this->gateway();
		match ($what) {
			'the port' => config_set_path('unbound/port', (string) ($this->port + 1)),
			'a TLS group turned on' => $this->krEnableDot(),
			'a TLS group turned off' => config_set_path(self::SETTINGS . 'pfb_dns_dot', ''),
			'DDR' => config_set_path(self::SETTINGS . 'pfb_dns_ddr', 'on'),
			'the module turned off' => $GLOBALS['pfb']['dnsbl'] = PfbToggle::Off,
			'the observer' => config_set_path('unbound/forwarding', ''),
		};
		if ($withAddress) {
			$GLOBALS['pfb_test_interface_ip'] = ['lan' => '0.0.0.0'];
		}
		$rc = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);

		// When the update pass runs
		$this->krEnsure();

		// Then the whole pair is restarted once, for its ports or settings, and no listener is changed live
		$this->assertNotSame($rc, (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the rc script the pass writes differs from the running one');
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertStringContainsString('Restarting the DNS proxy: its ports or DoT/DoH/DoQ/DDR settings changed', $this->krLog());
	}

	/** @return array<string,array{string,string}> how the gateway cannot take a live change: the proxy's state, and what its log holds */
	public static function boxesThatCannotBeReconciledLive(): array
	{
		return [
			'a proxy that is alive and not ready' => ['lives', 'a complete start'],
			'a log that holds no ready line' => ['serves', 'no ready line'],
			'no log' => ['serves', 'no log'],
		];
	}

	#[DataProvider('boxesThatCannotBeReconciledLive')]
	public function testAnAddressOnlyChangeThatCannotBeMadeLiveRestartsTheWholePair(string $proxy, string $log): void
	{
		// Given a proxy that cannot be reconciled live (before: with a complete start in its log the same change is made live, above)
		$lines = match ($log) {
			'a complete start' => $this->started(self::ADDRESSES),
			'no ready line' => ["listening udp+tcp 192.0.2.1:{$this->port}"],
			'no log' => NULL,
		};
		$this->quiet(['proxy' => $proxy, 'lan' => '0.0.0.0', 'gatewayLog' => $lines, 'restartLog' => $this->started(['0.0.0.0', '127.0.0.1', '[::1]'])]);
		$GLOBALS['pfb']['dns_proxy_log'] = "{$this->krDir}/dns_proxy.log";
		$record = $this->gateway();

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once because the listen addresses changed, and no frame is sent
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertStringContainsString('Restarting the DNS proxy: its listen addresses changed', $this->krLog());
	}

	public function testALogWithNoCompleteStartChangesNothingWhenTheRcScriptDidNotChange(): void
	{
		// Given a ready proxy whose log holds no `ready upstream` line (a start that cannot be judged), and an rc script that did not change
		$this->quiet(['gatewayLog' => ["listening udp+tcp 127.0.0.1:{$this->port}"]]);
		$record = $this->gateway();

		// When the update pass runs
		$this->assertTrue($this->krEnsure());

		// Then nothing is sent and nothing restarts
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
	}

	/** @return array<string,array{array<string,mixed>,string}> another reason the pass restarts the pair, and what it says */
	public static function otherReasonsToRestart(): array
	{
		return [
			'a restart pending' => [['marker' => 'the package changed its rc script'], 'a restart was deferred to this update'],
			'another gateway installed' => [['gateway' => 'different'], 'the package installed another gateway'],
		];
	}

	/** @param array<string,mixed> $scenario */
	#[DataProvider('otherReasonsToRestart')]
	public function testAnAddressChangeBesideAnotherReasonToRestartIsOneWholePairRestartWithNoFrame(array $scenario, string $why): void
	{
		// Given a ready proxy with another reason to restart, and an interface that has 0.0.0.0 by the time the pass runs
		$this->quiet($scenario + ['lan' => '0.0.0.0', 'restartLog' => $this->started(['0.0.0.0', '127.0.0.1', '[::1]'])]);
		$record = $this->gateway();

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once for that reason, and nothing is changed live
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertStringContainsString("Restarting the DNS proxy: {$why}", $this->krLog());
		$this->assertNull($this->krMarker());
	}

	// -----------------------------------------------------------------------
	// An address that is not there yet, or cannot be bound (D4.3)
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,?string}> the host as the command and the status spell it, and the IPv6 address lan has when the pass runs */
	public static function addressesTheBoxDoesNotHave(): array
	{
		return [
			'an IPv4 address the box does not have' => ['192.0.2.1', NULL],
			'an IPv6 address the box does not have' => ['[2001:db8::1]', '2001:db8::1'],
		];
	}

	#[DataProvider('addressesTheBoxDoesNotHave')]
	public function testAnAddressTheBoxCannotAssignYetIsLeftForALaterPassWithNothingSentLoggedOrRestarted(string $host, ?string $lan6): void
	{
		// Given a ready proxy whose command names an address that this box cannot assign (before: its bind fails as EADDRNOTAVAIL)
		$this->assertStringContainsString('assign requested address', self::bindError("{$host}:{$this->port}"), 'before: the bind fails for an address that is not there');
		$this->quietWithoutLan(['lan6' => $lan6]);
		$record = $this->gateway();
		$this->rewriteRc();
		$logged = strlen($this->pfbLog());

		// When the reconcile runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then nothing is sent, logged or asked for: the next pass tries again
		$this->assertNull($why);
		$this->assertSame([], self::frames($record));
		$this->assertSame($logged, strlen($this->pfbLog()), 'nothing was logged about an address that is not there yet');
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testTheFreeBSDWordingOfAnAddressThatIsNotThereYetIsLeftForALaterPassToo(): void
	{
		// Given a ready proxy whose command names 192.0.2.1, which its start could not assign, and a bind that fails in the words
		// FreeBSD gives EADDRNOTAVAIL ("Can't ...": Linux says "Cannot ...")
		$this->quietWithoutLan();
		$record = $this->gateway();
		$this->rewriteRc();
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_dns_proxy_listeners_sync', 'pfb_dns_proxy_listener_bind']);
		eval("namespace {$namespace}; function stream_socket_server(string \$address, &\$errno = NULL, &\$errstr = NULL, int \$flags = 0, \$context = NULL) { \$errno = 49; \$errstr = \"Can't assign requested address\"; return FALSE; }");
		$this->assertNull(($namespace . '\\pfb_dns_proxy_listener_bind')('udp+tcp', "192.0.2.1:{$this->port}", $failure), 'before: the bind fails');
		$this->assertSame("Can't assign requested address", $failure, 'before: in the words of FreeBSD');
		$logged = strlen($this->pfbLog());

		// When the reconcile runs
		$why = ($namespace . '\\pfb_dns_proxy_listeners_sync')();

		// Then nothing is sent, logged or asked for: the next pass tries again
		$this->assertNull($why);
		$this->assertSame([], self::frames($record));
		$this->assertSame($logged, strlen($this->pfbLog()), 'nothing was logged about an address that is not there yet');
		$this->assertSame([], $this->krProxyCalls());
	}

	#[DataProvider('addressesTheBoxDoesNotHave')]
	public function testTheUpdatePassRestartsNothingForAnAddressTheBoxCannotAssignYet(string $host, ?string $lan6): void
	{
		// Given the same ready proxy (for IPv6: an interface that gains the address by the time the pass runs)
		$this->assertStringContainsString('assign requested address', self::bindError("{$host}:{$this->port}"), 'before: the bind fails for an address that is not there');
		$this->quietWithoutLan(['lan6' => $lan6]);
		$record = $this->gateway();

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then the proxy is left alone, and the startup check names the address as not served
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertStringContainsString("Plain DNS is not served on {$host}:{$this->port}", implode(' ', $this->startupNotices()));
	}

	public function testAnAddressThatFailsToBindForAnotherReasonIsLoggedAndSkipped(): void
	{
		// Given a ready proxy that needs 0.0.0.0 and a port that something else holds (before: the bind fails, and not as EADDRNOTAVAIL)
		$this->hold("0.0.0.0:{$this->port}");
		$this->assertStringContainsStringIgnoringCase('in use', self::bindError("0.0.0.0:{$this->port}"), 'before: the port is taken');
		$this->quietWithoutLan(['lan' => '0.0.0.0']);
		$record = $this->gateway();
		$this->rewriteRc();

		// When the reconcile runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then the failure is one line of the pfB log naming the transport, the address and the reason; nothing is sent, nothing restarts
		$this->assertNull($why);
		$this->assertSame([], self::frames($record));
		$this->assertSame(1, $this->linesWith("0.0.0.0:{$this->port}"));
		$this->assertMatchesRegularExpression('/Plain DNS[^\n]*0\.0\.0\.0:' . $this->port . '[^\n]*in use/i', $this->pfbLog());
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAnAddressThatFailsToBindForAnotherReasonIsLoggedWhileARestartIsPendingToo(): void
	{
		// Given a restart pending, and a ready proxy that needs 0.0.0.0 on a port that something else holds (before: the bind fails, and not as EADDRNOTAVAIL)
		$this->hold("0.0.0.0:{$this->port}");
		$this->assertStringContainsStringIgnoringCase('in use', self::bindError("0.0.0.0:{$this->port}"), 'before: the port is taken');
		$this->quietWithoutLan(['lan' => '0.0.0.0', 'marker' => 'the package changed its rc script']);
		$record = $this->gateway();
		$this->rewriteRc();

		// When the reconcile runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then, as with no restart pending, the failure is one line of the pfB log; nothing is sent, nothing restarts, the marker stays
		$this->assertNull($why);
		$this->assertSame([], self::frames($record));
		$this->assertSame(1, $this->linesWith("0.0.0.0:{$this->port}"));
		$this->assertMatchesRegularExpression('/Plain DNS[^\n]*0\.0\.0\.0:' . $this->port . '[^\n]*in use/i', $this->pfbLog());
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame('the package changed its rc script', $this->krMarker());
	}

	public function testTheUpdatePassRestartsNothingForAnAddressItCannotBind(): void
	{
		// Given the same box, and an update pass
		$this->hold("0.0.0.0:{$this->port}");
		$this->quietWithoutLan(['lan' => '0.0.0.0']);
		$record = $this->gateway();

		// When the update pass runs
		$this->assertTrue($this->krEnsure());

		// Then the proxy is left alone and no frame is sent
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
	}

	public function testAHostThatIsNoIpAddressIsNeverBound(): void
	{
		// Given an rc script whose command names the host `127.1` (which a bind would turn into 127.0.0.1: before, it binds here),
		// beside the two loopback addresses the gateway serves
		$this->assertTrue(self::binds("127.1:{$this->port}"), 'before: this host binds 127.1');
		$this->krApply(['port' => (string) $this->port, 'gatewayLog' => $this->started(['127.0.0.1', '[::1]'])]);
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n\t/usr/sbin/daemon -f /bin/sh pfb_dns.sh --listen '127.1' --listen '127.0.0.1' --listen '::1' --port {$this->port} --upstream x\n");
		$record = $this->gateway();

		// When the reconcile runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then nothing is sent and nothing is asked for: the host was never handed to a bind
		$this->assertNull($why);
		$this->assertSame([], self::frames($record));
	}

	// -----------------------------------------------------------------------
	// What the sync must not take for a change
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> an rc script from which no plain listener can be read */
	public static function rcScriptsThatNameNoPlainListener(): array
	{
		return ['a missing script' => ['missing'], 'an empty script' => ['empty'], 'a script with no command' => ['no command']];
	}

	#[DataProvider('rcScriptsThatNameNoPlainListener')]
	public function testTheTickRemovesNoListenerWhenTheRcScriptNamesNoPlainListener(string $state): void
	{
		// Given a ready proxy that serves three addresses, whose rc script can no longer be read for any (a real script always names loopback)
		$this->quiet();
		$record = $this->gateway();
		$this->assertCount(3, pfb_dns_proxy_listeners()['listening']['udp+tcp'] ?? [], 'before: the log shows three listeners served');
		match ($state) {
			'missing' => unlink(PFB_DNS_PROXY_RCFILE),
			'empty' => file_put_contents(PFB_DNS_PROXY_RCFILE, ''),
			'no command' => file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n# the rc script an older package wrote\n"),
		};
		$this->assertSame([], pfb_dns_proxy_command_listeners()['udp+tcp'] ?? [], 'before: the script names no plain listener');

		// When the cron tick runs
		$this->krTick();

		// Then nothing was removed and nothing restarted: an unreadable script is no wish to stop serving
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
	}

	/** @return array<string,array{string}> a host the rc script spells as IPv4-mapped IPv6, which the gateway prints as the IPv4 address */
	public static function mappedHosts(): array
	{
		return ['dotted' => ['::ffff:127.0.0.1'], 'hex' => ['::ffff:7f00:1']];
	}

	#[DataProvider('mappedHosts')]
	public function testAnIPv4MappedHostIsTheIPv4AddressTheGatewayLogsSoTheTickChangesNothing(string $host): void
	{
		// Given a ready proxy whose rc script names loopback as an IPv4-mapped address, and a log that has it served as the gateway prints it
		$this->quiet();
		$rc = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);
		file_put_contents(PFB_DNS_PROXY_RCFILE, str_replace("--listen '127.0.0.1'", "--listen '{$host}'", $rc));
		$record = $this->gateway();
		$this->assertStringContainsString("--listen '{$host}'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the script spells loopback as the mapped address');
		$this->assertTrue(isset(pfb_dns_proxy_listeners()['listening']['udp+tcp']["127.0.0.1:{$this->port}"]), 'before: the log has 127.0.0.1 served');

		// When the cron tick runs
		$this->krTick();

		// Then it is the same listener: nothing is removed or added, and nothing restarts
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
	}

	/** @return list<string> the lines another writer logged: 70,000 bytes, more than the 64 KiB the log is read within */
	private static function filler(): array
	{
		return array_fill(0, 700, str_repeat('f', 99));
	}

	public function testALogWindowThatCutOffTheLatestStartsMarkerIsNotTakenForTheWholeServedSet(): void
	{
		// Given a start whose `starting pid` line and listener on 127.0.0.1 are before the last 64 KiB of the log, its ready line inside it
		$this->quiet(['gatewayLog' => [
			'starting pid 4242', "listening udp+tcp 127.0.0.1:{$this->port}", ...self::filler(),
			"listening udp+tcp 192.0.2.1:{$this->port}", "listening udp+tcp [::1]:{$this->port}", self::READY,
		]]);
		$record = $this->gateway();
		$this->assertGreaterThan(65536, pfb_dns_proxy_log_size(), 'before: the log is longer than the window');
		$this->assertNotContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the start\'s marker is outside the window');
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"), 'before: this host binds 127.0.0.1, which the window does not show served');

		// When the cron tick runs
		$this->krTick();

		// Then the sync changed nothing: 127.0.0.1 is served, and was neither added again nor logged as failing to be
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(0, $this->linesWith('cannot be added live'));
	}

	public function testAnAddressOnlyChangeWithACutLogRestartsTheWholePairAndSendsNoFrame(): void
	{
		// Given a ready proxy whose log is longer than 64 KiB with its latest start's `starting pid` line out of the window, and an
		// interface that has 0.0.0.0 now (before: with the marker in the window the same change is made live, above)
		$this->quiet([
			'lan' => '0.0.0.0', 'restartLog' => $this->started(['0.0.0.0', '127.0.0.1', '[::1]']),
			'gatewayLog' => [
				'starting pid 4242', "listening udp+tcp 127.0.0.1:{$this->port}", ...self::filler(),
				"listening udp+tcp 192.0.2.1:{$this->port}", "listening udp+tcp [::1]:{$this->port}", self::READY,
			],
		]);
		$record = $this->gateway();
		$this->assertGreaterThan(65536, pfb_dns_proxy_log_size(), 'before: the log is longer than the window');
		$this->assertNotContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the start\'s marker is outside the window');

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once, as with no record of the ready gateway, and no listener is changed live on a cut record
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertStringContainsString('Restarting the DNS proxy: its listen addresses changed', $this->krLog());
	}

	public function testALogLongerThanTheWindowWhoseLatestStartIsInItWholeIsReconciledLive(): void
	{
		// Given a log of more than 64 KiB whose latest start, marker included, is inside the last 64 KiB and did not bind 127.0.0.1
		$this->quiet(['gatewayLog' => [
			...self::filler(), 'starting pid 4242', "listening udp+tcp 192.0.2.1:{$this->port}", "listening udp+tcp [::1]:{$this->port}", self::READY,
		]]);
		$record = $this->gateway();
		$this->assertGreaterThan(65536, pfb_dns_proxy_log_size(), 'before: the log is longer than the window');
		$this->assertContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the start\'s marker is inside the window');

		// When the cron tick runs
		$this->krTick();

		// Then the listener the start did not bind is added, as with a short log
		$this->assertSame(["add udp+tcp 127.0.0.1:{$this->port}"], self::verbs($record));
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAnOlderGatewaysLogWithNoMarkerThatIsNotCutIsReconciledLive(): void
	{
		// Given a short log with no `starting pid` line (an older gateway's) that did not bind 127.0.0.1
		$this->quiet(['gatewayLog' => $this->started(['192.0.2.1', '[::1]'])]);
		$record = $this->gateway();
		$this->assertNotContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the log has no marker');

		// When the cron tick runs
		$this->krTick();

		// Then it is reconciled as it always was
		$this->assertSame(["add udp+tcp 127.0.0.1:{$this->port}"], self::verbs($record));
		$this->assertSame([], $this->krProxyCalls());
	}

	// -----------------------------------------------------------------------
	// A change the gateway does not take restarts the pair once (D4.4)
	// -----------------------------------------------------------------------

	/** @return array<string,array{?string,string}> what a gateway answers the first frame (NULL = it hangs up), and what the restart's reason names of it */
	public static function gatewaysThatDoNotTakeTheChange(): array
	{
		return [
			'an older gateway answering the frame as a certificate length' => [self::OLD_GATEWAY, 'a message of 4294967294 bytes'],
			'a gateway that answers an error' => ['error: udp+tcp 0.0.0.0 is not allowed', 'is not allowed'],
			'a gateway that hangs up' => [NULL, 'closed the connection with no reply'],
		];
	}

	#[DataProvider('gatewaysThatDoNotTakeTheChange')]
	public function testAChangeTheGatewayDoesNotTakeRestartsThePairOnceAndNamesTheListener(?string $reply, string $failure): void
	{
		// Given a ready proxy that started without its lan address, and an interface that has 0.0.0.0 now (before: a gateway that takes it is sent the add)
		$this->quietWithoutLan(['lan' => '0.0.0.0', 'restartLog' => $this->started(['0.0.0.0', '127.0.0.1', '[::1]'])]);
		$record = $this->gateway([$reply]);

		// When the update pass runs
		$this->krEnsure();

		// Then the add was sent once, the pair is restarted once, and what the restart says names the listener and the failure
		$this->assertSame(["add udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertMatchesRegularExpression('/Restarting the DNS proxy:[^\n]*0\.0\.0\.0:' . $this->port . '[^\n]*' . preg_quote($failure, '/') . '/', $this->krLog());
	}

	public function testAGatewayWithNoControlSocketRestartsThePairOnceAndNamesTheListener(): void
	{
		// Given a ready proxy that started without its lan address, an interface that has 0.0.0.0 now, and nobody listening on the control socket
		$this->quietWithoutLan(['lan' => '0.0.0.0', 'restartLog' => $this->started(['0.0.0.0', '127.0.0.1', '[::1]'])]);
		$this->assertFileDoesNotExist($this->socket, 'before: there is no control socket');

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once, and what the restart says names the listener and that the socket could not be reached
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertMatchesRegularExpression('/Restarting the DNS proxy:[^\n]*0\.0\.0\.0:' . $this->port . '[^\n]*cannot connect/', $this->krLog());
	}

	public function testWhenTheGatewayRefusesTheFirstChangeTheSecondIsNeverSent(): void
	{
		// Given a ready proxy that serves only ::1, whose command names 0.0.0.0 and 127.0.0.1 besides, and a gateway that refuses the first frame
		$this->quiet(['lan' => '0.0.0.0', 'gatewayLog' => $this->started(['[::1]']), 'restartLog' => $this->started(['0.0.0.0', '127.0.0.1', '[::1]'])]);
		$record = $this->gateway(['error: refused']);

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once, and only the first frame was sent
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame(["add udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
	}

	public function testAChangeTheGatewayTookIsWaitedForInTheLogOnlyWithinTheBudget(): void
	{
		// Given a ready proxy that started without its lan address, the box has 0.0.0.0 now, and a gateway that says ok and logs nothing
		$this->quietWithoutLan(['lan' => '0.0.0.0']);
		$record = $this->gateway(['ok silent']);
		$this->rewriteRc();
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_dns_proxy_listeners_sync'], ['PFB_DNS_PROXY_LOG_WAIT' => 1]);

		// When the reconcile runs on a virtual clock
		$why = ($namespace . '\\pfb_dns_proxy_listeners_sync')();

		// Then it gave up after the budget, polling every 100 ms, with no restart asked for: the startup check will say what is served
		$this->assertNull($why);
		$this->assertSame(["add udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
		$this->assertNotSame([], $clock->sleeps);
		$this->assertSame([100000], array_values(array_unique($clock->sleeps)));
		$this->assertLessThanOrEqual(1100000, array_sum($clock->sleeps));
		$this->assertGreaterThanOrEqual(1000000, array_sum($clock->sleeps));
	}

	/** @return array<string,array{bool,string,bool}> a change the gateway takes: whether it is a remove, the reply, and whether the log shows it */
	public static function changesWaitedForInTheLog(): array
	{
		return [
			'an add the gateway logs at once' => [FALSE, 'ok', FALSE],
			'a remove the gateway logs at once' => [TRUE, 'ok', FALSE],
			'a remove whose line never appears' => [TRUE, 'ok silent', TRUE],
		];
	}

	#[DataProvider('changesWaitedForInTheLog')]
	public function testTheLogWaitEndsAtOnceWhenTheLogShowsTheChangeAndAlsoConfirmsARemove(bool $remove, string $reply, bool $waits): void
	{
		// Given a ready proxy with one change to make (an address to add, or a served one the command does not name to remove)
		if ($remove) {
			$this->quiet(['gatewayLog' => [...$this->started(self::ADDRESSES), "listening udp+tcp 0.0.0.0:{$this->port}"]]);
		} else {
			$this->quietWithoutLan(['lan' => '0.0.0.0']);
			$this->rewriteRc();
		}
		$record = $this->gateway([$reply]);
		$clock = new PfbFlockClockFixture();
		$namespace = $clock->loadChain(['pfb_dns_proxy_listeners_sync'], ['PFB_DNS_PROXY_LOG_WAIT' => 1]);

		// When the reconcile runs on a virtual clock
		$why = ($namespace . '\\pfb_dns_proxy_listeners_sync')();

		// Then the frame was sent once, and it waited the budget only when the log never showed the change
		$this->assertNull($why);
		$this->assertSame([($remove ? 'remove' : 'add') . " udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
		if ($waits) {
			$this->assertSame([100000], array_values(array_unique($clock->sleeps)));
			$this->assertGreaterThanOrEqual(1000000, array_sum($clock->sleeps));
			$this->assertLessThanOrEqual(1100000, array_sum($clock->sleeps));
		} else {
			$this->assertSame([], $clock->sleeps, 'the log showed the change at once, so nothing was waited for');
		}
	}

	public function testEveryKindIsReconciledRemovesBeforeAddsPerKindWithItsOwnSockets(): void
	{
		// Given an rc script that names loopback and ::1 for plain DNS, DoT, DoH and DoQ (a port each), and a log that serves only a stale
		// 192.0.2.1 of each kind
		[$plain, $dot, $doh, $doq] = self::freePorts(4);
		$this->krApply(['gatewayLog' => ['ready upstream 127.0.0.1:5353 pid 4242']]);
		$listen = static fn (string $flag): string => " --{$flag}listen '127.0.0.1' --{$flag}listen '::1'";
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n\t/usr/sbin/daemon -f /bin/sh pfb_dns.sh" . $listen('') . " --port {$plain}" . $listen('dot-') . " --dot-port {$dot}" .
			$listen('doh-') . " --doh-port {$doh}" . $listen('doq-') . " --doq-port {$doq} --upstream x\n");
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], implode("\n", [
			"listening udp+tcp 192.0.2.1:{$plain}", "listening dot 192.0.2.1:{$dot}", "listening doh 192.0.2.1:{$doh}", "listening doq 192.0.2.1:{$doq}",
			self::READY,
		]) . "\n");
		$record = $this->gateway();

		// When the reconcile runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then each kind loses its stale address before it gains its two, in the command's order, with that kind's sockets
		$this->assertNull($why);
		$this->assertSame([
			"remove udp+tcp 192.0.2.1:{$plain}", "add udp+tcp 127.0.0.1:{$plain}", "add udp+tcp [::1]:{$plain}",
			"remove dot 192.0.2.1:{$dot}", "add dot 127.0.0.1:{$dot}", "add dot [::1]:{$dot}",
			"remove doh 192.0.2.1:{$doh}", "add doh 127.0.0.1:{$doh}", "add doh [::1]:{$doh}",
			"remove doq 192.0.2.1:{$doq}", "add doq 127.0.0.1:{$doq}", "add doq [::1]:{$doq}",
		], self::verbs($record));
		$types = [];
		foreach (self::frames($record) as $index => $frame) {
			$types[$frame['body']] = implode(',', array_column(self::fdsOf($record, $index), 0));
		}
		$this->assertSame('dgram,stream', $types["udp+tcp [::1]:{$plain}"]);
		$this->assertSame('stream', $types["dot [::1]:{$dot}"]);
		$this->assertSame('stream', $types["doh 127.0.0.1:{$doh}"]);
		$this->assertSame('dgram', $types["doq 127.0.0.1:{$doq}"]);
		$this->assertSame('', $types["doq 192.0.2.1:{$doq}"], 'a remove carries no descriptor');
	}

	// -----------------------------------------------------------------------
	// The record of the gateway that published the ready marker (D4.8)
	// -----------------------------------------------------------------------

	public function testTheReconcileSendsNothingWhileTheLogHoldsOnlyAnEarlierGatewaysStart(): void
	{
		// Given a ready marker that names pid 4242, and a log whose latest complete start ends `pid 4141` and served 0.0.0.0, which the command no longer names
		$this->quiet(['gatewayLog' => $this->started([...self::ADDRESSES, '0.0.0.0'], [], self::PREVIOUS)]);
		$record = $this->gateway();
		$this->assertSame('4242', rtrim((string) file_get_contents($GLOBALS['pfb']['dns_proxy_ready'])), 'before: the marker names the gateway of pid 4242');
		$this->assertTrue(isset(pfb_dns_proxy_listeners()['listening']['udp+tcp']["0.0.0.0:{$this->port}"]), 'before: the log holds that start, which served 0.0.0.0');

		// When the reconcile runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then it did nothing: that record is not the ready gateway's, so no remove was sent and nothing restarts
		$this->assertNull($why);
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
	}

	public function testAnAddressOnlyChangeWithNoRecordOfTheReadyGatewayRestartsTheWholePair(): void
	{
		// Given a ready marker that names pid 4242 and a log whose only complete start is the previous gateway's, and an interface that has 0.0.0.0 now
		$this->quiet(['lan' => '0.0.0.0', 'gatewayLog' => $this->started(self::ADDRESSES, [], self::PREVIOUS), 'restartLog' => $this->started(['0.0.0.0', '127.0.0.1', '[::1]'])]);
		$record = $this->gateway();

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once, as with no complete start, and no listener is changed live on the previous gateway's record
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertStringContainsString('Restarting the DNS proxy: its listen addresses changed', $this->krLog());
	}

	// -----------------------------------------------------------------------
	// The cron tick (D4, D5(d))
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> host as the rc script and the gateway spell it, and as a bind takes it */
	public static function refusedAddressesTheBoxBindsNow(): array
	{
		return [
			'IPv4' => ['127.0.0.1', '127.0.0.1'],
			'IPv6, bracketed as the gateway logs it' => ['[::1]', '::1'],
		];
	}

	#[DataProvider('refusedAddressesTheBoxBindsNow')]
	public function testTheCronTickAddsAnAddressTheStartRefusedAndTheStartupNoticeCloses(string $host, string $bare): void
	{
		// Given a serving proxy whose start could not assign $host (which this box binds now), with its startup problem standing as a notice
		$this->assertSame('', self::bindError("{$host}:{$this->port}"), "before: this host binds {$host}");
		$served = array_values(array_diff(self::ADDRESSES, [$host]));
		$this->quiet(['gatewayLog' => $this->started($served, [$host => self::CANT])]);
		$record = $this->gateway();
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertNotSame([], $this->startupNotices(), 'before: the start left a startup notice');

		// When the cron tick runs
		$this->krTick();

		// Then the address was added live, with its two sockets; the proxy was not restarted and the notice is closed
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["add udp+tcp {$host}:{$this->port}"], self::verbs($record));
		$this->assertSame([['dgram', "{$host}:{$this->port}", FALSE], ['stream', "{$host}:{$this->port}", TRUE]], self::fdsOf($record, 0));
		$this->assertSame([], $this->startupNotices());
	}

	public function testTheCronTickAddsEveryMissingListenerTheBoxBindsWithOneFrameEachAndRestartsNothing(): void
	{
		// Given a serving proxy whose start bound only 192.0.2.1 (the box binds 127.0.0.1 and ::1 now)
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"), 'before: this host binds 127.0.0.1');
		$this->quiet(['gatewayLog' => $this->started(['192.0.2.1'], ['127.0.0.1' => self::CANT, '[::1]' => self::CANT])]);
		$record = $this->gateway();

		// When the cron tick runs
		$this->krTick();

		// Then each is added with its own frame, in the command's order, and the pair is not restarted
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["add udp+tcp 127.0.0.1:{$this->port}", "add udp+tcp [::1]:{$this->port}"], self::verbs($record));
		$this->assertSame([], $this->startupNotices());
	}

	public function testTheCronTickRestartsOnceWhenTheGatewayRefusesTheAddAndJudgesTheNewStart(): void
	{
		// Given the same serving proxy and standing notice, and a gateway that refuses the add; the restart's new start binds every address
		$this->quiet(['gatewayLog' => $this->started(['192.0.2.1', '[::1]'], ['127.0.0.1' => self::CANT]), 'restartLog' => $this->started(self::ADDRESSES)]);
		$record = $this->gateway(['error: refused']);
		$this->restartReplacesTheGateway(TRUE);
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertNotSame([], $this->startupNotices(), 'before: the old start left a startup notice');

		// When the cron tick runs
		$this->krTick();

		// Then the pair was restarted once, and the new start was judged: the standing notice is closed
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame(["add udp+tcp 127.0.0.1:{$this->port}"], self::verbs($record));
		$this->assertSame([], $this->startupNotices());
	}

	public function testTheTickDoesNotJudgeTheStartItReplacedWhileTheNewGatewayDoesNotAnswerYet(): void
	{
		// Given the same old start and standing notice, a gateway that refuses the add, and a restart whose new gateway does not answer yet
		$this->quiet(['gatewayLog' => $this->started(['192.0.2.1', '[::1]'], ['127.0.0.1' => self::CANT]), 'restartLog' => NULL]);
		$record = $this->gateway(['error: refused']);
		$this->restartReplacesTheGateway(FALSE);
		pfb_dns_proxy_startup_check(TRUE);
		$this->assertNotSame([], $this->startupNotices(), 'before: the old start left a startup notice');
		$logged = strlen($this->pfbLog());

		// When the cron tick runs
		$this->krTick();

		// Then the proxy was restarted once, and what the tick logged says so and does not repeat the old start's problem
		$this->assertSame(["add udp+tcp 127.0.0.1:{$this->port}"], self::verbs($record));
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$during = substr($this->pfbLog(), $logged);
		$this->assertStringContainsString('Restarting the DNS proxy:', $during);
		$this->assertStringNotContainsString('pfB-DNS started with problems', $during);
	}

	public function testTheTickRemovesAListenerTheCommandNoLongerNamesLive(): void
	{
		// Given a ready proxy whose log shows an address that was added live and that the rc script's command does not name
		$this->quiet(['gatewayLog' => [...$this->started(self::ADDRESSES), "listening udp+tcp 0.0.0.0:{$this->port}"]]);
		$record = $this->gateway();
		$this->assertTrue(isset(pfb_dns_proxy_listeners()['listening']['udp+tcp']["0.0.0.0:{$this->port}"]), 'before: the live-added listener is served');

		// When the cron tick runs
		$this->krTick();

		// Then it is removed live, nothing is restarted, and the gateway's log no longer shows it served
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["remove udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
		$this->assertFalse(isset(pfb_dns_proxy_listeners()['listening']['udp+tcp']["0.0.0.0:{$this->port}"]));
	}

	public function testTheTickStillConfirmsAnAddressTheBoxCannotBind(): void
	{
		// Given a serving proxy whose latest start could not assign 192.0.2.1, which this box does not have
		$this->assertStringContainsString('assign requested address', self::bindError("192.0.2.1:{$this->port}"), 'before: this host does not have 192.0.2.1');
		$this->quietWithoutLan();
		$record = $this->gateway();
		$logged = strlen($this->pfbLog());

		// When the cron tick runs
		$this->krTick();

		// Then nothing is sent or restarted and the confirmation files the problem as it always did
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertStringContainsString("Plain DNS is not served on 192.0.2.1:{$this->port}: bind: can't assign requested address", substr($this->pfbLog(), $logged));
	}

	public function testTheTickChangesNothingWhileAnUpdatePassRuns(): void
	{
		// Given a serving proxy whose start refused 127.0.0.1, and an update pass running
		$ps = ['/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron'];
		$this->assertTrue(pfb_update_pass_running($ps), 'before: the process table holds an update pass');
		$this->quiet(['gatewayLog' => $this->started(['192.0.2.1', '[::1]'], ['127.0.0.1' => self::CANT])]);
		$record = $this->gateway();
		$filed = count($GLOBALS['pfb_test_file_notices']);

		// When the cron tick runs
		$this->krTick($ps);

		// Then the pass is left to do it: nothing is sent, restarted or filed
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertCount($filed, $GLOBALS['pfb_test_file_notices']);
	}

	public function testTheTickTakesNoRestartThatOnlyTheUpdatePassMakes(): void
	{
		// Given a start that bound every address, a restart pending, an rc script that differs and another gateway installed
		$this->quiet(['serving' => TRUE, 'marker' => 'the package changed its rc script', 'rc' => 'stale', 'gateway' => 'different']);
		$record = $this->gateway();
		$rc = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);

		// When the cron tick runs
		$this->krTick();

		// Then nothing is restarted or sent, and the pending restart and the rc script are as they were
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
		$this->assertSame('the package changed its rc script', $this->krMarker());
		$this->assertSame($rc, (string) file_get_contents(PFB_DNS_PROXY_RCFILE));
	}

	public function testATickRestartLeavesAPendingRestartToTheUpdatePassAndSendsNoFrame(): void
	{
		// Given a restart pending for the rc script, and a ready proxy whose start refused 127.0.0.1 (which this box binds)
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"), 'before: this host binds 127.0.0.1');
		$this->quiet([
			'marker' => 'the package changed its rc script', 'gatewayLog' => $this->started(['192.0.2.1', '[::1]'], ['127.0.0.1' => self::CANT]),
			'restartLog' => $this->started(self::ADDRESSES),
		]);
		$record = $this->gateway();

		// When the cron tick runs, and then the update pass
		$this->krTick();
		$afterTick = [$this->krProxyCalls(), $this->krMarker()];
		// the tick's config seams change what the rc script is generated from: the pass compares it with the one on disk
		pfb_dns_proxy_service($this->krProxyDir);
		$this->krEnsure();

		// Then the tick restarted without consuming the marker and sent no frame (what is pending may differ in more than addresses),
		// and the pass owns the marker: it restarts once more and clears it
		$this->assertSame([['restart_service pfb_dns_proxy'], 'the package changed its rc script'], $afterTick);
		$this->assertSame([], self::frames($record));
		$this->assertSame(['restart_service pfb_dns_proxy', 'restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertNull($this->krMarker());
	}

	public function testWhileARestartIsPendingNoListenerIsRemovedLive(): void
	{
		// Given a restart pending and a log that shows an address the command does not name, every address of the command served
		$this->quiet(['marker' => 'the package changed its rc script', 'gatewayLog' => [...$this->started(self::ADDRESSES), "listening udp+tcp 0.0.0.0:{$this->port}"]]);
		$record = $this->gateway();

		// When the cron tick runs
		$this->krTick();

		// Then nothing is removed or restarted: the pending restart's rc script may differ in more than addresses
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame('the package changed its rc script', $this->krMarker());
	}

	public function testAZonedRefusalIsNeverRecordedSoNothingIsChangedForIt(): void
	{
		// Given a ready proxy that serves every address of its command and whose start refused zoned link-local addresses
		$this->quiet(['gatewayLog' => [
			"cannot listen on [fe80::1%lo0]:{$this->port}: " . self::CANT, "cannot listen on [fe80::1%1]:{$this->port}: " . self::CANT,
			...$this->started(self::ADDRESSES),
		]]);
		$record = $this->gateway();

		// When the log is read, the update pass runs and then the cron tick
		$refused = pfb_dns_proxy_listeners()['refused'] ?? NULL;
		$ready = $this->krEnsure();
		$this->krTick();

		// Then the parser never recorded the refusal, and neither pass changed anything
		$this->assertSame([], $refused);
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame([], self::frames($record));
	}

	public function testATickNeverChangesTheListenersOfAProxyThatIsAliveButNotReady(): void
	{
		// Given a live proxy that never published its marker, whose log's latest start refused 127.0.0.1 (which this box binds); the
		// rollback its failed readiness leads to finds the config locked
		$this->quiet(['proxy' => 'lives', 'gatewayLog' => $this->started(['192.0.2.1', '[::1]'], ['127.0.0.1' => self::CANT])]);
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$record = $this->gateway();
		$this->assertFalse(pfb_dns_proxy_ready(), 'before: the proxy is alive and not ready');
		$this->assertSame(["127.0.0.1:{$this->port}" => self::CANT], pfb_dns_proxy_listeners()['refused'] ?? NULL, 'before: the refusal is in the record');

		// When the cron tick runs
		$this->krTick();

		// Then the tick neither added the address nor restarted: a proxy that is not ready has no record of its own to judge
		$this->assertSame([], self::frames($record));
		$this->assertNotContains('restart_service pfb_dns_proxy', $this->krProxyCalls());
	}
}
