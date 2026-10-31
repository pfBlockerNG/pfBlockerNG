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
 * without a restart: root PHP binds the socket and hands it over on the gateway's control socket, and what the gateway serves is what
 * it answers to a list request on that socket (pfb_dns_proxy_listener_list(), issue #3625; docs/specs/pfb-dns-live-listen-addresses.md,
 * D1, D4, D5). The stand-in gateway is support/ListenerControlServer.php, a real process on a real Unix socket that records every
 * frame and its descriptors, and serves the state a test gives it, which an add or remove it takes also changes.
 *
 *   - an rc script that differs only in its listen addresses, with the proxy READY and a gateway that lists what it serves, is
 *     reconciled live by the update pass: the gone addresses removed, the new ones added, nothing restarted; any other difference (a
 *     port, a TLS group on or off, DDR, a module flag) and a proxy that is not READY restart the pair, and so does a gateway that gives
 *     no list (no control socket, an older gateway's error), which leaves the sync nothing to compare with;
 *   - the sync asks the gateway what it serves, then removes each served listener the command no longer names and adds each one it
 *     names that nothing serves; a gateway that gives no list (no socket, an error, a hang-up) changes nothing: no frame but the
 *     request, nothing logged, no restart, and the gateway's log is never read in its place;
 *   - an address the box cannot assign yet (in the words of Linux and of FreeBSD) is left for a later pass with nothing sent, logged or
 *     restarted; one that fails to bind otherwise is logged and skipped, a restart pending or not; a change the gateway does not take
 *     (an older gateway's error, a hang-up) restarts the pair once and sends no further frame;
 *   - the cron tick adds an address the start refused and the box binds now, and removes one the command no longer names, live;
 *     with a restart pending it changes nothing live and restarts once for a missing listener that binds (the update pass keeps the
 *     marker); under an update pass it does nothing. A package operation's rows are DnsProxyKeepRunningPkgTest's.
 *   - the sync takes no gap for a change: an rc script that names no plain listener (missing, empty, no command) changes nothing; a
 *     host the gateway prints differently (an IPv4-mapped one) is spelled as it prints it; one TLS kind's address changes live by itself.
 *
 * Every row that binds uses a port above 1024 picked free at runtime and configured as the rc script's port, so that it runs as a
 * user that is not root too. Every row starts from the quiet box (nothing differs: nothing is sent or restarted).
 */
#[CoversFunction('pfb_dns_proxy_ensure_running')]
#[CoversFunction('pfb_dns_proxy_listeners_sync')]
#[CoversFunction('pfb_dns_proxy_listener_list')]
#[CoversFunction('pfb_dns_proxy_listener_bind')]
#[CoversFunction('pfb_dns_proxy_listener_add')]
#[CoversFunction('pfb_dns_proxy_listener_remove')]
#[CoversFunction('pfblockerng_tick')]
final class DnsProxyLiveListenersTest extends TestCase
{
	use KeepRunningScenario;
	use LiveListenerStandIn {
		frames as private everyFrame;
	}

	private const CANT = "bind: can't assign requested address";
	private const STARTUP = 'pfBlockerNG DNS Proxy startup';
	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	/** The hosts the rc script's command listens on in this fixture (lan is 192.0.2.1), as the gateway lists them. */
	private const ADDRESSES = ['192.0.2.1', '127.0.0.1', '[::1]'];
	/** What a gateway older than the add and remove verbs answers them with: it reads the frame's head as a certificate length. */
	private const OLD_GATEWAY = 'error: a message of 4294967294 bytes is not between 1 and 65536';
	/** What a gateway older than the list verb answers a list request with. */
	private const NO_LIST = "error: a message of 4294967292 bytes is not between 1 and 65536\n";

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

	/** A ready proxy whose rc script names 192.0.2.1, loopback and ::1 at the free port. The gateway it talks to is gateway()'s. */
	private function quiet(array $extra = []): void
	{
		$this->krApply($extra + ['port' => (string) $this->port]);
	}

	/**
	 * `<kind> <host:port>` of each of $hosts (hosts as the gateway spells them, IPv6 bracketed), at the free port unless $port is given.
	 *
	 * @param list<string> $hosts
	 * @return list<string>
	 */
	private function listed(array $hosts, string $kind = 'udp+tcp', ?int $port = NULL): array
	{
		return array_map(fn (string $host): string => "{$kind} {$host}:" . ($port ?? $this->port), $hosts);
	}

	/**
	 * The stand-in gateway on the control socket: it serves $listening (the three addresses of the command unless given), refuses
	 * $refused and takes the first add and remove frames as $replies say; returns the file its frames are recorded in.
	 *
	 * @param list<string|null> $replies
	 * @param list<string>|null $listening `<kind> <host:port>`
	 * @param array<string,string> $refused `<kind> <host:port>` => reason
	 */
	private function gateway(array $replies = [], ?array $listening = NULL, array $refused = []): string
	{
		return $this->standIn($this->socket, $replies, ['listening' => $listening ?? $this->listed(self::ADDRESSES), 'refused' => $refused]);
	}

	/**
	 * The gateway of a start that could not assign 192.0.2.1: it serves loopback and ::1, and refused lan with that reason.
	 *
	 * @param list<string|null> $replies
	 */
	private function gatewayWithoutLan(array $replies = []): string
	{
		return $this->gateway($replies, $this->listed(['127.0.0.1', '[::1]']), array_fill_keys($this->listed(['192.0.2.1']), self::CANT));
	}

	/**
	 * What the gateway's own log says: a complete start of pid 4242 that served $hosts at the free port. Nothing reads it any more
	 * (issue #3625); the rows that write it prove a gateway that gives no list is not judged by it.
	 *
	 * @param list<string> $hosts
	 */
	private function logSaysServed(array $hosts): void
	{
		$lines = ['starting pid 4242', ...array_map(fn (string $host): string => "listening udp+tcp {$host}:{$this->port}", $hosts), 'ready upstream 127.0.0.1:5353 pid 4242'];
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], implode("\n", $lines) . "\n");
	}

	/**
	 * From now on a restart of the proxy is a NEW gateway process: the stand-in is stopped and, with $listening, one that serves it
	 * starts; NULL = none answers yet.
	 *
	 * @param list<string>|null $listening `<kind> <host:port>`
	 */
	private function restartStartsAGateway(?array $listening): void
	{
		$serviceHook = $GLOBALS['pfb_test_service_hook'];
		$GLOBALS['pfb_test_service_hook'] = function (string $fn, string $service) use ($serviceHook, $listening): void {
			$serviceHook($fn, $service);
			if ($fn === 'restart_service') {
				$this->standInsStop();
				if ($listening !== NULL) {
					$this->standIn($this->socket, [], ['listening' => $listening]);
				}
			}
		};
	}

	/** @return list<array{head:string,body:string,fds:list<array{type:string,name:string,listening:bool}>}> the frames that change the gateway: its list requests are asserted through requests() by the rows that pin them */
	private static function frames(string $record): array
	{
		return array_values(array_filter(self::everyFrame($record), static fn (array $frame): bool => $frame['head'] !== 'fffffffc'));
	}

	/** The rc script the next pass would write, as the update pass has written it already (for the rows that call the sync alone). */
	private function rewriteRc(): void
	{
		pfb_dns_proxy_service($this->krProxyDir);
	}

	/** @return list<string> each frame the stand-in got, the list requests too, in order: "list", "add <kind> <host:port>" or "remove <kind> <host:port>" */
	private static function requests(string $record): array
	{
		return array_map(
			static fn (array $frame): string => match ($frame['head']) {
				'fffffffc' => 'list',
				'fffffffe' => "add {$frame['body']}",
				'fffffffd' => "remove {$frame['body']}",
				default => "{$frame['head']} {$frame['body']}",
			},
			self::everyFrame($record)
		);
	}

	/** @return list<string> each frame that changes the gateway, as requests() writes it */
	private static function verbs(string $record): array
	{
		return array_values(array_diff(self::requests($record), ['list']));
	}

	/** @return list<array{string,string,bool}> [type, host:port, listening] of each descriptor frame $index (of the frames that change the gateway) carried */
	private static function fdsOf(string $record, int $index): array
	{
		return array_map(
			static fn (array $fd): array => [$fd['type'], $fd['name'], $fd['listening']],
			self::frames($record)[$index]['fds'] ?? []
		);
	}

	/**
	 * What the stand-in serves now, as pfb_dns_proxy_listener_list() reads it: a request of its own, after the ones a row asserts.
	 *
	 * @return list<string> `<kind> <host:port>` of each, in the order the stand-in holds them
	 */
	private function served(): array
	{
		$list = pfb_dns_proxy_listener_list();
		$this->assertNotNull($list, 'the stand-in gateway gave no list');
		$served = [];
		foreach ($list['listening'] as $kind => $addresses) {
			foreach (array_keys($addresses) as $at) {
				$served[] = "{$kind} {$at}";
			}
		}
		return $served;
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
	// The sync asks the gateway what it serves (issue #3625)
	// -----------------------------------------------------------------------

	public function testTheSyncAsksWhatTheGatewayServesThenRemovesAndAddsOnlyTheDifferenceFromTheCommand(): void
	{
		// Given a gateway that serves 192.0.2.1 and loopback, and a command that names 0.0.0.0, loopback and ::1
		$this->quiet(['lan' => '0.0.0.0']);
		$record = $this->gateway([], $this->listed(['192.0.2.1', '127.0.0.1']));
		$this->rewriteRc();
		$this->assertEqualsCanonicalizing($this->listed(['192.0.2.1', '127.0.0.1']), $this->served(), 'before: the gateway serves 192.0.2.1 and loopback');
		$asked = count(self::requests($record));

		// When the sync runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then it asked first, removed the listener the command no longer names, added the two it names that nothing served, in the
		// command's order and with their sockets, and sent nothing else
		$p = $this->port;
		$this->assertNull($why);
		$this->assertSame(['list', "remove udp+tcp 192.0.2.1:{$p}", "add udp+tcp 0.0.0.0:{$p}", "add udp+tcp [::1]:{$p}"], array_slice(self::requests($record), $asked));
		$this->assertSame([['dgram', "0.0.0.0:{$p}", FALSE], ['stream', "0.0.0.0:{$p}", TRUE]], self::fdsOf($record, 1), 'the add of 0.0.0.0 carried the UDP socket, then the listening TCP socket');
		// and the gateway now serves exactly the command's listeners, each change taking one line of the pfB log
		$this->assertEqualsCanonicalizing($this->listed(['0.0.0.0', '127.0.0.1', '[::1]']), $this->served());
		$this->assertMatchesRegularExpression('/Plain DNS no longer listens on 192\.0\.2\.1:' . $p . '/', $this->pfbLog());
		$this->assertMatchesRegularExpression('/Plain DNS now listens on 0\.0\.0\.0:' . $p . '/', $this->pfbLog());
		$this->assertMatchesRegularExpression('/Plain DNS now listens on \[::1\]:' . $p . '/', $this->pfbLog());
		$this->assertSame([], $this->krProxyCalls());
	}

	/** @return array<string,array{string|false|null}> a gateway that gives no list: none listens (FALSE), or what it answers the list request with (NULL = it hangs up) */
	public static function gatewaysThatGiveNoList(): array
	{
		return [
			'no control socket' => [FALSE],
			'an older gateway answering the request as a bad message length' => [self::NO_LIST],
			'a gateway that hangs up' => [NULL],
		];
	}

	#[DataProvider('gatewaysThatGiveNoList')]
	public function testTheSyncChangesNothingAndAsksNothingMoreWhenTheGatewayGivesNoList(string|false|null $answer): void
	{
		// Given a command that names 0.0.0.0, a gateway that gives no list, and a log that says only 192.0.2.1 and loopback are served
		// (which, taken for the truth, would be a remove and two adds)
		$this->quiet(['lan' => '0.0.0.0']);
		$this->logSaysServed(['192.0.2.1', '127.0.0.1']);
		$record = ($answer === FALSE) ? NULL : $this->standIn($this->socket, [], ['list' => $answer]);
		$this->rewriteRc();
		$logged = strlen($this->pfbLog());
		if ($answer === FALSE) {
			$this->assertFileDoesNotExist($this->socket, 'before: there is no control socket');
		}

		// When the sync runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then nothing is to be done: no frame but the list request, nothing logged, no restart asked for
		$this->assertNull($why);
		if ($record !== NULL) {
			$this->assertSame(['list'], self::requests($record));
		}
		$this->assertSame($logged, strlen($this->pfbLog()), 'nothing was logged');
		$this->assertSame([], $this->krProxyCalls());
	}

	#[DataProvider('gatewaysThatGiveNoList')]
	public function testAnUpdatePassChangesNothingWhenTheRcScriptDidNotChangeAndTheGatewayGivesNoList(string|false|null $answer): void
	{
		// Given a ready proxy whose rc script did not change, a gateway that gives no list, and a log that says a listener is missing
		$this->quiet();
		$this->logSaysServed(['127.0.0.1']);
		$record = ($answer === FALSE) ? NULL : $this->standIn($this->socket, [], ['list' => $answer]);

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then nothing is changed live and nothing restarts
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls());
		if ($record !== NULL) {
			$this->assertSame([], self::frames($record));
		}
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
		$this->quiet(['lan' => '0.0.0.0']);
		$record = $this->gateway([], $this->listed(['192.0.2.1', '[::1]']));

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
		$this->quiet();
		$record = $this->gateway([], [...$this->listed(self::ADDRESSES), ...$this->listed(['198.51.100.1', '127.0.0.1', '[::1]'], $kind, $port)]);
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
		$this->quiet(['dot' => $what === 'a TLS group turned off']);
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

	/** @return array<string,array{string,string|bool|null}> how the gateway cannot take a live change: the proxy's state, and its answer to a list request (TRUE = the list; FALSE = no control socket; NULL = it hangs up) */
	public static function boxesThatCannotBeReconciledLive(): array
	{
		return [
			'a proxy that is alive and not ready' => ['lives', TRUE],
			'a gateway with no control socket' => ['serves', FALSE],
			'an older gateway that answers the list request as an error' => ['serves', self::NO_LIST],
		];
	}

	#[DataProvider('boxesThatCannotBeReconciledLive')]
	public function testAnAddressOnlyChangeThatCannotBeMadeLiveRestartsTheWholePair(string $proxy, string|bool|null $answer): void
	{
		// Given an interface that has 0.0.0.0 now, a gateway log that says everything is served (which, taken for the truth, would be
		// reconciled live: before, a known list does that, above), and a proxy that cannot be reconciled live
		$this->quiet(['proxy' => $proxy, 'lan' => '0.0.0.0']);
		$this->logSaysServed(self::ADDRESSES);
		$record = ($answer === FALSE) ? NULL : (($answer === TRUE) ? $this->gateway() : $this->standIn($this->socket, [], ['list' => $answer]));

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once because the listen addresses changed, and no listener is changed
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		if ($record !== NULL) {
			$this->assertSame([], self::frames($record));
		}
		$this->assertStringContainsString('Restarting the DNS proxy: its listen addresses changed', $this->krLog());
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
		$this->quiet($scenario + ['lan' => '0.0.0.0']);
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
		$this->quiet(['lan6' => $lan6]);
		$record = $this->gatewayWithoutLan();
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
		$this->quiet();
		$record = $this->gatewayWithoutLan();
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
		$this->quiet(['lan6' => $lan6]);
		$record = $this->gatewayWithoutLan();

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
		$this->quiet(['lan' => '0.0.0.0']);
		$record = $this->gatewayWithoutLan();
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
		$this->quiet(['lan' => '0.0.0.0', 'marker' => 'the package changed its rc script']);
		$record = $this->gatewayWithoutLan();
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
		$this->quiet(['lan' => '0.0.0.0']);
		$record = $this->gatewayWithoutLan();

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
		$this->quiet();
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n\t/usr/sbin/daemon -f /bin/sh pfb_dns.sh --listen '127.1' --listen '127.0.0.1' --listen '::1' --port {$this->port} --upstream x\n");
		$record = $this->gateway([], $this->listed(['127.0.0.1', '[::1]']));

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
		$this->assertCount(3, pfb_dns_proxy_listener_list()['listening']['udp+tcp'] ?? [], 'before: the gateway serves three listeners');
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
	public function testAnIPv4MappedHostIsTheIPv4AddressTheGatewayListsSoTheTickChangesNothing(string $host): void
	{
		// Given a ready proxy whose rc script names loopback as an IPv4-mapped address, and a gateway that lists it as it prints it
		$this->quiet();
		$rc = (string) file_get_contents(PFB_DNS_PROXY_RCFILE);
		file_put_contents(PFB_DNS_PROXY_RCFILE, str_replace("--listen '127.0.0.1'", "--listen '{$host}'", $rc));
		$record = $this->gateway();
		$this->assertStringContainsString("--listen '{$host}'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the script spells loopback as the mapped address');
		$this->assertTrue(isset(pfb_dns_proxy_listener_list()['listening']['udp+tcp']["127.0.0.1:{$this->port}"]), 'before: the gateway lists 127.0.0.1 as served');

		// When the cron tick runs
		$this->krTick();

		// Then it is the same listener: nothing is removed or added, and nothing restarts
		$this->assertSame([], self::frames($record));
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
		$this->quiet(['lan' => '0.0.0.0']);
		$record = $this->gatewayWithoutLan([$reply]);

		// When the update pass runs
		$this->krEnsure();

		// Then the add was sent once, the pair is restarted once, and what the restart says names the listener and the failure
		$this->assertSame(["add udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertMatchesRegularExpression('/Restarting the DNS proxy:[^\n]*0\.0\.0\.0:' . $this->port . '[^\n]*' . preg_quote($failure, '/') . '/', $this->krLog());
	}

	public function testWhenTheGatewayRefusesTheFirstChangeTheSecondIsNeverSent(): void
	{
		// Given a ready proxy that serves only ::1, whose command names 0.0.0.0 and 127.0.0.1 besides, and a gateway that refuses the first frame
		$this->quiet(['lan' => '0.0.0.0']);
		$record = $this->gateway(['error: refused'], $this->listed(['[::1]']));

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted once, and only the first frame was sent
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame(["add udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
	}

	public function testEveryKindIsReconciledRemovesBeforeAddsPerKindWithItsOwnSockets(): void
	{
		// Given an rc script that names loopback and ::1 for plain DNS, DoT, DoH and DoQ (a port each), and a gateway that serves only a
		// stale 192.0.2.1 of each kind
		[$plain, $dot, $doh, $doq] = self::freePorts(4);
		$this->krApply([]);
		$listen = static fn (string $flag): string => " --{$flag}listen '127.0.0.1' --{$flag}listen '::1'";
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n\t/usr/sbin/daemon -f /bin/sh pfb_dns.sh" . $listen('') . " --port {$plain}" . $listen('dot-') . " --dot-port {$dot}" .
			$listen('doh-') . " --doh-port {$doh}" . $listen('doq-') . " --doq-port {$doq} --upstream x\n");
		$record = $this->gateway([], [
			...$this->listed(['192.0.2.1'], 'udp+tcp', $plain), ...$this->listed(['192.0.2.1'], 'dot', $dot),
			...$this->listed(['192.0.2.1'], 'doh', $doh), ...$this->listed(['192.0.2.1'], 'doq', $doq),
		]);

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
	// The cron tick (D4, D5(d))
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> host as the rc script and the gateway spell it, and as a bind takes it */
	public static function refusedAddressesTheBoxBindsNow(): array
	{
		return [
			'IPv4' => ['127.0.0.1', '127.0.0.1'],
			'IPv6, bracketed as the gateway lists it' => ['[::1]', '::1'],
		];
	}

	#[DataProvider('refusedAddressesTheBoxBindsNow')]
	public function testTheCronTickAddsAnAddressTheStartRefusedAndTheStartupNoticeCloses(string $host, string $bare): void
	{
		// Given a serving proxy whose start could not assign $host (which this box binds now), with its startup problem standing as a notice
		$this->assertSame('', self::bindError("{$host}:{$this->port}"), "before: this host binds {$host}");
		$this->quiet();
		$record = $this->gateway([], $this->listed(array_values(array_diff(self::ADDRESSES, [$host]))), array_fill_keys($this->listed([$host]), self::CANT));
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
		$this->quiet();
		$record = $this->gateway([], $this->listed(['192.0.2.1']), array_fill_keys($this->listed(['127.0.0.1', '[::1]']), self::CANT));

		// When the cron tick runs
		$this->krTick();

		// Then each is added with its own frame, in the command's order, and the pair is not restarted
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["add udp+tcp 127.0.0.1:{$this->port}", "add udp+tcp [::1]:{$this->port}"], self::verbs($record));
		$this->assertSame([], $this->startupNotices());
	}

	public function testTheCronTickRestartsOnceWhenTheGatewayRefusesTheAddAndJudgesTheNewStart(): void
	{
		// Given the same serving proxy and standing notice, and a gateway that refuses the add; the restart starts a new gateway that serves every address
		$this->quiet();
		$record = $this->gateway(['error: refused'], $this->listed(['192.0.2.1', '[::1]']), array_fill_keys($this->listed(['127.0.0.1']), self::CANT));
		$this->restartStartsAGateway($this->listed(self::ADDRESSES));
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
		$this->quiet();
		$record = $this->gateway(['error: refused'], $this->listed(['192.0.2.1', '[::1]']), array_fill_keys($this->listed(['127.0.0.1']), self::CANT));
		$this->restartStartsAGateway(NULL);
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
		// Given a ready proxy whose gateway serves an address that was added live and that the rc script's command does not name
		$this->quiet();
		$record = $this->gateway([], $this->listed([...self::ADDRESSES, '0.0.0.0']));
		$this->assertContains("udp+tcp 0.0.0.0:{$this->port}", $this->served(), 'before: the live-added listener is served');

		// When the cron tick runs
		$this->krTick();

		// Then it is removed live, nothing is restarted, and the gateway no longer serves it
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame(["remove udp+tcp 0.0.0.0:{$this->port}"], self::verbs($record));
		$this->assertNotContains("udp+tcp 0.0.0.0:{$this->port}", $this->served());
	}

	public function testTheTickStillConfirmsAnAddressTheBoxCannotBind(): void
	{
		// Given a serving proxy whose latest start could not assign 192.0.2.1, which this box does not have
		$this->assertStringContainsString('assign requested address', self::bindError("192.0.2.1:{$this->port}"), 'before: this host does not have 192.0.2.1');
		$this->quiet();
		$record = $this->gatewayWithoutLan();
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
		$this->quiet();
		$record = $this->gateway([], $this->listed(['192.0.2.1', '[::1]']), array_fill_keys($this->listed(['127.0.0.1']), self::CANT));
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

	public function testWhileARestartIsPendingAMissingListenerTheBoxBindsNowIsTheReasonToRestartAndNothingIsSent(): void
	{
		// Given a restart pending, and a gateway that serves 192.0.2.1 and ::1 and refused 127.0.0.1 (which this box binds now)
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"), 'before: this host binds 127.0.0.1');
		$this->quiet(['marker' => 'the package changed its rc script']);
		$record = $this->gateway([], $this->listed(['192.0.2.1', '[::1]']), array_fill_keys($this->listed(['127.0.0.1']), self::CANT));

		// When the reconcile runs
		$why = pfb_dns_proxy_listeners_sync();

		// Then the address is the reason to restart the pair, and the gateway was only asked what it serves: no add, no remove
		$this->assertSame("the gateway could not bind 127.0.0.1:{$this->port} when it started, and that address can be bound now", $why);
		$this->assertSame(['list'], self::requests($record));
	}

	public function testATickRestartLeavesAPendingRestartToTheUpdatePassAndSendsNoFrame(): void
	{
		// Given a restart pending for the rc script, and a ready proxy whose start refused 127.0.0.1 (which this box binds)
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"), 'before: this host binds 127.0.0.1');
		$this->quiet(['marker' => 'the package changed its rc script']);
		$record = $this->gateway([], $this->listed(['192.0.2.1', '[::1]']), array_fill_keys($this->listed(['127.0.0.1']), self::CANT));

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
		// Given a restart pending and a gateway that serves an address the command does not name, besides every address of the command
		$this->quiet(['marker' => 'the package changed its rc script']);
		$record = $this->gateway([], $this->listed([...self::ADDRESSES, '0.0.0.0']));

		// When the cron tick runs
		$this->krTick();

		// Then nothing is removed or restarted: the pending restart's rc script may differ in more than addresses
		$this->assertSame([], self::frames($record));
		$this->assertSame([], $this->krProxyCalls());
		$this->assertSame('the package changed its rc script', $this->krMarker());
	}

	public function testATickNeverChangesTheListenersOfAProxyThatIsAliveButNotReady(): void
	{
		// Given a live proxy that never published its marker, whose gateway refused 127.0.0.1 (which this box binds); the
		// rollback its failed readiness leads to finds the config locked
		$this->quiet(['proxy' => 'lives']);
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$record = $this->gateway([], $this->listed(['192.0.2.1', '[::1]']), array_fill_keys($this->listed(['127.0.0.1']), self::CANT));
		$this->assertFalse(pfb_dns_proxy_ready(), 'before: the proxy is alive and not ready');
		$this->assertSame(["127.0.0.1:{$this->port}" => self::CANT], pfb_dns_proxy_listener_list()['refused']['udp+tcp'] ?? NULL, 'before: the gateway refused it');

		// When the cron tick runs
		$this->krTick();

		// Then the tick neither added the address nor restarted: a proxy that is not ready has no gateway of its own to judge
		$this->assertSame([], self::frames($record));
		$this->assertNotContains('restart_service pfb_dns_proxy', $this->krProxyCalls());
	}
}
