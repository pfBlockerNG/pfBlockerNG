<?php

declare(strict_types=1);

require_once __DIR__ . '/support/KeepRunningScenario.php';
require_once __DIR__ . '/support/LiveListenerStandIn.php';
require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3694 -- the running gateway's name-answer table follows the box without a restart. The rc script's command carries one
 * `--dns-name-answer 'LOCAL=ADDR[,ADDR]'` per address the gateway answers the DNS Name on; the update pass masks those arguments
 * (like the listen addresses, issue #3599), so a script that differs only in them is reconciled live: pfb_dns_proxy_listeners_sync()
 * sends the table parsed from the command to the gateway's control socket as one FF FF FF FB frame (pfb_dns_proxy_address_table()), a
 * 4-byte big-endian length and the lines `dns-name-answer LOCAL=ADDR[,ADDR]` joined by "\n", and the gateway answers `ok` or
 * `error: <reason>`. A gateway that does not take it is the reason to restart the pair.
 *
 * Name-answer rows are sent only while the command names a DNS Name (--dns-name). Independent listener ownership rows can be
 * sent without one. No table is sent while a restart is pending: the rc script may differ from the running gateway in more than
 * the table. The stand-in is a real Unix-socket process that records every frame before replying.
 */
#[CoversFunction('pfb_dns_proxy_address_table')]
#[CoversFunction('pfb_dns_proxy_listeners_sync')]
#[CoversFunction('pfb_dns_proxy_ensure_running')]
final class DnsProxyNameAnswerLiveTest extends TestCase
{
	use KeepRunningScenario;
	use LiveListenerStandIn;

	private const SETTINGS = 'installedpackages/pfblockerngdns/config/0/';
	private const NAME = 'fw.example.lan';
	private const TABLE = 'fffffffb';
	/** What a gateway older than the table verb answers it with: it reads the frame's head as a certificate length. */
	private const OLD_GATEWAY = 'error: a message of 4294967291 bytes is not between 1 and 65536';

	private array $savedGlobals = [];
	private int $port = 0;
	private string $socket = '';

	protected function setUp(): void
	{
		foreach (self::krGlobals() as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->krSeed(sys_get_temp_dir() . '/pfb_name_answers_' . getmypid() . '_' . bin2hex(random_bytes(4)));
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

	/** A ready proxy whose rc script names lan (192.0.2.1) and loopback at the free port, with the DNS Name set unless $name is ''. */
	private function ready(string $name = self::NAME, array $extra = []): void
	{
		config_set_path(self::SETTINGS . 'pfb_dns_name', $name);
		$this->krApply($extra + ['port' => (string) $this->port]);
	}

	/** @param list<string> $hosts as the gateway lists them: IPv6 bracketed */
	private function listed(array $hosts): array
	{
		return array_map(fn (string $host): string => "udp+tcp {$host}:{$this->port}", $hosts);
	}

	/** The stand-in gateway on the control socket, serving the three listeners of the quiet box unless told otherwise. */
	private function gateway(array $replies = [], ?array $hosts = NULL): string
	{
		return $this->standIn($this->socket, $replies, ['listening' => $this->listed($hosts ?? ['192.0.2.1', '127.0.0.1', '[::1]']), 'refused' => []]);
	}

	/** @return list<string> each frame the stand-in got after the list requests: "<head> <body>" */
	private static function sent(string $record): array
	{
		return array_map(static fn (array $frame): string => "{$frame['head']} {$frame['body']}", self::nameDdrFrames($record));
	}

	// -----------------------------------------------------------------------
	// the frame
	// -----------------------------------------------------------------------

	public function testTheTableIsOneFrameOfFbAndItsLinesJoinedByNewlines(): void
	{
		$record = $this->gateway();
		$lines = ['dns-name-answer 192.0.2.1=192.0.2.1', 'dns-name-answer 2001:db8::1=192.0.2.1,2001:db8::1'];

		$this->assertNull(pfb_dns_proxy_address_table($lines, $this->socket));

		$this->assertSame([self::TABLE . ' ' . implode("\n", $lines)], self::sent($record));
	}

	public function testTheStandInRecordsTheWholeOwnershipTableBeyondTheListenerBodyLimit(): void
	{
		$record = $this->gateway();
		$lines = [
			'listener-interface 192.0.2.1=' . base64_encode(str_repeat('LAN', 100)),
			'listener-interface 2001:db8::1=' . base64_encode('IPv6 LAN'),
		];
		$body = implode("\n", $lines);
		$this->assertGreaterThan(256, strlen($body), 'exercise the table beyond the listener-control body limit');

		$this->assertNull(pfb_dns_proxy_address_table($lines, $this->socket));

		$this->assertSame([['head' => self::TABLE, 'body' => $body, 'fds' => []]], self::frames($record));
	}

	public function testAnEmptyTableIsAFrameWithNoBody(): void
	{
		$record = $this->gateway();

		$this->assertNull(pfb_dns_proxy_address_table([], $this->socket));

		$this->assertSame([self::TABLE . ' '], self::sent($record), 'a body of length zero: the gateway empties its table');
	}

	public function testAGatewayThatRefusesTheTableOrHangsUpOrIsNotThereIsAWhy(): void
	{
		// Given the gateway takes it: nothing to say
		$this->gateway(['ok']);
		$this->assertNull(pfb_dns_proxy_address_table(['dns-name-answer 192.0.2.1=192.0.2.1'], $this->socket), 'before: ok');

		// When it answers an error, or an older gateway answers it as a bad length, the reason carries what it said
		foreach (['error: bad line 1', self::OLD_GATEWAY] as $reply) {
			$this->standInsStop();
			$this->gateway([$reply]);
			$why = pfb_dns_proxy_address_table(['dns-name-answer 192.0.2.1=192.0.2.1'], $this->socket);
			$this->assertIsString($why);
			$this->assertStringContainsString($reply, $why);
		}

		// And when it hangs up, or nothing listens, the reason says so
		$this->standInsStop();
		$this->gateway([NULL]);
		$this->assertIsString(pfb_dns_proxy_address_table(['dns-name-answer 192.0.2.1=192.0.2.1'], $this->socket), 'a hang-up');
		$this->standInsStop();
		$why = pfb_dns_proxy_address_table(['dns-name-answer 192.0.2.1=192.0.2.1'], "{$this->krDir}/nobody.sock");
		$this->assertIsString($why);
		$this->assertStringContainsString('nobody.sock', $why);
	}

	// -----------------------------------------------------------------------
	// the sync
	// -----------------------------------------------------------------------

	public function testTheSyncSendsTheTableTheCommandNamesAfterTheListenerChanges(): void
	{
		// Given a ready proxy whose command names the DNS Name and one answer, and a gateway that serves the three listeners
		$this->ready();
		$record = $this->gateway();
		$this->assertStringContainsString(" --dns-name '" . self::NAME . "'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the command carries the name');
		$this->assertStringContainsString(" --dns-name-answer '192.0.2.1=192.0.2.1'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the command carries the answer');
		$this->assertSame([], self::sent($record), 'before: the gateway has been sent nothing');

		// When the sync runs
		$why = pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list());

		// Then the table is the one frame sent
		$this->assertNull($why);
		$this->assertSame([self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1'], self::sent($record));
	}

	public function testTheSyncSendsEveryAnswerOfTheCommandInItsOrder(): void
	{
		// Given lan holds an IPv6 address too when the proxy starts
		$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1'];
		$this->ready();
		$record = $this->gateway([], ['192.0.2.1', '[2001:db8::1]', '127.0.0.1', '[::1]']);

		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));

		$this->assertSame([self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1,2001:db8::1' . "\n" . 'dns-name-answer 2001:db8::1=192.0.2.1,2001:db8::1'], self::sent($record));
	}

	public function testAGatewayThatDoesNotTakeTheTableIsTheReasonToRestartThePair(): void
	{
		// Given a ready proxy and a gateway older than the verb
		$this->ready();
		$record = $this->gateway([self::OLD_GATEWAY]);

		// When the sync runs
		$why = pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list());

		// Then the answer is the sync's reason to restart
		$this->assertIsString($why);
		$this->assertStringContainsString(self::OLD_GATEWAY, $why);
		$this->assertCount(1, self::sent($record), 'sent once');
	}

	public function testNothingIsSentWhileARestartIsPending(): void
	{
		// Given a ready proxy with a table to send: it is sent
		$this->ready();
		$record = $this->gateway();
		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));
		$this->assertCount(1, self::sent($record), 'before: the table goes');

		// When a restart is pending (the script may differ in more than the table)
		file_put_contents($GLOBALS['pfb']['dns_proxy_restart_pending'], "a package upgrade\n");
		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));

		// Then nothing more is sent
		$this->assertCount(1, self::sent($record));
	}

	public function testNoNameAnswersAreSentWhenTheCommandNamesNoDnsName(): void
	{
		// Given a ready proxy whose command names the DNS Name: the table is sent
		$this->ready();
		$record = $this->gateway();
		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));
		$this->assertCount(1, self::sent($record), 'before: the table goes');

		// When the name is gone, with DDR stored On (it means nothing without a name), and the script is written again
		config_set_path('installedpackages/pfblockerngdnssettings/config/0/pfb_dns_ddr', 'on');
		config_set_path(self::SETTINGS . 'pfb_dns_name', '');
		pfb_dns_proxy_service($this->krProxyDir);
		$this->assertStringNotContainsString('--dns-name', (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'the command names no DNS Name');
		$this->assertNull(pfb_dns_proxy_listeners_sync(pfb_dns_proxy_listener_list()));

		// Then name/DDR rows are absent, but the independent ownership snapshot still goes.
		$this->assertSame([self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1', self::TABLE . ' '], self::sent($record));
		$table = self::changeFrames($record)[1];
		$this->assertSame(self::TABLE, $table['head']);
		$this->assertSame([], $table['fds'], 'metadata carries no listener descriptors');
		$this->assertContains('listener-interface 192.0.2.1=', explode("\n", $table['body']), 'ownership is independent of the DNS Name');
	}

	// -----------------------------------------------------------------------
	// the update pass
	// -----------------------------------------------------------------------

	/** Plain DNS on the IP entry 192.0.2.1, so that the IPv6 address lan gains is no listener: only its answer changes. */
	private function readyThenLanGainsIpv6(): string
	{
		config_set_path(self::SETTINGS . 'pfb_dns_interface', '192.0.2.1');
		$this->ready(self::NAME, ['lan6' => '2001:db8::1']);
		return $this->gateway();
	}

	public function testAnAnswerOnlyChangeOfTheRcScriptIsMadeLiveAndRestartsNothing(): void
	{
		// Given a ready proxy that started with the answer 192.0.2.1=192.0.2.1, and a lan that has an IPv6 address by the time the pass runs
		$record = $this->readyThenLanGainsIpv6();
		$this->assertStringContainsString("--dns-name-answer '192.0.2.1=192.0.2.1' ", (string) file_get_contents(PFB_DNS_PROXY_RCFILE), 'before: the script the gateway runs has the IPv4 answer alone');

		// When the update pass runs
		$ready = $this->krEnsure();

		// Then the new table reached the gateway as one frame, nothing restarted, and the script is the new one
		$this->assertTrue($ready);
		$this->assertSame([], $this->krProxyCalls(), 'no restart');
		$this->assertSame([self::TABLE . ' dns-name-answer 192.0.2.1=192.0.2.1,2001:db8::1'], self::sent($record));
		$this->assertStringContainsString("--dns-name-answer '192.0.2.1=192.0.2.1,2001:db8::1'", (string) file_get_contents(PFB_DNS_PROXY_RCFILE));
	}

	public function testAChangeOfTheDnsNameItselfStillRestartsTheProxy(): void
	{
		// Given the same box, and the name changed by the time the pass runs: --dns-name is not masked
		$record = $this->readyThenLanGainsIpv6();
		config_set_path(self::SETTINGS . 'pfb_dns_name', 'fw2.example.lan');

		// When the update pass runs
		$this->krEnsure();

		// Then the pair is restarted, and the table is not pushed to a gateway that is about to be replaced
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
		$this->assertSame([], self::sent($record));
	}

	public function testAGatewayThatDoesNotTakeTheTableRestartsTheProxyOnce(): void
	{
		// Given a gateway older than the verb
		$this->readyThenLanGainsIpv6();
		$this->standInsStop();
		$record = $this->gateway([self::OLD_GATEWAY]);

		// When the update pass runs
		$this->krEnsure();

		// Then the table was offered once and the pair restarted once
		$this->assertCount(1, self::sent($record));
		$this->assertSame(['restart_service pfb_dns_proxy'], $this->krProxyCalls());
	}
}
