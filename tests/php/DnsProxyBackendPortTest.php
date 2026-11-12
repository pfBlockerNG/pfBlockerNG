<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- the loopback port pair Unbound's backend lives on (PROXYv2 on P, plain on P+1) is stored once, as the `proxy-protocol-port:` line of the
 * marked clause in the Resolver's Custom Options (default 5353), and read by one function; and the two questions the port move asks of the box's sockets, who
 * holds P or P+1 and which pair above is free, both read the one `sockstat` scan that tells whether Unbound owns the gateway's upstream
 * (pfb_dns_proxy_upstream_state()): there is one parser of that output, and the holder and the picker each make one scan.
 */
#[CoversFunction('pfb_dns_proxy_backend_port')]
#[CoversFunction('pfb_dns_proxy_backend_holder')]
#[CoversFunction('pfb_dns_proxy_backend_pick')]
#[CoversFunction('pfb_dns_proxy_listening_sockets')]
final class DnsProxyBackendPortTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private array $savedGlobals = [];
	private string $scanLog;
	private string $sockstatOriginal = '';

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_interface_ip'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_interface_ip'] = ['lo0' => '127.0.0.1'];
		$this->setUpUpstreamFixture();
		// The bootstrap's sockstat, made to log the arguments of each call: a scan is one call, and its port list is the contract
		$this->scanLog = $GLOBALS['pfb_test_sockstat_output'] . '.calls';
		@unlink($this->scanLog);
		$this->sockstatOriginal = (string) file_get_contents(PFB_DNS_PROXY_SOCKSTAT);
		$logged = str_replace("\ncat ", "\nprintf '%s\\n' \"\$*\" >> " . escapeshellarg($this->scanLog) . "\ncat ", $this->sockstatOriginal);
		$this->assertNotSame($this->sockstatOriginal, $logged, 'test bootstrap: the sockstat double has its cat line');
		file_put_contents(PFB_DNS_PROXY_SOCKSTAT, $logged);
	}

	protected function tearDown(): void
	{
		file_put_contents(PFB_DNS_PROXY_SOCKSTAT, $this->sockstatOriginal);
		@unlink($this->scanLog);
		$this->tearDownUpstreamFixture();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
	}

	/** One sockstat row: user, command, pid, fd, protocol, local address, foreign address. */
	private static function row(string $command, int $pid, string $protocol, string $local): string
	{
		return "root {$command} {$pid} 3 {$protocol} {$local} *:*";
	}

	private function sockets(string ...$rows): void
	{
		file_put_contents($GLOBALS['pfb_test_sockstat_output'],
			"USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n" . implode('', array_map(static fn (string $row): string => "{$row}\n", $rows)));
	}

	/** @return list<string> the arguments of every sockstat call so far */
	private function scans(): array
	{
		return is_file($this->scanLog) ? (file($this->scanLog, FILE_IGNORE_NEW_LINES) ?: []) : [];
	}

	// -----------------------------------------------------------------------
	// The reader
	// -----------------------------------------------------------------------

	/** The Resolver's Custom Options as a move leaves them: the admin's line, then our marked clause naming the pair (`proxy-protocol-port:` is the only stored P). */
	private function clauseFor(string $port, ?string $plain = NULL): string
	{
		$plain ??= (string) ((int) $port + 1);
		return "do-ip6: no\nserver:\n# pfBlockerNG DNS proxy\nport: {$plain}\ninterface: 127.0.0.1@{$port}\ninterface: ::1@{$port}\n"
			. "proxy-protocol-port: {$port}\n# end pfBlockerNG DNS proxy";
	}

	/** Unbound's backend pair is $port/$port+1 as the clause in Custom Options says. */
	private function backendPortIs(string $port): void
	{
		config_set_path('unbound/custom_options', base64_encode($this->clauseFor($port)));
	}

	public function testThePortIsNoRegisteredKeyBecauseTheClauseInTheResolverIsItsOnlyStoredSource(): void
	{
		// pfSense's Resolver sync copies Custom Options to a secondary, so a per-node key would disagree with the clause the secondary received
		$this->assertArrayNotHasKey('dns/pfb_dns_unbound_port', pfb_cfg_registry());
		$this->backendPortIs('5400');
		$this->assertSame('5400', pfb_dns_proxy_backend_port(), 'the clause alone names it');
	}

	/** @return array<string,array{?string,string}> the `proxy-protocol-port:` value the clause carries (NULL = no clause) and what the reader gives */
	public static function storedPorts(): array
	{
		return [
			'absent' => [NULL, '5353'],
			'a valid port' => ['5400', '5400'],
			'the lowest valid port' => ['1025', '1025'],
			'the highest valid port' => ['65534', '65534'],
			'below the range' => ['1024', '5353'],
			'above the range: P+1 would not be a port' => ['65535', '5353'],
			'far above' => ['70000', '5353'],
			'zero' => ['0', '5353'],
			'empty' => ['', '5353'],
			'not a number' => ['abc', '5353'],
			'a fraction' => ['5353.5', '5353'],
			'a sign' => ['+5400', '5353'],
			'a leading zero' => ['05400', '5353'],
			'extra spaces after the colon' => [' 5400', '5400'],
		];
	}

	#[DataProvider('storedPorts')]
	public function testTheReaderGivesTheClausesPortInRangeAndTheDefaultOtherwise(?string $stored, string $expected): void
	{
		if ($stored !== NULL) {
			config_set_path('unbound/custom_options', base64_encode($this->clauseFor($stored, '5354')));
		}

		$this->assertSame($expected, pfb_dns_proxy_backend_port());
	}

	/** @return array<string,array{string}> Custom Options that carry no clause of ours naming a port */
	public static function textsWithNoClause(): array
	{
		return [
			'an admin line outside our block' => ["server:\nproxy-protocol-port: 5400"],
			'a start marker with no end marker' => ["server:\n# pfBlockerNG DNS proxy\nproxy-protocol-port: 5400"],
			'a clause with no proxy-protocol-port line' => ["server:\n# pfBlockerNG DNS proxy\nport: 5354\n# end pfBlockerNG DNS proxy"],
			'a commented line inside the block' => ["server:\n# pfBlockerNG DNS proxy\n# proxy-protocol-port: 5400\n# end pfBlockerNG DNS proxy"],
			'a longer key inside the block' => ["server:\n# pfBlockerNG DNS proxy\nx-proxy-protocol-port: 5400\n# end pfBlockerNG DNS proxy"],
		];
	}

	#[DataProvider('textsWithNoClause')]
	public function testTheReaderIgnoresWhatIsNotOurClauseNamingAPort(string $custom): void
	{
		config_set_path('unbound/custom_options', base64_encode($custom));

		$this->assertSame('5353', pfb_dns_proxy_backend_port());
	}

	public function testTheReaderReadsOnlyOurBlockEvenWhenTheAdminHasTheSameLineBeforeIt(): void
	{
		config_set_path('unbound/custom_options', base64_encode("server:\nproxy-protocol-port: 5999\n" . $this->clauseFor('5400')));

		$this->assertSame('5400', pfb_dns_proxy_backend_port());
	}

	// -----------------------------------------------------------------------
	// The holder: one scan of P and P+1
	// -----------------------------------------------------------------------

	/** @return array<string,array{list<string>,?string}> the sockets sockstat lists, and the holder text (NULL = none), with Unbound as pid 5151 and the pair on 5353/5354 */
	public static function socketRows(): array
	{
		return [
			'no socket' => [[], NULL],
			'a TCP listener on P' => [[self::row('nc', 6161, 'tcp4', '127.0.0.1:5353')], 'nc (pid 6161) on 127.0.0.1:5353'],
			'a UDP socket on P' => [[self::row('dnsmasq', 777, 'udp4', '127.0.0.1:5353')], 'dnsmasq (pid 777) on 127.0.0.1:5353'],
			'a TCP listener on P+1' => [[self::row('nc', 6161, 'tcp4', '127.0.0.1:5354')], 'nc (pid 6161) on 127.0.0.1:5354'],
			'a UDP socket on P+1' => [[self::row('nc', 6161, 'udp4', '127.0.0.1:5354')], 'nc (pid 6161) on 127.0.0.1:5354'],
			'a wildcard address' => [[self::row('nc', 6161, 'tcp4', '*:5353')], 'nc (pid 6161) on *:5353'],
			'an IPv6 wildcard' => [[self::row('nc', 6161, 'tcp6', '*:5354')], 'nc (pid 6161) on *:5354'],
			'IPv6 loopback' => [[self::row('nc', 6161, 'tcp6', '[::1]:5353')], 'nc (pid 6161) on [::1]:5353'],
			'IPv6 loopback as sockstat -w prints it' => [[self::row('nc', 6161, 'udp6', '::1:5353')], 'nc (pid 6161) on [::1]:5353'],
			'Unbound itself on both ports' => [[
				self::row('unbound', 5151, 'tcp4', '127.0.0.1:5353'), self::row('unbound', 5151, 'udp4', '127.0.0.1:5353'),
				self::row('unbound', 5151, 'tcp4', '127.0.0.1:5354'), self::row('unbound', 5151, 'udp4', '127.0.0.1:5354'),
			], NULL],
			'Unbound with another pid than the live one' => [[self::row('unbound', 9999, 'tcp4', '127.0.0.1:5353')], 'unbound (pid 9999) on 127.0.0.1:5353'],
			'another command with Unbound\'s pid' => [[self::row('nc', 5151, 'tcp4', '127.0.0.1:5353')], 'nc (pid 5151) on 127.0.0.1:5353'],
			'a LAN address does not meet our loopback sockets' => [[self::row('nc', 6161, 'tcp4', '192.0.2.1:5353')], NULL],
			'another loopback address does not either' => [[self::row('nc', 6161, 'tcp4', '127.0.0.2:5353')], NULL],
			'another port' => [[self::row('nc', 6161, 'tcp4', '127.0.0.1:5355')], NULL],
			'Unbound owns P and a stranger holds P+1' => [[
				self::row('unbound', 5151, 'tcp4', '127.0.0.1:5353'), self::row('nc', 6161, 'udp4', '127.0.0.1:5354'),
			], 'nc (pid 6161) on 127.0.0.1:5354'],
			'the first holder is named' => [[
				self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'), self::row('dnsmasq', 777, 'udp4', '127.0.0.1:5354'),
			], 'nc (pid 6161) on 127.0.0.1:5353'],
		];
	}

	/** @param list<string> $rows */
	#[DataProvider('socketRows')]
	public function testTheHolderIsTheProcessOnTheBackendPortsThatIsNotTheLiveUnbound(array $rows, ?string $expected): void
	{
		$this->sockets(...$rows);

		$this->assertSame($expected, pfb_dns_proxy_backend_holder());
		$this->assertSame(['-46lw -p 5353,5354'], $this->scans(), 'one scan, of both ports');
	}

	public function testTheHolderFollowsThePortTheClauseNames(): void
	{
		$this->backendPortIs('5400');
		$this->sockets(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'), self::row('nc', 6162, 'tcp4', '127.0.0.1:5401'));

		$this->assertSame('nc (pid 6162) on 127.0.0.1:5401', pfb_dns_proxy_backend_holder(), '5353 is nobody\'s now; 5401 is the plain port');
		$this->assertSame(['-46lw -p 5400,5401'], $this->scans());
	}

	public function testWithNoValidUnboundPidfileAnUnboundNamedListenerIsNobodysHolderButAStrangerStillIs(): void
	{
		// Given Unbound is down or restarting: its pidfile names no live process, and sockets named unbound sit on the pair
		$this->seedUnbound(alive: FALSE);
		$this->sockets(self::row('unbound', 5151, 'tcp4', '127.0.0.1:5353'));

		$this->assertNull(pfb_dns_proxy_backend_holder(), 'the restart race: the same "unknown" the upstream state gives, never a stranger');

		unlink($this->unboundPidfile());
		$this->assertNull(pfb_dns_proxy_backend_holder(), 'and so with no pidfile at all');

		// ... while a process of any other name is a holder whatever the pidfile says
		$this->sockets(self::row('unbound', 5151, 'tcp4', '127.0.0.1:5353'), self::row('nc', 6161, 'udp4', '127.0.0.1:5354'));
		$this->assertSame('nc (pid 6161) on 127.0.0.1:5354', pfb_dns_proxy_backend_holder());

		// ... and with a valid pidfile an unbound of another pid is one too (a second Unbound that took the port)
		$this->seedUnbound(pid: '5151');
		$this->sockets(self::row('unbound', 9999, 'tcp4', '127.0.0.1:5353'));
		$this->assertSame('unbound (pid 9999) on 127.0.0.1:5353', pfb_dns_proxy_backend_holder());
	}

	public function testAScanThatFailsNamesNoHolder(): void
	{
		$this->sockets(self::row('nc', 6161, 'tcp4', '127.0.0.1:5353'));
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");

		$this->assertNull(pfb_dns_proxy_backend_holder(), 'no evidence is no holder');
	}

	public function testMalformedRowsNameNoHolder(): void
	{
		$this->sockets('root nc 6161', 'root nc notapid 3 tcp4 127.0.0.1:5353 *:*', 'root nc 0 3 tcp4 127.0.0.1:5353 *:*',
			'root nc 6161 3 sctp4 127.0.0.1:5353 *:*', 'root nc 6161 3 tcp4 not-an-address:5353 *:*', 'root nc 6161 3 tcp4 127.0.0.1:70000 *:*');

		$this->assertNull(pfb_dns_proxy_backend_holder());
	}

	// -----------------------------------------------------------------------
	// The picker: one scan, the lowest free pair above P
	// -----------------------------------------------------------------------

	public function testTheLowestPairAbovePIsPickedWhenNothingIsTaken(): void
	{
		$this->sockets();

		$this->assertSame('5355', pfb_dns_proxy_backend_pick(), 'P+2: the new pair never overlaps the old one');
		$this->assertSame(['-46lw -p 5355-5419'], $this->scans(), 'one scan of the 64 pairs the search may pick from');
	}

	/** @return array<string,array{list<string>,string}> the sockets sockstat lists in the search range, and the lowest free pair's PROXYv2 port */
	public static function takenPairs(): array
	{
		return [
			'the first pair\'s PROXYv2 port' => [[self::row('nc', 6161, 'tcp4', '127.0.0.1:5355')], '5356'],
			'the first pair\'s plain port, which is also where the next pair starts' => [[self::row('nc', 6161, 'udp4', '127.0.0.1:5356')], '5357'],
			'any address counts, a LAN one too' => [[self::row('nc', 6161, 'tcp4', '192.0.2.1:5355')], '5356'],
			'IPv6' => [[self::row('nc', 6161, 'tcp6', '*:5355')], '5356'],
			'a later pair only' => [[self::row('nc', 6161, 'tcp4', '127.0.0.1:5357')], '5355'],
			'two stray sockets' => [[self::row('nc', 6161, 'tcp4', '127.0.0.1:5355'), self::row('nc', 6162, 'udp4', '127.0.0.1:5357')], '5358'],
			'Unbound\'s own sockets count: the live pair is not a free one' => [[self::row('unbound', 5151, 'tcp4', '127.0.0.1:5355')], '5356'],
		];
	}

	/** @param list<string> $rows */
	#[DataProvider('takenPairs')]
	public function testPairsWithASocketOnEitherPortAreSkipped(array $rows, string $expected): void
	{
		$this->sockets(...$rows);

		$this->assertSame($expected, pfb_dns_proxy_backend_pick());
	}

	public function testThePickerSkipsThePairsTheListenPortTakes(): void
	{
		$this->sockets();

		config_set_path('unbound/port', '5355');
		$this->assertSame('5356', pfb_dns_proxy_backend_pick(), 'P\' = the Listen Port is out');

		config_set_path('unbound/port', '5356');
		$this->assertSame('5357', pfb_dns_proxy_backend_pick(), 'P\'+1 = the Listen Port is out, and so is the pair that starts on it');
	}

	/** @return array<string,array{string,string}> the DoT/DoH/DoQ setting, its port, and the pair the picker takes with that port reserved */
	public static function reservedTransportPorts(): array
	{
		return [
			'DoT' => ['pfb_dns_dot_port', '5357'],
			'DoH' => ['pfb_dns_doh_port', '5357'],
			'DoQ' => ['pfb_dns_doq_port', '5357'],
			'the DoT IPv6 port' => ['pfb_dns_dot_port6', '5357'],
			'the DoH IPv6 port' => ['pfb_dns_doh_port6', '5357'],
			'the DoQ IPv6 port' => ['pfb_dns_doq_port6', '5357'],
		];
	}

	#[DataProvider('reservedTransportPorts')]
	public function testThePickerSkipsTheConfiguredEncryptedTransportPortsWhateverTheToggle(string $setting, string $expected): void
	{
		// Given a transport configured on 5356, whether or not it is on: its pair would be taken the moment it is turned on
		$this->sockets();
		PfbConfig::writeSystem(pfb_dns_config_key($setting), '5356');

		$this->assertSame($expected, pfb_dns_proxy_backend_pick(), '5355 would put the plain port on 5356, and 5356 is the transport\'s');
	}

	public function testThePickerFindsNoPairWhenEveryOneInTheSearchIsTaken(): void
	{
		// Given a socket on every port the search may pick from: 5355..5419
		$this->sockets(...array_map(static fn (int $port): string => self::row('nc', 6000 + $port % 1000, 'tcp4', "127.0.0.1:{$port}"), range(5355, 5419)));

		$scanned = NULL;
		$this->assertNull(pfb_dns_proxy_backend_pick($scanned));
		$this->assertTrue($scanned, 'the sockets were seen: there really is no free pair');
	}

	public function testThePickerSearchesSixtyFourPairsAndNoMore(): void
	{
		// Given 5355..5417 taken: the 64th pair, 5418/5419, is free; and then one port beyond it
		$this->sockets(...array_map(static fn (int $port): string => self::row('nc', 6000 + $port % 1000, 'tcp4', "127.0.0.1:{$port}"), range(5355, 5417)));
		$this->assertSame('5418', pfb_dns_proxy_backend_pick(), 'the 64th pair is the last one searched');

		$this->sockets(...array_map(static fn (int $port): string => self::row('nc', 6000 + $port % 1000, 'tcp4', "127.0.0.1:{$port}"), range(5355, 5418)));
		$this->assertNull(pfb_dns_proxy_backend_pick(), 'a 65th is not searched');
	}

	public function testThePickerStaysBelowTheTopPort(): void
	{
		$this->backendPortIs('65530');
		$this->sockets();
		$this->assertSame('65532', pfb_dns_proxy_backend_pick());
		$this->assertSame(['-46lw -p 65532-65535'], $this->scans(), 'the scan ends at 65535');

		$this->sockets(self::row('nc', 6161, 'tcp4', '127.0.0.1:65533'));
		$this->assertSame('65534', pfb_dns_proxy_backend_pick(), '65534/65535 is the last pair there is');

		$this->sockets(self::row('nc', 6161, 'tcp4', '127.0.0.1:65533'), self::row('nc', 6162, 'tcp4', '127.0.0.1:65535'));
		$this->assertNull(pfb_dns_proxy_backend_pick(), 'there is no pair above it');
	}

	public function testAScanThatFailsPicksNothing(): void
	{
		$this->sockets();
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "1\n");

		$scanned = NULL;
		$this->assertNull(pfb_dns_proxy_backend_pick($scanned), 'with no sight of the sockets no pair is known free');
		$this->assertFalse($scanned, 'and the caller can tell that from a search that found none: it must not stop DNS for a scan that failed');
	}

	// -----------------------------------------------------------------------
	// One parser
	// -----------------------------------------------------------------------

	public function testOnlyOneFunctionRunsSockstat(): void
	{
		$source = (string) file_get_contents(self::INC);

		$this->assertSame(1, substr_count($source, 'escapeshellarg(PFB_DNS_PROXY_SOCKSTAT)'),
			'the upstream state, the holder and the picker all read pfb_dns_proxy_listening_sockets(): a second exec is a second parser');
	}
}
