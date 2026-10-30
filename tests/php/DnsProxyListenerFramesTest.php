<?php

declare(strict_types=1);

require_once __DIR__ . '/support/LiveListenerStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3599 -- what PHP puts on the gateway's control socket to add and remove a listener (docs/specs/pfb-dns-live-listen-addresses.md,
 * D2), and what it binds to do it (D4.2). The stand-in gateway (support/ListenerControlServer.php) is a real process on a real Unix
 * socket: the bytes asserted are the bytes a socket carried, and each descriptor is judged the way the gateway judges it (its type,
 * whether it listens, the address it is bound to) from inside the process that received it. Intent pinned here:
 *   - an add is ONE frame (`FF FF FF FE`, a 4-byte big-endian length, `<kind> <host:port>`) whose descriptors are the kind's sockets
 *     in the order the gateway wants them: plain DNS the UDP socket then the listening TCP socket, DoT and DoH one listening TCP
 *     socket, DoQ one UDP socket, each bound to the address of the frame, for IPv4 and IPv6; a remove (`FF FF FF FD`) carries none;
 *   - the gateway's `ok` is NULL, anything else (an error, a hang-up, no socket, a PHP with no sockets extension) is a reason, and
 *     whatever happens the sockets this process bound are closed again, so that no descriptor stays behind;
 *   - a bind that cannot be made (the address is in use, or the host is no IP address a bind would not resolve) is a reason, and
 *     leaves nothing bound.
 */
#[CoversFunction('pfb_dns_proxy_listener_bind')]
#[CoversFunction('pfb_dns_proxy_listener_add')]
#[CoversFunction('pfb_dns_proxy_listener_remove')]
#[CoversFunction('pfb_dns_proxy_ctl_exchange')]
final class DnsProxyListenerFramesTest extends TestCase
{
	use LiveListenerStandIn;

	private string $dir = '';
	private string $socket = '';
	private string $log = '';
	private int $port = 0;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		$this->savedGlobals['pfb'] = [array_key_exists('pfb', $GLOBALS), $GLOBALS['pfb'] ?? NULL];
		$this->dir = sys_get_temp_dir() . '/pfb_listener_frames_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
		$this->socket = "{$this->dir}/ctl.sock";
		$this->log = "{$this->dir}/dns_proxy.log";
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], ['dns_proxy_ctl' => $this->socket]);
		$this->port = self::freePort();
	}

	protected function tearDown(): void
	{
		$this->standInsStop();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->dir);
	}

	/** @return array<string,array{string,string,list<array{string,bool}>}> kind, host, and each descriptor's [type, listening] in the order the gateway wants them */
	public static function kindsAndFamilies(): array
	{
		$rows = [];
		$sockets = ['udp+tcp' => [['dgram', FALSE], ['stream', TRUE]], 'dot' => [['stream', TRUE]], 'doh' => [['stream', TRUE]], 'doq' => [['dgram', FALSE]]];
		foreach ($sockets as $kind => $types) {
			foreach (['IPv4' => '127.0.0.1', 'IPv6' => '[::1]'] as $family => $host) {
				$rows["{$kind} on {$family}"] = [$kind, $host, $types];
			}
		}
		return $rows;
	}

	/** @return array<string,array{string,string}> kind and host of each row of kindsAndFamilies() */
	public static function kindsAndHosts(): array
	{
		return array_map(static fn (array $row): array => [$row[0], $row[1]], self::kindsAndFamilies());
	}

	/** @param list<array{string,bool}> $types */
	#[DataProvider('kindsAndFamilies')]
	public function testAnAddIsOneFrameCarryingTheKindsSocketsInTheOrderTheGatewayWants(string $kind, string $host, array $types): void
	{
		// Given a gateway that takes it, and an address this host binds
		$at = "{$host}:{$this->port}";
		$this->assertSame('', self::bindError($at), "before: this host binds {$at}");
		$record = $this->standIn($this->socket, $this->log);
		$sockets = pfb_dns_proxy_listener_bind($kind, $at, $why);
		$this->assertIsArray($sockets, (string) $why);

		// When the listener is added
		$failed = pfb_dns_proxy_listener_add($kind, $at, $sockets);

		// Then the gateway got one add frame for the kind and address, with exactly the kind's descriptors, each bound to that address
		$this->assertNull($failed);
		$frames = self::frames($record);
		$this->assertCount(1, $frames);
		$this->assertSame('fffffffe', $frames[0]['head']);
		$this->assertSame("{$kind} {$at}", $frames[0]['body']);
		$this->assertSame(
			array_map(static fn (array $type): array => ['type' => $type[0], 'name' => $at, 'listening' => $type[1]], $types),
			$frames[0]['fds']
		);
		$this->assertSame("listening {$kind} {$at}\n", (string) file_get_contents($this->log), 'the gateway logs what it took');
	}

	#[DataProvider('kindsAndHosts')]
	public function testARemoveIsOneFrameWithNoDescriptor(string $kind, string $host): void
	{
		// Given a gateway that takes it
		$at = "{$host}:{$this->port}";
		$record = $this->standIn($this->socket, $this->log);

		// When the listener is removed (with the control socket the globals name)
		$failed = pfb_dns_proxy_listener_remove($kind, $at);

		// Then the gateway got one remove frame for the kind and address, and no descriptor
		$this->assertNull($failed);
		$frames = self::frames($record);
		$this->assertCount(1, $frames);
		$this->assertSame('fffffffd', $frames[0]['head']);
		$this->assertSame("{$kind} {$at}", $frames[0]['body']);
		$this->assertSame([], $frames[0]['fds']);
		$this->assertSame("stopped listening {$kind} {$at}\n", (string) file_get_contents($this->log));
	}

	/** @return array<string,array{string|false|null,string}> what the gateway does (a reply, NULL = hangs up, FALSE = nobody listens) and what the reason says */
	public static function failures(): array
	{
		return [
			'an error reply' => ['error: not today', 'error: not today'],
			'an older gateway' => ['error: a message of 4294967294 bytes is not between 1 and 65536', 'a message of 4294967294 bytes'],
			'a hang-up' => [NULL, 'closed the connection with no reply'],
			'no control socket' => [FALSE, 'cannot connect'],
		];
	}

	#[DataProvider('failures')]
	public function testAnAddTheGatewayDoesNotTakeIsAReasonAndTheSocketsAreClosed(string|false|null $reply, string $reason): void
	{
		// Given a gateway that does not take it, and the sockets bound for it
		$at = "127.0.0.1:{$this->port}";
		if ($reply !== FALSE) {
			$this->standIn($this->socket, $this->log, [$reply]);
		}
		$sockets = pfb_dns_proxy_listener_bind('udp+tcp', $at);
		$this->assertIsArray($sockets);
		$this->assertSame([TRUE, TRUE], array_map('is_resource', $sockets), 'before: the sockets are open');

		// When the listener is added
		$failed = pfb_dns_proxy_listener_add('udp+tcp', $at, $sockets);

		// Then the reason names the listener and what went wrong, and every socket is closed
		$this->assertIsString($failed);
		$this->assertStringContainsString("udp+tcp {$at}", $failed);
		$this->assertStringContainsString($reason, $failed);
		$this->assertSame([FALSE, FALSE], array_map('is_resource', $sockets));
		$this->assertSame('', self::bindError($at), 'the address is free again');
		$this->assertFileDoesNotExist($this->log, 'a change the gateway did not take is not logged');
	}

	#[DataProvider('failures')]
	public function testARemoveTheGatewayDoesNotTakeIsAReason(string|false|null $reply, string $reason): void
	{
		// Given a gateway that does not take it
		if ($reply !== FALSE) {
			$this->standIn($this->socket, $this->log, [$reply]);
		}

		// When the listener is removed
		$failed = pfb_dns_proxy_listener_remove('dot', "127.0.0.1:{$this->port}", $this->socket);

		// Then the reason names the listener and what went wrong
		$this->assertIsString($failed);
		$this->assertStringContainsString("dot 127.0.0.1:{$this->port}", $failed);
		$this->assertStringContainsString($reason, $failed);
	}

	/** @return array<string,array{string|false|null}> the gateway's answer to an add: ok, or what the failures() rows do */
	public static function everyOutcome(): array
	{
		return ['ok' => ['ok'], 'an error reply' => ['error: no'], 'a hang-up' => [NULL], 'no control socket' => [FALSE]];
	}

	#[DataProvider('everyOutcome')]
	public function testAnAddLeavesNoDescriptorOpenInThisProcess(string|false|null $reply): void
	{
		// Given a gateway (or none), and one add already made, so that whatever a first call opens for good is open
		if ($reply !== FALSE) {
			$this->standIn($this->socket, $this->log, ['ok', $reply]);
		}
		$at = "127.0.0.1:{$this->port}";
		$this->assertTrue(is_dir('/proc/self/fd'), 'before: this host lists the descriptors of a process');
		$this->add('udp+tcp', $at);
		$before = self::openDescriptors();

		// When a second add is made, whatever the gateway answers
		$this->add('udp+tcp', $at);

		// Then the process holds exactly the descriptors it held before
		$this->assertSame($before, self::openDescriptors());
	}

	/** Bind the sockets of $kind at $at and add them. */
	private function add(string $kind, string $at): ?string
	{
		$sockets = pfb_dns_proxy_listener_bind($kind, $at, $why);
		$this->assertIsArray($sockets, (string) $why);
		return pfb_dns_proxy_listener_add($kind, $at, $sockets, $this->socket);
	}

	public function testWithNoSocketsExtensionNothingIsSentAndTheStreamsAreClosed(): void
	{
		// Given a gateway that would take it, the sockets bound for it, and a PHP that has no socket_sendmsg()
		$at = "127.0.0.1:{$this->port}";
		$record = $this->standIn($this->socket, $this->log);
		$sockets = pfb_dns_proxy_listener_bind('dot', $at);
		$this->assertIsArray($sockets);
		$reflection = new ReflectionFunction('pfb_dns_proxy_listener_add');
		$body = implode('', array_slice((array) file((string) $reflection->getFileName()), $reflection->getStartLine() - 1, $reflection->getEndLine() - $reflection->getStartLine() + 1));
		$namespace = 'PfbNoSockets' . bin2hex(random_bytes(6));
		eval("namespace {$namespace}; function function_exists(string \$name): bool { return \$name !== 'socket_sendmsg' && \\function_exists(\$name); }\n{$body}");

		// When the listener is added
		$failed = ($namespace . '\\pfb_dns_proxy_listener_add')('dot', $at, $sockets, $this->socket);

		// Then it is a reason that names the missing function, nothing was sent, and the streams are closed
		$this->assertIsString($failed);
		$this->assertStringContainsString('socket_sendmsg', $failed);
		$this->assertSame([], self::frames($record));
		$this->assertSame([FALSE], array_map('is_resource', $sockets));
	}

	// -----------------------------------------------------------------------
	// What a bind can refuse
	// -----------------------------------------------------------------------

	public function testAnAddressInUseIsAReasonAndNothingStaysBound(): void
	{
		// Given a TCP port something else holds (before: a bind of it fails as in use)
		$this->hold("127.0.0.1:{$this->port}");
		$this->assertStringContainsStringIgnoringCase('in use', self::bindError("127.0.0.1:{$this->port}"));

		// When the plain DNS pair is bound there
		$sockets = pfb_dns_proxy_listener_bind('udp+tcp', "127.0.0.1:{$this->port}", $why);

		// Then it is NULL with the reason the bind gave
		$this->assertNull($sockets);
		$this->assertStringContainsStringIgnoringCase('in use', (string) $why);
	}

	public function testAUdpBindThatFailsClosesTheTcpSocketItAlreadyBound(): void
	{
		// Given a UDP port something else holds exclusively, and a TCP port that is free
		$this->holdUdp('127.0.0.1', $this->port);
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"), 'before: the TCP port is free');

		// When the plain DNS pair is bound there: TCP first, then UDP
		$sockets = pfb_dns_proxy_listener_bind('udp+tcp', "127.0.0.1:{$this->port}", $why);

		// Then it is NULL with the UDP reason, and the TCP socket it bound is closed again
		$this->assertNull($sockets);
		$this->assertStringContainsStringIgnoringCase('in use', (string) $why);
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"), 'the TCP port is free again');
	}

	/** @return array<string,array{string}> hosts a bind would take (resolving them) and inet_pton() does not */
	public static function hostsThatAreNoIpAddress(): array
	{
		return ['a short IPv4 form' => ['127.1'], 'a name' => ['localhost'], 'nothing' => ['']];
	}

	#[DataProvider('hostsThatAreNoIpAddress')]
	public function testAHostThatIsNoIpAddressIsAReasonAndIsNeverBound(string $host): void
	{
		// Given a host that is no IP address (before: where a bind would take it, it would bind)
		if ($host !== '') {
			$this->assertSame('', self::bindError("{$host}:{$this->port}"), "before: this host binds {$host}");
		}

		// When the plain DNS pair is bound there
		$sockets = pfb_dns_proxy_listener_bind('udp+tcp', "{$host}:{$this->port}", $why);

		// Then it is NULL with a reason, and nothing was bound: the port is free
		$this->assertNull($sockets);
		$this->assertNotSame('', (string) $why);
		$this->assertSame('', self::bindError("127.0.0.1:{$this->port}"));
	}
}
