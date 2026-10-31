<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ControlSocketStandIn.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3625 -- root asks the RUNNING pfB-DNS gateway which listeners it serves, on its control socket (go/pfb_dns_gateway, ctl.go),
 * instead of reading its log. The wire is the 4 bytes FF FF FF FC and nothing after; the gateway answers lines `listening <kind>
 * <host:port>` and `refused <kind> <host:port> <reason>`, then a final `ok` line, or one `error: <reason>` line. The stand-in gateway
 * is support/ControlSocketServer.php, a real Unix socket in a real process, on a virtual clock, so the bytes asserted are the bytes a
 * socket carried and no test waits. Intent pinned here:
 *   - the request is exactly those 4 bytes; the answer is an exact map, by kind and then by address, of what the gateway serves and of
 *     what it refused (with its reason), and a gateway that serves nothing is an empty list, which is not an unknown one;
 *   - a reply that arrives in pieces, or that has `ok` inside a reason, is read as the gateway wrote it;
 *   - whatever is not a whole, well-formed list is UNKNOWN (NULL), never a partial list: no socket, no answer in time, an older
 *     gateway's error, a hang-up or the 64 KiB cap before the final `ok`, and any line that is not exactly one of the two forms
 *     (spacing, control bytes, an address that is not the canonical `host:port` the gateway prints, an unknown kind, an empty reason,
 *     `ok` or `error:` anywhere but last).
 */
#[CoversFunction('pfb_dns_proxy_listener_list')]
#[CoversFunction('pfb_dns_proxy_ctl_exchange')]
final class DnsProxyListenerListTest extends TestCase
{
	use ControlSocketStandIn;

	private const TIMEOUT = 0.3;
	private const CAP = 65536;
	private const LINES = 1800;

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		$this->savedGlobals['pfb'] = [array_key_exists('pfb', $GLOBALS), $GLOBALS['pfb'] ?? NULL];
		$this->dir = sys_get_temp_dir() . '/pfb_dns_list_' . bin2hex(random_bytes(5));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
		$this->socket = "{$this->dir}/ctl.sock";
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], ['dns_proxy_ctl' => $this->socket]);
	}

	protected function tearDown(): void
	{
		$this->finish();
		$this->clocks = [];
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

	/**
	 * The listener list as it comes out when the gateway writes $script (see onVirtualClock()), on the virtual clock.
	 *
	 * @param list<array{float,?string}> $script
	 * @return array{0: ?array, 1: float} the list or NULL, and the virtual seconds it took
	 */
	private function askedWhen(array $script, float $timeout = self::TIMEOUT): array
	{
		$this->listen();
		[$namespace, $clock] = $this->onVirtualClock(['pfb_dns_proxy_listener_list', 'pfb_dns_proxy_ctl_exchange'], $script);

		return [($namespace . '\\pfb_dns_proxy_listener_list')($this->socket, $timeout), $clock->now()];
	}

	/** The listener list when the gateway writes $reply in one go. */
	private function listed(string $reply): ?array
	{
		return $this->askedWhen([[0.0, $reply]])[0];
	}

	/** $count listening lines for distinct ports (1000 up), each 33 bytes while the ports have four digits: a listener is named once. */
	private static function listeningLines(int $count): string
	{
		$lines = '';
		for ($port = 1000; $port < 1000 + $count; $port++) {
			$lines .= "listening udp+tcp 127.0.0.1:{$port}\n";
		}

		return $lines;
	}

	/** The length of the one refused line's reason that makes replyOfLength($length) exactly $length bytes. */
	private static function reasonLengthFor(int $length): int
	{
		return $length - strlen(self::listeningLines(self::LINES)) - strlen("ok\n") - strlen("refused dot 192.0.2.1:853 \n");
	}

	/** A valid reply of exactly $length bytes: listening lines, then one refused line whose reason takes up the slack, then `ok`. */
	private static function replyOfLength(int $length): string
	{
		return self::listeningLines(self::LINES) . 'refused dot 192.0.2.1:853 ' . str_repeat('r', self::reasonLengthFor($length)) . "\nok\n";
	}

	public function testTheRequestIsTheFourBytesFFFFFFFCOnTheControlSocketTheGlobalsName(): void
	{
		// Given a gateway that answers an empty list
		$record = $this->listen();
		[$namespace] = $this->onVirtualClock(['pfb_dns_proxy_listener_list', 'pfb_dns_proxy_ctl_exchange'], [[0.0, "ok\n"]]);

		// When the list is asked for with no socket named
		$list = ($namespace . '\\pfb_dns_proxy_listener_list')();
		$this->finish();

		// Then the gateway received exactly the verb, nothing after it, and the answer was read
		$this->assertSame("\xFF\xFF\xFF\xFC", (string) file_get_contents($record), 'the request is the 4 bytes FF FF FF FC and nothing else');
		$this->assertSame(['listening' => [], 'refused' => []], $list);
	}

	public function testEveryKindOnIPv4AndIPv6IsListedByKindThenAddressWithTheOutcomeOfEach(): void
	{
		// Given a gateway that serves every kind on IPv4 and IPv6, and refused some, one on an address another kind serves
		$reply = implode("\n", [
			'listening udp+tcp 127.0.0.1:53',
			'listening udp+tcp [::1]:53',
			'listening dot 192.0.2.1:853',
			'listening dot [2001:db8::1]:853',
			'listening doh 192.0.2.1:443',
			'listening doh [2001:db8::1]:443',
			'listening doq 127.0.0.1:853',
			'listening doq [::1]:853',
			'refused udp+tcp 192.0.2.2:53 bind: cannot assign requested address',
			'refused dot 192.0.2.2:853 bind: permission denied',
			'refused doh [2001:db8::2]:443 bind: address already in use',
			'refused doq 192.0.2.1:853 bind: address already in use',
			'ok',
		]) . "\n";

		// When the list is asked for
		$list = $this->listed($reply);

		// Then each outcome is under its kind and its address, and 192.0.2.1:853 is both served (DoT) and refused (DoQ)
		$this->assertSame([
			'listening' => [
				'udp+tcp' => ['127.0.0.1:53' => TRUE, '[::1]:53' => TRUE],
				'dot' => ['192.0.2.1:853' => TRUE, '[2001:db8::1]:853' => TRUE],
				'doh' => ['192.0.2.1:443' => TRUE, '[2001:db8::1]:443' => TRUE],
				'doq' => ['127.0.0.1:853' => TRUE, '[::1]:853' => TRUE],
			],
			'refused' => [
				'udp+tcp' => ['192.0.2.2:53' => 'bind: cannot assign requested address'],
				'dot' => ['192.0.2.2:853' => 'bind: permission denied'],
				'doh' => ['[2001:db8::2]:443' => 'bind: address already in use'],
				'doq' => ['192.0.2.1:853' => 'bind: address already in use'],
			],
		], $list);
	}

	public function testAGatewayThatServesNothingIsAnEmptyListNotAnUnknownOne(): void
	{
		// Given a gateway that serves no listener at all
		// When the list is asked for
		$list = $this->listed("ok\n");

		// Then the list is empty, which is a known answer, not an unknown one
		$this->assertSame(['listening' => [], 'refused' => []], $list);
	}

	public function testOkInsideAReasonIsTheReasonNotTheEndOfTheReply(): void
	{
		// Given a refusal whose reason says ok twice
		$list = $this->listed("refused dot 192.0.2.1:853 bind: ok ok\nok\n");

		// Then the reason is kept whole, and the reply ends at the last line
		$this->assertSame(['listening' => [], 'refused' => ['dot' => ['192.0.2.1:853' => 'bind: ok ok']]], $list);
	}

	public function testAReplyThatArrivesOneByteAtATimeWithinTheTimeoutIsListedWhole(): void
	{
		// Given a reply released byte by byte, a virtual millisecond apart, all within the timeout
		$reply = "listening udp+tcp 127.0.0.1:53\nrefused dot [2001:db8::1]:853 bind: ok\nok\n";
		$script = array_map(static fn (string $byte): array => [0.001, $byte], str_split($reply));

		// When the list is asked for
		[$list] = $this->askedWhen($script, 3.0);

		// Then it is read as if it came whole: no piece, not even a lone "o" or "ok", ended it early
		$this->assertSame(['listening' => ['udp+tcp' => ['127.0.0.1:53' => TRUE]], 'refused' => ['dot' => ['[2001:db8::1]:853' => 'bind: ok']]], $list);
	}

	public function testAReplyOfExactlyTheCapIsReadWhole(): void
	{
		// Given a valid reply of exactly 64 KiB
		$reply = self::replyOfLength(self::CAP);
		$this->assertSame(self::CAP, strlen($reply), 'before: the reply is exactly the cap');

		// When the list is asked for
		$list = $this->listed($reply);

		// Then it is listed, the long reason included
		$this->assertIsArray($list, 'a reply that ends at the cap is read whole');
		$this->assertCount(self::LINES, $list['listening']['udp+tcp']);
		$this->assertTrue($list['listening']['udp+tcp']['127.0.0.1:1000'] ?? NULL, 'the first listener is listed');
		$this->assertSame(self::reasonLengthFor(self::CAP), strlen($list['refused']['dot']['192.0.2.1:853']), 'the refusal reason is whole');
	}

	public function testTheLastByteOfAReplyOfExactlyTheCapArrivingOnItsOwnIsReadWhole(): void
	{
		// Given a valid reply of exactly 64 KiB whose final newline arrives after all the rest
		$reply = self::replyOfLength(self::CAP);

		// When the list is asked for
		[$list] = $this->askedWhen([[0.0, substr($reply, 0, -1)], [0.001, "\n"]]);

		// Then the byte that ends it at the cap is read: the cap is the count of bytes that may be read, not one fewer
		$this->assertIsArray($list, 'the last byte of a reply of exactly the cap is read');
	}

	public function testOneAddressListeningUnderOneKindAndRefusedUnderAnotherIsListedExactly(): void
	{
		// Given a gateway that serves DoT on an address and refused DoQ on the same address: two listeners, not one named twice
		$list = $this->listed("listening dot 192.0.2.1:853\nrefused doq 192.0.2.1:853 bind: x\nok\n");

		// Then both outcomes are listed, each under its own kind
		$this->assertSame(['listening' => ['dot' => ['192.0.2.1:853' => TRUE]], 'refused' => ['doq' => ['192.0.2.1:853' => 'bind: x']]], $list);
	}

	public function testNoControlSocketIsUnknown(): void
	{
		// Given nobody listens on the socket
		// When the list is asked for
		$list = pfb_dns_proxy_listener_list("{$this->dir}/nobody.sock", self::TIMEOUT);

		// Then it is unknown
		$this->assertNull($list);
	}

	public function testAGatewayThatNeverAnswersIsUnknownAtExactlyTheTimeout(): void
	{
		// Given a gateway that never writes
		[$list, $took] = $this->askedWhen([]);

		// Then the list is unknown, given up on after exactly the timeout (virtual seconds)
		$this->assertNull($list, 'no answer is an unknown list');
		$this->assertEqualsWithDelta(self::TIMEOUT, $took, 1e-9, 'given up on after exactly the timeout');
	}

	/** @return array<string,array{list<array{float,?string}>}> what the gateway writes, and in what pieces, instead of a whole list */
	public static function answersThatAreNotAWholeList(): array
	{
		return [
			'an older gateway answers the verb as a bad message length' => [[[0.0, "error: a message of 4294967292 bytes is not between 1 and 65536\n"]]],
			'lines with no final ok, then a hang-up' => [[[0.0, "listening udp+tcp 127.0.0.1:53\n"], [0.0, NULL]]],
			'lines with no final ok, then silence' => [[[0.0, "listening udp+tcp 127.0.0.1:53\n"]]],
			'more than 64 KiB of listening lines with no ok by the cap' => [[[0.0, self::listeningLines(2200)]]],
			'a valid reply one byte over the cap' => [[[0.0, self::replyOfLength(self::CAP + 1)]]],
			'the final ok has no newline, then silence' => [[[0.0, "listening udp+tcp 127.0.0.1:53\nok"]]],
			'the final ok has no newline, then a hang-up' => [[[0.0, "listening udp+tcp 127.0.0.1:53\nok"], [0.0, NULL]]],
		];
	}

	/** @param list<array{float,?string}> $script */
	#[DataProvider('answersThatAreNotAWholeList')]
	public function testAnAnswerThatIsNotAWholeListIsUnknown(array $script): void
	{
		// Given a gateway that answers as the row says
		// When the list is asked for
		[$list] = $this->askedWhen($script);

		// Then it is unknown, not a partial list
		$this->assertNull($list, 'expected an unknown list (NULL), got ' . var_export($list, TRUE));
	}

	/** @return array<string,array{string}> a whole reply (what the gateway writes in one go) that breaks the format on one line */
	public static function repliesThatBreakTheFormat(): array
	{
		return [
			'an unknown line verb' => ["bound udp+tcp 127.0.0.1:53\nok\n"],
			'two spaces after the verb' => ["listening  udp+tcp 127.0.0.1:53\nok\n"],
			'a trailing space on a listening line' => ["listening udp+tcp 127.0.0.1:53 \nok\n"],
			'a field after a listening line' => ["listening udp+tcp 127.0.0.1:53 extra\nok\n"],
			'a tab between the fields' => ["listening\tudp+tcp 127.0.0.1:53\nok\n"],
			'a tab inside a reason' => ["refused dot 192.0.2.1:853 bind:\tx\nok\n"],
			'a DEL byte inside a reason' => ["refused dot 192.0.2.1:853 bind: \x7Fx\nok\n"],
			'a CR inside a reason' => ["refused dot 192.0.2.1:853 bind: x\ry\nok\n"],
			'a CR before the LF of a line' => ["listening udp+tcp 127.0.0.1:53\r\nok\n"],
			'a CR before the LF of the final ok' => ["listening udp+tcp 127.0.0.1:53\nok\r\n"],
			'text after the final ok' => ["listening udp+tcp 127.0.0.1:53\nok now\n"],
			'a reason that starts with a space' => ["refused dot 192.0.2.1:853  bind: x\nok\n"],
			'a name for the host' => ["listening udp+tcp localhost:53\nok\n"],
			'no port' => ["listening udp+tcp 127.0.0.1\nok\n"],
			'a port above 65535' => ["listening udp+tcp 127.0.0.1:99999\nok\n"],
			'a port with a leading zero' => ["listening udp+tcp 127.0.0.1:053\nok\n"],
			'a negative port' => ["listening udp+tcp 127.0.0.1:-1\nok\n"],
			'an IPv4 address in brackets' => ["listening udp+tcp [127.0.0.1]:53\nok\n"],
			'an IPv6 address without brackets' => ["listening udp+tcp ::1:53\nok\n"],
			'an IPv6 address that is not canonical' => ["listening udp+tcp [::0001]:53\nok\n"],
			'an IPv4-mapped IPv6 address in uppercase' => ["listening udp+tcp [::FFFF:192.0.2.1]:53\nok\n"],
			'an IPv4-mapped IPv6 address' => ["listening udp+tcp [::ffff:192.0.2.1]:53\nok\n"],
			'an IPv6 address with a zone' => ["listening udp+tcp [fe80::1%em0]:53\nok\n"],
			'an IPv6 address in uppercase' => ["listening udp+tcp [2001:DB8::1]:53\nok\n"],
			'a refused line with a bad address' => ["refused dot localhost:853 bind: x\nok\n"],
			'an unknown kind' => ["listening dns 127.0.0.1:53\nok\n"],
			'a kind in uppercase' => ["listening UDP+TCP 127.0.0.1:53\nok\n"],
			'a kind that is only half of udp+tcp' => ["listening udp 127.0.0.1:53\nok\n"],
			'an unknown kind on a refused line' => ["refused tls 192.0.2.1:853 bind: x\nok\n"],
			'a refused line with no reason' => ["refused dot 192.0.2.1:853\nok\n"],
			'a refused line with a space and no reason' => ["refused dot 192.0.2.1:853 \nok\n"],
			'a NUL byte at the end of a line' => ["listening udp+tcp 127.0.0.1:53\0\nok\n"],
			'a NUL byte inside a reason' => ["refused dot 192.0.2.1:853 bind: \0x\nok\n"],
			'an ok line that is not last' => ["ok\nlistening udp+tcp 127.0.0.1:53\nok\n"],
			'an error line after lines' => ["listening udp+tcp 127.0.0.1:53\nerror: x\n"],
			'an empty first line' => ["\nok\n"],
			'an empty line between lines' => ["listening udp+tcp 127.0.0.1:53\n\nok\n"],
			'a listening line twice' => ["listening udp+tcp 127.0.0.1:53\nlistening udp+tcp 127.0.0.1:53\nok\n"],
			'a refused line twice with two reasons' => ["refused dot 192.0.2.1:853 bind: a\nrefused dot 192.0.2.1:853 bind: b\nok\n"],
			'one listener both listening and refused' => ["listening dot 192.0.2.1:853\nrefused dot 192.0.2.1:853 bind: x\nok\n"],
		];
	}

	#[DataProvider('repliesThatBreakTheFormat')]
	public function testAReplyWithOneLineThatBreaksTheFormatIsUnknownWhole(string $reply): void
	{
		// Given a reply whose lines are valid but for one, or whose lines name one listener twice
		// When the list is asked for
		$list = $this->listed($reply);

		// Then the whole list is unknown: a valid line beside the bad one is not returned
		$this->assertNull($list, 'expected an unknown list (NULL) for ' . var_export($reply, TRUE) . ', got ' . var_export($list, TRUE));
	}
}
