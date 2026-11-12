<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3849: the listener list (the explicit diagnostic) parses each numeric endpoint once, by its bytes, as the applied status
 * does: each row is keyed by pfb_dns_proxy_endpoint(), which spells those bytes as pfb_dns_proxy_host_port() does.
 * The gateway prints an IPv4-compatible address as ::c000:201 where PHP prints ::192.0.2.1, so a list that spelled that row as the
 * gateway does was refused whole. Uppercase hex, zero-padded groups, IPv4-mapped addresses and a leading-zero port are numeric
 * spellings of the same bytes and are normalized the same way. Duplicates are judged after that normalization, and every case with
 * a duplicate has a distinct-address sibling that is listed, so a refusal is attributable to the duplicate alone. Spellings other
 * than the gateway's are numeric-equivalence inputs, not gateway output; the one captured reply is the gateway's own list() output.
 */
#[CoversFunction('pfb_dns_proxy_listener_list')]
#[CoversFunction('pfb_dns_proxy_endpoint')]
final class DnsProxyListenerListAddressBytesTest extends TestCase
{
	private string $dir;
	private array $servers = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_list_bytes_' . bin2hex(random_bytes(5));
		mkdir($this->dir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as [$process, $pipes]) {
			fclose($pipes[0]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		$this->servers = [];
		rmdir_recursive($this->dir);
	}

	/** The house spelling of one numeric address: its bytes as inet_ntop prints them. */
	private static function house(string $address): string
	{
		return (string) inet_ntop((string) inet_pton($address));
	}

	/** The gateway's own list reply, as listenerSet.list() wrote it (support/real-list-ipv4-compatible.wire). */
	private static function goWire(): string
	{
		return (string) file_get_contents(__DIR__ . '/support/real-list-ipv4-compatible.wire');
	}

	/** The listener list when a control socket answers $reply once and hangs up, as the gateway does. */
	private function listed(string $reply): ?array
	{
		$n = count($this->servers);
		$socket = "{$this->dir}/ctl{$n}.sock";
		$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $socket, "{$this->dir}/frames{$n}", base64_encode($reply)],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$process, $pipes];

		return pfb_dns_proxy_listener_list($socket, 0.5);
	}

	public function testTheGatewaysOwnListReplyIsListedUnderTheHouseSpellingOfItsBytesWithNoWarning(): void
	{
		// Given the gateway's own reply: an IPv4-compatible IPv6 listener in the spelling Go prints, beside an IPv4 one and a refusal
		$house = self::house('::c000:201');
		set_error_handler(static function (int $number, string $message): bool {
			throw new ErrorException($message, 0, $number);
		}, E_WARNING | E_DEPRECATED);
		try {
			// When the list is asked for
			$list = $this->listed(self::goWire());
		} finally {
			restore_error_handler();
		}

		// Then each row is keyed by the house spelling of its bytes, and the refusal keeps its reason
		$this->assertSame([
			'listening' => [
				'dot' => ["[{$house}]:853" => TRUE],
				'udp+tcp' => ['127.0.0.1:53' => TRUE, "[{$house}]:53" => TRUE],
			],
			'refused' => ['doh' => ["[{$house}]:443" => 'bind: address already in use']],
		], $list);
	}

	/** @return array<string,array{string,string}> a listener line in a numeric spelling of the gateway's, and the house spelling of its bytes */
	public static function numericSpellings(): array
	{
		return [
			'the gateway spelling of an IPv4-compatible IPv6 address' => ['[::c000:201]:53', '[' . self::house('::c000:201') . ']:53'],
			'uppercase hex digits' => ['[2001:DB8::1]:53', '[2001:db8::1]:53'],
			'zero-padded groups' => ['[2001:0db8:0000:0000:0000:0000:0000:0001]:53', '[2001:db8::1]:53'],
			'a zero-padded group in a short address' => ['[::0001]:53', '[::1]:53'],
			'an IPv4-mapped address in dotted form' => ['[::ffff:192.0.2.1]:53', '192.0.2.1:53'],
			'an IPv4-mapped address in uppercase dotted form' => ['[::FFFF:192.0.2.1]:53', '192.0.2.1:53'],
			'an IPv4-mapped address in uppercase hex' => ['[::FFFF:C000:201]:53', '192.0.2.1:53'],
			'a leading-zero port' => ['127.0.0.1:053', '127.0.0.1:53'],
			'a five-digit port with leading zeros' => ['127.0.0.1:00053', '127.0.0.1:53'],
			'the house spelling is unchanged' => ['[2001:db8::1]:53', '[2001:db8::1]:53'],
		];
	}

	#[DataProvider('numericSpellings')]
	public function testANumericSpellingOfAListenerIsListedUnderItsHouseSpelling(string $line, string $house): void
	{
		// Given one UDP and TCP listener written in a numeric spelling of its bytes
		// When the list is asked for
		$list = $this->listed("listening udp+tcp {$line}\nok\n");

		// Then it is listed once, under the house spelling of its bytes, with no refusals
		$this->assertSame(['listening' => ['udp+tcp' => [$house => TRUE]], 'refused' => []], $list, "for the line {$line}");
	}

	/** @return array<string,array{string,string,string}> a kind, a listener line in the gateway's spelling, and the house spelling of its bytes */
	public static function kindsAndSpellings(): array
	{
		return [
			'dot' => ['dot', '[::c000:201]:853', '[' . self::house('::c000:201') . ']:853'],
			'doh' => ['doh', '[::FFFF:192.0.2.1]:443', '192.0.2.1:443'],
			'doq' => ['doq', '[2001:DB8::3]:853', '[2001:db8::3]:853'],
		];
	}

	#[DataProvider('kindsAndSpellings')]
	public function testTheKindDoesNotChangeTheSpellingRule(string $kind, string $line, string $house): void
	{
		// Given one listener of the kind, written in a numeric spelling of its bytes
		// When the list is asked for
		$list = $this->listed("listening {$kind} {$line}\nok\n");

		// Then it is listed under the kind and the house spelling of its bytes
		$this->assertSame(['listening' => [$kind => [$house => TRUE]], 'refused' => []], $list);
	}

	/** @return array<string,array{string}> a reply that names one listener twice, in two spellings of its bytes, or in one spelling twice */
	public static function duplicates(): array
	{
		$house = self::house('::c000:201');
		return [
			'the gateway spelling and the house spelling of one listener' => ["listening udp+tcp [::c000:201]:53\nlistening udp+tcp [{$house}]:53\nok\n"],
			'uppercase and lowercase hex of one listener' => ["listening udp+tcp [2001:DB8::1]:53\nlistening udp+tcp [2001:db8::1]:53\nok\n"],
			'a zero-padded group and the short form of one listener' => ["listening udp+tcp [2001:db8::1]:53\nlistening udp+tcp [2001:0db8::1]:53\nok\n"],
			'an IPv4-mapped address and the IPv4 address it is' => ["listening udp+tcp [::ffff:192.0.2.1]:53\nlistening udp+tcp 192.0.2.1:53\nok\n"],
			'a leading-zero port and its port' => ["listening udp+tcp 127.0.0.1:053\nlistening udp+tcp 127.0.0.1:53\nok\n"],
			'one listener listening and refused, spelled differently' => ["listening dot [2001:db8::1]:853\nrefused dot [2001:DB8::1]:853 bind: x\nok\n"],
			'one listener twice in the same spelling' => ["listening udp+tcp [{$house}]:53\nlistening udp+tcp [{$house}]:53\nok\n"],
		];
	}

	#[DataProvider('duplicates')]
	public function testTwoSpellingsOfOneListenerAreOneRowSoTheWholeListIsUnknown(string $reply): void
	{
		// Given a reply that names one listener twice, in one or two numeric spellings of its bytes
		// When the list is asked for
		// Then it is unknown: one listener is one row, however it is spelled
		$this->assertNull($this->listed($reply), 'a duplicate after normalization is unknown');
	}

	/** @return array<string,array{string,array<string,array<string,array<string,true|string>>>}> a reply whose listeners are distinct once normalized, and the list it gives */
	public static function distinctListeners(): array
	{
		$house = self::house('::c000:201');
		$other = self::house('::c000:202');
		return [
			'the same address under another kind' => ["listening udp+tcp [::c000:201]:53\nlistening dot [::c000:201]:853\nok\n",
				['listening' => ['udp+tcp' => ["[{$house}]:53" => TRUE], 'dot' => ["[{$house}]:853" => TRUE]], 'refused' => []]],
			'the sibling of the gateway and house duplicate' => ["listening udp+tcp [::c000:201]:53\nlistening udp+tcp [{$other}]:53\nok\n",
				['listening' => ['udp+tcp' => ["[{$house}]:53" => TRUE, "[{$other}]:53" => TRUE]], 'refused' => []]],
			'the sibling of the uppercase duplicate' => ["listening udp+tcp [2001:DB8::1]:53\nlistening udp+tcp [2001:db8::2]:53\nok\n",
				['listening' => ['udp+tcp' => ['[2001:db8::1]:53' => TRUE, '[2001:db8::2]:53' => TRUE]], 'refused' => []]],
			'the sibling of the mapped duplicate' => ["listening udp+tcp [::ffff:192.0.2.1]:53\nlistening udp+tcp 192.0.2.2:53\nok\n",
				['listening' => ['udp+tcp' => ['192.0.2.1:53' => TRUE, '192.0.2.2:53' => TRUE]], 'refused' => []]],
			'the sibling of the leading-zero duplicate' => ["listening udp+tcp 127.0.0.1:053\nlistening udp+tcp 127.0.0.1:54\nok\n",
				['listening' => ['udp+tcp' => ['127.0.0.1:53' => TRUE, '127.0.0.1:54' => TRUE]], 'refused' => []]],
			'the sibling of a listening and refused duplicate' => ["listening dot [2001:db8::1]:853\nrefused dot [2001:DB8::2]:853 bind: x\nok\n",
				['listening' => ['dot' => ['[2001:db8::1]:853' => TRUE]], 'refused' => ['dot' => ['[2001:db8::2]:853' => 'bind: x']]]],
			'the sibling of the same-spelling duplicate, on another port' => ["listening udp+tcp [{$house}]:53\nlistening udp+tcp [{$house}]:54\nok\n",
				['listening' => ['udp+tcp' => ["[{$house}]:53" => TRUE, "[{$house}]:54" => TRUE]], 'refused' => []]],
		];
	}

	/** @param array<string,array<string,array<string,true|string>>> $expected */
	#[DataProvider('distinctListeners')]
	public function testListenersThatAreDistinctOnceNormalizedAreEachListed(string $reply, array $expected): void
	{
		// Given a reply whose listeners are distinct, in a numeric spelling or the house one
		// When the list is asked for
		// Then every listener is a row under its house spelling, so no row is lost to a duplicate that is not one
		$this->assertSame($expected, $this->listed($reply));
	}

	/** @return array<string,array{string}> a whole reply whose one listener is not a numeric endpoint, or is one the gateway never serves */
	public static function unknownLists(): array
	{
		return [
			'port zero, in the gateway spelling' => ["listening udp+tcp [::c000:201]:0\nok\n"],
			'port zero, in the house spelling' => ["listening udp+tcp 127.0.0.1:0\nok\n"],
			'a six-digit port with leading zeros' => ["listening udp+tcp 127.0.0.1:000053\nok\n"],
			'a port above 65535 in the gateway spelling' => ["listening udp+tcp [::c000:201]:65536\nok\n"],
			'a negative port' => ["listening udp+tcp [::c000:201]:-53\nok\n"],
			'an IPv4 address in brackets' => ["listening udp+tcp [127.0.0.1]:53\nok\n"],
			'a zero-padded IPv4 octet' => ["listening udp+tcp 192.000.2.1:53\nok\n"],
			'a zone' => ["listening udp+tcp [fe80::1%em0]:53\nok\n"],
			'a hostname' => ["listening udp+tcp localhost:53\nok\n"],
			'an IPv6 address without brackets' => ["listening udp+tcp ::c000:201:53\nok\n"],
			'a space inside the brackets' => ["listening udp+tcp [ ::c000:201]:53\nok\n"],
			'a digit that is not hex' => ["listening udp+tcp [2001:db8::g]:53\nok\n"],
			'a group of more than four digits' => ["listening udp+tcp [2001:db8::12345]:53\nok\n"],
		];
	}

	#[DataProvider('unknownLists')]
	public function testAListenerThatIsNotANumericEndpointMakesTheWholeListUnknown(string $reply): void
	{
		// Given a whole reply with one line that is not a numeric endpoint of the gateway's listener
		// When the list is asked for
		// Then the whole list is unknown, not a partial one
		$this->assertNull($this->listed($reply), 'expected an unknown list (NULL) for ' . var_export($reply, TRUE));
	}
}
