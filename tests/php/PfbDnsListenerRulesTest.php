<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The two rules every consumer of a pfB-DNS listener row shares (the owner map and the gateway entries, the syslog event, the Reports
 * columns, the metrics reader): which text is an address that can be named as a receiving endpoint, and which text is a description that
 * is safe to log, store and send. Each is decided in one place, so no consumer can hold a narrower or a wider rule than another.
 */
#[CoversFunction('pfb_dns_canonical_ip')]
#[CoversFunction('pfb_dns_listener_label_valid')]
final class PfbDnsListenerRulesTest extends TestCase
{
	/** @return array<string,array{mixed,?string}> */
	public static function addresses(): array
	{
		return [
			'IPv4' => ['192.0.2.1', '192.0.2.1'],
			'IPv6 loopback' => ['::1', '::1'],
			'IPv6 in upper case and full form' => ['2001:DB8:0:0:0:0:0:1', '2001:db8::1'],
			'IPv6 in upper case' => ['2001:DB8::1', '2001:db8::1'],
			'IPv4-mapped IPv6 keeps the spelling inet_ntop gives' => ['::ffff:192.0.2.9', '::ffff:192.0.2.9'],
			'empty' => ['', NULL],
			'unspecified IPv4' => ['0.0.0.0', NULL],
			'unspecified IPv6' => ['::', NULL],
			'unspecified IPv6 in full form' => ['0:0:0:0:0:0:0:0', NULL],
			'host and port' => ['127.0.0.1:53', NULL],
			'bracketed IPv6' => ['[::1]', NULL],
			'zone' => ['fe80::1%lo0', NULL],
			'prefix' => ['192.0.2.1/24', NULL],
			'name' => ['host.example', NULL],
			'padded' => [' 192.0.2.1', NULL],
			'NUL byte, which inet_pton() would throw on' => ["192.0.2.1\0", NULL],
			'NULL' => [NULL, NULL],
			'integer' => [42, NULL],
			'array' => [['192.0.2.1'], NULL],
		];
	}

	#[DataProvider('addresses')]
	public function testAnAddressIsCanonicalOnlyWhenItIsAValidSpecificIp(mixed $input, ?string $expected): void
	{
		$this->assertSame($expected, pfb_dns_canonical_ip($input));
	}

	/** @return array<string,array{mixed,bool}> */
	public static function labels(): array
	{
		return [
			'empty' => ['', TRUE],
			'ASCII' => ['LAN', TRUE],
			'accented' => ['Län', TRUE],
			'CJK' => ['日本', TRUE],
			'emoji' => ['😀', TRUE],
			'punctuation and quotes' => ['Län,"\\', TRUE],
			'no-break space' => ["a\u{00A0}b", TRUE],
			'invalid UTF-8' => ["\xff", FALSE],
			'NUL' => ["a\x00b", FALSE],
			'newline' => ["a\nb", FALSE],
			'tab' => ["a\tb", FALSE],
			'C1 control' => ["a\u{0085}b", FALSE],
			'zero width joiner' => ["a\u{200D}b", FALSE],
			'left-to-right mark' => ["a\u{200E}b", FALSE],
			'line separator' => ["a\u{2028}b", FALSE],
			'paragraph separator' => ["a\u{2029}b", FALSE],
			'byte order mark' => ["a\u{FEFF}b", FALSE],
			'NULL' => [NULL, FALSE],
			'integer' => [42, FALSE],
			'array' => [['LAN'], FALSE],
		];
	}

	#[DataProvider('labels')]
	public function testALabelIsValidOnlyAsTextWithNoControlFormatOrSeparatorCharacter(mixed $input, bool $expected): void
	{
		$this->assertSame($expected, pfb_dns_listener_label_valid($input));
	}
}
