<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_abp_extract_ip() — ADR-07 P8 extraction of an IP from an ABP network
 * anchor (||ip^[$opts]) or a hosts line (<sink-ip> <ip>) for the DNSBL-IP
 * firewall pass. Returns '' when the line carries no IP-valued target.
 */
#[CoversFunction('pfb_dnsbl_abp_extract_ip')]
final class AbpExtractIpTest extends TestCase
{
	public static function provider(): array
	{
		return [
			// Deliberate DNS/pf coarsening (#723): ABP '||' WITHOUT a trailing '^' is
			// prefix-matching in ABP semantics (also matches 192.0.2.40), and
			// $third-party is a page-context scope — neither is expressible in a pf
			// IP table, so the extractor canonises both to the exact IP and drops the
			// option. These rows PIN that coarsening as intended behaviour.
			'abp anchor v4'            => ['||192.0.2.4^', '192.0.2.4'],
			'abp anchor v4 + options'  => ['||192.0.2.4^$third-party', '192.0.2.4'],
			'abp anchor v4 no caret'   => ['||192.0.2.4', '192.0.2.4'],
			'abp anchor v6'            => ['||2001:db8::1^', '2001:db8::1'],
			// URI-bracketed IPv6 anchors: unwrapped like the plain-line path (#938).
			'abp anchor bracketed v6'  => ['||[2001:db8::1]^', '2001:db8::1'],
			'abp anchor bracketed v6 + options' => ['||[2001:db8::1]^$important', '2001:db8::1'],
			'abp anchor bracketed mapped v6' => ['||[::ffff:c0a8:164]^', '::ffff:c0a8:164'],
			'abp anchor bracketed v6 space before caret' => ['||[2001:db8::1] ^', '2001:db8::1'],
			'abp anchor unclosed bracket -> none' => ['||[2001:db8::1', ''],
			'abp anchor bracketed non-ip -> none' => ['||[not-an-ip]^', ''],
			'abp anchor bracketed v4 -> none' => ['||[192.0.2.1]^', ''],
			'abp anchor bracketed v6 + port' => ['||[2001:db8::1]:443^', '2001:db8::1'],
			// A path is not a host: a numeric-looking last path segment is no IP literal.
			'abp anchor path, numeric tail -> none' => ['||example.com/ads/banner.1^', ''],
			'abp anchor path + option -> none' => ['||foo.com/a.1$third-party', ''],
			'abp anchor domain -> none' => ['||example.com^', ''],
			// Port dropped, CIDR honoured, padded octets decimal -- as the plain DNSBL path.
			'abp anchor v4 + port'      => ['||192.168.1.100:8080^', '192.168.1.100'],
			'abp anchor v4 + port + options' => ['||1.2.3.4:8080^$third-party', '1.2.3.4'],
			'abp anchor dword + port'   => ['||3232235876:8080^', '192.168.1.100'],
			'abp anchor padded v4 + port' => ['||192.168.010.1:8080^', '192.168.10.1'],
			'abp anchor v4 cidr'        => ['||10.0.0.0/8^', '10.0.0.0/8'],
			'abp anchor v4 cidr host bits kept' => ['||10.0.0.1/8^', '10.0.0.1/8'],
			'abp anchor v4 cidr /24 host bits kept' => ['||192.168.1.5/24^', '192.168.1.5/24'],
			'abp anchor padded cidr'    => ['||192.168.010.0/24^', '192.168.10.0/24'],
			'abp anchor v6 cidr'        => ['||2001:db8::/32^', '2001:db8::/32'],
			'abp anchor cidr /0'        => ['||1.2.3.4/0^', '1.2.3.4/0'],
			'abp anchor cidr /33 -> reject'  => ['||10.0.0.0/33^', FALSE],
			'abp anchor short-form cidr -> reject' => ['||192.168.1/24^', FALSE],
			'abp anchor dword cidr -> reject' => ['||3232235876/8^', FALSE],
			'abp anchor v6 cidr /129 -> reject' => ['||2001:db8::/129^', FALSE],
			'abp anchor huge mask -> reject' => ['||1.2.3.4/' . str_repeat('9', 5000) . '^', FALSE],
			'abp anchor padded v4'      => ['||192.168.010.1^', '192.168.10.1'],
			'abp anchor padded 08 quad' => ['||08.08.08.08^', '8.8.8.8'],
			'abp anchor out-of-range octet -> reject' => ['||192.168.256.1^', FALSE],
			'abp anchor non-number -> reject' => ['||a.0x1^', FALSE],
			'abp anchor v6 literal ending in hextet' => ['||2001:db8::1:443^', '2001:db8::1:443'],
			'abp anchor dword + slash -> none' => ['||3232235876/', ''],
			'abp anchor domain + port -> none' => ['||example.com:8080^', ''],
			'abp anchor domain path -> none' => ['||example.com/ads^', ''],
			'abp anchor domain numeric path -> none' => ['||example.com/123^', ''],
			'abp anchor bracketed v6 cidr form -> none' => ['||[2001:db8::]/32^', ''],
			// Hostile: nothing here may name an address the line does not carry.
			'abp anchor empty host + port -> none' => ['||:8080^', ''],
			'abp anchor colon only -> none' => ['||:^', ''],
			'abp anchor empty port -> none' => ['||1.2.3.4:^', ''],
			'abp anchor 6-digit port -> none' => ['||1.2.3.4:123456^', ''],
			'abp anchor empty mask -> none' => ['||1.2.3.4/^', ''],
			'abp anchor spaced mask -> none' => ['||1.2.3.4/ 8^', ''],
			'abp anchor double port -> none' => ['||[2001:db8::1]:443:80^', ''],
			'abp anchor fullwidth digits -> none' => ['||１.２.３.４:80^', ''],
			'abp anchor space before port -> none' => ['||1.2.3.4 :8080^', ''],
			'abp anchor tab before port -> none' => ["||1.2.3.4\t:8080^", ''],
			'hosts sink + ip target'   => ['0.0.0.0 192.0.2.9', '192.0.2.9'],
			'hosts v6 sink + ip target' => ['::1 2001:db8::1', '2001:db8::1'],
			'hosts tab-delimited'      => ["127.0.0.1\t192.0.2.9", '192.0.2.9'],
			'hosts domain target -> none' => ['127.0.0.1 example.com', ''],
			'hosts single ip -> none'  => ['192.0.2.9', ''],
			'plain domain -> none'     => ['example.com', ''],
			'empty -> none'            => ['', ''],
			'whitespace only -> none'  => ['   ', ''],
			'leading/trailing trim'    => ['  ||192.0.2.4^  ', '192.0.2.4'],
		];
	}

	#[DataProvider('provider')]
	public function testExtract(string $line, string|false $expected): void
	{
		$this->assertSame($expected, pfb_dnsbl_abp_extract_ip($line));
	}
}
