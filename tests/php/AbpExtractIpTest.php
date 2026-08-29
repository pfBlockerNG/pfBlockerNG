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
			'abp anchor domain -> none' => ['||example.com^', ''],
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
	public function testExtract(string $line, string $expected): void
	{
		$this->assertSame($expected, pfb_dnsbl_abp_extract_ip($line));
	}
}
