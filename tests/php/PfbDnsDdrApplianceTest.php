<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_ddr_result')]
final class PfbDnsDdrApplianceTest extends TestCase
{
	public function testApplianceDrillFooterAndEdnsDoNotCountAsAnAdditionalRecord(): void
	{
		$reply = <<<'DNS'
			;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 13054
			;; flags: qr aa rd ra ; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1
			;; QUESTION SECTION:
			;; _dns.resolver.arpa.	IN	SVCB

			;; ANSWER SECTION:
			_dns.resolver.arpa.	300	IN	SVCB	1 dns.brait.dev. alpn=h2 port=4443 ipv4hint=127.0.0.1 dohpath=/dns-query{?dns}
			_dns.resolver.arpa.	300	IN	SVCB	2 dns.brait.dev. alpn=dot ipv4hint=127.0.0.1
			_dns.resolver.arpa.	300	IN	SVCB	3 dns.brait.dev. alpn=doq ipv4hint=127.0.0.1

			;; AUTHORITY SECTION:

			;; ADDITIONAL SECTION:
			dns.brait.dev.	300	IN	A	127.0.0.1

			;; Query time: 1 msec
			;; EDNS: version 0; flags: ; udp: 1232
			;; SERVER: 127.0.0.1
			;; WHEN: Thu Nov  5 12:23:24 2026
			;; MSG SIZE  rcvd: 236
			DNS;
		$result = pfb_dns_ddr_result($reply, 0);
		$this->assertSame('ok', $result['state']);
		$this->assertSame(['h2', 'dot', 'doq'], array_column($result['answers'], 'alpn'));
		$this->assertSame([4443, 853, 853], array_column($result['answers'], 'port'));
		$this->assertSame(['127.0.0.1'], $result['additional']);
	}

	public function testNameNodataRejectsAnUnrelatedAuthorityZone(): void
	{
		$reply = ";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 1\n"
		    . ";; flags: qr aa ; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 0\n"
		    . ";; QUESTION SECTION:\n;; dns.example.com. IN AAAA\n;; ANSWER SECTION:\n;; AUTHORITY SECTION:\n"
		    . "resolver.arpa. 300 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 300\n;; ADDITIONAL SECTION:\n";
		$this->assertSame('error', pfb_dns_ddr_result($reply, 0, 'dns.example.com.', 'AAAA')['state']);
		$owned = str_replace('resolver.arpa. 300 IN SOA', 'dns.example.com. 300 IN SOA', $reply);
		$this->assertSame('ok', pfb_dns_ddr_result($owned, 0, 'dns.example.com.', 'AAAA')['state']);
	}
}
