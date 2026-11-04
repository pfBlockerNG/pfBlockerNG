<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_ddr_result')]
final class PfbDnsDdrResponseValidationTest extends TestCase
{
	/** @return array<string,array{string,int,string,string}> */
	public static function replies(): array
	{
		$svcb = '_dns.resolver.arpa. 300 IN SVCB 1 dns.example.net. alpn=h2 dohpath=/dns-query{?dns}';
		$wrong = '53. 300 IN A 203.0.113.99';
		return [
			'actual designation' => ['_dns.resolver.arpa.', 1, $svcb, 'advertised'],
			'actual NODATA' => ['_dns.resolver.arpa.', 0, '', 'empty'],
			'port parsed as query with an answer' => ['53.', 1, $wrong, 'error'],
			'port parsed as query with NODATA' => ['53.', 0, '', 'error'],
			'unrelated A answer is not an advertisement' => ['_dns.resolver.arpa.', 1, '_dns.resolver.arpa. 300 IN A 203.0.113.99', 'error'],
			'answer count without records is not an advertisement' => ['_dns.resolver.arpa.', 1, '', 'error'],
		];
	}

	#[DataProvider('replies')]
	public function testOnlyTheIntendedSvcbQuestionAndRecordsCanBeAdvertised(string $question, int $count, string $answer, string $state): void
	{
		$stdout = ";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 1\n"
		    . ";; flags: qr aa rd ra ; QUERY: 1, ANSWER: {$count}, AUTHORITY: 0, ADDITIONAL: 0\n"
		    . ";; QUESTION SECTION:\n;; {$question}\tIN\tSVCB\n\n;; ANSWER SECTION:\n{$answer}\n\n;; AUTHORITY SECTION:\n";
		$this->assertSame($state, pfb_dns_ddr_result($stdout, '', 0)['state'], $stdout);
	}
}
