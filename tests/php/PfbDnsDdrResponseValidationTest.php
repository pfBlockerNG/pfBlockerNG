<?php

declare(strict_types=1);

require_once __DIR__ . '/PfbDnsDdrStatusTest.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_ddr_result')]
final class PfbDnsDdrResponseValidationTest extends TestCase
{
	private function parsed(array $records, string $name = '_dns.resolver.arpa.', string $type = 'SVCB', array $additional = []): array
	{
		return pfb_dns_ddr_result(PfbDnsDdrStatusTest::response($records, $name, $type, additional: $additional), 0, $name, $type);
	}

	private function expected(string $host = '192.0.2.1'): array
	{
		return [
			['priority' => 1, 'target' => 'dns.example.com', 'alpn' => 'h2', 'port' => 4443, 'hint' => $host, 'path' => '/dns-query{?dns}'],
			['priority' => 2, 'target' => 'dns.example.com', 'alpn' => 'dot', 'port' => 853, 'hint' => $host, 'path' => ''],
			['priority' => 3, 'target' => 'dns.example.com', 'alpn' => 'doq', 'port' => 8853, 'hint' => $host, 'path' => ''],
		];
	}

	public function testEveryTransportAndOwnedAddressFamilyMustMatchAsASet(): void
	{
		$this->assertTrue(function_exists('pfb_dns_ddr_compare'), 'DDR must compare semantic answer sets, not merely detect an SVCB line');
		foreach (['192.0.2.1', '2001:db8::1', '192.0.2.53', '2001:db8::53', '192.0.2.54', '2001:db8::54', '127.0.0.1', '::1'] as $host) {
			$svcb = $this->parsed([PfbDnsDdrStatusTest::record($host, 'doq', 8853), PfbDnsDdrStatusTest::record($host, 'dot'),
				PfbDnsDdrStatusTest::record($host, 'h2', 4443)], additional: ['dns.example.com. 300 IN ' . (str_contains($host, ':') ? 'AAAA' : 'A') . " {$host}"]);
			$names = ['A' => $this->parsed(['dns.example.com. 300 IN A 192.0.2.53'], 'dns.example.com.', 'A'),
				'AAAA' => $this->parsed(['dns.example.com. 300 IN AAAA 2001:0db8:0:0:0:0:0:53'], 'dns.example.com.', 'AAAA')];
			$this->assertSame('matched', pfb_dns_ddr_compare($this->expected($host), $svcb, ['192.0.2.53', '2001:db8::53'], $names)['state'], $host);
			foreach (['priority', 'target', 'alpn', 'port', 'hint', 'path'] as $field) {
				$wrong = $svcb;
				$wrong['answers'][0][$field] = $field === 'port' || $field === 'priority' ? 42 : 'wrong';
				$this->assertSame('mismatch', pfb_dns_ddr_compare($this->expected($host), $wrong, ['192.0.2.53', '2001:db8::53'], $names)['state'], $field);
			}
			$missing = $svcb;
			array_pop($missing['answers']);
			$this->assertSame('mismatch', pfb_dns_ddr_compare($this->expected($host), $missing, [], [])['state']);
			$extra = $svcb;
			$extra['answers'][] = $extra['answers'][0];
			$this->assertSame('mismatch', pfb_dns_ddr_compare($this->expected($host), $extra, [], [])['state']);
			$names['AAAA']['answers'] = [];
			$this->assertSame('mismatch', pfb_dns_ddr_compare($this->expected($host), $svcb, ['192.0.2.53', '2001:db8::53'], $names)['state']);
		}
	}

	public function testNoMappingIsExplicitAndNoMissingFamilyQueryFailureCanMatch(): void
	{
		$this->assertTrue(function_exists('pfb_dns_ddr_compare'));
		$record = $this->parsed([PfbDnsDdrStatusTest::record()], additional: ['dns.example.com. 300 IN A 192.0.2.1']);
		$expected = [$this->expected()[1]];
		$result = pfb_dns_ddr_compare($expected, $record, NULL, []);
		$this->assertSame('matched', $result['state']);
		$this->assertStringContainsString('name resolution not checked', $result['reason']);
		$names = ['A' => $this->parsed(['dns.example.com. 300 IN A 192.0.2.1'], 'dns.example.com.', 'A'),
			'AAAA' => $this->parsed([], 'dns.example.com.', 'AAAA')];
		$this->assertSame('matched', pfb_dns_ddr_compare($expected, $record, ['192.0.2.1'], $names)['state']);
		foreach (['error', 'timeout', 'budget'] as $state) {
			$names['AAAA'] = ['state' => $state, 'reason' => 'query failed'];
			$this->assertSame($state, pfb_dns_ddr_compare($expected, $record, ['192.0.2.1'], $names)['state']);
			$this->assertSame($state, pfb_dns_ddr_compare($expected, ['state' => $state, 'reason' => 'query failed'], NULL, [])['state']);
		}
		$this->assertSame('mismatch', pfb_dns_ddr_compare($expected, $this->parsed([]), NULL, [])['state']);
	}

	public function testAdditionalAddressesMustMatchCompletelyIncludingMultiplicity(): void
	{
		foreach (['192.0.2.1', '2001:db8::1'] as $host) {
			$type = str_contains($host, ':') ? 'AAAA' : 'A';
			$address = "dns.example.com. 300 IN {$type} {$host}";
			$expected = [$this->expected($host)[1]];
			$records = [PfbDnsDdrStatusTest::record($host)];
			$names = ['A' => ['state' => 'ok', 'answers' => ['192.0.2.53']],
				'AAAA' => ['state' => 'ok', 'answers' => ['2001:db8::53']]];
			$owned = ['192.0.2.53', '2001:db8::53'];
			$valid = $this->parsed($records, additional: [$address]);
			$this->assertSame('matched', pfb_dns_ddr_compare($expected, $valid, $owned, $names)['state']);
			foreach ([[], [$address, $address], ["dns.example.com. 300 IN {$type} " . ($type === 'A' ? '192.0.2.99' : '2001:db8::99')]] as $additional) {
				$reply = $this->parsed($records, additional: $additional);
				$this->assertSame('ok', $reply['state'], 'The semantic comparison must reject a structurally valid reply');
				$this->assertSame('mismatch', pfb_dns_ddr_compare($expected, $reply, $owned, $names)['state'], json_encode($reply));
			}
		}
	}
}
