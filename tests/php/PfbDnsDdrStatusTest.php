<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_ddr_result')]
#[CoversFunction('pfb_dns_ddr_probe')]
#[CoversFunction('pfb_dns_ddr_status_panel')]
final class PfbDnsDdrStatusTest extends TestCase
{
	public static function response(array $answers, string $name = '_dns.resolver.arpa.', string $type = 'SVCB', array $authority = [], array $additional = []): string
	{
		$out = ";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 1\n;; flags: qr aa rd ra ; QUERY: 1, ANSWER: " . count($answers)
			. ', AUTHORITY: ' . count($authority) . ', ADDITIONAL: ' . count($additional) . "\n;; QUESTION SECTION:\n;; {$name} IN {$type}\n";
		foreach (['ANSWER' => $answers, 'AUTHORITY' => $authority, 'ADDITIONAL' => $additional] as $section => $records) {
			$out .= ";; {$section} SECTION:\n" . implode("\n", $records) . "\n";
		}
		return $out;
	}

	public static function record(string $host = '192.0.2.1', string $alpn = 'dot', int $port = 853): string
	{
		$priority = ['h2' => 1, 'dot' => 2, 'doq' => 3][$alpn];
		$hint = str_contains($host, ':') ? 'ipv6hint' : 'ipv4hint';
		return "_dns.resolver.arpa. 300 IN SVCB {$priority} DNS.Example.COM. alpn=\"{$alpn}\" port={$port} {$hint}={$host}"
			. ($alpn === 'h2' ? ' dohpath="/dns-query{?dns}"' : '');
	}

	public function testDecodedResponsesAreStructuredWithoutRawStreams(): void
	{
		$result = pfb_dns_ddr_result(self::response([self::record()]), 0);
		$this->assertSame('ok', $result['state']);
		$this->assertArrayNotHasKey('stdout', $result);
		$this->assertArrayNotHasKey('stderr', $result);
		$this->assertSame([['priority' => 2, 'target' => 'dns.example.com', 'alpn' => 'dot', 'port' => 853,
			'hint' => '192.0.2.1', 'path' => '']], $result['answers']);
	}

	public static function badResponses(): array
	{
		$good = self::response([self::record()]);
		$bad = [];
		foreach (['REFUSED', 'NXDOMAIN', 'SERVFAIL'] as $rcode) {
			$bad[$rcode] = [str_replace('rcode: NOERROR', "rcode: {$rcode}", $good)];
		}
		foreach ([
			'wrong owner' => ['_dns.resolver.arpa. 300', 'other.example. 300'],
			'wrong type' => ['IN SVCB 2', 'IN TXT 2'],
			'wrong question' => [';; _dns.resolver.arpa. IN', ';; other.example. IN'],
			'truncated' => ['qr aa rd ra', 'qr tc aa rd ra'],
			'count mismatch' => ['ANSWER: 1', 'ANSWER: 2'],
			'duplicate parameter' => ['port=853', 'port=853 port=853'],
			'empty parameter' => ['alpn="dot"', 'alpn=""'],
			'unknown parameter' => ['alpn="dot"', 'alpn="dot" key99=bad'],
			'HTML name' => ['DNS.Example.COM.', '<script>.example.'],
			'nonASCII name' => ['DNS.Example.COM.', 'dñs.example.'],
			'invalid hint' => ['192.0.2.1', '999.0.0.1'],
			'port overflow' => ['port=853', 'port=65536'],
			'broken quotes' => ['alpn="dot"', 'alpn="dot'],
			'shell token' => ['alpn="dot"', 'alpn=dot;touch'],
		] as $label => [$from, $to]) {
			$bad[$label] = [str_replace($from, $to, $good)];
		}
		$bad['missing header'] = [substr($good, strpos($good, ';; flags:'))];
		$bad['missing question'] = [str_replace(";; QUESTION SECTION:\n;; _dns.resolver.arpa. IN SVCB\n", '', $good)];
		$bad['oversized'] = [$good . str_repeat('x', 65537)];
		$bad['answer in authority'] = [self::response([], authority: [self::record()])];
		$bad['unrelated additional'] = [self::response([self::record()], additional: ['other.example. 300 IN A 192.0.2.1'])];
		return $bad;
	}

	#[DataProvider('badResponses')]
	public function testMalformedResponsesNeverBecomeSuccessful(string $response): void
	{
		$this->assertSame('error', pfb_dns_ddr_result($response, 0)['state']);
	}

	public function testWhitespaceAndDefaultPortsNormalizeSemantically(): void
	{
		$record = str_replace(' ', "\t  ", str_replace(' port=853', '', self::record()));
		$result = pfb_dns_ddr_result(self::response([$record]), 0);
		$this->assertSame('ok', $result['state']);
		$this->assertSame(853, $result['answers'][0]['port']);
	}

	public function testFailuresAndTimeoutsNeverExposeOutput(): void
	{
		foreach ([1 => 'error', 124 => 'timeout', 137 => 'timeout'] as $exit => $state) {
			$result = pfb_dns_ddr_result(self::response([self::record()]), $exit);
			$this->assertSame($state, $result['state']);
			$this->assertArrayNotHasKey('stdout', $result);
			$this->assertArrayNotHasKey('stderr', $result);
		}
	}

	public static function hostileListeners(): array
	{
		return array_map(static fn (string $at): array => [$at], ['127.0.0.1:53; touch /tmp/ddr', 'dns.example.com:53', '127.0.0.1:0',
			'127.0.0.1:65536', '127.0.0.1:053', '127.0.0.1:', '::1:53', '[fe80::1%em0]:53', '[2001:0db8::1]:53', '[::ffff:192.0.2.1]:53', '']);
	}

	#[DataProvider('hostileListeners')]
	public function testInvalidListenersCannotBecomeProbeTargets(string $listener): void
	{
		$result = pfb_dns_ddr_probe($listener, 2.0);
		$this->assertSame('error', $result['state']);
		$this->assertStringContainsString('Invalid bound listener', $result['reason']);
		$this->assertArrayNotHasKey('stdout', $result);
	}

	public function testAccessibleHouseTableEscapesAllValuesAndHasNoManualOrRawControl(): void
	{
		$hostile = '<script>" & label</script>';
		$rows = [];
		foreach (['matched', 'mismatch', 'error', 'timeout', 'budget', 'off', 'no_transport', 'unverified', 'unexpected'] as $state) {
			$rows[] = ['interface' => $hostile, 'identity' => 'Interface', 'address' => '192.0.2.1:53', 'name' => $hostile,
				'state' => $state, 'reason' => $hostile];
		}
		$doc = new DOMDocument();
		$this->assertTrue($doc->loadXML('<root>' . pfb_dns_ddr_status_panel(['notice' => $hostile, 'queried' => 'now', 'rows' => $rows]) . '</root>'));
		$xpath = new DOMXPath($doc);
		$this->assertSame(0, $xpath->query('//script | //pre | //form | //a[@id="pfb-dns-ddr-refresh"]')->length);
		$this->assertSame(9, $xpath->query('//tr[@data-address="192.0.2.1:53"]')->length);
		$this->assertSame(1, $xpath->query('//i[contains(@class,"text-success")]')->length);
		$this->assertSame(8, $xpath->query('//i[contains(@class,"text-danger")]')->length);
		$this->assertSame(9, $xpath->query('//span[@class="sr-only"]')->length);
		$this->assertSame($hostile, $xpath->evaluate('string(//tbody/tr/td[1])'));
		$this->assertSame($hostile, $xpath->evaluate('string(//tbody/tr/td[3])'));
		$this->assertSame(1, $xpath->query('//div[@class="table-responsive"]/table')->length);
		$this->assertSame('#pfb-dns-status-ddr_panel-body', $xpath->evaluate('string(//a[@data-toggle="collapse"]/@href)'));
	}

	public function testSuccessfulRowsShowOnlyAnIconWithAccessibleDetails(): void
	{
		$reason = 'SVCB matched; name resolution not checked (no owned address mapping)';
		$doc = new DOMDocument();
		$doc->loadXML('<root>' . pfb_dns_ddr_status_panel(['notice' => '', 'queried' => NULL, 'rows' => [[
			'interface' => 'Localhost', 'identity' => 'Interface', 'address' => '127.0.0.1:53',
			'name' => 'dns.example.com', 'state' => 'matched', 'reason' => $reason,
		]]]) . '</root>');
		$xpath = new DOMXPath($doc);
		$this->assertSame('', trim($xpath->evaluate('string(//tbody/tr/td[4]/text())')), 'Successful rows must not repeat prose');
		$this->assertStringContainsString($reason, $xpath->evaluate('string(//tbody/tr/td[4]/i/@title)'));
		$this->assertStringContainsString($reason, $xpath->evaluate('string(//tbody/tr/td[4]/span[@class="sr-only"])'));
	}
}
