<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_dns_status_panel')]
#[CoversFunction('pfb_dns_ddr_result')]
#[CoversFunction('pfb_dns_ddr_probe')]
final class PfbDnsDdrStatusTest extends TestCase
{
	private const ANSWERS = ";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 29492\n"
		. ";; flags: qr aa rd ra ; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
		. ";; ANSWER SECTION:\n"
		. "_dns.resolver.arpa. 300 IN SVCB 1 dns.example.com. alpn=h2 port=4443 ipv4hint=192.0.2.53 dohpath=/dns-query{?dns}\n"
		. "_dns.resolver.arpa. 300 IN SVCB 2 dns.example.com. alpn=dot ipv6hint=2001:db8::53\n"
		. "_dns.resolver.arpa. 300 IN SVCB 3 dns.example.com. alpn=doq port=8853\n\n";

	private function panel(array $ddr): DOMXPath
	{
		$document = new DOMDocument();
		$this->assertTrue($document->loadXML('<root>' . pfb_dns_status_panel([
			'service' => 'Running', 'mode' => 'On', 'transports' => NULL, 'ddr' => $ddr,
		]) . '</root>'));
		return new DOMXPath($document);
	}

	public function testAdvertisementsRetainExactDrillRecordsAndEscapeLabelsAndBothOutputStreams(): void
	{
		$hostile = '<script>alert("DDR")</script> & \'label\'';
		$panel = $this->panel(['notice' => '', 'queried' => '2026-11-04 21:37:22 UTC', 'rows' => [[
			'interface' => $hostile, 'identity' => 'Managed Resolver VIP', 'address' => '192.0.2.53:53',
			'state' => 'advertised', 'stdout' => self::ANSWERS, 'stderr' => $hostile,
		]]]);
		$section = "//div[@id='pfb-dns-status-ddr']";
		$this->assertSame(1, $panel->query($section)->length, 'the pfB-DNS status surface includes DDR observations');
		$this->assertSame('DDR Advertisements', $panel->evaluate("string({$section}/div/h2)"));
		$this->assertSame($hostile, $panel->evaluate("string({$section}//tbody/tr/td[1])"));
		$this->assertSame('Managed Resolver VIP', $panel->evaluate("string({$section}//tbody/tr/td[2])"));
		$this->assertSame('192.0.2.53:53', $panel->evaluate("string({$section}//tbody/tr/td[3])"));
		$this->assertSame('Advertised', $panel->evaluate("string({$section}//tbody/tr/td[4]/strong)"));
		$this->assertSame(self::ANSWERS, $panel->evaluate("string({$section}//pre[@class='pfb-dns-ddr-stdout'])"));
		$this->assertSame($hostile, $panel->evaluate("string({$section}//pre[@class='pfb-dns-ddr-stderr'])"));
		$this->assertSame(0, $panel->query("{$section}//script")->length);
		$text = $panel->evaluate("string({$section})");
		$this->assertStringContainsString('2026-11-04 21:37:22 UTC', $text);
		$this->assertStringContainsString('protocol default', $text);
		$this->assertStringContainsString('does not prove', $text);
		$this->assertStringNotContainsString('endpoint working', strtolower($text));
	}

	public function testRefreshIsReadOnlyAndThePanelAndRawOutputScrollInsideTheSection(): void
	{
		$panel = $this->panel(['notice' => '', 'queried' => NULL, 'rows' => [[
			'interface' => 'LAN', 'identity' => 'Interface', 'address' => '[2001:db8::1]:5353',
			'state' => 'not_queried', 'stdout' => '', 'stderr' => '',
		]]]);
		$section = "//div[@id='pfb-dns-status-ddr']";
		$this->assertSame('Toggle DDR Advertisements', $panel->evaluate("string({$section}//a[@data-toggle='collapse']/@aria-label)"));
		$this->assertSame('#pfb-dns-status-ddr_panel-body', $panel->evaluate("string({$section}//a[@data-toggle='collapse']/@href)"));
		$this->assertSame('pfblockerng_dns.php?refresh_ddr=1#pfb-dns-status-ddr', $panel->evaluate("string({$section}//a[@id='pfb-dns-ddr-refresh']/@href)"));
		$this->assertSame('Refresh DDR advertisements', $panel->evaluate("string({$section}//a[@id='pfb-dns-ddr-refresh'])"));
		$this->assertSame(1, $panel->query("{$section}//div[@class='table-responsive']/table")->length);
		$this->assertStringContainsString('Not yet queried', $panel->evaluate("string({$section})"));
		$this->assertSame(0, $panel->query("{$section}//form | {$section}//input")->length, 'refresh submits no configuration');
	}

	/** @return array<string,array{string,string}> */
	public static function outcomes(): array
	{
		return [
			'no refresh' => ['not_queried', 'Not yet queried'],
			'whole-request budget' => ['budget', 'Not queried: request deadline reached'],
			'drill timeout' => ['timeout', 'Query timed out'],
			'drill failure' => ['error', 'Query error'],
			'empty response' => ['empty', 'NOERROR, no advertisements'],
		];
	}

	#[DataProvider('outcomes')]
	public function testEachNonAdvertisementOutcomeIsExplicit(string $state, string $meaning): void
	{
		$panel = $this->panel(['notice' => '', 'queried' => NULL, 'rows' => [[
			'interface' => 'OPT1', 'identity' => 'Manual VIP: guest', 'address' => '[2001:db8::53]:5353',
			'state' => $state, 'stdout' => '', 'stderr' => '',
		]]]);
		$this->assertSame($meaning, $panel->evaluate("string(//div[@id='pfb-dns-status-ddr']//tbody/tr/td[4]/strong)"));
		$this->assertSame('Manual VIP: guest', $panel->evaluate("string(//div[@id='pfb-dns-status-ddr']//tbody/tr/td[2])"));
	}

	/** @return array<string,array{string,string,int,string}> */
	public static function responses(): array
	{
		return [
			'actual advertisements' => [self::ANSWERS, '', 0, 'advertised'],
			'NOERROR with no advertisements' => [";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 1\n;; flags: qr ; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n", '', 0, 'empty'],
			'refused is not empty' => [";; ->>HEADER<<- opcode: QUERY, rcode: REFUSED, id: 1\n;; flags: qr ; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n", '', 0, 'error'],
			'NXDOMAIN is not empty' => [";; ->>HEADER<<- opcode: QUERY, rcode: NXDOMAIN, id: 1\n;; flags: qr ; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0\n", '', 0, 'error'],
			'incomplete header is not success' => [';; ANSWER: 3', '', 0, 'error'],
			'no header is not empty' => ['', '', 0, 'error'],
			'process failed despite stdout' => [self::ANSWERS, 'socket failed\n', 1, 'error'],
			'deadline' => ['', 'partial stderr\n', 124, 'timeout'],
			'kill grace' => ['partial stdout\n', '', 137, 'timeout'],
		];
	}

	#[DataProvider('responses')]
	public function testOnlySuccessfulNoerrorResponsesAreAdvertisementsOrEmpty(string $stdout, string $stderr, int $exit, string $state): void
	{
		$this->assertTrue(function_exists('pfb_dns_ddr_result'), 'DDR query results must distinguish advertisements, empty, errors and timeouts');
		$result = pfb_dns_ddr_result($stdout, $stderr, $exit);
		$this->assertSame($state, $result['state']);
		$this->assertSame($stdout, $result['stdout'], 'complete stdout remains available for display');
		$this->assertSame($stderr, $result['stderr'], 'complete stderr remains available for display');
	}

	/** @return array<string,array{string}> */
	public static function hostileListeners(): array
	{
		return [
			'shell metacharacters' => ['127.0.0.1:53; touch /tmp/ddr'],
			'host name' => ['dns.example.com:53'],
			'zero port' => ['127.0.0.1:0'],
			'oversized port' => ['127.0.0.1:65536'],
			'noncanonical port' => ['127.0.0.1:053'],
			'IPv6 without brackets' => ['::1:53'],
			'IPv6 zone' => ['[fe80::1%em0]:53'],
			'noncanonical IPv6' => ['[2001:0db8::1]:53'],
			'mapped IPv6' => ['[::ffff:192.0.2.1]:53'],
			'empty' => [''],
		];
	}

	#[DataProvider('hostileListeners')]
	public function testInvalidListenersCannotBecomeProbeTargets(string $listener): void
	{
		$this->assertTrue(function_exists('pfb_dns_ddr_probe'), 'DDR probes validate current listener addresses before launching drill');
		$result = pfb_dns_ddr_probe($listener, 2.0);
		$this->assertSame('error', $result['state']);
		$this->assertSame('', $result['stdout']);
		$this->assertStringContainsString('Invalid bound listener', $result['stderr']);
	}
}
