<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class IpParseLineWiringTest extends TestCase
{
	/** @return array{vtype:string,pftype:string,custom:bool,cidr_floor_v4:int|string,cidr_floor_v6:int|string,suppression:string,range:string,ipv4:string,ipv6:string} */
	private function config(string $vtype, string $pftype = 'regex', string $suppression = 'off'): array
	{
		return [
			'vtype'         => $vtype,
			'pftype'        => $pftype,
			'custom'        => FALSE,
			'cidr_floor_v4' => 'Disabled',
			'cidr_floor_v6' => 'Disabled',
			'suppression'   => $suppression,
			'range'         => pfb_ip_regex_config()['range'],
			'ipv4'          => pfb_ip_regex_config()['ipv4'],
			'ipv6'          => pfb_ip_regex_config()['ipv6'],
		];
	}

	public function testReplayAppendsEntriesInParserOrderAndAdvancesLineNumber(): void
	{
		$ip_data = "10.0.0.1\n";
		$state = pfb_ip_parse_line_replay(
			"from 192.0.2.1 to 198.51.100.7\n",
			$this->config('_v4'),
			4,
			$ip_data,
			FALSE,
			2
		);

		$this->assertSame(5, $state['line_number']);
		$this->assertSame("from 192.0.2.1 to 198.51.100.7", $state['line']);
		$this->assertSame("10.0.0.1\n192.0.2.1\n198.51.100.7\n", $ip_data);
		$this->assertFalse($state['ip_suppressed']);
		$this->assertSame(2, $state['parse_fail']);
		$this->assertSame([], $state['messages']);
		$this->assertFalse($state['detailed_parse_fail']);
	}

	/** #3121: the caller's variable is the only accumulator; the result carries no copy of it. */
	public function testReplayAppendsToTheCallerAccumulatorInPlace(): void
	{
		$ip_data = '';
		foreach (["192.0.2.1\n", "192.0.2.2\n", "192.0.2.3\n"] as $line) {
			$state = pfb_ip_parse_line_replay($line, $this->config('_v4', 'auto'), 0, $ip_data, FALSE, 0);
			$this->assertArrayNotHasKey('ip_data', $state, 'result must not carry a second copy of the accumulator');
		}

		$this->assertSame("192.0.2.1\n192.0.2.2\n192.0.2.3\n", $ip_data);
	}

	public function testReplayCarriesV6SuppressionAndExistingState(): void
	{
		$ip_data = '';
		$state = pfb_ip_parse_line_replay(
			'fc00::1',
			$this->config('_v6', 'auto', 'on'),
			0,
			$ip_data,
			TRUE,
			1
		);

		$this->assertSame(1, $state['line_number']);
		$this->assertSame('fc00::1', $state['line']);
		$this->assertSame('', $ip_data);
		$this->assertTrue($state['ip_suppressed']);
		$this->assertSame(1, $state['parse_fail']);
		$this->assertSame([], $state['messages']);
	}

	public function testReplayReturnsDetailedFailureWithRawLineForDiagnostics(): void
	{
		$ip_data = '';
		$state = pfb_ip_parse_line_replay(
			" 999.999.999.999 \n",
			$this->config('_v4', 'auto'),
			9,
			$ip_data,
			FALSE,
			0
		);

		$this->assertSame(10, $state['line_number']);
		$this->assertSame('999.999.999.999', $state['line']);
		$this->assertSame(1, $state['parse_fail']);
		$this->assertTrue($state['detailed_parse_fail']);
		$this->assertSame(" 999.999.999.999 \n", $state['raw_line']);
	}

	/** #993: the live sync/download/firewall monolith is unsafe off-appliance; comments are stripped. */
	public function testLiveFeedDispatchUsesReplaySeam(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertStringContainsString(
			'$replayed_line = pfb_ip_parse_line_replay($line',
			$source,
			'live feed dispatch must replay parser state before writing firewall alias data'
		);
	}
}
