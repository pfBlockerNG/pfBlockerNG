<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Direct matrix for the pure generic IP-feed line parser extracted from the
 * sync loop.  The result array is the complete handoff contract to that loop.
 */
#[CoversFunction('pfb_ip_parse_line')]
final class IpParseLineTest extends TestCase
{
	private const RANGE = '/((?:\d{1,3}\.){3}\d{1,3})-((?:\d{1,3}\.){3}\d{1,3})/';
	private const IPV4 = '/(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/\d{1,2})?/';
	private const IPV6 = '/[0-9A-Fa-f:]+(?:\/\d{1,3})?/';

	/** @return array{vtype:string,pftype:string,custom:bool,cidr_floor_v4:int|string,cidr_floor_v6:int|string,suppression:string,range:string,ipv4:string,ipv6:string} */
	private function config(string $vtype, string $pftype = 'auto', bool $custom = TRUE, string $suppression = 'off', int|string $v4Floor = 'Disabled', int|string $v6Floor = 'Disabled'): array
	{
		return [
			'vtype'         => $vtype,
			'pftype'        => $pftype,
			'custom'        => $custom,
			'cidr_floor_v4' => $v4Floor,
			'cidr_floor_v6' => $v6Floor,
			'suppression'   => $suppression,
			'range'         => self::RANGE,
			'ipv4'          => self::IPV4,
			'ipv6'          => self::IPV6,
		];
	}

	/** @param array<string,mixed> $expected */
	private function assertLine(string $raw, array $config, array $expected): void
	{
		$this->assertSame($expected, pfb_ip_parse_line($raw, $config), "unexpected result for {$raw}");
	}

	/**
	 * @param array{entries?:list<string>,suppressed?:bool,parse_fail_delta?:int,detailed_parse_fail?:bool,messages?:list<string>} $overrides
	 * @return array{entries:list<string>,line:string,suppressed:bool,parse_fail_delta:int,detailed_parse_fail:bool,messages:list<string>}
	 */
	private function expectedResult(string $line, array $overrides = []): array
	{
		return array_replace([
			'entries'             => [],
			'line'                => $line,
			'suppressed'          => FALSE,
			'parse_fail_delta'    => 0,
			'detailed_parse_fail' => FALSE,
			'messages'            => [],
		], $overrides);
	}

	public function testBlankAndCommentPrefixesAreSkippedAfterTrim(): void
	{
		$config = $this->config('_v4');
		foreach (["  \n", ' # comment', ' ! generated', ' // generated'] as $line) {
			$this->assertLine($line, $config, [
				'entries' => [], 'line' => trim($line), 'suppressed' => FALSE,
				'parse_fail_delta' => 0, 'detailed_parse_fail' => FALSE, 'messages' => [],
			]);
		}
	}

	public function testIpv4AutoHostCidrAndCommentsPreserveOrder(): void
	{
		$config = $this->config('_v4');
		$this->assertLine("  1.2.3.4/32 # trailing\n", $config, [
			'entries' => ['1.2.3.4'], 'line' => '1.2.3.4/32', 'suppressed' => FALSE,
			'parse_fail_delta' => 0, 'detailed_parse_fail' => FALSE, 'messages' => [],
		]);
		$this->assertLine('1.2.3.0/24', $config, [
			'entries' => ['1.2.3.0/24'], 'line' => '1.2.3.0/24', 'suppressed' => FALSE,
			'parse_fail_delta' => 0, 'detailed_parse_fail' => FALSE, 'messages' => [],
		]);
	}

	public function testIpv4AutoIblockAndRangeExpand(): void
	{
		$config = $this->config('_v4');
		$this->assertLine('JKS Media, LLC:4.53.2.12-4.53.2.15', $config, $this->expectedResult(
			'4.53.2.12-4.53.2.15',
			['entries' => ['4.53.2.12/30']]
		));
		$this->assertLine('192.0.2.1-192.0.2.2', $config, $this->expectedResult(
			'192.0.2.1-192.0.2.2',
			['entries' => ['192.0.2.1', '192.0.2.2']]
		));
	}

	public function testIpv4RegexDeduplicatesAndSkipsCloudflare(): void
	{
		$config = $this->config('_v4', 'regex');
		$this->assertLine('from 1.2.3.4 to 1.2.3.4 and 5.6.7.8', $config, $this->expectedResult(
			'from 1.2.3.4 to 1.2.3.4 and 5.6.7.8',
			['entries' => ['1.2.3.4', '5.6.7.8']]
		));
		$this->assertLine('cf-footer-item 1.2.3.4', $config, $this->expectedResult('cf-footer-item 1.2.3.4'));
		$this->assertLine('version 1.2.3', $config, $this->expectedResult('version 1.2.3'));
	}

	public function testIpv4SuppressionFloorReplaysCoreMessage(): void
	{
		$config = $this->config('_v4', 'auto', FALSE, 'on', 24);
		$this->assertLine('8.8.8.0/16', $config, $this->expectedResult('8.8.8.0/16', [
			'entries'  => ['8.8.8.0/32'],
			'messages' => ["\n  Suppression CIDR Limit: 8.8.8.0/16"],
		]));
	}

	public function testIpv4RegexRangeCountsEachSuppressedExpandedCidr(): void
	{
		$this->assertLine(
			'192.0.2.1-192.0.2.10',
			$this->config('_v4', 'regex', FALSE, 'on'),
			$this->expectedResult('192.0.2.1-192.0.2.10', ['parse_fail_delta' => 5])
		);
	}

	public function testMalformedNumericLineRequestsDetailedParseFailureButAlphabeticIsSilent(): void
	{
		$config = $this->config('_v4');
		$this->assertLine('999.999.999.999', $config, $this->expectedResult('999.999.999.999', [
			'parse_fail_delta'    => 1,
			'detailed_parse_fail' => TRUE,
		]));
		$this->assertLine('not-an-address', $config, $this->expectedResult('not-an-address'));
		$this->assertLine('0', $config, $this->expectedResult('0'));
	}

	public function testOppositeFamilyIsSilentlySkipped(): void
	{
		$this->assertLine('2001:db8::1', $this->config('_v4'), $this->expectedResult('2001:db8::1'));
		$this->assertLine('192.0.2.1', $this->config('_v6'), $this->expectedResult('192.0.2.1'));
	}

	public function testIpv6AutoCanonicalisesCommentsAndMarksSuppression(): void
	{
		$config = $this->config('_v6');
		$this->assertLine('2001:0db8::1 # note', $config, $this->expectedResult(
			'2001:0db8::1 ',
			['entries' => ['2001:db8::1']]
		));
		$this->assertLine('fc00::1', $this->config('_v6', 'auto', FALSE, 'on'), $this->expectedResult(
			'fc00::1',
			['suppressed' => TRUE]
		));
	}

	public function testIpv6RangeAndMalformedRangeFallThroughToRegexOrFailure(): void
	{
		$config = $this->config('_v6');
		$this->assertLine('2001:db8::1-2001:db8::2', $config, $this->expectedResult(
			'2001:db8::1-2001:db8::2',
			['entries' => ['2001:db8::1/128', '2001:db8::2/128']]
		));
		$badConfig = $config;
		$badConfig['ipv6'] = '/(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})/';
		$this->assertLine('1234:5678', $badConfig, $this->expectedResult('1234:5678', [
			'parse_fail_delta'    => 1,
			'detailed_parse_fail' => TRUE,
		]));
	}

	public function testIpv6RegexDeduplicatesCloudflareAndComments(): void
	{
		$config = $this->config('_v6', 'regex');
		$this->assertLine('from 2001:db8::1#note to 2001:db8::1', $config, $this->expectedResult(
			'from 2001:db8::1#note to 2001:db8::1',
			['entries' => ['2001:db8::1']]
		));
		$this->assertLine('cf-footer-item 2001:db8::1', $config, $this->expectedResult('cf-footer-item 2001:db8::1'));
		$this->assertLine('plain-hostname', $config, $this->expectedResult('plain-hostname'));
	}

	public function testHostileWhitespaceQuotesAndInvalidUtf8StayPure(): void
	{
		$config = $this->config('_v4', 'regex');
		$this->assertLine("\t 1.2.3.4  \t", $config, $this->expectedResult('1.2.3.4', ['entries' => ['1.2.3.4']]));
		$this->assertLine('"1.2.3.4"', $config, $this->expectedResult('"1.2.3.4"', ['entries' => ['1.2.3.4']]));
		$this->assertLine("\xFF1.2.3.4", $config, $this->expectedResult("\xFF1.2.3.4", ['entries' => ['1.2.3.4']]));
	}

	public function testNonStringInputRaisesTypeErrorAtTrustBoundary(): void
	{
		$this->expectException(TypeError::class);
		/** @phpstan-ignore-next-line intentionally hostile non-string input */
		pfb_ip_parse_line([], $this->config('_v4'));
	}

	public function testOversizedNumericLineReturnsBoundedResultWithoutWriting(): void
	{
		$line = str_repeat('9', 100000);
		$this->assertLine($line, $this->config('_v4'), $this->expectedResult($line, [
			'parse_fail_delta'    => 1,
			'detailed_parse_fail' => TRUE,
		]));
	}

	public function testIpv4AutoMalformedRangeFallsThroughToRegex(): void
	{
		$this->assertLine('1.2.3.4-1.2.3.5-extra', $this->config('_v4'), $this->expectedResult(
			'1.2.3.4-1.2.3.5-extra',
			['entries' => ['1.2.3.4/31']]
		));
	}

	public function testIpv6EmptyAndInvalidRangesDoNotEmitEntries(): void
	{
		$config = $this->config('_v6');
		$config['ipv6'] = '/(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})/';
		foreach (['2001:db8::1-', '1234:5678-1234:5678'] as $line) {
			$this->assertLine($line, $config, $this->expectedResult($line));
		}
	}
}
