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
		$result = pfb_ip_parse_line('JKS Media, LLC:4.53.2.12-4.53.2.15', $config);
		$this->assertSame(['4.53.2.12/30'], $result['entries']);
		$this->assertSame(0, $result['parse_fail_delta']);
		$this->assertFalse($result['detailed_parse_fail']);

		$result = pfb_ip_parse_line('192.0.2.1-192.0.2.2', $config);
		$this->assertSame(['192.0.2.1', '192.0.2.2'], $result['entries']);
	}

	public function testIpv4RegexDeduplicatesAndSkipsCloudflare(): void
	{
		$config = $this->config('_v4', 'regex');
		$result = pfb_ip_parse_line('from 1.2.3.4 to 1.2.3.4 and 5.6.7.8', $config);
		$this->assertSame(['1.2.3.4', '5.6.7.8'], $result['entries']);
		$this->assertSame(0, $result['parse_fail_delta']);
		$this->assertSame([], pfb_ip_parse_line('cf-footer-item 1.2.3.4', $config)['entries']);
		$this->assertSame([], pfb_ip_parse_line('version 1.2.3', $config)['entries']);
	}

	public function testIpv4SuppressionFloorReplaysCoreMessage(): void
	{
		$config = $this->config('_v4', 'auto', FALSE, 'on', 24);
		$result = pfb_ip_parse_line('8.8.8.0/16', $config);
		$this->assertSame(['8.8.8.0/32'], $result['entries']);
		$this->assertSame(["\n  Suppression CIDR Limit: 8.8.8.0/16"], $result['messages']);
	}

	public function testIpv4RegexRangeCountsEachSuppressedExpandedCidr(): void
	{
		$result = pfb_ip_parse_line(
			'192.0.2.1-192.0.2.10',
			$this->config('_v4', 'regex', FALSE, 'on')
		);
		$this->assertSame([], $result['entries']);
		$this->assertSame(5, $result['parse_fail_delta']);
		$this->assertFalse($result['detailed_parse_fail']);
	}

	public function testMalformedNumericLineRequestsDetailedParseFailureButAlphabeticIsSilent(): void
	{
		$config = $this->config('_v4');
		$result = pfb_ip_parse_line('999.999.999.999', $config);
		$this->assertSame([], $result['entries']);
		$this->assertSame(1, $result['parse_fail_delta']);
		$this->assertTrue($result['detailed_parse_fail']);
		$this->assertSame(0, pfb_ip_parse_line('not-an-address', $config)['parse_fail_delta']);
		$this->assertSame(0, pfb_ip_parse_line('0', $config)['parse_fail_delta']);
	}

	public function testOppositeFamilyIsSilentlySkipped(): void
	{
		$v4 = pfb_ip_parse_line('2001:db8::1', $this->config('_v4'));
		$this->assertSame([], $v4['entries']);
		$this->assertSame(0, $v4['parse_fail_delta']);
		$v6 = pfb_ip_parse_line('192.0.2.1', $this->config('_v6'));
		$this->assertSame([], $v6['entries']);
		$this->assertSame(0, $v6['parse_fail_delta']);
	}

	public function testIpv6AutoCanonicalisesCommentsAndMarksSuppression(): void
	{
		$config = $this->config('_v6');
		$result = pfb_ip_parse_line('2001:0db8::1 # note', $config);
		$this->assertSame(['2001:db8::1'], $result['entries']);
		$this->assertSame('2001:0db8::1 ', $result['line']);
		$suppressed = pfb_ip_parse_line('fc00::1', $this->config('_v6', 'auto', FALSE, 'on'));
		$this->assertSame([], $suppressed['entries']);
		$this->assertTrue($suppressed['suppressed']);
	}

	public function testIpv6RangeAndMalformedRangeFallThroughToRegexOrFailure(): void
	{
		$config = $this->config('_v6');
		$result = pfb_ip_parse_line('2001:db8::1-2001:db8::2', $config);
		$this->assertSame(['2001:db8::1/128', '2001:db8::2/128'], $result['entries']);
		$badConfig = $config;
		$badConfig['ipv6'] = '/(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})/';
		$malformed = pfb_ip_parse_line('1234:5678', $badConfig);
		$this->assertSame(1, $malformed['parse_fail_delta']);
		$this->assertTrue($malformed['detailed_parse_fail']);
	}

	public function testIpv6RegexDeduplicatesCloudflareAndComments(): void
	{
		$config = $this->config('_v6', 'regex');
		$result = pfb_ip_parse_line('from 2001:db8::1#note to 2001:db8::1', $config);
		$this->assertSame(['2001:db8::1'], $result['entries']);
		$this->assertSame([], pfb_ip_parse_line('cf-footer-item 2001:db8::1', $config)['entries']);
		$this->assertSame([], pfb_ip_parse_line('plain-hostname', $config)['entries']);
	}

	public function testHostileWhitespaceQuotesAndInvalidUtf8StayPure(): void
	{
		$config = $this->config('_v4', 'regex');
		$this->assertSame(['1.2.3.4'], pfb_ip_parse_line("\t 1.2.3.4  \t", $config)['entries']);
		$quoted = pfb_ip_parse_line('"1.2.3.4"', $config);
		$this->assertSame(['1.2.3.4'], $quoted['entries']);
		$this->assertSame(0, $quoted['parse_fail_delta']);
		$invalid = pfb_ip_parse_line("\xFF1.2.3.4", $config);
		$this->assertIsArray($invalid);
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
		$result = pfb_ip_parse_line($line, $this->config('_v4'));
		$this->assertSame([], $result['entries']);
		$this->assertSame(1, $result['parse_fail_delta']);
		$this->assertSame(100000, strlen($result['line']));
	}

	public function testIpv4AutoMalformedRangeFallsThroughToRegex(): void
	{
		$result = pfb_ip_parse_line('1.2.3.4-1.2.3.5-extra', $this->config('_v4'));
		$this->assertSame(['1.2.3.4/31'], $result['entries']);
		$this->assertSame(0, $result['parse_fail_delta']);
	}

	public function testIpv6EmptyAndInvalidRangesDoNotEmitEntries(): void
	{
		$config = $this->config('_v6');
		$config['ipv6'] = '/(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})/';
		foreach (['2001:db8::1-', '1234:5678-1234:5678'] as $line) {
			$result = pfb_ip_parse_line($line, $config);
			$this->assertSame([], $result['entries'], $line);
			$this->assertSame(0, $result['parse_fail_delta'], $line);
		}
	}
}
