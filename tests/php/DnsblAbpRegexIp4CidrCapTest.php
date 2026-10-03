<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

/**
 * Issue #3434: the 256-CIDR cap on its own. Each third-octet value below yields two CIDRs ('.0/31' and '.2/32'),
 * so these rules stay at or under 256 merged intervals and only the CIDR count decides. A count of 257 cannot
 * occur: with a partial fourth octet the count is |values| x CIDRs per /24, and a full one tops out at 128 per /16.
 */
#[CoversFunction('pfb_dnsbl_abp_regex_ip4_cidrs')]
final class DnsblAbpRegexIp4CidrCapTest extends TestCase
{
	use PfbNoPhpWarningTrait;

	public function testTwoHundredFiftySixCidrsFromOneHundredTwentyEightIntervalsAreKept(): void
	{
		$expected = [];
		foreach (range(0, 127) as $c) {
			$expected[] = "5.8.$c.0/31";
			$expected[] = "5.8.$c.2/32";
		}
		$rule = '/^5\.8\.(\d{1,2}|1[01]\d|12[0-7])\.[0-2]$/';
		$this->assertSame($expected, $this->assertNoPhpWarning(static fn(): array => pfb_dnsbl_abp_regex_ip4_cidrs($rule, 'testfeed')));
	}

	public function testTwoHundredFiftyEightCidrsFromOneHundredTwentyNineIntervalsAreRefused(): void
	{
		$rule = '/^5\.8\.(\d{1,2}|1[01]\d|12[0-8])\.[0-2]$/';
		$this->assertSame([], $this->assertNoPhpWarning(static fn(): array => pfb_dnsbl_abp_regex_ip4_cidrs($rule, 'testfeed')));
	}
}
