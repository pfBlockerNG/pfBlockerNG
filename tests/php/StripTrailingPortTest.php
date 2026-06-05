<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_strip_trailing_port() — strip a ":<port>" from a host:port DNSBL feed line
 * WITHOUT mangling a bare IPv6 literal.
 *
 * Regression for the DNSBL-IP dual-stack partition (ex-issue #35): the old inline
 * /:[0-9]{1,5}$/ rewrite fired on every colon-bearing line, so an IPv6 literal like
 * '2001:db8:5::7' (which ends in ':<hextet>') was rewritten to the invalid
 * '2001:db8:5:'. is_ipaddrv6() then rejected it and the IP was dropped, leaving
 * pfB_DNSBLIP_v6 holding only the '::<placeholder>' sentinel. The guard preserves
 * every valid IPv6 literal while stripping ports from all non-v6 lines exactly as
 * before.
 */
#[CoversFunction('pfb_strip_trailing_port')]
final class StripTrailingPortTest extends TestCase
{
	public static function provider(): array
	{
		return [
			// The bug: an IPv6 literal whose trailing hextet the old regex mangled.
			'v6 trailing :hextet preserved'  => ['2001:db8:5::7', '2001:db8:5::7'],
			'v6 :: + single digit preserved' => ['2001:db8::1', '2001:db8::1'],
			'v6 full form preserved'         => ['2001:db8:0:0:0:0:0:1', '2001:db8:0:0:0:0:0:1'],
			'v4-mapped v6 preserved'         => ['::ffff:1.2.3.4', '::ffff:1.2.3.4'],
			// Non-v6 lines: the port IS stripped, exactly as before the guard.
			'host:port stripped'             => ['evil.com:8080', 'evil.com'],
			'ipv4:port stripped'             => ['1.2.3.4:8080', '1.2.3.4'],
			'host:port max 5 digits'         => ['evil.com:65535', 'evil.com'],
			// No trailing :port -> untouched.
			'bare ipv4 untouched'            => ['203.0.113.7', '203.0.113.7'],
			'bare domain untouched'          => ['example.com', 'example.com'],
			'six-digit suffix not a port'    => ['evil.com:123456', 'evil.com:123456'],
		];
	}

	#[DataProvider('provider')]
	public function testStrip(string $line, string $expected): void
	{
		$this->assertSame($expected, pfb_strip_trailing_port($line));
	}

	/**
	 * The partition invariant end-to-end through is_ipaddrv6(): the v6 literal must
	 * STILL validate as IPv6 after the strip (the old regex broke exactly this, so the
	 * v6 IP never reached pfB_DNSBLIP_v6). Asserts the before-state (input is v6) and
	 * the after-state (output is still v6) so green proves the guard caused the fix.
	 */
	public function testIpv6SurvivesStripAndStillValidates(): void
	{
		$v6 = '2001:db8:5::7';
		$this->assertTrue(is_ipaddrv6($v6), 'precondition: input is a valid IPv6 literal');
		$out = pfb_strip_trailing_port($v6);
		$this->assertSame($v6, $out, 'IPv6 literal must pass through unchanged');
		$this->assertTrue(is_ipaddrv6($out), 'IPv6 literal must STILL validate after the strip');
	}
}
