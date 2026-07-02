<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * is_ipaddrv4() / is_ipaddrv6() / is_ipaddr() / is_linklocal() — pin the
 * pfsense_doubles.php behavioural doubles to REAL pfSense util.inc semantics
 * (verified against pfSense master and the CE-2.8.0-era source at commit
 * 4ecba17, 2025-03-26 — the youngest util.inc change before the CE 2.8.0
 * release; both bodies identical, including the redmine #16005 try/catch,
 * which the filter_var() stand-in absorbs since it cannot throw).
 *
 * Regression for two doubles that modeled util.inc wrongly (issue #721):
 *   - is_ipaddrv4() did an ip2long()/long2ip() ROUND-TRIP that real pfSense
 *     never does; real pfSense is a bare `ip2long($ipaddr) === FALSE` check.
 *     PHP's ip2long() delegates to libc inet_pton(AF_INET), which accepts only
 *     the canonical dotted-quad — leading-zero octets ('192.000.002.005') are
 *     rejected on BOTH FreeBSD (the pfSense/CE target; inet_pton4's
 *     leading-zero guard) and glibc — so the old round-trip was behaviourally
 *     equivalent for v4 and this is a control-flow-fidelity fix (mirror
 *     upstream verbatim, prevent future drift), not a verdict flip.
 *   - is_ipaddrv6() stripped ANY '%zone' suffix before validating. Real
 *     pfSense strips it ONLY when the address is link-local (is_linklocal()),
 *     so a non-link-local zoned address ('2001:db8::1%em0') was wrongly
 *     accepted by the old double instead of failing validation. This flip IS
 *     observable off-appliance (confirmed red on the old double, green here).
 */
#[CoversFunction('is_ipaddrv4')]
#[CoversFunction('is_ipaddrv6')]
#[CoversFunction('is_ipaddr')]
#[CoversFunction('is_linklocal')]
final class IpAddrDoublesTest extends TestCase
{
	// --- is_ipaddrv4() --------------------------------------------------------

	public static function v4Provider(): array
	{
		return [
			// Rejected on-box and off: ip2long()/inet_pton() accepts only the
			// canonical dotted-quad on FreeBSD and glibc alike (see class
			// docblock) — old and fixed doubles agree here; the pinned oracle
			// is the real pfSense verdict.
			'leading-zero octets rejected (inet_pton is canonical-only)' => ['192.000.002.005', false],
			'plain dotted-quad accepted'   => ['192.0.2.5', true],
			'three-octet form rejected'    => ['1.2.3', false],
			'out-of-range octet rejected'  => ['256.1.1.1', false],
			'empty string rejected'        => ['', false],
			'non-string int rejected'      => [42, false],
			'non-string null rejected'     => [null, false],
			'non-string array rejected'    => [['192.0.2.5'], false],
		];
	}

	#[DataProvider('v4Provider')]
	public function testIsIpaddrv4(mixed $input, bool $expected): void
	{
		$this->assertSame($expected, is_ipaddrv4($input));
	}

	// --- is_ipaddrv6() --------------------------------------------------------

	public static function v6Provider(): array
	{
		return [
			'plain v6 accepted' => ['2001:db8::1', true],
			// The flip: a NON-link-local zoned address keeps its '%zone' (real
			// pfSense strips '%zone' only for a link-local address) and then
			// fails validation -- the old double stripped every '%zone' first
			// and wrongly accepted it.
			'non-linklocal zoned address rejected'     => ['2001:db8::1%em0', false],
			'linklocal zone stripped, accepted'        => ['fe80::1%em0', true],
			'linklocal zone strip is case-insensitive' => ['FE80::1%igb0', true],
			'cidr-suffixed address rejected'           => ['2001:db8::1/64', false],
			'double compression rejected'              => ['1::2::3', false],
			'empty string rejected'                    => ['', false],
			'non-string int rejected'                  => [42, false],
		];
	}

	#[DataProvider('v6Provider')]
	public function testIsIpaddrv6(mixed $input, bool $expected): void
	{
		$this->assertSame($expected, is_ipaddrv6($input));
	}

	// --- is_linklocal() --------------------------------------------------------

	public static function linklocalProvider(): array
	{
		return [
			'v4 link-local (169.254/16) -> 4'      => ['169.254.1.1', 4],
			'v6 link-local (fe80::) -> 6'          => ['fe80::1', 6],
			'v6 link-local /10 upper bound -> 6'   => ['febf::1', 6],
			'v6 just past /10 (site-local) falsy'  => ['fec0::1', false],
			'v6 non-linklocal -> false'            => ['2001:db8::1', false],
			'v4 non-linklocal -> false'            => ['10.0.0.1', false],
		];
	}

	#[DataProvider('linklocalProvider')]
	public function testIsLinklocal(string $input, int|bool $expected): void
	{
		$this->assertSame($expected, is_linklocal($input));
	}

	// --- is_ipaddr() (existing double, unchanged) ------------------------------
	//
	// pfb_get_vips() switches on case 4/6, so the 4/6 bucketing (not a loose
	// bool) is the load-bearing contract -- one assertion per bucket.

	public function testIsIpaddrBucketsV4AddressAsFour(): void
	{
		$this->assertSame(4, is_ipaddr('192.0.2.5'));
	}

	public function testIsIpaddrBucketsV6AddressAsSix(): void
	{
		$this->assertSame(6, is_ipaddr('2001:db8::1'));
	}

	public function testIsIpaddrReturnsFalseForNonAddress(): void
	{
		$this->assertFalse(is_ipaddr('not-an-ip'));
	}
}
