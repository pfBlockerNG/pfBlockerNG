<?php

declare(strict_types=1);

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
 *     PHP's ip2long() delegates to libc inet_pton(AF_INET), whose treatment of
 *     leading-zero octets ('192.000.002.005') is PLATFORM-DEPENDENT: FreeBSD
 *     (the pfSense/CE target; inet_pton4's leading-zero guard) and glibc
 *     reject them, but macOS ACCEPTS them (all three verdicts executed
 *     2026-07-18 — full probe matrix in pfsense_doubles.php's header NOTE;
 *     issue #1468). The double therefore pins the APPLIANCE verdict with an
 *     explicit leading-zero reject after the bare ip2long() check, so its
 *     answers are identical on every dev platform (see the pinned
 *     v4Provider rows).
 *   - is_ipaddrv6() stripped ANY '%zone' suffix before validating. Real
 *     pfSense strips it ONLY when the address is link-local (is_linklocal()),
 *     so a non-link-local zoned address ('2001:db8::1%em0') was wrongly
 *     accepted by the old double instead of failing validation. This flip IS
 *     observable off-appliance (confirmed red on the old double, green here).
 *
 * No #[CoversFunction] here: the covered functions are the test doubles in
 * tests/php/pfsense_doubles.php, and coverage targets must live in phpunit.xml's
 * <source> (production files only) — php-code-coverage >= 12 warns otherwise.
 */
final class IpAddrDoublesTest extends TestCase
{
	// --- is_ipaddrv4() --------------------------------------------------------

	public static function v4Provider(): array
	{
		return [
			// Leading-zero octets are LIBC-DEPENDENT (#723): FreeBSD (the
			// pfSense target) and glibc (CI) reject them at inet_pton(), but
			// macOS accepts them (all three probed — see the header NOTE in
			// pfsense_doubles.php, #1468). The double pins the FreeBSD/appliance
			// verdict with an explicit leading-zero reject, so these rows are
			// CONSTANT on every dev platform — including a Mac dev box, where a
			// bare ip2long() double would wrongly accept them. The single-zero
			// rows pin the guard's boundary: a '0' octet with no second digit is
			// canonical and must stay accepted (probed accepted on all three
			// platforms); they fail if the reject is ever widened past
			// leading-zero shapes.
			'plain dotted-quad accepted'                  => ['192.0.2.5', true],
			'single-zero octets accepted (boundary)'      => ['0.0.0.0', true],
			'single-zero first octet accepted (boundary)' => ['0.1.2.3', true],
			'leading-zero octets rejected (pinned)'       => ['192.000.002.005', false],
			'leading-zero first octet rejected (pinned)'  => ['010.0.0.1', false],
			'three-octet form rejected'                   => ['1.2.3', false],
			'out-of-range octet rejected'                 => ['256.1.1.1', false],
			'empty string rejected'                       => ['', false],
			'non-string int rejected'                     => [42, false],
			'non-string null rejected'                    => [null, false],
			'non-string array rejected'                   => [['192.0.2.5'], false],
		];
	}

	#[DataProvider('v4Provider')]
	public function testIsIpaddrv4(mixed $input, bool $expected): void
	{
		$this->assertSame($expected, is_ipaddrv4($input));
	}

	public function testIsIpaddrv4LeadingZeroVerdictIsPlatformIndependent(): void
	{
		// The #1468 pin: even where the LOCAL libc accepts a leading-zero octet
		// (macOS), the double must still return the appliance verdict (reject).
		// Replaces the old mechanism-parity assertion, which followed the local
		// ip2long() and so gave a different verdict on a Mac dev box.
		$this->assertFalse(is_ipaddrv4('192.000.002.005'),
			'expected: leading-zero octet rejected regardless of local ip2long() verdict '
			. '(local ip2long acceptance: ' . var_export(ip2long('192.000.002.005') !== false, true) . ')');
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

	// --- is_port() (double aligned with upstream util.inc, #723) ---------------

	public static function portProvider(): array
	{
		return [
			'numeric low bound'        => ['1', true],
			'numeric high bound'       => ['65535', true],
			'zero rejected'            => ['0', false],
			'above range rejected'     => ['65536', false],
			'service name domain'      => ['domain', true],
			'service name http'        => ['http', true],
			'unknown name rejected'    => ['no-such-service-xyz', false],
		];
	}

	#[DataProvider('portProvider')]
	public function testIsPort(string $input, bool $expected): void
	{
		$this->assertSame($expected, is_port($input),
			"is_port({$input}) must match upstream util.inc (digits 1..65535 OR getservbyname)");
	}

	public function testIsPortNameRejectedWhenValidateNameOff(): void
	{
		// The \$validate_name=false branch: service names are rejected, digits still pass.
		$this->assertFalse(is_port('domain', false));
		$this->assertTrue(is_port('53', false));
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
