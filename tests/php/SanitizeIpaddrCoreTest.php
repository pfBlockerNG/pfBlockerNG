<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_sanitize_ipaddr')]
#[CoversFunction('pfb_sanitize_ipaddr_v6')]
final class SanitizeIpaddrCoreTest extends TestCase
{
	public function testIpv4CoreReturnsAddressAndClampMessage(): void
	{
		$this->assertSame(
			[
				'address' => '1.2.3.4',
				'messages' => ["\n  Feed /0 CIDR clamped to single host: 1.2.3.4/0"],
			],
			pfb_sanitize_ipaddr('1.2.3.4/0', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	public function testIpv4CoreCarriesFloorMessageBeforeDrop(): void
	{
		$this->assertSame(
			[
				'address' => NULL,
				'messages' => ["\n  Suppression CIDR Limit: 10.0.0.5/8"],
			],
			pfb_sanitize_ipaddr('10.0.0.5/8', FALSE, 24, PfbToggle::On)
		);
	}

	// issue #1922: 0.0.0.0 is never a valid entry under any mask, suppression
	// setting, or list type — the reject is unconditional, so even a custom
	// list's 0.0.0.0/0 (previously honored per issue #744) is dropped.
	public function testIpv4CoreRejectsZeroAddressEvenOnCustomList(): void
	{
		$this->assertSame(
			['address' => NULL, 'messages' => []],
			pfb_sanitize_ipaddr('0.0.0.0/0', TRUE, 'Disabled', PfbToggle::On)
		);
	}

	public function testIpv4CoreRejectsZeroAddressWithSuppressionOff(): void
	{
		$this->assertSame(
			['address' => NULL, 'messages' => []],
			pfb_sanitize_ipaddr('0.0.0.0', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	// issue #1922: the v6 sibling — '::' rejected under any mask, suppression
	// setting, or list type.
	public function testIpv6CoreRejectsAllZerosEvenOnCustomList(): void
	{
		$this->assertSame(
			['address' => NULL, 'messages' => []],
			pfb_sanitize_ipaddr_v6('::/0', TRUE, 'Disabled', PfbToggle::On)
		);
	}

	public function testIpv6CoreRejectsAllZerosWithSuppressionOff(): void
	{
		$this->assertSame(
			['address' => NULL, 'messages' => []],
			pfb_sanitize_ipaddr_v6('::', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	// A feed's ::/0 still logs the issue #744 clamp before the unconditional
	// reject drops the row — the clamp message is not silently lost.
	public function testIpv6CoreFeedZeroSlashZeroKeepsClampMessageBeforeReject(): void
	{
		$this->assertSame(
			[
				'address' => NULL,
				'messages' => ["\n  Feed /0 CIDR clamped to single host: ::/0"],
			],
			pfb_sanitize_ipaddr_v6('::/0', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	/**
	 * Scenario: an auto-typed feed ships a bare "IP/path" URL line.
	 *   Given a line whose first path segment is a small number (the #1922 shape)
	 *   When the IPv4 core sanitizer splits on '/'
	 *   Then the path segment is NOT read as a CIDR mask — the bare host is
	 *        recovered, matching the regex path's mask-internal guard outcome.
	 * Before, parts[2..] were silently discarded and '/1' became the prefix
	 * length (= 0.0.0.0/1 after aggregation — the issue #1922 outage shape).
	 */
	public function testIpv4CorePathSegmentsRecoverBareHostNotMask(): void
	{
		$this->assertSame(
			['address' => '84.38.133.113', 'messages' => []],
			pfb_sanitize_ipaddr('84.38.133.113/1/webpanel/login.php', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	// A '/0' path segment is path junk, not a feed /0 — the bare host comes
	// back WITHOUT the issue #744 clamp message (no mask was ever present).
	public function testIpv4CoreZeroPathSegmentIsNotAFeedZeroClamp(): void
	{
		$this->assertSame(
			['address' => '1.2.3.4', 'messages' => []],
			pfb_sanitize_ipaddr('1.2.3.4/0/path', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	// Custom lists get the same bare-host recovery: a path segment is never a
	// user-authored mask, so the custom /0-honor rule (issue #744) does not
	// apply either — a '/0' path segment on a custom list is still path junk.
	public function testIpv4CorePathSegmentsRecoverBareHostOnCustomList(): void
	{
		$this->assertSame(
			['address' => '1.2.3.4', 'messages' => []],
			pfb_sanitize_ipaddr('1.2.3.4/8/junk', TRUE, 'Disabled', PfbToggle::Off)
		);
		$this->assertSame(
			['address' => '1.2.3.4', 'messages' => []],
			pfb_sanitize_ipaddr('1.2.3.4/0/path', TRUE, 'Disabled', PfbToggle::Off)
		);
	}

	// Degenerate multi-slash shapes: an empty middle part or a trailing slash
	// also recover the bare host — only a genuine two-part 'addr/<n>' is a CIDR.
	public function testIpv4CoreDegenerateSlashShapesRecoverBareHost(): void
	{
		foreach (['1.2.3.4//24', '1.2.3.4/24/'] as $shape) {
			$this->assertSame(
				['address' => '1.2.3.4', 'messages' => []],
				pfb_sanitize_ipaddr($shape, FALSE, 'Disabled', PfbToggle::Off),
				"{$shape} must recover the bare host"
			);
		}
	}

	public function testIpv4CoreSuppressesReservedClassesWithoutMessages(): void
	{
		$addresses = [
			'zero'             => '0.0.0.0',
			'loopback'         => '127.0.0.1',
			'documentation'     => '192.0.2.1',
			'multicast'        => '224.0.0.1',
			'carrier-grade NAT' => '100.64.0.1',
			'benchmarking'      => '198.18.0.1',
			'6to4 relay'        => '192.88.99.1',
		];
		foreach ($addresses as $class => $address) {
			$this->assertSame(
				['address' => NULL, 'messages' => []],
				pfb_sanitize_ipaddr($address, FALSE, 'Disabled', PfbToggle::On),
				"{$class} address must be suppressed without a message"
			);
		}
	}

	public function testIpv6CoreReturnsCanonicalAddressAndClampMessage(): void
	{
		$this->assertSame(
			[
				'address' => '2001:db8::1',
				'messages' => ["\n  Feed /0 CIDR clamped to single host: 2001:DB8::1/0"],
			],
			pfb_sanitize_ipaddr_v6('2001:DB8::1/0', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	public function testIpv6CoreCarriesFloorMessageBeforeDrop(): void
	{
		$this->assertSame(
			[
				'address' => NULL,
				'messages' => ["\n  Suppression CIDR Limit: fc00::1/32"],
			],
			pfb_sanitize_ipaddr_v6('fc00::1/32', FALSE, 48, PfbToggle::On)
		);
	}

	public function testIpv6CoreDropsZoneWithoutMessages(): void
	{
		$this->assertSame(
			['address' => NULL, 'messages' => []],
			pfb_sanitize_ipaddr_v6('fe80::1%igb0', FALSE, 'Disabled', PfbToggle::Off)
		);
	}

	public function testIpv6CoreSuppressesReservedClassesWithoutMessages(): void
	{
		$addresses = [
			'unique-local'  => 'fc00::1',
			'link-local'    => 'fe80::1',
			'loopback'      => '::1',
			'documentation' => '2001:db8::1',
			'multicast'     => 'ff02::1',
			'NAT64'         => '64:ff9b::1',
		];
		foreach ($addresses as $class => $address) {
			$this->assertSame(
				['address' => NULL, 'messages' => []],
				pfb_sanitize_ipaddr_v6($address, FALSE, 'Disabled', PfbToggle::On),
				"{$class} address must be suppressed without a message"
			);
		}
	}
}
