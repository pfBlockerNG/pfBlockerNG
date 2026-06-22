<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_collect_localip() — local-IPv6 recognition for Reports/Alerts external-host detection.
 *
 * pfb_daemon_filterlog() uses pfb_collect_localip() to tell apart local and remote
 * hosts: if the destination IP is in the local set, the *source* is the external host
 * (inbound); otherwise the *destination* is external (outbound). When a local IPv6
 * address from a dynamic prefix (track6/dhcp6/SLAAC — where interfaces[x][ipaddr] is
 * a keyword like 'track6', not a literal IP) is not recognised as local, the local host
 * ends up being treated as the external host and GeoIP/ASN run against the user's own
 * ISP instead of the foreign source.
 *
 * Scenario: Local-IPv6 recognition in pfb_collect_localip()
 *   Background:
 *     Given a LAN interface using dynamic IPv6 (ipaddr='track6'), so the stored config
 *           entry carries no literal IPv6 address
 *     And   the interface's runtime IPv6 address is 2001:db8:1:2::1 /64 (fetched via
 *           get_configured_ipv6_addresses / get_interface_subnetv6 at runtime)
 *     And   a WAN interface with a static IPv4 192.168.1.1/24
 *
 *   Case A (local IPv6 — the bug):
 *     When pfb_collect_localip() is called
 *     Then an address inside the local /64 (e.g. 2001:db8:1:2::1234) MUST be
 *          recognised as local (isset in $pfb_local OR pfb_local_ip returns TRUE)
 *     [This assertion FAILS before the fix and PASSES after it]
 *
 *   Case B (external IPv6):
 *     When pfb_collect_localip() is called
 *     Then an address outside the local prefix (e.g. 2400:cb00::1, a well-known
 *          Cloudflare GUA outside the /64) must NOT be recognised as local
 *
 *   Case C (IPv4 unchanged):
 *     When pfb_collect_localip() is called
 *     Then a host inside the static IPv4 /24 (e.g. 192.168.1.42) is still recognised
 *          as local, proving the IPv4 path is byte-identical after the fix
 */
#[CoversFunction('pfb_collect_localip')]
#[CoversFunction('pfb_local_ip')]
final class CollectLocalIpV6Test extends TestCase
{
	/** Saved $GLOBALS state to restore after each test. */
	private bool $hadConfig = false;
	private array $savedConfig = [];

	/** The runtime IPv6 address the "track6" LAN interface resolves to. */
	private const LAN_IPV6_ADDR   = '2001:db8:1:2::1';
	private const LAN_IPV6_BITS   = 64;
	private const LAN_IPV6_SUBNET = '2001:db8:1:2::/64';

	/** An IPv6 inside the local /64. */
	private const LOCAL_IPV6_HOST = '2001:db8:1:2::1234';

	/** An IPv6 outside the local prefix — Cloudflare GUA, clearly not on our /64. */
	private const EXTERNAL_IPV6 = '2400:cb00::1';

	/** The static IPv4 WAN interface address and subnet. */
	private const WAN_IPV4_ADDR = '192.168.1.1';
	private const WAN_IPV4_BITS = 24;

	/** A host inside the IPv4 /24. */
	private const LOCAL_IPV4_HOST = '192.168.1.42';

	protected function setUp(): void
	{
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? [];

		// Minimal config: one dynamic-IPv6 LAN (track6), one static-IPv4 WAN, no VIPs/NAT.
		$GLOBALS['config'] = [
			'interfaces' => [
				'lan' => [
					'enable' => '',
					'ipaddr' => 'track6',    // dynamic — NOT a literal IPv6 addr
					'ipaddrv6' => 'track6',
					// No 'subnet' / 'subnetv6' here: the stored value is the keyword.
				],
				'wan' => [
					'enable' => '',
					'ipaddr' => self::WAN_IPV4_ADDR,
					'subnet' => (string) self::WAN_IPV4_BITS,
				],
			],
			'virtualip'  => ['vip' => []],
			'nat'        => ['rule' => [], 'onetoone' => []],
			'aliases'    => ['alias' => []],
		];

		// Seed the test-visible globals the doubles key on.
		$GLOBALS['pfb_test_interfaces_with_gateway'] = [];
		$GLOBALS['pfb_test_interface_ip']            = [];
		$GLOBALS['pfb_test_configured_ipv6']         = ['lan' => self::LAN_IPV6_ADDR];
		$GLOBALS['pfb_test_interface_subnetv6']      = ['lan' => (string) self::LAN_IPV6_BITS];
	}

	protected function tearDown(): void
	{
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		unset(
			$GLOBALS['pfb_test_interfaces_with_gateway'],
			$GLOBALS['pfb_test_interface_ip'],
			$GLOBALS['pfb_test_configured_ipv6'],
			$GLOBALS['pfb_test_interface_subnetv6'],
		);
	}

	// -------------------------------------------------------------------------
	// Case A — local IPv6 (the bug: fails before fix, passes after)
	// -------------------------------------------------------------------------

	public function testLocalIpv6FromDynamicPrefixIsRecognisedAsLocal(): void
	{
		// Scenario: Local IPv6 address from a track6 interface must be in the local set.
		//
		// Given  pfb_collect_localip() pulls runtime IPv6 from get_configured_ipv6_addresses()
		// When   we ask whether 2001:db8:1:2::1234 is local
		// Then   it must be recognised — either as an exact key in $pfb_local OR via
		//        pfb_local_ip() matching the /64 in $pfb_localsub.
		//
		// Before the fix: dynamic IPv6 is invisible → this assertion FAILS (RED).
		// After  the fix: runtime IPv6 is collected  → this assertion PASSES (GREEN).

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$isLocal = isset($pfb_local[self::LOCAL_IPV6_HOST])
			|| pfb_local_ip(self::LOCAL_IPV6_HOST, $pfb_localsub);

		$this->assertTrue(
			$isLocal,
			sprintf(
				"Local IPv6 %s (inside %s from a track6 interface) must be recognised as local.\n"
				. "pfb_local keys: %s\npfb_localsub: %s",
				self::LOCAL_IPV6_HOST,
				self::LAN_IPV6_SUBNET,
				implode(', ', array_keys($pfb_local)),
				implode(', ', $pfb_localsub),
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case B — external IPv6
	// -------------------------------------------------------------------------

	public function testExternalIpv6IsNotRecognisedAsLocal(): void
	{
		// Scenario: An IPv6 address outside the local prefix must NOT be in the local set.
		//
		// Given  the LAN /64 is 2001:db8:1:2::/64
		// When   we ask whether 2400:cb00::1 is local
		// Then   it must NOT be recognised.

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$isLocal = isset($pfb_local[self::EXTERNAL_IPV6])
			|| pfb_local_ip(self::EXTERNAL_IPV6, $pfb_localsub);

		$this->assertFalse(
			$isLocal,
			sprintf(
				"External IPv6 %s must NOT be recognised as local (local prefix is %s).\n"
				. "pfb_localsub: %s",
				self::EXTERNAL_IPV6,
				self::LAN_IPV6_SUBNET,
				implode(', ', $pfb_localsub),
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case C — IPv4 path unchanged (regression guard)
	// -------------------------------------------------------------------------

	public function testIpv4LocalHostIsStillRecognisedAfterFix(): void
	{
		// Scenario: The IPv4 code path must be byte-identical after the fix.
		//
		// Given  the WAN interface has a static IPv4 192.168.1.1/24
		// When   we ask whether 192.168.1.42 is local
		// Then   it must be recognised (the /24 is expanded to exact hosts OR put in $pfb_localsub).

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$isLocal = isset($pfb_local[self::LOCAL_IPV4_HOST])
			|| pfb_local_ip(self::LOCAL_IPV4_HOST, $pfb_localsub);

		$this->assertTrue(
			$isLocal,
			sprintf(
				"Local IPv4 %s (inside %s/24) must still be recognised as local after the fix.\n"
				. "pfb_local keys: %s\npfb_localsub: %s",
				self::LOCAL_IPV4_HOST,
				self::WAN_IPV4_ADDR,
				implode(', ', array_keys($pfb_local)),
				implode(', ', $pfb_localsub),
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case D — #461 regression guard: empty-string interface node is skipped
	// -------------------------------------------------------------------------

	public function testEmptyStringInterfaceNodeIsSkippedWithoutFatal(): void
	{
		// Scenario: pfb_collect_localip() must not fatal when an interfaces config
		//           entry is an empty string (pfSense parses <lan></lan> as "").
		//
		// Background:
		//   pfSense's XML parser stores an EMPTY element (e.g. <opt1></opt1>) as the
		//   empty string "" rather than an array. Core get_interfaces_with_gateway()
		//   dereferences $ifcfg['ipaddr'] on every node without an array guard, which
		//   throws "Cannot access offset of type string on string" under PHP 8 (#461).
		//   The fix enumerates interfaces directly and skips any non-array node.
		//
		// Given  a config with a well-formed dynamic-WAN interface ('wan' => dhcp)
		//        and a malformed empty-string node ('opt1' => '')
		// When   pfb_collect_localip() runs
		// Then   it does NOT fatal (reaching the asserts proves no exception)
		//        AND the gateway interface's IP is collected into $pfb_local
		//        AND the empty-string node is silently skipped (no error)

		// Override the config for this specific test case.
		$GLOBALS['config']['interfaces'] = [
			'wan'  => ['if' => 'vtnet0', 'ipaddr' => 'dhcp'],
			'lan'  => ['if' => 'vtnet1', 'ipaddr' => '192.168.1.1', 'subnet' => '24'],
			'opt1' => '',
		];
		$GLOBALS['pfb_test_interface_ip'] = ['wan' => '203.0.113.5'];

		// When: call the function under test (a fatal/TypeError would abort here)
		[$pfb_local, ] = pfb_collect_localip();

		// Then: the gateway WAN IP must appear in $pfb_local (keyed by IP value)
		$this->assertArrayHasKey(
			'203.0.113.5',
			$pfb_local,
			"The dynamic-WAN IP 203.0.113.5 must be collected into \$pfb_local "
			. "even when an empty-string interface node ('opt1' => '') is present. "
			. "pfb_local keys: " . implode(', ', array_keys($pfb_local))
		);

		// The empty-string 'opt1' node must not surface as an IP or cause a crash —
		// reaching this line without a TypeError is the primary regression guard.
		// (No explicit assertNotContains needed: the key '' cannot be a valid IP address,
		// and reaching this assertion with $pfb_local populated proves the walk completed.)
		$this->assertNotContains(
			'',
			array_keys($pfb_local),
			"The empty-string 'opt1' node must not produce a '' key in \$pfb_local"
		);
	}
}
