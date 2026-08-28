<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_host_allowed() / pfb_ip_is_internal() / pfb_ip_in_cidr() — the pre-fetch
 * guard that rejects a feed whose host resolves to a non-public/reserved address
 * before any connection is made (loopback / link-local / RFC1918 / ULA / CGNAT /
 * metadata), fail-closed on a host that does not resolve. A resolved internal
 * address is permitted only when covered by the operator's IP/CIDR allowlist; an
 * empty allowlist (the default) blocks every internal-resolving feed.
 *
 * Scenario: a feed download must only ever dial a routable public address, unless
 * the operator has explicitly allowlisted the internal address it resolves to.
 *   Background:
 *     Given the allowlist 'pfb_feed_internal_allowlist' is empty (secure default)
 *     And the resolver is driven by $GLOBALS['pfb_test_resolve_map']
 */
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_ip_is_internal')]
#[CoversFunction('pfb_ip_in_cidr')]
#[CoversFunction('pfb_ip_is_self')]
final class FeedHostAllowedTest extends TestCase
{
	protected function setUp(): void
	{
		// Secure default: allowlist empty (no internal exemptions), and no IP
		// configured on the box (the self-exemption never fires unless seeded).
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
	}

	/** Set the internal-address allowlist config value the guard reads.
	 *
	 * Stored base64-encoded (the pfBlockerNG textarea convention; pfb_feed_internal_allowlist()
	 * base64_decodes it), so encode the plain IP/CIDR list the caller passes.
	 */
	private function setAllowlist(string $value): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_allowlist', base64_encode($value));
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
	}

	/** Drive the guard for a host, returning [allowed, reason, pinned]. */
	private function guard(string $host): array
	{
		$reason = '';
		$pinned = '';
		$allowed = pfb_feed_host_allowed($host, $reason, $pinned);
		return [$allowed, $reason, $pinned];
	}

	// --- pfb_ip_is_internal(): every reserved range, each family ----------------

	public static function internalIpProvider(): array
	{
		return [
			'loopback v4'        => ['127.0.0.1', '127.0.0.0/8'],
			'rfc1918 10/8'       => ['10.1.2.3', '10.0.0.0/8'],
			'rfc1918 172.16/12'  => ['172.16.5.5', '172.16.0.0/12'],
			'rfc1918 192.168/16' => ['192.168.1.1', '192.168.0.0/16'],
			'link-local v4'      => ['169.254.169.254', '169.254.0.0/16'],	// metadata IP
			'cgnat 100.64/10'    => ['100.64.0.1', '100.64.0.0/10'],
			'this-network 0/8'   => ['0.0.0.0', '0.0.0.0/8'],
			'loopback v6'        => ['::1', '::1/128'],
			'link-local v6'      => ['fe80::1', 'fe80::/10'],
			'ula v6'             => ['fd00::1', 'fc00::/7'],
			'v4-mapped private'  => ['::ffff:10.0.0.1', '10.0.0.0/8'],	// unwrap then v4 check
		];
	}

	#[DataProvider('internalIpProvider')]
	public function testInternalIpIsRejected(string $ip, string $expectedCidr): void
	{
		// Then the address is flagged internal, reporting the matched CIDR.
		$this->assertSame($expectedCidr, pfb_ip_is_internal($ip));
	}

	public static function publicIpProvider(): array
	{
		return [
			'public v4'          => ['203.0.113.10'],	// TEST-NET-3, routable shape
			'public v6'          => ['2001:db8::1'],
			'just outside 100.64'=> ['100.128.0.1'],	// 100.64/10 upper bound check
			'just outside 172.16'=> ['172.32.0.1'],		// 172.16/12 upper bound check
		];
	}

	#[DataProvider('publicIpProvider')]
	public function testPublicIpIsAllowed(string $ip): void
	{
		// Then a routable public address is not flagged.
		$this->assertFalse(pfb_ip_is_internal($ip));
	}

	public function testNonIpInputIsNotFlagged(): void
	{
		// pfb_ip_is_internal answers "is this a known-internal IP"; a non-IP is not
		// (the host-level guard is what fails such input closed — see below).
		$this->assertFalse(pfb_ip_is_internal('not-an-ip'));
		$this->assertFalse(pfb_ip_is_internal(''));
	}

	// --- pfb_feed_host_allowed(): host resolution + verdict ---------------------

	public function testPublicHostIsAllowedAndPinsResolvedIp(): void
	{
		// Given a host resolving to a public address
		$GLOBALS['pfb_test_resolve_map']['feed.example.'] = [
			['type' => 'A', 'data' => '203.0.113.5'],
		];
		// When the guard runs
		[$allowed, $reason, $pinned] = $this->guard('feed.example');
		// Then it is allowed and the connection is pinned to that vetted IP.
		$this->assertTrue($allowed);
		$this->assertSame('', $reason);
		$this->assertSame('203.0.113.5', $pinned);
	}

	public function testIpLiteralPublicHostIsAllowedAndPinned(): void
	{
		// A host that is already an IP literal is vetted directly (no resolution).
		[$allowed, , $pinned] = $this->guard('198.51.100.7');
		$this->assertTrue($allowed);
		$this->assertSame('198.51.100.7', $pinned);
	}

	public function testInternalHostIsRejected(): void
	{
		// Given a host resolving to an RFC1918 address
		$GLOBALS['pfb_test_resolve_map']['internal.example.'] = [
			['type' => 'A', 'data' => '10.10.10.10'],
		];
		// When the guard runs / Then it is rejected with a neutral reason and no pin.
		[$allowed, $reason, $pinned] = $this->guard('internal.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
		$this->assertSame('', $pinned);
	}

	public function testMetadataIpLiteralHostIsRejected(): void
	{
		// The cloud metadata address as a bare host literal is rejected.
		[$allowed, $reason] = $this->guard('169.254.169.254');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
	}

	public function testAnyInternalAddressInTheSetRejectsTheWholeHost(): void
	{
		// A host with one public AND one internal address is rejected (fail-closed:
		// the internal record must not be reachable via round-robin).
		$GLOBALS['pfb_test_resolve_map']['mixed.example.'] = [
			['type' => 'A', 'data' => '203.0.113.9'],
			['type' => 'A', 'data' => '192.168.50.1'],
		];
		[$allowed, $reason] = $this->guard('mixed.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
	}

	public function testCnameChainResolvingInternalIsRejected(): void
	{
		// A CNAME whose target resolves to an internal address is followed and rejected.
		$GLOBALS['pfb_test_resolve_map']['alias.example.'] = [
			['type' => 'CNAME', 'data' => 'backend.example'],
		];
		$GLOBALS['pfb_test_resolve_map']['backend.example.'] = [
			['type' => 'A', 'data' => '172.16.0.5'],
		];
		[$allowed, $reason] = $this->guard('alias.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
	}

	public function testCnameWithInternalIpLiteralIsRejected(): void
	{
		// A CNAME record whose 'data' is itself an IP literal (the IP-literal branch
		// of the CNAME handling) is taken directly as an address: when that literal
		// is internal it must be rejected without a further resolution step.
		$GLOBALS['pfb_test_resolve_map']['alias.example.'] = [
			['type' => 'CNAME', 'data' => '10.0.0.7'],
		];
		[$allowed, $reason, $pinned] = $this->guard('alias.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
		$this->assertSame('', $pinned);
	}

	// --- Fail-closed --------------------------------------------------------------

	public function testUnresolvableHostIsRejected(): void
	{
		// Given a host that does not resolve ([] from the resolver)
		$GLOBALS['pfb_test_resolve_map']['nxdomain.example.'] = false;
		// When the guard runs / Then it fails closed.
		[$allowed, $reason] = $this->guard('nxdomain.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host did not resolve', $reason);
	}

	public function testHostResolvingToNoValidAddressIsRejected(): void
	{
		// Records exist but carry no usable IP -> fail closed.
		$GLOBALS['pfb_test_resolve_map']['empty.example.'] = [
			['type' => 'A', 'data' => ''],
		];
		[$allowed, $reason] = $this->guard('empty.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host did not resolve to a valid address', $reason);
	}

	public function testEmptyHostIsRejected(): void
	{
		[$allowed, $reason] = $this->guard('');
		$this->assertFalse($allowed);
		$this->assertSame('feed host is empty', $reason);
	}

	// --- Allowlist is a real branch (absent -> rejected, present -> allowed) -----

	public function testAllowlistingTheResolvedIpFlipsInternalHostFromRejectedToAllowed(): void
	{
		// Given a host resolving to an internal address
		$GLOBALS['pfb_test_resolve_map']['internal.example.'] = [
			['type' => 'A', 'data' => '10.0.0.9'],
		];

		// When the allowlist is empty (default) -> rejected (before-state).
		[$allowedOff, $reasonOff, $pinnedOff] = $this->guard('internal.example');
		$this->assertFalse($allowedOff);
		$this->assertSame('feed host resolves to a non-permitted address', $reasonOff);
		$this->assertSame('', $pinnedOff);

		// When that exact IP is allowlisted -> the same host is now allowed, and the
		// vetted internal IP becomes the pinned connection target.
		$this->setAllowlist('10.0.0.9');
		[$allowedOn, $reasonOn, $pinnedOn] = $this->guard('internal.example');
		$this->assertTrue($allowedOn);
		$this->assertSame('', $reasonOn);
		$this->assertSame('10.0.0.9', $pinnedOn);
	}

	public function testInternalIpCoveredByAllowlistedCidrIsAllowed(): void
	{
		// Given a host resolving to an internal address inside an allowlisted CIDR
		$GLOBALS['pfb_test_resolve_map']['mirror.example.'] = [
			['type' => 'A', 'data' => '10.1.2.3'],
		];
		$this->setAllowlist('10.0.0.0/8');
		// When the guard runs / Then it is allowed and pins the vetted IP.
		[$allowed, $reason, $pinned] = $this->guard('mirror.example');
		$this->assertTrue($allowed);
		$this->assertSame('', $reason);
		$this->assertSame('10.1.2.3', $pinned);
	}

	public function testHostWithOnlyOneOfTwoInternalIpsAllowlistedIsRejected(): void
	{
		// A host with two internal addresses where only one is allowlisted is
		// rejected: EVERY internal address must be covered (fail-closed).
		$GLOBALS['pfb_test_resolve_map']['twohomed.example.'] = [
			['type' => 'A', 'data' => '10.0.0.1'],
			['type' => 'A', 'data' => '192.168.1.1'],
		];
		$this->setAllowlist('10.0.0.1');	// covers only the first
		[$allowed, $reason] = $this->guard('twohomed.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
	}

	public function testInvalidAllowlistEntriesAreIgnored(): void
	{
		// Given a host resolving to an internal address
		$GLOBALS['pfb_test_resolve_map']['internal.example.'] = [
			['type' => 'A', 'data' => '10.0.0.9'],
		];
		// And an allowlist made only of invalid entries (no valid IP/CIDR exemption)
		$this->setAllowlist("not-an-ip\n999.0.0.0/8");
		// When the guard runs / Then nothing is exempted -> still rejected.
		[$allowed, $reason] = $this->guard('internal.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
	}

	public function testPublicHostIsAllowedRegardlessOfAllowlistContents(): void
	{
		// The allowlist exempts internal addresses only; a public host is allowed
		// whether or not the allowlist is populated (here it lists an unrelated range).
		$GLOBALS['pfb_test_resolve_map']['public.example.'] = [
			['type' => 'A', 'data' => '203.0.113.20'],
		];
		$this->setAllowlist('10.0.0.0/8');
		[$allowed, $reason, $pinned] = $this->guard('public.example');
		$this->assertTrue($allowed);
		$this->assertSame('', $reason);
		$this->assertSame('203.0.113.20', $pinned);
	}

	// --- Self-host exemption: a feed served by the box itself -------------------
	//
	// The firewall's own LAN address is RFC1918, but a self-hosted feed
	// (http://127.0.0.1/…, http://[::1]/…, http://<box-IP>/…) is a long-supported
	// pfBlockerNG case. A resolved candidate that is the box itself is allowed even
	// with an empty allowlist; the same RFC1918 IP NOT configured on the box is
	// rejected — proving self-ownership, not the address shape, is the cause.

	public function testSelfConfiguredInternalIpFlipsRejectedHostToAllowed(): void
	{
		// Given a host resolving to an RFC1918 address
		$GLOBALS['pfb_test_resolve_map']['selfhost.example.'] = [
			['type' => 'A', 'data' => '192.168.1.1'],
		];

		// When that IP is NOT configured on the box -> rejected (before-state).
		[$allowedOff, $reasonOff, $pinnedOff] = $this->guard('selfhost.example');
		$this->assertFalse($allowedOff);
		$this->assertSame('feed host resolves to a non-permitted address', $reasonOff);
		$this->assertSame('', $pinnedOff);

		// When the SAME IP is the box's own configured address -> allowed, pinning it.
		$GLOBALS['pfb_test_configured_ips'] = ['192.168.1.1'];
		[$allowedOn, $reasonOn, $pinnedOn] = $this->guard('selfhost.example');
		$this->assertTrue($allowedOn);
		$this->assertSame('', $reasonOn);
		$this->assertSame('192.168.1.1', $pinnedOn);
	}

	public function testLoopbackLiteralHostsAreAllowed(): void
	{
		// 127.0.0.1 / ::1 as bare host literals are self (loopback) -> allowed, with
		// no box-configured IPs seeded (loopback is recognised unconditionally).
		[$allowed4, , $pinned4] = $this->guard('127.0.0.1');
		$this->assertTrue($allowed4);
		$this->assertSame('127.0.0.1', $pinned4);

		[$allowed6, , $pinned6] = $this->guard('::1');
		$this->assertTrue($allowed6);
		$this->assertSame('::1', $pinned6);
	}

	public function testSelfExemptionDoesNotBlanketAllowAMixedSet(): void
	{
		// A host resolving to [box-self, foreign-internal-not-self-not-allowlisted]
		// still REJECTS on the foreign-internal address: the self-exemption is
		// per-candidate, never a blanket allow once one candidate is self.
		$GLOBALS['pfb_test_resolve_map']['mixedself.example.'] = [
			['type' => 'A', 'data' => '192.168.1.1'],	// the box itself
			['type' => 'A', 'data' => '10.0.0.5'],		// foreign internal
		];
		$GLOBALS['pfb_test_configured_ips'] = ['192.168.1.1'];

		[$allowed, $reason] = $this->guard('mixedself.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
	}

	public function testHostResolvingOnlyToBoxSelfIsAllowed(): void
	{
		// The complement of the mixed-set case: a host resolving ONLY to the box's own
		// (RFC1918) address is allowed and pins that address.
		$GLOBALS['pfb_test_resolve_map']['onlyself.example.'] = [
			['type' => 'A', 'data' => '192.168.1.1'],
		];
		$GLOBALS['pfb_test_configured_ips'] = ['192.168.1.1'];

		[$allowed, $reason, $pinned] = $this->guard('onlyself.example');
		$this->assertTrue($allowed);
		$this->assertSame('', $reason);
		$this->assertSame('192.168.1.1', $pinned);
	}

	public function testPublicForeignHostRejectedWhenAllCandidatesNonSelfInternal(): void
	{
		// A host resolving to [public, foreign-internal] (neither self nor allowlisted)
		// is rejected on the foreign-internal record (fail-closed preserved).
		$GLOBALS['pfb_test_resolve_map']['pubint.example.'] = [
			['type' => 'A', 'data' => '203.0.113.50'],
			['type' => 'A', 'data' => '10.0.0.5'],
		];
		[$allowed, $reason] = $this->guard('pubint.example');
		$this->assertFalse($allowed);
		$this->assertSame('feed host resolves to a non-permitted address', $reason);
	}

	// --- pfb_ip_is_self(): the self-ownership predicate -------------------------

	public function testIpIsSelfPredicate(): void
	{
		// Loopback is self unconditionally; a configured box IP is self; anything else
		// (incl. a non-configured RFC1918 address and a public address) is not.
		$GLOBALS['pfb_test_configured_ips'] = ['192.168.1.1'];
		$this->assertTrue(pfb_ip_is_self('127.0.0.1'));
		$this->assertTrue(pfb_ip_is_self('::1'));
		$this->assertTrue(pfb_ip_is_self('192.168.1.1'));
		$this->assertFalse(pfb_ip_is_self('10.0.0.5'));		// RFC1918 but not configured
		$this->assertFalse(pfb_ip_is_self('203.0.113.7'));	// public, not configured
		$this->assertFalse(pfb_ip_is_self(''));
	}

	// --- pfb_ip_in_cidr(): the shared binary-containment helper -----------------

	public function testIpInCidrMatchesInsideRange(): void
	{
		$this->assertTrue(pfb_ip_in_cidr('10.1.2.3', '10.0.0.0/8'));
		$this->assertTrue(pfb_ip_in_cidr('2001:db8::5', '2001:db8::/32'));
	}

	public function testIpJustOutsideCidrDoesNotMatch(): void
	{
		// 100.128.0.1 is one block above the 100.64.0.0/10 (CGNAT) upper bound.
		$this->assertFalse(pfb_ip_in_cidr('100.128.0.1', '100.64.0.0/10'));
		$this->assertFalse(pfb_ip_in_cidr('172.32.0.1', '172.16.0.0/12'));
	}

	public function testIpInCidrFamilyMismatchDoesNotMatch(): void
	{
		// A v4 address can never be contained in a v6 CIDR, nor a bare (non-CIDR) arg.
		$this->assertFalse(pfb_ip_in_cidr('10.0.0.1', 'fc00::/7'));
		$this->assertFalse(pfb_ip_in_cidr('::1', '10.0.0.0/8'));
		$this->assertFalse(pfb_ip_in_cidr('10.0.0.1', '10.0.0.0'));
	}
}
