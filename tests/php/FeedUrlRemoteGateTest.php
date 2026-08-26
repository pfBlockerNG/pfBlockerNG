<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filter(..., PFB_FILTER_URL, ..., $escape = FALSE) — the remote-feed branch.
 *
 * PFBL-02 Phase 2 routes this branch's "any other remote URL" verdict through the
 * shared host check pfb_feed_host_allowed(), toggle-gated by pfb_feed_filter_enabled().
 * The branch matrix the gate introduces (each asserted here):
 *
 *   - a self host (firewall's own / loopback)          -> ALLOWED  (helper exempts self)
 *   - a non-self internal host, NOT allowlisted, ON    -> REJECTED (the gap Phase 2 closes)
 *   - the SAME host with the filter toggled OFF        -> ALLOWED  (before-state proves the flip)
 *   - a non-self internal host, allowlisted, ON        -> ALLOWED  (operator exemption)
 *   - a public host                                    -> ALLOWED  (unchanged)
 *
 * Both decisions read the same resolver / configured-IP / allowlist doubles, so a
 * single seeded host drives the verdict end-to-end.
 *
 * Scenario: the remote-feed validator only accepts a URL whose host the fetch guard
 * would also dial.
 *   Background:
 *     Given the internal-address allowlist is empty (secure default)
 *     And the resolver / configured-IP doubles back both decisions
 */
#[CoversFunction('pfb_filter')]
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_filter_enabled')]
final class FeedUrlRemoteGateTest extends TestCase
{
	protected function setUp(): void
	{
		// Secure defaults: empty config => filter ON, allowlist empty, no self IP.
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
	}

	/** The remote-feed validator verdict for a URL ($escape = FALSE): TRUE = accepted. */
	private function validate(string $url): bool
	{
		return pfb_filter($url, PFB_FILTER_URL, 'remote-gate', '', false) !== false;
	}

	private function setFilter(string $value): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter', $value);
	}

	private function setAllowlist(string $value): void
	{
		// pfBlockerNG textarea convention: stored base64-encoded.
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_allowlist', base64_encode($value));
	}

	/**
	 * A self-hosted feed (host resolves to the firewall's own configured address) is
	 * accepted even though it is non-public — the helper exempts self.
	 */
	public function testSelfHostedFeedAccepted(): void
	{
		// Given a host resolving to an address configured on the box.
		$GLOBALS['pfb_test_resolve_map']['self.feed.'] = [['type' => 'A', 'data' => '192.168.10.5']];
		$GLOBALS['pfb_test_configured_ips'] = ['192.168.10.5'];

		// Then the validator accepts it (filter ON — the default).
		$this->assertTrue($this->validate('https://self.feed/list.txt'), 'self-hosted feed must be allowed');
	}

	/**
	 * A non-self internal host that is NOT allowlisted is REJECTED with the filter ON,
	 * and ALLOWED with the filter OFF — the before/after pair proves the toggle drives
	 * the change (not an always-reject path).
	 */
	public function testNonSelfInternalRejectedWhenOnAllowedWhenOff(): void
	{
		// Given a host resolving to a foreign RFC1918 address (not the firewall's own).
		$GLOBALS['pfb_test_resolve_map']['internal.feed.'] = [['type' => 'A', 'data' => '10.20.30.40']];

		// When the filter is ON (default) the validator rejects it.
		$this->assertFalse(
			$this->validate('https://internal.feed/list.txt'),
			'non-self internal host must be rejected while the filter is ON'
		);

		// When the filter is toggled OFF the same host is accepted (pre-filter behaviour).
		$this->setFilter('off');
		$this->assertTrue(
			$this->validate('https://internal.feed/list.txt'),
			'the same host must be allowed once the filter is OFF'
		);
	}

	/**
	 * A non-self internal host the operator has allowlisted is accepted with the filter
	 * ON — the explicit exemption overrides the internal-address reject.
	 */
	public function testInternalAllowlistedHostAccepted(): void
	{
		// Given a host resolving to a foreign internal address that is allowlisted.
		$GLOBALS['pfb_test_resolve_map']['mirror.feed.'] = [['type' => 'A', 'data' => '172.16.5.5']];

		// First prove the before-state: without the allowlist entry it is rejected.
		$this->assertFalse($this->validate('https://mirror.feed/list.txt'), 'internal host rejected before allowlisting');

		// When the address is allowlisted the validator accepts it (filter still ON).
		$this->setAllowlist('172.16.5.5');
		$this->assertTrue($this->validate('https://mirror.feed/list.txt'), 'allowlisted internal host must be allowed');
	}

	/**
	 * A public host is accepted (unchanged behaviour) regardless of the toggle.
	 */
	public function testPublicHostAccepted(): void
	{
		// Given a host resolving to a routable public address.
		$GLOBALS['pfb_test_resolve_map']['public.feed.'] = [['type' => 'A', 'data' => '203.0.113.20']];

		// Then it is accepted with the filter ON ...
		$this->assertTrue($this->validate('https://public.feed/list.txt'), 'public host allowed with filter ON');

		// ... and still accepted with the filter OFF.
		$this->setFilter('off');
		$this->assertTrue($this->validate('https://public.feed/list.txt'), 'public host allowed with filter OFF');
	}
}
