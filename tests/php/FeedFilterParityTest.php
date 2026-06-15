<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Parity between the feed-URL validator pfb_filter(..., PFB_FILTER_URL, ...) in its
 * remote-feed mode ($escape = FALSE) and the pre-fetch host guard
 * pfb_feed_host_allowed(): for the SAME resolved-host set, the two MUST return the
 * SAME accept/reject verdict. Both read the same resolver / configured-IP doubles
 * ($GLOBALS['pfb_test_resolve_map'] + $GLOBALS['pfb_test_configured_ips']), so a
 * single seeded host drives both — any divergence is a real gap, not a test artefact.
 *
 * The verdict the two must agree on is the host-reachability decision: a feed URL
 * whose host resolves to a non-public/reserved address (and is neither the firewall
 * itself nor allowlisted) must be REJECTED by the validator exactly as the fetch
 * guard rejects it — so the URL accepted at validation is the URL the guard would
 * dial. A public host, a self-hosted host, and an allowlisted-internal host are
 * accepted by both.
 *
 * PFBL-02 Phase 2 routes PFB_FILTER_URL's remote-feed decision through
 * pfb_feed_host_allowed(), so the two verdicts now agree: a non-self internal host
 * the guard rejects is rejected by the validator too.
 *
 * Scenario: the URL a feed-config validation accepts is exactly the URL the fetch
 * guard will permit dialling.
 *   Background:
 *     Given the internal-address allowlist is empty (secure default)
 *     And the feed-host filter is enabled (default ON)
 *     And both decisions read the same resolver / configured-IP doubles
 */
#[CoversFunction('pfb_filter')]
#[CoversFunction('pfb_feed_host_allowed')]
final class FeedFilterParityTest extends TestCase
{
	protected function setUp(): void
	{
		// Secure defaults: empty allowlist, no IP configured on the box, filter ON
		// (pfb_feed_filter_enabled() returns TRUE when the key is absent).
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
	}

	/** The host guard's boolean verdict for a host (reason/pin discarded — the gate
	 *  consumes only the verdict; the pin is a fetch-path concern). */
	private function guardVerdict(string $host): bool
	{
		$reason = '';
		$pinned = '';
		return pfb_feed_host_allowed($host, $reason, $pinned);
	}

	/** The validator's verdict for a feed URL in remote-feed mode ($escape = FALSE):
	 *  TRUE when pfb_filter accepts the URL, FALSE when it rejects it. */
	private function validatorVerdict(string $url): bool
	{
		return pfb_filter($url, PFB_FILTER_URL, 'parity', '', false) !== false;
	}

	/**
	 * Host sets covering each verdict branch the two decisions share. Each entry is
	 * [host, resolved-records|configured-self-ip, expected-shared-verdict].
	 */
	public static function parityHostProvider(): array
	{
		return [
			// A public host: both accept.
			'public host accepted by both' => [
				'feed.parity.public',
				[['type' => 'A', 'data' => '203.0.113.20']],
				true,
			],
			// A non-self internal host: the guard rejects; the validator MUST too.
			// This is the branch that diverges until Phase 2 routes the gate.
			'internal host rejected by both' => [
				'feed.parity.internal',
				[['type' => 'A', 'data' => '10.20.30.40']],
				false,
			],
		];
	}

	#[DataProvider('parityHostProvider')]
	public function testValidatorAndGuardAgree(string $host, array $records, bool $expected): void
	{
		// Given the host resolves to the seeded record set (same double for both).
		$GLOBALS['pfb_test_resolve_map']["{$host}."] = $records;

		// When each decision runs over the same host / URL.
		$guard     = $this->guardVerdict($host);
		$validator = $this->validatorVerdict("https://{$host}/list.txt");

		// Then both reach the shared verdict, and they agree with each other.
		$this->assertSame($expected, $guard, 'fetch guard verdict');
		$this->assertSame($expected, $validator, 'feed-URL validator verdict');
		$this->assertSame($guard, $validator, 'validator and guard must return identical verdicts');
	}

	/**
	 * The specific case PFBL-02 Phase 2 closes, asserted concretely: a non-self
	 * internal host that the fetch guard REJECTS must be rejected by the validator
	 * too. Phase 2 removes the skip; the assertions stand unchanged.
	 */
	public function testNonSelfInternalHostRejectedByValidatorMatchesGuard(): void
	{
		// Given a host resolving to an RFC1918 address, not the firewall's own.
		$GLOBALS['pfb_test_resolve_map']['internal.parity.'] = [
			['type' => 'A', 'data' => '192.168.50.50'],
		];

		// When the guard runs, it rejects (the established fetch-path behaviour).
		$this->assertFalse($this->guardVerdict('internal.parity'), 'guard rejects a non-self internal host');

		// Then the validator must reject the same feed URL (parity).
		$this->assertFalse(
			$this->validatorVerdict('https://internal.parity/list.txt'),
			'validator must reject the URL the guard rejects'
		);
	}
}
