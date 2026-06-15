<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Anti-drift parity between the feed-URL validator pfb_filter(..., PFB_FILTER_URL, ...)
 * in its remote-feed mode ($escape = FALSE) and the pre-fetch host guard
 * pfb_feed_host_allowed(): with the feed-host filter ENABLED (the default), for the
 * SAME resolved-host set the two MUST return the SAME accept/reject verdict, across
 * every host class they share — self, non-self internal (not allowlisted), internal
 * allowlisted, and public. Both read the same resolver / configured-IP / allowlist
 * doubles ($GLOBALS['pfb_test_resolve_map'] + $GLOBALS['pfb_test_configured_ips'] +
 * the base64 allowlist config), so a single seeded host drives both — any divergence
 * is a real gap between validation-time and fetch-time, not a test artefact.
 *
 * The URL the validator accepts at config time is therefore exactly the URL the fetch
 * guard would permit dialling. The toggle that gates this lives on the VALIDATOR side
 * (pfb_feed_filter_enabled); the guard has no toggle. A separate case pins that the
 * toggle — and only the toggle — is what lets the two diverge: with the filter OFF the
 * validator bypasses the guard and accepts an internal host the guard still rejects,
 * proving the parity above is the gate's doing, not an always-equal accident.
 *
 * Scenario: the URL a feed-config validation accepts is exactly the URL the fetch
 * guard will permit dialling.
 *   Background:
 *     Given the internal-address allowlist is empty (secure default)
 *     And the feed-host filter is enabled (default ON)
 *     And both decisions read the same resolver / configured-IP / allowlist doubles
 */
#[CoversFunction('pfb_filter')]
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_filter_enabled')]
final class FeedFilterParityTest extends TestCase
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

	private function setAllowlist(string $value): void
	{
		// pfBlockerNG textarea convention: stored base64-encoded.
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_allowlist', base64_encode($value));
	}

	/**
	 * Host classes covering every verdict branch the two decisions share, with the
	 * filter ENABLED. Each entry is [host, resolved-records, configured-self-ips,
	 * allowlist-literal, expected-shared-verdict].
	 *
	 * The self case uses a root path ('/') because the validator's self-host allowance
	 * is path-restricted to the firewall root; the guard accepts self regardless of
	 * path, so the root path is the URL on which the two are comparable — and both
	 * accept it. Every other class never reaches the validator's self-branch, so it
	 * routes straight through the guard and the path is irrelevant.
	 */
	public static function parityHostProvider(): array
	{
		return [
			// Public host: both accept (unchanged behaviour).
			'public host accepted by both' => [
				'feed.parity.public', [['type' => 'A', 'data' => '203.0.113.20']],
				[], '', '/list.txt', true,
			],
			// Self-hosted host (resolves to the firewall's own address): both accept.
			'self host accepted by both' => [
				'feed.parity.self', [['type' => 'A', 'data' => '192.168.10.5']],
				['192.168.10.5'], '', '/', true,
			],
			// Non-self internal host, NOT allowlisted: both reject (the gap Phase 2 closes).
			'internal non-allowlisted host rejected by both' => [
				'feed.parity.internal', [['type' => 'A', 'data' => '10.20.30.40']],
				[], '', '/list.txt', false,
			],
			// Non-self internal host the operator allowlisted: both accept (exemption).
			'internal allowlisted host accepted by both' => [
				'feed.parity.mirror', [['type' => 'A', 'data' => '172.16.5.5']],
				[], '172.16.5.5', '/list.txt', true,
			],
		];
	}

	/**
	 * With the feed-host filter ENABLED (default), the validator and the guard reach
	 * the SAME verdict for the same host — across self, public, internal-rejected, and
	 * internal-allowlisted. Any future divergence between the two code paths fails here.
	 */
	#[DataProvider('parityHostProvider')]
	public function testValidatorAndGuardAgreeWhenFilterEnabled(
		string $host,
		array $records,
		array $configuredIps,
		string $allowlist,
		string $path,
		bool $expected
	): void {
		// Given the host resolves to the seeded record set (same double for both), and
		// any self / allowlist context the class needs.
		$GLOBALS['pfb_test_resolve_map']["{$host}."] = $records;
		$GLOBALS['pfb_test_configured_ips'] = $configuredIps;
		if ($allowlist !== '') {
			$this->setAllowlist($allowlist);
		}

		// When each decision runs over the same host / URL (filter ON — the default).
		$guard     = $this->guardVerdict($host);
		$validator = $this->validatorVerdict("https://{$host}{$path}");

		// Then both reach the expected shared verdict, and they agree with each other.
		$this->assertSame($expected, $guard, 'fetch guard verdict');
		$this->assertSame($expected, $validator, 'feed-URL validator verdict');
		$this->assertSame($guard, $validator, 'validator and guard must return identical verdicts');
	}

	/**
	 * The toggle — and only the toggle — is what lets the two diverge. The guard has no
	 * toggle; with the filter OFF the validator stops consulting it. For a non-self
	 * internal host: filter ON => both REJECT (parity); filter OFF => the validator
	 * ACCEPTS while the guard STILL REJECTS. Asserting the ON parity first proves the
	 * OFF divergence is the gate opening, not pre-existing drift.
	 */
	public function testToggleOffDivergesValidatorFromGuard(): void
	{
		// Given a non-self internal host (foreign RFC1918, not the firewall's own).
		$GLOBALS['pfb_test_resolve_map']['internal.parity.'] = [['type' => 'A', 'data' => '192.168.50.50']];
		$url = 'https://internal.parity/list.txt';

		// When the filter is ON (default) both reject — they agree.
		$this->assertFalse($this->guardVerdict('internal.parity'), 'guard rejects a non-self internal host');
		$this->assertFalse($this->validatorVerdict($url), 'validator rejects it too while the filter is ON');

		// When the filter is toggled OFF the validator bypasses the guard and accepts,
		// while the guard's own verdict is unchanged (it has no toggle) — the documented
		// divergence, owned entirely by the gate.
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter', 'off');
		$this->assertTrue($this->validatorVerdict($url), 'validator accepts once the filter is OFF (gate bypassed)');
		$this->assertFalse($this->guardVerdict('internal.parity'), 'the guard still rejects — only the gate moved');
	}
}
