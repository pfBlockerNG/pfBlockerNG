<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_collect_localip() — Firewall Alias -> IP address conversion (issue #782).
 *
 * pfSense stores a multi-entry alias's 'address' as a SPACE-SEPARATED string
 * (e.g. '10.0.0.1 10.0.0.2'). Before the fix, an $pfb_local entry that matched
 * an alias name was replaced with that compound string VERBATIM; once
 * $pfb_local is array_flip()ed at the end of pfb_collect_localip(), the whole
 * compound string becomes ONE unmatchable key. pfb_remove_states() and
 * pfb_daemon_filterlog() then check isset($pfb_local[$s_ip]) against a single
 * member IP, which can never match the compound key — so a local IP behind a
 * multi-entry alias (a NAT target, a VIP, a gateway) is never spared by the
 * kill-states / Reports "local host" exclusion.
 *
 * Scenario: Firewall-Alias conversion in pfb_collect_localip()
 *   Background:
 *     Given the alias-conversion block reads config 'aliases/alias' and, for
 *           every $pfb_local entry whose value equals an alias name, must
 *           replace it with each of the alias's SPLIT, INDIVIDUALLY CLASSIFIED
 *           members (plain IP -> its own $pfb_local entry; CIDR -> $pfb_localsub;
 *           anything else -> dropped) rather than the raw compound string.
 *
 *   Case A (the bug — MUST fail before the fix, pass after):
 *     Given a NAT rule target set to alias name 'Multi_Hosts' whose stored
 *           address is '203.0.113.10 203.0.113.20'
 *     When  pfb_collect_localip() is called
 *     Then  BOTH member IPs are recognised as local (isset in the flipped
 *           $pfb_local)
 *     And   the compound string '203.0.113.10 203.0.113.20' is NOT itself a
 *           $pfb_local key
 *
 *   Case B (CIDR member of a mixed alias):
 *     Given alias 'Multi_Cidr' = '198.51.100.0/28 203.0.113.50'
 *     Then  a host inside the CIDR (198.51.100.5) is recognised as local via
 *           pfb_local_ip($host, $pfb_localsub), the plain IP member is its own
 *           $pfb_local key, and the CIDR string itself is never a $pfb_local key
 *
 *   Case C (non-IP members dropped):
 *     Given alias 'Multi_Bad' = 'example.org 8080' (a hostname and a bare port)
 *     Then  neither member appears as a $pfb_local key and nothing bogus lands
 *           in $pfb_localsub
 *
 *   Case D (regression guard — green before AND after):
 *     Given a single-IP alias 'Single_Host' = '203.0.113.99'
 *     Then  it still resolves to that one IP as a $pfb_local key
 *
 *   Case E (regression guard — entries that are not an alias name):
 *     Given a NAT rule target of a plain IP '192.0.2.7' (matches no alias name)
 *     Then  it passes through unchanged and is recognised as local
 */
#[CoversFunction('pfb_collect_localip')]
#[CoversFunction('pfb_local_ip')]
final class CollectLocalIpAliasTest extends TestCase
{
	/** Saved $GLOBALS state to restore after each test. */
	private bool $hadConfig = false;
	private array $savedConfig = [];

	protected function setUp(): void
	{
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? [];

		// Minimal config: no interfaces/VIPs contributing noise, one NAT rule
		// per test case, and the alias table under test.
		$GLOBALS['config'] = [
			'interfaces' => [],
			'virtualip'  => ['vip' => []],
			'nat'        => ['rule' => [], 'onetoone' => []],
			'aliases'    => [
				'alias' => [
					['name' => 'Multi_Hosts',  'address' => '203.0.113.10 203.0.113.20'],
					['name' => 'Multi_Cidr',   'address' => '198.51.100.0/28 203.0.113.50'],
					['name' => 'Multi_Bad',    'address' => 'example.org 8080'],
					['name' => 'Single_Host',  'address' => '203.0.113.99'],
				],
			],
		];

		$GLOBALS['pfb_test_configured_ipv6'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		unset($GLOBALS['pfb_test_configured_ipv6']);
	}

	// -------------------------------------------------------------------------
	// Case A — multi-IP alias (the bug: fails before fix, passes after)
	// -------------------------------------------------------------------------

	public function testMultiIpAliasMembersAreEachRecognisedAsLocal(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Multi_Hosts'],
		];

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'203.0.113.10',
			$pfb_local,
			sprintf(
				"Alias member 203.0.113.10 (from 'Multi_Hosts' = '203.0.113.10 203.0.113.20') "
				. "must be recognised as local.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayHasKey(
			'203.0.113.20',
			$pfb_local,
			sprintf(
				"Alias member 203.0.113.20 (from 'Multi_Hosts' = '203.0.113.10 203.0.113.20') "
				. "must be recognised as local.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayNotHasKey(
			'203.0.113.10 203.0.113.20',
			$pfb_local,
			sprintf(
				"The RAW compound alias address must never survive as a single \$pfb_local key "
				. "-- it can never match an individual member IP once flipped.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case B — mixed alias: CIDR member + plain-IP member
	// -------------------------------------------------------------------------

	public function testMixedAliasCidrMemberIsRecognisedViaLocalSubnetAndPlainIpAsKey(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Multi_Cidr'],
		];

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$host = '198.51.100.5';
		$this->assertTrue(
			pfb_local_ip($host, $pfb_localsub),
			sprintf(
				"Host %s inside alias CIDR member 198.51.100.0/28 must be recognised as local "
				. "via pfb_localsub.\npfb_localsub: %s",
				$host,
				implode(', ', $pfb_localsub)
			)
		);
		$this->assertArrayHasKey(
			'203.0.113.50',
			$pfb_local,
			sprintf(
				"Plain-IP alias member 203.0.113.50 must be its own \$pfb_local key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayNotHasKey(
			'198.51.100.0/28',
			$pfb_local,
			"The CIDR member string itself must never appear as a \$pfb_local key "
			. "(it belongs in \$pfb_localsub, matched by value via ip_in_subnet)."
		);
		$this->assertArrayNotHasKey(
			'198.51.100.0/28 203.0.113.50',
			$pfb_local,
			"The raw compound alias address must never survive as a single \$pfb_local key."
		);
	}

	// -------------------------------------------------------------------------
	// Case C — non-IP alias members are dropped silently
	// -------------------------------------------------------------------------

	public function testNonIpAliasMembersAreDroppedSilently(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Multi_Bad'],
		];

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$this->assertArrayNotHasKey(
			'example.org',
			$pfb_local,
			sprintf(
				"Hostname alias member 'example.org' must be dropped, never a \$pfb_local key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayNotHasKey(
			'8080',
			$pfb_local,
			sprintf(
				"Bare-port alias member '8080' must be dropped, never a \$pfb_local key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertNotContains(
			'example.org',
			$pfb_localsub,
			"Hostname alias member must not leak into \$pfb_localsub either."
		);
		$this->assertNotContains(
			'8080',
			$pfb_localsub,
			"Bare-port alias member must not leak into \$pfb_localsub either."
		);
	}

	// -------------------------------------------------------------------------
	// Case D — single-IP alias (regression guard, green before AND after)
	// -------------------------------------------------------------------------

	public function testSingleIpAliasStillResolvesToThatIp(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Single_Host'],
		];

		[$pfb_local, ] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'203.0.113.99',
			$pfb_local,
			sprintf(
				"A single-IP alias must still resolve to that one IP as a \$pfb_local key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case E — entry matching no alias name passes through unchanged
	// -------------------------------------------------------------------------

	public function testNatTargetNotMatchingAnyAliasNamePassesThroughUnchanged(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => '192.0.2.7'],
		];

		[$pfb_local, ] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'192.0.2.7',
			$pfb_local,
			sprintf(
				"A NAT target IP matching no alias name must pass through unchanged and be "
				. "recognised as local.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
	}
}
