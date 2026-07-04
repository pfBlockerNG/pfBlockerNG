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
 *
 *   Case F (IPv6 members classify exactly like IPv4 ones):
 *     Given alias 'V6_Hosts' = '2001:db8::1 2001:db8:1::/64'
 *     Then  the plain IPv6 member is its own $pfb_local key and a host inside
 *           the IPv6 CIDR member is recognised via $pfb_localsub
 *
 *   Case G (empty / whitespace-only alias address is dropped safely):
 *     Given alias 'Empty_Alias' whose stored address is only whitespace
 *     Then  pfb_collect_localip() returns without error and neither an empty
 *           key nor the alias name itself survives in $pfb_local
 *
 *   Case H (malformed non-string entry must not fatal — MUST fail before the
 *           is_string() guard, pass after):
 *     Given a NAT rule whose 'target' is an ARRAY (corrupted / hand-edited
 *           config.xml), a shape the pre-#782 code tolerated with only an
 *           array_flip() warning
 *     Then  pfb_collect_localip() completes without a TypeError and the other
 *           collected entries are unaffected
 *
 *   Cases I–L (nested alias references resolve transitively, issue #784 —
 *              I/J/K/L MUST fail before the transitive expansion, pass after):
 *     I: referenced alias listed BEFORE the referencing one (pfSense's typical
 *        config.xml order) — members behind the nested name are collected,
 *        including a CIDR member routed to $pfb_localsub
 *     J: referencing alias listed BEFORE the referenced one — order must not
 *        matter (the pre-#782 code resolved one level only in this ordering,
 *        by accident)
 *     K: a two-alias reference CYCLE terminates (depth cap) and still yields
 *        both aliases' IP members
 *     L: a three-level chain resolves through every level
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
					['name' => 'V6_Hosts',     'address' => '2001:db8::1 2001:db8:1::/64'],
					['name' => 'Empty_Alias',  'address' => '   '],
					// #784 nested-alias fixtures. Referenced-first order (pfSense's
					// typical config.xml layout):
					['name' => 'Inner_Hosts',  'address' => '203.0.113.60 198.51.100.32/28'],
					['name' => 'Outer_Ref',    'address' => 'Inner_Hosts 203.0.113.70'],
					// Referencing-first order:
					['name' => 'Outer_First',  'address' => 'Inner_Last'],
					['name' => 'Inner_Last',   'address' => '203.0.113.80'],
					// Reference cycle:
					['name' => 'Cycle_A',      'address' => 'Cycle_B 203.0.113.90'],
					['name' => 'Cycle_B',      'address' => 'Cycle_A 203.0.113.91'],
					// Three-level chain:
					['name' => 'Chain_L1',     'address' => 'Chain_L2'],
					['name' => 'Chain_L2',     'address' => 'Chain_L3'],
					['name' => 'Chain_L3',     'address' => '203.0.113.95'],
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

	// -------------------------------------------------------------------------
	// Case F — IPv6 alias members classify exactly like IPv4 ones
	// -------------------------------------------------------------------------

	public function testIpv6AliasMembersSplitAndClassifyLikeIpv4(): void
	{
		// Guards a future refactor that special-cases IPv4 (e.g. dotted-quad
		// detection instead of the generic is_ipaddr()/is_subnet() calls): the
		// split/classify path must stay address-family agnostic.
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'V6_Hosts'],
		];

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'2001:db8::1',
			$pfb_local,
			sprintf(
				"Plain IPv6 alias member 2001:db8::1 must be its own \$pfb_local key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$host = '2001:db8:1::abcd';
		$this->assertTrue(
			pfb_local_ip($host, $pfb_localsub),
			sprintf(
				"Host %s inside IPv6 alias CIDR member 2001:db8:1::/64 must be recognised "
				. "as local via pfb_localsub.\npfb_localsub: %s",
				$host,
				implode(', ', $pfb_localsub)
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case G — empty / whitespace-only alias address dropped safely
	// -------------------------------------------------------------------------

	public function testWhitespaceOnlyAliasAddressIsDroppedWithoutError(): void
	{
		// Guards the empty-member skip in the split loop: a whitespace-only
		// address must produce no key at all (not '', not the alias name).
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Empty_Alias'],
		];

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$this->assertArrayNotHasKey(
			'',
			$pfb_local,
			sprintf(
				"A whitespace-only alias address must never yield an empty \$pfb_local key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayNotHasKey(
			'Empty_Alias',
			$pfb_local,
			sprintf(
				"The matched alias NAME must be consumed, not left behind as a key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertNotContains(
			'',
			$pfb_localsub,
			"A whitespace-only alias address must not leak an empty \$pfb_localsub entry."
		);
	}

	// -------------------------------------------------------------------------
	// Case H — malformed non-string entry must not fatal (#461-style tolerance)
	// -------------------------------------------------------------------------

	public function testArrayTypedNatTargetDoesNotFatalTheAliasWalk(): void
	{
		// Scenario: array_key_exists() throws a TypeError on a non-scalar key
		//           under PHP 8, so the alias walk must skip non-string entries.
		//
		// Given  a NAT rule whose 'target' is an ARRAY (corrupted / hand-edited
		//        config.xml) alongside a well-formed alias-name target
		// When   pfb_collect_localip() runs
		// Then   it completes without a TypeError (pre-guard: uncaught TypeError
		//        'Cannot access offset of type array on array' — FAILS)
		//        AND the well-formed alias target still resolves normally.
		$GLOBALS['config']['nat']['rule'] = [
			['target' => ['192.0.2.1', '192.0.2.2']],
			['target' => 'Single_Host'],
		];

		// When: a fatal TypeError would abort here (suppress the array_flip()
		// warning the tolerated stray entry triggers, same as pre-#782 code).
		[$pfb_local, ] = @pfb_collect_localip();

		// Then: reaching the assertion proves no TypeError; the sibling
		// well-formed alias target must still have been resolved.
		$this->assertArrayHasKey(
			'203.0.113.99',
			$pfb_local,
			sprintf(
				"An array-typed NAT target must be skipped (pre-#782 tolerance), leaving "
				. "the well-formed alias target resolved.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case I — nested alias, referenced-first ordering (#784: fails before fix)
	// -------------------------------------------------------------------------

	public function testNestedAliasReferencedFirstResolvesMembersAndCidr(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Outer_Ref'],
		];

		[$pfb_local, $pfb_localsub] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'203.0.113.60',
			$pfb_local,
			sprintf(
				"IP member behind nested alias 'Inner_Hosts' must be collected as local.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$host = '198.51.100.35';
		$this->assertTrue(
			pfb_local_ip($host, $pfb_localsub),
			sprintf(
				"Host %s inside nested alias CIDR member 198.51.100.32/28 must be recognised "
				. "via pfb_localsub.\npfb_localsub: %s",
				$host,
				implode(', ', $pfb_localsub)
			)
		);
		$this->assertArrayHasKey(
			'203.0.113.70',
			$pfb_local,
			sprintf(
				"The referencing alias's own direct IP member must still be collected.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayNotHasKey(
			'Inner_Hosts',
			$pfb_local,
			sprintf(
				"The nested alias NAME must be consumed by expansion, never left as a key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case J — nested alias, referencing-first ordering (#784: fails before fix)
	// -------------------------------------------------------------------------

	public function testNestedAliasReferencingFirstResolvesRegardlessOfOrder(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Outer_First'],
		];

		[$pfb_local, ] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'203.0.113.80',
			$pfb_local,
			sprintf(
				"Nested resolution must not depend on aliases/alias ordering: 'Outer_First' "
				. "is stored before the 'Inner_Last' it references.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayNotHasKey(
			'Inner_Last',
			$pfb_local,
			sprintf(
				"The nested alias NAME must be consumed by expansion, never left as a key.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
	}

	// -------------------------------------------------------------------------
	// Case K — reference cycle terminates, both members collected (#784)
	// -------------------------------------------------------------------------

	public function testNestedAliasCycleTerminatesAndCollectsBothMembers(): void
	{
		// Given: Cycle_A references Cycle_B and vice versa. The depth cap must
		// terminate the expansion (reaching the assertions proves it) while both
		// aliases' IP members are still collected.
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Cycle_A'],
		];

		[$pfb_local, ] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'203.0.113.90',
			$pfb_local,
			sprintf(
				"Cycle_A's direct IP member must be collected.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		$this->assertArrayHasKey(
			'203.0.113.91',
			$pfb_local,
			sprintf(
				"Cycle_B's IP member (reachable only through the cycle edge) must be "
				. "collected.\npfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
		foreach (['Cycle_A', 'Cycle_B'] as $name) {
			$this->assertArrayNotHasKey(
				$name,
				$pfb_local,
				sprintf(
					"Alias NAME '%s' must never survive as a \$pfb_local key.\npfb_local keys: %s",
					$name,
					implode(', ', array_keys($pfb_local))
				)
			);
		}
	}

	// -------------------------------------------------------------------------
	// Case L — three-level chain resolves through every level (#784)
	// -------------------------------------------------------------------------

	public function testNestedAliasThreeLevelChainResolves(): void
	{
		$GLOBALS['config']['nat']['rule'] = [
			['target' => 'Chain_L1'],
		];

		[$pfb_local, ] = pfb_collect_localip();

		$this->assertArrayHasKey(
			'203.0.113.95',
			$pfb_local,
			sprintf(
				"Chain_L1 -> Chain_L2 -> Chain_L3 must resolve to the leaf IP.\n"
				. "pfb_local keys: %s",
				implode(', ', array_keys($pfb_local))
			)
		);
	}
}
