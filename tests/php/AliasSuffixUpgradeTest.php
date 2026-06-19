<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_rule_alias_needs_v4_suffix() — pins the predicate that guards the
 * firewall-rule '_v4' suffix migration (scan phase and upgrade phase in
 * pfblockerng.inc).
 *
 * The predicate returns TRUE only for a bare pfB_ alias on an inet-family rule
 * that still needs the '_v4' suffix. Addresses already ending in '_v4' or '_v6'
 * are excluded:
 *   - '_v4' already suffixed — no double-suffix.
 *   - '_v6' guard — fixes issue #360: without this guard a rule referencing
 *     'pfB_Bogons_v6' on an inet-family rule would be rewritten to the
 *     nonexistent 'pfB_Bogons_v6_v4', breaking the pf filter reload. The NAT
 *     upgrade path already carried this guard; the filter-rule paths did not.
 *
 * Branch coverage: every exit path of the predicate has its own assertion.
 * The '_v6'+inet→FALSE case is paired with a bare-pfB_+inet→TRUE case in the
 * same test so green proves the '_v6' guard is a real branch, not an
 * always-FALSE path.
 */
#[CoversFunction('pfb_rule_alias_needs_v4_suffix')]
final class AliasSuffixUpgradeTest extends TestCase
{
	// -------------------------------------------------------------------------
	// Core: bare pfB_ alias on inet — the only case that should return TRUE.
	// Paired in one test with the _v6 case to prove both branches are real.
	// -------------------------------------------------------------------------

	/**
	 * A bare pfB_ alias on an inet-family rule needs the '_v4' suffix (TRUE),
	 * but a pfB_*_v6 alias on the same inet-family rule must NOT be eligible
	 * (FALSE) — appending '_v4' would produce the nonexistent 'pfB_Foo_v6_v4'
	 * (issue #360).
	 */
	public function testBarePfbInetNeedsSuffixButV6InetDoesNot(): void
	{
		// Given: a bare pfB_ alias on an inet rule → should be suffixed.
		$this->assertTrue(
			pfb_rule_alias_needs_v4_suffix('pfB_Bogons', 'inet'),
			'bare pfB_ alias + inet must return TRUE (needs _v4 suffix)'
		);

		// Given: a _v6 alias on an inet rule → must NOT be suffixed (issue #360).
		$this->assertFalse(
			pfb_rule_alias_needs_v4_suffix('pfB_Bogons_v6', 'inet'),
			'pfB_*_v6 alias + inet must return FALSE (would become pfB_*_v6_v4)'
		);
	}

	// -------------------------------------------------------------------------
	// Already suffixed with '_v4' — no double-suffix.
	// -------------------------------------------------------------------------

	public function testAlreadyV4SuffixedReturnsFalse(): void
	{
		$this->assertFalse(
			pfb_rule_alias_needs_v4_suffix('pfB_Bogons_v4', 'inet'),
			'pfB_*_v4 alias already has the suffix — must return FALSE'
		);
	}

	// -------------------------------------------------------------------------
	// IPv6-family rule — suffix migration only applies to inet.
	// -------------------------------------------------------------------------

	public function testBarePfbInet6ReturnsFalse(): void
	{
		$this->assertFalse(
			pfb_rule_alias_needs_v4_suffix('pfB_Bogons', 'inet6'),
			'bare pfB_ alias on an inet6 rule must return FALSE (not an IPv4 rule)'
		);
	}

	// -------------------------------------------------------------------------
	// Non-pfB_ address — never eligible.
	// -------------------------------------------------------------------------

	public function testNonPfbAddressReturnsFalse(): void
	{
		$this->assertFalse(
			pfb_rule_alias_needs_v4_suffix('RFC1918', 'inet'),
			'non-pfB_ address must return FALSE'
		);
	}

	// -------------------------------------------------------------------------
	// Empty string — the 'any' source/destination case; must not crash.
	// -------------------------------------------------------------------------

	public function testEmptyAddressReturnsFalse(): void
	{
		$this->assertFalse(
			pfb_rule_alias_needs_v4_suffix('', 'inet'),
			'empty address (any rule) must return FALSE without error'
		);
	}
}
