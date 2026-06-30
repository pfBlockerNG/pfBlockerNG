<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-37 — DoT/DoQ block rule builder + action-normalisation unit tests.
 *
 * Functions under test:
 *   pfb_dot_block_action()        — normalise a stored/posted action to 'block' | 'reject'.
 *   pfb_dot_block_rule()          — build the per-interface filter/rule array.
 *   pfb_dot_block_floating_rule() — build the single floating filter/rule (floating mode).
 *
 * Intent: the DoT/DoQ block rules are outbound (LAN->WAN) rules, so they DEFAULT to
 * Reject (fast-fail the client to plain DNS) — matching the outbound Rule Action
 * convention on the IP settings page — while remaining user-selectable as Block.
 *
 * Coverage mandate: branch coverage — the action drives the rule 'type' in BOTH
 * directions (reject AND block), with the unknown/empty value falling back to the
 * Reject default; the exclude-alias source is asserted present AND absent.
 */
#[CoversFunction('pfb_dot_block_action')]
#[CoversFunction('pfb_dot_block_rule')]
#[CoversFunction('pfb_dot_block_floating_rule')]
final class DotBlockRuleBuilderTest extends TestCase
{
	// Reset the seeded firewall aliases before each test (test isolation): the source
	// builder only negates an exception alias that actually resolves to a firewall alias.
	protected function setUp(): void
	{
		$this->seedAliases([]);
	}

	protected function tearDown(): void
	{
		$this->seedAliases([]);
	}

	// Seed firewall aliases into config — the source pfb_exclude_alias_exists() reads (#664).
	// (The check is config-based, NOT is_alias(): is_alias() consults the $aliastable cache,
	// which is empty in a cron/service-restart sync, so a valid alias would read as missing.)
	private function seedAliases(array $names, string $type = 'host'): void
	{
		$GLOBALS['config']['aliases']['alias'] = array_map(
			static fn (string $name): array => ['name' => $name, 'type' => $type],
			$names
		);
	}

	// -----------------------------------------------------------------------
	// pfb_dot_block_action() — normalisation
	// -----------------------------------------------------------------------

	public function testActionDefaultsToRejectForEmptyValue(): void
	{
		// Given an unconfigured (absent/empty) action — the upgrade-from-old-config case
		// Then it resolves to Reject (the new default), NOT Block (the old hardcoded type)
		$this->assertSame('reject', pfb_dot_block_action(''), 'empty action must default to reject');
	}

	public function testActionDefaultsToRejectForUnknownValue(): void
	{
		// Given a garbage/unknown token
		// Then it falls back to the Reject default rather than passing through
		$this->assertSame('reject', pfb_dot_block_action('drop'), 'unknown action must fall back to reject');
	}

	public function testActionPreservesExplicitBlock(): void
	{
		// Given the user explicitly selected Block
		$this->assertSame('block', pfb_dot_block_action('block'), 'block must be preserved');
	}

	public function testActionPreservesExplicitReject(): void
	{
		// Given the user explicitly selected Reject
		$this->assertSame('reject', pfb_dot_block_action('reject'), 'reject must be preserved');
	}

	// -----------------------------------------------------------------------
	// pfb_dot_block_rule() — rule disposition follows the action (both branches)
	// -----------------------------------------------------------------------

	public function testRuleTypeDefaultsToRejectForEmptyAction(): void
	{
		// Given an empty action (an existing install upgrading with no action stored)
		$rule = pfb_dot_block_rule('lan', '', '');

		// Then the rule is a Reject — the corrected default for an outbound block rule
		$this->assertSame('reject', $rule['type'], 'default (empty action) DoT rule must be reject');
	}

	public function testRuleTypeIsBlockWhenActionIsBlock(): void
	{
		// Given the action is explicitly Block, the rule must drop silently
		$rule = pfb_dot_block_rule('lan', '', 'block');
		$this->assertSame('block', $rule['type'], 'action=block must yield a block rule');
	}

	public function testRuleTypeIsRejectWhenActionIsReject(): void
	{
		// Given the action is explicitly Reject (proves block above is a real branch,
		// not an always-reject path)
		$rule = pfb_dot_block_rule('lan', '', 'reject');
		$this->assertSame('reject', $rule['type'], 'action=reject must yield a reject rule');
	}

	// -----------------------------------------------------------------------
	// pfb_dot_block_rule() — fixed rule shape (ADR-37 §2.2 field values)
	// -----------------------------------------------------------------------

	public function testRuleCarriesFixedFieldValues(): void
	{
		$rule = pfb_dot_block_rule('opt1', '', 'reject');

		$this->assertSame('opt1', $rule['interface'], 'interface = the passed iface');
		$this->assertSame('inet46', $rule['ipprotocol'], 'ipprotocol must be inet46 (dual-stack)');
		$this->assertSame('tcp/udp', $rule['protocol'], 'protocol must be tcp/udp (DoT TCP + DoQ UDP)');
		$this->assertSame('keep state', $rule['statetype'], 'statetype must be keep state');
		$this->assertSame('pfB_DoT_Block_opt1', $rule['descr'], 'descr = prefix + iface');

		// Destination: the firewall itself on port 853, negated (self-exempt).
		$this->assertSame('(self)', $rule['destination']['network'], 'destination.network = (self)');
		$this->assertArrayHasKey('not', $rule['destination'], 'destination must carry the negation key');
		$this->assertSame('853', $rule['destination']['port'], 'destination.port = 853');
	}

	// -----------------------------------------------------------------------
	// pfb_dot_block_rule() — exception-alias source (both branches)
	// -----------------------------------------------------------------------

	public function testSourceIsAnyWhenNoExcludeAlias(): void
	{
		// Given no exception alias, the source is 'any' (block from every host)
		$rule = pfb_dot_block_rule('lan', '', 'reject');
		$this->assertSame(['any' => ''], $rule['source'], 'no alias -> source any');
	}

	public function testSourceIsNegatedAliasWhenExcludeAliasGiven(): void
	{
		// Given an exception alias that EXISTS, the source negates it so listed hosts bypass
		$this->seedAliases(['DoT_Exceptions']);
		$rule = pfb_dot_block_rule('lan', 'DoT_Exceptions', 'reject');
		$this->assertSame(
			['address' => 'DoT_Exceptions', 'not' => ''],
			$rule['source'],
			'existing alias present -> negated alias source'
		);
	}

	public function testSourceFallsBackToAnyWhenExcludeAliasNotFound(): void
	{
		// Regression: a non-empty exception alias that does NOT resolve to a real firewall
		// alias must NOT be emitted as the source — an unresolvable address renders as a
		// sourceless "from !" that fails the entire pf ruleset load. The guard falls back to
		// 'any' (no exception applied) instead.
		// Before -> the SAME name yields a negated-alias source while it exists (proves the
		// existence check, not some always-any path, is what changes the result).
		$this->seedAliases(['DoT_Exceptions']);
		$ruleExisting = pfb_dot_block_rule('lan', 'DoT_Exceptions', 'reject');
		$this->assertSame(['address' => 'DoT_Exceptions', 'not' => ''], $ruleExisting['source'],
			'pre-condition: existing alias -> negated alias source');

		// When the alias is not a real firewall alias
		$this->seedAliases(['DoT_Exceptions']);
		$rule = pfb_dot_block_rule('lan', 'DoT_Typo', 'reject');

		// Then the source is 'any' (the exception is dropped, the ruleset stays valid)
		$this->assertSame(['any' => ''], $rule['source'], 'unknown alias -> source any (no "from !")');
	}

	public function testSourceFallsBackToAnyForPortAlias(): void
	{
		// A port alias cannot be a firewall-rule source, so even though it exists it must NOT
		// be emitted as the negated source — it falls back to 'any', same as a missing alias.
		// Before -> the SAME name yields a negated-alias source as an ADDRESS (host) alias.
		$this->seedAliases(['SvcAlias'], 'host');
		$ruleHost = pfb_dot_block_rule('lan', 'SvcAlias', 'reject');
		$this->assertSame(['address' => 'SvcAlias', 'not' => ''], $ruleHost['source'],
			'pre-condition: an address (host) alias -> negated alias source');

		// When the same name is a PORT alias instead
		$this->seedAliases(['SvcAlias'], 'port');
		$rule = pfb_dot_block_rule('lan', 'SvcAlias', 'reject');

		// Then the source falls back to 'any' (a port alias is not a usable source)
		$this->assertSame(['any' => ''], $rule['source'], 'port alias -> source any');
	}

	public function testSourceFallsBackToAnyForPfbManagedAlias(): void
	{
		// Defense-in-depth: a pfBlockerNG-managed (pfB_*) alias is rejected at save time, but if
		// a stale/hand-edited config still references one, the rule builder must NOT emit it as
		// the source — it falls back to 'any', same as a missing alias.
		// Before -> an ordinary (non-pfB_) address alias yields a negated-alias source.
		$this->seedAliases(['DoT_Exceptions']);
		$ruleOk = pfb_dot_block_rule('lan', 'DoT_Exceptions', 'reject');
		$this->assertSame(['address' => 'DoT_Exceptions', 'not' => ''], $ruleOk['source'],
			'pre-condition: a non-managed address alias -> negated alias source');

		// When the alias is a pfB_-managed alias that EXISTS (urltable) in config
		$this->seedAliases(['pfB_DNSBLIP'], 'urltable');
		$rule = pfb_dot_block_rule('lan', 'pfB_DNSBLIP', 'reject');

		// Then the source falls back to 'any' (a managed alias is not a usable exception source)
		$this->assertSame(['any' => ''], $rule['source'], 'pfB_ managed alias -> source any');
	}

	// -----------------------------------------------------------------------
	// Key order — the 'tracker' is appended by the caller, so the builder's last
	// key must be 'descr'. Pins the stored-rule key order the sync compare relies on.
	// -----------------------------------------------------------------------

	public function testBuilderOmitsTrackerAndEndsOnDescr(): void
	{
		$rule = pfb_dot_block_rule('lan', '', 'reject');
		$this->assertArrayNotHasKey('tracker', $rule, 'builder must not set tracker (caller appends it last)');
		$this->assertSame('descr', array_key_last($rule), 'descr must be the last key before the tracker is appended');
	}

	// -----------------------------------------------------------------------
	// pfb_dot_block_floating_rule() — single floating rule (floating mode)
	// -----------------------------------------------------------------------

	public function testFloatingRuleIsFloatingQuickDirectionIn(): void
	{
		// Given floating mode, the single rule must be floating + quick with direction 'in'
		// (the direction ADR-37 mandates for a floating variant — matches client egress
		// entering the firewall on the selected interfaces).
		$rule = pfb_dot_block_floating_rule(['lan', 'opt1'], '', 'reject');

		$this->assertSame('yes', $rule['floating'], 'floating rule must set floating=yes');
		$this->assertSame('yes', $rule['quick'], 'floating rule must set quick=yes');
		$this->assertSame('in', $rule['direction'], 'floating rule direction must be in');
	}

	public function testFloatingRuleJoinsAllInterfacesIntoOneRule(): void
	{
		// Given multiple interfaces, floating mode produces ONE rule whose interface field
		// is the comma-joined list (not one rule per interface).
		$rule = pfb_dot_block_floating_rule(['lan', 'opt1', 'opt2'], '', 'reject');
		$this->assertSame('lan,opt1,opt2', $rule['interface'], 'interface = comma-joined selected ifaces');
		$this->assertSame('pfB_DoT_Block_Floating', $rule['descr'], 'floating rule carries the single floating marker');
	}

	public function testFloatingRuleTypeFollowsActionBlock(): void
	{
		// Action drives the floating rule's disposition too (block branch).
		$rule = pfb_dot_block_floating_rule(['lan'], '', 'block');
		$this->assertSame('block', $rule['type'], 'floating action=block must yield a block rule');
	}

	public function testFloatingRuleTypeDefaultsToRejectForEmptyAction(): void
	{
		// And defaults to reject for an empty/unknown action (proves block above is a real branch).
		$rule = pfb_dot_block_floating_rule(['lan'], '', '');
		$this->assertSame('reject', $rule['type'], 'floating default (empty action) must be reject');
	}

	public function testFloatingRuleCarriesFixedDestinationAndSourceBranches(): void
	{
		// Destination is the same negated (self):853 as the per-interface rule.
		$rule = pfb_dot_block_floating_rule(['lan'], '', 'reject');
		$this->assertSame('(self)', $rule['destination']['network'], 'floating destination.network = (self)');
		$this->assertSame('853', $rule['destination']['port'], 'floating destination.port = 853');
		$this->assertSame('inet46', $rule['ipprotocol'], 'floating ipprotocol = inet46');
		$this->assertSame('tcp/udp', $rule['protocol'], 'floating protocol = tcp/udp');
		$this->assertSame(['any' => ''], $rule['source'], 'no alias -> source any');

		// An existing exception alias negates the source, same as the per-interface rule.
		$this->seedAliases(['DoT_Exceptions']);
		$withAlias = pfb_dot_block_floating_rule(['lan'], 'DoT_Exceptions', 'reject');
		$this->assertSame(
			['address' => 'DoT_Exceptions', 'not' => ''],
			$withAlias['source'],
			'existing alias present -> negated alias source'
		);

		// A non-existent alias falls back to 'any' (never a sourceless "from !").
		$rule = pfb_dot_block_floating_rule(['lan'], 'DoT_Missing', 'reject');
		$this->assertSame(['any' => ''], $rule['source'], 'unknown alias -> source any');
	}

	public function testFloatingBuilderOmitsTrackerAndEndsOnDescr(): void
	{
		// Same key-order invariant as the per-interface builder: the caller appends 'tracker'
		// last, so the builder must not set it and 'descr' must be the final key. The sync
		// change-detection compare ($dot_ex_owned !== $dot_new_owned) relies on this order.
		$rule = pfb_dot_block_floating_rule(['lan'], '', 'reject');
		$this->assertArrayNotHasKey('tracker', $rule, 'floating builder must not set tracker (caller appends it last)');
		$this->assertSame('descr', array_key_last($rule), 'descr must be the last key before the tracker is appended');
	}
}
