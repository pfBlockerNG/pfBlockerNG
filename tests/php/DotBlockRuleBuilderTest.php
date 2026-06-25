<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-37 — DoT/DoQ block rule builder + action-normalisation unit tests.
 *
 * Functions under test:
 *   pfb_dot_block_action()  — normalise a stored/posted action to 'block' | 'reject'.
 *   pfb_dot_block_rule()    — build the per-interface filter/rule array.
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
final class DotBlockRuleBuilderTest extends TestCase
{
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
		// Given an exception alias, the source negates that alias so listed hosts bypass
		$rule = pfb_dot_block_rule('lan', 'DoT_Exceptions', 'reject');
		$this->assertSame(
			['address' => 'DoT_Exceptions', 'not' => ''],
			$rule['source'],
			'alias present -> negated alias source'
		);
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
}
