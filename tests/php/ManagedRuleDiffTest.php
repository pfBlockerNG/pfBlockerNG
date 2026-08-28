<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_diff_managed_rules() — pure diff helper that classifies pfBlockerNG-owned
 * filter rules as created / modified / removed between two rule arrays, and sets
 * 'reordered' = TRUE when no pfB rule changed content (only order or user rules differ).
 *
 * Test fail-before/pass-after applies: the function is new, so calling it on the
 * pre-change code raises a fatal (undefined function) — definitively red. Green after.
 */
#[CoversFunction('pfb_diff_managed_rules')]
final class ManagedRuleDiffTest extends TestCase
{
	/** Minimal pfB rule with a given descr and optional extra field. */
	private static function rule(string $descr, array $extra = []): array
	{
		return array_merge(['descr' => $descr, 'type' => 'block', 'interface' => 'wan'], $extra);
	}

	public function testEmptyInputsReturnsEmptyDiffAndReordered(): void
	{
		$result = pfb_diff_managed_rules([], []);

		$this->assertSame([], $result['created'],  'created must be empty for empty inputs');
		$this->assertSame([], $result['modified'], 'modified must be empty for empty inputs');
		$this->assertSame([], $result['removed'],  'removed must be empty for empty inputs');
		$this->assertTrue($result['reordered'],    'reordered must be TRUE when nothing changed');
	}

	public function testCreatedDetectedWhenPfbRuleAddedToNew(): void
	{
		$old = [];
		$new = [self::rule('pfB_Deny_Inbound_WAN')];

		$result = pfb_diff_managed_rules($old, $new);

		$this->assertContains('pfB_Deny_Inbound_WAN', $result['created'],
			'a pfB rule present in new but absent in old must appear in created');
		$this->assertSame([], $result['modified']);
		$this->assertSame([], $result['removed']);
		$this->assertFalse($result['reordered']);
	}

	public function testRemovedDetectedWhenPfbRuleDroppedFromNew(): void
	{
		$old = [self::rule('pfB_PRI4_Outbound')];
		$new = [];

		$result = pfb_diff_managed_rules($old, $new);

		$this->assertContains('pfB_PRI4_Outbound', $result['removed'],
			'a pfB rule present in old but absent in new must appear in removed');
		$this->assertSame([], $result['created']);
		$this->assertSame([], $result['modified']);
		$this->assertFalse($result['reordered']);
	}

	public function testModifiedDetectedWhenPfbRuleContentChanges(): void
	{
		$old = [self::rule('pfB_DNSBL_Permit', ['interface' => 'lan'])];
		$new = [self::rule('pfB_DNSBL_Permit', ['interface' => 'opt1'])];

		$result = pfb_diff_managed_rules($old, $new);

		$this->assertContains('pfB_DNSBL_Permit', $result['modified'],
			'same descr with differing content must appear in modified, not created/removed');
		$this->assertSame([], $result['created']);
		$this->assertSame([], $result['removed']);
		$this->assertFalse($result['reordered']);
	}

	public function testReorderedTrueWhenPfbRulesSwapOrderOnly(): void
	{
		$rule_a = self::rule('pfB_Deny_Inbound_WAN');
		$rule_b = self::rule('pfB_PRI4_Outbound');
		$old    = [$rule_a, $rule_b];
		$new    = [$rule_b, $rule_a];

		$result = pfb_diff_managed_rules($old, $new);

		$this->assertSame([], $result['created'],  'no pfB rule created on a pure reorder');
		$this->assertSame([], $result['modified'], 'no pfB rule modified on a pure reorder');
		$this->assertSame([], $result['removed'],  'no pfB rule removed on a pure reorder');
		$this->assertTrue($result['reordered'],    'reordered must be TRUE when pfB sets are identical');
	}

	public function testUserRulesNeverAppearInDiff(): void
	{
		// Only a non-pfB rule changes — the pfB diff must be empty and reordered TRUE.
		$old = [self::rule('My LAN rule', ['type' => 'pass'])];
		$new = [self::rule('My LAN rule', ['type' => 'block'])];

		$result = pfb_diff_managed_rules($old, $new);

		$this->assertSame([], $result['created'],
			'a changed user rule must not appear in created');
		$this->assertSame([], $result['modified'],
			'a changed user rule must not appear in modified');
		$this->assertSame([], $result['removed'],
			'a changed user rule must not appear in removed');
		$this->assertTrue($result['reordered'],
			'reordered TRUE when only user rules differ (pfB set is unchanged)');
	}

	public function testUserRuleAddedOnlyYieldsReorderedTrue(): void
	{
		// Adding a user rule: pfB diff empty, reordered TRUE.
		$old = [self::rule('pfB_Deny_Inbound_WAN')];
		$new = [self::rule('pfB_Deny_Inbound_WAN'), self::rule('User block rule')];

		$result = pfb_diff_managed_rules($old, $new);

		$this->assertSame([], $result['created']);
		$this->assertSame([], $result['modified']);
		$this->assertSame([], $result['removed']);
		$this->assertTrue($result['reordered'],
			'adding only a user rule leaves the pfB set unchanged → reordered TRUE');
	}
}
