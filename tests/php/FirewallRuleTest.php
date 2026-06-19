<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_firewall_rule() — pins the rule-array assembly and bucket dispatch for
 * all nine action values, the Advanced Inbound and Advanced Outbound feed
 * settings, vtype, float, log, and the Deny_Both / Permit_Both / Match_Both
 * fall-through behaviour.
 *
 * Each test calls pfb_firewall_rule() against a sandboxed $GLOBALS['pfb'] and
 * asserts the rule pushed onto the correct per-direction bucket; no live pfSense
 * state is involved.
 *
 * Intent anchors (from the UI help texts in pfblockerng_category_edit.php):
 *   - Baseline: auto-rule uses 'any' port, 'any' protocol, 'any' destination,
 *     'any' gateway.
 *   - Advanced Inbound (alias = source): Custom DST Port → destination port;
 *     Custom Destination → destination address; autonot_in inverts the custom
 *     destination address; aproto_in / agateway_in refine the rule.
 *   - Advanced Outbound (alias = destination): Custom DST Port → destination
 *     port; Custom Source → source address; autonot_out inverts the custom
 *     source address; aproto_out / agateway_out refine the rule.
 *   - Invert Source/Destination (autoaddrnot_in / autoaddrnot_out) REQUIRES
 *     Action = Alias_Native (UI validation lines 619-628). Alias_Native has NO
 *     switch case in pfb_firewall_rule() and therefore emits NO auto-rule — the
 *     intended semantics: use the native alias directly in a hand-crafted
 *     inverted rule. The aaddrnot branches inside pfb_firewall_rule() are
 *     therefore unreachable in valid config and are intentionally NOT asserted
 *     as a feature here — see testInvertActionAliasNativeProducesNoAutoRule.
 *
 * Covered branches:
 *   - All nine action values and their target buckets.
 *   - _Both fall-through: one rule lands in BOTH outbound and inbound buckets.
 *   - Advanced Inbound: four destination combinations (neither / adest-only /
 *     aports-only / both); anot_in when adest present and when absent;
 *     aproto_in set vs empty; agateway_in 'default'/''/custom.
 *   - Advanced Outbound: asrc_out empty vs set; anot_out with and without
 *     asrc_out; aports_out; aproto_out; agateway_out.
 *   - Alias_Native and an unknown action → no auto-rule (zero rules in every
 *     bucket), which is the intended Invert Source/Destination behaviour.
 *   - vtype: _v4 → ipprotocol stays 'inet'; _v6 → 'inet6'.
 *   - float off → no 'direction' key on Deny/Permit; float on → 'direction' set.
 *   - Match rules: 'direction' always set even with float off; no 'quick' key
 *     even though base_rule_float has it.
 *   - log: global_log off + pfb_log default → absent; global_log on → present;
 *     pfb_log 'enabled' with global off → present.
 *   - created: username === 'Auto', 'time' key is an int.
 *   - deny action type: Deny_Inbound uses deny_action_inbound; Deny_Outbound
 *     uses deny_action_outbound (fixture sets distinct values).
 */
#[CoversFunction('pfb_firewall_rule')]
final class FirewallRuleTest extends TestCase
{
	private array $originalPfb = [];
	private bool $hadPfb       = FALSE;

	/** Buckets initialised to empty arrays. */
	private const BUCKETS = [
		'deny_outbound',
		'deny_inbound',
		'permit_outbound',
		'permit_inbound',
		'match_outbound',
		'match_inbound',
	];

	protected function setUp(): void
	{
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$buckets = array_fill_keys(self::BUCKETS, []);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], $buckets, [
			'base_rule'            => ['ipprotocol' => 'inet'],
			'base_rule_float'      => ['quick' => 'yes', 'floating' => 'yes', 'ipprotocol' => 'inet'],
			'deny_action_inbound'  => 'block',
			'deny_action_outbound' => 'reject',
			'float'                => 'off',
			'suffix'               => ' Auto Rule',
			'global_log'           => 'off',
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	// -------------------------------------------------------------------------
	// Helper: retrieve the last rule pushed onto a named bucket.
	// -------------------------------------------------------------------------

	/** @return array<string, mixed> */
	private function lastRule(string $bucket): array
	{
		$rules = $GLOBALS['pfb'][$bucket];
		$this->assertIsArray($rules, "bucket '{$bucket}' must be an array");
		$this->assertNotEmpty($rules, "bucket '{$bucket}' must not be empty after the call");
		return $rules[count($rules) - 1];
	}

	/** Assert the bucket grew by exactly one entry and return the new rule. */
	private function assertBucketGrew(string $bucket, int $sizeBefore = 0): array
	{
		$rules = $GLOBALS['pfb'][$bucket];
		$this->assertCount($sizeBefore + 1, $rules,
			"bucket '{$bucket}' must have grown by one rule");
		return $rules[$sizeBefore];
	}

	/** Assert every bucket OTHER than the listed ones is still empty. */
	private function assertOtherBucketsEmpty(string ...$nonEmpty): void
	{
		foreach (self::BUCKETS as $b) {
			if (!in_array($b, $nonEmpty, TRUE)) {
				$this->assertCount(0, $GLOBALS['pfb'][$b],
					"bucket '{$b}' must remain empty");
			}
		}
	}

	// -------------------------------------------------------------------------
	// Baseline rules — per action: correct bucket, type, descr, source/dest,
	// created.username='Auto', created.time is an int.
	// -------------------------------------------------------------------------

	public function testDenyInboundBaselineRule(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_TestAlias', '_v4', 'off');

		$rule = $this->lastRule('deny_inbound');

		$this->assertSame('block',          $rule['type'],                   'type must be deny_action_inbound value');
		$this->assertSame('inet',           $rule['ipprotocol'],             'ipprotocol must be inet for _v4');
		$this->assertSame('pfB_TestAlias Auto Rule', $rule['descr'],         'descr = alias + suffix');
		$this->assertSame(['address' => 'pfB_TestAlias'], $rule['source'],    'source.address = alias');
		$this->assertSame(['any' => ''],    $rule['destination'],             'destination defaults to any when adest+aports empty');
		$this->assertSame('Auto',           $rule['created']['username'],     'created.username must be Auto');
		$this->assertIsInt($rule['created']['time'],                          'created.time must be an int');
		$this->assertArrayNotHasKey('direction', $rule,                       'no direction when float=off');
		$this->assertArrayNotHasKey('log',       $rule,                       'no log key when global_log=off and pfb_log not enabled');
		$this->assertArrayNotHasKey('gateway',   $rule,                       'no gateway when agateway_in=default');
	}

	public function testDenyOutboundBaselineRule(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_TestAlias', '_v4', 'off');

		$rule = $this->lastRule('deny_outbound');

		$this->assertSame('reject',         $rule['type'],                   'type must be deny_action_outbound value');
		$this->assertSame('inet',           $rule['ipprotocol'],             'ipprotocol must be inet for _v4');
		$this->assertSame('pfB_TestAlias Auto Rule', $rule['descr'],         'descr = alias + suffix');
		$this->assertSame(['any' => ''],    $rule['source'],                  'source defaults to any when asrc_out empty');
		$this->assertSame(['address' => 'pfB_TestAlias'], $rule['destination'], 'destination.address = alias');
		$this->assertSame('Auto',           $rule['created']['username'],     'created.username must be Auto');
		$this->assertIsInt($rule['created']['time'],                          'created.time must be an int');
		$this->assertArrayNotHasKey('direction', $rule,                       'no direction when float=off');
		$this->assertArrayNotHasKey('log',       $rule,                       'no log key when global_log=off and pfb_log not enabled');
	}

	public function testPermitInboundBaselineRule(): void
	{
		pfb_firewall_rule('Permit_Inbound', 'pfB_PermitAlias', '_v4', 'off');

		$rule = $this->lastRule('permit_inbound');

		$this->assertSame('pass',           $rule['type'],                   'Permit type must be pass');
		$this->assertSame('pfB_PermitAlias Auto Rule', $rule['descr']);
		$this->assertSame(['address' => 'pfB_PermitAlias'], $rule['source']);
		$this->assertSame(['any' => ''],    $rule['destination']);
		$this->assertSame('Auto',           $rule['created']['username']);
	}

	public function testPermitOutboundBaselineRule(): void
	{
		pfb_firewall_rule('Permit_Outbound', 'pfB_PermitAlias', '_v4', 'off');

		$rule = $this->lastRule('permit_outbound');

		$this->assertSame('pass',           $rule['type'],                   'Permit type must be pass');
		$this->assertSame(['any' => ''],    $rule['source'],                  'source any when asrc_out empty');
		$this->assertSame(['address' => 'pfB_PermitAlias'], $rule['destination']);
	}

	public function testMatchInboundBaselineRule(): void
	{
		pfb_firewall_rule('Match_Inbound', 'pfB_MatchAlias', '_v4', 'off');

		$rule = $this->lastRule('match_inbound');

		$this->assertSame('match',          $rule['type'],                   'Match type must be match');
		$this->assertSame('in',             $rule['direction'],              'Match_Inbound always has direction=in');
		$this->assertArrayNotHasKey('quick', $rule,                          'Match rule must not have quick key (unset from base_rule_float)');
		$this->assertSame('yes',            $GLOBALS['pfb']['base_rule_float']['quick'],
			'base_rule_float fixture must still carry quick=yes (unset only on the rule copy)');
		$this->assertSame('pfB_MatchAlias Auto Rule', $rule['descr']);
		$this->assertSame(['address' => 'pfB_MatchAlias'], $rule['source']);
		$this->assertSame(['any' => ''],    $rule['destination']);
		$this->assertSame('Auto',           $rule['created']['username']);
	}

	public function testMatchOutboundBaselineRule(): void
	{
		pfb_firewall_rule('Match_Outbound', 'pfB_MatchAlias', '_v4', 'off');

		$rule = $this->lastRule('match_outbound');

		$this->assertSame('match',          $rule['type']);
		$this->assertSame('out',            $rule['direction'],              'Match_Outbound always has direction=out');
		$this->assertArrayNotHasKey('quick', $rule,                          'Match rule must not have quick key');
		$this->assertSame(['any' => ''],    $rule['source']);
		$this->assertSame(['address' => 'pfB_MatchAlias'], $rule['destination']);
	}

	// -------------------------------------------------------------------------
	// _Both fall-through — one call pushes TWO rules (outbound AND inbound).
	// -------------------------------------------------------------------------

	public function testDenyBothPushesRuleToOutboundAndInbound(): void
	{
		// Given: all buckets empty (setUp).

		// When: Deny_Both is called.
		pfb_firewall_rule('Deny_Both', 'pfB_BothAlias', '_v4', 'off');

		// Then: exactly one rule in deny_outbound and one in deny_inbound.
		$ruleOut = $this->assertBucketGrew('deny_outbound');
		$ruleIn  = $this->assertBucketGrew('deny_inbound');

		$this->assertSame('reject', $ruleOut['type'],  'Deny_Both outbound rule uses deny_action_outbound');
		$this->assertSame('block',  $ruleIn['type'],   'Deny_Both inbound rule uses deny_action_inbound');
		$this->assertSame(['address' => 'pfB_BothAlias'], $ruleOut['destination'], 'outbound dest = alias');
		$this->assertSame(['address' => 'pfB_BothAlias'], $ruleIn['source'],       'inbound src = alias');

		// All other buckets must stay empty.
		$this->assertOtherBucketsEmpty('deny_outbound', 'deny_inbound');
	}

	public function testPermitBothPushesRuleToOutboundAndInbound(): void
	{
		pfb_firewall_rule('Permit_Both', 'pfB_BothAlias', '_v4', 'off');

		$ruleOut = $this->assertBucketGrew('permit_outbound');
		$ruleIn  = $this->assertBucketGrew('permit_inbound');

		$this->assertSame('pass', $ruleOut['type']);
		$this->assertSame('pass', $ruleIn['type']);
		$this->assertOtherBucketsEmpty('permit_outbound', 'permit_inbound');
	}

	public function testMatchBothPushesRuleToOutboundAndInbound(): void
	{
		pfb_firewall_rule('Match_Both', 'pfB_BothAlias', '_v4', 'off');

		$ruleOut = $this->assertBucketGrew('match_outbound');
		$ruleIn  = $this->assertBucketGrew('match_inbound');

		$this->assertSame('match', $ruleOut['type']);
		$this->assertSame('out',   $ruleOut['direction']);
		$this->assertSame('match', $ruleIn['type']);
		$this->assertSame('in',    $ruleIn['direction']);
		$this->assertArrayNotHasKey('quick', $ruleOut, 'Match_Both outbound must not have quick');
		$this->assertArrayNotHasKey('quick', $ruleIn,  'Match_Both inbound must not have quick');
		$this->assertOtherBucketsEmpty('match_outbound', 'match_inbound');
	}

	// -------------------------------------------------------------------------
	// Deny action type — Deny_Inbound uses deny_action_inbound,
	// Deny_Outbound uses deny_action_outbound (distinct fixture values: block vs reject).
	// -------------------------------------------------------------------------

	public function testDenyInboundRuleTypeMatchesDenyActionInbound(): void
	{
		// Fixture: deny_action_inbound='block', deny_action_outbound='reject' (setUp).
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertSame('block', $this->lastRule('deny_inbound')['type'],
			'Deny_Inbound must use deny_action_inbound (block)');
	}

	public function testDenyOutboundRuleTypeMatchesDenyActionOutbound(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
		$this->assertSame('reject', $this->lastRule('deny_outbound')['type'],
			'Deny_Outbound must use deny_action_outbound (reject)');
	}

	// -------------------------------------------------------------------------
	// Advanced Inbound — destination combinations.
	// -------------------------------------------------------------------------

	public function testDenyInboundDestBothEmptyGivesAnyDestination(): void
	{
		// Neither adest_in nor aports_in — destination=['any'=>''].
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '');
		$rule = $this->lastRule('deny_inbound');
		$this->assertSame(['any' => ''], $rule['destination']);
	}

	public function testDenyInboundDestAdestOnlyGivesAddressDestination(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '192.0.2.0/24', '', '', '');
		$rule = $this->lastRule('deny_inbound');
		$this->assertSame(['address' => '192.0.2.0/24'], $rule['destination']);
	}

	public function testDenyInboundDestAportsOnlyGivesAnyWithPort(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '443', '', '');
		$rule = $this->lastRule('deny_inbound');
		$this->assertSame(['any' => '', 'port' => '443'], $rule['destination']);
	}

	public function testDenyInboundDestBothAdestAndAportsGivesAddressAndPort(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '10.0.0.0/8', '80', '', '');
		$rule = $this->lastRule('deny_inbound');
		$this->assertSame(['address' => '10.0.0.0/8', 'port' => '80'], $rule['destination']);
	}

	// -------------------------------------------------------------------------
	// Advanced Inbound — anot_in: sets destination['not'] only when adest non-empty.
	// -------------------------------------------------------------------------

	public function testDenyInboundAnot_inWithAdestSetsDestinationNot(): void
	{
		// adest_in non-empty AND anot_in='on' → destination gets 'not'.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '192.0.2.0/24', '', '', 'on');
		$rule = $this->lastRule('deny_inbound');
		$this->assertArrayHasKey('not', $rule['destination'],
			'destination[not] must be set when adest_in is non-empty and anot_in=on');
	}

	public function testDenyInboundAnot_inWithoutAdestDoesNotSetDestinationNot(): void
	{
		// adest_in empty AND anot_in='on' → destination stays ['any'=>'']; no 'not'.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', 'on');
		$rule = $this->lastRule('deny_inbound');
		$this->assertArrayNotHasKey('not', $rule['destination'],
			'destination[not] must NOT be set when adest_in is empty, even with anot_in=on');
	}

	// -------------------------------------------------------------------------
	// Advanced Inbound — aproto_in: empty → no protocol key; set → protocol key.
	// -------------------------------------------------------------------------

	public function testDenyInboundAproto_inAbsentLeavesNoProtocol(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayNotHasKey('protocol', $this->lastRule('deny_inbound'));
	}

	public function testDenyInboundAproto_inSetAddsProtocol(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', 'tcp', '');
		$rule = $this->lastRule('deny_inbound');
		$this->assertSame('tcp', $rule['protocol']);
	}

	// -------------------------------------------------------------------------
	// Advanced Inbound — agateway_in: 'default' and '' → no gateway; real name → set.
	// -------------------------------------------------------------------------

	public function testDenyInboundGatewayDefaultLeavesNoGatewayKey(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off', 'default');
		$this->assertArrayNotHasKey('gateway', $this->lastRule('deny_inbound'));
	}

	public function testDenyInboundGatewayEmptyStringLeavesNoGatewayKey(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off', '');
		$this->assertArrayNotHasKey('gateway', $this->lastRule('deny_inbound'));
	}

	public function testDenyInboundGatewayCustomNameSetsGateway(): void
	{
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off', 'GW_WAN');
		$rule = $this->lastRule('deny_inbound');
		$this->assertSame('GW_WAN', $rule['gateway']);
	}

	// -------------------------------------------------------------------------
	// Advanced Inbound — touch on Permit_Inbound too.
	// -------------------------------------------------------------------------

	public function testPermitInboundAnot_inWithAdestSetsDestinationNot(): void
	{
		pfb_firewall_rule('Permit_Inbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '10.0.0.0/8', '', '', 'on');
		$this->assertArrayHasKey('not', $this->lastRule('permit_inbound')['destination']);
	}

	// -------------------------------------------------------------------------
	// Advanced Outbound — asrc_out: empty → source=['any'=>'']; set → source['address'].
	// -------------------------------------------------------------------------

	public function testDenyOutboundAsrc_outEmptyGivesAnySource(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '', '', '', '', '', '');
		$this->assertSame(['any' => ''], $this->lastRule('deny_outbound')['source']);
	}

	public function testDenyOutboundAsrc_outSetGivesAddressSource(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '', '', '10.0.0.1');
		$rule = $this->lastRule('deny_outbound');
		$this->assertSame(['address' => '10.0.0.1'], $rule['source']);
	}

	// -------------------------------------------------------------------------
	// Advanced Outbound — anot_out: sets source['not'] only when asrc_out non-empty.
	// -------------------------------------------------------------------------

	public function testDenyOutboundAnot_outWithAsrc_outSetsSourceNot(): void
	{
		// Given: asrc_out non-empty AND anot_out='on'.
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '', '', '10.0.0.1', '', '', 'on');
		$rule = $this->lastRule('deny_outbound');
		$this->assertArrayHasKey('not', $rule['source'],
			'source[not] must be set when asrc_out is non-empty and anot_out=on');
	}

	public function testDenyOutboundAnot_outWithoutAsrc_outDoesNotSetSourceNot(): void
	{
		// asrc_out empty, anot_out='on' → source=['any'=>'']; no 'not'.
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '', '', '', '', '', 'on');
		$rule = $this->lastRule('deny_outbound');
		$this->assertArrayNotHasKey('not', $rule['source'],
			'source[not] must NOT be set when asrc_out is empty, even with anot_out=on');
	}

	// -------------------------------------------------------------------------
	// Advanced Outbound — aports_out adds destination port.
	// -------------------------------------------------------------------------

	public function testDenyOutboundAports_outAddsDestinationPort(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '', '', '', '8080');
		$rule = $this->lastRule('deny_outbound');
		$this->assertSame(['address' => 'pfB_A', 'port' => '8080'], $rule['destination']);
	}

	public function testDenyOutboundAports_outEmptyOmitsPort(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
		$rule = $this->lastRule('deny_outbound');
		$this->assertSame(['address' => 'pfB_A'], $rule['destination']);
	}

	// -------------------------------------------------------------------------
	// Advanced Outbound — aproto_out.
	// -------------------------------------------------------------------------

	public function testDenyOutboundAproto_outSetAddsProtocol(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '', '', '', '', 'udp');
		$this->assertSame('udp', $this->lastRule('deny_outbound')['protocol']);
	}

	public function testDenyOutboundAproto_outEmptyLeavesNoProtocol(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayNotHasKey('protocol', $this->lastRule('deny_outbound'));
	}

	// -------------------------------------------------------------------------
	// Advanced Outbound — agateway_out: 'default' and '' → no gateway; real name → set.
	// -------------------------------------------------------------------------

	public function testDenyOutboundGatewayDefaultLeavesNoGatewayKey(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off', 'default', 'default');
		$this->assertArrayNotHasKey('gateway', $this->lastRule('deny_outbound'));
	}

	public function testDenyOutboundGatewayEmptyStringLeavesNoGatewayKey(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off', 'default', '');
		$this->assertArrayNotHasKey('gateway', $this->lastRule('deny_outbound'));
	}

	public function testDenyOutboundGatewayCustomNameSetsGateway(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off', 'default', 'GW_WAN_OUT');
		$this->assertSame('GW_WAN_OUT', $this->lastRule('deny_outbound')['gateway']);
	}

	// -------------------------------------------------------------------------
	// Advanced Outbound — touch on Permit_Outbound too.
	// -------------------------------------------------------------------------

	public function testPermitOutboundAsrc_outSetGivesAddressSource(): void
	{
		pfb_firewall_rule('Permit_Outbound', 'pfB_A', '_v4', 'off',
			'default', 'default', '', '', '', '', '', '', '172.16.0.0/12');
		$this->assertSame(['address' => '172.16.0.0/12'],
			$this->lastRule('permit_outbound')['source']);
	}

	// -------------------------------------------------------------------------
	// Alias_Native and unknown actions produce NO auto-rule (zero bucket entries).
	//
	// Intent: Action=Alias_Native is required for "Invert Source/Destination"
	// (UI validation lines 619-628). It has no switch case in pfb_firewall_rule()
	// so NO auto-rule is emitted — the alias is used raw in user-defined rules.
	// -------------------------------------------------------------------------

	public function testInvertActionAliasNativeProducesNoAutoRule(): void
	{
		/**
		 * Scenario: Alias_Native with both Invert toggles active emits no auto-rule.
		 *
		 * Given: all six buckets are empty (setUp).
		 * When:  pfb_firewall_rule() is called with action=Alias_Native and both
		 *        autoaddrnot flags set to 'on' (the only valid config per UI validation).
		 * Then:  every bucket remains empty — Alias_Native skips the switch and the
		 *        function returns without pushing anything.
		 */

		// Given: all buckets empty.

		// When: Alias_Native called with invert on for both directions.
		pfb_firewall_rule('Alias_Native', 'pfB_X', '_v4', 'off',
			'default', 'default', 'on', '', '', '', '', 'on', '', '', '', '');

		// Then: no bucket received any rule.
		foreach (self::BUCKETS as $bucket) {
			$this->assertCount(0, $GLOBALS['pfb'][$bucket],
				"bucket '{$bucket}' must stay empty when action=Alias_Native (no auto-rule emitted)");
		}
	}

	public function testUnknownActionProducesNoAutoRule(): void
	{
		/**
		 * Scenario: an unrecognised action pushes nothing onto any bucket.
		 *
		 * Given: all six buckets are empty.
		 * When:  pfb_firewall_rule() is called with action values that match no
		 *        switch case ('Disabled' and 'Frobnicate').
		 * Then:  all six buckets remain empty after each call.
		 */

		// Given: all buckets empty.

		// When/Then: 'Disabled' matches no case.
		pfb_firewall_rule('Disabled', 'pfB_X', '_v4', 'off');
		foreach (self::BUCKETS as $bucket) {
			$this->assertCount(0, $GLOBALS['pfb'][$bucket],
				"bucket '{$bucket}' must stay empty for action=Disabled");
		}

		// When/Then: an arbitrary unknown string matches no case.
		pfb_firewall_rule('Frobnicate', 'pfB_X', '_v4', 'off');
		foreach (self::BUCKETS as $bucket) {
			$this->assertCount(0, $GLOBALS['pfb'][$bucket],
				"bucket '{$bucket}' must stay empty for action=Frobnicate");
		}
	}

	// -------------------------------------------------------------------------
	// vtype — _v4 keeps ipprotocol='inet'; _v6 → 'inet6'.
	// Before/after transition proves causation.
	// -------------------------------------------------------------------------

	public function testVtypeV4KeepsInet(): void
	{
		// Given: call with _v4.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertSame('inet', $this->lastRule('deny_inbound')['ipprotocol'],
			'_v4 must leave ipprotocol as inet');
	}

	public function testVtypeV6SetsInet6(): void
	{
		// Given: _v4 first (before-state).
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$before = $this->lastRule('deny_inbound');
		$this->assertSame('inet', $before['ipprotocol'], 'before: ipprotocol=inet for _v4');

		// When: _v6 call.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v6', 'off');
		$after = $this->lastRule('deny_inbound');

		// Then: ipprotocol changed to inet6.
		$this->assertSame('inet6', $after['ipprotocol'], 'after: ipprotocol=inet6 for _v6');
	}

	public function testVtypeV6OnOutboundSetsInet6(): void
	{
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v6', 'off');
		$this->assertSame('inet6', $this->lastRule('deny_outbound')['ipprotocol']);
	}

	public function testVtypeV6OnMatchSetsInet6(): void
	{
		pfb_firewall_rule('Match_Outbound', 'pfB_A', '_v6', 'off');
		$this->assertSame('inet6', $this->lastRule('match_outbound')['ipprotocol']);
	}

	// -------------------------------------------------------------------------
	// float — off → no 'direction' key on Deny/Permit; on → 'direction' set.
	// Match always has 'direction' regardless of float.
	// Before/after transition for Deny_Inbound.
	// -------------------------------------------------------------------------

	public function testDenyInboundFloatOffLeavesNoDirectionKey(): void
	{
		// Given: float=off (setUp default).
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayNotHasKey('direction', $this->lastRule('deny_inbound'),
			'Deny_Inbound with float=off must not have direction key');
	}

	public function testDenyInboundFloatOnFlipAddsDirection(): void
	{
		// Given: float off.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$before = $this->lastRule('deny_inbound');
		$this->assertArrayNotHasKey('direction', $before,
			'before: no direction when float=off');

		// When: float flipped to on.
		$GLOBALS['pfb']['float'] = 'on';
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$after = $this->lastRule('deny_inbound');

		// Then: direction='in' now present.
		$this->assertSame('in', $after['direction'],
			'after: Deny_Inbound direction=in when float=on');
	}

	public function testDenyOutboundFloatOnSetsDirectionOut(): void
	{
		$GLOBALS['pfb']['float'] = 'on';
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
		$this->assertSame('out', $this->lastRule('deny_outbound')['direction']);
	}

	public function testPermitInboundFloatOffLeavesNoDirectionKey(): void
	{
		pfb_firewall_rule('Permit_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayNotHasKey('direction', $this->lastRule('permit_inbound'));
	}

	public function testPermitOutboundFloatOnSetsDirectionOut(): void
	{
		$GLOBALS['pfb']['float'] = 'on';
		pfb_firewall_rule('Permit_Outbound', 'pfB_A', '_v4', 'off');
		$this->assertSame('out', $this->lastRule('permit_outbound')['direction']);
	}

	// -------------------------------------------------------------------------
	// Match rules always have 'direction' even with float=off; no 'quick' key.
	// -------------------------------------------------------------------------

	public function testMatchInboundAlwaysHasDirectionEvenWithFloatOff(): void
	{
		// Precondition: float=off (setUp default).
		$this->assertSame('off', $GLOBALS['pfb']['float']);
		pfb_firewall_rule('Match_Inbound', 'pfB_A', '_v4', 'off');
		$rule = $this->lastRule('match_inbound');
		$this->assertSame('in', $rule['direction'],
			'Match_Inbound must always have direction=in regardless of float');
		$this->assertArrayNotHasKey('quick', $rule,
			'Match rule must not carry the quick key from base_rule_float');
	}

	public function testMatchOutboundAlwaysHasDirectionEvenWithFloatOff(): void
	{
		$this->assertSame('off', $GLOBALS['pfb']['float']);
		pfb_firewall_rule('Match_Outbound', 'pfB_A', '_v4', 'off');
		$rule = $this->lastRule('match_outbound');
		$this->assertSame('out', $rule['direction'],
			'Match_Outbound must always have direction=out regardless of float');
		$this->assertArrayNotHasKey('quick', $rule);
	}

	// -------------------------------------------------------------------------
	// log — three cases: absent / global_log on / pfb_log 'enabled'.
	// -------------------------------------------------------------------------

	public function testLogAbsentWhenGlobalLogOffAndPfbLogNotEnabled(): void
	{
		// global_log='off' (setUp), pfb_log='off'.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayNotHasKey('log', $this->lastRule('deny_inbound'),
			'log must be absent when global_log=off and pfb_log != enabled');
	}

	public function testLogPresentWhenGlobalLogOn(): void
	{
		// Given: global_log=off (before-state verified; log absent).
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayNotHasKey('log', $this->lastRule('deny_inbound'),
			'before: log absent with global_log=off');

		// When: global_log flipped to on.
		$GLOBALS['pfb']['global_log'] = 'on';
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$after = $this->lastRule('deny_inbound');

		// Then: log key now present (value is '').
		$this->assertArrayHasKey('log', $after,
			'after: log must be present when global_log=on');
		$this->assertSame('', $after['log']);
	}

	public function testLogPresentWhenPfbLogEnabledAndGlobalLogOff(): void
	{
		// global_log remains off; pfb_log='enabled' (per-list aliaslog).
		// Before: no log.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayNotHasKey('log', $this->lastRule('deny_inbound'),
			'before: log absent when pfb_log is not enabled');

		// When: pfb_log='enabled'.
		pfb_firewall_rule('Deny_Inbound', 'pfB_A', '_v4', 'enabled');
		$after = $this->lastRule('deny_inbound');

		// Then: log present.
		$this->assertArrayHasKey('log', $after,
			'after: log must be present when pfb_log=enabled');
	}

	public function testLogPresentOnOutboundWhenGlobalLogOn(): void
	{
		$GLOBALS['pfb']['global_log'] = 'on';
		pfb_firewall_rule('Deny_Outbound', 'pfB_A', '_v4', 'off');
		$this->assertArrayHasKey('log', $this->lastRule('deny_outbound'));
	}

	public function testLogPresentOnMatchWhenPfbLogEnabled(): void
	{
		pfb_firewall_rule('Match_Outbound', 'pfB_A', '_v4', 'enabled');
		$this->assertArrayHasKey('log', $this->lastRule('match_outbound'));
	}
}
