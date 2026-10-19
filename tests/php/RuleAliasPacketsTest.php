<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_rule_alias_packets(): the widget's per-alias rule and packet aggregation
 * over the pfB filter rules and the pf tracker counters.
 */
#[CoversFunction('pfb_rule_alias_packets')]
final class RuleAliasPacketsTest extends TestCase
{
	public function testAggregatesEnabledDisabledAndSkipsDnsblAndNonPfbRules(): void
	{
		$filter_rules = [
			// enabled pfB deny on the source side
			['descr' => 'pfB_Alpha', 'tracker' => 101, 'type' => 'block',
				'source' => ['address' => 'pfB_Alpha_v4'], 'destination' => ['address' => 'any']],
			// disabled pfB rule on the destination side
			['descr' => 'pfB_Beta', 'tracker' => 102, 'type' => 'pass', 'disabled' => '',
				'source' => ['address' => 'any'], 'destination' => ['address' => 'pfB_Beta_v4']],
			// DNSBL Ping rule: skipped entirely, its tracker is never counted
			['descr' => 'pfB_DNSBL_Ping', 'tracker' => 103, 'type' => 'pass',
				'source' => ['address' => 'pfB_Gamma_v4'], 'destination' => ['address' => 'any']],
			// not a pfB rule: tracked, but names no pfB alias
			['descr' => 'LAN to any', 'tracker' => 104, 'type' => 'pass',
				'source' => ['address' => 'lan_net'], 'destination' => ['address' => 'any']],
		];
		$pf_rules = [
			['tracker' => 101, 'packets' => 40],
			'pfctl: rule lookup failed',          // non-array entry
			['tracker' => 102, 'packets' => 15],
			['tracker' => 103, 'packets' => 999], // Ping tracker: not tracked
			['tracker' => 104, 'packets' => 7],
			['tracker' => 101, 'packets' => -5], // negative packets: no contribution
		];

		$this->assertSame(
			[
				'pfB_Alpha_v4' => ['rule' => 1, 'packets' => 40, 'type' => 'Block'],
				'pfB_Beta_v4'  => ['rule' => 0, 'packets' => 15, 'type' => ''],
			],
			pfb_rule_alias_packets($filter_rules, $pf_rules)
		);
	}

	public function testTwoEnabledRulesOnOneAliasCountTwoAndTheirTrackersSumTheirPackets(): void
	{
		$filter_rules = [
			['descr' => 'pfB_Alpha in', 'tracker' => 201, 'type' => 'block',
				'source' => ['address' => 'pfB_Alpha_v4'], 'destination' => ['address' => 'any']],
			['descr' => 'pfB_Alpha out', 'tracker' => 202, 'type' => 'block',
				'source' => ['address' => 'any'], 'destination' => ['address' => 'pfB_Alpha_v4']],
		];
		$pf_rules = [
			['tracker' => 201, 'packets' => 30],
			['tracker' => 202, 'packets' => 12],
		];

		$this->assertSame(
			['pfB_Alpha_v4' => ['rule' => 2, 'packets' => 42, 'type' => 'Block']],
			pfb_rule_alias_packets($filter_rules, $pf_rules)
		);
	}

	public function testDnsblPermitRuleIsSkippedLikeThePingRule(): void
	{
		$filter_rules = [
			['descr' => 'pfB_DNSBL_Permit', 'tracker' => 301, 'type' => 'pass',
				'source' => ['address' => 'pfB_Delta_v4'], 'destination' => ['address' => 'any']],
		];
		$pf_rules = [['tracker' => 301, 'packets' => 500]];

		$this->assertSame([], pfb_rule_alias_packets($filter_rules, $pf_rules));
	}

	public function testRuleWithAnEmptyTypeIsLabelledUnknown(): void
	{
		$filter_rules = [
			['descr' => 'pfB_Epsilon', 'tracker' => 401, 'type' => '',
				'source' => ['address' => 'pfB_Epsilon_v4'], 'destination' => ['address' => 'any']],
		];
		$pf_rules = [['tracker' => 401, 'packets' => 5]];

		$this->assertSame(
			['pfB_Epsilon_v4' => ['rule' => 1, 'packets' => 5, 'type' => 'unknown']],
			pfb_rule_alias_packets($filter_rules, $pf_rules)
		);
	}
}
