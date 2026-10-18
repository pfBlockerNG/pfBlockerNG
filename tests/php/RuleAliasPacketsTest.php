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
			['tracker' => 101, 'packets' => 0],   // zero packets: no contribution
		];

		$this->assertSame(
			[
				'pfB_Alpha_v4' => ['rule' => 1, 'packets' => 40, 'type' => 'Block'],
				'pfB_Beta_v4'  => ['rule' => 0, 'packets' => 15, 'type' => ''],
			],
			pfb_rule_alias_packets($filter_rules, $pf_rules)
		);
	}
}
