<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Renders pfblockerng.prom (issue #3522): exact exposition text, label escaping,
 * disabled DNSBL rows, and source failures that drop only their own families.
 */
#[CoversFunction('pfb_metrics_render')]
final class MetricsRenderTest extends TestCase
{
	/** @param array<string,mixed> $overrides @return array<string,mixed> */
	private function minimal(array $overrides = []): array
	{
		return $overrides + [
			'version' => '3.3.3',
			'ip_tables' => NULL,
			'ip_rule_packets' => NULL,
			'dnsbl_groups' => NULL,
			'resolver_queries' => NULL,
			'feed_success' => NULL,
			'feed_failing' => [],
			'pass' => NULL,
			'source_up' => [],
		];
	}

	public function testFullFixture_RendersExactExposition(): void
	{
		$out = pfb_metrics_render([
			'version' => '3.3.3',
			'ip_tables' => ['pfB_Permit_v4' => 0, 'pfB_Deny_v4' => 1200],
			'ip_rule_packets' => ['pfB_Deny_v4' => 42],
			'dnsbl_groups' => [
				['group' => 'DNSBL_Ads', 'entries' => 5000, 'counter' => 17],
				['group' => 'Upstream', 'entries' => 0, 'counter' => 3],
			],
			'resolver_queries' => 9001,
			'feed_success' => ['ipv4:Alias_v4' => 1700000000, 'dnsbl:DNSBL_Ads' => 1700000060],
			'feed_failing' => [['facility' => 'pfb_sync', 'feed' => 'ipv4:Alias_v4', 'stage' => 'download']],
			'pass' => ['last_start' => 1700000100, 'last_end' => 1700000200],
			'source_up' => ['pfctl' => TRUE, 'dnsbl_db' => TRUE, 'pass_status' => TRUE],
		]);

		$expected = <<<'PROM'
		# HELP pfblockerng_info pfBlockerNG package version.
		# TYPE pfblockerng_info gauge
		pfblockerng_info{version="3.3.3"} 1
		# HELP pfblockerng_ip_table_entries Addresses in each pfB alias table.
		# TYPE pfblockerng_ip_table_entries gauge
		pfblockerng_ip_table_entries{table="pfB_Permit_v4"} 0
		pfblockerng_ip_table_entries{table="pfB_Deny_v4"} 1200
		# HELP pfblockerng_ip_rule_packets_total Packets matched by pfB firewall rules, per alias.
		# TYPE pfblockerng_ip_rule_packets_total counter
		pfblockerng_ip_rule_packets_total{table="pfB_Deny_v4"} 42
		# HELP pfblockerng_dnsbl_blocked_queries_total DNS queries blocked, per DNSBL group.
		# TYPE pfblockerng_dnsbl_blocked_queries_total counter
		pfblockerng_dnsbl_blocked_queries_total{group="DNSBL_Ads"} 17
		pfblockerng_dnsbl_blocked_queries_total{group="Upstream"} 3
		# HELP pfblockerng_dnsbl_group_entries Entries in each enabled DNSBL group.
		# TYPE pfblockerng_dnsbl_group_entries gauge
		pfblockerng_dnsbl_group_entries{group="DNSBL_Ads"} 5000
		pfblockerng_dnsbl_group_entries{group="Upstream"} 0
		# HELP pfblockerng_dnsbl_resolver_queries_total DNS queries handled by the pfB resolver.
		# TYPE pfblockerng_dnsbl_resolver_queries_total counter
		pfblockerng_dnsbl_resolver_queries_total 9001
		# HELP pfblockerng_feed_last_success_timestamp_seconds Unix time of the last successful check, per feed.
		# TYPE pfblockerng_feed_last_success_timestamp_seconds gauge
		pfblockerng_feed_last_success_timestamp_seconds{feed="ipv4:Alias_v4"} 1700000000
		pfblockerng_feed_last_success_timestamp_seconds{feed="dnsbl:DNSBL_Ads"} 1700000060
		# HELP pfblockerng_feed_failing 1 while a feed failure is open, by facility and stage.
		# TYPE pfblockerng_feed_failing gauge
		pfblockerng_feed_failing{facility="pfb_sync",feed="ipv4:Alias_v4",stage="download"} 1
		# HELP pfblockerng_update_last_start_timestamp_seconds Unix time the latest update pass started.
		# TYPE pfblockerng_update_last_start_timestamp_seconds gauge
		pfblockerng_update_last_start_timestamp_seconds 1700000100
		# HELP pfblockerng_update_last_end_timestamp_seconds Unix time the latest update pass ended.
		# TYPE pfblockerng_update_last_end_timestamp_seconds gauge
		pfblockerng_update_last_end_timestamp_seconds 1700000200
		# HELP pfblockerng_metrics_source_up 1 when the metrics source was collected, 0 when it failed.
		# TYPE pfblockerng_metrics_source_up gauge
		pfblockerng_metrics_source_up{source="pfctl"} 1
		pfblockerng_metrics_source_up{source="dnsbl_db"} 1
		pfblockerng_metrics_source_up{source="pass_status"} 1
		PROM;

		$this->assertSame($expected . "\n", $out);
	}

	public function testHostileGroupLabel_IsEscapedOnOneLine(): void
	{
		$out = pfb_metrics_render($this->minimal([
			'dnsbl_groups' => [['group' => "a\"b\\c\n", 'entries' => 1, 'counter' => 2]],
		]));

		$line = <<<'LINE'
		pfblockerng_dnsbl_blocked_queries_total{group="a\"b\\c\n"} 2
		LINE;
		$this->assertStringContainsString($line . "\n", $out);
	}

	public function testInvalidUtf8InALabel_IsScrubbedAndValidUtf8Survives(): void
	{
		$out = pfb_metrics_render($this->minimal([
			'dnsbl_groups' => [
				['group' => "bad\xFF\xFEgroup", 'entries' => 1, 'counter' => 2],
				['group' => "caf\u{e9}", 'entries' => 1, 'counter' => 3],
			],
		]));

		$this->assertTrue(mb_check_encoding($out, 'UTF-8'), 'invalid UTF-8 makes the textfile collector reject the whole file');
		$this->assertStringContainsString('pfblockerng_dnsbl_blocked_queries_total{group="bad??group"} 2' . "\n", $out);
		$this->assertStringContainsString("pfblockerng_dnsbl_blocked_queries_total{group=\"caf\u{e9}\"} 3\n", $out);
	}

	public function testDisabledDnsblRow_KeepsBlockedCounterAndOmitsEntries(): void
	{
		$out = pfb_metrics_render($this->minimal([
			'dnsbl_groups' => [['group' => 'DNSBL_Off', 'entries' => NULL, 'counter' => 4]],
		]));

		$this->assertStringContainsString('pfblockerng_dnsbl_blocked_queries_total{group="DNSBL_Off"} 4' . "\n", $out);
		$this->assertStringNotContainsString('pfblockerng_dnsbl_group_entries', $out);
	}

	public function testNullIpTablesAndFailedPfctl_EmitsSourceUpZeroOnly(): void
	{
		$out = pfb_metrics_render($this->minimal([
			'source_up' => ['pfctl' => FALSE],
		]));

		$expected = <<<'PROM'
		# HELP pfblockerng_info pfBlockerNG package version.
		# TYPE pfblockerng_info gauge
		pfblockerng_info{version="3.3.3"} 1
		# HELP pfblockerng_metrics_source_up 1 when the metrics source was collected, 0 when it failed.
		# TYPE pfblockerng_metrics_source_up gauge
		pfblockerng_metrics_source_up{source="pfctl"} 0
		PROM;

		$this->assertSame($expected . "\n", $out);
	}

	public function testEmptyInputFamilies_EmitNoOrphanHelpOrType(): void
	{
		$out = pfb_metrics_render($this->minimal([
			'ip_tables' => [],
			'ip_rule_packets' => [],
			'dnsbl_groups' => [],
			'feed_success' => [],
		]));

		$expected = <<<'PROM'
		# HELP pfblockerng_info pfBlockerNG package version.
		# TYPE pfblockerng_info gauge
		pfblockerng_info{version="3.3.3"} 1
		PROM;

		$this->assertSame($expected . "\n", $out);
	}
}
