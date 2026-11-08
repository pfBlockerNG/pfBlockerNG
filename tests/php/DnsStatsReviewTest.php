<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/DnsStatsAggregationTest.php';
require_once __DIR__ . '/AlertsPageLoader.php';

final class DnsStatsReviewTest extends TestCase
{
	private function pageSource(): string
	{
		return file_get_contents(__DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
	}

	public function testUnterminatedQuotedEofKeepsThePhysicalLineTotal(): void
	{
		foreach (["\n", "\r\n"] as $ending) {
			foreach ([1, 2] as $lines) {
				$input = 'DNS-reply,2030-01-15 09:00:00,"unterminated' . str_repeat($ending, $lines);
				[$result] = DnsStatsAggregationTest::aggregate('dnsbl_reply_stat', $input);
				$this->assertSame($lines, $result['count']['dnsbl_reply_stat'], bin2hex($input));
			}
		}
	}

	public function testCommaDomainSurvivesRenderedCellsFiltersAndThreatUrls(): void
	{
		pfb_test_load_alerts_page_functions();
		$domain = 'a,b.test';
		$rows = [['DNSBL', '2030-01-15 09:00:00', $domain, '192.0.2.1', 'Python', 'TLD', 'group', $domain, 'feed', '+', 'A']];
		[$all] = DnsStatsAggregationTest::aggregate('dnsbl_stat', DnsStatsAggregationTest::csv($rows));
		$source = $this->pageSource();
		$source = substr($source, strpos($source, '// issue #1495:'));
		$start = strpos($source, 'if (!empty($alert_stats[$alert_view][$stat_type])) {');
		$end = strpos($source, '?>', $start);
		$render = substr($source, $start, $end - $start);
		foreach (['dnsbldomain', 'dnsblevald'] as $stat_type) {
			$alert_stats = $all;
			$alert_view = 'dnsbl_stat';
			$pfbmaxtable = 'max';
			$stype = ['', '', '', TRUE, 'domain'];
			ob_start();
			try {
				eval($render);
				$html = ob_get_contents();
			} finally {
				ob_end_clean();
			}
			$this->assertStringContainsString('>' . $domain . '</td>', $html, $stat_type);
			$this->assertStringContainsString('>TLD</td>', $html, $stat_type);
			$this->assertStringContainsString('value="' . $domain . '"', $html, $stat_type);
			$this->assertStringContainsString('?domain=' . rawurlencode($domain) . '"', $html, $stat_type);
		}
	}

	public function testReplyDomainAndSourceIpFilterSplitOnlyAtTheIpSuffix(): void
	{
		$source = $this->pageSource();
		$start = strpos($source, "if (\$submit_type == 'replysrcipd') {");
		$end = strpos($source, "elseif (\$submit_type == 'replydstipd')", $start);
		$handler = substr($source, $start, $end - $start);
		$prior = $_POST;
		try {
			$_POST = ['filterlogentries_submit_replysrcipd' => 'a,b.test,192.0.2.1'];
			$submit_type = 'replysrcipd';
			$final_type = 'replydomain';
			eval($handler);
			$this->assertSame('a,b.test', $_POST['filterlogentries_replydomain']);
			$this->assertSame('192.0.2.1', $_POST['filterlogentries_replysrcip']);
		} finally {
			$_POST = $prior;
		}
	}
}
