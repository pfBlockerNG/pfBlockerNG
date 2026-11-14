<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Detector terminal outcomes must be durable source facts, not apply results. */
final class ScheduledFeedOutcomeTest extends TestCase
{
	private array $originalPfb = [];
	private string $dir = '';

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_schedule_outcome_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);
		$GLOBALS['pfb']['errlog'] = $this->dir . '/error.log';
		$GLOBALS['pfb']['log'] = $this->dir . '/pfblockerng.log';
		$GLOBALS['pfb']['skipfeed'] = 0;
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		rmdir_recursive($this->dir);
	}

	public function testLocalFeedChangeDetectionIsDeferredToCorePhase(): void
	{
		$dbdir = $GLOBALS['pfb']['dbdir'];
		@mkdir($dbdir, 0755, TRUE);
		$source = "{$dbdir}/scheduled-outcome-source-" . getmypid() . '.txt';
		$orig = $this->dir . '/feed.orig';
		$folder = $this->dir . '/folder';
		mkdir($folder, 0755, TRUE);
		file_put_contents($source, "1.2.3.4\n");
		file_put_contents($orig, "1.2.3.4\n");
		touch($folder . '/feed.txt');
		$GLOBALS['pfb']['cron_update'] = FALSE;
		$GLOBALS['pfb']['update_cron'] = FALSE;

		$result = pfb_update_check('feed', $source, $folder, $this->dir, FALSE, '', '_v4');

		$this->assertNull($result, 'Core FeedPhase owns the local source change decision');
		$this->assertTrue($GLOBALS['pfb']['cron_update']);
		$this->assertTrue($GLOBALS['pfb']['update_cron']);
		$this->assertFileExists($folder . '/feed.update');
		$this->assertFalse(file_exists($folder . '/feed.fail'));
		$this->assertFalse(file_exists($this->dir . '/feed.md5.raw'));
		@unlink($source);
	}

	public function testSkipFeedCapReturnsRetryCapTerminal(): void
	{
		$header = 'capped';
		$GLOBALS['pfb_test_resolve_map']['example.test.'] = [
			['type' => 'A', 'data' => '203.0.113.20'],
		];
		$GLOBALS['pfb']['grep'] = 'grep';
		pfb_logger("\n\n [ pfB_TestAlias - {$header} ] Download FAIL [ NOW ]\n", 2);
		$GLOBALS['pfb']['skipfeed'] = 1;

		$result = pfb_update_check(
			$header,
			'https://example.test/feed',
			$this->dir,
			$this->dir,
			FALSE,
			'',
			'_v4'
		);

		$this->assertSame('retry-cap-reached', $result?->value, 'skipfeed cap must complete with a retry-cap outcome');
	}

	public function testFailureBelowCapReportsNoTerminalOutcome(): void
	{
		$GLOBALS['pfb_test_resolve_map']['example.test.'] = [['type' => 'A', 'data' => '203.0.113.20']];
		$GLOBALS['pfb']['grep'] = 'grep';
		$GLOBALS['pfb']['skipfeed'] = 3;
		unset($GLOBALS['pfb']['scheduled_outcomes']);

		$result = pfb_update_check(
			'retry', 'https://example.test/feed', $this->dir, $this->dir, FALSE, '', '_v4'
		);

		$this->assertNull($result, 'no terminal result: the occurrence stays pending in Core');
		$this->assertArrayNotHasKey('scheduled_outcomes', $GLOBALS['pfb']);
	}

	public function testAlwaysRefreshFormatsDeferTheirOutcomeToCoreFeedPhase(): void
	{
		$folder = $this->dir . '/formats';
		mkdir($folder);
		file_put_contents($folder . '/sync.txt', "old\n");
		file_put_contents($this->dir . '/sync.orig', "old\n");
		$GLOBALS['pfb_test_resolve_map']['example.test.'] = [
			['type' => 'A', 'data' => '203.0.113.20'],
		];
		$outcomes = [];
		$updates = [];
		$rowUpdates = [];
		$markers = [];
		foreach ([
			['whois', 'whois', 'example.com'],
			['asn', 'asn', 'AS64500'],
			['sync', 'rsync', 'https://example.test/feed'],
		] as [$header, $format, $url]) {
			$GLOBALS['pfb']['update_cron'] = FALSE;
			$GLOBALS['pfb']['cron_update'] = FALSE;
			$result = pfb_update_check($header, $url, $folder, $this->dir, FALSE, $format, '_v4');
			$outcomes[$format] = $result?->value;
			$updates[$format] = $GLOBALS['pfb']['update_cron'];
			$rowUpdates[$format] = $GLOBALS['pfb']['cron_update'];
			$markers[$format] = file_exists("{$folder}/{$header}.update");
		}
		$this->assertSame(['whois' => NULL, 'asn' => NULL, 'rsync' => NULL], $outcomes);
		$this->assertSame(['whois' => TRUE, 'asn' => TRUE, 'rsync' => TRUE], $updates);
		$this->assertSame(['whois' => TRUE, 'asn' => TRUE, 'rsync' => TRUE], $rowUpdates);
		$this->assertSame(['whois' => TRUE, 'asn' => TRUE, 'rsync' => TRUE], $markers);
	}

	public function testDownstreamFailureDoesNotUndoSuccessfulSourceOutcome(): void
	{
		$marker = $this->dir . '/feed.update';
		unset($GLOBALS['pfb']['scheduled_outcomes']);
		pfb_schedule_outcome_record('ipv4:feed_v4', PfbScheduleTerminalResult::Success);
		pfb_list_script_failure_record('ip', 'feed_v4', 'transform failed', $this->dir, $marker);

		$this->assertSame(['ipv4:feed_v4' => 'success'], $GLOBALS['pfb']['scheduled_outcomes']);
		$this->assertFileExists($marker);
	}

	public function testSyntheticDnsblipAliasesFollowTheirRebuildMarkers(): void
	{
		$GLOBALS['pfb']['scheduled_runtime_cron'] = TRUE;
		$GLOBALS['pfb']['scheduled_selected_ids'] = ['dnsbl:source' => TRUE];

		$this->assertTrue(pfb_schedule_feed_selected('ipv4', 'DNSBLIP_v4'));
		$this->assertTrue(pfb_schedule_feed_selected('ipv6', 'DNSBLIP_v6'));
		$this->assertFalse(pfb_schedule_feed_selected('ipv4', 'unselected_v4'));
	}
}
