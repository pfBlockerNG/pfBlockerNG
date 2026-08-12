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
		foreach (glob($this->dir . '/*') ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dir);
	}

	public function testSuccessfulUnchangedLocalSourceReturnsSuccessTerminal(): void
	{
		@mkdir($GLOBALS['pfb']['dbdir'], 0755, TRUE);
		$source = $GLOBALS['pfb']['dbdir'] . '/scheduled-outcome-source-' . getmypid() . '.txt';
		$orig = $this->dir . '/feed.orig';
		$folder = $this->dir . '/folder';
		mkdir($folder, 0755, TRUE);
		file_put_contents($source, "1.2.3.4\n");
		file_put_contents($orig, "1.2.3.4\n");
		touch($folder . '/feed.txt');

		$result = pfb_update_check(
			'feed',
			$source,
			$folder,
			$this->dir,
			FALSE,
			'',
			'_v4'
		);

		$this->assertSame('success', $result?->value, 'unchanged local source must close a pending occurrence');
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
}
