<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';

/**
 * issue #3115 — the scheduled detector's own status rows must land in the two columns the
 * Update log already established, for every feed-header length.
 *
 * Issue #2989 fixed the sync loop's rows (`[ header ]<pad> exists.`) by padding the header
 * field with spaces, which puts their status text in column 53. The detector's rows never
 * got that treatment: they separate `[ header ]` from its status with a single space and
 * reach their verdict with one `\t`, so both columns move with the header's length, and the
 * change-detection probe pads with four tabs and lands in a third column again.
 *
 * The two columns pinned here are the ones already in the log, not new ones: 53 is issue
 * #2989's status column, and 80 is where the probe row's `. 200 OK` already sits.
 *
 * Tabs are rejected outright because a tab's rendered width belongs to whatever displays the
 * log — the Update viewer's textarea, `cat`, a pager — so a column contract cannot be
 * expressed with them at all.
 *
 * Coverage: every detector row whose branch is decidable from the filesystem is driven
 * through pfb_update_check() itself. The four conditional-GET verdicts need a live origin
 * (they are exercised end to end by DownloadRejectValidatorClearTest and
 * tests/smoke/test_smoke_feeds.py), so their status strings are pinned here at the shared
 * formatter instead — one row per parenthetical the detector can emit.
 */
#[CoversFunction('pfb_update_check')]
#[CoversFunction('pfb_log_status_line')]
final class UpdateCheckLogAlignmentTest extends TestCase
{
	/** Column (0-based) that carries a row's status text — issue #2989's column. */
	private const STATUS_COL = 53;

	/** Column (0-based) that carries a row's verdict text — the probe row's `. 200 OK` column. */
	private const VERDICT_COL = 80;

	/** @var array<string,array{bool,mixed}> */
	private array $saved = [];

	private string $sandbox;
	private string $log;
	private string $folder;
	private string $orig;

	protected function setUp(): void
	{
		foreach (['pfb', 'config'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}

		$this->sandbox = (string) tempnam(sys_get_temp_dir(), 'pfb_detector_alignment_');
		$this->assertNotSame('', $this->sandbox, 'failed to create the sandbox path');
		$this->assertTrue(unlink($this->sandbox), 'failed to claim the sandbox path');
		$this->folder = "{$this->sandbox}/txt";
		$this->orig   = "{$this->sandbox}/orig";
		foreach ([$this->sandbox, $this->folder, $this->orig] as $dir) {
			$this->assertTrue(mkdir($dir, 0777, TRUE), "failed to create {$dir}");
		}

		$this->log = "{$this->sandbox}/pfblockerng.log";
		$GLOBALS['pfb']['log']           = $this->log;
		$GLOBALS['pfb']['errlog']        = "{$this->sandbox}/error.log";
		$GLOBALS['pfb']['runlog']        = '';
		$GLOBALS['pfb']['runlog_active'] = FALSE;
		$GLOBALS['pfb']['skipfeed']      = 0;
		// A local feed path is accepted by PFB_FILTER_URL when it sits directly in
		// $pfb['dbdir'] (pfblockerng.inc:2004), which is what makes the local-feed
		// verdict reachable off-appliance.
		$GLOBALS['pfb']['dbdir'] = $this->sandbox;
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->sandbox);
		foreach ($this->saved as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	/** @return list<string> */
	private function loggedLines(): array
	{
		$text = is_file($this->log) ? (string) file_get_contents($this->log) : '';
		return array_values(array_filter(explode("\n", $text), static fn (string $l): bool => $l !== ''));
	}

	/** The one logged line carrying $marker; fails when none or several do. */
	private function rowContaining(string $marker): string
	{
		$lines = $this->loggedLines();
		$hits  = array_values(array_filter($lines, static fn (string $l): bool => str_contains($l, $marker)));
		$this->assertCount(1, $hits, "expected exactly one row carrying '{$marker}', log was:\n" . implode("\n", $lines));
		return $hits[0];
	}

	/** Both columns of one status row, plus the no-tabs rule that makes them hold. */
	private function assertRowColumns(string $line, string $status, string $verdict): void
	{
		$this->assertStringNotContainsString("\t", $line,
			"a status row pads with spaces — a tab's width belongs to the renderer: '{$line}'");
		if ($status !== '') {
			$this->assertSame(self::STATUS_COL, strpos($line, $status),
				'status text must start in column ' . self::STATUS_COL . ": '{$line}'");
		}
		$this->assertSame(self::VERDICT_COL, strpos($line, $verdict),
			'verdict text must start in column ' . self::VERDICT_COL . ": '{$line}'");
	}

	/** A local feed whose bytes match the last-ingested .orig — the unchanged verdict. */
	private function seedUnchangedLocalFeed(string $header): string
	{
		$source = "{$this->sandbox}/localfeed.txt";
		$body   = "198.51.100.7\n";
		$this->assertNotFalse(file_put_contents($source, $body), 'failed to write the local feed');
		$this->assertNotFalse(file_put_contents("{$this->folder}/{$header}.txt", $body), 'failed to write the .txt');
		$this->assertNotFalse(file_put_contents("{$this->orig}/{$header}.orig", $body), 'failed to write the .orig');
		return $source;
	}

	/** @return list<array{string}> */
	public static function headerLengths(): array
	{
		return [
			'short'                => ['abc'],
			'one under a tab stop' => [str_repeat('a', 11)],
			'on a tab stop'        => [str_repeat('a', 12)],
			'wide'                 => [str_repeat('a', 19)],
			'wider'                => [str_repeat('a', 20)],
			'near the field edge'  => [str_repeat('a', 27)],
			'at the field edge'    => [str_repeat('a', 28)],
		];
	}

	/**
	 * Scenario: the reported defect — a header-bearing detector verdict.
	 *
	 * Given a local feed whose content matches its last-ingested copy
	 * When the scheduled detector evaluates it under a feed header of any supported length
	 * Then the verdict's status and verdict text sit in the log's two columns.
	 */
	#[DataProvider('headerLengths')]
	public function testLocalFeedVerdictHoldsBothColumnsAtEveryHeaderLength(string $header): void
	{
		$source = $this->seedUnchangedLocalFeed($header);

		pfb_update_check($header, $source, $this->folder, $this->orig, '', '', '_v4');

		$this->assertRowColumns(
			$this->rowContaining('( local feed unchanged )'),
			'( local feed unchanged )',
			'Update not required'
		);
	}

	/**
	 * A header wider than the header field cannot be padded into column 53, so it keeps
	 * exactly one separating space — the rule issue #2989 set for the sync loop's rows.
	 */
	public function testHeaderWiderThanTheFieldKeepsOneSeparatingSpace(): void
	{
		$header = str_repeat('a', 29);
		$source = $this->seedUnchangedLocalFeed($header);

		pfb_update_check($header, $source, $this->folder, $this->orig, '', '', '_v4');

		$this->assertStringContainsString("[ {$header} ] ( local feed unchanged )",
			$this->rowContaining('( local feed unchanged )'));
	}

	public function testWhoisUpdateFoundHoldsTheVerdictColumn(): void
	{
		pfb_update_check('Whois_v4', 'example.com', $this->folder, $this->orig, '', 'whois', '_v4');

		$this->assertRowColumns($this->rowContaining('Update found'), '', 'Update found');
	}

	public function testPreviousFailureRetryHoldsBothColumns(): void
	{
		$this->assertNotFalse(touch("{$this->folder}/Retry_v4.fail"), 'failed to write the fail marker');

		pfb_update_check('Retry_v4', 'http://203.0.113.10/list.txt', $this->folder, $this->orig, '', '', '_v4');

		$this->assertRowColumns(
			$this->rowContaining('Previous download failed.'),
			'Previous download failed.',
			'Re-attempt download'
		);
	}

	public function testMissingFeedFileUpdateFoundHoldsTheVerdictColumn(): void
	{
		pfb_update_check('Fresh_v4', 'http://203.0.113.10/list.txt', $this->folder, $this->orig, '', '', '_v4');

		$this->assertRowColumns($this->rowContaining('Update found'), '', 'Update found');
	}

	public function testRsyncUpdateFoundHoldsBothColumns(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->folder}/Rsync_v4.txt", "198.51.100.7\n"), 'failed to write the .txt');
		$this->assertNotFalse(file_put_contents("{$this->orig}/Rsync_v4.orig", "198.51.100.7\n"), 'failed to write the .orig');

		pfb_update_check('Rsync_v4', 'rsync://203.0.113.10/module', $this->folder, $this->orig, '', 'rsync', '_v4');

		$this->assertRowColumns($this->rowContaining('( rsync )'), '( rsync )', 'Update found');
	}

	public function testMissingOriginalUpdateFoundHoldsTheVerdictColumn(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->folder}/NoOrig_v4.txt", "198.51.100.7\n"), 'failed to write the .txt');

		pfb_update_check('NoOrig_v4', 'http://203.0.113.10/list.txt', $this->folder, $this->orig, '', '', '_v4');

		$this->assertRowColumns($this->rowContaining('Update found'), '', 'Update found');
	}

	/** @return list<array{string,string,string}> every parenthetical the detector can emit */
	public static function detectorStatuses(): array
	{
		return [
			'change-detection probe' => ['ISC_Block_v4', '( change check )', ''],
			'rsync'                  => ['', '( rsync )', 'Update found'],
			'local feed unchanged'   => ['ISC_Block_v4', '( local feed unchanged )', 'Update not required'],
			'304 not modified'       => ['ISC_Block_v4', '( 304 not modified )', 'Update not required'],
			'content changed'        => ['ISC_Block_v4', '( content changed )', 'Update found'],
			'content unchanged'      => ['ISC_Block_v4', '( content unchanged )', 'Update not required'],
		];
	}

	/**
	 * The widest parenthetical the detector emits still leaves its verdict in column 80, so
	 * no status the log can carry pushes the verdict column out of alignment.
	 */
	#[DataProvider('detectorStatuses')]
	public function testEveryDetectorStatusHoldsBothColumns(string $header, string $status, string $verdict): void
	{
		// The probe row carries no verdict of its own: pfb_download() appends the cURL
		// status to it, so stand in for that with the same '. 200 OK' the log shows.
		$tail = $verdict === '' ? '. 200 OK' : '';

		pfb_logger(pfb_log_status_line($header, $status, $verdict) . $tail . "\n", 1);

		$this->assertRowColumns($this->rowContaining($status), $status, "{$verdict}{$tail}");
	}
}
