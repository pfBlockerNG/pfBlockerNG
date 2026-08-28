<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_validate_log() -- the thin emit wrapper for the canonical download-validation
 * reject line (ADR-48 Phase 1). It must route through pfb_logger() at the caller's
 * level: the default reject level (2) writes to BOTH the pfB log and the error log;
 * level 1 writes to the pfB log only -- proving level routing, not just presence.
 * Uses the sink-capture technique from PfbLoggerIsoTimestampTest: $GLOBALS['pfb']
 * 'log'/'errlog' point at temp files so the real on-disk write is asserted.
 *
 * ADR-60 P2: pfb_logger() now inserts its ISO-8601 stamp AFTER
 * pfb_validate_log_line()'s leading "\n" (a pure separator from the PREVIOUS
 * write, preserved verbatim) and BEFORE the "pfb_validate: REJECT ..." text --
 * expectations below match on that shape, not the pre-stamp literal.
 */
#[CoversFunction('pfb_validate_log')]
final class PfbValidateLogTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['log', 'errlog', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		// A stray 'runlog_active' from an earlier test must not mirror our writes
		// into a third file this test never provisions.
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
	}

	/**
	 * pfb_validate_log_line()'s leading "\n" is preserved verbatim by pfb_logger();
	 * the ISO-8601 stamp lands right after it, before the rest of the canonical line.
	 */
	private function assertSinkContainsStampedLine(string $expectedLine, string $sink, string $message): void
	{
		$pattern = '/\n\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ' . preg_quote(substr($expectedLine, 1), '/') . '/';
		$this->assertMatchesRegularExpression($pattern, $sink, $message);
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function tempFile(string $prefix): string
	{
		$path = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($path, "could not create temp file for {$prefix}");
		$this->tmpfiles[] = $path;
		return $path;
	}

	public function testDefaultLevelWritesBothPfbLogAndErrorLog(): void
	{
		// Given: two empty temp sinks.
		$log    = $this->tempFile('pfb_validate_log_');
		$errlog = $this->tempFile('pfb_validate_errlog_');
		$GLOBALS['pfb']['log']    = $log;
		$GLOBALS['pfb']['errlog'] = $errlog;

		$this->assertSame('', file_get_contents($log), 'pfB log must start empty');
		$this->assertSame('', file_get_contents($errlog), 'error log must start empty');

		$expectedLine = pfb_validate_log_line('FeedX', 'mime', 'r', 'd');

		// When: emitted at the default (reject) level.
		pfb_validate_log('FeedX', 'mime', 'r', 'd');

		// Then: the canonical line lands in BOTH sinks (level 2 semantics).
		$logContents    = (string) file_get_contents($log);
		$errlogContents = (string) file_get_contents($errlog);
		$this->assertSinkContainsStampedLine(
			$expectedLine,
			$logContents,
			"expected pfB log to contain <{$expectedLine}>, got <{$logContents}>"
		);
		$this->assertSinkContainsStampedLine(
			$expectedLine,
			$errlogContents,
			"expected error log to contain <{$expectedLine}>, got <{$errlogContents}>"
		);
	}

	public function testLevelOneWritesPfbLogOnlyNotErrorLog(): void
	{
		// Given: two empty temp sinks.
		$log    = $this->tempFile('pfb_validate_log_');
		$errlog = $this->tempFile('pfb_validate_errlog_');
		$GLOBALS['pfb']['log']    = $log;
		$GLOBALS['pfb']['errlog'] = $errlog;

		$this->assertSame('', file_get_contents($log), 'pfB log must start empty');
		$this->assertSame('', file_get_contents($errlog), 'error log must start empty');

		$expectedLine = pfb_validate_log_line('FeedY', 'structural', 'r2', 'd2');

		// When: emitted at level 1 (pfB log only -- not the reject default).
		pfb_validate_log('FeedY', 'structural', 'r2', 'd2', 1);

		// Then: the pfB log carries the line...
		$logContents = (string) file_get_contents($log);
		$this->assertSinkContainsStampedLine(
			$expectedLine,
			$logContents,
			"expected pfB log to contain <{$expectedLine}>, got <{$logContents}>"
		);
		// ...but the error log stays untouched -- proves level routing, not just
		// that SOME write happened.
		$errlogContents = (string) file_get_contents($errlog);
		$this->assertSame(
			'',
			$errlogContents,
			"expected error log to stay EMPTY at level 1, got <{$errlogContents}>"
		);
	}

	/**
	 * ADR-48 Phase 2: the four ADR-45 structural-probe call sites in pfb_download()
	 * build detail as `"{$file_type} " . basename($file_download)` and pass it
	 * RAW to pfb_validate_log($header, 'structural', 'probe_failed', $detail) --
	 * pfb_download() itself is not off-appliance unit-testable (curl/exec), so
	 * this pins the exact call-site detail SHAPE and proves it reaches the sink
	 * completely VERBATIM -- pfb_validate_log_line() no longer HTML-escapes (its
	 * sole renderer, the Logs-tab textarea, never parses HTML). Phase 3 smoke
	 * covers the true end-to-end four lines on the live VM.
	 */
	public function testStructuralStageCallSiteShapeIsUnescapedInSink(): void
	{
		// Given: an empty sink and the exact detail-construction expression used
		// at the call sites, fed a raw '&' -- as file(1) output could carry one.
		$log = $this->tempFile('pfb_validate_structural_log_');
		$GLOBALS['pfb']['log'] = $log;
		$this->assertSame('', file_get_contents($log), 'pfB log must start empty');

		$file_type     = 'application/x-gzip&evil';
		$file_download = '/tmp/pfB_Feed7.gz';
		$detail        = "{$file_type} " . basename($file_download);

		// When: the call-site swap emits through pfb_validate_log().
		pfb_validate_log('pfB_Feed7', 'structural', 'probe_failed', $detail);

		// Then: the sink carries the canonical line with '&' verbatim (never
		// "&amp;") -- the call site passes the raw value straight through, and
		// the formatter no longer escapes it either.
		$expectedLine = pfb_validate_log_line('pfB_Feed7', 'structural', 'probe_failed', $detail);
		$logged       = (string) file_get_contents($log);
		$this->assertSinkContainsStampedLine($expectedLine, $logged, "expected sink to contain <{$expectedLine}>, got <{$logged}>");
		$this->assertStringContainsString('application/x-gzip&evil', $logged);
		$this->assertStringNotContainsString(
			'&amp;',
			$logged,
			"detail was HTML-escaped in <{$logged}>"
		);
	}
}
