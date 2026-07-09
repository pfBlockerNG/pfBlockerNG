<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1004 Step 1 — pfb_ip_parsed_fail(): the dedicated IP-parse-error sink.
 *
 * Scenario: mirrors pfb_parsed_fail()'s CSV/FILE_APPEND idiom exactly, plus a
 * trailing line-number column (the #1004 DNSBL-parity addition).
 *   Background:
 *     - pfb_ip_parsed_fail($header, $line, $oline, $logfile, $lineno) writes
 *       "{now},{header},{line-or-'null'},{oline},{lineno}\n" via FILE_APPEND.
 *     - An empty $line records the literal string 'null', never a blank field.
 *
 * This step wires ONLY the helper -- no parse-loop caller exists yet (Step 2).
 */
#[CoversFunction('pfb_ip_parsed_fail')]
final class PfbIpParsedFailTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	protected function tearDown(): void
	{
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	/** Create an empty temp file, registered for teardown removal, with its result asserted. */
	private function mktemp(string $prefix): string
	{
		$path = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($path, "tempnam({$prefix}) failed");
		$this->tmpfiles[] = $path;
		$this->assertNotFalse(file_put_contents($path, ''), "could not truncate {$path}");
		return $path;
	}

	private function readFile(string $path): string
	{
		$raw = file_get_contents($path);
		$this->assertNotFalse($raw, "could not read {$path}");
		return (string) $raw;
	}

	/**
	 * A single call writes exactly one CSV row: now,header,line,oline,lineno.
	 */
	public function testAppendsSingleCsvRowWithLineNumber(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: a malformed IP line is recorded with its source line number.
		pfb_ip_parsed_fail('pfB_X_v4', '1.2.3.4bad', '1.2.3.4bad garbage', $logfile, 42);

		// Then: exactly one newline-terminated CSV row, timestamp first, lineno last.
		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},pfB_X_v4,1\.2\.3\.4bad,1\.2\.3\.4bad garbage,42\n$/',
			$logged,
			"unexpected CSV row shape: {$logged}"
		);
	}

	/**
	 * An empty $line records the literal 'null' -- never a blank field. Uses a
	 * stricter `!== ''` check than pfb_parsed_fail()'s `?:`, so a line whose
	 * content is literally "0" is kept as "0" here, not coerced to 'null'.
	 */
	public function testEmptyLineRecordsNullPlaceholder(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: $line is empty (e.g. a wholly-unparseable row).
		pfb_ip_parsed_fail('pfB_X_v4', '', 'garbage-row', $logfile, 7);

		// Then: the line field reads 'null', not ''.
		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},pfB_X_v4,null,garbage-row,7\n$/',
			$logged,
			"empty \$line must record 'null', not blank: {$logged}"
		);
	}

	/**
	 * Regression (issue #1004): a raw fgets() $oline keeps its trailing newline.
	 * The writer must strip it so the appended $lineno column stays on the SAME
	 * physical line -- otherwise the record splits and the next row's field0
	 * (its timestamp) is emptied, which ADR-60 age-cutoff reads as expired and
	 * can wipe the whole log. Pins exactly one physical line per record.
	 */
	public function testRawFgetsLineWithTrailingNewlineDoesNotSplitTheRecord(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: two failures are recorded with fgets-shaped $oline (trailing "\n").
		pfb_ip_parsed_fail('FeedA', '1.1.1.1bad', "1.1.1.1bad junk\n", $logfile, 3);
		pfb_ip_parsed_fail('FeedB', '2.2.2.2bad', "2.2.2.2bad junk\n", $logfile, 8);

		// Then: exactly two physical lines, each with a parseable timestamp in field0
		// (a split would produce 3+ lines, two of them starting with a stray comma).
		$logged = $this->readFile($logfile);
		$lines  = explode("\n", rtrim($logged, "\n"));
		$this->assertCount(2, $lines, "each record must be exactly one physical line: {$logged}");
		foreach ($lines as $l) {
			$this->assertMatchesRegularExpression(
				'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},/',
				$l,
				"every physical line must start with a parseable field0 timestamp: {$l}"
			);
		}
		$this->assertStringEndsWith(",1.1.1.1bad junk,3\n", explode("\n", $logged)[0] . "\n");
	}

	/**
	 * Two calls append two rows back-to-back (FILE_APPEND) -- the second call
	 * must not truncate/overwrite the first.
	 */
	public function testTwoCallsAppendTwoRowsViaFileAppend(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: two distinct failures are recorded in sequence.
		pfb_ip_parsed_fail('FeedA', '1.1.1.1bad', '1.1.1.1bad junk', $logfile, 1);
		pfb_ip_parsed_fail('FeedB', '2.2.2.2bad', '2.2.2.2bad junk', $logfile, 2);

		// Then: both rows are present, back-to-back (each newline-terminated), in call order.
		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},FeedA,1\.1\.1\.1bad,1\.1\.1\.1bad junk,1\n'
			. '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},FeedB,2\.2\.2\.2bad,2\.2\.2\.2bad junk,2\n$/',
			$logged,
			"FILE_APPEND must accumulate both rows, not overwrite the first: {$logged}"
		);
	}
}
