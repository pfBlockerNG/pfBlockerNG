<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_parse_fail_log() -- the CSV parse-failure sink shared by the DNSBL and
 * IP per-line fail paths (issue #1408). Pins the written bytes: one appended
 * newline-terminated row "{Y-m-d H:i:s},{header},{line},{oline},{lineno}".
 *
 * Axes: falsy-line coercion ('0' vs '') x mode (lenient/strict via
 * $keep_falsy_line), $oline trailing CRLF stripped vs mid-string LF kept,
 * comma-containing $line kept raw, UTF-8 $line kept raw, default
 * $lineno='', multi-append ordering (FILE_APPEND).
 */
#[CoversFunction('pfb_parse_fail_log')]
final class PfbParseFailLogTest extends TestCase
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
	 * The divergent branch: lenient mode's `$line ?: 'null'` treats the literal
	 * string '0' as falsy -- unlike strict mode's `$line !== ''`, which keeps
	 * '0' as-is.
	 */
	public function testLenientModeCoercesLiteralZeroLineToNull(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_lenient0_');

		pfb_parse_fail_log('TestFeed', '0', 'orig 0 line', $logfile, 9);

		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},TestFeed,null,orig 0 line,9\n$/',
			$logged,
			"lenient mode must coerce a literal '0' \$line to 'null' (the divergent `?:` branch); got: {$logged}"
		);
	}

	public function testStrictModeKeepsLiteralZeroLine(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_strict0_');

		pfb_parse_fail_log('TestFeed', '0', 'orig 0 line', $logfile, 9, TRUE);

		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},TestFeed,0,orig 0 line,9\n$/',
			$logged,
			"strict mode must keep a literal '0' \$line as '0', not coerce it to 'null'; got: {$logged}"
		);
	}

	public function testLenientModeCoercesEmptyLineToNull(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_lenientempty_');

		pfb_parse_fail_log('TestFeed', '', 'orig empty line', $logfile, 2);

		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},TestFeed,null,orig empty line,2\n$/',
			$logged,
			"lenient mode must coerce an empty \$line to 'null'; got: {$logged}"
		);
	}

	public function testCommaContainingLineIsKeptRawUnescaped(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_comma_');

		pfb_parse_fail_log('TestFeed', 'a,b,c-not-a-domain', 'orig, csv, line', $logfile, 1);

		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},TestFeed,a,b,c-not-a-domain,orig, csv, line,1\n$/',
			$logged,
			"a comma-containing \$line/\$oline is pre-existing CSV column injection -- pinned raw, not escaped; got: {$logged}"
		);
	}

	public function testOlineTrailingCrlfIsStripped(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_crlf_');

		pfb_parse_fail_log('TestFeed', 'line', "orig line\r\n", $logfile, 4);

		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},TestFeed,line,orig line,4\n$/',
			$logged,
			"a raw fgets()-shaped \\r\\n-terminated \$oline must have the CRLF stripped, not just LF; got: {$logged}"
		);
	}

	public function testOlineEmbeddedMidStringNewlineIsKept(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_midnl_');

		pfb_parse_fail_log('TestFeed', 'line', "before\nafter", $logfile, 6);

		$logged = $this->readFile($logfile);
		$this->assertStringContainsString(
			"before\nafter,6\n",
			$logged,
			"only a TRAILING \\r\\n on \$oline is stripped -- a mid-string embedded \\n must survive verbatim; got: {$logged}"
		);
	}

	public function testUtf8LineIsPreservedRaw(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_utf8_');

		pfb_parse_fail_log('TestFeed', 'xn--might-be-münchen.example', 'orig utf8 line', $logfile, 3);

		$logged = $this->readFile($logfile);
		$this->assertStringContainsString(
			'münchen',
			$logged,
			"a UTF-8 \$line must be written byte-for-byte, not mangled; got: {$logged}"
		);
	}

	public function testDefaultLinenoIsEmptyString(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_deflineno_');

		pfb_parse_fail_log('TestFeed', 'line', 'orig line', $logfile);

		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},TestFeed,line,orig line,\n$/',
			$logged,
			"omitting \$lineno must default to an empty trailing column, not drop it; got: {$logged}"
		);
	}

	// -------------------------------------------------------------------
	// Strict mode ($keep_falsy_line = TRUE) -- the IP fail path's contract.
	// -------------------------------------------------------------------

	/**
	 * A single call writes exactly one CSV row: now,header,line,oline,lineno.
	 */
	public function testStrictModeAppendsSingleCsvRowWithLineNumber(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: a malformed IP line is recorded with its source line number.
		pfb_parse_fail_log('pfB_X_v4', '1.2.3.4bad', '1.2.3.4bad garbage', $logfile, 42, TRUE);

		// Then: exactly one newline-terminated CSV row, timestamp first, lineno last.
		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},pfB_X_v4,1\.2\.3\.4bad,1\.2\.3\.4bad garbage,42\n$/',
			$logged,
			"unexpected CSV row shape: {$logged}"
		);
	}

	/**
	 * An empty $line records the literal 'null' -- never a blank field. Strict mode
	 * uses `!== ''` (not `?:`), so a line whose content is literally "0" is kept as
	 * "0" here (pinned separately above), not coerced to 'null'.
	 */
	public function testStrictModeEmptyLineRecordsNullPlaceholder(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: $line is empty (e.g. a wholly-unparseable row).
		pfb_parse_fail_log('pfB_X_v4', '', 'garbage-row', $logfile, 7, TRUE);

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
	public function testStrictModeRawFgetsLineWithTrailingNewlineDoesNotSplitTheRecord(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: two failures are recorded with fgets-shaped $oline (trailing "\n").
		pfb_parse_fail_log('FeedA', '1.1.1.1bad', "1.1.1.1bad junk\n", $logfile, 3, TRUE);
		pfb_parse_fail_log('FeedB', '2.2.2.2bad', "2.2.2.2bad junk\n", $logfile, 8, TRUE);

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
	public function testStrictModeTwoCallsAppendTwoRowsViaFileAppend(): void
	{
		$logfile = $this->mktemp('pfb_ip_parse_err_');	// Given: an empty parse-error log.

		// When: two distinct failures are recorded in sequence.
		pfb_parse_fail_log('FeedA', '1.1.1.1bad', '1.1.1.1bad junk', $logfile, 1, TRUE);
		pfb_parse_fail_log('FeedB', '2.2.2.2bad', '2.2.2.2bad junk', $logfile, 2, TRUE);

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
