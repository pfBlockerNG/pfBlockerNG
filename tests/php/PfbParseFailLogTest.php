<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1408 oracle -- pins CSV parse-fail output that pfb_parsed_fail()/
 * pfb_ip_parsed_fail() write TODAY but no existing test covers, ahead of
 * collapsing both into pfb_parse_fail_log(). Every assertion here is a
 * characterization of CURRENT behaviour (not a spec for new behaviour);
 * the collapse must reproduce every byte unchanged.
 *
 * Axes: falsy-line coercion divergence ('0' vs '') x mode (lenient/strict),
 * $oline CRLF-stripped vs mid-string LF kept, comma-containing $line kept
 * raw, UTF-8 $line kept raw, default $lineno=''.
 */
#[CoversFunction('pfb_parsed_fail')]
#[CoversFunction('pfb_ip_parsed_fail')]
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
	 * The one genuinely divergent branch (issue #1408 packet): lenient mode's
	 * `$line ?: 'null'` treats the literal string '0' as falsy -- unlike strict
	 * mode's `$line !== ''`, which keeps '0' as-is. Currently unpinned.
	 */
	public function testLenientModeCoercesLiteralZeroLineToNull(): void
	{
		$logfile = $this->mktemp('pfb_parsefail_lenient0_');

		pfb_parsed_fail('TestFeed', '0', 'orig 0 line', $logfile, 9);

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

		pfb_ip_parsed_fail('TestFeed', '0', 'orig 0 line', $logfile, 9);

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

		pfb_parsed_fail('TestFeed', '', 'orig empty line', $logfile, 2);

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

		pfb_parsed_fail('TestFeed', 'a,b,c-not-a-domain', 'orig, csv, line', $logfile, 1);

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

		pfb_parsed_fail('TestFeed', 'line', "orig line\r\n", $logfile, 4);

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

		pfb_parsed_fail('TestFeed', 'line', "before\nafter", $logfile, 6);

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

		pfb_parsed_fail('TestFeed', 'xn--might-be-münchen.example', 'orig utf8 line', $logfile, 3);

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

		pfb_parsed_fail('TestFeed', 'line', 'orig line', $logfile);

		$logged = $this->readFile($logfile);
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},TestFeed,line,orig line,\n$/',
			$logged,
			"omitting \$lineno must default to an empty trailing column, not drop it; got: {$logged}"
		);
	}
}
