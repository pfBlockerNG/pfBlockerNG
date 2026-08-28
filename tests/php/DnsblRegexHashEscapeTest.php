<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1867 -- a backslash-escaped '#' belongs to the regex, not the description.
 *
 * The save-time validator splits each line into pattern and description before
 * compiling the pattern half. Splitting at the FIRST '#' anywhere meant a
 * pattern containing a literal hash was cut in two: "^ads\#tag\.example\.com$"
 * reached Python as "^ads\", which is not a compilable regex, so the admin got a
 * confusing "bad escape" diagnostic for a pattern that reads perfectly well --
 * and a pattern whose truncated half DID compile saved silently and then matched
 * something other than what was typed.
 *
 * The rule: the description starts at the first '#' preceded by an EVEN number of
 * backslashes. No unescaping step is needed -- Python's re reads "\#" as a
 * literal '#' already -- so the pattern half reaches re.compile verbatim.
 *
 * Twin of tests/test_issue1867_regex_hash_escape.py, which pins the same rule on
 * the resolver's own load path.
 */
#[CoversFunction('pfb_dnsbl_regex_validation_errors')]
#[CoversFunction('pfb_split_regex_line')]
final class DnsblRegexHashEscapeTest extends TestCase
{
	private static string $python;
	private static string $timeout;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		self::$python = self::commandPath('python3');
		self::$timeout = self::commandPath('timeout');
	}

	private static function commandPath(string $command): string
	{
		$output = [];
		$status = 1;
		exec('command -v ' . escapeshellarg($command) . ' 2>/dev/null', $output, $status);
		if ($status !== 0 || $output === [] || trim($output[0]) === '') {
			throw new RuntimeException("required test command not found: {$command}");
		}
		return trim($output[0]);
	}

	/** @return array<int, string> */
	private static function errors(string $contents): array
	{
		return pfb_dnsbl_regex_validation_errors($contents, self::$python, FALSE, self::$timeout);
	}

	public function testAnEscapedHashPatternValidatesCleanly(): void
	{
		// RED before the fix: the validator saw "^ads\" and reported
		// "bad escape (end of pattern)" for a pattern the admin wrote correctly.
		$this->assertSame(
			[],
			self::errors("^ads\\#tag\\.example\\.com$\n"),
			'a pattern whose only hash is escaped must validate, not be truncated at the hash'
		);
	}

	public function testAnEscapedHashPatternKeepsItsTrailingDescription(): void
	{
		// The escape must not swallow the REAL marker further along the line.
		$this->assertSame(
			[],
			self::errors("^ads\\#tag\\.example\\.com$ # hashtag\n"),
			'an escaped hash in the pattern and a later bare hash starting the description must both be honoured'
		);
	}

	public function testAnUnescapedHashStillEndsThePattern(): void
	{
		// Regression guard: everything after a bare '#' is a description and is
		// never compiled, so a syntactically broken tail cannot fail the save.
		$this->assertSame(
			[],
			self::errors("^ads\\.example\\.com$#a ( b [ c\n"),
			'text after an unescaped hash is a description and must not be compiled as regex'
		);
	}

	public function testAnEvenBackslashRunLeavesTheHashAsTheMarker(): void
	{
		// "\\" is an escaped backslash, so the '#' after it is NOT escaped: the
		// pattern is "^ads\\" (a literal backslash), which compiles.
		$this->assertSame(
			[],
			self::errors("^ads\\\\#evenrun\n"),
			'an escaped backslash must not protect the hash that follows it'
		);
	}

	public function testATruncatedPatternIsStillReportedWhenItIsGenuinelyBroken(): void
	{
		// Vacuity guard: the validator must still reject a real compile error, so
		// the assertions above cannot pass merely because validation stopped
		// running. A lone trailing backslash is a bad escape in any split.
		$errors = self::errors("^ads\\\n");
		$this->assertNotSame([], $errors, 'a genuinely uncompilable pattern must still be reported');
		$this->assertStringContainsString('line 1', $errors[0]);
	}
}
