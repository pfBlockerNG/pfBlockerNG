<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1868 -- the documented 15-character description limit is advisory, and
 * the editor is where it gets said.
 *
 * The Regex List help text tells the admin to keep each description under 15
 * characters because the Alerts tab shows it, but nothing checked it: a longer
 * description saved without a word, and the admin only found out later when
 * reading Alerts.
 *
 * The chosen shape is ADVISORY, not a save blocker: an existing config carrying
 * a long description must keep saving, including on saves that have nothing to
 * do with the regex list. So the check lives on the lint endpoint's path
 * (severity 'warning') and NOT in pfb_dnsbl_regex_validation_errors(), which is
 * what the save handler consults. Both halves of that split are pinned here --
 * a warning that also blocked the save would be the wrong fix passing a
 * one-sided test.
 */
#[CoversFunction('pfb_lint_diagnostics')]
#[CoversFunction('pfb_dnsbl_regex_description_warnings')]
final class DnsblRegexDescriptionLintTest extends TestCase
{
	private const OVER_LIMIT = 'this description is far too long';
	private const AT_LIMIT = '123456789012345';

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

	/** @return array<int, array{line: int, message: string, severity: string}> */
	private static function lint(string $contents): array
	{
		return pfb_lint_diagnostics('regex', $contents, FALSE, self::$python, null, self::$timeout);
	}

	/** @return array<int, string> */
	private static function saveErrors(string $contents): array
	{
		return pfb_dnsbl_regex_validation_errors($contents, self::$python, FALSE, self::$timeout);
	}

	public function testAnOverLongDescriptionIsFlaggedByTheLint(): void
	{
		$diagnostics = self::lint("^ads\\.example\\.com$ # " . self::OVER_LIMIT . "\n");
		$warnings = array_values(array_filter(
			$diagnostics,
			static fn (array $d): bool => $d['severity'] === 'warning'
		));
		$this->assertCount(1, $warnings, 'expected exactly one advisory warning, got: ' . var_export($diagnostics, TRUE));
		$this->assertSame(1, $warnings[0]['line'], 'the warning must carry the source line it belongs to');
		$this->assertMatchesRegularExpression('/15/', $warnings[0]['message'], 'the message must name the limit');
	}

	public function testAnOverLongDescriptionStillSaves(): void
	{
		// The advisory half of the contract: a warning must never become a save
		// blocker, or every existing config with a long description breaks.
		$this->assertSame(
			[],
			self::saveErrors("^ads\\.example\\.com$ # " . self::OVER_LIMIT . "\n"),
			'the description-length check must not reach the save-time validator'
		);
	}

	public function testADescriptionExactlyAtTheLimitIsNotFlagged(): void
	{
		// The boundary, asserted from the allowed side so the rule is "> 15", not ">= 15".
		$this->assertSame(
			[],
			self::lint("^ads\\.example\\.com$ # " . self::AT_LIMIT . "\n"),
			'a 15-character description is within the documented limit'
		);
	}

	public function testALineWithNoDescriptionIsNotFlagged(): void
	{
		$this->assertSame(
			[],
			self::lint("^ads\\.example\\.com$\n"),
			'a row with no description has nothing to measure'
		);
	}

	public function testTheWarningNamesTheRightLineInAMultiLineList(): void
	{
		// Line mapping is the whole point of a gutter diagnostic; a warning
		// pinned to the wrong row is worse than none.
		$contents = "^one\\.example\\.com$ # short\n"
			. "# a whole-line comment\n"
			. "^two\\.example\\.com$ # " . self::OVER_LIMIT . "\n";
		$warnings = array_values(array_filter(
			self::lint($contents),
			static fn (array $d): bool => $d['severity'] === 'warning'
		));
		$this->assertCount(1, $warnings);
		$this->assertSame(3, $warnings[0]['line'], 'the warning must point at the third source line');
	}

	public function testAnEscapedHashInThePatternIsNotCountedAsADescription(): void
	{
		// Composes with #1867: the length rule measures the REAL description, so
		// an escaped hash inside the pattern must not fabricate one.
		$this->assertSame(
			[],
			self::lint("^ads\\#" . self::OVER_LIMIT . "$\n"),
			'an escaped hash keeps the rest of the line in the pattern, so there is no description to measure'
		);
	}
}
