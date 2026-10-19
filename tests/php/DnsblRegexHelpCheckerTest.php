<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3059: the Regex List help must say which checker the editor runs, that it
 * is advisory, and that Python validates on save and is authoritative.
 *
 * The editor's inline checker is a second implementation of Python's regex parser
 * and marks valid patterns (issue #3063). Nothing in the UI told a user the marker
 * could be wrong, so the natural response was to edit a working rule until it
 * cleared -- silently weakening their blocking.
 *
 * The rendered string is taken from the function, not scraped out of the file: a
 * scrape pins the shape of the source (how the value is returned) rather than the
 * prose, and fails on a refactor that changes nothing a user sees.
 */
final class DnsblRegexHelpCheckerTest extends TestCase
{
	private static function helpText(): string
	{
		return pfb_dnsbl_regex_help_text();
	}

	public function testHelpNamesPythonAsTheAuthoritativeValidator(): void
	{
		$help = self::helpText();
		self::assertMatchesRegularExpression(
			'/validated on save by (the same )?Python/i',
			$help,
			'the help must state that Python validates on save'
		);
		self::assertMatchesRegularExpression(
			'/authoritative/i',
			$help,
			'the help must say which validator wins'
		);
	}

	public function testHelpWarnsTheInlineCheckerCanFlagAValidPattern(): void
	{
		self::assertMatchesRegularExpression(
			'/editing aid/i',
			self::helpText(),
			'the help must tell the user an inline marker is not proof the pattern is wrong'
		);
	}

	public function testHelpLinksThePythonReSyntaxReference(): void
	{
		self::assertStringContainsString(
			'docs.python.org/3/library/re.html',
			self::helpText(),
			'the help must link the Python re syntax reference'
		);
	}

	public function testHelpSaysThePatternCharacterSetExcludesSpaces(): void
	{
		self::assertStringContainsString(
			'printable ASCII without spaces',
			self::helpText(),
			'the help must say that a space is not a pattern character'
		);
	}

	public function testHelpNamesTheAnchorThatAdmitsAnOpenRunBeforeALiteralTail(): void
	{
		$help = self::helpText();
		self::assertStringContainsString('\S+\.example\.com', $help, 'the help must show an open run before a literal tail');
		self::assertStringContainsString('ad.*\.example\.com', $help, 'the help must show a second open run before a literal tail');
		self::assertStringContainsString(
			'are refused unless anchored with <code>^</code>',
			$help,
			'the help must name the remedy the save-time error also gives'
		);
	}

	/**
	 * scripts/check_noopener.py scans `src/usr/local/www` only, and this help lives
	 * under `src/usr/local/pkg`, so the repo-wide gate never sees these links. This
	 * assertion is what pins them.
	 */
	public function testExternalLinksCarryTargetAndRel(): void
	{
		$help = self::helpText();
		$links = preg_match_all('/<a\s[^>]*href="https:/', $help);
		self::assertGreaterThan(0, $links, 'expected at least one external link to pin');
		self::assertSame(
			$links,
			preg_match_all('/<a\s[^>]*rel="noopener noreferrer"[^>]*>/', $help),
			'every https link in this help must carry rel="noopener noreferrer"'
		);
		self::assertSame(
			$links,
			preg_match_all('/<a\s[^>]*target="_blank"[^>]*>/', $help),
			'every https link in this help must open in a new tab'
		);
	}
}
