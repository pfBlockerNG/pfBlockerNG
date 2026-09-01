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
 */
final class DnsblRegexHelpCheckerTest extends TestCase
{
	private static function helpText(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read pfblockerng_extra.inc');
		}
		self::assertSame(
			1,
			preg_match('/function pfb_dnsbl_regex_help_text\(\): string\s*\{\s*return (.*?);\s*\}/s', $source, $m),
			'pfb_dnsbl_regex_help_text() must exist and return a single expression'
		);
		return $m[1];
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
		$help = self::helpText();
		self::assertMatchesRegularExpression(
			'/editing aid|may flag a valid pattern/i',
			$help,
			'the help must tell the user an inline marker is not proof the pattern is wrong'
		);
	}

	public function testHelpLinksThePythonReSyntaxReference(): void
	{
		$help = self::helpText();
		self::assertStringContainsString(
			'docs.python.org/3/library/re.html',
			$help,
			'the help must link the Python re syntax reference'
		);
	}

	/**
	 * Every external link on this page carries the house attributes;
	 * scripts/check_noopener.py enforces the rel, and this pins the pairing
	 * at the one site this issue adds.
	 */
	public function testExternalLinksCarryTargetAndRel(): void
	{
		$help = self::helpText();
		self::assertSame(
			preg_match_all('/<a\s[^>]*href="https:/', $help),
			preg_match_all('/<a\s[^>]*rel="noopener noreferrer"[^>]*>/', $help),
			'every https link in this help must carry rel="noopener noreferrer"'
		);
		self::assertSame(
			preg_match_all('/<a\s[^>]*href="https:/', $help),
			preg_match_all('/<a\s[^>]*target="_blank"[^>]*>/', $help),
			'every https link in this help must open in a new tab'
		);
	}
}
