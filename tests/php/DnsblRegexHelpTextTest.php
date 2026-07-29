<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1866 -- the DNSBL "Regex List" field's help text.
 *
 * Two defects, both in the same string:
 *
 *  1. It hard-wraps mid-sentence. The literal carries a `<br />` after the word
 *     "in", so the rendered paragraph breaks between "in" and "the" at every
 *     window width. A `<br />` in prose is a paragraph break, so each one has to
 *     land where a sentence actually ends.
 *  2. It told the admin to "Ensure a space is entered before the # character",
 *     which is not what the package does: the description starts at the first
 *     UNESCAPED '#' on the line, space or no space (see #1867 for the escape).
 *
 * pfblockerng_dnsbl.php carries top-level render execution and cannot be
 * require()d off-appliance, so the help literal is read from the real source --
 * the same technique DnsblRegexHighlightWiringTest uses for this page, and the
 * Tier-A coverage for this www/ change.
 */
final class DnsblRegexHelpTextTest extends TestCase
{
	private static string $helpText;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_dnsbl.php');
		}
		if (preg_match("/\\\$regex_text\\s*=\\s*'(.*?)';/s", $src, $match) !== 1) {
			throw new RuntimeException('could not locate the $regex_text help literal');
		}
		self::$helpText = $match[1];
	}

	public function testEveryLineBreakLandsAtTheEndOfASentence(): void
	{
		// Split on each <br />, then check what the preceding fragment ENDS with.
		// A fragment that ends mid-word (the "...used in" case) is the defect.
		$fragments = preg_split('#<br\s*/?>#', self::$helpText);
		$this->assertIsArray($fragments);
		// The final fragment has no <br /> after it, so it is not a break site.
		array_pop($fragments);

		$midSentence = [];
		foreach ($fragments as $fragment) {
			$trimmed = rtrim($fragment);
			if ($trimmed === '') {
				continue; // a doubled <br /><br /> paragraph gap is fine
			}
			if (preg_match('/[.:!?]$/', $trimmed) !== 1) {
				$midSentence[] = $trimmed;
			}
		}

		$this->assertSame(
			[],
			$midSentence,
			"every <br /> must follow the end of a sentence; these break mid-sentence:\n"
				. implode("\n", array_map(static fn (string $f): string => '  ...' . substr($f, -60), $midSentence))
		);
	}

	public function testDoesNotClaimASpaceIsRequiredBeforeTheHash(): void
	{
		$this->assertDoesNotMatchRegularExpression(
			'/space\s+is\s+entered\s+before/i',
			self::$helpText,
			'the help text still tells the admin a space is required before "#", which the decoder does not require'
		);
	}

	public function testDocumentsThatTheFirstUnescapedHashStartsTheDescription(): void
	{
		$this->assertMatchesRegularExpression(
			'/first\b.*\bunescaped\b/is',
			self::$helpText,
			'the help text must state that the FIRST UNESCAPED "#" starts the description'
		);
	}

	public function testDocumentsTheBackslashEscapeForALiteralHash(): void
	{
		// #1867's escape is only usable if it is written down where the admin
		// looks; an undocumented escape is the same defect in a new place.
		$this->assertStringContainsString(
			'\\#',
			self::$helpText,
			'the help text must show the \\# escape for a literal hash inside a pattern'
		);
	}
}
