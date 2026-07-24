<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * PR #1667 CodeRabbit finding (Major, availability): the DNSBL save handler ran
 * pfb_dnsbl_regex_validation_errors() on every save whenever pfb_regex_list was
 * non-empty, even when the `pfb_regex` feature toggle was OFF -- in which case
 * pfb_unbound.py never loads those patterns at all. Because the helper fails CLOSED
 * on an unresolvable pfb_python_interpreter(), an install where that interpreter
 * cannot resolve could not save the DNSBL settings page AT ALL (every unrelated
 * field on it) with no remedy short of emptying the Regex List -- a regression this
 * PR introduced (pre-PR, DNSBL saves never depended on Python).
 *
 * pfblockerng_dnsbl.php carries top-level render execution (require_once('guiconfig.inc')
 * et al.) and cannot be require()d/executed off-appliance -- same constraint documented
 * on DnsblRegexHighlightWiringTest/GeneralSyntaxHighlightToggleWiringTest. This pins the
 * fix the same way those do: literal source-shape assertions on the save block, rather
 * than executing the save path. Behavioural coverage for the two axes this wiring test
 * cannot exercise directly (list contents x interpreter availability) already lives in
 * DnsblRegexEntryErrorTest against pfb_dnsbl_regex_validation_errors() itself
 * (testMissingPythonAndTimeoutFailClosed = fail-closed proof, the malformed/benign
 * pattern tests = invalid/valid proof); composed with this test's proof that the call
 * site is now wrapped in the toggle gate, that covers: toggle off -> validator never
 * runs (no Customlist pfb_regex_list error, regardless of pattern/interpreter); toggle
 * on -> validator runs exactly as it always has (invalid pattern blocks, valid pattern
 * doesn't, unresolvable interpreter still blocks -- fail-closed preserved).
 */
final class DnsblRegexToggleGateWiringTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_dnsbl.php');
		}
		self::$src = $src;
	}

	public function testRegexValidationCallIsGatedByTheSubmittedPfbRegexToggle(): void
	{
		// The whole foreach/error-append block must sit inside
		// if ((($_POST['pfb_regex'] ?? '') === 'on') { ... } -- the same raw-$_POST
		// on/off idiom this codebase already uses for toggle gates that read the
		// submitted form value directly (see pfb_syntax_highlight's save ternary in
		// GeneralSyntaxHighlightToggleWiringTest). Anything that isn't a literal 'on'
		// (absent key, '', 'off', '0', an array, whitespace-padded junk) must fall to
		// the else side of this comparison without a warning/TypeError -- === against a
		// non-scalar (e.g. an array from pfb_regex[]=on) is always false, never a crash.
		$this->assertMatchesRegularExpression(
			"#if\\s*\\(\\s*\\(\\s*\\\$_POST\\['pfb_regex'\\]\\s*\\?\\?\\s*''\\s*\\)\\s*===\\s*'on'\\s*\\)\\s*\\{\\s*"
			. "foreach\\s*\\(pfb_dnsbl_regex_validation_errors\\(\\(string\\)\\s*\\(\\s*\\\$_POST\\['pfb_regex_list'\\]\\s*\\?\\?\\s*''\\s*\\),\\s*"
			. "pfb_python_interpreter\\(\\)\\)\\s*as\\s*\\\$regex_error\\)\\s*\\{\\s*"
			. "\\\$input_errors\\[\\]\\s*=\\s*'Customlist pfb_regex_list:\\s*'\\s*\\.\\s*"
			. "htmlspecialchars\\(\\\$regex_error,\\s*ENT_QUOTES\\s*\\|\\s*ENT_SUBSTITUTE,\\s*'UTF-8'\\);\\s*\\}\\s*\\}#",
			self::$src,
			'expected the pfb_dnsbl_regex_validation_errors() call and its error-append to be '
			. "wrapped in if ((\$_POST['pfb_regex'] ?? '') === 'on') { ... }"
		);
	}

	public function testRegexValidationCallSiteAppearsExactlyOnce(): void
	{
		// Vacuity-safe proof: the previous test only shows a gated occurrence EXISTS --
		// it would still pass if a second, unguarded call existed elsewhere in the file.
		// Counting closes that gap.
		$this->assertSame(
			1,
			substr_count(self::$src, 'pfb_dnsbl_regex_validation_errors('),
			'expected exactly one pfb_dnsbl_regex_validation_errors( call in the whole file -- '
			. 'a second, unguarded call would defeat the toggle-gate contract'
		);
	}
}
