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
 * pattern tests = invalid/valid proof); composed with this test's proof of the guard's
 * shape, that covers: interpreter usable -> validator runs whatever the toggle says
 * (invalid pattern blocks, valid one does not), so an entry that would vanish at load
 * is still reported while the feature is off; interpreter unusable + toggle on ->
 * blocked, fail-closed preserved; interpreter unusable + toggle off -> skipped, which
 * is the availability leg this fix exists for.
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

	public function testRegexValidationRunsWheneverTheInterpreterIsUsable(): void
	{
		// A usable interpreter is sufficient on its own: an entry the resolver would drop
		// is reported at save even while the feature is still off, which is the feedback
		// contract issue #1656 exists for.
		$this->assertMatchesRegularExpression(
			"#if\\s*\\(\\s*\\(\\s*\\\$pfb_regex_python\\s*!==\\s*''\\s*&&\\s*"
			. "is_executable\\(\\\$pfb_regex_python\\)\\s*\\)\\s*\\|\\|#",
			self::$src,
			'expected the validation guard to run whenever the resolved interpreter is executable'
		);
	}

	public function testUnusableInterpreterOnlyBlocksTheSaveWhileTheFeatureIsOn(): void
	{
		// The second disjunct is the fail-closed leg: with no usable interpreter the
		// validator can only report "interpreter unavailable", so it must apply solely
		// when pfb_regex is submitted as the literal 'on' -- otherwise an unresolvable
		// interpreter would make the whole DNSBL page unsavable, unrelated fields
		// included. Anything that is not literally 'on' (absent key, '', 'off', '0', an
		// array from pfb_regex[]=on, whitespace-padded junk) falls to the else side:
		// === against a non-scalar is false in PHP, never a warning or TypeError.
		$this->assertMatchesRegularExpression(
			"#\\|\\|\\s*\\(\\s*\\(\\s*\\\$_POST\\['pfb_regex'\\]\\s*\\?\\?\\s*''\\s*\\)\\s*===\\s*'on'\\s*\\)\\s*\\)\\s*\\{\\s*"
			. "foreach\\s*\\(pfb_dnsbl_regex_validation_errors\\(\\(string\\)\\s*\\(\\s*\\\$_POST\\['pfb_regex_list'\\]\\s*\\?\\?\\s*''\\s*\\),\\s*"
			. "\\\$pfb_regex_python,\\s*\\(\\s*\\\$_POST\\['pfb_regex_cap'\\]\\s*\\?\\?\\s*''\\s*\\)\\s*===\\s*'on'\\)\\s*as\\s*\\\$regex_error\\)\\s*\\{\\s*"
			. "\\\$input_errors\\[\\]\\s*=\\s*'Customlist pfb_regex_list:\\s*'\\s*\\.\\s*"
			. "htmlspecialchars\\(\\\$regex_error,\\s*ENT_QUOTES\\s*\\|\\s*ENT_SUBSTITUTE,\\s*'UTF-8'\\);\\s*\\}\\s*\\}#",
			self::$src,
			"expected the toggle disjunct to gate only the fail-closed leg, with the "
			. 'validation call (including the pfb_regex_cap third argument, issue #1688) and its error-append inside that guard'
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
