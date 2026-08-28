<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * The Software page's "New version check" checkbox has to POST a token its own save path
 * accepts (issue #2367), and that save path has to be the one the page actually runs
 * (issue #2525).
 *
 * pfSense's Form_Checkbox posts 'yes' unless the caller passes a value:
 * ``__construct($name, $title, $description, $checked, $value = 'yes')``. The save path
 * filters with PFB_FILTER_ON_OFF, which accepts only 'on' and '' — so a checkbox built
 * without that argument posts a token the filter rejects, and every Save, including one
 * with the box ticked, persists the disabled token. The page then renders back unchecked
 * and no UI path can turn the check back on.
 *
 * The posted token is read OUT OF THE PAGE here rather than assumed, so this stays a test
 * of what the page renders: drop the explicit value again and the extraction falls back to
 * pfSense's 'yes' and these cases go red.
 *
 * issue #2525 — the persistence half is EXECUTED, never modelled: every case below drives
 * pfb_software_check_save(), the function the page's Save handler calls, so deleting that
 * function's PfbConfig::write() turns cases red.
 */
#[CoversFunction('pfb_software_check_save')]
#[CoversFunction('pfb_software_check_enabled')]
final class SoftwareCheckPostRoundTripTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_software.php';

	/** The Save handler's opening line, and the two statements it must carry, in order. */
	private const SAVE_OPEN = "if (\$_POST && isset(\$_POST['save'])) {";
	private const PERSIST   = 'pfb_software_check_save($_POST);';
	private const FLUSH     = "write_config('[pfBlockerNG] save Software settings');";

	/**
	 * The value the rendered checkbox posts when ticked: the Form_Checkbox call's 5th
	 * argument, or pfSense's default when the page omits it.
	 *
	 * Read from the comment-stripped, whitespace-collapsed source so a reformat of the call
	 * (one line, re-indented, a comment between arguments) cannot change the answer.
	 */
	private function postedWhenChecked(): string
	{
		$source = php_strip_whitespace(self::PAGE);
		$found  = preg_match(
			"/new Form_Checkbox\\(\\s*'pfb_software_check'\\s*,((?:[^()]|\\([^()]*\\))*)\\)/",
			$source,
			$m
		);
		$this->assertSame(1, $found, 'the Software page must build its check-for-updates checkbox');

		// name is consumed by the pattern, so what remains is title, description, checked
		// and — when the page passes it — the posted value.
		$args = array_map('trim', explode(',', $m[1]));
		if (count($args) < 4 || $args[3] === '') {
			return 'yes'; // pfSense's Form_Checkbox default.
		}

		return trim($args[3], "'\"");
	}

	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;

	protected function setUp(): void
	{
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];

		// issue #1895: this field's write authorization is the package-manager page, not
		// the package's own general page, so a write refuses without it and the round-trip
		// below would read as the defect it is looking for.
		$GLOBALS['pfb_test_allowed_pages'] = ['pkg_mgr_installed.php' => TRUE];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_allowed_pages']);
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	/**
	 * Save with the box ticked persists ENABLED. This is the defect's direct oracle: with a
	 * posted 'yes' the filter rejects the token, the save stores '', and the setting reads
	 * back disabled however many times it is saved.
	 */
	public function testCheckedSavePersistsEnabled(): void
	{
		// Before: an unticked Save has left the setting off, so a green below is this
		// save's doing and not the registry's enabled-by-default. Asserting that BEFORE
		// state is also what makes a save that persists nothing at all fail here: an
		// absent key reads as the registered On default.
		$this->assertSame('', pfb_software_check_save([]), 'an absent checkbox saves the empty Off token');
		$this->assertFalse(pfb_software_check_enabled(), 'precondition: the check starts disabled');

		$posted = $this->postedWhenChecked();
		$this->assertSame(
			$posted,
			pfb_software_check_save(['pfb_software_check' => $posted]),
			'the token the rendered checkbox posts must survive the save unchanged'
		);

		$this->assertTrue(
			pfb_software_check_enabled(),
			'a Save with the box ticked must persist the enabled token; the posted value was '
			. var_export($posted, TRUE)
		);
	}

	/**
	 * The other branch: a browser omits an unticked checkbox entirely, and that absence has
	 * to keep persisting the disabled token — the fix must not make the box unturnoffable.
	 */
	public function testUncheckedSavePersistsDisabled(): void
	{
		PfbConfig::write('gen/pfb_software_check', PfbToggle::On);
		$this->assertTrue(pfb_software_check_enabled(), 'precondition: the check is enabled first');

		// An absent POST key is exactly what a browser sends for an unticked checkbox.
		$this->assertSame('', pfb_software_check_save([]), 'an unticked Save returns the empty Off token');

		$this->assertFalse(pfb_software_check_enabled(), 'an unticked Save must persist the disabled token');
	}

	/**
	 * The trap itself, named: the page must pass its checkbox value explicitly. Sibling
	 * pages that pass 'on' (pfblockerng_sync.php) round-trip; one that relies on the
	 * default posts 'yes' and cannot. The save oracle for that token lives in
	 * testCheckedSavePersistsEnabled() — this case states only what the page must render.
	 */
	public function testCheckboxPostsATokenTheFilterAccepts(): void
	{
		$this->assertNotSame(
			'yes',
			$this->postedWhenChecked(),
			"the checkbox must pass its value explicitly; pfSense's Form_Checkbox default 'yes' "
			. 'is rejected by PFB_FILTER_ON_OFF'
		);
	}

	/**
	 * The save keeps rejecting every token the toggle gateway cannot round-trip, stated as
	 * behaviour rather than as a regex over the source: widening the filter to accept
	 * pfSense's 'yes' would be a different contract, not a refactor. 'yes' is the exact
	 * token the checkbox posted for a release (issue #2367), so this is the input class
	 * that actually reached the save in the field.
	 */
	public function testSaveRejectsATokenTheToggleGatewayCannotRoundTrip(): void
	{
		PfbConfig::write('gen/pfb_software_check', PfbToggle::On);
		$this->assertTrue(pfb_software_check_enabled(), 'precondition: the check is enabled first');

		$this->assertSame('', pfb_software_check_save(['pfb_software_check' => 'yes']));

		$this->assertFalse(
			pfb_software_check_enabled(),
			"'yes' is not an accepted token: it must persist as the disabled token, never enable the check"
		);
	}

	/**
	 * The extraction is only worth anything while the function these cases drive is the one
	 * the page runs (issue #2525). The Save branch must persist through
	 * pfb_software_check_save() and only then flush config.xml, and the page must carry no
	 * second, untested write of this field.
	 *
	 * LIMITATION, stated rather than implied: this proves the wiring TEXT and cannot prove
	 * reachability. A handler behind an inverted condition is caught, because the branch's
	 * opening line is part of the pinned sequence, but a rewrite that keeps the sequence and
	 * makes it unreachable -- the whole branch inside a dead `if (FALSE)`, or in a function
	 * nobody calls, or after an unconditional exit -- survives this test. The executable
	 * proof for this field is the cases above, which drive the extracted function itself.
	 *
	 * There is no executable proof of the page's DECISION to call it, because the page's
	 * top-level handler cannot be run under this harness: including the page after
	 * tests/php/bootstrap.php exits 255 at its line 31, `require_once('guiconfig.inc')`,
	 * before any page logic -- the bootstrap's include path carries tests/php/shims and the
	 * system path, and no guiconfig.inc. That is why #2525 chose extraction, and a runtime
	 * shim for guiconfig.inc and what it pulls in is tracked separately.
	 *
	 * The branch is pinned as ONE literal sequence, with each of its three lines required to
	 * occur exactly once on the page. Never reintroduce anything that resolves the handler's
	 * EXTENT -- a closing-brace scan, a token walk: a wrong extent passes against the wrong
	 * region, which happened twice here.
	 */
	public function testPageSaveDelegatesToTheExtractedSave(): void
	{
		$source = (string) file_get_contents(self::PAGE);

		$this->assertSame(1, substr_count($source, self::SAVE_OPEN), 'the page must open the Save branch exactly once');
		$this->assertSame(1, substr_count($source, self::PERSIST), 'the page must call the extracted save exactly once');
		$this->assertSame(1, substr_count($source, self::FLUSH), 'the page must flush the Software settings exactly once');

		$this->assertStringContainsString(
			self::SAVE_OPEN . "\n\t" . self::PERSIST . "\n\t" . self::FLUSH,
			$source,
			'the Save branch must persist through pfb_software_check_save() and then flush config.xml'
		);

		$this->assertStringNotContainsString(
			"PfbConfig::write('gen/pfb_software_check'",
			$source,
			'the page must not persist this field itself: an inline write is a path no test executes'
		);
	}
}
