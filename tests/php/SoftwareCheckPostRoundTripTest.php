<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * The Software page's "New version check" checkbox has to POST a token its own save path
 * accepts (issue #2367).
 *
 * pfSense's Form_Checkbox posts 'yes' unless the caller passes a value:
 * ``__construct($name, $title, $description, $checked, $value = 'yes')``. The save path
 * filters with PFB_FILTER_ON_OFF, which accepts only 'on' and '' — so a checkbox built
 * without that argument posts a token the filter rejects, and every Save, including one
 * with the box ticked, persists the disabled token. The page then renders back unchecked
 * and no UI path can turn the check back on.
 *
 * The posted token is read OUT OF THE PAGE here rather than assumed, so this stays a test
 * of what the page does: drop the explicit value again and the extraction falls back to
 * pfSense's 'yes' and these cases go red.
 */
#[CoversFunction('pfb_software_check_enabled')]
final class SoftwareCheckPostRoundTripTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_software.php';

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

	/**
	 * The page's save filter, applied through the SAME constant the page names, so swapping
	 * the page to another filter cannot leave this modelling the old one.
	 */
	private function saveFilter(string $posted): string
	{
		$source = php_strip_whitespace(self::PAGE);
		$found  = preg_match(
			"/pfb_filter\\(\\\$_POST\\['pfb_software_check'\\] \\?\\? '', (PFB_FILTER_[A-Z_]+), 'software'\\) \\?: ''/",
			$source,
			$m
		);
		$this->assertSame(1, $found, 'the modelled save expression no longer matches the page');
		// Applied through the page's own constant so this cannot model a filter the page
		// stopped using, AND pinned to the one that makes the round-trip meaningful: a save
		// widened to accept a looser token set is a different contract, not a refactor.
		$this->assertSame(
			'PFB_FILTER_ON_OFF',
			$m[1],
			'the Save must keep filtering with PFB_FILTER_ON_OFF; a looser filter would accept tokens '
			. 'that no longer round-trip through the toggle gateway'
		);

		return pfb_filter($posted, constant($m[1]), 'software') ?: '';
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
	 * posted 'yes' the filter rejects the token, the page stores '', and the setting reads
	 * back disabled however many times it is saved.
	 */
	public function testCheckedSavePersistsEnabled(): void
	{
		// Before: an unticked Save has left the setting off, so a green below is this
		// save's doing and not the registry's enabled-by-default.
		PfbConfig::write('gen/pfb_software_check', $this->saveFilter(''));
		$this->assertFalse(pfb_software_check_enabled(), 'precondition: the check starts disabled');

		PfbConfig::write('gen/pfb_software_check', $this->saveFilter($this->postedWhenChecked()));

		$this->assertTrue(
			pfb_software_check_enabled(),
			'a Save with the box ticked must persist the enabled token; the posted value was '
			. var_export($this->postedWhenChecked(), TRUE)
		);
	}

	/**
	 * The other branch: a browser omits an unticked checkbox entirely, and that absence has
	 * to keep persisting the disabled token — the fix must not make the box unturnoffable.
	 */
	public function testUncheckedSavePersistsDisabled(): void
	{
		PfbConfig::write('gen/pfb_software_check', $this->saveFilter($this->postedWhenChecked()));
		$this->assertTrue(pfb_software_check_enabled(), 'precondition: the check is enabled first');

		// An absent POST key reaches the save path as ''.
		PfbConfig::write('gen/pfb_software_check', $this->saveFilter(''));

		$this->assertFalse(pfb_software_check_enabled(), 'an unticked Save must persist the disabled token');
	}

	/**
	 * The trap itself, named: the page must pass its checkbox value explicitly. Sibling
	 * pages that pass 'on' (pfblockerng_sync.php) round-trip; one that relies on the
	 * default posts 'yes' and cannot.
	 */
	public function testCheckboxPostsATokenTheFilterAccepts(): void
	{
		$posted = $this->postedWhenChecked();

		$this->assertNotSame(
			'yes',
			$posted,
			"the checkbox must pass its value explicitly; pfSense's Form_Checkbox default 'yes' "
			. 'is rejected by PFB_FILTER_ON_OFF'
		);
		$this->assertSame(
			$posted,
			$this->saveFilter($posted),
			'the posted token must survive the page\'s own save path unchanged'
		);
	}
}
