<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #2851 — the General tab gains an Advanced Settings section carrying exactly ONE
 * new database download timeout control, wired end to end:
 *   - rendered from the EFFECTIVE stored value (a hostile stored value must not render
 *     as a number the runtime never uses);
 *   - canonicalized on save through the same resolver both language seams read with, so
 *     the stored value IS the effective one;
 *   - persisted through the section write the page already performs (a bare
 *     PfbConfig::write() there would be clobbered by writeSection).
 *
 * Reachable-surface coverage: Tier A render in tests/smoke/ui/test_render_smoke.py,
 * Tier B section/field interaction in tests/smoke/ui/test_browser_general.py, live
 * persistence in tests/smoke/ui/test_functional.py.
 */
final class GeneralAdvancedTimeoutUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read General page');
		}
		return $source;
	}

	public function testTheSaveCanonicalizesThroughTheSharedResolverBeforePersisting(): void
	{
		$source = self::source();

		$canon  = strpos($source, "\$_POST['pfb_reentry_timeout'] = (string) pfb_reentry_timeout(");
		$persist = strpos($source, "\$pfb['gconfig']['pfb_reentry_timeout']\t\t= \$_POST['pfb_reentry_timeout']");
		$section = strpos($source, "PfbConfig::writeSection('installedpackages/pfblockerng/config/0', \$pfb['gconfig'])");

		$this->assertNotFalse($canon,
			'the submitted budget must be canonicalized through pfb_reentry_timeout() -- storing an out-of-range value would render a number the seams never use');
		$this->assertNotFalse($persist, 'the canonical budget must be written into $pfb[\'gconfig\']');
		$this->assertNotFalse($section, 'the General page must keep saving its section through the gateway');
		$this->assertLessThan($persist, $canon, 'canonicalization must happen BEFORE the value is persisted');
		$this->assertLessThan($section, $persist,
			'the field must join $pfb[\'gconfig\'] before writeSection -- a bare PfbConfig::write() would be clobbered');
	}

	public function testTheFieldIsANumberInputInsideTheGeneralAdvancedSection(): void
	{
		$source = self::source();

		$advanced = strpos($source, "new Form_Section('Advanced Settings', 'general_advanced', COLLAPSIBLE|SEC_CLOSED)");
		$this->assertNotFalse($advanced,
			'the General tab must carry a collapsible Advanced Settings section (the house shape, cf. ip_advanced)');

		$field = strpos($source, "'pfb_reentry_timeout',");
		$this->assertNotFalse($field, 'the database download timeout input must exist');
		$this->assertMatchesRegularExpression(
			"/new Form_Input\(\s*'pfb_reentry_timeout',\s*'[^']+',\s*'number',/",
			$source,
			'the database download timeout must remain a number input');
		$this->assertGreaterThan($advanced, $field, 'the field must live inside the Advanced Settings section');

		$support = strpos($source, "new Form_Section('Support')");
		$this->assertNotFalse($support);
		$this->assertLessThan($support, $advanced, 'Advanced Settings must sit before the trailing Support section');
	}

	public function testTheInputBoundsComeFromTheRuntimeWindowNotFromRestatedLiterals(): void
	{
		$source = self::source();

		$this->assertStringContainsString("'min' => (string) PFB_REENTRY_TIMEOUT_MIN", $source,
			'the browser-side minimum must be the runtime minimum, not a literal that can drift');
		$this->assertStringContainsString("'max' => (string) PFB_REENTRY_TIMEOUT_MAX", $source,
			'the browser-side maximum must be the runtime maximum, not a literal that can drift');
		$this->assertStringContainsString("'placeholder' => (string) PFB_REENTRY_TIMEOUT", $source,
			'the empty-field placeholder must be the runtime default');
	}
}
