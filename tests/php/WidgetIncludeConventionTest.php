<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1777: pfSense's dashboard widget-include convention reads a small
 * set of `$pfblockerng_*`-prefixed variables from widget-pfblockerng.inc
 * (`$widgetname`/`$pfblockerng_title`/`$pfblockerng_title_link` are the
 * already-baselined siblings -- see tests/smoke/ui/php_diagnostic_baseline.txt).
 * `$pfblockerng_allow_multiple_widget_copies` was never set, so pfSense's own
 * dashboard.php reads it undefined on every render. The widget is a
 * singleton by construction (a fixed POST action URL, settings keyed off one
 * `installedpackages/pfblockerngglobal` config block) -- FALSE is correct,
 * not a placeholder.
 *
 * Only the variable-assignment prologue (before the `pfb_widget_post_allowed()`
 * function definition, already covered by WidgetPostAllowedTest/
 * WidgetSubmitPostGuardTest's own require_once of this same file) is
 * eval-extracted -- a bare `include` would risk a "Cannot redeclare function"
 * fatal if PHPUnit runs this in the same process after those sibling tests
 * have already required the file.
 */
final class WidgetIncludeConventionTest extends TestCase
{
	private const WIDGET_INC = __DIR__ . '/../../src/usr/local/www/widgets/include/widget-pfblockerng.inc';

	public function testAllowMultipleWidgetCopiesConventionVariableIsDefinedFalse(): void
	{
		$src = file_get_contents(self::WIDGET_INC);
		$this->assertNotFalse($src, 'failed to read widget-pfblockerng.inc');

		if (!preg_match('/<\?php\n(.*?)\nfunction pfb_widget_post_allowed/s', $src, $m)) {
			$this->fail('could not locate the variable-assignment prologue before pfb_widget_post_allowed()');
		}
		eval($m[1]);

		$this->assertTrue(isset($pfblockerng_allow_multiple_widget_copies), '$pfblockerng_allow_multiple_widget_copies must be defined');
		$this->assertFalse($pfblockerng_allow_multiple_widget_copies, 'the widget is a singleton (fixed POST action URL, one config block) -- must be FALSE');

		// Control: the pre-existing sibling convention variables must still be
		// defined too (this fix must not disturb them).
		$this->assertTrue(isset($pfblockerng_title), '$pfblockerng_title must still be defined');
		$this->assertTrue(isset($pfblockerng_title_link), '$pfblockerng_title_link must still be defined');
	}
}
