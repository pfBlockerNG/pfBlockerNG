<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class GeneralSyntaxHighlightToggleWiringTest extends TestCase
{
	private const GENERAL_PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_general.php';

	public function testSavePersistsExplicitOnAndOffTokens(): void
	{
		$this->assertSame('on', pfb_general_toggle_stored_value('on'));
		$this->assertSame('off', pfb_general_toggle_stored_value(''));
		$this->assertSame('off', pfb_general_toggle_stored_value(NULL));
		$this->assertSame('off', pfb_general_toggle_stored_value(['on']));
	}

	/**
	 * #993: the page-save request reaches pfSense globals and sync orchestration, so it is
	 * not executable off-appliance; pin only its helper binding. php_strip_whitespace() makes
	 * comments and docblocks irrelevant to this assertion. Render behavior stays in smoke UI.
	 */
	public function testGeneralPageSaveBindsTheToggleHelper(): void
	{
		$source = php_strip_whitespace(self::GENERAL_PAGE);
		$start  = "if (isset(\$_POST['save'])) {";
		$end    = 'PfbConfig::writeSection(';
		$from   = strpos($source, $start);
		$to     = $from === FALSE ? FALSE : strpos($source, $end, $from + strlen($start));

		$this->assertNotFalse($from, 'general page save branch must remain present');
		$this->assertNotFalse($to, 'general page save must persist through the config gateway');
		$window = substr($source, $from, $to - $from);
		$needle = "\$pfb['gconfig']['pfb_syntax_highlight'] = pfb_general_toggle_stored_value(";
		$this->assertSame(1, substr_count($window, $needle), 'save branch must bind the toggle helper exactly once');
	}
}
