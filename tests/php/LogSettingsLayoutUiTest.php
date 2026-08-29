<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * General tab Log Settings: one column-title row, full-width category dividers,
 * scoped desktop hide of label-start, Trim Margin help not duplicated in the intro.
 */
final class LogSettingsLayoutUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read General page');
		}
		return $source;
	}

	private static function logTypesLoop(string $source): string
	{
		self::assertSame(
			1,
			preg_match(
				'/foreach \(\$log_types as \$logdescr => \$logtype\) \{(.*)\n\}\n\n\/\/ issue #1109/s',
				$source,
				$m
			),
			'Log Settings per-category loop must exist'
		);
		return $m[1];
	}

	public function testColumnTitlesAreEmittedOnceBeforeTheCategoryLoop(): void
	{
		$source = self::source();
		$this->assertStringContainsString("addClass('pfb-logcolhdr')", $source);
		$colPos = strpos($source, "addClass('pfb-logcolhdr')");
		$loopPos = strpos($source, 'foreach ($log_types as $logdescr => $logtype)');
		$this->assertNotFalse($colPos);
		$this->assertNotFalse($loopPos);
		$this->assertLessThan($loopPos, $colPos, 'the Max lines/Max days header row must sit above the category loop');

		$loop = self::logTypesLoop($source);
		$this->assertStringNotContainsString(
			'form-control-static hidden-xs"><strong>Max lines</strong>',
			$loop
		);
		$this->assertStringNotContainsString(
			'form-control-static hidden-xs"><strong>Max days</strong>',
			$loop
		);
		$this->assertStringContainsString(
			'form-control-static hidden-xs"><strong>Max lines</strong>',
			$source
		);
		$this->assertStringContainsString(
			'form-control-static hidden-xs"><strong>Max days</strong>',
			$source
		);
	}

	public function testDesktopFormLabelHideIsScopedToLogRows(): void
	{
		$source = self::source();
		$this->assertStringNotContainsString(
			'@media (min-width: 768px) { label.form-label { display: none; } }',
			$source
		);
		$this->assertStringContainsString('.pfb-logrow label.form-label', $source);
		$this->assertStringContainsString("addClass('pfb-logrow')", $source);
		$this->assertStringNotContainsString(
			'setWidth(12)',
			$source,
			'pfSense Form_Input rejects width 12; the category divider must not pass it'
		);
		// Full-width centred divider must not depend on a col-sm-* class from setWidth.
		$this->assertStringContainsString('pfb_form_subhdr_css_rules()', $source);
		$this->assertStringContainsString("pfb_form_subhdr(\$logdescr, 'pfb-loghdr')", $source);
		$this->assertStringContainsString('.pfb-logtrim { margin-top: 14px; padding-top: 10px; }', $source);
		$this->assertStringContainsString("addClass('pfb-logtrim')", $source);
	}

	public function testSupportLogoScalesInsteadOfOverflowingOnMobile(): void
	{
		$source = self::source();
		$this->assertStringContainsString('class="col-sm-9"', $source);
		$this->assertStringContainsString('<div class="col-sm-3" style="color-scheme: only light; text-align: center">', $source);
		$this->assertStringContainsString('display:block;margin-left:auto;margin-right:auto;width:100%;height:auto;max-width:140pt;', $source);
		$this->assertStringNotContainsString('forced-color-adjust', $source);
		$this->assertStringNotContainsString('data:image/svg+xml', $source);
		$this->assertStringNotContainsString('max-width:180pt', $source);
		$this->assertStringContainsString('viewBox="128 172 384 384"', $source);
		$this->assertStringNotContainsString('enable-background', $source);
		$this->assertStringNotContainsString('width="180.0pt"', $source);
		$this->assertStringNotContainsString('height="180.0pt"', $source);
		$this->assertStringNotContainsString('width: 75%; height: 180px; float: left;', $source);
	}

	public function testTrimMarginHelpIsNotRepeatedInTheIntroList(): void
	{
		$source = self::source();
		self::assertSame(
			1,
			preg_match(
				"/new Form_StaticText\(\s*''\s*,\s*'<style>'(.*?)<\/ul>'/s",
				$source,
				$m
			),
			'Log Settings intro Form_StaticText must exist'
		);
		$intro = $m[1];
		$this->assertStringContainsString('<li><strong>Max lines</strong>', $intro);
		$this->assertStringContainsString('<li><strong>Max days</strong>', $intro);
		$this->assertStringNotContainsString('<li><strong>Trim Margin</strong>', $intro);
		$this->assertStringContainsString('less flash/SSD wear', $source);
		$this->assertStringContainsString("'pfb_log_trim_margin_pct'", $source);
	}

	public function testTrimMarginSitsAfterTheLogRowsAndBeforeSyslog(): void
	{
		$source = self::source();
		$loop = strpos($source, 'foreach ($log_types as $logdescr => $logtype)');
		$trim = strpos($source, "new Form_Input(\n\t'pfb_log_trim_margin_pct'");
		$syslog = strpos($source, "new Form_Checkbox(\n\t'log_syslog'");
		$this->assertNotFalse($loop);
		$this->assertNotFalse($trim);
		$this->assertNotFalse($syslog);
		$this->assertGreaterThan($loop, $trim, 'Trim Margin must follow the category rows');
		$this->assertLessThan($syslog, $trim, 'Trim Margin must sit immediately before syslog');
	}
}
