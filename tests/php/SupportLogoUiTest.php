<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Support logo must not overflow a narrow viewport, must not clip the circle,
 * and must keep a light color-scheme so force-dark cannot wash the fills.
 */
final class SupportLogoUiTest extends TestCase
{
	public function testSupportLogoUsesAFluidColumnAndACircleViewBox(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php');
		$this->assertNotFalse($source);
		$this->assertStringContainsString('class="col-sm-9"', $source);
		$this->assertStringContainsString('class="col-sm-3"', $source);
		$this->assertStringContainsString('viewBox="128 172 384 384"', $source);
		$this->assertStringContainsString('color-scheme: only light', $source);
		$this->assertStringContainsString('max-width:140pt', $source);
		$this->assertStringContainsString('margin-left:auto;margin-right:auto', $source);
		$this->assertStringNotContainsString('enable-background', $source);
		$this->assertStringNotContainsString('width="180.0pt"', $source);
		$this->assertStringNotContainsString('height="180.0pt"', $source);
		$this->assertStringNotContainsString('width: 75%; height: 180px; float: left;', $source);
		$this->assertStringNotContainsString('width: 25%; height: 170px; float: right;', $source);
		$this->assertStringNotContainsString('max-width:180pt', $source);
	}
}
