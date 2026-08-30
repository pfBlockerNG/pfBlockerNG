<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Support logo must not overflow a narrow viewport, must not clip the circle,
 * and must keep a light color-scheme so force-dark cannot wash the fills.
 *
 * Both shipped copies are held to one contract. They drifted before: issue #2863
 * found the wizard still carrying the fixed float column and the clipping viewBox
 * months after the General page was fixed, because only the General page was pinned.
 */
final class SupportLogoUiTest extends TestCase
{
	/** @return array<string, array{0: string}> */
	public static function logoPages(): array
	{
		return [
			'general page' => ['src/usr/local/www/pfblockerng/pfblockerng_general.php'],
			'setup wizard' => ['src/usr/local/www/wizards/pfblockerng_wizard.xml'],
		];
	}

	#[DataProvider('logoPages')]
	public function testSupportLogoUsesAFluidColumnAndACircleViewBox(string $page): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/' . $page);
		$this->assertNotFalse($source, "{$page} must be readable");

		$this->assertStringContainsString('class="col-sm-9"', $source, "{$page}: fluid text column");
		$this->assertStringContainsString('class="col-sm-3"', $source, "{$page}: fluid logo column");
		$this->assertStringContainsString('viewBox="128 172 384 384"', $source,
			"{$page}: the viewBox must contain the circle (cx=320.2 cy=363.8 r=184.1, top edge y=179.7)");
		$this->assertStringContainsString('color-scheme: only light', $source, "{$page}: force-dark guard");
		$this->assertStringContainsString('max-width:140pt', $source, "{$page}: bounded intrinsic width");
		$this->assertStringContainsString('margin-left:auto;margin-right:auto', $source, "{$page}: centred");

		foreach ([
			'enable-background',
			'width="180.0pt"',
			'height="180.0pt"',
			'width: 75%; height: 180px; float: left;',
			'width: 25%; height: 170px; float: right;',
			'width: 75%; height: 170px; float: left;',
			'viewBox="120 225 560 470"',
			'max-width:180pt',
		] as $retired) {
			$this->assertStringNotContainsString($retired, $source,
				"{$page}: retired construction is back: {$retired}");
		}
	}
}
