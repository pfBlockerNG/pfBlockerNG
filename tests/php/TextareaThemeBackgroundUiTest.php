<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * List textareas must not force an unpaired light fill; the Update log
 * viewer is a deliberate light pane and pins the matching foreground.
 */
final class TextareaThemeBackgroundUiTest extends TestCase
{
	public function testNoGuiPageHardcodesAnUnpairedFafafa(): void
	{
		$dir = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng';
		$hits = [];
		foreach (glob($dir . '/*.php') ?: [] as $path) {
			$source = file_get_contents($path);
			$this->assertNotFalse($source, $path);
			if (str_contains($source, 'background:#fafafa')) {
				$hits[] = basename($path);
			}
		}
		$this->assertSame([], $hits, 'unpaired background:#fafafa bleaches the dark theme');
	}

	public function testUpdateLogViewerPinsALightPaneWithForeground(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');
		$this->assertNotFalse($source);
		$this->assertSame(
			2,
			substr_count($source, "setAttribute('style', 'width: 100%; background-color: #fafafa; color: #212121;')")
		);
	}

	public function testEditHooksKeepsMonospaceAndCategoryFailedRowKeepsBothColours(): void
	{
		$hooks = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_edit_hooks.php');
		$category = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php');
		$this->assertNotFalse($hooks);
		$this->assertNotFalse($category);
		$this->assertStringContainsString("setAttribute('style', 'width: 100%; font-family: monospace;')", $hooks);
		$this->assertStringContainsString('#FFFF00', $category);
		$this->assertStringContainsString('color: black', $category);
	}
}
