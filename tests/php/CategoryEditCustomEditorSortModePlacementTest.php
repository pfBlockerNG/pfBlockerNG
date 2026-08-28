<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class CategoryEditCustomEditorSortModePlacementTest extends TestCase
{
	public function testCustomEditorMountRunsForNoSortAndAutoSortRows(): void
	{
		$noSort = pfb_category_editor_render(TRUE, 'no-sort')['mount'];
		$auto   = pfb_category_editor_render(TRUE, 'auto-sort')['mount'];

		$this->assertStringContainsString('pfbCM.mountLists', $noSort);
		$this->assertStringContainsString('custom', $noSort);
		$this->assertSame($noSort, $auto);
	}

	public function testDisabledCustomEditorStaysEmptyRegardlessOfSortMode(): void
	{
		$this->assertSame('', pfb_category_editor_render(FALSE, 'no-sort')['mount']);
		$this->assertSame('', pfb_category_editor_render(FALSE, 'auto-sort')['mount']);
	}
}
