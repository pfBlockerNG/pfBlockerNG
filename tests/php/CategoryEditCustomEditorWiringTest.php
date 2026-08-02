<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class CategoryEditCustomEditorWiringTest extends TestCase
{
	public function testDisabledEditorEmitsNoCustomMount(): void
	{
		$this->assertSame('', pfb_category_editor_render(FALSE, 'no-sort')['mount']);
	}

	public function testEnabledEditorMountsTheCustomFieldExactlyOnce(): void
	{
		$init = pfb_category_editor_render(TRUE, 'no-sort')['mount'];

		$this->assertStringContainsString('window.pfbCM', $init);
		$this->assertSame(1, substr_count($init, 'pfbCM.mountLists('));
		$this->assertStringContainsString('custom', $init);
	}
}
