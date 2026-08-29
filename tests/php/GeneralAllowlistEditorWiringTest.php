<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class GeneralAllowlistEditorWiringTest extends TestCase
{
	public function testDisabledEditorEmitsNoAllowlistMount(): void
	{
		$this->assertSame('', pfb_general_editor_render(FALSE)['lists']);
	}

	public function testEnabledEditorMountsTheInternalAllowlistField(): void
	{
		$init = pfb_general_editor_render(TRUE)['lists'];

		$this->assertStringContainsString('window.pfbCM', $init);
		$this->assertSame(1, substr_count($init, 'pfbCM.mountLists('));
		$this->assertStringContainsString('pfb_feed_internal_allowlist', $init);
	}
}
