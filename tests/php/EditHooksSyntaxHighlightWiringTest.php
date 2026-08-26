<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class EditHooksSyntaxHighlightWiringTest extends TestCase
{
	public function testDisabledHookEditorEmitsNoAssetOrInitialization(): void
	{
		$rendered = pfb_hooks_editor_render(FALSE, 'py');
		$this->assertSame('', $rendered['asset']);
		$this->assertSame('', $rendered['mount']);
	}

	public function testEnabledHookEditorTargetsContentAndLiveLanguage(): void
	{
		$rendered = pfb_hooks_editor_render(TRUE, 'py');
		$asset = $rendered['asset'];
		$init  = $rendered['mount'];

		$this->assertStringContainsString('cm-hooks.min.js?v=', $asset);
		$this->assertStringContainsString("getElementById('pfb_hook_editor_content')", $init);
		$this->assertStringContainsString('window.pfbHooksCM', $init);
		$this->assertStringContainsString('fromTextarea(pfbHookEditorEl, "py"', $init);
		$this->assertStringContainsString("lintUrl: '/pfblockerng/pfblockerng_lint.php'", $init);
	}

	public function testHookEditorUsesCurrentServerLanguage(): void
	{
		$python = pfb_hooks_editor_render(TRUE, 'py')['mount'];
		$shell  = pfb_hooks_editor_render(TRUE, 'sh')['mount'];

		$this->assertStringContainsString('"py"', $python);
		$this->assertStringNotContainsString('"sh"', $python);
		$this->assertStringContainsString('"sh"', $shell);
		$this->assertStringNotContainsString('"py"', $shell);
	}

	public function testHookEditorAssetAndLintEachRenderOnce(): void
	{
		$asset = pfb_hooks_editor_render(TRUE, 'sh')['asset'];
		$init  = pfb_hooks_editor_render(TRUE, 'sh')['mount'];

		$this->assertSame(1, substr_count($asset, '<script'));
		$this->assertSame(1, substr_count($init, 'pfbHooksCM.fromTextarea('));
		$this->assertSame(1, substr_count($init, "lintUrl: '/pfblockerng/pfblockerng_lint.php'"));
	}
}
