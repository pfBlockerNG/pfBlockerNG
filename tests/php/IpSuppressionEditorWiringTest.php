<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class IpSuppressionEditorWiringTest extends TestCase
{
	public function testDisabledEditorEmitsNoSuppressionMount(): void
	{
		$this->assertSame('', pfb_ip_editor_render(FALSE)['lists']);
	}

	public function testEnabledEditorMountsBothSuppressionFieldsExactlyOnce(): void
	{
		$init = pfb_ip_editor_render(TRUE)['lists'];

		$this->assertStringContainsString('window.pfbCM', $init);
		$this->assertSame(1, substr_count($init, 'pfbCM.mountLists('));
		$this->assertStringContainsString('v4suppression', $init);
		$this->assertStringContainsString('v6suppression', $init);
	}
}
