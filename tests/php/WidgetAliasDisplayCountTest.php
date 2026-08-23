<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Widget IP-table display count (issue #2645): kernel Addresses includes
 * ip_ph; a placeholder-only file is an empty feed and must show 0.
 */
#[CoversFunction('pfb_widget_alias_display_count')]
final class WidgetAliasDisplayCountTest extends TestCase
{
	private string $file;

	protected function setUp(): void
	{
		$this->file = sys_get_temp_dir() . '/pfb_ph_' . uniqid() . '.txt';
	}

	protected function tearDown(): void
	{
		@unlink($this->file);
	}

	public function testPlaceholderOnlyFile_ReturnsZero(): void
	{
		$this->assertNotFalse(file_put_contents($this->file, "127.1.7.7\n"));
		$this->assertSame(
			0,
			pfb_widget_alias_display_count(1, $this->file, '127.1.7.7'),
			'expected: 0 for a padded-empty alias (Addresses=1 is the placeholder);\nactual: non-zero'
		);
	}

	public function testMixedFile_KeepsAddresses(): void
	{
		$this->assertNotFalse(file_put_contents($this->file, "127.1.7.7\n1.2.3.4\n"));
		$this->assertSame(
			16733,
			pfb_widget_alias_display_count(16733, $this->file, '127.1.7.7'),
			'expected: Addresses unchanged for a mixed alias;\nactual: diverged'
		);
	}

	public function testV6PlaceholderOnly_ReturnsZero(): void
	{
		$this->assertNotFalse(file_put_contents($this->file, "::127.1.7.7\n"));
		$this->assertSame(0, pfb_widget_alias_display_count(1, $this->file, '::127.1.7.7'));
	}
}
