<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Widget IP-table display count (issue #2645): kernel Addresses includes
 * ip_ph; a placeholder-only file is an empty feed and must show 0.
 */
#[CoversFunction('pfb_widget_alias_display_count')]
#[CoversFunction('pfb_ip_placeholder')]
#[CoversFunction('pfb_placeholder_for_family')]
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

	public function testPlaceholderReadsIpconfigNotApplyOnlyIpPh(): void
	{
		unset($GLOBALS['pfb']['ip_ph']);
		$GLOBALS['pfb']['ipconfig']['ip_placeholder'] = '10.9.8.7';
		$got = pfb_ip_placeholder();
		$this->assertSame(
			'10.9.8.7',
			$got,
			"expected: IP-tab ip_placeholder;\nactual: {$got}"
		);
		unset($GLOBALS['pfb']['ipconfig']['ip_placeholder']);
		$this->assertSame('127.1.7.7', pfb_ip_placeholder());
	}

	public function testPlaceholderRejectsInvalidConfig(): void
	{
		$GLOBALS['pfb']['ipconfig']['ip_placeholder'] = 'not-an-ip';
		$this->assertSame('127.1.7.7', pfb_ip_placeholder());
	}

	public function testPlaceholderForFamily_PrefixesV6Only(): void
	{
		$this->assertSame('127.1.7.7', pfb_placeholder_for_family('127.1.7.7', 'v4'));
		$this->assertSame('::127.1.7.7', pfb_placeholder_for_family('127.1.7.7', 'v6'));
	}

	public function testPlaceholderOnlyFile_ReturnsZero(): void
	{
		$this->assertNotFalse(file_put_contents($this->file, "127.1.7.7\n"));
		$got = pfb_widget_alias_display_count(1, $this->file, '127.1.7.7');
		$this->assertSame(
			0,
			$got,
			"expected: 0 for a padded-empty alias (Addresses=1 is the placeholder);\nactual: {$got}"
		);
	}

	public function testAddressesGreaterThanOne_SkipsFileSlurp(): void
	{
		// Placeholder-only content would return 0 if the file were read.
		// Addresses>1 must keep 16733; a missing-file fixture cannot fail
		// that, because an unreadable path is not placeholder-only.
		$this->assertNotFalse(file_put_contents($this->file, "127.1.7.7\n"));
		$got = pfb_widget_alias_display_count(16733, $this->file, '127.1.7.7');
		$this->assertSame(
			16733,
			$got,
			"expected: Addresses kept without reading the file;\nactual: {$got}"
		);
	}

	public function testMixedFile_KeepsAddresses(): void
	{
		$this->assertNotFalse(file_put_contents($this->file, "127.1.7.7\n1.2.3.4\n"));
		$got = pfb_widget_alias_display_count(16733, $this->file, '127.1.7.7');
		$this->assertSame(
			16733,
			$got,
			"expected: Addresses unchanged for a mixed alias;\nactual: {$got}"
		);
	}

	public function testV6PlaceholderOnly_ReturnsZero(): void
	{
		$this->assertNotFalse(file_put_contents($this->file, "::127.1.7.7\n"));
		$this->assertSame(0, pfb_widget_alias_display_count(1, $this->file, '::127.1.7.7'));
	}

	public function testV6BareEmptyfilesPad_ReturnsZero(): void
	{
		$this->assertNotFalse(file_put_contents($this->file, "127.1.7.7\n"));
		$got = pfb_widget_alias_display_count(1, $this->file, '::127.1.7.7');
		$this->assertSame(
			0,
			$got,
			"expected: 0 for sh emptyfiles() bare-IPv4 pad on a v6 alias;\nactual: {$got}"
		);
	}
}
