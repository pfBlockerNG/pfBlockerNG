<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ConfigPathDoublesTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = [];
	}

	public function testTrailingSlashAppendsToExistingLeafArray(): void
	{
		$GLOBALS['config'] = ['items' => ['first']];
		$this->assertSame(['first'], config_get_path('items'));

		$this->assertSame('second', config_set_path('items/', 'second'));

		$this->assertSame(['first', 'second'], config_get_path('items'));
	}

	public function testPlainPathReplacesExistingLeafArray(): void
	{
		$GLOBALS['config'] = ['items' => ['first']];
		$this->assertSame(['first'], config_get_path('items'));

		$this->assertSame('second', config_set_path('items', 'second'));

		$this->assertSame('second', config_get_path('items'));
	}
}
