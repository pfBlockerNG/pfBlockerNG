<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_filter_enabled() — the runtime reader for the master feed-host filter
 * toggle ('pfb_feed_internal_filter'). It gates whether pfb_download() invokes the
 * feed-host guard at all.
 *
 * Default-ON contract: a fresh, never-configured install (key absent) reads as ON, so
 * the filter ships active. An explicit stored 'off' (written by an unchecked save, or
 * pinned by the install-time grandfather migration on an existing box) reads as OFF.
 * Any other stored value reads as ON (the value the UI writes when checked is 'on').
 */
#[CoversFunction('pfb_feed_filter_enabled')]
final class FeedFilterEnabledTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config']);
	}

	private function setToggle(string $value): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter', $value);
	}

	public function testDefaultsOnWhenKeyAbsent(): void
	{
		// Fresh install: the key is unset -> the filter is enabled (secure default).
		$this->assertTrue(pfb_feed_filter_enabled());
	}

	public function testExplicitOffDisablesTheFilter(): void
	{
		// Before: absent -> enabled.
		$this->assertTrue(pfb_feed_filter_enabled());
		// After: a stored 'off' (unchecked save / grandfather pin) -> disabled.
		$this->setToggle('off');
		$this->assertFalse(pfb_feed_filter_enabled());
	}

	public function testExplicitOnEnablesTheFilter(): void
	{
		// First pin it off, then on, so green proves the 'on' value flips it back.
		$this->setToggle('off');
		$this->assertFalse(pfb_feed_filter_enabled());
		$this->setToggle('on');
		$this->assertTrue(pfb_feed_filter_enabled());
	}

	public function testAnyNonOffValueReadsAsEnabled(): void
	{
		// Only the literal 'off' disables; an empty string or stray value reads ON
		// (fail-safe toward keeping the filter active).
		$this->setToggle('');
		$this->assertTrue(pfb_feed_filter_enabled());
	}
}
