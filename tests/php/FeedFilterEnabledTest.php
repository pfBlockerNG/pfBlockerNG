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
 * the filter ships active. Case-insensitive 'on' reads as On; every other present token
 * reads as Off. Unchecked saves write canonical empty; legacy 'off' remains read-compatible.
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
		// After: a legacy stored 'off' (hand-edited or HA-synchronised) -> disabled.
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

	public function testEmptyStringReadsAsExplicitOff(): void
	{
		// issue #2120: the owner-ruled toggle contract preserves present '' as Off.
		$this->setToggle('');
		$this->assertFalse(pfb_feed_filter_enabled());
	}

	public function testJunkTokenFallsBackToOff(): void
	{
		// issue #1887 contract change, deliberate: junk used to read as enabled
		// (`!== 'off'`); under the shared toggle adapter it falls back to Off like
		// every other toggle. Junk is only reachable via a hand-edited config.xml —
		// both save paths emit canonical tokens — and the case variants an operator
		// would actually type ('OFF', 'On') are now recognised instead of being junk.
		$this->setToggle('yes');
		$this->assertFalse(pfb_feed_filter_enabled());

		$this->setToggle('OFF');
		$this->assertFalse(pfb_feed_filter_enabled(), "the 'OFF' case variant must disable, not read as junk");
	}
}
