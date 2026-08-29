<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1887 — pfb_feed_internal_filter and pfb_software_check adopt the toggle adapter.
 *
 * These were the last two toggle fields registered with NULL adapters, each carrying its
 * default-ON semantics in a hand-written reader (`!== 'off'`) instead of the registry.
 * Adopting the adapter moves the default where every other toggle keeps it, and the
 * accessors compare the enum — no caller sees a key, a token or a default.
 *
 * Deliberate contract change, recorded here rather than hidden: the old readers treated
 * ANY non-'off' token as enabled, so junk ('yes', '1') read as ON. Under the adapter,
 * junk falls back to Off — the same convention as every other toggle — and the case
 * variants an operator would plausibly hand-edit ('OFF', 'On') are now recognised
 * instead of being junk. Junk can only exist via a hand-edited config.xml: both save
	 * paths emit canonical 'on'/empty tokens, and the registry seeds registered defaults.
 *
 * No global setters exist for either field (the #1895 interim confinement decision):
 * the Software page's privilege gate (issue #485) stays meaningful because the write
 * remains inline on the page.
 */
final class ToggleAdapterAdoptionTest extends TestCase
{
	private const FEED = 'installedpackages/pfblockerng/config/0/pfb_feed_internal_filter';
	private const SW   = 'installedpackages/pfblockerng/config/0/pfb_software_check';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// pfb_feed_internal_filter — the feed-host SSRF guard's master toggle
	// -----------------------------------------------------------------------

	/**
	 * The gateway returns the enum, and absent still means ON (the registered default).
	 */
	public function testFeedFilterReadReturnsTheEnumAndDefaultsOn(): void
	{
		$this->assertNull(config_get_path(self::FEED));
		$this->assertSame(
			PfbToggle::On,
			PfbConfig::read('gen/pfb_feed_internal_filter'),
			'absent pfb_feed_internal_filter must read as the registered default On, as the enum'
		);
	}

	/**
	 * Both accessor directions — the security-control assertion pair.
	 *
	 * A stuck-off regression silently disables the SSRF guard and a stuck-on one breaks
	 * the operator's opt-out; both current failure modes of a botched conversion are
	 * silent, so both directions are pinned.
	 */
	public function testFeedFilterAccessorHonoursBothDirections(): void
	{
		config_set_path(self::FEED, 'on');
		$this->assertTrue(pfb_feed_filter_enabled(), 'stored on must enable the feed-host filter');

		config_set_path(self::FEED, 'off');
		$this->assertFalse(pfb_feed_filter_enabled(), 'stored off must disable the feed-host filter');
	}

	/**
	 * The case variant an operator would plausibly hand-edit is recognised.
	 *
	 * This is the assertion that fails on the OLD reader: 'OFF' !== 'off' read as
	 * enabled, silently ignoring the operator's intent.
	 */
	public function testFeedFilterRecognisesCaseVariantOff(): void
	{
		config_set_path(self::FEED, 'OFF');
		$this->assertFalse(pfb_feed_filter_enabled(), "stored 'OFF' must disable the filter, not be junk");
	}

	// -----------------------------------------------------------------------
	// pfb_software_check — background new-version check
	// -----------------------------------------------------------------------

	/**
	 * The registry now owns the default-ON, so an absent key reads On as the enum.
	 *
	 * Before this, the registered default was '' and the ON default lived only in the
	 * hand-written reader — the exact split #1887 removes.
	 */
	public function testSoftwareCheckReadReturnsTheEnumAndDefaultsOn(): void
	{
		$this->assertNull(config_get_path(self::SW));
		$this->assertSame(
			PfbToggle::On,
			PfbConfig::read('gen/pfb_software_check'),
			'absent pfb_software_check must read as the registered default On, as the enum'
		);
	}

	/**
	 * The accessor asks the gateway itself — no argument, no narrowing at call sites.
	 *
	 * The old shape (`pfb_software_check_enabled(is_string($raw) ? $raw : null)`) is the
	 * one that would have silently jammed the toggle ON once read() returned an enum:
	 * the is_string() narrowing passes null, and null read as the never-saved default.
	 */
	public function testSoftwareCheckAccessorHonoursBothDirections(): void
	{
		config_set_path(self::SW, 'on');
		$this->assertTrue(pfb_software_check_enabled(), 'stored on must enable the background check');

		config_set_path(self::SW, 'off');
		$this->assertFalse(pfb_software_check_enabled(), 'stored off must disable the background check');

		config_set_path(self::SW, 'OFF');
		$this->assertFalse(pfb_software_check_enabled(), "stored 'OFF' must disable the check, not be junk");
	}

	/**
	 * The unchecked-save round trip: the Software page's inline empty write survives
	 * the gateway and reads back as a disabled check.
	 */
	public function testSoftwareCheckUncheckedSaveRoundTrips(): void
	{
		PfbConfig::write('gen/pfb_software_check', PfbToggle::Off);
		$this->assertSame('', config_get_path(self::SW), 'Off must persist as the canonical empty token');
		$this->assertFalse(pfb_software_check_enabled(), 'the persisted off must read back as disabled');
	}
}
