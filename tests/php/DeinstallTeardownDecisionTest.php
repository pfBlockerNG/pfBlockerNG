<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_deinstall_full_teardown() — the #687 pure decision behind the pre-deinstall: does a package
 * removal FULLY tear pfBlockerNG down (turn it OFF + remove live objects), or SKIP that to keep it
 * active across a version/OS upgrade? pfSense cannot tell an upgrade from a real uninstall in the
 * pre-deinstall, so the user's settings + the Software-page intent marker decide — never
 * upgrade-detection.
 *
 * Ladder (first match wins):
 *   keep-settings OFF                          -> FULL teardown (settings are going away)
 *   Software-page "Uninstall" intent marker    -> FULL teardown (explicit removal)
 *   "Keep enabled during version upgrades" ON  -> SKIP  (stay live across the upgrade)
 *   otherwise                                  -> FULL teardown (today's behaviour)
 *
 * Only keep-on + toggle-on + no-marker skips teardown. Every branch is asserted below.
 */
#[CoversFunction('pfb_deinstall_full_teardown')]
final class DeinstallTeardownDecisionTest extends TestCase
{
	public function testKeepSettingsOffAlwaysTearsDown(): void
	{
		// keep=off => cleanup is mandatory regardless of the toggle or the marker.
		$this->assertTrue(pfb_deinstall_full_teardown(false, false, false));
		$this->assertTrue(pfb_deinstall_full_teardown(false, true, false));
		$this->assertTrue(pfb_deinstall_full_teardown(false, true, true));
	}

	public function testIntentionalUninstallTearsDownEvenWithToggleOn(): void
	{
		// keep=on + toggle=on, but the Software-page marker forces a full removal.
		$this->assertTrue(pfb_deinstall_full_teardown(true, true, true));
	}

	public function testToggleOnKeepsPfblockerngLiveAcrossUpgrade(): void
	{
		// keep=on + toggle=on + no marker => SKIP teardown (the only skip case) — stay live across
		// the version/OS upgrade window.
		$this->assertFalse(pfb_deinstall_full_teardown(true, true, false));
	}

	public function testToggleOffPreservesTodaysTeardownBehaviour(): void
	{
		// keep=on + toggle=off + no marker => FULL teardown (the pre-#687 default).
		$this->assertTrue(pfb_deinstall_full_teardown(true, false, false));
	}
}
