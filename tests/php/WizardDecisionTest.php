<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Setup-wizard decision helpers (issue #88) — the pure logic behind the Skip button
 * and the auto-launch guard added in #111. The pfblockerng_wizard.inc /
 * pfblockerng_general.php controllers do the impure work (read $_POST/$_GET/config,
 * redirect, write_config, set $pfb_wizard); these pure deciders are what determines
 * behaviour, so they are pinned here in the fast tier. Branch coverage: every input
 * class of all three functions, including the "fresh unconfigured install still
 * auto-launches" case the general.php comment explicitly worries about.
 */
#[CoversFunction('pfb_wizard_skip_action')]
#[CoversFunction('pfb_wizard_get_action')]
#[CoversFunction('pfb_wizard_suppress_autolaunch')]
final class WizardDecisionTest extends TestCase
{
	// --- pfb_wizard_skip_action(): Skip button + suppress checkbox -> action --- //

	public function testSkipNotPressedReturnsNull(): void
	{
		$this->assertNull(pfb_wizard_skip_action([]));
		// A POST without the Skip button (e.g. Next/Back) is not a skip.
		$this->assertNull(pfb_wizard_skip_action(['back' => 'Back']));
	}

	public function testSkipWithoutSuppressIsSessionSkip(): void
	{
		// Skip pressed, checkbox absent -> skip for this session only.
		$this->assertSame('skip', pfb_wizard_skip_action(['skip' => 'Skip']));
	}

	public function testSkipWithSuppressIsDisable(): void
	{
		// Skip pressed, checkbox ticked ('on') -> persist disable.
		$this->assertSame('disable', pfb_wizard_skip_action(['skip' => 'Skip', 'pfb_wizard_suppress' => 'on']));
	}

	public function testSuppressCheckboxFalseyValuesStaySkip(): void
	{
		// An empty / unchecked value must not count as ticked.
		$this->assertSame('skip', pfb_wizard_skip_action(['skip' => 'Skip', 'pfb_wizard_suppress' => '']));
		$this->assertSame('skip', pfb_wizard_skip_action(['skip' => 'Skip', 'pfb_wizard_suppress' => '0']));
	}

	// --- pfb_wizard_get_action(): ?wizard=<action> normalisation --- //

	public function testGetActionRecognisedValues(): void
	{
		$this->assertSame('skip', pfb_wizard_get_action(['wizard' => 'skip']));
		$this->assertSame('disable', pfb_wizard_get_action(['wizard' => 'disable']));
	}

	public function testGetActionUnrecognisedOrAbsentIsNull(): void
	{
		$this->assertNull(pfb_wizard_get_action([]));
		$this->assertNull(pfb_wizard_get_action(['wizard' => '']));
		$this->assertNull(pfb_wizard_get_action(['wizard' => 'bogus']));
		$this->assertNull(pfb_wizard_get_action(['other' => 'skip']));
	}

	// --- pfb_wizard_suppress_autolaunch(): the three OR'd suppression triggers --- //

	public function testFreshUnconfiguredInstallAutoLaunches(): void
	{
		// THE case the general.php comment guards: no skip, no persisted flag, and
		// config/0 unset (null) or empty -> the wizard MUST auto-launch (not suppressed).
		$this->assertFalse(pfb_wizard_suppress_autolaunch(null, null, null));
		$this->assertFalse(pfb_wizard_suppress_autolaunch(null, '', []));
	}

	public function testExplicitSkipSuppresses(): void
	{
		$this->assertTrue(pfb_wizard_suppress_autolaunch('skip', null, null));
	}

	public function testPersistedDisableFlagSuppresses(): void
	{
		$this->assertTrue(pfb_wizard_suppress_autolaunch(null, 'on', null));
	}

	public function testAlreadyConfiguredSuppresses(): void
	{
		// config/0 non-empty means the package is configured -> no auto-launch.
		$this->assertTrue(pfb_wizard_suppress_autolaunch(null, null, ['enable_cb' => 'on']));
	}

	public function testDisableActionAloneDoesNotSuppressThisRequest(): void
	{
		// ?wizard=disable is NOT a per-request suppressor by itself (only 'skip' is);
		// it suppresses via the flag it persists, which general.php reads back as 'on'.
		$this->assertFalse(pfb_wizard_suppress_autolaunch('disable', null, null));
		$this->assertTrue(pfb_wizard_suppress_autolaunch('disable', 'on', null));
	}
}
