<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-19 — the hidden Software-page override sentinel (pfb_software_panel_override). A pure,
 * pfSense-decoupled helper: the file's content forces the provenance gate on/off so CI can
 * render BOTH the enabled and disabled Software-page states deterministically (the Tier-A UI
 * deploy is a sideload whose %R is empty, so the auto-detect alone could only show "hidden").
 *
 * Per CLAUDE.md test-coverage rules every branch + input class is asserted: forced-on,
 * forced-off, case/whitespace normalisation, the absent file, and the "any other content =>
 * NULL (auto-detect applies)" fall-through (empty / garbage / a non-on-off word).
 */
#[CoversFunction('pfb_software_panel_override')]
final class SoftwarePanelOverrideTest extends TestCase
{
	private string $tmp = '';

	protected function setUp(): void
	{
		$this->tmp = (string) tempnam(sys_get_temp_dir(), 'pfb_sw_panel_');
	}

	protected function tearDown(): void
	{
		if ($this->tmp !== '' && is_file($this->tmp)) {
			unlink($this->tmp);
		}
	}

	private function override(string $content): ?bool
	{
		file_put_contents($this->tmp, $content);
		return pfb_software_panel_override($this->tmp);
	}

	public function testOnForcesEnabled(): void
	{
		// 'on' (and case/whitespace variants) => force the gate OPEN (true).
		$this->assertTrue($this->override('on'));
		$this->assertTrue($this->override("  ON\n"));
		$this->assertTrue($this->override("On\r\n"));
	}

	public function testOffForcesDisabled(): void
	{
		// 'off' (and case/whitespace variants) => force the gate CLOSED (false) — distinct from
		// NULL: a forced-off must NOT fall through to the auto-detect.
		$this->assertFalse($this->override('off'));
		$this->assertFalse($this->override("\tOFF "));
	}

	public function testAnyOtherContentFallsThroughToAutoDetect(): void
	{
		// Empty / unrelated content => NULL: the caller then runs the %R auto-detect. This is the
		// third branch, NOT a silent on/off — a typo'd sentinel must never force a state.
		$this->assertNull($this->override(''));
		$this->assertNull($this->override('   '));
		$this->assertNull($this->override('enabled'));
		$this->assertNull($this->override('1'));
		$this->assertNull($this->override('on off'));
	}

	public function testAbsentFileIsNotForced(): void
	{
		// No sentinel => NULL (auto-detect): the default state on every normal install.
		unlink($this->tmp);
		$this->assertNull(pfb_software_panel_override($this->tmp));
	}
}
