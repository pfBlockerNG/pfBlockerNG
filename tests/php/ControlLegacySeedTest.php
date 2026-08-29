<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_control_legacy_seed() -- the one-time upgrade seed for the deprecated legacy
 * DNS-TXT control sub-toggle (PFBL-03). DNSBL control is CLI-driven; the DNS-TXT
 * transport is OFF by default. To keep an operator already driving control over DNS TXT
 * working through the one-release migration window, the legacy sub-toggle is seeded ON
 * IFF the pre-existing config already had DNSBL Control enabled at this upgrade. A
 * one-shot marker makes the seed run EXACTLY ONCE.
 *
 * Contract:
 *   - empty/non-array config => NULL (nothing to seed).
 *   - pfb_control == 'on' and not yet seeded => legacy ON + marker set.
 *   - pfb_control absent/off and not yet seeded => legacy left OFF, marker set.
 *   - already seeded (marker present) => NULL, regardless of pfb_control -- run-once,
 *     and an operator who cleared the legacy toggle is never re-enabled.
 */
#[CoversFunction('pfb_control_legacy_seed')]
final class ControlLegacySeedTest extends TestCase
{
	public function testEmptyConfigIsNoSeed(): void
	{
		// A fresh, never-configured install has nothing to grandfather.
		$this->assertNull(pfb_control_legacy_seed([]));
		$this->assertNull(pfb_control_legacy_seed(null));
	}

	public function testControlOnSeedsLegacyOnAndMarks(): void
	{
		// BEFORE: DNSBL Control was enabled over DNS TXT; legacy toggle unset.
		$dconfig = ['pfb_control' => 'on', 'pfb_dnsbl' => 'on'];
		$this->assertArrayNotHasKey('pfb_control_legacy', $dconfig);

		// WHEN: the one-time seed runs.
		$out = pfb_control_legacy_seed($dconfig);

		// THEN: the deprecated path is kept working (seeded ON) and the run-once marker set.
		$this->assertIsArray($out);
		$this->assertSame('on', $out['pfb_control_legacy']);
		$this->assertSame('on', $out['pfb_control_legacy_seeded']);
	}

	public function testControlOffLeavesLegacyOffButMarks(): void
	{
		// A box that never enabled DNSBL Control: no DNS-TXT path active by default.
		$out = pfb_control_legacy_seed(['pfb_control' => '', 'pfb_dnsbl' => 'on']);
		$this->assertIsArray($out);
		$this->assertArrayNotHasKey('pfb_control_legacy', $out);  // left OFF.
		$this->assertSame('on', $out['pfb_control_legacy_seeded']);  // but the seed ran.
	}

	public function testControlAbsentLeavesLegacyOffButMarks(): void
	{
		// pfb_control key absent entirely (older/minimal config) is also treated as OFF.
		$out = pfb_control_legacy_seed(['pfb_dnsbl' => 'on']);
		$this->assertIsArray($out);
		$this->assertArrayNotHasKey('pfb_control_legacy', $out);
		$this->assertSame('on', $out['pfb_control_legacy_seeded']);
	}

	public function testAlreadySeededIsNoOpEvenWithControlOn(): void
	{
		// Run-once: a second pass does nothing even though pfb_control is on.
		$dconfig = ['pfb_control' => 'on', 'pfb_control_legacy_seeded' => 'on'];
		$this->assertNull(pfb_control_legacy_seed($dconfig));
	}

	public function testAlreadySeededDoesNotReEnableUserClearedToggle(): void
	{
		// The operator deliberately turned the legacy toggle back OFF after the seed.
		// A later upgrade pass MUST NOT re-enable it (NULL => no change written).
		$dconfig = [
			'pfb_control' => 'on',
			'pfb_control_legacy' => '',
			'pfb_control_legacy_seeded' => 'on',
		];
		$this->assertNull(pfb_control_legacy_seed($dconfig));
	}

	public function testSeedIsExactlyOnceAcrossTwoPasses(): void
	{
		// First pass seeds (control on -> legacy on + marker). Feeding the RESULT back in
		// (a simulated second upgrade) yields NULL -> the seed never runs twice.
		$first = pfb_control_legacy_seed(['pfb_control' => 'on']);
		$this->assertSame('on', $first['pfb_control_legacy']);
		$this->assertNull(pfb_control_legacy_seed($first));
	}
}
