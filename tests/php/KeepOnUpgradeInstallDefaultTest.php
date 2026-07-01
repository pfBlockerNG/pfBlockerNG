<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_keep_on_upgrade_install_default() — the #687 grandfather decision the install/upgrade hook
 * applies for "Keep enabled during version upgrades". (The procedural application in
 * pfblockerng_install.inc — PfbConfig::write — is smoke/manual-verified; this pins the pure
 * decision the hook delegates to.)
 *
 * Contract:
 *   - config/0 == null (fresh, never-configured install) => NULL: leave the key unset, so the
 *     registry absent-default 'on' applies (protect across upgrades by default, for NEW installs).
 *   - config/0 present, key absent (an already-configured upgrade) => 'off': preserve that
 *     operator's prior teardown-on-removal behaviour and the safe stock-Package-Manager uninstall
 *     path, rather than silently keeping pfBlockerNG live across removals.
 *   - key already set (any value) => NULL: run-once + idempotent, never overrides an operator's
 *     explicit choice (incl. an explicit 'on').
 */
#[CoversFunction('pfb_keep_on_upgrade_install_default')]
final class KeepOnUpgradeInstallDefaultTest extends TestCase
{
	public function testFreshInstallLeavesKeyUnset(): void
	{
		// config/0 == null => fresh => NULL (=> registry absent-default 'on' for new installs).
		$this->assertNull(pfb_keep_on_upgrade_install_default(null));
	}

	public function testExistingInstallWithoutKeyIsPinnedOff(): void
	{
		// An already-configured install (other settings present, key absent) is the grandfather
		// case -> pin 'off' so the upgrade preserves prior teardown-on-removal behaviour.
		$gconfig = ['enable_cb' => 'on', 'pfb_keep' => 'on'];
		$this->assertSame('off', pfb_keep_on_upgrade_install_default($gconfig));
	}

	public function testKeyAlreadyOnIsNotRePinned(): void
	{
		// An operator who explicitly chose 'on' must never be flipped to 'off' by a later
		// upgrade -> NULL (no write).
		$this->assertNull(pfb_keep_on_upgrade_install_default(['pfb_keep_on_upgrade' => 'on']));
	}

	public function testKeyAlreadyOffIsLeftUnchanged(): void
	{
		// Idempotent: a stored 'off' is not re-applied (NULL => no write).
		$this->assertNull(pfb_keep_on_upgrade_install_default(['pfb_keep_on_upgrade' => 'off']));
	}
}
