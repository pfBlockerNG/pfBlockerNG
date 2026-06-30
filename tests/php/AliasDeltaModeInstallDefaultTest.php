<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_alias_delta_mode_install_default() — the ADR-40 grandfather decision the
 * install/upgrade hook applies for the alias-table apply mode. (The procedural
 * application in pfblockerng_install.inc — PfbConfig::write — is smoke/manual-verified;
 * this pins the pure decision the hook delegates to.)
 *
 * Contract:
 *   - config/0 == null (fresh, never-configured install) => NULL: leave the key unset,
 *     so the registry absent-default 'auto' applies (delta for small churn, new installs).
 *   - config/0 present, key absent (an already-configured upgrade) => 'replace': pin the
 *     pre-ADR-40 full -T replace once, so the upgrade does not silently switch to delta.
 *   - key already set (any value) => NULL: run-once + idempotent, never overrides an
 *     operator's explicit choice (incl. an explicit 'auto').
 */
#[CoversFunction('pfb_alias_delta_mode_install_default')]
final class AliasDeltaModeInstallDefaultTest extends TestCase
{
	public function testFreshInstallLeavesKeyUnset(): void
	{
		// config/0 == null => fresh => NULL (=> registry absent-default 'auto').
		$this->assertNull(pfb_alias_delta_mode_install_default(null));
	}

	public function testExistingInstallWithoutKeyIsPinnedReplace(): void
	{
		// An already-configured install (other settings present, key absent) is the
		// grandfather case -> pin 'replace' to preserve pre-ADR-40 behaviour.
		$gconfig = ['enable_cb' => 'on', 'pfb_keep' => 'on'];
		$this->assertSame('replace', pfb_alias_delta_mode_install_default($gconfig));
	}

	public function testKeyAlreadyAutoIsNotRePinned(): void
	{
		// An operator who explicitly chose 'auto' must never be flipped to 'replace' by a
		// later upgrade -> NULL (no write).
		$this->assertNull(pfb_alias_delta_mode_install_default(['pfb_alias_delta_mode' => 'auto']));
	}

	public function testKeyAlreadyReplaceIsLeftUnchanged(): void
	{
		// Idempotent: a stored 'replace' is not re-applied (NULL => no write).
		$this->assertNull(pfb_alias_delta_mode_install_default(['pfb_alias_delta_mode' => 'replace']));
	}

	public function testKeyAlreadyDeltaIsPreserved(): void
	{
		// A power-user 'delta' choice survives the seed -> NULL (no write).
		$this->assertNull(pfb_alias_delta_mode_install_default(['pfb_alias_delta_mode' => 'delta']));
	}
}
