<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #684 / #695: pfb_hook_lifecycle_ctx() maps the $pfb['hook_lifecycle'] marker to the extra
 * PFB_* hook-context keys, so a hook owner learns which pkg transition (if any) the pass belongs to.
 *
 * This is context, NOT special handling: pfBlockerNG fires hooks the same way on every pass and
 * never branches on the lifecycle -- it only publishes it. Both keys are ALWAYS emitted as '1'/'0'
 * (#695), matching the '1'/'0' contract of the other context vars (PFB_IP_CHANGED / PFB_DNSBL_CHANGED)
 * so a hook can guard every PFB_* flag uniformly. The install/upgrade turn-ON (resync) sets
 * PFB_POST_INSTALL=1; the pre-deinstall turn-OFF sets PFB_PRE_UNINSTALL=1; a normal cron/manual/force
 * update sets both to '0'. Exactly ONE key is '1' during a transition; the off-phase key is '0', never
 * unset.
 */
#[CoversFunction('pfb_hook_lifecycle_ctx')]
final class HookLifecycleCtxTest extends TestCase
{
	public function testInstallMarkerSetsPostInstallOneUninstallZero(): void
	{
		$this->assertSame(['POST_INSTALL' => '1', 'PRE_UNINSTALL' => '0'], pfb_hook_lifecycle_ctx('install'));
	}

	public function testUninstallMarkerSetsPreUninstallOnePostInstallZero(): void
	{
		$this->assertSame(['POST_INSTALL' => '0', 'PRE_UNINSTALL' => '1'], pfb_hook_lifecycle_ctx('uninstall'));
	}

	public function testNormalPassSetsBothToZero(): void
	{
		// A normal cron/manual/force update (the '' default $pfb['hook_lifecycle'] ?? '' produces) --
		// both keys present and '0', so a hook reading them never hits an unset var.
		$this->assertSame(['POST_INSTALL' => '0', 'PRE_UNINSTALL' => '0'], pfb_hook_lifecycle_ctx(''));
	}

	public function testUnknownMarkerFailsSafeToBothZero(): void
	{
		// Fail-safe: any value other than the two known markers is treated as a normal pass, so a
		// stray/garbage marker can never raise a lifecycle flag to '1'.
		$this->assertSame(['POST_INSTALL' => '0', 'PRE_UNINSTALL' => '0'], pfb_hook_lifecycle_ctx('something-else'));
	}

	/**
	 * Both keys are ALWAYS present regardless of phase -- pinned so a regression to the old
	 * present-only form (unset off-phase) is caught, and so a rename can't silently drift the public
	 * hook contract (PFB_POST_INSTALL / PFB_PRE_UNINSTALL after the PFB_ prefix is applied).
	 */
	public function testBothKeysAreAlwaysPresentInEveryPass(): void
	{
		foreach (['install', 'uninstall', '', 'something-else'] as $lifecycle) {
			$this->assertSame(
				['POST_INSTALL', 'PRE_UNINSTALL'],
				array_keys(pfb_hook_lifecycle_ctx($lifecycle)),
				"both lifecycle keys must be present for lifecycle='{$lifecycle}'"
			);
		}
	}
}
