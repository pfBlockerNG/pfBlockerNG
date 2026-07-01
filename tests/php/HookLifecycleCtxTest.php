<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #684: pfb_hook_lifecycle_ctx() maps the $pfb['hook_lifecycle'] marker to the extra PFB_*
 * hook-context keys, so a hook owner learns which pkg transition (if any) the pass belongs to.
 *
 * This is context, NOT special handling: pfBlockerNG fires hooks the same way on every pass and
 * never branches on the lifecycle -- it only publishes it. The install/upgrade turn-ON (resync)
 * marks 'install' -> PFB_POST_INSTALL=1; the pre-deinstall turn-OFF marks 'uninstall' ->
 * PFB_PRE_UNINSTALL=1; a normal cron/manual/force update leaves the marker unset -> neither key.
 * Present-when-applicable (a hook tests `[ -n "$PFB_POST_INSTALL" ]`), matching ADR-12 style.
 */
#[CoversFunction('pfb_hook_lifecycle_ctx')]
final class HookLifecycleCtxTest extends TestCase
{
	public function testInstallMarkerYieldsPostInstall(): void
	{
		$this->assertSame(['POST_INSTALL' => '1'], pfb_hook_lifecycle_ctx('install'));
	}

	public function testUninstallMarkerYieldsPreUninstall(): void
	{
		$this->assertSame(['PRE_UNINSTALL' => '1'], pfb_hook_lifecycle_ctx('uninstall'));
	}

	public function testNormalPassYieldsNoLifecycleKeys(): void
	{
		// An unset marker (the '' default $pfb['hook_lifecycle'] ?? '' produces) — a plain
		// cron/manual/force update — publishes NEITHER key.
		$this->assertSame([], pfb_hook_lifecycle_ctx(''));
	}

	public function testUnknownMarkerYieldsNoLifecycleKeys(): void
	{
		// Fail-safe: any value other than the two known markers is treated as a normal pass,
		// so a stray/garbage marker can never inject an unexpected PFB_* key.
		$this->assertSame([], pfb_hook_lifecycle_ctx('something-else'));
	}

	/**
	 * The keys are exactly the two documented ones — pinned so a rename can't silently drift the
	 * public hook contract (PFB_POST_INSTALL / PFB_PRE_UNINSTALL after the PFB_ prefix is applied).
	 */
	public function testPublishedKeysAreExactlyTheTwoLifecycleSignals(): void
	{
		$this->assertSame(['POST_INSTALL'], array_keys(pfb_hook_lifecycle_ctx('install')));
		$this->assertSame(['PRE_UNINSTALL'], array_keys(pfb_hook_lifecycle_ctx('uninstall')));
	}
}
