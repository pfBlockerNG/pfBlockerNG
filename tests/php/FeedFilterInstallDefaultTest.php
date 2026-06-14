<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_filter_install_default() — the grandfather decision the install/upgrade
 * hook applies for the feed-host filter toggle. (The procedural application in
 * pfblockerng_install.inc — config_get_path/config_set_path — is smoke/manual-verified;
 * this pins the pure decision the hook delegates to.)
 *
 * Contract:
 *   - config/0 == null (fresh, never-configured install) => NULL: leave the key unset,
 *     so the runtime reader's ON default applies (filter active for new installs).
 *   - config/0 present, key absent (an already-configured upgrade) => 'off': pin it off
 *     once so existing feeds are never silently dropped.
 *   - key already set (either value) => NULL: run-once + idempotent, never re-disables
 *     an operator who re-enabled it.
 */
#[CoversFunction('pfb_feed_filter_install_default')]
final class FeedFilterInstallDefaultTest extends TestCase
{
	public function testFreshInstallLeavesKeyUnset(): void
	{
		// config/0 == null => fresh => NULL (=> runtime default ON).
		$this->assertNull(pfb_feed_filter_install_default(null));
	}

	public function testExistingInstallWithoutKeyIsPinnedOff(): void
	{
		// An already-configured install (other settings present, toggle absent) is the
		// grandfather case -> pin 'off'.
		$gconfig = ['enable_cb' => 'on', 'pfb_keep' => 'on'];
		$this->assertSame('off', pfb_feed_filter_install_default($gconfig));
	}

	public function testKeyAlreadyOffIsLeftUnchanged(): void
	{
		// Idempotent: a stored 'off' is not re-applied (NULL => no write).
		$this->assertNull(pfb_feed_filter_install_default(['pfb_feed_internal_filter' => 'off']));
	}

	public function testKeyAlreadyOnIsNotReDisabled(): void
	{
		// An operator who opted back in ('on') must never be re-disabled by a later
		// upgrade -> NULL (no write).
		$this->assertNull(pfb_feed_filter_install_default(['pfb_feed_internal_filter' => 'on']));
	}
}
