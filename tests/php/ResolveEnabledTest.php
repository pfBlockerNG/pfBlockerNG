<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_resolve_enabled() and pfb_rdns_seed_value() — reverse-DNS toggle gate
 * and upgrade-seed decision for the block-log daemon (issue #336).
 *
 * Default-OFF contract (pfb_resolve_enabled): an absent 'enable_rdns' key
 * (new install) returns FALSE — reverse-DNS is off by default. Existing
 * installs receive a one-time 'on' seed at upgrade via pfb_rdns_seed_value()
 * (see pfblockerng_install.inc) to preserve the historical always-resolving
 * behaviour.
 *
 * pfb_resolve_enabled() branches:
 *   - key absent     → FALSE  (new-install default OFF)
 *   - key = 'on'     → TRUE   (user has the checkbox checked)
 *   - key = ''       → FALSE  (user unchecked the checkbox)
 *
 * Scenario: pfb_rdns_seed_value() grandfather logic
 *   Background: the key 'enable_rdns' did not exist before issue #336.
 *               Existing installs historically always resolved (default ON).
 *               New installs must default OFF.
 *
 *   Given an existing install (non-empty general config) with no enable_rdns key
 *   When  pfb_rdns_seed_value() is called
 *   Then  it returns 'on' — so the install hook seeds the key to ON (preserve behaviour)
 *
 *   Given a fresh install (empty general config)
 *   When  pfb_rdns_seed_value() is called
 *   Then  it returns null — key stays absent, pfb_resolve_enabled() defaults OFF
 *
 *   Given an existing install where enable_rdns is already 'on'
 *   When  pfb_rdns_seed_value() is called
 *   Then  it returns null — key already set, never reseed
 *
 *   Given an existing install where the user explicitly unchecked the box (key = '')
 *   When  pfb_rdns_seed_value() is called
 *   Then  it returns null — user's explicit OFF must never be overwritten
 */
#[CoversFunction('pfb_resolve_enabled')]
#[CoversFunction('pfb_rdns_seed_value')]
final class ResolveEnabledTest extends TestCase
{
	// -------------------------------------------------------------------------
	// pfb_resolve_enabled()
	// -------------------------------------------------------------------------

	public function testDefaultsOffWhenKeyAbsent(): void
	{
		// New install: enable_rdns key does not exist yet.
		// Must return FALSE — reverse-DNS is off by default for new installs.
		$this->assertFalse(pfb_resolve_enabled([]));
	}

	public function testExplicitOnReturnsTrue(): void
	{
		// Before: absent key → FALSE (new-install default).
		$this->assertFalse(pfb_resolve_enabled([]));
		// After: stored 'on' (checkbox checked) → TRUE.
		$this->assertTrue(pfb_resolve_enabled(['enable_rdns' => 'on']));
	}

	public function testExplicitOffReturnsFalse(): void
	{
		// Before: stored 'on' (checkbox checked) → TRUE; proves the flip is real.
		$this->assertTrue(pfb_resolve_enabled(['enable_rdns' => 'on']));
		// After: stored '' (unchecked save) → FALSE — reverse-DNS disabled.
		$this->assertFalse(pfb_resolve_enabled(['enable_rdns' => '']));
	}

	// -------------------------------------------------------------------------
	// pfb_rdns_seed_value()
	// -------------------------------------------------------------------------

	public function testExistingInstallWithNoKeySeededOn(): void
	{
		// Given: existing install (non-empty general config), enable_rdns absent.
		// When:  pfb_rdns_seed_value() called.
		// Then:  returns 'on' — install hook seeds existing installs to preserve
		//        historical always-resolving behaviour.
		$this->assertSame('on', pfb_rdns_seed_value(['enable' => 'on'], []));
	}

	public function testFreshInstallNoKeyReturnsNull(): void
	{
		// Given: fresh install (empty general config), enable_rdns absent.
		// When:  pfb_rdns_seed_value() called.
		// Then:  returns null — key stays absent; pfb_resolve_enabled() defaults OFF.
		$this->assertNull(pfb_rdns_seed_value([], []));
	}

	public function testExistingInstallKeyAlreadyOnReturnsNull(): void
	{
		// Given: existing install with enable_rdns already 'on' (already seeded).
		// When:  pfb_rdns_seed_value() called.
		// Then:  returns null — never reseed an already-set key.
		$this->assertNull(pfb_rdns_seed_value(['enable' => 'on'], ['enable_rdns' => 'on']));
	}

	public function testUserOptedOutExplicitlyNeverReseeded(): void
	{
		// Given: existing install where the user EXPLICITLY unchecked the box
		//        (stored as '' — the 'off' value for this toggle).
		// When:  pfb_rdns_seed_value() called.
		// Then:  returns null — the key IS present (value ''), so no reseed.
		//        This is the critical safety branch: a user's deliberate opt-out
		//        must NEVER be overwritten by the upgrade seed.
		$this->assertNull(pfb_rdns_seed_value(['enable' => 'on'], ['enable_rdns' => '']));
	}
}
