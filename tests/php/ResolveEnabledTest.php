<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_resolve_enabled() — predicate for the reverse-DNS PTR lookup gate in the
 * block-log daemon (issue #336).
 *
 * Default-ON contract: an absent 'enable_resolve' key (fresh install / upgrade
 * from a version that did not have this option) returns TRUE, preserving the
 * legacy behaviour of always resolving. The user must explicitly uncheck
 * "Resolve IP Addresses" (stored as '') to disable lookups.
 *
 * Three branches:
 *   - key absent     → TRUE  (default-on / legacy behaviour)
 *   - key = 'on'     → TRUE  (user has the checkbox checked)
 *   - key = ''       → FALSE (user unchecked the checkbox)
 */
#[CoversFunction('pfb_resolve_enabled')]
final class ResolveEnabledTest extends TestCase
{
	public function testDefaultsOnWhenKeyAbsent(): void
	{
		// Fresh install or upgrade: the key does not exist in the config row yet.
		// Must return TRUE so existing boxes keep resolving without any config change.
		$this->assertTrue(pfb_resolve_enabled([]));
	}

	public function testExplicitOnReturnsTrue(): void
	{
		// Before: absent → TRUE.
		$this->assertTrue(pfb_resolve_enabled([]));
		// After: stored 'on' (checkbox checked) → TRUE.
		$this->assertTrue(pfb_resolve_enabled(['enable_resolve' => 'on']));
	}

	public function testExplicitOffReturnsFalse(): void
	{
		// Before: stored 'on' (default) → TRUE; proves the flip is real.
		$this->assertTrue(pfb_resolve_enabled(['enable_resolve' => 'on']));
		// After: stored '' (unchecked save) → FALSE — reverse-DNS disabled.
		$this->assertFalse(pfb_resolve_enabled(['enable_resolve' => '']));
	}
}
