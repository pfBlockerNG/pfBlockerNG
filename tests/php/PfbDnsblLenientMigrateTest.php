<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_lenient_migrate() -- the one-time upgrade migration for the ADR-22
 * 'pfb_dnsbl_lenient' DNSBL scheme-parsing toggle.
 *
 * Scenario: preserve permissive parsing for existing installs on upgrade.
 *   Background: $dconfig is the existing DNSBL-settings 'config/0' node.
 *     - New installs default OFF (strict): a fresh box has no prior config section.
 *     - Existing installs are migrated to 'on' (lenient): a populated section that
 *       predates the key keeps the permissive behaviour it relied on.
 *     - Migration ONLY sets a missing key; it never overwrites an existing value.
 *
 * Contract (ADR §2.2 / §2.6.6):
 *   - empty/non-array config (fresh install) => NULL (no migration; strict default stands).
 *   - populated config lacking the key (existing install) => key set to 'on'.
 *   - populated config already carrying the key => NULL (never overwritten), for both
 *     'on' and 'off'.
 */
#[CoversFunction('pfb_dnsbl_lenient_migrate')]
final class PfbDnsblLenientMigrateTest extends TestCase
{
	public function testMigrationSkipsFreshInstall(): void
	{
		// Given a first-ever install: no prior DNSBL config section.
		// Before: nothing to migrate.
		$this->assertNull(pfb_dnsbl_lenient_migrate([]));
		$this->assertNull(pfb_dnsbl_lenient_migrate(null));
		// After: still nothing written -- the new-install strict default (OFF) stands.
		// (A NULL return means the install.inc block does not config_set_path/write_config,
		// so the key is never created and the unchecked checkbox = strict is preserved.)
	}

	public function testMigrationSetsLenientOnForExistingInstallMissingKey(): void
	{
		// Given an existing, already-configured install (a populated section) that predates
		// the key.
		$dconfig = ['pfb_dnsbl' => 'on', 'pfb_hsts' => 'on'];
		// Before: the key is absent.
		$this->assertArrayNotHasKey('pfb_dnsbl_lenient', $dconfig);

		// When the one-time migration runs.
		$out = pfb_dnsbl_lenient_migrate($dconfig);

		// Then it is set to 'on' (lenient) -- the permissive behaviour is preserved.
		$this->assertIsArray($out);
		$this->assertSame('on', $out['pfb_dnsbl_lenient']);
		// And the rest of the section is carried through untouched.
		$this->assertSame('on', $out['pfb_dnsbl']);
		$this->assertSame('on', $out['pfb_hsts']);
	}

	public function testMigrationDoesNotOverwriteExistingValue(): void
	{
		// Given an existing install where the operator already chose strict ('off').
		$dconfig = ['pfb_dnsbl' => 'on', 'pfb_dnsbl_lenient' => 'off'];
		// Before: value is 'off'.
		$this->assertSame('off', $dconfig['pfb_dnsbl_lenient']);

		// When the migration runs.
		$out = pfb_dnsbl_lenient_migrate($dconfig);

		// Then nothing changes (NULL = no write) -- the chosen value is never overwritten.
		$this->assertNull($out);
	}

	public function testMigrationDoesNotOverwriteExistingOnValue(): void
	{
		// A box already carrying 'on' is likewise left alone (run-once, idempotent).
		$out = pfb_dnsbl_lenient_migrate(['pfb_dnsbl' => 'on', 'pfb_dnsbl_lenient' => 'on']);
		$this->assertNull($out);
	}
}
