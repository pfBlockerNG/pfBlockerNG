<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_keep_migrate() -- the one-time upgrade seed for the 'pfb_keep'
 * General-settings flag (issue #281).
 *
 * Scenario: preserve user settings across pkg upgrade.
 *   Background: $gconfig is the existing General 'config/0' node.
 *     - The pre-deinstall hook wipes ALL pfBlockerNG config sections unless
 *       pfb_keep == 'on'. The GUI default is 'on' but it only persists to
 *       config.xml once General settings are saved.
 *     - On an EXISTING install (a populated section) that predates the key,
 *       seed it to 'on' so a later pkg upgrade's pre-deinstall is safe.
 *     - A fresh install has no prior section -> NULL (no write); pfb_global()
 *       covers it with ?? 'on'.
 *     - An existing value (including an explicit '' = off) is NEVER overwritten.
 *
 * Contract:
 *   - empty/non-array config (fresh install) => NULL (no migration; runtime default stands).
 *   - populated config lacking the key (existing install) => key seeded to 'on'.
 *   - populated config with explicit '' (user chose off) => NULL (never overwritten).
 *   - populated config already carrying 'on' => NULL (idempotent, never re-seeds).
 */
#[CoversFunction('pfb_keep_migrate')]
final class PfbKeepMigrateTest extends TestCase
{
	public function testMigrationSkipsFreshInstall(): void
	{
		// Given a first-ever install: no prior General config section.
		// Before: nothing to migrate.
		$this->assertNull(pfb_keep_migrate([]));
		$this->assertNull(pfb_keep_migrate(null));
		// After: still nothing written -- the pfb_global() runtime default ('on') stands.
		// (A NULL return means the install.inc block does not config_set_path/write_config,
		// so the key is never created; pfb_global() fills it with ?? 'on' at runtime.)
	}

	public function testMigrationSeedsOnForExistingInstallMissingKey(): void
	{
		// Given an existing, already-configured install (a populated section) that predates
		// the key.
		$gconfig = ['enable_cb' => 'on', 'pfb_interval' => '1'];
		// Before: the key is absent.
		$this->assertArrayNotHasKey('pfb_keep', $gconfig);

		// When the one-time migration runs.
		$out = pfb_keep_migrate($gconfig);

		// Then it is seeded to 'on' -- the safe upgrade default is preserved.
		$this->assertIsArray($out);
		$this->assertSame('on', $out['pfb_keep']);
		// And the rest of the section is carried through untouched.
		$this->assertSame('on', $out['enable_cb']);
		$this->assertSame('1', $out['pfb_interval']);
	}

	public function testMigrationDoesNotOverwriteExplicitOffValue(): void
	{
		// Given an existing install where the operator explicitly chose off ('').
		// This is the critical branch: '' means the user WANTS to lose settings on
		// disable/upgrade -- their deliberate choice must never be overwritten.
		$gconfig = ['enable_cb' => 'on', 'pfb_keep' => ''];
		// Before: value is '' (explicit off).
		$this->assertSame('', $gconfig['pfb_keep']);

		// When the migration runs.
		$out = pfb_keep_migrate($gconfig);

		// Then nothing changes (NULL = no write) -- the chosen value is never overwritten.
		$this->assertNull($out);
	}

	public function testMigrationDoesNotOverwriteExistingOnValue(): void
	{
		// A box already carrying 'on' is likewise left alone (run-once, idempotent).
		$gconfig = ['enable_cb' => 'on', 'pfb_keep' => 'on'];
		// Before: value is already 'on'.
		$this->assertSame('on', $gconfig['pfb_keep']);

		// When the migration runs.
		$out = pfb_keep_migrate($gconfig);

		// Then nothing changes -- no redundant re-seed.
		$this->assertNull($out);
	}
}
