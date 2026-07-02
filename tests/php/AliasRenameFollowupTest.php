<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_alias_rename_followup() (issue #357) and
 * pfb_alias_field_type_ok() (issue #356).
 *
 * pfb_alias_rename_followup():
 *   Rewrites the four per-row Advanced Inbound/Outbound alias keys
 *   (aliasports_in / aliasports_out / aliasaddr_in / aliasaddr_out) across
 *   the three pfBlockerNG list sections when a firewall alias is renamed.
 *   Operates via the PfbConfig section gateway; does NOT call write_config().
 *   Returns TRUE when at least one key changed, FALSE otherwise.
 *
 * pfb_alias_field_type_ok():
 *   Port fields (aliasports_*) require a 'port' alias.
 *   Address fields (aliasaddr_*) require a 'network' or 'host' alias.
 *   Unknown fields return FALSE (fail closed).
 */
#[CoversFunction('pfb_alias_rename_followup')]
#[CoversFunction('pfb_alias_field_type_ok')]
final class AliasRenameFollowupTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/**
	 * Seed a single row into one of the three list sections.
	 *
	 * @param string $section  'pfblockernglistsv4', 'pfblockernglistsv6', or 'pfblockerngdnsbl'.
	 * @param int    $idx      Row index.
	 * @param array  $row      Row data (partial; only the keys you provide are set).
	 */
	private function seedRow(string $section, int $idx, array $row): void
	{
		$path = "installedpackages/{$section}/config/{$idx}";
		foreach ($row as $key => $value) {
			config_set_path("{$path}/{$key}", $value);
		}
	}

	/**
	 * Read a single key from a stored row.
	 */
	private function readRowKey(string $section, int $idx, string $key): mixed
	{
		return config_get_path("installedpackages/{$section}/config/{$idx}/{$key}");
	}

	// -----------------------------------------------------------------------
	// pfb_alias_rename_followup() — rename-follow tests
	// -----------------------------------------------------------------------

	/**
	 * A row in pfblockernglistsv4 with aliasaddr_in = 'OldAlias' is rewritten
	 * to 'NewAlias' after the rename, and the function returns TRUE.
	 *
	 * Before-and-after asserted so a regression (rename not applied) would
	 * fail on the post-call assertion, not silently pass.
	 */
	public function testSingleKeyInV4SectionIsRewrittenAndReturnsTrue(): void
	{
		// Given: one row in pfblockernglistsv4 with aliasaddr_in = 'OldAlias'.
		$this->seedRow('pfblockernglistsv4', 0, [
			'aliasname'    => 'MyFeed',
			'aliasaddr_in' => 'OldAlias',
		]);

		// Before: confirm the original value is present.
		$this->assertSame('OldAlias', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'Before rename: aliasaddr_in must be OldAlias');

		// When.
		$result = pfb_alias_rename_followup('OldAlias', 'NewAlias');

		// Then: value was rewritten and return is TRUE.
		$this->assertTrue($result, 'Should return TRUE when at least one key changed');
		$this->assertSame('NewAlias', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'After rename: aliasaddr_in must be NewAlias');
	}

	/**
	 * All four alias keys are rewritten across two sections when they all
	 * reference the old alias name.
	 *
	 * Covers every key path in the function and verifies cross-section handling.
	 */
	public function testAllFourKeysAcrossTwoSectionsAreRewritten(): void
	{
		// Given: a row in pfblockernglistsv4 with all four alias keys set.
		$this->seedRow('pfblockernglistsv4', 0, [
			'aliasports_in'  => 'OldPorts',
			'aliasports_out' => 'OldPorts',
			'aliasaddr_in'   => 'OldAlias',
			'aliasaddr_out'  => 'OldAlias',
		]);
		// And a row in pfblockerngdnsbl with two of the four keys.
		$this->seedRow('pfblockerngdnsbl', 0, [
			'aliasports_in' => 'OldPorts',
			'aliasaddr_in'  => 'OldAlias',
		]);

		// Before: confirm original values in both sections.
		$this->assertSame('OldPorts', $this->readRowKey('pfblockernglistsv4', 0, 'aliasports_in'),
			'Before: aliasports_in in v4 must be OldPorts');
		$this->assertSame('OldAlias', $this->readRowKey('pfblockerngdnsbl', 0, 'aliasaddr_in'),
			'Before: aliasaddr_in in dnsbl must be OldAlias');

		// When: rename OldPorts.
		$result_ports = pfb_alias_rename_followup('OldPorts', 'NewPorts');

		// Then: all OldPorts keys updated.
		$this->assertTrue($result_ports, 'Should return TRUE for OldPorts rename');
		$this->assertSame('NewPorts', $this->readRowKey('pfblockernglistsv4', 0, 'aliasports_in'),
			'After OldPorts rename: aliasports_in in v4 must be NewPorts');
		$this->assertSame('NewPorts', $this->readRowKey('pfblockernglistsv4', 0, 'aliasports_out'),
			'After OldPorts rename: aliasports_out in v4 must be NewPorts');
		$this->assertSame('NewPorts', $this->readRowKey('pfblockerngdnsbl', 0, 'aliasports_in'),
			'After OldPorts rename: aliasports_in in dnsbl must be NewPorts');

		// When: rename OldAlias.
		$result_addr = pfb_alias_rename_followup('OldAlias', 'NewAddr');

		// Then: all OldAlias keys updated.
		$this->assertTrue($result_addr, 'Should return TRUE for OldAlias rename');
		$this->assertSame('NewAddr', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'After OldAlias rename: aliasaddr_in in v4 must be NewAddr');
		$this->assertSame('NewAddr', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_out'),
			'After OldAlias rename: aliasaddr_out in v4 must be NewAddr');
		$this->assertSame('NewAddr', $this->readRowKey('pfblockerngdnsbl', 0, 'aliasaddr_in'),
			'After OldAlias rename: aliasaddr_in in dnsbl must be NewAddr');
	}

	/**
	 * A row referencing a DIFFERENT alias is left unchanged (targeted rewrite,
	 * not blanket replacement).
	 *
	 * Proves the function rewrites only the exact matching key value.
	 */
	public function testRowReferencingDifferentAliasIsNotTouched(): void
	{
		// Given: two rows — one references OldAlias, one references OtherAlias.
		$this->seedRow('pfblockernglistsv4', 0, ['aliasaddr_in' => 'OldAlias']);
		$this->seedRow('pfblockernglistsv4', 1, ['aliasaddr_in' => 'OtherAlias']);

		// Before: both values confirmed.
		$this->assertSame('OldAlias',   $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'));
		$this->assertSame('OtherAlias', $this->readRowKey('pfblockernglistsv4', 1, 'aliasaddr_in'));

		// When: rename OldAlias only.
		pfb_alias_rename_followup('OldAlias', 'NewAlias');

		// Then: row 0 updated, row 1 unchanged.
		$this->assertSame('NewAlias',   $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'Row referencing OldAlias must be updated');
		$this->assertSame('OtherAlias', $this->readRowKey('pfblockernglistsv4', 1, 'aliasaddr_in'),
			'Row referencing OtherAlias must be unchanged');
	}

	/**
	 * No-op: old_name === new_name — returns FALSE and changes nothing.
	 */
	public function testSameNameReturnsFalseAndChangesNothing(): void
	{
		$this->seedRow('pfblockernglistsv4', 0, ['aliasaddr_in' => 'SameAlias']);

		$result = pfb_alias_rename_followup('SameAlias', 'SameAlias');

		$this->assertFalse($result, 'old === new must return FALSE');
		$this->assertSame('SameAlias', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'Value must be unchanged when old === new');
	}

	/**
	 * No-op: empty old_name — returns FALSE immediately without touching config.
	 */
	public function testEmptyOldNameReturnsFalse(): void
	{
		$this->seedRow('pfblockernglistsv4', 0, ['aliasaddr_in' => 'SomeAlias']);

		$result = pfb_alias_rename_followup('', 'NewAlias');

		$this->assertFalse($result, 'Empty old_name must return FALSE');
		$this->assertSame('SomeAlias', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'Value must be unchanged when old_name is empty');
	}

	/**
	 * No-op: empty new_name — returns FALSE immediately without touching config.
	 */
	public function testEmptyNewNameReturnsFalse(): void
	{
		$this->seedRow('pfblockernglistsv4', 0, ['aliasaddr_in' => 'SomeAlias']);

		$result = pfb_alias_rename_followup('SomeAlias', '');

		$this->assertFalse($result, 'Empty new_name must return FALSE');
		$this->assertSame('SomeAlias', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'Value must be unchanged when new_name is empty');
	}

	/**
	 * No-op: old_name not present in any section — returns FALSE.
	 *
	 * Proves the function does not corrupt unrelated data when the alias name
	 * does not appear anywhere in the config.
	 */
	public function testAbsentOldNameReturnsFalse(): void
	{
		$this->seedRow('pfblockernglistsv4', 0, ['aliasaddr_in' => 'CompletelyDifferent']);

		// Before: confirm value.
		$this->assertSame('CompletelyDifferent', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'));

		$result = pfb_alias_rename_followup('NotPresentAnywhere', 'NewAlias');

		$this->assertFalse($result, 'Absent old_name must return FALSE');
		$this->assertSame('CompletelyDifferent', $this->readRowKey('pfblockernglistsv4', 0, 'aliasaddr_in'),
			'Unrelated value must be unchanged');
	}

	// -----------------------------------------------------------------------
	// #708 — single-config (config/0) sections: DNSBL settings + GeoIP tabs.
	// The DNSBL-settings tab and every GeoIP continent tab store the same four
	// alias keys on config/0 (not in a multi-row feed list). Pre-#708 the
	// follow-up skipped them, so after a rename the built DNSBL/GeoIP rule lost
	// its In/Out restriction. Each case seeds ONE such section and asserts the
	// rename propagates — red before the fix, green after, and every hardcoded
	// section name is exercised (a typo in the list fails its case).
	// -----------------------------------------------------------------------

	/**
	 * @return array<string, array{string}>
	 */
	public static function configZeroSections(): array
	{
		return [
			'DNSBL settings'      => ['pfblockerngdnsblsettings'],
			'Top Spammers'        => ['pfblockerngtopspammers'],
			'Africa'              => ['pfblockerngafrica'],
			'Antarctica'          => ['pfblockerngantarctica'],
			'Asia'                => ['pfblockerngasia'],
			'Europe'              => ['pfblockerngeurope'],
			'North America'       => ['pfblockerngnorthamerica'],
			'Oceania'             => ['pfblockerngoceania'],
			'South America'       => ['pfblockerngsouthamerica'],
			'Proxy and Satellite' => ['pfblockerngproxyandsatellite'],
		];
	}

	#[DataProvider('configZeroSections')]
	public function testConfigZeroSectionKeyIsRewritten(string $section): void
	{
		// Given: config/0 of this section references OldAlias on an address key.
		$this->seedRow($section, 0, [
			'aliasports_in' => 'OldPorts',
			'aliasaddr_out' => 'OldAlias',
		]);

		// Before.
		$this->assertSame('OldAlias', $this->readRowKey($section, 0, 'aliasaddr_out'),
			"Before rename: {$section} config/0 aliasaddr_out must be OldAlias");

		// When.
		$result = pfb_alias_rename_followup('OldAlias', 'NewAlias');

		// Then.
		$this->assertTrue($result, "Rewriting {$section} config/0 must return TRUE");
		$this->assertSame('NewAlias', $this->readRowKey($section, 0, 'aliasaddr_out'),
			"After rename: {$section} config/0 aliasaddr_out must be NewAlias");
		// The untouched key stays as seeded (targeted rewrite).
		$this->assertSame('OldPorts', $this->readRowKey($section, 0, 'aliasports_in'),
			"After rename: {$section} config/0 aliasports_in (unrelated) must be unchanged");
	}

	/**
	 * A config/0 section referencing a DIFFERENT alias is left untouched — the
	 * rewrite is targeted, and $changed stays FALSE when nothing matches.
	 */
	public function testConfigZeroSectionDifferentAliasIsNotTouched(): void
	{
		$this->seedRow('pfblockerngeurope', 0, ['aliasaddr_in' => 'KeepMe']);

		$this->assertSame('KeepMe', $this->readRowKey('pfblockerngeurope', 0, 'aliasaddr_in'));

		$result = pfb_alias_rename_followup('OldAlias', 'NewAlias');

		$this->assertFalse($result, 'No matching key anywhere must return FALSE');
		$this->assertSame('KeepMe', $this->readRowKey('pfblockerngeurope', 0, 'aliasaddr_in'),
			'A config/0 section referencing a different alias must be untouched');
	}

	// -----------------------------------------------------------------------
	// pfb_alias_field_type_ok() — per-field alias-type validation tests
	// -----------------------------------------------------------------------

	/**
	 * aliasports_in + 'port' → TRUE (port field accepts port alias).
	 */
	public function testPortsInFieldAcceptsPortType(): void
	{
		$this->assertTrue(pfb_alias_field_type_ok('aliasports_in', 'port'),
			'aliasports_in + port must be TRUE');
	}

	/**
	 * aliasports_out + 'port' → TRUE (port field accepts port alias).
	 */
	public function testPortsOutFieldAcceptsPortType(): void
	{
		$this->assertTrue(pfb_alias_field_type_ok('aliasports_out', 'port'),
			'aliasports_out + port must be TRUE');
	}

	/**
	 * aliasports_in + 'network' → FALSE (port field rejects network alias).
	 * aliasports_in + 'host' → FALSE (port field rejects host alias).
	 *
	 * Paired in one test so both sides of the type check are proven non-trivial.
	 */
	public function testPortsInFieldRejectsNetworkAndHostTypes(): void
	{
		$this->assertFalse(pfb_alias_field_type_ok('aliasports_in', 'network'),
			'aliasports_in + network must be FALSE');
		$this->assertFalse(pfb_alias_field_type_ok('aliasports_in', 'host'),
			'aliasports_in + host must be FALSE');
	}

	/**
	 * aliasports_out + 'network' → FALSE (port field rejects network alias).
	 * aliasports_out + 'host' → FALSE (port field rejects host alias).
	 */
	public function testPortsOutFieldRejectsNetworkAndHostTypes(): void
	{
		$this->assertFalse(pfb_alias_field_type_ok('aliasports_out', 'network'),
			'aliasports_out + network must be FALSE');
		$this->assertFalse(pfb_alias_field_type_ok('aliasports_out', 'host'),
			'aliasports_out + host must be FALSE');
	}

	/**
	 * aliasaddr_in + 'network' → TRUE (address field accepts network alias).
	 * aliasaddr_in + 'host' → TRUE (address field accepts host alias).
	 */
	public function testAddrInFieldAcceptsNetworkAndHostTypes(): void
	{
		$this->assertTrue(pfb_alias_field_type_ok('aliasaddr_in', 'network'),
			'aliasaddr_in + network must be TRUE');
		$this->assertTrue(pfb_alias_field_type_ok('aliasaddr_in', 'host'),
			'aliasaddr_in + host must be TRUE');
	}

	/**
	 * aliasaddr_out + 'network' → TRUE (address field accepts network alias).
	 * aliasaddr_out + 'host' → TRUE (address field accepts host alias).
	 */
	public function testAddrOutFieldAcceptsNetworkAndHostTypes(): void
	{
		$this->assertTrue(pfb_alias_field_type_ok('aliasaddr_out', 'network'),
			'aliasaddr_out + network must be TRUE');
		$this->assertTrue(pfb_alias_field_type_ok('aliasaddr_out', 'host'),
			'aliasaddr_out + host must be TRUE');
	}

	/**
	 * aliasaddr_in + 'port' → FALSE (address field rejects port alias).
	 * aliasaddr_out + 'port' → FALSE (address field rejects port alias).
	 *
	 * Paired so both address fields are shown to reject port aliases.
	 */
	public function testAddrFieldsRejectPortType(): void
	{
		$this->assertFalse(pfb_alias_field_type_ok('aliasaddr_in', 'port'),
			'aliasaddr_in + port must be FALSE');
		$this->assertFalse(pfb_alias_field_type_ok('aliasaddr_out', 'port'),
			'aliasaddr_out + port must be FALSE');
	}

	/**
	 * Unknown field name → FALSE (fail closed — no permissive default).
	 */
	public function testUnknownFieldReturnsFalse(): void
	{
		$this->assertFalse(pfb_alias_field_type_ok('unknown_field', 'port'),
			'Unknown field + port must be FALSE (fail closed)');
		$this->assertFalse(pfb_alias_field_type_ok('unknown_field', 'network'),
			'Unknown field + network must be FALSE (fail closed)');
		$this->assertFalse(pfb_alias_field_type_ok('', 'port'),
			'Empty field name must be FALSE (fail closed)');
	}
}
