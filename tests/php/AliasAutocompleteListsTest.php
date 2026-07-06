<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_alias_autocomplete_lists() — the Custom Source/Destination/Port
 * autocomplete + save-time option-validation map builder shared by the IP,
 * DNSBL, and Feed (category-edit) settings pages.
 *
 * Two bugs this pins:
 *
 *   Bug A — the old per-page loops collected ONLY 'network'-type aliases for
 *   the address list, excluding 'host' (single-IP), 'url', and 'urltable'
 *   aliases. A Host alias — the common case — never appeared in the "Custom
 *   Source"/"Custom Destination" autocomplete dropdown on any of the three
 *   pages.
 *
 *   Bug B — the DNSBL page built its address/port option arrays as
 *   explode(',', $csv) — a VALUE list with numeric keys — while the save
 *   validator checks array_key_exists($_POST[$field], $options_...). Against
 *   a numeric-keyed array that is always FALSE, so every submitted Custom
 *   field was silently reset to '' on save. The fix returns NAME-KEYED
 *   (name => name) maps so array_key_exists() works.
 */
#[CoversFunction('pfb_alias_autocomplete_lists')]
final class AliasAutocompleteListsTest extends TestCase
{
	public function testAddressListIncludesEveryAddressBearingTypeNameKeyedExcludingManagedAndPorts(): void
	{
		// Given a mix of alias types, including a pfB_-managed one and an empty name
		$aliases = [
			['name' => 'H',           'type' => 'host'],
			['name' => 'N',           'type' => 'network'],
			['name' => 'U',           'type' => 'url'],
			['name' => 'UT',          'type' => 'urltable'],
			['name' => 'P1',          'type' => 'port'],
			['name' => 'P2',          'type' => 'port'],
			['name' => 'pfB_Managed', 'type' => 'urltable'],
			['name' => '',            'type' => 'network'],
		];

		// When the autocomplete maps are built
		$r = pfb_alias_autocomplete_lists($aliases);

		// Then every address-bearing type is present and NAME-KEYED — this is the
		// Bug A + Bug B fix: a Host alias ('H') is now offered AND
		// array_key_exists('H', $r['networks']) works (the old explode()-built,
		// network-only list failed BOTH: it excluded 'H' entirely, and even a
		// present name was reachable only by value, never by key).
		$this->assertTrue(array_key_exists('H', $r['networks']),
			'a Host alias must be a key in the address map (old network-only + explode() logic failed this)');
		$this->assertSame('H', $r['networks']['H']);
		$this->assertArrayHasKey('N', $r['networks']);
		$this->assertSame('N', $r['networks']['N']);
		$this->assertArrayHasKey('U', $r['networks']);
		$this->assertArrayHasKey('UT', $r['networks']);

		// Managed (pfB_*), port, and empty-name entries are excluded from the address map
		$this->assertArrayNotHasKey('pfB_Managed', $r['networks']);
		$this->assertArrayNotHasKey('P1', $r['networks']);
		$this->assertArrayNotHasKey('P2', $r['networks']);
		$this->assertArrayNotHasKey('', $r['networks']);
	}

	public function testPortListIsNameKeyedAndExcludesAddressesAndManagedAliases(): void
	{
		// Given the same mixed input
		$aliases = [
			['name' => 'H',           'type' => 'host'],
			['name' => 'N',           'type' => 'network'],
			['name' => 'U',           'type' => 'url'],
			['name' => 'UT',          'type' => 'urltable'],
			['name' => 'P1',          'type' => 'port'],
			['name' => 'P2',          'type' => 'port'],
			['name' => 'pfB_Managed', 'type' => 'urltable'],
			['name' => '',            'type' => 'network'],
		];

		// When built
		$r = pfb_alias_autocomplete_lists($aliases);

		// Then the port map is exactly the name-keyed port aliases
		$this->assertSame(['P1' => 'P1', 'P2' => 'P2'], $r['ports']);
		$this->assertArrayNotHasKey('H', $r['ports']);
		$this->assertArrayNotHasKey('pfB_Managed', $r['ports']);
	}
}
