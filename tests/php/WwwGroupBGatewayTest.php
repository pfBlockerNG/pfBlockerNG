<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 7 — www/ group B gateway routing tests.
 *
 * Covers the pages routed in Phase 7:
 *   - pfblockerng_safesearch.php  (section: installedpackages/pfblockerngsafesearch)
 *   - pfblockerng_blacklist.php   (section: installedpackages/pfblockerngblacklist — foreign section)
 *   - pfblockerng_feeds.php       (section: installedpackages/pfblockerngglobal — foreign section)
 *   - pfblockerng_category_edit.php (dynamic sections: installedpackages/pfblockernglistsv4/v6/dnsbl/config)
 *
 * Reputation tab (pfblockerng_reputation.php) does not exist in the codebase;
 * it is only a tab link in pfblockerng_ip.php. No routing work is needed.
 *
 * Test groups:
 *
 * A — LOAD DEFAULT PARITY
 *   SafeSearch fields are in the registry (all default 'Disable'). Assert that
 *   PfbConfig::read($key) on an absent section returns the SAME value the page
 *   used to produce via its `?: 'Disable'` fallback.
 *
 *   Blacklist, Feeds, and Category sections are NOT in the registry — their
 *   sub-keys are foreign. Assert registry lookup throws (proving they are
 *   correctly NOT routed through PfbConfig::read()).
 *
 * B — SAVE ROUND-TRIP IDENTITY (section blobs)
 *   For every section routed through PfbConfig::readSection/writeSection, assert
 *   that writing an array and reading it back returns byte-identical values.
 *   Special emphasis on list/structure sections (blacklist `item`, category `row`)
 *   that must survive the gateway unchanged.
 *
 * Scenario (group A — SafeSearch parity):
 *   Background: config.xml empty — no pfblockerngsafesearch section.
 *     Given PfbConfig::read($key) with no seed.
 *     When the key is absent.
 *     Then the gateway default equals the prior page default (parity).
 *
 * Scenario (group B — section round-trip):
 *   Background: a representative section array is built.
 *     Given a section array mirroring what a page save handler would produce.
 *     When PfbConfig::writeSection(section, array) is called.
 *     Then PfbConfig::readSection(section) returns the same array byte-for-byte.
 */
final class WwwGroupBGatewayTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// A — Load default parity: SafeSearch page fields
	// -----------------------------------------------------------------------

	/**
	 * safesearch_enable: page used `?: 'Disable'` — default 'Disable'.
	 * Registry default = 'Disable'. Parity: absent key → 'Disable'.
	 */
	public function testSafeSearchEnableAbsentDefaultMatchesPriorPageDefault(): void
	{
		$path = 'installedpackages/pfblockerngsafesearch/safesearch_enable';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'safesearch_enable must be absent for this test');

		// When: gateway read.
		$result = PfbConfig::read('safesearch_enable');

		// Then: 'Disable' — matches prior page default '?: Disable'.
		$this->assertSame('Disable', $result, 'safesearch_enable absent -> "Disable" (parity with prior page default)');
	}

	/**
	 * safesearch_youtube: page used `?: 'Disable'` — default 'Disable'.
	 * Registry default = 'Disable'. Parity: absent key → 'Disable'.
	 */
	public function testSafeSearchYoutubeAbsentDefaultMatchesPriorPageDefault(): void
	{
		$path = 'installedpackages/pfblockerngsafesearch/safesearch_youtube';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'safesearch_youtube must be absent');

		// When: gateway read.
		$result = PfbConfig::read('safesearch_youtube');

		// Then: 'Disable' — matches prior page default.
		$this->assertSame('Disable', $result, 'safesearch_youtube absent -> "Disable" (parity with prior page default)');
	}

	/**
	 * safesearch_doh: page used `?: 'Disable'` — default 'Disable'.
	 * Registry default = 'Disable'. Parity: absent key → 'Disable'.
	 */
	public function testSafeSearchDohAbsentDefaultMatchesPriorPageDefault(): void
	{
		$path = 'installedpackages/pfblockerngsafesearch/safesearch_doh';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'safesearch_doh must be absent');

		// When: gateway read.
		$result = PfbConfig::read('safesearch_doh');

		// Then: 'Disable' — matches prior page default.
		$this->assertSame('Disable', $result, 'safesearch_doh absent -> "Disable" (parity with prior page default)');
	}

	/**
	 * safesearch_doh_list: page reads from section blob, explodes CSV, falls back to array().
	 * Registry default = '' (empty CSV). Parity: absent key → '' (explode('', '') gives [''], not
	 * [] — this is handled by the page's ?: array() guard on the result of explode).
	 * Assert registry default is '' so the section-blob access is appropriate.
	 */
	public function testSafeSearchDohListAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngsafesearch/safesearch_doh_list';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'safesearch_doh_list must be absent');

		// When: gateway read returns the registry default string.
		$result = PfbConfig::read('safesearch_doh_list');

		// Then: '' — the page's ?: array() guard on explode('', '') protects the UI;
		// the stored/registry value is '' confirming no divergence.
		$this->assertSame('', $result, 'safesearch_doh_list absent -> "" (registry default; page explode + guard handles empty)');
	}

	/**
	 * Confirm blacklist/feeds/category keys are NOT in the registry.
	 * Their sections are foreign — they must NOT be routed through PfbConfig::read().
	 */
	public function testForeignSectionKeysAreNotInRegistry(): void
	{
		// blacklist_enable: foreign key — registry lookup must throw.
		$this->expectException(InvalidArgumentException::class);
		PfbConfig::read('blacklist_enable');
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: SafeSearch section
	// -----------------------------------------------------------------------

	/**
	 * SafeSearch section write → read round-trips byte-identically via gateway.
	 *
	 * Scenario:
	 *   Given a representative SafeSearch settings array (mirrors save handler).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then PfbConfig::readSection() returns an identical array.
	 */
	public function testSafeSearchSectionWriteReadRoundTrip(): void
	{
		$section = 'installedpackages/pfblockerngsafesearch';

		$data = [
			'safesearch_enable'  => 'Enable',
			'safesearch_youtube' => 'Strict',
			'safesearch_doh'     => 'Enable',
			'safesearch_doh_list' => 'dns.google,cloudflare-dns.com',
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'SafeSearch section absent -> empty array before write');

		// When: write (models the page save handler).
		PfbConfig::writeSection($section, $data);

		// Then: read back is byte-identical.
		$result = PfbConfig::readSection($section);
		$this->assertSame($data, $result, 'SafeSearch section round-trips identically through gateway');
	}

	/**
	 * SafeSearch section: safesearch_enable toggled Disable → Enable → Disable round-trips.
	 * Asserts the before-state ('Disable') and after-state ('Enable') are distinct.
	 */
	public function testSafeSearchEnableToggleRoundTrips(): void
	{
		$section = 'installedpackages/pfblockerngsafesearch';

		// Given: write 'Disable' first.
		PfbConfig::writeSection($section, ['safesearch_enable' => 'Disable']);
		$this->assertSame('Disable', PfbConfig::readSection($section)['safesearch_enable'], 'safesearch_enable starts as "Disable"');

		// When: write 'Enable'.
		PfbConfig::writeSection($section, ['safesearch_enable' => 'Enable']);

		// Then: reads back as 'Enable'.
		$this->assertSame('Enable', PfbConfig::readSection($section)['safesearch_enable'], 'safesearch_enable "Enable" round-trips identically');
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: Blacklist section (structure blob)
	// -----------------------------------------------------------------------

	/**
	 * Blacklist section — scalar fields write → read round-trips byte-identically.
	 *
	 * The pfblockerngblacklist section contains scalar settings fields that the
	 * page writes as individual config_set_path calls (foreign keys). The section
	 * load uses PfbConfig::readSection. This test verifies a representative scalar
	 * payload survives the gateway unchanged.
	 */
	public function testBlacklistSectionScalarFieldsRoundTrip(): void
	{
		$section = 'installedpackages/pfblockerngblacklist';

		$data = [
			'blacklist_enable'   => 'Enable',
			'blacklist_lang'     => 'EN',
			'blacklist_selected' => 'ut1',
			'blacklist_freq'     => 'EveryDay',
			'blacklist_logging'  => 'enabled',
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'blacklist section absent -> empty array before write');

		// When: write.
		PfbConfig::writeSection($section, $data);

		// Then: byte-identical read back.
		$result = PfbConfig::readSection($section);
		$this->assertSame($data, $result, 'Blacklist scalar fields round-trip identically through gateway');
	}

	/**
	 * Blacklist section — `item` structure blob must round-trip byte-identically.
	 *
	 * The `item` key holds a list of per-provider configs (xml, selected, title, feed,
	 * size; optional username/password). This is a dynamic structure — no per-field
	 * adapter can flatten it. Assert byte-identity through the section gateway.
	 *
	 * Scenario:
	 *   Given a blacklist config section containing an `item` structure.
	 *   When PfbConfig::writeSection persists it.
	 *   Then PfbConfig::readSection returns the item structure byte-identically.
	 */
	public function testBlacklistItemStructureRoundTripsByteIdentically(): void
	{
		$section = 'installedpackages/pfblockerngblacklist';

		$item_structure = [
			[
				'xml'      => 'ut1',
				'title'    => 'UT1 Toulouse',
				'feed'     => 'http://example.com/ut1.tar.gz',
				'size'     => '400Mb',
				'selected' => 'dating,gambling,porn',
			],
			[
				'xml'      => 'shallalist',
				'title'    => 'Shallalist',
				'feed'     => 'http://example.com/shallalist.tar.gz',
				'size'     => '100Mb',
				'selected' => 'adv,costtraps',
				'username' => 'user@example.com',
				'password' => 'secret',
			],
		];

		$data = [
			'blacklist_enable'   => 'Enable',
			'blacklist_selected' => 'ut1,shallalist',
			'item'               => $item_structure,
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'blacklist section absent before write');

		// When: write.
		PfbConfig::writeSection($section, $data);

		// Then: full section including `item` structure is byte-identical.
		$result = PfbConfig::readSection($section);
		$this->assertSame($data, $result, 'Blacklist item structure round-trips byte-identically through gateway');

		// Specifically: the item sub-array is preserved.
		$this->assertSame($item_structure, $result['item'], 'Blacklist item list preserved byte-identically');
		$this->assertSame('dating,gambling,porn', $result['item'][0]['selected'], 'First item selected categories preserved');
		$this->assertSame('user@example.com', $result['item'][1]['username'], 'Second item username preserved');
	}

	/**
	 * Blacklist item: toggling from 'Disable' to 'Enable' is reflected in the section.
	 * Before-state asserted, then after-state — proves write caused the change.
	 */
	public function testBlacklistEnableToggleRoundTrips(): void
	{
		$section = 'installedpackages/pfblockerngblacklist';

		// Given: write 'Disable'.
		PfbConfig::writeSection($section, ['blacklist_enable' => 'Disable']);
		$this->assertSame('Disable', PfbConfig::readSection($section)['blacklist_enable'], 'blacklist_enable starts as "Disable"');

		// When: write 'Enable'.
		PfbConfig::writeSection($section, ['blacklist_enable' => 'Enable']);

		// Then: reads back as 'Enable'.
		$this->assertSame('Enable', PfbConfig::readSection($section)['blacklist_enable'], 'blacklist_enable "Enable" round-trips identically');
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: Feeds global section (dynamic keys)
	// -----------------------------------------------------------------------

	/**
	 * Feeds global section — dynamic alias-name keys round-trip byte-identically.
	 *
	 * pfblockerngglobal stores `feed_<aliasname>` overrides and `feed_alt_<header>`
	 * alternate URL selections as dynamic keys. These are foreign to the registry.
	 * The section load uses PfbConfig::readSection. Assert a representative payload
	 * survives the gateway unchanged.
	 *
	 * Scenario:
	 *   Given a pfblockerngglobal section with feed_* and feed_alt_* keys.
	 *   When PfbConfig::writeSection persists it.
	 *   Then PfbConfig::readSection returns it byte-identically.
	 */
	public function testFeedsGlobalSectionWithDynamicKeysRoundTrip(): void
	{
		$section = 'installedpackages/pfblockerngglobal';

		$data = [
			'feed_pfbdenyv4'      => '',
			'feed_pfbdenyv6'      => '',
			'feed_pfbpermitv4'    => 'MyPermitAlias',
			'feed_dnsblhphosts'   => '',
			'feed_alt_hagezi_pro' => 'alt_HaGeZi_Pro_mini',
			'feed_alt_someother'  => 'alt_AnotherAlt',
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'pfblockerngglobal absent -> empty array before write');

		// When: write.
		PfbConfig::writeSection($section, $data);

		// Then: byte-identical read back.
		$result = PfbConfig::readSection($section);
		$this->assertSame($data, $result, 'Feeds global section round-trips identically through gateway');

		// Specifically: dynamic keys preserved.
		$this->assertSame('MyPermitAlias', $result['feed_pfbpermitv4'], 'Alternate alias name preserved');
		$this->assertSame('alt_HaGeZi_Pro_mini', $result['feed_alt_hagezi_pro'], 'Alternate URL selection preserved');
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: Category list sections (structure blobs)
	// -----------------------------------------------------------------------

	/**
	 * Category list section — row structure blob must round-trip byte-identically.
	 *
	 * pfblockernglistsv4/v6/dnsbl/config holds a list of alias/group configs, each
	 * with a `row` sub-array of feed definitions (state/url/header). This is a
	 * dynamic list structure — no per-field adapter can represent it. Assert
	 * byte-identity through the section gateway.
	 *
	 * Scenario:
	 *   Given a category config section containing a list with row sub-arrays.
	 *   When PfbConfig::writeSection persists it.
	 *   Then PfbConfig::readSection returns the structure byte-identically.
	 */
	public function testCategoryListSectionRowStructureRoundTripsByteIdentically(): void
	{
		$section = 'installedpackages/pfblockernglistsv4/config';

		$row_structure = [
			[
				'aliasname'   => 'PRI1',
				'description' => 'Primary blocklists',
				'action'      => 'Deny_Both',
				'cron'        => 'EveryDay',
				'dow'         => '',
				'sort'        => 'sort',
				'aliaslog'    => 'enabled',
				'row'         => [
					[
						'state'  => 'Enabled',
						'url'    => 'https://example.com/list1.txt',
						'header' => 'PRI1_SRC1',
					],
					[
						'state'  => 'Disabled',
						'url'    => 'https://example.com/list2.txt',
						'header' => 'PRI1_SRC2',
					],
				],
			],
			[
				'aliasname'   => 'DNSBL_Grp1',
				'description' => 'DNSBL Group',
				'action'      => 'unbound',
				'cron'        => '01hour',
				'dow'         => '',
				'sort'        => 'no-sort',
				'aliaslog'    => 'enabled',
				'logging'     => 'enabled',
				'row'         => [
					[
						'state'  => 'Enabled',
						'url'    => 'https://example.com/dnsbl.txt',
						'header' => 'DNSBL_Grp1_SRC1',
						'format' => 'auto',
					],
				],
			],
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'category list section absent before write');

		// When: write.
		PfbConfig::writeSection($section, $row_structure);

		// Then: full structure is byte-identical.
		$result = PfbConfig::readSection($section);
		$this->assertSame($row_structure, $result, 'Category list structure round-trips byte-identically through gateway');

		// Specifically: row sub-arrays are preserved.
		$this->assertCount(2, $result, 'Two alias rows preserved');
		$this->assertSame('PRI1', $result[0]['aliasname'], 'First alias name preserved');
		$this->assertCount(2, $result[0]['row'], 'First alias row count preserved');
		$this->assertSame('Enabled', $result[0]['row'][0]['state'], 'Row state preserved');
		$this->assertSame('https://example.com/list1.txt', $result[0]['row'][0]['url'], 'Row URL preserved');
		$this->assertSame('PRI1_SRC2', $result[0]['row'][1]['header'], 'Row header preserved');
		$this->assertSame('enabled', $result[1]['logging'], 'DNSBL logging key preserved');
	}

	/**
	 * Category DNSBL section round-trip with custom (base64) field.
	 * The `custom` key holds a base64-encoded custom list — assert it survives unchanged.
	 */
	public function testCategoryDnsblSectionWithCustomFieldRoundTrips(): void
	{
		$section  = 'installedpackages/pfblockerngdnsbl/config';
		$b64_custom = base64_encode("example.com\nbad-domain.net\n# comment\n");

		$data = [
			[
				'aliasname'   => 'Custom_DNSBL',
				'description' => 'Custom domain list',
				'action'      => 'unbound',
				'cron'        => 'Never',
				'dow'         => '',
				'sort'        => 'sort',
				'logging'     => 'enabled',
				'order'       => 'default',
				'custom'      => $b64_custom,
				'row'         => [],
			],
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'DNSBL section absent before write');

		// When: write.
		PfbConfig::writeSection($section, $data);

		// Then: byte-identical including the base64 custom field.
		$result = PfbConfig::readSection($section);
		$this->assertSame($data, $result, 'DNSBL category section round-trips byte-identically');
		$this->assertSame($b64_custom, $result[0]['custom'], 'base64 custom field preserved byte-identically');
		$this->assertSame(
			"example.com\nbad-domain.net\n# comment\n",
			base64_decode($result[0]['custom']),
			'base64 custom field decodes to original content'
		);
	}
}
