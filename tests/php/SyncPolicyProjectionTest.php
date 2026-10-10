<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3450 — pfb_sync_policy_projection(): the ordered `installedpackages/<section>/...`
 * => leaf map of a node's policy content across the 19 synced sections
 * (docs/specs/xmlrpc-per-field-sync.md, "Policy projection").
 *
 * Settings sections (pfblockerng, pfblockerngipsettings, pfblockerngdnsblsettings) are an
 * allowlist driven by the registry 'sync' value; every other synced section is a deny list
 * (pfb_sync_local_paths()). The projection is pure and verbatim: normalising leaves for the
 * wire belongs to the manual builder (#3452), so nothing is cast or trimmed here.
 *
 * The disk-shaped fixture (SyncPolicyFixtureTrait) declares each leaf as policy or not where
 * it is created, so the whole-projection assertion is an independent oracle, not a replay of
 * the production classification.
 */
#[CoversFunction('pfb_sync_policy_projection')]
final class SyncPolicyProjectionTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private const SECTIONS_ROOT = 'installedpackages/';

	/** @return array<string,mixed> */
	private function project(array $sections): array
	{
		return $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_projection($sections));
	}

	// Guard: the fixture itself is shaped as the tests below assume.
	public function testFixtureCoversEverySectionAndBuildsPolicyInSyncOrder(): void
	{
		$fx = self::diskFixture();
		$this->assertSame(
			array_merge(pfblockerng_sync_sections(TRUE), ['pfblockerngsync', 'pfblockerngbogus']),
			array_keys($fx['sections']),
			'the fixture must hold all 19 synced sections, then pfblockerngsync and an unknown section'
		);

		$order = array_flip(pfblockerng_sync_sections(TRUE));
		$last  = -1;
		foreach (array_keys($fx['policy']) as $path) {
			$section = explode('/', $path)[1];
			$this->assertArrayHasKey($section, $order, "{$path} must sit in a synced section");
			$this->assertGreaterThanOrEqual($last, $order[$section], "{$path} breaks the expected section order");
			$last = $order[$section];
		}

		foreach (self::localRegistryKeys() as $key) {
			if (str_starts_with($key, 'gen/') || str_starts_with($key, 'ip/') || str_starts_with($key, 'dnsbl/')) {
				[$alias, $bare] = explode('/', $key, 2);
				$this->assertArrayHasKey(PFB_SECTIONS[$alias] . '/' . $bare, $fx['nonpolicy'],
					"fixture must carry the local key {$key}");
			}
		}
	}

	// B1 -- nothing local, credential, unknown, hook, retired, foreign or sync-owned is projected.
	public function testProjectionCarriesNoNonPolicyPathOrValue(): void
	{
		$fx = self::diskFixture();
		$this->assertNotEmpty($fx['nonpolicy'], 'vacuity guard: the fixture holds non-policy leaves');

		$projection = $this->project($fx['sections']);
		$this->assertNotEmpty($projection, 'vacuity guard: the fixture holds policy leaves');

		$this->assertSame([], array_values(array_intersect(array_keys($projection), array_keys($fx['nonpolicy']))),
			'no non-policy path may appear in the projection');

		$fixtureText = serialize($fx['sections']);
		$serialized  = serialize($projection);
		$encoded     = json_encode($projection, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
		foreach ($fx['nonpolicy'] as $path => $needle) {
			$this->assertStringContainsString($needle, $fixtureText, "vacuity guard: the fixture must hold the value of {$path}");
			$this->assertStringNotContainsString($needle, $serialized, "the value of {$path} leaked into serialize(projection)");
			$this->assertStringNotContainsString($needle, $encoded, "the value of {$path} leaked into json_encode(projection)");
		}
	}

	// B1 (positive side) -- the projection is exactly the policy leaves, in section then stored order.
	public function testProjectionOfTheFullFixtureIsExactlyItsPolicyLeaves(): void
	{
		$fx = self::diskFixture();

		$this->assertSame($fx['policy'], $this->project($fx['sections']));
	}

	// B2 -- a feed URL that embeds a provider key stays list policy and travels with its row.
	public function testFeedUrlEmbeddingAKeyStaysListPolicy(): void
	{
		$fx = self::diskFixture();
		$this->assertStringContainsString('key=EMBEDDED-POLICY-KEY', serialize($fx['sections']), 'vacuity guard');

		$projection = $this->project($fx['sections']);

		$this->assertArrayHasKey(self::EMBEDDED_KEY_PATH, $projection);
		$this->assertSame(self::EMBEDDED_KEY_VALUE, $projection[self::EMBEDDED_KEY_PATH]);
	}

	// B3 -- path format, section order, stored order and verbatim values, pinned exactly.
	public function testCompactFixtureProjectsToTheExactOrderedMap(): void
	{
		$input = [
			// Input order deliberately differs from sync order: pfblockerngsafesearch is last.
			'pfblockerngsafesearch' => ['safesearch_enable' => 'Google', 'safesearch_doh' => ' Block '],
			'pfblockerngdnsbl'      => ['config' => [
				1 => ['aliasname' => 'Second', 'srcint' => 'lan', 'row' => [0 => ['url' => 'https://b.example/f']]],
				0 => ['action' => 'Deny_Inbound', 'aliasname' => 'First'],
			]],
			'pfblockerng'           => ['config' => [0 => [
				'skipfeed'      => '3',
				'log_max_log'   => '9',
				'pfb_agg_types' => 'Deny,Permit',
				'zz_unknown'    => 'u',
			]]],
		];

		$this->assertSame([
			'installedpackages/pfblockerng/config/0/skipfeed'                 => '3',
			'installedpackages/pfblockerng/config/0/pfb_agg_types'            => 'Deny,Permit',
			'installedpackages/pfblockerngdnsbl/config/1/aliasname'           => 'Second',
			'installedpackages/pfblockerngdnsbl/config/1/row/0/url'           => 'https://b.example/f',
			'installedpackages/pfblockerngdnsbl/config/0/action'              => 'Deny_Inbound',
			'installedpackages/pfblockerngdnsbl/config/0/aliasname'           => 'First',
			'installedpackages/pfblockerngsafesearch/safesearch_enable'       => 'Google',
			'installedpackages/pfblockerngsafesearch/safesearch_doh'          => ' Block ',
		], $this->project($input));
	}

	// B4 -- a stored '' leaf is listed; an in-memory [] leaf is listed as []; NULL and absent are not.
	public function testEmptyLeavesAreListedAndNullOrAbsentKeysAreNot(): void
	{
		$input = [
			'pfblockerng'           => ['config' => [0 => [
				'skipfeed'      => '',
				'pfb_agg_types' => [],
				'pfb_quiet_hours' => NULL,
			]]],
			'pfblockerngsafesearch' => ['safesearch_enable' => [], 'safesearch_doh' => NULL, 'safesearch_youtube' => ''],
		];

		$this->assertSame([
			'installedpackages/pfblockerng/config/0/skipfeed'                  => '',
			'installedpackages/pfblockerng/config/0/pfb_agg_types'             => [],
			'installedpackages/pfblockerngsafesearch/safesearch_enable'        => [],
			'installedpackages/pfblockerngsafesearch/safesearch_youtube'       => '',
		], $this->project($input));
	}

	// B5 -- row indices and row order are preserved by the path, gaps included.
	public function testRowIndicesAndOrderArePreserved(): void
	{
		$input = [
			'pfblockernglistsv4' => ['config' => [
				1    => ['aliasname' => 'one'],
				0    => ['aliasname' => 'zero'],
				'01' => ['aliasname' => 'zero-one'],
			]],
			'pfblockernglistsv6' => ['config' => [
				0 => ['aliasname' => 'first'],
				2 => ['aliasname' => 'third'],
			]],
			'pfblockerngdnsbl' => ['config' => ['0' => ['aliasname' => 'string-numeric']]],
		];

		$this->assertSame([
			'installedpackages/pfblockernglistsv4/config/1/aliasname'  => 'one',
			'installedpackages/pfblockernglistsv4/config/0/aliasname'  => 'zero',
			'installedpackages/pfblockernglistsv4/config/01/aliasname' => 'zero-one',
			'installedpackages/pfblockernglistsv6/config/0/aliasname'  => 'first',
			'installedpackages/pfblockernglistsv6/config/2/aliasname'  => 'third',
			'installedpackages/pfblockerngdnsbl/config/0/aliasname'    => 'string-numeric',
		], $this->project($input));
	}

	// B6 -- Blacklist provider rows travel without their credentials, for every item index.
	public function testBlacklistItemsProjectWithoutUsernameAndPassword(): void
	{
		$fx         = self::diskFixture();
		$projection = $this->project($fx['sections']);
		$bl         = 'installedpackages/pfblockerngblacklist';

		foreach (['blacklist_enable', 'blacklist_freq', 'blacklist_lang', 'blacklist_logging', 'blacklist_selected'] as $leaf) {
			$this->assertSame("POLICY<blacklist.{$leaf}>", $projection["{$bl}/{$leaf}"] ?? NULL, "flat key {$leaf} is policy");
		}
		foreach (array_keys(self::blacklistCredentials()) as $n) {
			foreach (['title', 'xml', 'feed', 'size', 'selected'] as $leaf) {
				$this->assertSame("POLICY<blacklist.item{$n}.{$leaf}>", $projection["{$bl}/item/{$n}/{$leaf}"] ?? NULL,
					"item {$n} {$leaf} is policy");
			}
			$this->assertArrayNotHasKey("{$bl}/item/{$n}/username", $projection, "item {$n} username is a credential");
			$this->assertArrayNotHasKey("{$bl}/item/{$n}/password", $projection, "item {$n} password is a credential");
		}
	}

	// A row-local key name is local only inside a group's `config/<N>` rows, not at the same depth elsewhere.
	public function testRowLocalKeyNameOutsideGroupRowsStaysPolicy(): void
	{
		$this->assertSame(
			['installedpackages/pfblockerngblacklist/item/0/srcint' => 'lan'],
			$this->project(['pfblockerngblacklist' => ['item' => [['srcint' => 'lan']]]])
		);
	}

	// The legacy `infolists` tag is deleted by the category editor and is row-local, subtree included.
	public function testLegacyInfolistsSubtreeInGroupRowsIsNotProjected(): void
	{
		$this->assertSame(
			['installedpackages/pfblockerngafrica/config/0/action' => 'Deny_Inbound'],
			$this->project(['pfblockerngafrica' => ['config' => [0 => ['action' => 'Deny_Inbound', 'infolists' => ['row' => [0 => ['x' => '1']]]]]]])
		);
	}

	// B7 -- in pfblockerngglobal only feed_* (which includes feed_alt_*) is policy.
	public function testGlobalSectionProjectsOnlyFeedPrefixedKeys(): void
	{
		$input = ['pfblockerngglobal' => [
			'alertrefresh'       => 'on',
			'feed_Foo'           => 'a',
			'widget-pfblockerng' => 'b',
			'feed_alt_Foo'       => 'c',
			'pfbextdns'          => 'd',
			'feed'               => 'no underscore',
			'xfeed_Foo'          => 'not a prefix match',
			'Feed_Foo'           => 'case differs',
			'feed_Nested'        => ['k' => '1'],
		]];

		$this->assertSame([
			'installedpackages/pfblockerngglobal/feed_Foo'      => 'a',
			'installedpackages/pfblockerngglobal/feed_alt_Foo'  => 'c',
			'installedpackages/pfblockerngglobal/feed_Nested/k' => '1',
		], $this->project($input));
	}

	// B8 -- the settings allowlist follows the registry class, nothing else.
	public function testSettingsAllowlistFollowsTheRegistryClass(): void
	{
		$registry = pfb_cfg_registry();
		$this->assertSame('policy', $registry['gen/skipfeed']['sync'] ?? NULL, 'before-state: skipfeed is registered policy');
		$this->assertSame('local', $registry['gen/log_max_log']['sync'] ?? NULL, 'before-state: log_max_log is registered local');
		$this->assertArrayNotHasKey('gen/zz_unregistered', $registry, 'before-state: the third key is unregistered');

		$input = ['pfblockerng' => [
			'config'      => [
				0 => ['skipfeed' => 'in-0', 'log_max_log' => 'local', 'zz_unregistered' => 'unknown'],
				1 => ['skipfeed' => 'other-index'],
				'skipfeed' => 'section-level',
			],
			'skipfeed'    => 'outside-config',
			'hooks'       => ['row' => [0 => ['script' => 'x']]],
		]];

		$this->assertSame(
			['installedpackages/pfblockerng/config/0/skipfeed' => 'in-0'],
			$this->project($input)
		);

		// The registry class, not the section alias, decides: the DNSBL and IP sections follow it too.
		$this->assertSame('policy', $registry['dnsbl/pfb_hsts']['sync'] ?? NULL);
		$this->assertSame('local', $registry['dnsbl/pfb_dnsport']['sync'] ?? NULL);
		$this->assertSame('policy', $registry['ip/enable_dup']['sync'] ?? NULL);
		$this->assertSame('local', $registry['ip/enable_rdns']['sync'] ?? NULL);
		$this->assertSame([
			'installedpackages/pfblockerngipsettings/config/0/enable_dup'  => 'on',
			'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts' => 'on',
		], $this->project([
			'pfblockerngipsettings'    => ['config' => [0 => ['enable_rdns' => 'on', 'enable_dup' => 'on', 'zz' => 'u']]],
			'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsport' => '8081', 'pfb_hsts' => 'on', 'dnsbl_webpage' => 'x']]],
		]));
	}

	// B8 (nested) -- a non-empty array under a registered policy key projects as nested leaves under the key path.
	public function testNestedArrayUnderRegisteredPolicyKeyProjectsAsNestedLeaves(): void
	{
		$input = ['pfblockerng' => ['config' => [0 => [
			'skipfeed'        => ['a' => 'x', 'b' => ['c' => 'y']],
			'log_max_log'     => ['a' => 'local-nested'],
			'zz_unregistered' => ['a' => 'unknown-nested'],
		]]]];

		$this->assertSame([
			'installedpackages/pfblockerng/config/0/skipfeed/a'   => 'x',
			'installedpackages/pfblockerng/config/0/skipfeed/b/c' => 'y',
		], $this->project($input));
	}

	// B9 -- sections that are not arrays, are empty, or are absent contribute nothing.
	public function testNonArrayEmptyOrMissingSectionsContributeNothing(): void
	{
		$this->assertSame([], $this->project([]), 'no sections at all');
		$this->assertSame([], $this->project([
			'pfblockerng'            => '',
			'pfblockerngipsettings'  => 'x',
			'pfblockerngdnsblsettings' => 0,
			'pfblockernglistsv4'     => [],
			'pfblockernglistsv6'     => NULL,
			'pfblockerngdnsbl'       => 'rows',
			'pfblockerngsafesearch'  => FALSE,
		]), 'non-array and empty section values');
	}

	// B9 -- the Sync section and unknown sections are never part of the projection.
	public function testSyncSectionAndUnknownSectionsContributeNothing(): void
	{
		$input = [
			'pfblockerngsync'  => ['config' => [0 => ['syncscope' => 'policy', 'varsynconchanges' => 'auto', 'row' => [0 => ['password' => 'p']]]]],
			'pfblockerngbogus' => ['config' => [0 => ['x' => 'y']]],
			'installedpackages' => ['pfblockerng' => ['config' => [0 => ['skipfeed' => '3']]]],
		];

		$this->assertSame([], $this->project($input));
	}

	// Hostile shapes in settings sections: only a real config/0 array is read.
	public function testSettingsSectionWithMalformedConfigShapesProjectsNothing(): void
	{
		foreach ([
			'config holds a string'        => ['config' => 'skipfeed'],
			'config holds an int'          => ['config' => 7],
			'config/0 is a string'         => ['config' => [0 => 'skipfeed']],
			'config/0 is NULL'             => ['config' => [0 => NULL]],
			'config has no index 0'        => ['config' => [1 => ['skipfeed' => '3']]],
			'string-key 0 lookalike'       => ['config' => ['00' => ['skipfeed' => '3']]],
			'config is empty'              => ['config' => []],
		] as $label => $blob) {
			$this->assertSame([], $this->project(['pfblockerng' => $blob]), $label);
		}
	}

	// Hostile shapes in deny-list sections: a stray scalar is an ordinary leaf, not a crash.
	public function testDenyListSectionWithAScalarConfigKeyProjectsTheLeafVerbatim(): void
	{
		$this->assertSame(
			['installedpackages/pfblockerngdnsbl/config' => 'oops'],
			$this->project(['pfblockerngdnsbl' => ['config' => 'oops']])
		);
	}

	// Hostile keys: spaces, unicode and hyphens are path text, never reinterpreted.
	public function testKeysWithSpacesUnicodeAndHyphensAreProjectedVerbatim(): void
	{
		$this->assertSame([
			'installedpackages/pfblockerngsafesearch/my key'      => 'space',
			'installedpackages/pfblockerngsafesearch/clé-ünï'     => 'unicode',
			'installedpackages/pfblockerngsafesearch/with-hyphen' => 'hyphen',
		], $this->project(['pfblockerngsafesearch' => [
			'my key'      => 'space',
			'clé-ünï'     => 'unicode',
			'with-hyphen' => 'hyphen',
		]]));
	}

	// Hostile values: newlines, binary and 64 KiB strings are copied byte for byte.
	public function testHostileValuesAreCopiedByteForByte(): void
	{
		$long   = str_repeat('A', 65536) . 'tail';
		$binary = "\x01\x02\xfe\xff\x7f";
		$input  = ['pfblockerngsafesearch' => [
			'newlines' => "line1\nline2\r\n",
			'binary'   => $binary,
			'long'     => $long,
		]];

		$projection = $this->project($input);

		$this->assertSame("line1\nline2\r\n", $projection['installedpackages/pfblockerngsafesearch/newlines']);
		$this->assertSame($binary, $projection['installedpackages/pfblockerngsafesearch/binary']);
		$this->assertSame($long, $projection['installedpackages/pfblockerngsafesearch/long']);
		$this->assertSame(65540, strlen($projection['installedpackages/pfblockerngsafesearch/long']));
	}

	// Non-string scalars are copied as stored: normalising them for the wire is the manual builder's job (#3452).
	public function testNonStringScalarLeavesAreCopiedWithoutNormalization(): void
	{
		$this->assertSame([
			'installedpackages/pfblockerngsafesearch/t' => TRUE,
			'installedpackages/pfblockerngsafesearch/f' => FALSE,
			'installedpackages/pfblockerngsafesearch/z' => 0,
			'installedpackages/pfblockerngsafesearch/d' => 1.5,
		], $this->project(['pfblockerngsafesearch' => ['t' => TRUE, 'f' => FALSE, 'z' => 0, 'd' => 1.5]]));
	}

	// B10 -- the projection never modifies its input.
	public function testInputIsLeftUnchanged(): void
	{
		$fx     = self::diskFixture();
		$before = $fx['sections'];
		$text   = serialize($before);

		$this->project($fx['sections']);

		$this->assertSame($before, $fx['sections']);
		$this->assertSame($text, serialize($fx['sections']));
	}

	// B11 -- every projected path is rooted at installedpackages/<one of the 19 synced sections>/.
	public function testEveryPathStartsWithInstalledPackagesAndASyncedSection(): void
	{
		$fx = self::diskFixture();
		$projection = $this->project($fx['sections']);
		$this->assertNotEmpty($projection, 'vacuity guard');

		$sections = pfblockerng_sync_sections(TRUE);
		$this->assertCount(19, $sections);
		foreach (array_keys($projection) as $path) {
			$this->assertStringStartsWith(self::SECTIONS_ROOT, $path);
			$segments = explode('/', $path);
			$this->assertContains($segments[1], $sections, "{$path} must sit in one of the 19 synced sections");
			$this->assertGreaterThanOrEqual(3, count($segments), "{$path} must name a leaf below its section");
		}
	}
}
