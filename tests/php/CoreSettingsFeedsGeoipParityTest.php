<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: freezes today's PHP behaviour for Core's `feeds/geoip` projection (the nine GeoIP continent groups: their action,
 * their IPv4 and IPv6 countries and the list class their action and Advanced Inbound/Outbound inversions give) as the parity fixture
 * tests/core/fixtures/settings_feeds_geoip_parity.json; go/pfb_core/settings passes the same file.
 *   - A case is a config.xml: `php` is what the apply pass makes of each continent it names (the statements of
 *     sync_package_pfblockerng() at pfblockerng_apply.inc "Find all enabled Continents lists" and the continent loop, replayed here
 *     with their source anchored below), `groups` (each over the fixture's defaults) is what the settings adapter's read answers.
 *     Where Core and today's PHP differ (a country the pass would pass on as typed) the case says why.
 *   - A refused row is a whole value Core refuses to read; the adapter's write refuses it too, naming the field.
 */
#[CoversFunction('pfb_core_settings')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsFeedsGeoipParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_feeds_geoip_parity.json';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_feeds_geoip_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function cases(): array
	{
		$cases = [];
		foreach (self::fixture()['cases'] as $case) {
			$cases[$case['id']] = [$case];
		}
		return $cases;
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function refused(): array
	{
		$rows = [];
		foreach (self::fixture()['refused'] as $row) {
			$rows[$row['id']] = [$row];
		}
		return $rows;
	}

	/**
	 * config.xml as the case holds it: `config` is a continent section's entry 0, `configRaw` what the section's `config` holds as it is.
	 *
	 * @param array<string, mixed> $case
	 */
	private function arrange(array $case): void
	{
		foreach ($case['config'] as $section => $stored) {
			config_set_path("installedpackages/{$section}/config/0", $stored);
		}
		foreach ($case['configRaw'] ?? [] as $section => $stored) {
			config_set_path("installedpackages/{$section}/config", $stored);
		}
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'read'], "{$this->dir}/node_exporter", static fn(): array => []);
		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode($reply));
		$this->assertArrayHasKey('feeds/geoip', $reply['settings'], 'the read answers the feeds/geoip projection: ' . json_encode(array_keys($reply['settings'])));
		return $reply;
	}

	/** @return list<array<string, mixed>> the fixture's defaults with each group the map names replaced */
	private static function groupsOver(array $groups): array
	{
		return array_map(static fn(array $default): array => array_replace($default, $groups[$default['name']] ?? []), self::fixture()['defaults']['groups']);
	}

	/**
	 * What the apply pass makes of the continent of $alias: NULL when it finds no section, ['valid' => FALSE] for an action it skips, else the
	 * folder the list goes in (NULL for Disabled, which builds nothing) and the country tokens it explodes (a TypeError for an array).
	 *
	 * @return array<string, mixed>|null
	 */
	private function observe(string $alias, string $section): ?array
	{
		if (empty(config_get_path("installedpackages/{$section}/config"))) {
			return NULL;
		}
		$continent = config_get_path("installedpackages/{$section}/config/0");
		if (!pfb_group_action_valid($continent['action'] ?? NULL, 'geoip')) {
			return ['valid' => FALSE];
		}
		$tokens = static function (string $type) use ($continent): array|string {
			if (empty($continent[$type])) {
				return [];
			}
			try {
				return explode(',', $continent[$type]);
			} catch (TypeError) {
				return 'TypeError';
			}
		};
		$folder = $continent['action'] === 'Disabled' ? NULL : basename(pfb_determine_list_detail($continent['action'], "{$alias}_v4", $section, '0')['folder'] ?? '');
		return ['valid' => TRUE, 'folder' => $folder, 'countries4' => $tokens('countries4'), 'countries6' => $tokens('countries6')];
	}

	public function testTheFixtureHoldsTheCoverageMatrixAndHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('feeds/geoip', $doc['projection']);
		$this->assertSame($GLOBALS['pfb']['continents'], array_column($doc['continents'], 'alias', 'name'), "the fixture lists today's continents in today's order");
		$this->assertSame(array_column($doc['continents'], 'alias'), array_column($doc['defaults']['groups'], 'name'), 'the defaults list the nine in that order');
		foreach ($doc['continents'] as $continent) {
			$this->assertSame('pfblockerng' . strtolower(str_replace(' ', '', $continent['name'])), $continent['section'], "{$continent['name']}: its section name");
		}
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		$expected = ['defaults', 'action-missing', 'several-continents', 'section-string', 'section-not-a-list', 'section-entry-string', 'section-entry-empty', 'countries4-array',
			'countries6-array', 'countries6-several', 'countries6-hostile', 'class-invert-both', 'class-invert-on-native', 'class-invert-on-disabled'];
		array_push($expected, ...array_map(static fn(array $c): string => "continent-{$c['alias']}", $doc['continents']));
		array_push($expected, ...array_map(static fn(string $a): string => "action-{$a}", ['Disabled', 'Deny_Inbound', 'Deny_Outbound', 'Deny_Both', 'Permit_Inbound',
			'Permit_Outbound', 'Permit_Both', 'Match_Inbound', 'Match_Outbound', 'Match_Both', 'Alias_Deny', 'Alias_Permit', 'Alias_Match', 'Alias_Native']));
		array_push($expected, 'action-invalid-deny', 'action-invalid-deny_both', 'action-invalid-empty', 'action-invalid-array', 'action-invalid-unbound',
			'class-invert-in-on', 'class-invert-out-on', 'class-invert-in-upper', 'class-invert-out-upper', 'class-not-inverted-yes', 'class-not-inverted-one',
			'class-not-inverted-space-on', 'class-not-inverted-array', 'countries4-one', 'countries4-several', 'countries4-rep', 'countries4-a1', 'countries4-a2',
			'countries4-a1-country-rep', 'countries4-page-form', 'countries4-repeated', 'countries4-three-letter', 'countries4-lower-case', 'countries4-path',
			'countries4-path-after-code', 'countries4-semicolon', 'countries4-space');
		foreach ($expected as $id) {
			$this->assertContains($id, $ids, "the coverage matrix row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
		foreach (['group-name-outside', 'group-tenth', 'group-repeated', 'group-missing', 'countriesV4-three-letters', 'countriesV4-lower-case', 'countriesV4-path',
			'countriesV4-repeated', 'countriesV6-three-letters', 'countriesV6-repeated', 'action-outside', 'list-class-outside'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
	}

	public function testTheApplyPassStillReadsTheContinentsAsTheObserverReplaysIt(): void
	{
		$source = (string) file_get_contents(self::APPLY);

		foreach ([
			"\$cont_key = 'pfblockerng' . strtolower(str_replace(' ', '', \$continent));",
			"'countries4' => '_v4', 'countries6' => '_v6'",
			"!pfb_group_action_valid(\$continent_config['action'] ?? NULL, 'geoip')",
			"foreach (explode(',', \$continent_config[\$c_type]) as \$iso)",
			"pfb_determine_list_detail(\$continent_config['action'], \"{\$cc_alias}\", \$cc_name, '0')",
			"pfb_dnsbl_toggle_enabled(\$continent_config['autoaddrnot_in'] ?? '')",
			"pfb_dnsbl_toggle_enabled(\$continent_config['autoaddrnot_out'] ?? '')",
			"pfb_dnsbl_toggle_enabled(\$list['autoaddrnot_in'] ?? '')",
		] as $statement) {
			$this->assertStringContainsString($statement, $source, "the apply pass still has: {$statement}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesObservations(array $case): void
	{
		$this->arrange($case);
		$sections = array_column(self::fixture()['continents'], 'section', 'alias');

		$seen = [];
		foreach (array_keys($case['php']) as $alias) {
			$seen[$alias] = $this->observe($alias, $sections[$alias]);
		}

		$this->assertSame($case['php'], $seen, "{$case['id']}: today's PHP reading of the continents");
		$this->assertNotSame([], $case['php'], "{$case['id']}: the case observes today's PHP");
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTheAdapterProjectsTheFixturesGeoip(array $case): void
	{
		$this->arrange($case);

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame(['groups' => self::groupsOver($case['groups'])], $reply['settings']['feeds/geoip'], "{$case['id']}: the feeds/geoip projection");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	public function testTheAdapterReadsAMegabyteCountryListAndInvalidUtf8WithoutWarningAndKeepsTheValidCodes(): void
	{
		config_set_path('installedpackages/pfblockerngeurope/config/0', ['action' => 'Deny_Both', 'countries4' => str_repeat('US,', 350000) . 'DE', 'countries6' => "GB,\xff\xfe,DE"]);

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$europe = array_values(array_filter($reply['settings']['feeds/geoip']['groups'], static fn(array $g): bool => $g['name'] === 'pfB_Europe'))[0];
		$this->assertSame([['code' => 'US'], ['code' => 'DE']], $europe['countriesV4'], 'a megabyte of repeats is two codes');
		$this->assertSame([['code' => 'GB'], ['code' => 'DE']], $europe['countriesV6'], 'invalid UTF-8 in a token drops the token');
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesTheFixturesHostileValueNamingTheFieldAndWritesNothing(array $row): void
	{
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/geoip'] = $row['value'];

		$reply = $this->assertNoPhpWarning(fn(): array => pfb_core_settings_backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'],
			'settings' => $settings], "{$this->dir}/node_exporter", static fn(): array => []));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$this->assertContains("feeds/geoip.{$row['field']}", array_column($reply['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']} " . json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$row['id']}: write_config() was called");
		$this->assertSame($before, $GLOBALS['config'], "{$row['id']}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$row['id']}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$row['id']}: the config lock is still held");
	}
}
