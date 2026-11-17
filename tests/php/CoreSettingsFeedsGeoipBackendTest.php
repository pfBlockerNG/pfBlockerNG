<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: the settings adapter writes Core's `feeds/geoip` projection into config.xml by merging, never by rewriting:
 *   - only the key of a field whose native value differs from what the read gives is written, in the section of its continent, in the
 *     one write_config() under the DNS config lock; a section never saved is created holding only the changed key; an unchanged write is a no-op;
 *   - the list class is derived: a write holding any valid token for it, on a continent or an IP group, stores no key for it, and a
 *     write that changes an action leaves the inversions alone, so the next read derives the class again;
 *   - a value that is not the nine continents once each, of the right fields and types, is invalid_argument naming feeds/geoip.groups[<i>]..., changing nothing.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_geoip_faults')]
#[CoversFunction('pfb_core_geoip_merge')]
final class CoreSettingsFeedsGeoipBackendTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const AFRICA = 'installedpackages/pfblockerngafrica/config/0';
	private const EUROPE = 'installedpackages/pfblockerngeurope/config/0';
	private const OCEANIA = 'installedpackages/pfblockerngoceania/config/0';
	private const MESSAGE = '[pfBlockerNG] pfBlockerNG Core saved the settings';

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_feeds_geoip_backend_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
		$this->arrange();
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** config.xml: Africa Deny_Both with countries and a key no field maps to, Europe Deny_Both inverted, Oceania never saved, and one IPv4 group. */
	private function arrange(): void
	{
		config_set_path(self::AFRICA, ['action' => 'Deny_Both', 'countries4' => 'US,DE', 'countries6' => 'GB', 'description' => 'kept']);
		config_set_path(self::EUROPE, ['action' => 'Deny_Both', 'countries4' => 'FR', 'autoaddrnot_in' => 'on']);
		config_set_path('installedpackages/pfblockernglistsv4/config/0', ['aliasname' => 'G', 'action' => 'Permit_Both', 'autoaddrnot_out' => 'on', 'cron' => 'Never']);
		$this->configXmlOnDisk();
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('feeds/geoip', $reply['settings'] ?? [], 'the read answers the feeds/geoip projection: ' . json_encode($reply));
		return $reply;
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to its settings */
	private function write(callable $change): array
	{
		$read = $this->read();
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $change($read['settings'])]);
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to the group of $alias */
	private function writeGroup(string $alias, callable $change): array
	{
		return $this->write(static function (array $settings) use ($alias, $change): array {
			foreach ($settings['feeds/geoip']['groups'] as $i => $group) {
				if ($group['name'] === $alias) {
					$settings['feeds/geoip']['groups'][$i] = $change($group);
				}
			}
			return $settings;
		});
	}

	/** @return array<string, mixed> the group of $alias as the read answers it */
	private function group(string $alias): array
	{
		return array_values(array_filter($this->read()['settings']['feeds/geoip']['groups'], static fn(array $g): bool => $g['name'] === $alias))[0];
	}

	/** @return array<string, scalar> every leaf of config.xml by its path */
	private static function leaves(array $config, string $prefix = ''): array
	{
		$out = [];
		foreach ($config as $key => $value) {
			is_array($value) ? $out += self::leaves($value, "{$prefix}{$key}/") : $out["{$prefix}{$key}"] = $value;
		}
		return $out;
	}

	/** @return array<string, array{0: mixed, 1: mixed}> path => [before, after] for the leaves that differ, added or removed ones included (NULL) */
	private static function changes(array $before, array $after): array
	{
		$a = self::leaves($before);
		$b = self::leaves($after);
		$out = [];
		foreach (array_unique(array_merge(array_keys($a), array_keys($b))) as $path) {
			if (($a[$path] ?? NULL) !== ($b[$path] ?? NULL)) {
				$out[$path] = [$a[$path] ?? NULL, $b[$path] ?? NULL];
			}
		}
		ksort($out);
		return $out;
	}

	/** @param array<string, array{0: mixed, 1: mixed}> $expected */
	private function assertWrittenOnly(array $expected, array $before, array $reply, int $revisionBefore): void
	{
		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply, 'the reply is the revision config.xml projects now');
		$this->assertNotSame($revisionBefore, $reply['revision'], 'the revision moves with the change');
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config(), with the Core message');
		$this->assertSame('try_lock', $GLOBALS['pfb_test_lock_events'][0][0], 'the write holds the config lock');
		$this->assertSame(PFB_DNS_CONFIG_LOCK, $GLOBALS['pfb_test_lock_events'][0][1], 'the DNS config lock');
		$this->assertFileExists("{$this->dir}/pending", 'the change applies on the next Update');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
		$this->assertSame($this->disk, $GLOBALS['config'], 'what was written is what config.xml holds');
		ksort($expected);
		$this->assertSame($expected, self::changes($before, $GLOBALS['config']), 'exactly these keys of config.xml changed');
	}

	private function assertNothingWritten(array $before, string $why): void
	{
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$why}: write_config() was called");
		$this->assertSame([], self::changes($before, $GLOBALS['config']), "{$why}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$why}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$why}: the config lock is still held");
	}

	/** @return array<string, array{0: string, 1: string, 2: mixed, 3: array<string, array{0: mixed, 1: mixed}>}> continent, field, native value, the keys of config.xml that change */
	public static function fields(): array
	{
		$africa = self::AFRICA . '/';
		$oceania = self::OCEANIA . '/';
		return [
			'an action'                       => ['pfB_Africa', 'action', 'Permit_Inbound', [$africa . 'action' => ['Deny_Both', 'Permit_Inbound']]],
			'an action to Disabled'           => ['pfB_Africa', 'action', 'Disabled', [$africa . 'action' => ['Deny_Both', 'Disabled']]],
			'an IPv4 country added'           => ['pfB_Africa', 'countriesV4', [['code' => 'US'], ['code' => 'DE'], ['code' => 'A1_US_rep']], [$africa . 'countries4' => ['US,DE', 'US,DE,A1_US_rep']]],
			'IPv4 countries emptied'          => ['pfB_Africa', 'countriesV4', [], [$africa . 'countries4' => ['US,DE', '']]],
			'IPv4 countries reordered'        => ['pfB_Africa', 'countriesV4', [['code' => 'DE'], ['code' => 'US']], [$africa . 'countries4' => ['US,DE', 'DE,US']]],
			'an IPv6 country replaced'        => ['pfB_Africa', 'countriesV6', [['code' => 'FR']], [$africa . 'countries6' => ['GB', 'FR']]],
			'a never saved continent: action' => ['pfB_Oceania', 'action', 'Match_Both', [$oceania . 'action' => [NULL, 'Match_Both']]],
			'a never saved continent: IPv6'   => ['pfB_Oceania', 'countriesV6', [['code' => 'AU']], [$oceania . 'countries6' => [NULL, 'AU']]],
		];
	}

	/** @param array<string, array{0: mixed, 1: mixed}> $expected */
	#[DataProvider('fields')]
	public function testAChangedFieldReachesItsKeyOfItsContinentAndOnlyIt(string $alias, string $field, mixed $value, array $expected): void
	{
		$before = $GLOBALS['config'];
		$revision = $this->read()['revision'];
		$this->assertNotSame($value, $this->group($alias)[$field], 'before-state: the read gives another value');

		$reply = $this->writeGroup($alias, static function (array $group) use ($field, $value): array {
			$group[$field] = $value;
			return $group;
		});

		$this->assertWrittenOnly($expected, $before, $reply, $revision);
		$this->assertSame($value, $this->group($alias)[$field], 'the read gives back what Core asked');
	}

	public function testAnUnchangedWriteIsANoOp(): void
	{
		$read = $this->read();
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $read['settings']]);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply);
		$this->assertNothingWritten($before, 'an unchanged write');
	}

	public function testAStoredValueTheReadNormalizesStaysUntilCoreChangesIt(): void
	{
		config_set_path(self::AFRICA, ['action' => 'Deny', 'countries4' => 'US,USA,us,US', 'countries6' => '../x']);
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->write(static fn(array $settings): array => $settings);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertNothingWritten($before, 'values read as their defaults and written back as they were read');
	}

	/** @return array<string, array{0: string, 1: array<mixed>|string}> the continent's `config` as a restored or hand-edited config.xml may hold it */
	public static function unwritableSections(): array
	{
		return ['config is a string' => ['pfblockerngasia', 'garbage'], 'entry 0 is a string' => ['pfblockerngasia', ['garbage']]];
	}

	/** @param array<mixed>|string $stored */
	#[DataProvider('unwritableSections')]
	public function testASectionThatCannotTakeAKeyBecomesTheContinentsKeysWhenCoreChangesIt(string $section, array|string $stored): void
	{
		config_set_path("installedpackages/{$section}/config", $stored);
		$this->configXmlOnDisk();
		$this->assertSame('Disabled', $this->group('pfB_Asia')['action'], 'before-state');

		$this->writeGroup('pfB_Asia', static fn(array $group): array => ['action' => 'Alias_Native', 'countriesV4' => [['code' => 'JP']]] + $group);

		$this->assertSame('Alias_Native', $this->group('pfB_Asia')['action']);
		$this->assertSame(['action' => 'Alias_Native', 'countries4' => 'JP'], config_get_path("installedpackages/{$section}/config/0"), 'the stored section holds only the changed keys');
	}

	public function testAWriteOverACorruptedFirstEntryKeepsEveryOtherEntryOfTheSection(): void
	{
		config_set_path('installedpackages/pfblockerngasia/config', ['garbage', ['action' => 'Deny_Both', 'countries4' => 'DE']]);
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$this->assertSame('Disabled', $this->group('pfB_Asia')['action'], 'before-state: a string where the entry belongs projects the defaults');

		$this->writeGroup('pfB_Asia', static fn(array $group): array => ['action' => 'Alias_Native'] + $group);

		$expected = $before['installedpackages'];
		$expected['pfblockerngasia']['config'][0] = ['action' => 'Alias_Native'];
		$this->assertSame($expected, $GLOBALS['config']['installedpackages'],
			'only entry 0 of the continent Core changed is replaced: its other entries and every other section are as stored');
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls'], 'one write_config()');
	}

	public function testTheListClassOfAContinentIsNeverStoredAndAnActionChangeLeavesTheInversionsAlone(): void
	{
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertSame('native', $this->group('pfB_Europe')['listClass'], 'before-state: inverted, so native');

		$reply = $this->writeGroup('pfB_Europe', static fn(array $group): array => ['listClass' => 'deny'] + $group);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply, 'a class alone is no change');
		$this->assertNothingWritten($before, 'a list class alone');
		$revision = $this->read()['revision'];

		$reply = $this->writeGroup('pfB_Europe', static fn(array $group): array => ['action' => 'Permit_Both', 'listClass' => 'permit'] + $group);

		$this->assertWrittenOnly([self::EUROPE . '/action' => ['Deny_Both', 'Permit_Both']], $before, $reply, $revision);
		$this->assertSame('on', config_get_path(self::EUROPE . '/autoaddrnot_in'), 'the inversion is as it was');
		$this->assertSame('native', $this->group('pfB_Europe')['listClass'], 'the read derives the class again from the stored keys');
		$this->assertArrayNotHasKey('listClass', config_get_path(self::EUROPE), 'no key is stored for it');
	}

	public function testAListClassOffItsTokensOnAnIpGroupIsRefusedNamingItAndWritesNothing(): void
	{
		$before = $GLOBALS['config'];
		$settings = $this->read()['settings'];
		$settings['feeds/ipv4']['groups'][0]['listClass'] = 'bogus';

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $this->read()['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains('feeds/ipv4.groups[0].listClass', array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertNothingWritten($before, 'a list class off its tokens');
	}

	public function testTheListClassOfAnIpGroupIsNeverStoredAndAnActionChangeLeavesTheInversionsAlone(): void
	{
		$section = 'installedpackages/pfblockernglistsv4/config/0';
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertSame('native', $read['settings']['feeds/ipv4']['groups'][0]['listClass'], 'before-state: inverted, so native');
		$write = function (array $changes) use ($read): array {
			$settings = $this->read()['settings'];
			$settings['feeds/ipv4']['groups'][0] = $changes + $settings['feeds/ipv4']['groups'][0];
			return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $this->read()['revision'], 'settings' => $settings]);
		};

		$reply = $write(['listClass' => 'deny']);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply, 'a class alone is no change');
		$this->assertNothingWritten($before, 'a list class alone on an IP group');
		$revision = $this->read()['revision'];

		$reply = $write(['action' => 'Match_Both', 'listClass' => 'match']);

		$this->assertWrittenOnly([$section . '/action' => ['Permit_Both', 'Match_Both']], $before, $reply, $revision);
		$this->assertSame('on', config_get_path($section . '/autoaddrnot_out'), 'the inversion is as it was');
		$this->assertSame('native', $this->read()['settings']['feeds/ipv4']['groups'][0]['listClass'], 'the read derives the class again');
	}

	public function testAWriteBeneathAStaleRevisionIsAConflictAndWritesNothing(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/geoip']['groups'][1]['action'] = 'Permit_Both';
		config_set_path(self::AFRICA . '/countries6', 'JP');
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertNothingWritten($before, 'a stale revision');
	}

	public function testOneWriteCarriesADnsChangeAndAContinentChange(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['dns']['control'] = !$settings['dns']['control'];
		$settings['feeds/geoip']['groups'][1]['countriesV6'] = [['code' => 'JP']];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config() for both projections');
		$this->assertSame('JP', config_get_path(self::AFRICA . '/countries6'));
		$this->assertSame($settings['dns']['control'], $this->read()['settings']['dns']['control']);
	}

	/** @return array<string, array{0: callable, 1: string, 2: string}> a change of the written projection, the field it is named by, its message */
	public static function malformed(): array
	{
		$group = static fn(int $i, callable $change): callable => static function (array $v) use ($i, $change): array {
			$v['groups'][$i] = $change($v['groups'][$i]);
			return $v;
		};
		return [
			'a field left out'                  => [static function (array $v): array { unset($v['groups']); return $v; }, 'feeds/geoip.groups', 'required'],
			'an unknown field'                  => [static fn(array $v): array => $v + ['bogus' => TRUE], 'feeds/geoip.bogus', 'no such field'],
			'groups that is no list'            => [static fn(array $v): array => ['groups' => ['name' => 'pfB_Top']], 'feeds/geoip.groups', 'not a list'],
			'a group that is a string'          => [static fn(array $v): array => ['groups' => ['pfB_Top'] + $v['groups']], 'feeds/geoip.groups[0]', 'not an object'],
			'a group field left out'            => [$group(2, static function (array $g): array { unset($g['listClass']); return $g; }), 'feeds/geoip.groups[2].listClass', 'required'],
			'an unknown group field'            => [$group(2, static fn(array $g): array => $g + ['x' => 1]), 'feeds/geoip.groups[2].x', 'no such field'],
			'a continent that is not one'       => [$group(0, static fn(array $g): array => ['name' => 'pfB_Mars'] + $g), 'feeds/geoip.groups[0].name', 'not a valid value'],
			'a name that is no string'          => [$group(0, static fn(array $g): array => ['name' => 5] + $g), 'feeds/geoip.groups[0].name', 'not a valid value'],
			'a repeated continent'              => [$group(8, static fn(array $g): array => ['name' => 'pfB_Top'] + $g), 'feeds/geoip.groups[8].name', 'not unique'],
			'a tenth group'                     => [static fn(array $v): array => ['groups' => [...$v['groups'], $v['groups'][0]]], 'feeds/geoip.groups[9].name', 'not unique'],
			'a continent left out'              => [static fn(array $v): array => ['groups' => array_slice($v['groups'], 0, 8)], 'feeds/geoip.groups', 'must hold each of the 9 continents'],
			'an action off its tokens'          => [$group(1, static fn(array $g): array => ['action' => 'unbound'] + $g), 'feeds/geoip.groups[1].action', 'not a valid value'],
			'an action that is no string'       => [$group(1, static fn(array $g): array => ['action' => 1] + $g), 'feeds/geoip.groups[1].action', 'not a valid value'],
			'a list class off its tokens'       => [$group(1, static fn(array $g): array => ['listClass' => 'block'] + $g), 'feeds/geoip.groups[1].listClass', 'not a valid value'],
			'a country list that is a string'   => [$group(1, static fn(array $g): array => ['countriesV4' => 'US'] + $g), 'feeds/geoip.groups[1].countriesV4', 'not a list'],
			'a country that is a string'        => [$group(1, static fn(array $g): array => ['countriesV6' => ['US']] + $g), 'feeds/geoip.groups[1].countriesV6[0]', 'not an object'],
			'a country off the pattern'         => [$group(1, static fn(array $g): array => ['countriesV4' => [['code' => 'usa']]] + $g), 'feeds/geoip.groups[1].countriesV4[0].code', 'not a valid value'],
			'a path as a country'               => [$group(1, static fn(array $g): array => ['countriesV4' => [['code' => '../x']]] + $g), 'feeds/geoip.groups[1].countriesV4[0].code', 'not a valid value'],
			'a repeated country'                => [$group(1, static fn(array $g): array => ['countriesV6' => [['code' => 'US'], ['code' => 'US']]] + $g), 'feeds/geoip.groups[1].countriesV6[1].code', "repeats an earlier item's"],
			'a country item with a field of its own' => [$group(1, static fn(array $g): array => ['countriesV4' => [['code' => 'US', 'x' => 1]]] + $g), 'feeds/geoip.groups[1].countriesV4[0].x', 'no such field'],
			'a projection that is no object'    => [static fn(array $v): array => ['x'], 'feeds/geoip', 'not an object'],
		];
	}

	#[DataProvider('malformed')]
	public function testAMalformedGeoipIsInvalidArgumentNamingTheFieldAndChangesNothing(callable $change, string $field, string $message): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->write(static function (array $settings) use ($change): array {
			$settings['feeds/geoip'] = $change($settings['feeds/geoip']);
			return $settings;
		});

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains(['field' => $field, 'message' => $message], $reply['error']['fieldErrors'] ?? [], json_encode($reply));
		$this->assertNothingWritten($before, 'a malformed feeds/geoip');
	}

	public function testAWriteWithoutFeedsGeoipIsMalformedNamingTheProjections(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->write(static function (array $settings): array {
			unset($settings['feeds/geoip']);
			return $settings;
		});

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('feeds/geoip', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
		$this->assertNothingWritten($before, 'a write without feeds/geoip');
	}
}
