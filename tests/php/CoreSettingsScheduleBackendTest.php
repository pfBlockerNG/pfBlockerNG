<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941: the settings adapter reads and writes Core's `schedule` projection (the scheduler's inputs: General's schedule, each
 * group's override slot, the Blacklist's updates) in config.xml by merging, never by rewriting:
 *   - only the config.xml keys whose native value differs from what the read gives are written, in the one write_config() of the
 *     other projections; an unchanged write is a no-op;
 *   - a group or provider is matched by id; one Core leaves out of its list is left as it is, and one that names no group or provider
 *     of config.xml is invalid_argument naming the field, changing nothing: Core cannot create them here;
 *   - a provider's `selected` adds its id to blacklist_selected (appended) or removes it, keeping the order of the others;
 *   - a group the feed projections delete in the same write is not patched.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
#[CoversFunction('pfb_core_schedule_faults')]
#[CoversFunction('pfb_core_schedule_merge')]
final class CoreSettingsScheduleBackendTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const GEN = 'installedpackages/pfblockerng/config/0';
	private const V4 = 'installedpackages/pfblockernglistsv4/config';
	private const V6 = 'installedpackages/pfblockernglistsv6/config';
	private const DNSBL = 'installedpackages/pfblockerngdnsbl/config';
	private const BLACKLIST = 'installedpackages/pfblockerngblacklist';
	private const MESSAGE = '[pfBlockerNG] pfBlockerNG Core saved the settings';

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_schedule_backend_' . bin2hex(random_bytes(8));
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

	/** A group as the Groups editor stores it: keys no schedule field maps to beside the override and its slot. */
	private static function group(string $name, array $extra = []): array
	{
		return $extra + ['aliasname' => $name, 'description' => 'kept', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'schedule_override' => '',
			'row' => [['format' => 'auto', 'state' => 'Enabled', 'url' => "https://example.org/{$name}.txt", 'header' => "{$name}_f"]]];
	}

	/** config.xml: the groups of the three types and a Blacklist whose provider ut1 and ut2 are selected, in that order of the list. */
	private function arrange(array $over = []): void
	{
		$sections = $over + [
			self::GEN => ['pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '3', 'pfb_schedule_hour' => '2', 'pfb_schedule_minute' => '15'],
			self::V4 => [self::group('A', ['schedule_override' => 'on', 'schedule_weekday' => '5', 'schedule_hour' => '13', 'schedule_minute' => '45']), self::group('B')],
			self::V6 => [self::group('Six')],
			self::DNSBL => [self::group('Ads', ['action' => 'unbound', 'cron' => 'Weekly'])],
			self::BLACKLIST => ['blacklist_enable' => 'Enable', 'blacklist_freq' => 'EveryDay', 'blacklist_selected' => 'ut2,ut1', 'blacklist_lang' => 'EN', 'item' => [
				['xml' => 'ut1', 'title' => 'UT1', 'feed' => 'https://example.org/ut1', 'selected' => 'adult', 'size' => '1'],
				['xml' => 'ut2', 'title' => 'UT2', 'feed' => 'https://example.org/ut2', 'selected' => 'phishing'],
				['xml' => 'ut3', 'title' => 'UT3', 'feed' => 'https://example.org/ut3', 'selected' => ''],
				['xml' => 'shalla', 'title' => 'Shallalist', 'feed' => 'https://example.org/shalla', 'selected' => 'adult'],
			]],
		];
		foreach ($sections as $path => $value) {
			config_set_path($path, $value);
		}
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
		$this->assertArrayHasKey('schedule', $reply['settings'] ?? [], 'the read answers the schedule projection: ' . json_encode($reply));
		return $reply;
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to its `schedule` */
	private function writeSchedule(callable $change): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['schedule'] = $change($settings['schedule']);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);
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
	private function assertWrittenOnly(array $expected, array $before, array $reply): void
	{
		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply, 'the reply is the revision config.xml projects now');
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config(), with the Core message');
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

	// ----- the read -----

	public function testTheReadAnswersTheScheduleOfConfigXmlAndTheRevisionCoversIt(): void
	{
		$read = $this->read();

		$this->assertSame(['dns', 'feeds/ipv4', 'feeds/ipv6', 'feeds/dnsbl', 'schedule', 'ingest'], array_keys($read['settings']));
		$this->assertSame([
			'scheduledUpdates' => TRUE, 'weekday' => 3, 'hour' => 2, 'minute' => 15,
			'groups' => [
				['id' => 'ipv4/A', 'override' => TRUE, 'weekday' => 5, 'hour' => 13, 'minute' => 45],
				['id' => 'ipv4/B', 'override' => FALSE, 'weekday' => 7, 'hour' => 0, 'minute' => 0],
				['id' => 'ipv6/Six', 'override' => FALSE, 'weekday' => 7, 'hour' => 0, 'minute' => 0],
				['id' => 'dnsbl/Ads', 'override' => FALSE, 'weekday' => 7, 'hour' => 0, 'minute' => 0],
			],
			'categoryUpdates' => TRUE, 'categoryFrequency' => 'EveryDay',
			'categoryProviders' => [
				['id' => 'ut1', 'selected' => TRUE, 'categories' => 'adult'],
				['id' => 'ut2', 'selected' => TRUE, 'categories' => 'phishing'],
				['id' => 'ut3', 'selected' => FALSE, 'categories' => ''],
			],
		], $read['settings']['schedule'], 'the Shallalist provider is not projected');
		foreach ([['weekday', 4], ['scheduledUpdates', FALSE], ['categoryFrequency', 'Weekly']] as [$field, $value]) {
			$moved = $read['settings'];
			$moved['schedule'][$field] = $value;
			$this->assertNotSame($read['revision'], pfb_core_settings_revision($moved), "{$field} moves the revision");
		}
		$GLOBALS['config'] = $this->disk;
		config_set_path(self::GEN . '/pfb_schedule_hour', '9');
		$this->assertNotSame($read['revision'], $this->read()['revision'], 'a config.xml change of the schedule moves the revision');
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
	}

	public function testAProviderRepeatedInTheBlacklistProjectsOnceAndAMalformedOneNotAtAll(): void
	{
		$this->arrange([self::BLACKLIST => ['item' => [
			['xml' => 'ut1', 'title' => 'UT1', 'feed' => 'https://example.org/ut1', 'selected' => 'adult'],
			['xml' => 'ut1', 'title' => 'UT1', 'feed' => 'https://example.org/ut1', 'selected' => 'other'],
			['xml' => 'a,b', 'title' => 'Comma', 'feed' => 'https://example.org/c', 'selected' => ''],
			['xml' => '0', 'title' => 'Zero', 'feed' => 'https://example.org/z', 'selected' => ''],
			['xml' => 'markup', 'title' => 'Markup', 'feed' => 'https://example.org/m', 'selected' => 'a<b'],
			['xml' => 'ut4', 'title' => 'UT4', 'feed' => 'https://example.org/ut4', 'selected' => 'ok'],
		]]]);

		$providers = $this->read()['settings']['schedule']['categoryProviders'];

		$this->assertSame(['ut1', 'ut4'], array_column($providers, 'id'));
		$this->assertSame('adult', $providers[0]['categories'], 'the first of a repeated id');
	}

	// ----- the write -----

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
		$this->arrange([self::V4 => [self::group('A', ['schedule_override' => 'on', 'schedule_weekday' => '8', 'schedule_hour' => '05', 'schedule_minute' => '20'])],
			self::GEN => ['pfb_schedule_weekday' => 'x']]);
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static fn(array $s): array => $s);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertNothingWritten($before, 'a value read as its default and written back as it was read');
	}

	/** @return array<string, array{0: string, 1: mixed, 2: array<string, array{0: mixed, 1: mixed}>}> field, native value, the keys of config.xml that change */
	public static function generalFields(): array
	{
		return [
			'weekday'                   => ['weekday', 5, [self::GEN . '/pfb_schedule_weekday' => ['3', '5']]],
			'hour'                      => ['hour', 13, [self::GEN . '/pfb_schedule_hour' => ['2', '13']]],
			'minute'                    => ['minute', 45, [self::GEN . '/pfb_schedule_minute' => ['15', '45']]],
			'scheduled updates off'     => ['scheduledUpdates', FALSE, [self::GEN . '/pfb_scheduled_feed_updates' => ['on', '']]],
			'category updates off'      => ['categoryUpdates', FALSE, [self::BLACKLIST . '/blacklist_enable' => ['Enable', 'Disable']]],
			'category frequency'        => ['categoryFrequency', 'Weekly', [self::BLACKLIST . '/blacklist_freq' => ['EveryDay', 'Weekly']]],
		];
	}

	/** @param array<string, array{0: mixed, 1: mixed}> $expected */
	#[DataProvider('generalFields')]
	public function testAChangedSettingReachesItsKeyAndOnlyIt(string $field, mixed $value, array $expected): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s) use ($field, $value): array {
			$s[$field] = $value;
			return $s;
		});

		$this->assertWrittenOnly($expected, $before, $reply);
	}

	public function testScheduledUpdatesTurnedBackOnIsStoredOn(): void
	{
		$this->arrange([self::GEN => ['pfb_scheduled_feed_updates' => '', 'pfb_schedule_weekday' => '3']]);
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['scheduledUpdates'] = TRUE;
			return $s;
		});

		$this->assertWrittenOnly([self::GEN . '/pfb_scheduled_feed_updates' => ['', 'on']], $before, $reply);
	}

	public function testAGroupsSlotAndOverrideReachItsKeysOnly(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['groups'][1] = ['id' => 'ipv4/B', 'override' => TRUE, 'weekday' => 1, 'hour' => 23, 'minute' => 30];
			$s['groups'][0]['override'] = FALSE;
			return $s;
		});

		$this->assertWrittenOnly([
			self::V4 . '/0/schedule_override' => ['on', ''],
			self::V4 . '/1/schedule_override' => ['', 'on'],
			self::V4 . '/1/schedule_weekday' => [NULL, '1'],
			self::V4 . '/1/schedule_hour' => [NULL, '23'],
			self::V4 . '/1/schedule_minute' => [NULL, '30'],
		], $before, $reply);
	}

	public function testAGroupsSlotChangesWithoutTouchingItsOverride(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['groups'][3]['hour'] = 6;
			$s['groups'][0]['minute'] = 0;
			return $s;
		});

		$this->assertWrittenOnly([self::V4 . '/0/schedule_minute' => ['45', '0'], self::DNSBL . '/0/schedule_hour' => [NULL, '6']], $before, $reply);
	}

	public function testAGroupLeftOutOfTheListIsLeftAsItIs(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['groups'] = [['id' => 'ipv6/Six', 'override' => TRUE, 'weekday' => 2, 'hour' => 2, 'minute' => 15]];
			return $s;
		});

		$this->assertWrittenOnly([
			self::V6 . '/0/schedule_override' => ['', 'on'], self::V6 . '/0/schedule_weekday' => [NULL, '2'],
			self::V6 . '/0/schedule_hour' => [NULL, '2'], self::V6 . '/0/schedule_minute' => [NULL, '15'],
		], $before, $reply);
		$this->assertSame('on', config_get_path(self::V4 . '/0/schedule_override'), 'ipv4/A, left out of the list, keeps its override');
	}

	/** @return array<string, array{0: string}> */
	public static function unknownGroupIds(): array
	{
		return [
			'a group of no section'          => ['ipv4/Nope'],
			'the right name in another type' => ['dnsbl/B'],
			'a name too long for an IP group, which does not project' => ['ipv4/ABCDEFGHIJKLMNOPQRSTUVWXY'],
		];
	}

	#[DataProvider('unknownGroupIds')]
	public function testAGroupThatNamesNoGroupIsRefusedAndNothingIsWritten(string $id): void
	{
		config_set_path(self::V4, array_merge(config_get_path(self::V4), [self::group('ABCDEFGHIJKLMNOPQRSTUVWXY')]));
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s) use ($id): array {
			$s['groups'][] = ['id' => $id, 'override' => TRUE, 'weekday' => 1, 'hour' => 1, 'minute' => 0];
			return $s;
		});

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains('schedule.groups[4].id', array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertNothingWritten($before, 'a group config.xml does not hold');
	}

	public function testAGroupTheFeedProjectionDeletesIsNotPatchedAndOneItKeepsIs(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'] = [$settings['feeds/ipv4']['groups'][1]];	// Core deletes ipv4/A
		$settings['schedule']['groups'][0]['weekday'] = 2;	// and still lists it
		$settings['schedule']['groups'][1]['override'] = TRUE;	// ipv4/B, which stays

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertSame(['B'], array_column(config_get_path(self::V4), 'aliasname'), 'ipv4/A is deleted');
		$this->assertSame('on', config_get_path(self::V4 . '/0/schedule_override'), 'ipv4/B takes its override on top of the feed merge');
		$this->assertSame($this->disk, $GLOBALS['config']);
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config()');
	}

	public function testProviderSelectionAddsAndRemovesItsIdKeepingTheOrderOfTheOthers(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryProviders'][1]['selected'] = FALSE;	// ut2 off
			$s['categoryProviders'][2]['selected'] = TRUE;	// ut3 on, appended
			return $s;
		});

		$this->assertWrittenOnly([self::BLACKLIST . '/blacklist_selected' => ['ut2,ut1', 'ut1,ut3']], $before, $reply);
	}

	public function testSelectingAProviderWhenNoneIsSelectedAndDeselectingTheLast(): void
	{
		$this->arrange([self::BLACKLIST => ['item' => [['xml' => 'ut1', 'title' => 'UT1', 'feed' => 'https://example.org/ut1', 'selected' => 'adult']]]]);
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryProviders'][0]['selected'] = TRUE;
			return $s;
		});
		$this->assertWrittenOnly([self::BLACKLIST . '/blacklist_selected' => [NULL, 'ut1']], $before, $reply);

		$GLOBALS['pfb_test_write_config_calls'] = [];
		unlink("{$this->dir}/pending");
		$before = $GLOBALS['config'];
		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryProviders'][0]['selected'] = FALSE;
			return $s;
		});
		$this->assertWrittenOnly([self::BLACKLIST . '/blacklist_selected' => ['ut1', '']], $before, $reply);
	}

	public function testAProvidersCategoriesReachItsItemOnly(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryProviders'][2]['categories'] = 'adult,porn';
			return $s;
		});

		$this->assertWrittenOnly([self::BLACKLIST . '/item/2/selected' => ['', 'adult,porn']], $before, $reply);
	}

	/** @return array<string, array{0: string}> */
	public static function unknownProviderIds(): array
	{
		return ['an id no item has' => ['nope'], 'a Shallalist item, which does not project' => ['shalla']];
	}

	#[DataProvider('unknownProviderIds')]
	public function testAProviderThatNamesNoProviderIsRefusedAndNothingIsWritten(string $id): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s) use ($id): array {
			$s['categoryProviders'][] = ['id' => $id, 'selected' => TRUE, 'categories' => 'adult'];
			return $s;
		});

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains('schedule.categoryProviders[3].id', array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertNothingWritten($before, 'a provider config.xml does not hold');
	}

	public function testAMinuteOffTheQuarterHourIsRefusedAndNothingIsWritten(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['minute'] = 20;
			$s['groups'][0]['minute'] = 10;
			return $s;
		});

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertEqualsCanonicalizing(['schedule.minute', 'schedule.groups[0].minute'], array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertNothingWritten($before, 'a minute off the quarter hour');
	}

	public function testAScheduleWriteWithAStaleRevisionIsAConflict(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['schedule']['weekday'] = 1;
		config_set_path(self::GEN . '/pfb_schedule_hour', '9');	// config.xml moved after Core read it
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertNothingWritten($before, 'a stale revision');
	}

	// ----- an override keeps a whole slot (the runtime model rejects an override on with a partial one) -----

	/** @return array<string, array{0: int, 1: int, 2: int}> */
	public static function slots(): array
	{
		return ['3/0/0' => [3, 0, 0], '7/0/0, the default' => [7, 0, 0], '1/23/45' => [1, 23, 45]];
	}

	/** The runtime model pfb_schedule_runtime_config() builds from config.xml now, which must hold. @return array<string, mixed> */
	private function runtimeModel(): array
	{
		$GLOBALS['pfb_test_logger_calls'] = [];
		$model = pfb_schedule_runtime_config();
		$this->assertNotNull($model, 'the runtime model rejects config.xml: ' . json_encode($GLOBALS['pfb_test_logger_calls']));
		return $model;
	}

	#[DataProvider('slots')]
	public function testAnOverrideTurnedOnOnAGroupWithNoStoredSlotLeavesAValidRuntimeModelWithThatSlot(int $weekday, int $hour, int $minute): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s) use ($weekday, $hour, $minute): array {
			$s['groups'][1] = ['id' => 'ipv4/B', 'override' => TRUE, 'weekday' => $weekday, 'hour' => $hour, 'minute' => $minute];
			return $s;
		});

		$this->assertWrittenOnly([
			self::V4 . '/1/schedule_override' => ['', 'on'],
			self::V4 . '/1/schedule_weekday' => [NULL, (string) $weekday],
			self::V4 . '/1/schedule_hour' => [NULL, (string) $hour],
			self::V4 . '/1/schedule_minute' => [NULL, (string) $minute],
		], $before, $reply);
		$this->assertSame(['weekday' => $weekday, 'hour' => $hour, 'minute' => $minute], $this->runtimeModel()['entries']['ipv4:B_f_v4']['override'],
			'the model of config.xml carries the override with the slot Core wrote');
	}

	public function testChangingOneFieldOfAnOverrideWritesTheWholeSlotAndRepairsAPartialOne(): void
	{
		$this->arrange([self::V4 => [self::group('A', ['schedule_override' => 'on', 'schedule_weekday' => '5'])]]);
		$before = $GLOBALS['config'];
		$this->assertSame(['weekday' => 5, 'hour' => 0, 'minute' => 0],
			array_intersect_key($this->read()['settings']['schedule']['groups'][0], array_flip(['weekday', 'hour', 'minute'])), 'a stored partial slot reads with defaults');

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['groups'][0]['hour'] = 6;
			return $s;
		});

		$this->assertWrittenOnly([self::V4 . '/0/schedule_hour' => [NULL, '6'], self::V4 . '/0/schedule_minute' => [NULL, '0']], $before, $reply);
		$this->assertSame(['weekday' => 5, 'hour' => 6, 'minute' => 0], $this->runtimeModel()['entries']['ipv4:A_f_v4']['override']);
	}

	public function testAnOverrideThatDoesNotChangeIsLeftWithItsStoredSlotWhateverItIs(): void
	{
		$this->arrange([self::V4 => [self::group('A', ['schedule_override' => 'on', 'schedule_weekday' => '5'])]]);
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static fn(array $s): array => $s);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertNothingWritten($before, 'a group that did not change');
	}

	// ----- a group name that three types hold -----

	/** @return array<string, array{0: string, 1: string}> */
	public static function families(): array
	{
		return ['ipv4' => ['ipv4', self::V4], 'ipv6' => ['ipv6', self::V6], 'dnsbl' => ['dnsbl', self::DNSBL]];
	}

	#[DataProvider('families')]
	public function testAGroupNameThatAllThreeTypesHoldIsPatchedInTheTypeItsIdNames(string $type, string $path): void
	{
		$this->arrange([self::V4 => [self::group('X')], self::V6 => [self::group('X')], self::DNSBL => [self::group('X', ['action' => 'unbound'])]]);
		$before = $GLOBALS['config'];
		$this->assertSame(['ipv4/X', 'ipv6/X', 'dnsbl/X'], array_column($this->read()['settings']['schedule']['groups'], 'id'));

		$reply = $this->writeSchedule(static function (array $s) use ($type): array {
			foreach ($s['groups'] as $i => $group) {
				if ($group['id'] === "{$type}/X") {
					$s['groups'][$i] = ['id' => "{$type}/X", 'override' => TRUE, 'weekday' => 2, 'hour' => 3, 'minute' => 15];
				}
			}
			return $s;
		});

		$this->assertWrittenOnly([
			"{$path}/0/schedule_override" => ['', 'on'], "{$path}/0/schedule_weekday" => [NULL, '2'],
			"{$path}/0/schedule_hour" => [NULL, '3'], "{$path}/0/schedule_minute" => [NULL, '15'],
		], $before, $reply);
	}

	// ----- what the read normalizes -----

	/** @return array<string, array{0: ?string, 1: bool}> blacklist_enable as stored => what the runtime model makes of it */
	public static function enableTokens(): array
	{
		return ['Enable' => ['Enable', TRUE], 'a token other than Disable' => ['on', TRUE], 'a case variant of Disable' => ['disable', TRUE],
			'Disable' => ['Disable', FALSE], 'empty' => ['', FALSE], 'absent' => [NULL, FALSE], 'PHP-empty zero' => ['0', FALSE]];
	}

	private static function blacklist(?string $enable): array
	{
		return ($enable === NULL ? [] : ['blacklist_enable' => $enable]) + ['blacklist_freq' => 'EveryDay', 'blacklist_selected' => 'ut1',
			'item' => [['xml' => 'ut1', 'title' => 'UT1', 'feed' => 'https://example.org/ut1', 'selected' => 'adult']]];
	}

	#[DataProvider('enableTokens')]
	public function testCategoryUpdatesReadAsTheRuntimeModelTakesBlacklistEnable(?string $token, bool $on): void
	{
		$this->arrange([self::BLACKLIST => self::blacklist($token)]);

		$this->assertSame($on, $this->read()['settings']['schedule']['categoryUpdates']);
		$this->assertSame($on, $this->runtimeModel()['entries']['extra:bl']['enabled'], 'the runtime model enables the Blacklist job exactly then');
	}

	public function testCategoryUpdatesTurnedOnAreStoredAsEnableAndOffAsDisable(): void
	{
		$this->arrange([self::BLACKLIST => self::blacklist('Disable')]);
		$before = $GLOBALS['config'];
		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryUpdates'] = TRUE;
			return $s;
		});
		$this->assertWrittenOnly([self::BLACKLIST . '/blacklist_enable' => ['Disable', 'Enable']], $before, $reply);

		$GLOBALS['pfb_test_write_config_calls'] = [];
		unlink("{$this->dir}/pending");
		$before = $GLOBALS['config'];
		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryUpdates'] = FALSE;
			return $s;
		});
		$this->assertWrittenOnly([self::BLACKLIST . '/blacklist_enable' => ['Enable', 'Disable']], $before, $reply);
	}

	public function testABlacklistEnabledByAnotherTokenStaysAsItIsUntilCoreTurnsItOff(): void
	{
		$this->arrange([self::BLACKLIST => self::blacklist('on')]);
		$before = $GLOBALS['config'];
		$this->writeSchedule(static fn(array $s): array => $s);
		$this->assertNothingWritten($before, 'the token on, which the model reads as enabled and Core reads as true');

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryUpdates'] = FALSE;
			return $s;
		});
		$this->assertWrittenOnly([self::BLACKLIST . '/blacklist_enable' => ['on', 'Disable']], $before, $reply);
	}

	public function testABlacklistWithNoEnableKeyIsOffAndTurnedOnIsStoredAsEnable(): void
	{
		$this->arrange([self::BLACKLIST => self::blacklist(NULL)]);
		$before = $GLOBALS['config'];

		$reply = $this->writeSchedule(static function (array $s): array {
			$s['categoryUpdates'] = TRUE;
			return $s;
		});

		$this->assertWrittenOnly([self::BLACKLIST . '/blacklist_enable' => [NULL, 'Enable']], $before, $reply);
	}

	public function testAnOddOverrideTokenReadsAsNoOverrideAndADailyFrequencyAsNever(): void
	{
		$this->arrange([self::V4 => [self::group('A', ['schedule_override' => 'yes', 'schedule_weekday' => '1', 'schedule_hour' => '1', 'schedule_minute' => '0'])],
			self::BLACKLIST => array_merge(self::blacklist('Enable'), ['blacklist_freq' => 'Daily'])]);

		$schedule = $this->read()['settings']['schedule'];

		$this->assertSame(['id' => 'ipv4/A', 'override' => FALSE, 'weekday' => 1, 'hour' => 1, 'minute' => 0], $schedule['groups'][0]);
		$this->assertSame('Never', $schedule['categoryFrequency']);
	}

	// ----- the functions work from the current schedule they are given -----

	public function testTheFaultsKnowTheGroupsAndProvidersOfTheCurrentScheduleTheyAreGiven(): void
	{
		$current = $this->read()['settings']['schedule'];
		$value = $current;
		$value['groups'][] = ['id' => 'ipv4/OnlyInCurrent', 'override' => FALSE, 'weekday' => 7, 'hour' => 0, 'minute' => 0];
		$value['categoryProviders'][] = ['id' => 'only', 'selected' => FALSE, 'categories' => ''];
		$known = $current;
		$known['groups'][] = $value['groups'][4];
		$known['categoryProviders'][] = $value['categoryProviders'][3];

		$this->assertSame([], pfb_core_schedule_faults($value, $known), 'the ids of the given current schedule are the ones that exist');
		$this->assertSame(['schedule.groups[4].id', 'schedule.categoryProviders[3].id'], array_column(pfb_core_schedule_faults($value, $current), 'field'),
			'an id the given current schedule lacks is refused');
	}

	public function testTheMergeDiffsAgainstTheCurrentScheduleItIsGiven(): void
	{
		$current = $this->read()['settings']['schedule'];
		$wanted = $current;
		$current['weekday'] = 5;	// not what config.xml holds (3): the merge works from what it is given
		$sections = [];

		$keys = pfb_core_schedule_merge($wanted, $current, $sections);

		$this->assertSame(['gen/pfb_schedule_weekday' => '3'], $keys);
		$this->assertSame([], $sections);
	}

	public function testAWriteWithoutTheScheduleProjectionIsRefused(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['schedule']);

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('schedule', $reply['error']['message']);
	}
}
