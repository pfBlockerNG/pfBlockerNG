<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941: freezes today's PHP behaviour for Core's `schedule` projection as the parity fixture
 * tests/core/fixtures/settings_schedule_parity.json; go/pfb_core/settings and go/pfb_core/schedule pass the same file.
 *   - A case is a config.xml: the settings adapter's read answers the case's `schedule` and the feed projections it holds, and
 *     pfb_schedule_runtime_config(), run as shipped on it, computes the case's `model` (null: it rejects the config). The adapter's
 *     own write validation accepts what its read answered.
 *   - A refused row is hostile input: the adapter's write validation refuses it, naming `field`.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
#[CoversFunction('pfb_schedule_runtime_config')]
final class CoreSettingsScheduleParityTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_schedule_parity.json';
	private const SECTIONS = ['ipv4' => 'pfblockernglistsv4', 'ipv6' => 'pfblockernglistsv6', 'dnsbl' => 'pfblockerngdnsbl'];

	private array $priorConfig;
	private array $priorPfb;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		unset($GLOBALS['pfb_test_lock_events'], $GLOBALS['pfb_test_logger_calls']);
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

	/** config.xml as the case holds it: General's keys, the three group sections, the Blacklist. @param array<string, mixed> $config */
	private static function arrange(array $config): void
	{
		$paths = ['gen' => 'installedpackages/pfblockerng/config/0', 'blacklist' => 'installedpackages/pfblockerngblacklist'];
		foreach ($config as $key => $value) {
			config_set_path($paths[$key] ?? 'installedpackages/' . self::SECTIONS[$key] . '/config', $value);
		}
	}

	public function testTheFixtureHoldsTheCoverageMatrixAndHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('schedule', $doc['projection']);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['defaults', 'scheduled-off', 'default-slot', 'override-on', 'override-on-absent-slot', 'override-on-invalid-slot', 'override-off-stored-slot',
			'three-families-in-order', 'groups-that-do-not-project', 'blacklist-disabled', 'blacklist-weekly', 'blacklist-selected-without-categories',
			'blacklist-provider-excluded', 'blacklist-provider-not-selected', 'blacklist-never', 'feed-states', 'override-token-not-on',
			'blacklist-frequency-daily', 'blacklist-enable-on-token', 'blacklist-enable-lowercase-disable', 'blacklist-enable-zero-token'] as $id) {
			$this->assertContains($id, $ids, "the coverage matrix row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
		foreach (['group-id-without-family', 'group-id-unknown-family', 'group-id-name-with-dash', 'group-id-name-with-space', 'provider-id-zero',
			'provider-id-comma', 'provider-id-empty', 'provider-categories-markup', 'weekday-zero', 'weekday-eight', 'hour-24', 'minute-60',
			'minute-negative', 'minute-20', 'scheduled-updates-string'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesProjectionsAndModel(array $case): void
	{
		self::arrange($case['config']);

		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'read'], '/nonexistent', static fn(): array => []);

		$this->assertArrayHasKey('settings', $reply, "{$case['id']}: the read answered " . json_encode($reply));
		$this->assertSame($case['schedule'], $reply['settings']['schedule'] ?? NULL, "{$case['id']}: the schedule projection");
		$this->assertSame($case['feeds'], array_intersect_key($reply['settings'], $case['feeds']), "{$case['id']}: the feed projections the model is built from");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");

		$model = pfb_schedule_runtime_config();

		$this->assertSame($case['model'], self::shape($model), "{$case['id']}: pfb_schedule_runtime_config()");
	}

	/** @param ?array<string, mixed> $model @return ?array<string, mixed> the model as the fixture holds it */
	private static function shape(?array $model): ?array
	{
		if ($model === NULL) {
			return NULL;
		}
		$entries = [];
		foreach ($model['entries'] as $id => $entry) {
			$entries[] = ['id' => $id, 'cadence' => $entry['cadence'], 'enabled' => $entry['enabled'], 'override' => $entry['override']];
		}
		return ['scheduled' => $model['scheduled'], 'default' => $model['default'], 'entries' => $entries, 'config_hash' => $model['config_hash']];
	}

	/**
	 * @param array<string, mixed> $row
	 */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteValidationRefusesTheFixturesHostileInputNamingTheField(array $row): void
	{
		// A group Good and a provider ut1 exist: the refusal is the value's, not an id that names nothing
		config_set_path('installedpackages/pfblockernglistsv4/config', [['aliasname' => 'Good', 'action' => 'Disabled', 'cron' => 'Never']]);
		config_set_path('installedpackages/pfblockerngblacklist', ['item' => [['xml' => 'ut1', 'title' => 'UT1', 'feed' => 'https://example.org/ut1', 'selected' => 'adult']]]);
		$schedule = array_merge(['scheduledUpdates' => TRUE, 'weekday' => 7, 'hour' => 0, 'minute' => 0, 'groups' => [], 'categoryUpdates' => FALSE,
			'categoryFrequency' => 'Never', 'categoryProviders' => []], $row['schedule']);
		$group = ['override' => FALSE, 'weekday' => 7, 'hour' => 0, 'minute' => 0];
		$provider = ['selected' => FALSE, 'categories' => ''];
		$schedule['groups'] = array_map(static fn(array $g): array => $g + $group, $schedule['groups']);
		$schedule['categoryProviders'] = array_map(static fn(array $p): array => $p + $provider, $schedule['categoryProviders']);
		$settings = ['dns' => pfb_core_dns_settings(), 'feeds/ipv4' => ['groups' => []], 'feeds/ipv6' => ['groups' => []], 'feeds/dnsbl' => ['groups' => []], 'schedule' => $schedule];

		$refusal = pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => 1, 'settings' => $settings], static fn(): array => []);

		$this->assertSame('invalid_argument', $refusal['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($refusal));
		$this->assertContains("schedule.{$row['field']}", array_column($refusal['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']}");
	}
}
