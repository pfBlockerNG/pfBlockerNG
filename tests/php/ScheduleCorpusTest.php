<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3938 (map #3813): replays the schedule evaluation parity corpus, go/pfb_core/schedule/testdata/schedule.json
 * (schema: that directory's README.md), through the REAL old-path functions. Core's Go port (package schedule) replays
 * the same file and must give the same answers: a case that diverges fails on one side or the other.
 *
 * Issue #3941: Core owns the scheduler now, so the PHP functions behind the `next_occurrence`, `plan`, `extra_plan`, `next_due`,
 * `state_valid`, `set_pending` and `record_outcome` sections are gone (RETIRED): the corpus keeps them, Go replays them alone.
 * The PHP sections left are the ones a function of the Outpost still answers: `quiet_hours`, `model` and `blacklist`.
 */
#[CoversFunction('pfb_quiet_hours_in_window')]
#[CoversFunction('pfb_schedule_runtime_model')]
#[CoversFunction('pfb_schedule_runtime_config')]
final class ScheduleCorpusTest extends TestCase
{
	public const CORPUS = __DIR__ . '/../../go/pfb_core/schedule/testdata/schedule.json';
	/** Section => the input keys of its cases (besides id, description and expect), all required. */
	public const SECTIONS = [
		'next_occurrence' => ['timezone', 'cadence', 'weekday', 'hour', 'minute', 'reference'],
		'plan'            => ['timezone', 'default', 'now', 'groups'],
		'extra_plan'      => ['timezone', 'default', 'now', 'entries', 'state', 'cache', 'geoip_ready'],
		'next_due'        => ['timezone', 'scheduled', 'default', 'now', 'entries', 'state'],
		'quiet_hours'     => ['timezone', 'now', 'window'],
		'state_valid'     => ['input'],
		'set_pending'     => ['state', 'occurrences'],
		'record_outcome'  => ['state', 'item', 'outcome', 'now', 'expected_occurrence'],
		'model'           => ['general', 'sections', 'extras'],
		'blacklist'       => ['blacklist'],
	];
	/** Sections whose PHP function the cutover removed; the corpus still holds them for Core's runner. */
	private const RETIRED = ['next_occurrence', 'plan', 'extra_plan', 'next_due', 'state_valid', 'set_pending', 'record_outcome'];
	private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;
	private string $originalZone = '';

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->originalZone = date_default_timezone_get();
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		date_default_timezone_set($this->originalZone);
	}

	/** @return array<string, array{string, array<string, mixed>}> */
	public static function cases(): array
	{
		$doc = json_decode((string) file_get_contents(self::CORPUS), TRUE, 64, JSON_THROW_ON_ERROR);
		$keys = array_merge(['schema'], array_keys(self::SECTIONS));
		if (!is_array($doc) || array_keys($doc) !== $keys || $doc['schema'] !== 1) {
			throw new RuntimeException('schedule.json must be {"schema": 1, ' . implode(', ', array_keys(self::SECTIONS)) . '} in that order');
		}
		$out = [];
		foreach (self::SECTIONS as $section => $inputs) {
			if (!is_array($doc[$section]) || $doc[$section] === [] || !array_is_list($doc[$section])) {
				throw new RuntimeException("schedule.json: {$section} must be a non-empty list");
			}
			$wanted = array_merge(['id', 'description'], $inputs, ['expect']);
			foreach ($doc[$section] as $i => $case) {
				if (!is_array($case) || array_keys($case) !== $wanted) {
					throw new RuntimeException("schedule.json: {$section}[{$i}] must hold exactly " . implode(', ', $wanted) . ' in that order');
				}
				if (!is_string($case['id']) || $case['id'] === '' || !is_string($case['description']) || $case['description'] === '') {
					throw new RuntimeException("schedule.json: {$section}[{$i}] needs a non-empty id and description");
				}
				$name = "{$section}/{$case['id']}";
				if (isset($out[$name])) {
					throw new RuntimeException("schedule.json: duplicate id {$name}");
				}
				if (!in_array($section, self::RETIRED, TRUE)) {
					$out[$name] = [$section, $case];
				}
			}
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testOldPathMatchesCorpus(string $section, array $case): void
	{
		$expect = self::canon($case['expect']);
		$actual = self::canon(self::evaluate($section, $case));
		$this->assertSame(
			$expect,
			$actual,
			"{$section}/{$case['id']}: {$case['description']}\nexpected " . json_encode($expect, self::JSON_FLAGS)
				. "\nactual   " . json_encode($actual, self::JSON_FLAGS)
		);
	}

	/**
	 * The old path's answer for one case, in the corpus's `expect` shape (objects as arrays).
	 *
	 * @param array<string, mixed> $case
	 */
	public static function evaluate(string $section, array $case): mixed
	{
		$zone = isset($case['timezone']) ? new DateTimeZone($case['timezone']) : NULL;
		switch ($section) {
			case 'quiet_hours':
				date_default_timezone_set($case['timezone']);
				return pfb_quiet_hours_in_window($case['now'], $case['window']);
			case 'model':
				$reason = NULL;
				$model = pfb_schedule_runtime_model($case['general'], $case['sections'], $case['extras'] ?? [], $reason);
				return $model === NULL ? ['reject' => $reason] : self::modelShape($model);
			case 'blacklist':
				$GLOBALS['config'] = [];
				config_set_path('installedpackages/pfblockerng/config/0', [
					'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '3', 'pfb_schedule_hour' => '2', 'pfb_schedule_minute' => '15',
				]);
				foreach (['pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsbl'] as $list) {
					config_set_path("installedpackages/{$list}/config", []);
				}
				config_set_path('installedpackages/pfblockerngblacklist', $case['blacklist']);
				$GLOBALS['pfb_test_logger_calls'] = [];
				$model = pfb_schedule_runtime_config();
				if ($model === NULL) {
					$message = (string) (end($GLOBALS['pfb_test_logger_calls'])['message'] ?? '');
					return ['reject' => preg_replace('/^Schedule: runtime model rejected - /', '', $message)];
				}
				return ['enabled' => $model['entries']['extra:bl']['enabled'], 'cadence' => $model['entries']['extra:bl']['cadence']];
		}
		throw new RuntimeException("unknown section {$section}");
	}

	/** @param array<string, mixed> $model */
	private static function modelShape(array $model): array
	{
		$entries = [];
		foreach ($model['entries'] as $id => $entry) {
			if ($entry['has_active_rows'] !== TRUE) {
				throw new RuntimeException("model entry {$id} lacks has_active_rows");
			}
			$entries[] = ['id' => $id, 'cadence' => $entry['cadence'], 'enabled' => $entry['enabled'], 'override' => $entry['override']];
		}
		return ['scheduled' => $model['scheduled'], 'default' => $model['default'], 'entries' => $entries, 'config_hash' => $model['config_hash']];
	}

	/** Key order of JSON objects is not part of an answer; list order is. */
	public static function canon(mixed $value): mixed
	{
		if (!is_array($value)) {
			return $value;
		}
		$value = array_map(self::canon(...), $value);
		if (!array_is_list($value)) {
			ksort($value, SORT_STRING);
		}
		return $value;
	}
}
