<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941: replays the tick corpus, go/pfb_core/schedule/testdata/tick.json (schema: the "Tick corpus" section of
 * that directory's README.md), through the functions pfblockerng_tick() calls for its feed plan and its reservation.
 * Core's Go port (package schedule) replays the same file and must give the same answers.
 */
#[CoversFunction('pfb_schedule_feed_plan')]
#[CoversFunction('pfb_schedule_reserve')]
final class ScheduleTickCorpusTest extends TestCase
{
	public const CORPUS = __DIR__ . '/../../go/pfb_core/schedule/testdata/tick.json';
	/** Section => the input keys of its cases (besides id, description and expect), all required. */
	public const SECTIONS = [
		'feed_plan' => ['timezone', 'scheduled', 'default', 'now', 'entries', 'state'],
		'reserve'   => ['state', 'occurrences'],
	];
	private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_schedule_tick_corpus_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/** @return array<string, array{string, array<string, mixed>}> */
	public static function cases(): array
	{
		$doc = json_decode((string) file_get_contents(self::CORPUS), TRUE, 64, JSON_THROW_ON_ERROR);
		$keys = array_merge(['schema'], array_keys(self::SECTIONS));
		if (!is_array($doc) || array_keys($doc) !== $keys || $doc['schema'] !== 1) {
			throw new RuntimeException('tick.json must be {"schema": 1, ' . implode(', ', array_keys(self::SECTIONS)) . '} in that order');
		}
		$out = [];
		foreach (self::SECTIONS as $section => $inputs) {
			if (!is_array($doc[$section]) || $doc[$section] === [] || !array_is_list($doc[$section])) {
				throw new RuntimeException("tick.json: {$section} must be a non-empty list");
			}
			$wanted = array_merge(['id', 'description'], $inputs, ['expect']);
			foreach ($doc[$section] as $i => $case) {
				if (!is_array($case) || array_keys($case) !== $wanted) {
					throw new RuntimeException("tick.json: {$section}[{$i}] must hold exactly " . implode(', ', $wanted) . ' in that order');
				}
				if (!is_string($case['id']) || $case['id'] === '' || !is_string($case['description']) || $case['description'] === '') {
					throw new RuntimeException("tick.json: {$section}[{$i}] needs a non-empty id and description");
				}
				$name = "{$section}/{$case['id']}";
				if (isset($out[$name])) {
					throw new RuntimeException("tick.json: duplicate id {$name}");
				}
				$out[$name] = [$section, $case];
			}
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTickMatchesCorpus(string $section, array $case): void
	{
		$file = "{$this->dir}/pfb_schedule_state.json";
		if ($section === 'reserve') {
			$items = array_map(static fn (array $item): object => (object) $item, $case['state']);
			file_put_contents($file, json_encode(['schema' => 1, 'items' => (object) $items], self::JSON_FLAGS));
		}
		$before = is_file($file) ? file_get_contents($file) : NULL;
		$expect = self::canon($case['expect']);
		$actual = self::canon(self::evaluate($section, $case, $this->dir));
		$this->assertSame(
			$expect,
			$actual,
			"{$section}/{$case['id']}: {$case['description']}\nexpected " . json_encode($expect, self::JSON_FLAGS)
				. "\nactual   " . json_encode($actual, self::JSON_FLAGS)
		);
		if ($section === 'reserve' && $actual === 'rejected') {
			// A rejected reservation is all or nothing: not even the valid ids of the call are written.
			$this->assertSame($before, file_get_contents($file), "{$section}/{$case['id']}: a rejected reservation changed the state file");
		}
	}

	/**
	 * The tick's answer for one case, in the corpus's `expect` shape (objects as arrays).
	 *
	 * @param array<string, mixed> $case
	 */
	private static function evaluate(string $section, array $case, string $dir): mixed
	{
		switch ($section) {
			case 'feed_plan':
				$entries = [];
				foreach ($case['entries'] as $entry) {
					$entries[$entry['id']] = ['cadence' => $entry['cadence'], 'enabled' => $entry['enabled'], 'has_active_rows' => TRUE,
						'override' => $entry['override']];
				}
				$plan = pfb_schedule_feed_plan(
					['scheduled' => $case['scheduled'], 'default' => $case['default'], 'entries' => $entries],
					['schema' => 1, 'items' => $case['state']],
					$case['now'],
					new DateTimeZone($case['timezone'])
				);
				return ['due' => $plan['due'], 'occurrences' => $plan['occurrences']];
			case 'reserve':
				if (!pfb_schedule_reserve($case['occurrences'], $dir)) {
					return 'rejected';
				}
				$state = pfb_schedule_state_read($dir);
				if ($state === NULL) {
					throw new RuntimeException('published schedule state is unreadable');
				}
				return $state['items'];
		}
		throw new RuntimeException("unknown section {$section}");
	}

	/** Key order of JSON objects is not part of an answer; list order is. */
	private static function canon(mixed $value): mixed
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
