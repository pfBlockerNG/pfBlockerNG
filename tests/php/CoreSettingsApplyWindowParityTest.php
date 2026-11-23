<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4038 (sub-slice 9c): freezes today's reader of the apply window `gen/pfb_quiet_hours` as the parity fixture
 * tests/core/fixtures/settings_apply_window_parity.json, for the field `applyWindow` of Core's read-only `ingest`.
 *   - A case is a stored value: `php` is today's decision, pfb_quiet_hours_in_window() on (string) PfbConfig::read(), at each
 *     of the fixture's instants; `applyWindow` is what the settings adapter answers, one spelling for one window and `''` for
 *     every value today's reader takes as no window. go/pfb_core/schedule proves InApplyWindow on it gives `php` again.
 *   - The adapter's write refuses a changed window: config.xml owns it.
 */
#[CoversFunction('pfb_core_ingest_settings')]
#[CoversFunction('pfb_quiet_hours_in_window')]
#[CoversFunction('pfb_quiet_hours_bounds')]
#[CoversFunction('pfb_core_settings_backend')]
final class CoreSettingsApplyWindowParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_apply_window_parity.json';
	private const KEY = 'installedpackages/pfblockerng/config/0/pfb_quiet_hours';

	private array $priorConfig;
	private array $priorPfb;
	private string $priorZone;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->priorZone = date_default_timezone_get();
		date_default_timezone_set('UTC');	// the instants are minutes after midnight UTC, as the Go side reads them
		$this->dir = sys_get_temp_dir() . '/pfb_core_window_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir("{$this->dir}/db", 0700, TRUE));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['dbdir'] = "{$this->dir}/db";
		$GLOBALS['pfb']['core_revision_key'] = "{$this->dir}/db/core_revision.key";
		@pfb_core_revision_key();	// made here: its first creation warns, which the no-warning read below must not see
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		date_default_timezone_set($this->priorZone);
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

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode($reply));
		return $reply;
	}

	public function testTheFixtureHoldsTheWindowsTodaysPageWritesAndTheHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame([1, 'ingest', 'applyWindow'], [$doc['schema'], $doc['projection'], $doc['field']]);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['absent', 'empty', 'quarter-hours', 'wraps-midnight', 'zero-width', 'single-digit-hours', 'trailing-newline',
			'spaces-around-dash', 'words', 'hour-24', 'minute-60', 'array', 'empty-array'] as $id) {
			$this->assertContains($id, $ids, "the coverage row {$id}");
		}
		foreach ($doc['cases'] as $case) {
			$this->assertCount(count($doc['instants']), $case['php'], "{$case['id']}: one decision per instant");
		}
		$refused = array_column($doc['refused'], 'id');
		foreach (['spaces-around-dash', 'single-digit-hours', 'trailing-newline', 'hour-24', 'array', 'number'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysReaderGivesTheFixturesDecisionsAndTheAdapterItsApplyWindow(array $case): void
	{
		if (array_key_exists('stored', $case)) {
			config_set_path(self::KEY, $case['stored']);
		}
		$decisions = [];
		foreach (self::fixture()['instants'] as $minute) {
			// today's reader, as pfblockerng_cron.inc and the tick call it; it warns on an array, which is why the adapter does not use it
			$decisions[] = pfb_quiet_hours_in_window($minute * 60, (string) @PfbConfig::read('gen/pfb_quiet_hours'));
		}
		$this->assertSame($case['php'], $decisions, "{$case['id']}: today's decision at each instant");

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame($case['applyWindow'], $reply['settings']['ingest']['applyWindow'] ?? NULL, "{$case['id']}: {$case['description']}");
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	public function testTheAdaptersWriteRefusesAChangedApplyWindowAndWritesNothing(): void
	{
		config_set_path(self::KEY, '02:00-06:00');
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertSame('02:00-06:00', $read['settings']['ingest']['applyWindow'] ?? NULL, 'before-state: the stored window');
		$settings = $read['settings'];
		$settings['ingest']['applyWindow'] = '';

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame([['field' => 'ingest.applyWindow', 'message' => 'read-only: config.xml and the platform own it']], $reply['error']['fieldErrors'] ?? NULL);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$this->assertSame($before, $GLOBALS['config'], 'config.xml is unchanged');
	}

	public function testTheRevisionMovesWhenTheWindowChanges(): void
	{
		$base = $this->read()['revision'];

		config_set_path(self::KEY, '02:00-06:00');
		$windowed = $this->read()['revision'];
		$this->assertNotSame($base, $windowed, 'a window set moves the revision, so Core reads it again');

		config_set_path(self::KEY, '');
		$this->assertSame($base, $this->read()['revision'], 'the window cleared moves it back');
	}
}
