<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4038 (sub-slice 9h): freezes today's reader of the Uber aggregate selection `gen/pfb_agg_types` (ADR-11) as the parity
 * fixture tests/core/fixtures/settings_aggregate_types_parity.json, for the derived field `aggregates` of Core's `policy/ip`.
 *   - A case is a stored value: `php` is today's reader, pfb_global()'s $pfb['agg_types'] expression on PfbConfig::read();
 *     `aggregates` is what the settings adapter answers, each type as its lower-case class.
 *   - The field is the Outpost's answer: a write that changes it stores nothing, as for the other derived fields.
 */
#[CoversFunction('pfb_core_policy_ip_fields')]
#[CoversFunction('pfb_core_settings_backend')]
final class CoreSettingsAggregateTypesParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_aggregate_types_parity.json';
	private const KEY = 'installedpackages/pfblockerng/config/0/pfb_agg_types';

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_agg_' . bin2hex(random_bytes(8));
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

	public function testTheFixtureHoldsTheSelectionsTheIpPageWritesAndTheHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame([1, 'policy/ip', 'aggregates'], [$doc['schema'], $doc['projection'], $doc['field']]);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['absent', 'empty', 'deny', 'all-four', 'other-order', 'repeated', 'unknown-and-empty-tokens', 'lower-case'] as $id) {
			$this->assertContains($id, $ids, "the coverage row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		foreach (['upper-case-class', 'unknown-class', 'repeated-class', 'not-a-list'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysReaderGivesTheFixturesTypesAndTheAdapterItsAggregates(array $case): void
	{
		if (array_key_exists('stored', $case)) {
			config_set_path(self::KEY, $case['stored']);
		}
		// today's reader, verbatim from pfb_global()
		$today = array_values(array_intersect(PFB_AGGREGATE_TYPES, array_filter(explode(',', PfbConfig::read('gen/pfb_agg_types')))));
		$this->assertSame($case['php'], $today, "{$case['id']}: today's selection");

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame($case['aggregates'], $reply['settings']['policy/ip']['aggregates'] ?? NULL, "{$case['id']}: {$case['description']}");
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	public function testAWriteThatChangesTheSelectionStoresNothingForIt(): void
	{
		config_set_path(self::KEY, 'Deny');
		$this->configXmlOnDisk();
		$read = $this->read();
		$this->assertSame([['class' => 'deny']], $read['settings']['policy/ip']['aggregates'] ?? NULL, 'before-state: the stored selection');
		$settings = $read['settings'];
		$settings['policy/ip']['aggregates'] = [];

		$this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('Deny', config_get_path(self::KEY), 'config.xml keeps the IP page\'s selection');
		$this->assertSame([['class' => 'deny']], $this->read()['settings']['policy/ip']['aggregates'] ?? NULL, 'the next read answers it again');
	}

	public function testTheRevisionMovesWhenTheSelectionChanges(): void
	{
		$base = $this->read()['revision'];

		config_set_path(self::KEY, 'Deny,Native');
		$selected = $this->read()['revision'];
		$this->assertNotSame($base, $selected, 'a selection moves the revision, so Core reads it again');

		config_set_path(self::KEY, '');
		$this->assertSame($base, $this->read()['revision'], 'the selection cleared moves it back');
	}
}
