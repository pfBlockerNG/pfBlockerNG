<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: freezes today's PHP behaviour for Core's read-only `hooks` projection (the Update hook rows) as the parity fixture
 * tests/core/fixtures/settings_hooks_parity.json; go/pfb_core/settings passes the same file.
 *   - A case is what config.xml stores under `hooks`: `php` is what today's runner makes of it (pfb_get_hooks() per fire point, its
 *     timeouts by pfb_hook_timeout(), and which scripts pfb_hook_script_valid() lets it run from a directory that holds a file of
 *     every name that can be one), `value` is the projection the settings adapter's read answers. A row the runner would never run
 *     is not listed; where Core is stricter than today's PHP (a control character in a name) the case says so. A case without `php`
 *     holds an array where a string is stored, which today's readers warn about.
 *   - A refused row is a value Core refuses to read. The projection is read-only: the adapter's write refuses any difference from
 *     what config.xml projects, naming `hooks.rows`.
 */
#[CoversFunction('pfb_core_hooks_settings')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsHooksParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_hooks_parity.json';
	private const HOOKS = 'installedpackages/pfblockerng/config/0/hooks';
	private const ROWS = [['when' => 'pre', 'script' => 'hook_pre_a.sh', 'description' => 'First', 'timeout' => '30', 'enabled' => 'on'],
		['when' => 'post', 'script' => 'hook_post_b.py', 'enabled' => '']];

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_hooks_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir("{$this->dir}/scripts", 0700, TRUE));
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
		return array_column(array_map(static fn(array $case): array => [$case['id'], [$case]], self::fixture()['cases']), 1, 0);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function refused(): array
	{
		return array_column(array_map(static fn(array $row): array => [$row['id'], [$row]], self::fixture()['refused']), 1, 0);
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('hooks', $reply['settings'] ?? [], 'the read answers the hooks projection: ' . json_encode(array_keys($reply['settings'] ?? $reply)));
		return $reply;
	}

	public function testTheFixtureHoldsTheCoverageMatrixAndHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame([1, 'hooks', ['rows' => []]], [$doc['schema'], $doc['projection'], $doc['defaults']]);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['no-hooks', 'row-list', 'bare-list', 'lone-row', 'hooks-is-a-string', 'row-is-a-string', 'rows-pre-and-post', 'same-script-twice',
			'enabled-on', 'enabled-empty', 'enabled-capitalized', 'enabled-absent', 'enabled-array', 'timeout-absent', 'timeout-empty', 'timeout-zero', 'timeout-thirty',
			'timeout-negative', 'timeout-suffix', 'timeout-array', 'description-trimmed', 'description-control-characters', 'description-array',
			'script-empty-middle', 'script-slash', 'script-absolute', 'script-parent', 'script-dot-dot', 'script-leading-dash', 'script-trailing-line-break',
			'script-wrong-fire-point', 'script-wrong-extension', 'script-no-prefix', 'script-control-character', 'script-empty', 'script-array',
			'when-capitalized', 'when-both', 'when-absent', 'when-array', 'row-not-an-object'] as $id) {
			$this->assertContains($id, $ids, "the coverage matrix row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
		foreach (['script-slash', 'script-parent', 'script-leading-dash', 'script-wrong-extension', 'script-wrong-fire-point', 'script-control-character',
			'when-both', 'timeout-zero', 'timeout-negative', 'id-not-a-number', 'id-repeated'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesObservations(array $case): void
	{
		if ($case['php'] === []) {
			$this->assertStringContainsString('array', strtolower($case['description']), "{$case['id']}: only an array where a string is stored goes unobserved");
			return;
		}
		$config = array_key_exists('stored', $case) ? ['hooks' => $case['stored']] : [];
		$scripts = "{$this->dir}/scripts";
		foreach (array_keys($case['php']['valid'] ?? []) as $name) {
			$name = (string) $name;
			if (!str_contains($name, '/') && $name !== '..') {
				$this->assertSame(0, file_put_contents("{$scripts}/{$name}", ''), "a file named as the script {$name}");
			}
		}
		foreach (['pre', 'post'] as $when) {
			$hooks = pfb_get_hooks($config, $when);
			$this->assertSame($case['php'][$when], array_column($hooks, 'script'), "{$case['id']}: the scripts of the rows pfb_get_hooks() gives the {$when} fire point");
			if (isset($case['php']['timeouts'][$when])) {
				$this->assertSame($case['php']['timeouts'][$when], array_map('pfb_hook_timeout', $hooks), "{$case['id']}: their timeouts");
			}
			foreach ($hooks as $hook) {
				if (isset($case['php']['valid'][$hook['script']])) {
					$this->assertSame($case['php']['valid'][$hook['script']], pfb_hook_script_valid($hook['script'], $when, $scripts),
						"{$case['id']}: whether the runner runs " . json_encode($hook['script']) . " at {$when}");
				}
			}
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTheAdapterProjectsTheFixturesHooks(array $case): void
	{
		if (array_key_exists('stored', $case)) {
			config_set_path(self::HOOKS, $case['stored']);
		}

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame($case['value'], $reply['settings']['hooks'], "{$case['id']}: {$case['description']}");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	public function testAScriptOrDescriptionThatIsNotUtf8IsNoRowAndNoText(): void
	{
		config_set_path(self::HOOKS . '/row', [['when' => 'pre', 'script' => "hook_pre_\xff.sh", 'enabled' => 'on'],
			['when' => 'pre', 'script' => 'hook_pre_ok.sh', 'description' => "a\xffb", 'enabled' => 'on']]);

		$rows = $this->assertNoPhpWarning(fn(): array => $this->read())['settings']['hooks']['rows'];

		$this->assertSame(['1'], array_column($rows, 'id'), 'the row whose script is not text is not listed');
		$this->assertTrue(mb_check_encoding($rows[0]['description'], 'UTF-8'), 'the description Core gets is text: ' . bin2hex($rows[0]['description']));
	}

	/** @return array<string, array{0: callable(array<string, mixed>): mixed}> a change to the projection the read answered */
	public static function changes(): array
	{
		return [
			'a row enabled'         => [static function (array $h): array { $h['rows'][1]['enabled'] = TRUE; return $h; }],
			'a timeout changed'     => [static function (array $h): array { $h['rows'][0]['timeout'] = 31; return $h; }],
			'a script changed'      => [static function (array $h): array { $h['rows'][0]['script'] = 'hook_pre_other.sh'; return $h; }],
			'a row added'           => [static function (array $h): array { $h['rows'][] = ['id' => '2', 'when' => 'pre', 'script' => 'hook_pre_n.sh', 'description' => '', 'timeout' => 60, 'enabled' => TRUE]; return $h; }],
			'a row removed'         => [static function (array $h): array { array_pop($h['rows']); return $h; }],
			'the rows reordered'    => [static function (array $h): array { $h['rows'] = array_reverse($h['rows']); return $h; }],
			'no rows'               => [static fn(array $h): array => ['rows' => []]],
			'a field left out'      => [static function (array $h): array { unset($h['rows'][0]['description']); return $h; }],
			'rows left out'         => [static fn(array $h): array => []],
			'an unknown field'      => [static fn(array $h): array => $h + ['bogus' => 1]],
		];
	}

	#[DataProvider('changes')]
	public function testAWriteThatChangesHooksIsRefusedNamingItAndWritesNothing(callable $change): void
	{
		config_set_path(self::HOOKS . '/row', self::ROWS);
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertCount(2, $read['settings']['hooks']['rows'], 'before-state: two rows project');
		$settings = $read['settings'];
		$settings['hooks'] = $change($settings['hooks']);

		$reply = $this->assertNoPhpWarning(fn(): array => $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$fields = array_column($reply['error']['fieldErrors'] ?? [], 'field');
		$this->assertNotSame([], $fields, json_encode($reply));
		foreach ($fields as $field) {
			$this->assertStringStartsWith('hooks.', $field, 'every fault names the read-only projection: ' . json_encode($reply));
		}
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'write_config() was called');
		$this->assertSame($before, $GLOBALS['config'], 'config.xml changed');
		$this->assertFileDoesNotExist("{$this->dir}/pending", 'pending changes were marked');
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesTheFixturesHostileRows(array $row): void
	{
		$this->configXmlOnDisk();
		$read = $this->read();
		$settings = $read['settings'];
		$settings['hooks'] = $row['value'];

		$reply = $this->assertNoPhpWarning(fn(): array => $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$this->assertContains('hooks.rows', array_column($reply['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']}");
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$row['id']}: write_config() was called");
	}

	public function testAWriteThatLeavesHooksAsItWasStoresTheOtherProjectionsAndAnUnchangedWriteIsANoOp(): void
	{
		config_set_path(self::HOOKS . '/row', self::ROWS);
		$this->configXmlOnDisk();
		$read = $this->read();

		$unchanged = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $read['settings']]);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $unchanged, 'an unchanged write answers the revision it was at');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written for an unchanged write');

		$settings = $read['settings'];
		$settings['dns']['control'] = TRUE;
		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertSame(self::ROWS, config_get_path(self::HOOKS . '/row'), 'the stored rows are untouched');
		$this->assertSame($read['settings']['hooks'], $this->read()['settings']['hooks'], 'hooks is as it was');
	}

	public function testAWriteWhoseRowsListTheirMembersInAnotherOrderIsUnchanged(): void
	{
		config_set_path(self::HOOKS . '/row', self::ROWS);
		$this->configXmlOnDisk();
		$read = $this->read();
		$settings = $read['settings'];
		// Core's JSON lists an object's members in sorted order, not the adapter's
		$settings['hooks']['rows'] = array_map(static function (array $row): array {
			ksort($row);
			return $row;
		}, $settings['hooks']['rows']);
		$this->assertNotSame(array_keys($read['settings']['hooks']['rows'][0]), array_keys($settings['hooks']['rows'][0]), 'the members are in another order');

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply, 'the same rows are no change, whatever order their members come in');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	public function testAChangedHooksBeneathAStaleRevisionIsAConflictNotARefusal(): void
	{
		config_set_path(self::HOOKS . '/row', self::ROWS);
		$this->configXmlOnDisk();
		$read = $this->read();
		config_set_path(self::HOOKS . '/row/1/enabled', 'on');	// the Hooks page saved after Core read
		$this->configXmlOnDisk();

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $read['settings']]);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, 'Core read before the row changed: it reads again: ' . json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	public function testTheRevisionMovesWhenARowChanges(): void
	{
		config_set_path(self::HOOKS . '/row', self::ROWS);
		$base = $this->read()['revision'];
		$seen = [$base => 'the start'];
		foreach (['enabled' => ['1/enabled', 'on'], 'timeout' => ['0/timeout', '45'], 'description' => ['0/description', 'Second'], 'script' => ['0/script', 'hook_pre_z.sh']] as $why => [$path, $value]) {
			config_set_path(self::HOOKS . '/row', self::ROWS);
			config_set_path(self::HOOKS . "/row/{$path}", $value);
			$revision = $this->read()['revision'];
			$this->assertArrayNotHasKey($revision, $seen, "a changed {$why} moves the revision, to one no other change gave");
			$seen[$revision] = $why;
		}
	}

	public function testAWriteWithoutHooksIsMalformedNamingTheProjections(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['hooks']);

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('hooks', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
	}
}
