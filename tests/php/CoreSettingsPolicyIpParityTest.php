<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PageStatementLoader.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: freezes today's PHP behaviour for Core's `policy/ip` projection (the IP page's deduplication and aggregation, the
 * Reputation page's limits and country/ET actions, the two suppression lists) as the parity fixture
 * tests/core/fixtures/settings_policy_ip_parity.json; go/pfb_core/settings passes the same file.
 *   - A case is a config.xml: `php` is what today's readers make of it (the statements and the Reputation block of
 *     sync_package_pfblockerng() in pfblockerng_apply.inc, run as shipped; pfb_create_suppression_file()), `policyIp` (over the
 *     fixture's defaults) is what the settings adapter's read answers. Where Core and today's PHP differ (a value no page offers) the
 *     case says why.
 *   - A refused row is a value Core refuses to read; the adapter's write refuses it too, naming the field.
 */
#[CoversFunction('pfb_core_settings')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsPolicyIpParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_policy_ip_parity.json';
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const REPUTATION_FROM = "\t// Reputation config variables";
	private const UNOBSERVED = ['suppression-v4-array', 'suppression-v6-array'];
	private const REPUTATION_TO = "\n\t// Starting variable to skip Reputation functions";

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_policy_ip_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb']['supptxt'] = "{$this->dir}/pfbsuppression.txt";
		$GLOBALS['pfb']['supptxt_v6'] = "{$this->dir}/pfbsuppression_v6.txt";
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

	/** config.xml as the case holds it; suppression text is stored base64 as the IP page stores it. @param array<string, mixed> $case */
	private function arrange(array $case): void
	{
		foreach ($case['config'] as $section => $keys) {
			foreach ($keys as $key => $value) {
				config_set_path(PFB_SECTIONS[$section] . "/{$key}", $value);
			}
		}
		foreach ($case['suppressionText'] ?? [] as $family => $text) {
			config_set_path(PFB_SECTIONS['ip'] . "/{$family}suppression", base64_encode($text));
		}
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode($reply));
		$this->assertArrayHasKey('policy/ip', $reply['settings'], 'the read answers the policy/ip projection: ' . json_encode(array_keys($reply['settings'])));
		return $reply;
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to its `policy/ip` */
	private function writePolicy(callable $change, ?int $revision = NULL): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['policy/ip'] = $change($settings['policy/ip']);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $revision ?? $read['revision'], 'settings' => $settings]);
	}

	/** @return array<string, mixed> $pfb after the statements and the Reputation block of sync_package_pfblockerng() ran over config.xml */
	private function syncReads(): array
	{
		$code = pfb_test_page_statement(self::APPLY, '/\$pfb\[\'dup\'\]\s*=/') . pfb_test_page_statement(self::APPLY, '/\$pfb\[\'agg\'\]\s*=/')
			. pfb_test_page_region(self::APPLY, self::REPUTATION_FROM, self::REPUTATION_TO);
		$pfb = &$GLOBALS['pfb'];
		// The block reads a key config.xml does not hold yet without isset(): PHP warns, and the `?: 'x'` after it is what the fixture freezes
		set_error_handler(static fn(int $errno, string $errstr): bool => str_starts_with($errstr, 'Undefined array key'), E_WARNING);
		try {
			eval($code);
		} finally {
			restore_error_handler();
		}
		return $pfb;
	}

	/** @return array{0: string, 1: string} what pfb_create_suppression_file() writes: the IPv4 and the IPv6 file ('' when there is none) */
	private function suppressionFiles(): array
	{
		$GLOBALS['pfb']['ipconfig'] = config_get_path(PFB_SECTIONS['ip'], []);
		pfb_create_suppression_file();
		return array_map(static fn(string $file): string => is_file($file) ? (string) file_get_contents($file) : '', [$GLOBALS['pfb']['supptxt'], $GLOBALS['pfb']['supptxt_v6']]);
	}

	public function testTheFixtureHoldsTheCoverageMatrixAndHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('policy/ip', $doc['projection']);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		$expected = ['defaults'];
		foreach (['dedup', 'aggregate', 'max', 'pMax', 'dMax'] as $toggle) {
			array_push($expected, ...array_map(static fn(string $v): string => "{$toggle}-{$v}", ['on', 'empty', 'upper', 'off', 'one', 'yes', 'array']));
		}
		foreach (['maxLimit', 'pMaxLimit', 'dMaxLimit'] as $limit) {
			array_push($expected, ...array_map(static fn(string $v): string => "{$limit}-{$v}", ['empty', 'zero', 'opt-5', 'opt-10', 'opt-15', 'opt-20', 'opt-25', 'opt-50', 'lowest',
				'non-option', 'negative', 'text', 'exponent', 'fraction', 'over-50', 'list', 'leading-zero', 'leading-space', 'array']));
		}
		array_push($expected, 'ccwhite-ignore', 'ccwhite-match', 'ccwhite-match-capitalized', 'ccwhite-empty', 'ccblack-block', 'ccblack-match', 'ccblack-empty',
			'countryWhitelist-one', 'countryWhitelist-several', 'countryWhitelist-page-form', 'countryWhitelist-three-letter', 'countryWhitelist-lower-case',
			'countryWhitelist-repeated', 'countryWhitelist-unsafe-csv', 'countryWhitelist-rep-suffix', 'countryWhitelist-array',
			'etBlock-one', 'etBlock-page-form', 'etBlock-repeated', 'etBlock-no-prefix', 'etBlock-unsafe-csv', 'etMatch-one', 'etMatch-page-form', 'etMatch-array',
			'suppression-v4-one', 'suppression-v4-several', 'suppression-v4-comments-blank-crlf', 'suppression-v4-mask-lowest', 'suppression-v4-mask-highest',
			'suppression-v4-not-an-address', 'suppression-v4-no-mask', 'suppression-v4-leading-zero-prefix', 'suppression-v4-zero-prefix', 'suppression-v4-mask-too-low',
			'suppression-v4-mask-too-high', 'suppression-v4-ipv6-entry', 'suppression-v4-invalid-utf8', 'suppression-v4-nul-inside-line', 'suppression-v4-base64-garbage',
			'suppression-v4-array', 'suppression-v6-one', 'suppression-v6-several', 'suppression-v6-comments-blank-crlf', 'suppression-v6-upper-case-hex',
			'suppression-v6-mask-lowest', 'suppression-v6-mask-highest', 'suppression-v6-zone', 'suppression-v6-mask-31', 'suppression-v6-ipv4-entry', 'suppression-v6-array');
		foreach ($expected as $id) {
			$this->assertContains($id, $ids, "the coverage matrix row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
		foreach (['max-limit-negative', 'p-max-limit-51', 'max-limit-string', 'country-three-letters', 'country-lower-case', 'country-repeated', 'et-block-no-prefix',
			'suppression-v4-not-an-address', 'suppression-v4-leading-zero-prefix', 'suppression-v4-zero-prefix', 'suppression-v6-zone', 'suppression-v6-upper-case',
			'suppression-v4-ipv6-entry', 'white-action-capitalized', 'black-action-capitalized'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
		$this->assertSame(['dedup', 'aggregate', 'max', 'maxLimit', 'pMax', 'pMaxLimit', 'dMax', 'dMaxLimit', 'countryWhitelistAction', 'countryBlacklistAction',
			'countryWhitelist', 'etBlock', 'etMatch', 'suppressionV4', 'suppressionV6', 'aggregates'], array_keys($doc['defaults']), 'the defaults name every field in the protocol order');
	}

	public function testTheSyncBlockStillReadsTheReputationKeysWithTheFallbackAndTheCsvFilter(): void
	{
		$region = pfb_test_page_region(self::APPLY, self::REPUTATION_FROM, self::REPUTATION_TO);

		foreach (['p24_max_var', 'p24_dmax_var', 'p24_pmax_var', 'ccwhite', 'ccblack', 'ccexclude', 'etblock', 'etmatch'] as $key) {
			$this->assertStringContainsString("'{$key}'", $region, "the block reads {$key}");
		}
		$this->assertStringContainsString("?: 'x'", $region, 'an unset value is x');
		$this->assertStringContainsString('PFB_FILTER_CSV', $region, 'a value is the stored CSV or x');
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesObservations(array $case): void
	{
		$this->arrange($case);
		$pfb = $this->syncReads();
		$seen = [
			'dup'         => static fn(): bool => $pfb['dup'] === PfbToggle::On,
			'agg'         => static fn(): bool => $pfb['agg'] === PfbToggle::On,
			'rep'         => static fn(): bool => $pfb['rep'] === PfbToggle::On,
			'prep'        => static fn(): bool => $pfb['prep'] === PfbToggle::On,
			'drep'        => static fn(): bool => $pfb['drep'] === PfbToggle::On,
			'max'         => static fn(): string => $pfb['max'],
			'dmax'        => static fn(): string => $pfb['dmax'],
			'pmax'        => static fn(): string => $pfb['pmax'],
			'ccwhite'     => static fn(): string => $pfb['ccwhite'],
			'ccblack'     => static fn(): string => $pfb['ccblack'],
			'ccexclude'   => static fn(): string => $pfb['ccexclude'],
			'etblock'     => static fn(): string => $pfb['etblock'],
			'etmatch'     => static fn(): string => $pfb['etmatch'],
			'suppression' => fn(): array => $this->suppressionFiles(),
			'suppressionValid' => fn(): array => array_map(static fn(string $text): array => array_values(array_filter(explode("\n", $text),
				static fn(string $line): bool => $line !== '' && pfb_validate_suppression_line($line, str_contains($line, ':') ? 'ipv6' : 'ipv4') === NULL)), $this->suppressionFiles()),
		];
		$this->assertSame(in_array($case['id'], self::UNOBSERVED, TRUE), $case['php'] === [], "{$case['id']}: the case observes today's PHP, or says why it cannot");
		foreach ($case['php'] as $key => $expected) {
			$this->assertSame($expected, $seen[$key](), "{$case['id']}: today's PHP reading of {$key}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTheAdapterProjectsTheFixturesPolicyIp(array $case): void
	{
		$this->arrange($case);

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame(array_replace(self::fixture()['defaults'], $case['policyIp']), $reply['settings']['policy/ip'], "{$case['id']}: the policy/ip projection");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesTheFixturesHostileValueNamingTheFieldAndWritesNothing(array $row): void
	{
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->assertNoPhpWarning(fn(): array => $this->writePolicy(static fn(array $policy): array => array_replace($policy, $row['policyIp'])));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$this->assertContains("policy/ip.{$row['field']}", array_column($reply['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']} " . json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$row['id']}: write_config() was called");
		$this->assertSame($before, $GLOBALS['config'], "{$row['id']}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$row['id']}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$row['id']}: the config lock is still held");
	}
}
