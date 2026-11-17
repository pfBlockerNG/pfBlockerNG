<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: freezes today's PHP behaviour for Core's `extras` projection (the MaxMind account, key, locale and CSV switch, the
 * IPinfo token, the TOP1M provider and its token) as the parity fixture tests/core/fixtures/settings_extras_parity.json;
 * go/pfb_core/settings passes the same file.
 *   - A case is a config.xml: `php` is what pfb_global() and the gateway read of it today, `extras` (over the fixture's defaults) is
 *     what the settings adapter's read answers. Where Core and today's PHP differ (a value no page stores) the case says why. A case
 *     without `php` holds an array where a string is stored, which today's readers warn about.
 *   - A refused row is a value Core refuses to read; the adapter's write refuses it too, naming the field.
 * The three secrets travel in clear between the adapter and Core: only Core's API hides them.
 */
#[CoversFunction('pfb_core_settings')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsExtrasParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_extras_parity.json';
	private const IP = 'installedpackages/pfblockerngipsettings/config/0';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_extras_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		config_set_path(self::DNSBL, ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
		$GLOBALS['g']['unbound_chroot_path'] = $this->dir;
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
		return array_column(array_map(static fn(array $case): array => [$case['id'], [$case]], self::fixture()['cases']), 1, 0);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function refused(): array
	{
		return array_column(array_map(static fn(array $row): array => [$row['id'], [$row]], self::fixture()['refused']), 1, 0);
	}

	/** @param array<string, array<string, mixed>> $config section alias => key => stored value */
	private function arrange(array $config): void
	{
		foreach ($config as $section => $keys) {
			foreach ($keys as $key => $value) {
				config_set_path(PFB_SECTIONS[$section] . "/{$key}", $value);
			}
		}
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('extras', $reply['settings'] ?? [], 'the read answers the extras projection: ' . json_encode(array_keys($reply['settings'] ?? $reply)));
		return $reply;
	}

	/** @return array<string, mixed> Core's write of the read with $change laid over its `extras` */
	private function writeExtras(array $change, ?int $revision = NULL): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['extras'] = array_replace($settings['extras'], $change);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $revision ?? $read['revision'], 'settings' => $settings]);
	}

	public function testTheFixtureHoldsTheCoverageMatrixAndHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('extras', $doc['projection']);
		$this->assertSame(['maxmindAccount', 'maxmindKey', 'maxmindLocale', 'maxmindCsvDisabled', 'ipinfoToken', 'top1mProvider', 'top1mToken'],
			array_keys($doc['defaults']), 'the defaults name every field in the protocol order');
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['defaults', 'account-word', 'account-zero', 'account-not-a-word', 'account-array', 'key-word', 'key-not-a-word', 'key-array',
			'locale-en', 'locale-fr', 'locale-pt-BR', 'locale-de', 'locale-ja', 'locale-zh-CN', 'locale-es', 'locale-upper-case', 'locale-unknown', 'locale-path',
			'locale-array', 'csv-disabled-on', 'csv-disabled-empty', 'csv-disabled-array', 'ipinfo-token', 'ipinfo-token-symbols', 'ipinfo-token-crlf',
			'ipinfo-token-nul', 'ipinfo-token-array', 'provider-tranco', 'provider-cisco', 'provider-openpagerank', 'provider-majestic', 'provider-cloudflare',
			'provider-legacy-alexa', 'provider-legacy-domcop', 'provider-capitalized', 'provider-array', 'top1m-token', 'top1m-token-crlf', 'top1m-token-array'] as $id) {
			$this->assertContains($id, $ids, "the coverage matrix row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
		foreach (['account-dash', 'key-space', 'locale-unknown', 'csv-disabled-string', 'ipinfo-token-line-break', 'ipinfo-token-nul', 'provider-legacy',
			'top1m-token-carriage-return'] as $id) {
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
		$this->arrange($case['config']);
		pfb_global();
		$pfb = $GLOBALS['pfb'];
		$seen = [
			'account'     => static fn(): string => $pfb['maxmind_account'],
			'key'         => static fn(): string => $pfb['maxmind_key'],
			'locale'      => static fn(): string => $pfb['maxmind_locale'],
			'csvDisabled' => static fn(): bool => $pfb['cc'],
			'ipinfo'      => static fn(): string => $pfb['asn_token'],
			'provider'    => static fn(): string => $pfb['dnsbl_top1m_type']->value,
			'top1mToken'  => static fn(): string => (string) PfbConfig::read('dnsbl/top1m_token'),
		];
		foreach ($case['php'] as $key => $expected) {
			$this->assertSame($expected, $seen[$key](), "{$case['id']}: today's PHP reading of {$key}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTheAdapterProjectsTheFixturesExtras(array $case): void
	{
		$this->arrange($case['config']);

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame(array_replace(self::fixture()['defaults'], $case['extras']), $reply['settings']['extras'], "{$case['id']}: {$case['description']}");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	public function testATokenThatIsNotUtf8ReadsAsNone(): void
	{
		config_set_path(self::IP . '/asn_token', "ab\xff\xfecd");
		config_set_path(self::DNSBL . '/top1m_token', "\xc3\x28");

		$extras = $this->assertNoPhpWarning(fn(): array => $this->read())['settings']['extras'];

		$this->assertSame(['', ''], [$extras['ipinfoToken'], $extras['top1mToken']], 'a token Core could not hold as text is no token');
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesTheFixturesHostileValueNamingTheFieldAndWritesNothing(array $row): void
	{
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->assertNoPhpWarning(fn(): array => $this->writeExtras($row['extras']));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$this->assertContains("extras.{$row['field']}", array_column($reply['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']}");
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$row['id']}: write_config() was called");
		$this->assertSame($before, $GLOBALS['config'], "{$row['id']}: config.xml changed");
	}

	/** @return array<string, array{0: string, 1: mixed, 2: string, 3: string}> field, the value Core writes, config path, the stored text */
	public static function fields(): array
	{
		return [
			'the account'            => ['maxmindAccount', '424242', self::IP . '/maxmind_account', '424242'],
			'the key'                => ['maxmindKey', 'New_Key_9', self::IP . '/maxmind_key', 'New_Key_9'],
			'the key cleared'        => ['maxmindKey', '', self::IP . '/maxmind_key', ''],
			'the locale'             => ['maxmindLocale', 'ja', self::IP . '/maxmind_locale', 'ja'],
			'CSV updates disabled'   => ['maxmindCsvDisabled', TRUE, self::IP . '/database_cc', 'on'],
			'the IPinfo token'       => ['ipinfoToken', 'ipi=new/1', self::IP . '/asn_token', 'ipi=new/1'],
			'the IPinfo token cleared' => ['ipinfoToken', '', self::IP . '/asn_token', ''],
			'the provider'           => ['top1mProvider', 'cloudflare', self::DNSBL . '/top1m_source', 'cloudflare'],
			'the TOP1M token'        => ['top1mToken', 'cf-token.2', self::DNSBL . '/top1m_token', 'cf-token.2'],
			'the TOP1M token cleared' => ['top1mToken', '', self::DNSBL . '/top1m_token', ''],
		];
	}

	#[DataProvider('fields')]
	public function testAChangedFieldReachesItsKeyAndOnlyIt(string $field, mixed $value, string $path, string $stored): void
	{
		config_set_path(self::IP, ['maxmind_account' => '111', 'maxmind_key' => 'Old_Key', 'maxmind_locale' => 'fr', 'asn_token' => 'old-ipi', 'other' => 'kept']);
		config_set_path(self::DNSBL . '/top1m_source', 'cisco');
		config_set_path(self::DNSBL . '/top1m_token', 'old-top1m');
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertNotSame($value, $read['settings']['extras'][$field], 'before-state: the field holds another value');

		$reply = $this->writeExtras([$field => $value]);

		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertSame($stored, config_get_path($path), "{$field} reached its key");
		$this->assertSame(self::without($before, $path), self::without($GLOBALS['config'], $path), 'every other key of config.xml is as it was');
		$this->assertCount(1, $GLOBALS['pfb_test_write_config_calls'], 'one write_config()');
		$this->assertSame($value, $this->read()['settings']['extras'][$field], 'the next read answers what was written');
		$this->assertNotSame($read['revision'], $reply['revision'], 'the revision moves, also for a secret');
		$this->assertSame($this->read()['revision'], $reply['revision'], 'the reply is the revision config.xml projects now');
	}

	/** $config without the leaf at $path. */
	private static function without(array $config, string $path): array
	{
		$node = &$config;
		$keys = explode('/', $path);
		$leaf = array_pop($keys);
		foreach ($keys as $key) {
			$node = &$node[$key];
		}
		unset($node[$leaf]);
		return $config;
	}

	public function testAnUnchangedWriteWithItsSecretsInClearIsANoOp(): void
	{
		config_set_path(self::IP, ['maxmind_account' => '111', 'maxmind_key' => 'Old_Key', 'asn_token' => 'old-ipi']);
		config_set_path(self::DNSBL . '/top1m_token', 'old-top1m');
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertSame(['Old_Key', 'old-ipi', 'old-top1m'], [$read['settings']['extras']['maxmindKey'], $read['settings']['extras']['ipinfoToken'],
			$read['settings']['extras']['top1mToken']], 'the read carries the three secrets in clear for Core to hide');

		$reply = $this->writeExtras([]);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply, 'an unchanged write answers the revision it was at');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testAWriteBeneathAStaleRevisionIsAConflictAndWritesNothing(): void
	{
		$this->configXmlOnDisk();

		$reply = $this->writeExtras(['maxmindLocale' => 'de'], $this->read()['revision'] + 1);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	/** @return array<string, array{0: callable(array<string, mixed>): mixed, 1: string}> */
	public static function malformed(): array
	{
		return [
			'a field left out'   => [static function (array $e): array { unset($e['top1mToken']); return $e; }, 'extras.top1mToken'],
			'an unknown field'   => [static fn(array $e): array => $e + ['bogus' => 1], 'extras.bogus'],
			'a secret as a list' => [static fn(array $e): array => ['maxmindKey' => ['x']] + $e, 'extras.maxmindKey'],
			'a null token'       => [static fn(array $e): array => ['ipinfoToken' => NULL] + $e, 'extras.ipinfoToken'],
		];
	}

	#[DataProvider('malformed')]
	public function testAMalformedExtrasIsInvalidArgumentNamingTheFieldAndChangesNothing(callable $change, string $field): void
	{
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->read();
		$settings = $read['settings'];
		$settings['extras'] = $change($settings['extras']);

		$reply = $this->assertNoPhpWarning(fn(): array => $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains($field, array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testAWriteWithoutExtrasIsMalformedNamingTheProjections(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['extras']);

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('extras', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
	}
}
