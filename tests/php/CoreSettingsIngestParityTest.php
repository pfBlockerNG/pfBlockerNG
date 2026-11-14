<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3975: freezes today's PHP behaviour for Core's read-only `ingest` projection (what the feed phase reads of the package
 * settings and the platform) as the parity fixture tests/core/fixtures/settings_ingest_parity.json; go/pfb_core/settings passes the
 * same file.
 *   - A case is a config.xml (and the addresses the box lists): `php` is what today's readers say of it (pfb_global(),
 *     pfb_list_cidr_floors(), pfb_feed_filter_enabled(), pfb_feed_internal_allowlist(), pfb_ip_is_self(), the cURL proxy options),
 *     `ingest` (over the fixture's defaults) is what the settings adapter's read answers. Where PHP and Core differ (a value the
 *     page never offers, an entry Core's lists cannot hold) the case says why.
 *   - A refused row is a value Core refuses to read; the adapter's write refuses it too, naming the field: the projection is
 *     read-only, config.xml and the platform own it.
 */
#[CoversFunction('pfb_core_ingest_settings')]
#[CoversFunction('pfb_core_ingest_faults')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsIngestParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_ingest_parity.json';
	private const GLOBALS_SEEDED = ['pfb_test_configured_ip_addresses', 'pfb_test_configured_ipv6', 'pfb_test_configured_ips'];

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_ingest_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
		$GLOBALS['g']['unbound_chroot_path'] = $this->dir;
		foreach ([CURLOPT_PROXY, CURLOPT_PROXYPORT, CURLOPT_PROXYAUTH, CURLOPT_PROXYUSERPWD] as $option) {
			unset($GLOBALS['pfb']['curl_defaults'][$option]);
		}
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
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail', ...array_map(static fn(string $g): string => substr($g, 9), self::GLOBALS_SEEDED)] as $global) {
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

	/**
	 * config.xml as the case holds it, and the addresses the box lists: the doubles pfSense's own functions answer from
	 * (is_ipaddr_configured() knows every listed address, as the real one does through the same lists).
	 *
	 * @param array<string, mixed> $case
	 */
	private function arrange(array $case): void
	{
		$paths = PFB_SECTIONS + ['system' => 'system'];
		foreach ($case['config'] as $section => $keys) {
			foreach ($keys as $key => $value) {
				config_set_path("{$paths[$section]}/{$key}", $value);
			}
		}
		if (isset($case['allowlistText'])) {
			config_set_path(PFB_SECTIONS['gen'] . '/pfb_feed_internal_allowlist', base64_encode($case['allowlistText']));
		}
		$platform = $case['platform'] ?? ['ipv4' => [], 'ipv6' => []];
		$GLOBALS['pfb_test_configured_ip_addresses'] = $platform['ipv4'];
		$GLOBALS['pfb_test_configured_ipv6'] = $platform['ipv6'];
		$GLOBALS['pfb_test_configured_ips'] = array_values(array_filter(array_merge(array_values($platform['ipv4']), array_values($platform['ipv6'])), static fn(mixed $a): bool => is_string($a) && $a !== ''));
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'read'], "{$this->dir}/node_exporter", static fn(): array => []);
		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode($reply));
		$this->assertArrayHasKey('ingest', $reply['settings'], 'the read answers the ingest projection: ' . json_encode($reply));
		return $reply;
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to its `ingest` */
	private function writeIngest(callable $change, ?int $revision = NULL): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['ingest'] = $change($settings['ingest']);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $revision ?? $read['revision'], 'settings' => $settings]);
	}

	public function testTheFixtureHoldsTheCoverageMatrixAndHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('ingest', $doc['projection']);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['defaults', 'suppression-on', 'suppression-off', 'cidr-disabled', 'cidr-v4-lowest', 'cidr-v4-highest-v6-highest', 'cidr-out-of-range', 'cidr-garbage',
			'dnsbl-ip-disabled', 'dnsbl-ip-deny-inbound', 'lenient-on', 'lenient-off', 'lenient-absent', 'filter-on', 'filter-off', 'filter-absent',
			'allowlist-valid', 'allowlist-invalid-dropped', 'allowlist-base64-garbage', 'allowlist-spaces-and-blank-lines', 'allowlist-ipv6-zone',
			'proxy-none', 'proxy-host-and-port', 'proxy-host-port-user-and-password', 'proxy-user-without-password', 'proxy-url-with-userinfo', 'proxy-url-with-crlf',
			'proxy-url-with-https-scheme', 'proxy-url-with-socks5-scheme', 'proxy-url-with-socks4-scheme', 'proxy-port-negative', 'proxy-port-beyond-65535',
			'proxy-ipv6-host', 'proxy-port-zero-is-empty', 'proxy-port-leading-digits',
			'self-interface-and-vip', 'self-link-local-excluded', 'self-hostile-addresses'] as $id) {
			$this->assertContains($id, $ids, "the coverage matrix row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
		foreach (['proxy-url-with-userinfo', 'proxy-url-with-crlf', 'allowlist-with-spaces', 'allowlist-ipv6-zone', 'self-unspecified-v4', 'self-unspecified-v6', 'self-mapped-ipv4'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
		$this->assertSame(['suppression', 'suppressionCidrV4', 'suppressionCidrV6', 'dnsblIp', 'dnsblLenient', 'feedHostFilter', 'feedHostAllowlist', 'selfAddresses',
			'proxyUrl', 'proxyUser', 'proxyPassword', 'proxyUnusable'], array_keys($doc['defaults']), 'the defaults name every field in the protocol order');
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesObservationsAndTheAdapterTheFixturesProjection(array $case): void
	{
		$this->arrange($case);
		pfb_global();
		$pfb = $GLOBALS['pfb'];
		$curl = $pfb['curl_defaults'];
		$seen = [
			'supp'    => static fn(): bool => $pfb['supp'] === PfbToggle::On,
			'floors'  => static fn(): array => pfb_list_cidr_floors([], 'auto', (string) $pfb['supp_cidr'], (string) $pfb['supp_cidr_v6']),
			'dnsblIp' => static fn(): bool => pfb_dnsblip_action_value($pfb['dnsblconfig']['action'] ?? NULL) !== 'Disabled',
			'lenient' => static fn(): bool => $pfb['dnsbl_lenient'] === PfbToggle::On,
			'filter'  => static fn(): bool => pfb_feed_filter_enabled(),
			'allow'   => static fn(): array => pfb_feed_internal_allowlist(),
			'proxy'   => static fn(): array => ['host' => $curl[CURLOPT_PROXY] ?? NULL, 'port' => $curl[CURLOPT_PROXYPORT] ?? NULL, 'userpwd' => $curl[CURLOPT_PROXYUSERPWD] ?? NULL],
		];
		foreach ($case['php'] as $key => $expected) {
			if ($key === 'self') {
				$probes = array_keys($expected);
				$actual = array_combine($probes, array_map('pfb_ip_is_self', $probes));
			} else {
				$actual = $seen[$key]();
			}
			$this->assertSame($expected, $actual, "{$case['id']}: today's PHP reading of {$key}");
		}

		$reply = $this->read();

		$this->assertSame(array_replace(self::fixture()['defaults'], $case['ingest']), $reply['settings']['ingest'], "{$case['id']}: the ingest projection");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	public function testTheReadAnswersTheProxyPasswordInClearForCoreToHide(): void
	{
		config_set_path('system', ['proxyurl' => 'proxy.example.com', 'proxyport' => '3128', 'proxyuser' => 'alice', 'proxypass' => 'hunter2']);

		$ingest = $this->read()['settings']['ingest'];

		$this->assertSame('hunter2', $ingest['proxyPassword'], 'the adapter carries it as it carries feed credentials: only Core hides it');
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesAChangedIngestNamingTheFieldAndWritesNothing(array $row): void
	{
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->writeIngest(static fn(array $ingest): array => array_replace($ingest, $row['ingest']));

		$field = 'ingest.' . preg_replace('/[\[.].*$/', '', $row['field']);
		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$this->assertContains($field, array_column($reply['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']}");
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$row['id']}: write_config() was called");
		$this->assertSame($before, $GLOBALS['config'], "{$row['id']}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$row['id']}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$row['id']}: the config lock is still held");
	}

	public function testAWriteThatLeavesIngestAsItWasStoresTheOtherProjectionsAndAnUnchangedWriteIsANoOp(): void
	{
		config_set_path('system', ['proxyurl' => 'proxy.example.com', 'proxyport' => '3128', 'proxyuser' => 'alice', 'proxypass' => 'hunter2']);
		$this->configXmlOnDisk();

		$unchanged = $this->writeIngest(static fn(array $ingest): array => $ingest);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $unchanged, 'an unchanged write answers the revision it was at');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written for an unchanged write');

		$read = $this->read();
		$settings = $read['settings'];
		$settings['dns']['control'] = TRUE;
		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('on', $this->onDisk('installedpackages/pfblockerngdnsblsettings/config/0/pfb_control'), 'the dns change reached config.xml');
		$this->assertSame($read['settings']['ingest'], $this->read()['settings']['ingest'], 'ingest is as it was');
		$this->assertSame($this->read()['revision'], $reply['revision'] ?? NULL, 'the reply is the revision config.xml projects now');
		$this->assertSame('hunter2', $this->onDisk('system/proxypass'), 'the proxy the platform owns is untouched');
	}

	public function testAChangedIngestBeneathAStaleRevisionIsAConflictNotARefusal(): void
	{
		$this->configXmlOnDisk();
		$read = $this->read();
		$settings = $read['settings'];
		$GLOBALS['pfb_test_configured_ip_addresses'] = ['lan' => '192.168.1.1'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, 'Core read the box before its address changed: it reads again, it did not ask to change ingest: ' . json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	public function testAWriteWithoutIngestIsMalformed(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['ingest']);

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('ingest', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
	}

	/** @return array<string, array{0: mixed}> */
	public static function notAnObject(): array
	{
		return ['a string' => ['x'], 'null' => [NULL], 'an int' => [7], 'a bool' => [FALSE]];
	}

	#[DataProvider('notAnObject')]
	public function testAWriteWhoseIngestIsNotAnObjectIsMalformedNotAFatalError(mixed $ingest): void
	{
		$this->configXmlOnDisk();

		$reply = $this->writeIngest(static fn(array $current): mixed => $ingest);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('ingest', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	public function testAWriteThatLeavesAnIngestFieldOutIsRefusedNamingIt(): void
	{
		$this->configXmlOnDisk();

		$reply = $this->assertNoPhpWarning(fn(): array => $this->writeIngest(static function (array $ingest): array {
			unset($ingest['proxyUrl']);
			return $ingest;
		}));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame([['field' => 'ingest.proxyUrl', 'message' => 'read-only: config.xml and the platform own it']], $reply['error']['fieldErrors'] ?? NULL, 'exactly the field left out');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	public function testAWriteThatAddsAnIngestFieldCoreDoesNotKnowIsRefusedNamingIt(): void
	{
		$this->configXmlOnDisk();

		$reply = $this->assertNoPhpWarning(fn(): array => $this->writeIngest(static fn(array $ingest): array => $ingest + ['bogus' => TRUE]));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame([['field' => 'ingest.bogus', 'message' => 'no such field']], $reply['error']['fieldErrors'] ?? NULL, 'exactly the field added');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	public function testTheRevisionMovesWhenASelfAddressOrTheProxyChanges(): void
	{
		$reset = static function (): void {
			$GLOBALS['config'] = [];
			unset($GLOBALS['pfb_test_configured_ip_addresses'], $GLOBALS['pfb_test_configured_ipv6']);
		};
		$reset();
		$base = $this->read()['revision'];
		$moves = [
			'a VIP is added'              => static function (): void { $GLOBALS['pfb_test_configured_ip_addresses'] = ['_vip1' => '192.168.1.2']; },
			'an interface address moves'  => static function (): void { $GLOBALS['pfb_test_configured_ip_addresses'] = ['lan' => '192.168.1.9']; },
			'an IPv6 address appears'     => static function (): void { $GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8::1']; },
			'the proxy host changes'      => static function (): void { config_set_path('system/proxyurl', 'proxy.example.com'); },
			'the proxy port changes'      => static function (): void { config_set_path('system/proxyurl', 'proxy.example.com'); config_set_path('system/proxyport', '8080'); },
			'the proxy password changes'  => static function (): void { config_set_path('system/proxyurl', 'proxy.example.com'); config_set_path('system/proxyuser', 'u'); config_set_path('system/proxypass', 'p'); },
		];
		$seen = [$base => 'the start'];
		foreach ($moves as $why => $move) {
			$reset();
			$move();
			$revision = $this->read()['revision'];
			$this->assertArrayNotHasKey($revision, $seen, "{$why}: the revision moves, to one no other change gave");
			$seen[$revision] = $why;
		}
		$reset();
		$this->assertSame($base, $this->read()['revision'], 'the same box gives the same revision');
	}
}
