<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3924: on pfSense Core keeps no settings store; it runs the settings adapter (pfb_core_settings.sh, the `core_settings`
 * verb of pfblockerng.inc) once per call, one JSON request on stdin and one JSON reply on stdout (docs/misc/core-api-protocol.md).
 * Pinned here, for the adapter that answers over config.xml:
 *   - read: the 17 native `settings/dns` fields as pfb_core_dns_settings() projects them, beside the feed projections (issue #3937,
 *     CoreSettingsFeedsBackendTest; empty here: config.xml holds no group), with their revision;
 *   - write: every changed field reaches its registered config.xml key and only that key, under the config lock, with one
 *     write_config() and the pending-changes mark; the projection afterwards is what was asked for;
 *   - a stale revision, a refused or failed write_config(), a lock that stays taken and a failed client-IP privacy step answer
 *     conflict / unavailable and leave config.xml as it was; a malformed request answers invalid_argument before any lock or write;
 *   - the verb prints one JSON object and nothing else, and the adapter never calls Core (Core is waiting on it).
 */
#[CoversFunction('pfb_core_settings_revision')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_serve')]
final class CoreSettingsBackendTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_dns_parity.json';
	private const MESSAGE = '[pfBlockerNG] pfBlockerNG Core saved the settings';
	private const WRAPPER = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfb_core_settings.sh';
	private const ENTRY = __DIR__ . '/bin/cli_dispatch_entry.php';

	/** The feed projections of a config.xml with no group (issue #3937): every read and write carries them beside `dns`. */
	private const FEEDS = ['feeds/ipv4' => ['groups' => []], 'feeds/ipv6' => ['groups' => []], 'feeds/dnsbl' => ['groups' => []]];

	/** The `schedule` projection of a config.xml that holds nothing of it (issue #3941): every field its default, after the feed projections. */
	private const SCHEDULE = ['scheduledUpdates' => TRUE, 'weekday' => 7, 'hour' => 0, 'minute' => 0, 'groups' => [], 'categoryUpdates' => FALSE,
		'categoryFrequency' => 'Never', 'categoryProviders' => []];

	/** The native field => [registry key, default native, default stored, other native, other stored]: the table the adapter must honour. */
	private const FIELDS = [
		'replyLogging'          => ['dnsbl/pfb_py_reply', TRUE, 'on', FALSE, ''],
		'hstsNullBlocking'      => ['dnsbl/pfb_hsts', TRUE, 'on', FALSE, ''],
		'tldWildcard'           => ['dnsbl/tld_wildcard', FALSE, '', TRUE, 'on'],
		'pslIncludePrivate'     => ['dnsbl/pfb_psl_include_private', TRUE, 'on', FALSE, ''],
		'pslAllowPrivate'       => ['dnsbl/pfb_psl_allow_private', FALSE, '', TRUE, 'on'],
		'pslFeedPrivatePolicy'  => ['dnsbl/pfb_psl_feed_private_policy', 'honor', 'honor', 'apex', 'apex'],
		'pslFeedIcannPolicy'    => ['dnsbl/pfb_psl_feed_icann_policy', 'honor', 'honor', 'ignore', 'ignore'],
		'idnMode'               => ['dnsbl/pfb_idn', 'off', '', 'confusable', 'confusable'],
		'idnBlockMalicious'     => ['dnsbl/pfb_idn_block_malicious', TRUE, 'on', FALSE, ''],
		'idnEscalateSuspicious' => ['dnsbl/pfb_idn_escalate_suspicious', FALSE, '', TRUE, 'on'],
		'decisionCacheMax'      => ['dnsbl/pfb_py_cache_max', 10000, '10000', 777, '777'],
		'logViaWebserver'       => ['dnsbl/pfb_py_nolog', FALSE, '', TRUE, 'on'],
		'cnameValidation'       => ['dnsbl/pfb_cname', FALSE, '', TRUE, 'on'],
		'control'               => ['dnsbl/pfb_control', FALSE, '', TRUE, 'on'],
		'controlLegacy'         => ['dnsbl/pfb_control_legacy', FALSE, '', TRUE, 'on'],
		'regexCap'              => ['dnsbl/pfb_regex_cap', FALSE, '', TRUE, 'on'],
		'metricsClientIp'       => ['gen/pfb_metrics_client_ip', FALSE, '', TRUE, 'on'],
	];

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;
	/** config.xml as the file holds it: what a fresh read under the lock returns */
	private array $disk = [];
	/** @var ?array{0: resource, 1: array<int, resource>, 2: string} the Core stand-in */
	private ?array $standIn = NULL;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_backend_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['dnsbl_info'] = "{$this->dir}/dnsbl_info.sqlite";
		$GLOBALS['pfb']['dnsbl_resolver'] = "{$this->dir}/dnsbl_resolver.sqlite";
		$GLOBALS['pfb']['core_socket'] = "{$this->dir}/api.sock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
	}

	protected function tearDown(): void
	{
		if ($this->standIn !== NULL) {
			[$process, $pipes] = $this->standIn;
			proc_terminate($process);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> the parity fixture's `defaults` native values: all 17 fields in the protocol's order */
	private static function defaults(): array
	{
		return self::fixture()['defaults'];
	}

	/** @return array{defaults: array<string, mixed>, stored: array<string, array<string, mixed>>} */
	private static function fixture(): array
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$out = ['defaults' => [], 'stored' => []];
		foreach ($doc['cases'] as $case) {
			if ($case['id'] === 'defaults') {
				$out['defaults'] = $case['native'];
			}
			if ($case['source'] === 'stored' && $case['valid']) {
				$out['stored'][$case['id']] = $case;
			}
		}
		return $out;
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function storedCases(): array
	{
		return array_map(static fn(array $case): array => [$case], self::fixture()['stored']);
	}

	/** @param array<string, ?string> $stored registry key => stored value; becomes config.xml and the file on disk */
	private function arrange(array $stored): void
	{
		foreach ($stored as $key => $value) {
			[$alias, $leaf] = explode('/', $key, 2);
			if ($value !== NULL) {
				config_set_path(PFB_SECTIONS[$alias] . '/' . $leaf, $value);
			}
		}
		$this->disk = $GLOBALS['config'];
		// A fresh read under the lock, or after a refused write, is what the file holds
		$GLOBALS['pfb_test_config_read_hook'] = function (): void {
			$GLOBALS['config'] = $this->disk;
		};
		$GLOBALS['pfb_test_write_config_hook'] = function (string $description): void {
			if (!in_array($GLOBALS['pfb_test_write_config_result'] ?? TRUE, [FALSE, -1], TRUE)) {
				$this->disk = $GLOBALS['config'];
			}
		};
	}

	/** @return array<string, mixed> every projection the adapter answers: $dns, and the feed, schedule and ingest projections of a config.xml with no group (issue #3975: nothing stored, nothing of the box listed) */
	private static function settings(array $dns): array
	{
		$ingest = json_decode((string) file_get_contents(__DIR__ . '/../core/fixtures/settings_ingest_parity.json'), TRUE, 512, JSON_THROW_ON_ERROR)['defaults'];
		return ['dns' => $dns] + self::FEEDS + ['schedule' => self::SCHEDULE, 'ingest' => $ingest];
	}

	/** @return array<string, mixed> */
	private static function writeRequest(array $current, array $wanted, ?int $expected = NULL): array
	{
		return ['version' => 1, 'op' => 'write', 'expectedRevision' => $expected ?? pfb_core_settings_revision(self::settings($current)), 'settings' => self::settings($wanted)];
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter");
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

	/** @return list<string> the leaves of config.xml that differ between two copies, added or removed ones included */
	private static function changedLeaves(array $before, array $after): array
	{
		$a = self::leaves($before);
		$b = self::leaves($after);
		return array_values(array_unique(array_merge(array_keys(array_diff_assoc($a, $b)), array_keys(array_diff_assoc($b, $a)))));
	}

	private function assertNothingWritten(array $before, string $why): void
	{
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$why}: write_config() was called");
		$this->assertSame([], self::changedLeaves($before, $GLOBALS['config']), "{$why}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$why}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$why}: the config lock is still held");
	}

	// ----- the revision -----

	public function testTheRevisionIsAPositiveIntThatMovesWithAnyFieldAndIsPinnedForTheDefaults(): void
	{
		$defaults = self::settings(self::defaults());

		$revision = pfb_core_settings_revision($defaults);

		$key = (string) file_get_contents($GLOBALS['pfb']['core_revision_key']);
		$this->assertSame((int) hexdec(substr(hash_hmac('sha256', (string) json_encode($defaults), $key), 0, 13)), $revision,
			'the first 52 bits of the HMAC-SHA256 of the JSON of the defaults under the box key (#3937): Core compares it for equality only');
		$this->assertSame($revision, pfb_core_settings_revision($defaults), 'equal settings: equal revision');
		$this->assertLessThan(2 ** 52, $revision, 'exact in PHP, JSON and JS');
		foreach (self::FIELDS as $field => [, , , $other]) {
			$changed = $defaults;
			$changed['dns'][$field] = $other;
			$this->assertNotSame($revision, pfb_core_settings_revision($changed), "{$field} moves the revision");
		}
	}

	// ----- read -----

	/** @param array<string, mixed> $case */
	#[DataProvider('storedCases')]
	public function testReadAnswersTheFixturesNativeValuesWithTheirRevision(array $case): void
	{
		$this->arrange($case['values']);
		$native = array_merge(self::defaults(), $case['native']);

		$reply = $this->backend(['version' => 1, 'op' => 'read']);

		$this->assertSame(['version', 'revision', 'settings'], array_keys($reply), "{$case['id']}: the reply's keys");
		$this->assertSame(1, $reply['version']);
		$this->assertSame(self::settings($native), $reply['settings'], "{$case['id']}: the 17 native fields, in the protocol's order");
		$this->assertSame(pfb_core_settings_revision(self::settings($native)), $reply['revision'], "{$case['id']}: the projection's revision");
		$this->assertGreaterThanOrEqual(1, $reply['revision']);
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	// ----- write -----

	/** @return array<string, array{0: string, 1: bool}> every field, from its default to the other value and back */
	public static function fieldWrites(): array
	{
		$cases = [];
		foreach (array_keys(self::FIELDS) as $field) {
			$cases["{$field}: default to other"] = [$field, TRUE];
			$cases["{$field}: other to default"] = [$field, FALSE];
		}
		return $cases;
	}

	#[DataProvider('fieldWrites')]
	public function testWriteStoresOnlyTheChangedFieldsMappedValueAndTheProjectionRoundTrips(string $field, bool $toOther): void
	{
		[$key, $default, $defaultStored, $other, $otherStored] = self::FIELDS[$field];
		$preset = $field === 'controlLegacy' ? ['dnsbl/pfb_control' => 'on'] : [];
		$this->arrange($preset + ($toOther ? [] : [$key => $otherStored]));
		$current = pfb_core_dns_settings();
		$this->assertSame($toOther ? $default : $other, $current[$field], 'before-state');
		$wanted = $current;
		$wanted[$field] = $toOther ? $other : $default;
		$before = $GLOBALS['config'];

		$reply = $this->backend(self::writeRequest($current, $wanted));

		$this->assertSame(['version' => 1, 'revision' => pfb_core_settings_revision(self::settings($wanted))], $reply);
		$this->assertSame($wanted, pfb_core_dns_settings(), 'the projection afterwards is what was asked for');
		[$alias, $leaf] = explode('/', $key, 2);
		$path = PFB_SECTIONS[$alias] . '/' . $leaf;
		$this->assertSame($toOther ? $otherStored : $defaultStored, config_get_path($path), "{$key} as stored");
		$this->assertSame([$path], self::changedLeaves($before, $GLOBALS['config']), 'no other config.xml key is touched');
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config(), with the Core message');
		$this->assertFileExists("{$this->dir}/pending", 'the change applies on the next Update');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
		$this->assertSame($this->disk, $GLOBALS['config'], 'what was written is what config.xml holds');
	}

	public function testWriteOfSeveralFieldsPersistsThemAllInOneWrite(): void
	{
		$this->arrange([]);
		$current = pfb_core_dns_settings();
		$wanted = array_merge($current, ['hstsNullBlocking' => FALSE, 'idnMode' => 'on', 'decisionCacheMax' => 0, 'pslFeedIcannPolicy' => 'apex']);

		$reply = $this->backend(self::writeRequest($current, $wanted));

		$this->assertSame(pfb_core_settings_revision(self::settings($wanted)), $reply['revision']);
		$this->assertSame($wanted, pfb_core_dns_settings());
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config() for all fields');
	}

	public function testATurnedOnControlDoesNotRevealAStoredLegacyTransportThatWasAskedOff(): void
	{
		// Given a legacy token stored beneath a control that is off: the projection holds controlLegacy false
		$this->arrange(['dnsbl/pfb_control' => '', 'dnsbl/pfb_control_legacy' => 'on']);
		$current = pfb_core_dns_settings();
		$this->assertFalse($current['controlLegacy'], 'before-state');
		$wanted = array_merge($current, ['control' => TRUE]);

		// When Core turns control on, controlLegacy false
		$reply = $this->backend(self::writeRequest($current, $wanted));

		// Then the projection is what Core asked for
		$this->assertSame($wanted, pfb_core_dns_settings(), 'controlLegacy stays off');
		$this->assertSame(pfb_core_settings_revision(self::settings($wanted)), $reply['revision']);
	}

	public function testWriteOfWhatConfigXmlAlreadyHoldsChangesNothing(): void
	{
		$this->arrange(['dnsbl/pfb_hsts' => '']);
		$current = pfb_core_dns_settings();
		$before = $GLOBALS['config'];

		$reply = $this->backend(self::writeRequest($current, $current));

		$this->assertSame(['version' => 1, 'revision' => pfb_core_settings_revision(self::settings($current))], $reply);
		$this->assertNothingWritten($before, 'nothing changed');
	}

	public function testWriteAgainstAStaleRevisionIsAConflictAndWritesNothing(): void
	{
		$this->arrange([]);
		$current = pfb_core_dns_settings();
		$stale = pfb_core_settings_revision(self::settings(array_merge($current, ['regexCap' => TRUE])));
		$before = $GLOBALS['config'];

		$reply = $this->backend(self::writeRequest($current, array_merge($current, ['hstsNullBlocking' => FALSE]), $stale));

		$this->assertSame(1, $reply['version']);
		$this->assertSame('conflict', $reply['error']['code']);
		$this->assertNotSame('', $reply['error']['message']);
		$this->assertNothingWritten($before, 'a stale revision');
		$this->assertSame('try_lock', $GLOBALS['pfb_test_lock_events'][0][0], 'the revision is checked under the lock');
	}

	/** @return array<string, array{0: bool|int}> what pfSense's write_config() answers for a refusal and for a file-write failure */
	public static function failedWrites(): array
	{
		return ['write refused' => [FALSE], 'file write failed' => [-1]];
	}

	#[DataProvider('failedWrites')]
	public function testAWriteConfigThatFailsIsUnavailableAndConfigXmlIsReadAgain(bool|int $result): void
	{
		$this->arrange([]);
		$current = pfb_core_dns_settings();
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_write_config_result'] = $result;

		$reply = $this->backend(self::writeRequest($current, array_merge($current, ['hstsNullBlocking' => FALSE, 'control' => TRUE])));

		$this->assertSame('unavailable', $reply['error']['code']);
		$this->assertStringContainsString('refused the configuration write', $reply['error']['message']);
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'write_config() was asked once');
		$this->assertSame($current, pfb_core_dns_settings(), 'the copy of config.xml holds what the file holds, not the refused change');
		$this->assertSame([], self::changedLeaves($before, $GLOBALS['config']));
		$this->assertFileDoesNotExist("{$this->dir}/pending");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
	}

	public function testAConfigLockThatStaysTakenIsUnavailableAndWritesNothing(): void
	{
		$this->arrange([]);
		$current = pfb_core_dns_settings();
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		$reply = $this->backend(self::writeRequest($current, array_merge($current, ['hstsNullBlocking' => FALSE])));

		$this->assertSame('unavailable', $reply['error']['code']);
		$this->assertSame('pfb_dns_config', $GLOBALS['pfb_test_lock_events'][0][1], 'the DNS config lock was asked for');
		$this->assertNothingWritten($before, 'a lock that stays taken');
	}

	public function testAMetricsClientIpChangeSettlesThePrivacyDataBeforeConfigXmlIsWritten(): void
	{
		// Given client IP metrics on, with a client identity stored
		$this->arrange(['gen/pfb_metrics_client_ip' => 'on']);
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE dns_metric_blocks (client_ip TEXT, domain TEXT, count INTEGER)');
		$db->exec("INSERT INTO dns_metric_blocks VALUES ('192.0.2.7', 'example.com', 1)");
		$db->close();
		$identitiesAtWrite = NULL;
		$disk = $GLOBALS['pfb_test_write_config_hook'];
		$GLOBALS['pfb_test_write_config_hook'] = function (string $description) use (&$identitiesAtWrite, $disk): void {
			$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
			$identitiesAtWrite = $db->querySingle("SELECT count(*) FROM dns_metric_blocks WHERE client_ip = '192.0.2.7'");
			$db->close();
			$disk($description);
		};
		$current = pfb_core_dns_settings();
		$this->assertTrue($current['metricsClientIp'], 'before-state');

		// When Core turns it off
		$reply = $this->backend(self::writeRequest($current, array_merge($current, ['metricsClientIp' => FALSE])));

		// Then the stored identities were already purged when write_config() ran, and the counts remain
		$this->assertSame(pfb_core_settings_revision(self::settings(array_merge($current, ['metricsClientIp' => FALSE]))), $reply['revision']);
		$this->assertSame(0, $identitiesAtWrite, 'the privacy change comes before the write');
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$this->assertSame(1, $db->querySingle('SELECT count(*) FROM dns_metric_blocks'));
		$db->close();
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testAFailedPrivacyStepIsUnavailableAndNothingIsWritten(): void
	{
		// Given the metrics lock cannot be opened (its directory is missing)
		$this->arrange([]);
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/missing/metrics.lock";
		$current = pfb_core_dns_settings();
		$before = $GLOBALS['config'];

		// When Core turns client IP metrics on together with another field
		$reply = $this->backend(self::writeRequest($current, array_merge($current, ['metricsClientIp' => TRUE, 'hstsNullBlocking' => FALSE])));

		// Then the metrics error is the refusal, and the other field was not written either
		$this->assertSame('unavailable', $reply['error']['code']);
		$this->assertStringContainsString('Client IP metrics could not be changed', $reply['error']['message']);
		$this->assertNothingWritten($before, 'a failed privacy step');
	}

	/** Issue #3927: the adapter gives up on a busy metrics lock after its own short wait (CoreSettingsAdapterDeadlineTest's budget), not the page's 10 s. */
	public function testABusyMetricsLockIsWaitedForOnlyTheAdaptersShortWait(): void
	{
		$this->arrange([]);
		$current = pfb_core_dns_settings();
		$before = $GLOBALS['config'];
		$holder = fopen($GLOBALS['pfb']['metrics_lock'], 'c');
		$this->assertTrue(flock($holder, LOCK_EX | LOCK_NB), 'before-state: the test holds the metrics lock');
		try {
			$reply = $this->backend(self::writeRequest($current, array_merge($current, ['metricsClientIp' => TRUE])));
		} finally {
			fclose($holder);
		}

		$this->assertSame('unavailable', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('metrics publication stayed busy for 2 s', $reply['error']['message']);
		$this->assertNothingWritten($before, 'a busy metrics lock');
	}

	/** Issue #3927: a metrics database another writer holds is waited for only the adapter's SQLite wait, whatever the process's own. */
	public function testABusyMetricsDatabaseIsWaitedForOnlyTheAdaptersSqliteWait(): void
	{
		$this->arrange(['gen/pfb_metrics_client_ip' => 'on']);
		$GLOBALS['pfb']['sqlite_timeout'] = 100000;
		$current = pfb_core_dns_settings();
		$before = $GLOBALS['config'];
		$holder = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$holder->exec('CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER NOT NULL, epoch TEXT NOT NULL)');
		$holder->exec('BEGIN IMMEDIATE');
		try {
			$reply = $this->backend(self::writeRequest($current, array_merge($current, ['metricsClientIp' => FALSE])));
		} finally {
			$holder->exec('ROLLBACK');
			$holder->close();
		}

		$this->assertSame('unavailable', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('dnsbl_info.sqlite: database is locked (waited 500 ms)', $reply['error']['message']);
		$this->assertNothingWritten($before, 'a busy metrics database');
	}

	#[DataProvider('failedWrites')]
	public function testARefusedWriteConfigAfterAClientIpChangePutsThePrivacyPolicyBack(bool|int $result): void
	{
		// Given client IP metrics off, and the database that records the policy
		$this->arrange([]);
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE dns_metric_settings (row INTEGER PRIMARY KEY, client_ip INTEGER NOT NULL, epoch TEXT NOT NULL)');
		$db->exec("INSERT INTO dns_metric_settings VALUES (0,0,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')");
		$db->close();
		$current = pfb_core_dns_settings();
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_write_config_result'] = $result;

		// When Core turns it on and pfSense refuses the write
		$reply = $this->backend(self::writeRequest($current, array_merge($current, ['metricsClientIp' => TRUE])));

		// Then the write is unavailable, and neither config.xml nor the database policy changed
		$this->assertSame('unavailable', $reply['error']['code']);
		$this->assertStringContainsString('refused the configuration write', $reply['error']['message']);
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$this->assertSame(0, $db->querySingle('SELECT client_ip FROM dns_metric_settings WHERE row=0'), 'the policy is what config.xml still says');
		$db->close();
		$this->assertSame([], self::changedLeaves($before, $GLOBALS['config']));
		$this->assertFileDoesNotExist("{$this->dir}/pending");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
	}

	// ----- a malformed request -----

	/** @return array<string, mixed> a valid write request over the defaults that changes two fields */
	private static function validWrite(): array
	{
		$wanted = self::defaults();
		$wanted['hstsNullBlocking'] = FALSE;
		$wanted['regexCap'] = TRUE;
		return ['version' => 1, 'op' => 'write', 'expectedRevision' => pfb_core_settings_revision(self::settings(self::defaults())), 'settings' => self::settings($wanted)];
	}

	/** @return array<string, array{0: array<string, mixed>, 1: ?string}> a hostile write request, and the `dns.` field its error names */
	public static function malformedRequests(): array
	{
		$set = static function (array $path, mixed $value): array {
			$request = self::validWrite();
			$node = &$request;
			foreach ($path as $key) {
				$node = &$node[$key];
			}
			$node = $value;
			return $request;
		};
		$drop = static function (array $path): array {
			$request = self::validWrite();
			$node = &$request;
			$last = array_pop($path);
			foreach ($path as $key) {
				$node = &$node[$key];
			}
			unset($node[$last]);
			return $request;
		};
		return [
			'version 2'                     => [$set(['version'], 2), NULL],
			'version missing'               => [$drop(['version']), NULL],
			'version as a string'           => [$set(['version'], '1'), NULL],
			'version as a float'            => [$set(['version'], 1.0), NULL],
			'op unknown'                    => [$set(['op'], 'delete'), NULL],
			'op missing'                    => [$drop(['op']), NULL],
			'op not a string'               => [$set(['op'], 1), NULL],
			'expectedRevision missing'      => [$drop(['expectedRevision']), NULL],
			'expectedRevision a string'     => [$set(['expectedRevision'], '5'), NULL],
			'expectedRevision negative'     => [$set(['expectedRevision'], -1), NULL],
			'expectedRevision a float'      => [$set(['expectedRevision'], 5.0), NULL],
			'expectedRevision a bool'       => [$set(['expectedRevision'], TRUE), NULL],
			'an unknown top-level key'      => [$set(['force'], TRUE), NULL],
			'settings missing'              => [$drop(['settings']), NULL],
			'settings not an object'        => [$set(['settings'], 'x'), NULL],
			'settings without dns'          => [$set(['settings'], []), NULL],
			'settings with another projection' => [$set(['settings', 'other'], []), NULL],
			'dns not an object'             => [$set(['settings', 'dns'], 'x'), NULL],
			'dns missing a field'           => [$drop(['settings', 'dns', 'idnMode']), 'dns.idnMode'],
			'dns with an unknown field'     => [$set(['settings', 'dns', 'bogus'], TRUE), 'dns.bogus'],
			'a bool as "true"'              => [$set(['settings', 'dns', 'regexCap'], 'true'), 'dns.regexCap'],
			'a bool as 1'                   => [$set(['settings', 'dns', 'control'], 1), 'dns.control'],
			'an int as "5"'                 => [$set(['settings', 'dns', 'decisionCacheMax'], '5'), 'dns.decisionCacheMax'],
			'an int as a float'             => [$set(['settings', 'dns', 'decisionCacheMax'], 5.0), 'dns.decisionCacheMax'],
			'decisionCacheMax over the cap' => [$set(['settings', 'dns', 'decisionCacheMax'], 5000001), 'dns.decisionCacheMax'],
			'decisionCacheMax negative'     => [$set(['settings', 'dns', 'decisionCacheMax'], -1), 'dns.decisionCacheMax'],
			'idnMode not a token'           => [$set(['settings', 'dns', 'idnMode'], 'ON'), 'dns.idnMode'],
			'idnMode not a string'          => [$set(['settings', 'dns', 'idnMode'], 5), 'dns.idnMode'],
			'a policy not a token'          => [$set(['settings', 'dns', 'pslFeedIcannPolicy'], 'x'), 'dns.pslFeedIcannPolicy'],
			'controlLegacy without control' => [$set(['settings', 'dns', 'controlLegacy'], TRUE), 'dns.controlLegacy'],
		];
	}

	/** @param array<string, mixed> $request */
	#[DataProvider('malformedRequests')]
	public function testAMalformedWriteIsInvalidArgumentBeforeAnyLockOrWrite(array $request, ?string $field): void
	{
		$this->arrange([]);
		$before = $GLOBALS['config'];

		$reply = $this->backend($request);

		$this->assertSame(1, $reply['version']);
		$this->assertSame('invalid_argument', $reply['error']['code'], json_encode($reply));
		$this->assertNotSame('', $reply['error']['message']);
		if ($field !== NULL) {
			$this->assertContains($field, array_column($reply['error']['fieldErrors'] ?? [], 'field'), 'the faulty field is named');
		}
		$this->assertNothingWritten($before, 'a malformed request');
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'no lock was asked for');
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function malformedReads(): array
	{
		return [
			'version 2'            => [['version' => 2, 'op' => 'read']],
			'a read with a revision' => [['version' => 1, 'op' => 'read', 'expectedRevision' => 1]],
			'a read with settings' => [['version' => 1, 'op' => 'read', 'settings' => ['dns' => []]]],
			'an empty request'     => [[]],
		];
	}

	/** @param array<string, mixed> $request */
	#[DataProvider('malformedReads')]
	public function testAMalformedReadIsInvalidArgument(array $request): void
	{
		$reply = $this->backend($request);

		$this->assertSame('invalid_argument', $reply['error']['code'], json_encode($reply));
		$this->assertArrayNotHasKey('settings', $reply);
	}

	// ----- the verb -----

	/**
	 * Run the real `core_settings` verb of pfblockerng.inc (the dispatch the wrapper execs) with $stdin on its standard input.
	 *
	 * @return array{stdout: string, stderr: string, exit: int}
	 */
	private function verb(string $stdin): array
	{
		$in = "{$this->dir}/stdin";
		file_put_contents($in, $stdin);
		$command = [PHP_BINARY, self::ENTRY, 'core_settings'];
		$process = proc_open($command, [0 => ['file', $in, 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);
		$run = pfb_test_finish_process([$process, $pipes, implode(' ', $command)], 60.0);
		return ['stdout' => $run['stdout'], 'stderr' => $run['stderr'], 'exit' => $run['exit']];
	}

	public function testTheVerbPrintsExactlyOneJsonObjectForARead(): void
	{
		$run = $this->verb('{"version":1,"op":"read"}');

		$this->assertSame(0, $run['exit'], $run['stderr']);
		$defaults = self::defaults();
		// The verb's sandbox has its own revision key (#3937): its revision is any positive int, the rest is exact
		$revision = json_decode($run['stdout'], TRUE)['revision'] ?? NULL;
		$this->assertIsInt($revision, $run['stdout']);
		$this->assertGreaterThan(0, $revision);
		$this->assertSame(
			json_encode(['version' => 1, 'revision' => $revision, 'settings' => self::settings($defaults)]),
			$run['stdout'],
			'nothing but the reply on stdout: ' . $run['stderr']
		);
	}

	/** @return array<string, array{0: string}> what stdin can hold that is no request */
	public static function hostileInputs(): array
	{
		return [
			'an empty array'     => ['[]'],
			'null'               => ['null'],
			'a string'           => ['"read"'],
			'a list'             => ['[1, 2]'],
			'not JSON'           => ['{"version":'],
			'nothing'            => [''],
			'over 32 MiB'        => ['{"version":1,"op":"read"}' . str_repeat(' ', PFB_CORE_SETTINGS_MAX_REQUEST)],
		];
	}

	#[DataProvider('hostileInputs')]
	public function testTheVerbAnswersInvalidArgumentForInputThatIsNoRequest(string $stdin): void
	{
		$run = $this->verb($stdin);

		$this->assertSame(0, $run['exit'], $run['stderr']);
		$reply = json_decode($run['stdout'], TRUE);
		$this->assertIsArray($reply, "stdout is one JSON object: {$run['stdout']}");
		$this->assertSame(json_encode($reply), $run['stdout'], 'nothing else on stdout');
		$this->assertSame(1, $reply['version']);
		$this->assertSame('invalid_argument', $reply['error']['code']);
	}

	public function testTheVerbAnswersAWriteOfAStaleRevisionAsAConflictOnAnOtherwiseEmptyStdout(): void
	{
		// Given a write whose expected revision is not the one config.xml projects
		$stale = pfb_core_settings_revision(self::settings(array_merge(self::defaults(), ['regexCap' => TRUE])));
		$request = ['version' => 1, 'op' => 'write', 'expectedRevision' => $stale, 'settings' => self::settings(array_merge(self::defaults(), ['hstsNullBlocking' => FALSE]))];

		// When the verb serves it
		$run = $this->verb((string) json_encode($request));

		// Then the refusal is the one JSON object on stdout
		$reply = json_decode($run['stdout'], TRUE);
		$this->assertSame(0, $run['exit'], $run['stderr']);
		$this->assertSame('conflict', $reply['error']['code'], $run['stdout']);
		$this->assertSame(json_encode($reply), $run['stdout']);
	}

	public function testAWriteThatThrowsIsAnUnavailableReplyNotAFatalErrorAndTheLockIsReleased(): void
	{
		// Given a write_config() that throws
		$this->arrange([]);
		$current = pfb_core_dns_settings();
		$GLOBALS['pfb_test_write_config_hook'] = static function (): never {
			throw new RuntimeException('config.xml could not be written');
		};

		// When the adapter serves the write
		$out = pfb_core_settings_serve((string) json_encode(self::writeRequest($current, array_merge($current, ['hstsNullBlocking' => FALSE]))));

		// Then the reply is the refusal, as one JSON object, with nothing written and the lock released
		$reply = json_decode($out, TRUE);
		$this->assertSame('unavailable', $reply['error']['code'], $out);
		$this->assertStringContainsString('config.xml could not be written', $reply['error']['message']);
		$this->assertSame($current, (static function (array $disk): array {
			$GLOBALS['config'] = $disk;
			return pfb_core_dns_settings();
		})($this->disk), 'config.xml on disk is as it was');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
		$this->assertFileDoesNotExist("{$this->dir}/pending");
	}

	// ----- no call to Core -----

	public function testTheAdapterNeverCallsCoreWhichIsWaitingOnIt(): void
	{
		// Given a Core stand-in listening on the socket PHP would call, and a positive control that it records a call
		$socket = "{$this->dir}/api.sock";
		$record = "{$this->dir}/requests";
		$this->standIn = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreSettingsStandIn.php', $socket, $record, '{"GetVersion": [200, {}]}']);
		$deadline = hrtime(TRUE) + 10_000_000_000;
		for ($out = ''; !str_contains($out, 'ready'); usleep(1000)) {
			$out .= (string) stream_get_contents($this->standIn[1][1]);
			if (hrtime(TRUE) > $deadline) {
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
		}
		$this->arrange(['gen/pfb_metrics_client_ip' => 'on']);
		$current = pfb_core_dns_settings();

		// When the adapter reads, and writes a change that runs the privacy step too
		$read = $this->backend(['version' => 1, 'op' => 'read']);
		$write = $this->backend(self::writeRequest($current, array_merge($current, ['metricsClientIp' => FALSE, 'hstsNullBlocking' => FALSE])));

		// Then both worked, and the stand-in got nothing
		$this->assertArrayHasKey('settings', $read);
		$this->assertSame(['version' => 1, 'revision' => pfb_core_settings_revision(self::settings(array_merge($current, ['metricsClientIp' => FALSE, 'hstsNullBlocking' => FALSE])))], $write);
		$this->assertFileDoesNotExist($record, 'the adapter called Core');
		$this->assertSame(200, pfb_core_call('GetVersion')['status'], 'positive control: a call is recorded');
		$this->assertFileExists($record);
	}

	// ----- the wrapper -----

	public function testTheWrapperExecsTheVerbAndNothingElse(): void
	{
		$lines = file(self::WRAPPER, FILE_IGNORE_NEW_LINES);

		$this->assertIsArray($lines, 'the wrapper exists');
		$this->assertCount(3, $lines);
		$this->assertSame('#!/bin/sh', $lines[0]);
		$this->assertStringStartsWith('# ', $lines[1]);
		$this->assertSame('exec /usr/local/bin/php -d display_errors=stderr -f /usr/local/pkg/pfblockerng/pfblockerng.inc core_settings', $lines[2]);
		$this->assertTrue(is_executable(self::WRAPPER), 'the nightly port installs *.sh with their mode; Core execs it');
		$syntax = pfb_test_run_process(['/bin/sh', '-n', self::WRAPPER]);
		$this->assertSame(0, $syntax['exit'], $syntax['stderr']);
	}

	/** A warning or notice PHP prints while it loads or serves goes to stderr: Core reads stdout as exactly one JSON object. */
	public function testTheWrappersPhpOptionsKeepAWarningOffStdout(): void
	{
		$lines = file(self::WRAPPER, FILE_IGNORE_NEW_LINES);
		$this->assertIsArray($lines, 'the wrapper exists');
		$this->assertSame(1, preg_match('#^exec /usr/local/bin/php((?: \S+)*?) -f /usr/local/pkg/pfblockerng/pfblockerng\.inc core_settings$#', $lines[2], $m), $lines[2]);
		$options = array_values(array_filter(explode(' ', $m[1])));

		$run = pfb_test_run_process([PHP_BINARY, '-d', 'display_errors=1', '-d', 'error_reporting=-1', ...$options, '-r', 'echo $undefined; echo "{}";']);

		$this->assertSame('{}', $run['stdout'], 'stdout holds the reply only');
		$this->assertStringContainsString('Undefined variable $undefined', $run['stderr'], 'the warning went to stderr');
	}
}
