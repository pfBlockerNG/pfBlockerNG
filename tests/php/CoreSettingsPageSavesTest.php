<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';
require_once __DIR__ . '/PageStatementLoader.php';
require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issues #3913, #3924: every page that writes a `settings/dns` field asks Core's dry run (ValidateSettings) after its own checks and
 * its in-memory writes and before write_config(), and tells Core (SettingsChanged: it reads config.xml through its settings adapter)
 * after a successful write_config() only. A Core refusal is shown as input errors and nothing is written; a Core that does not
 * answer never blocks the save and leaves the failure for DNS General to show. The writers: DNS > General (`dnsbl/pfb_py_reply`),
 * DNS > DNSBL (the other DNSBL fields) and General (`gen/pfb_metrics_client_ip`).
 *
 * The saves of DNS > General and DNS > DNSBL are the pages' real POST code (support/DnsSaveWorker.php, DnsblSaveWorker.php) and
 * General's is the page's own save region run in-process (pfb_test_general_save()); each talks to a Core stand-in (support/CoreSettingsStandIn.php) that
 * answers from a script and records every request it gets.
 */
final class CoreSettingsPageSavesTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const DNS_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dns_general.php';
	private const DNS_SAVE = '[pfBlockerNG] save DNS settings';
	private const DNSBL_SAVE = '[pfBlockerNG] save DNSBL settings';
	private const GENERAL_SAVE = '[pfBlockerNG] save General settings';

	private string $dir;
	/** @var ?array{0: resource, 1: array<int, resource>, 2: string} the running stand-in */
	private ?array $standIn = NULL;
	private array $priorConfig;
	private array $priorPfb;
	private array $priorPost;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->priorPost = $_POST;
		$this->dir = sys_get_temp_dir() . '/pfb_core_pages_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['core_socket'] = "{$this->dir}/api.sock";
		$GLOBALS['pfb']['core_settings_failed'] = "{$this->dir}/core_settings_failed";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['dnsbl_info'] = "{$this->dir}/dnsbl_info.sqlite";
		$GLOBALS['pfb']['dnsbl_resolver'] = "{$this->dir}/dnsbl_resolver.sqlite";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
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
		$GLOBALS['pfb'] = $this->priorPfb;
		$_POST = $this->priorPost;
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_write_config_result'], $GLOBALS['pfb_test_info_boxes'],
			$GLOBALS['pfb_test_write_config_hook'], $GLOBALS['pfb_test_config_read_hook'], $GLOBALS['pfb_test_config_read_calls'],
			$GLOBALS['pfb_test_try_lock_fail'], $GLOBALS['pfb_test_lock_held'], $GLOBALS['pfb_test_lock_events']);
		rmdir_recursive($this->dir);
	}

	/**
	 * Start the Core stand-in on the sandbox's socket with $script; returns once it listens.
	 *
	 * @param array<string, array{0: int, 1: array}> $script method => [status, reply object]
	 */
	private function core(array $script): string
	{
		$socket = "{$this->dir}/api.sock";
		$this->standIn = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreSettingsStandIn.php', $socket, "{$this->dir}/requests", json_encode($script, JSON_THROW_ON_ERROR)]);
		$deadline = hrtime(TRUE) + 10_000_000_000;
		$out = '';
		while (!str_contains($out, 'ready')) {
			$out .= (string) stream_get_contents($this->standIn[1][1]);
			if (hrtime(TRUE) > $deadline) {
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
			usleep(1000);
		}
		return $socket;
	}

	/** @return list<array{method: string, body: array}> every request the stand-in got, in order */
	private function requests(): array
	{
		$lines = @file("{$this->dir}/requests", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		return array_map(static fn (string $line): array => json_decode($line, TRUE, 512, JSON_THROW_ON_ERROR), $lines);
	}

	/** @return list<string> */
	private function methods(): array
	{
		return array_column($this->requests(), 'method');
	}

	/** @return array{0: int, 1: array} Core refuses `settings/dns` for one field */
	private static function refusal(string $field): array
	{
		return [400, ['error' => ['code' => 'invalid_argument', 'message' => 'the settings are invalid',
			'fieldErrors' => [['field' => "changes.dns.{$field}", 'message' => 'refused by the stand-in']]]]];
	}

	/**
	 * A Core that accepts the dry run and takes the notice that config.xml changed.
	 *
	 * @return array<string, array{0: int, 1: array}>
	 */
	private static function accepting(): array
	{
		return [
			'ValidateSettings' => [200, []],
			'GetSettings'      => [200, ['initialized' => TRUE, 'revision' => 3, 'projections' => []]],
			'SettingsChanged'  => [200, ['initialized' => TRUE, 'revision' => 4, 'projections' => []]],
		];
	}

	/**
	 * One real save of a page's POST handler in a child process.
	 *
	 * @param array<string, mixed> $case the worker's case
	 * @return array<string, mixed> the worker's result
	 */
	private function save(string $worker, string $scenario, array $case): array
	{
		$resultFile = "{$this->dir}/result.json";
		$run = pfb_test_run_process([PHP_BINARY, __DIR__ . "/support/{$worker}.php", $scenario, $resultFile, json_encode($case, JSON_THROW_ON_ERROR)], 60.0);
		$this->assertFileExists($resultFile, "worker did not report (exit {$run['exit']}): {$run['stderr']}{$run['stdout']}");
		return json_decode((string) file_get_contents($resultFile), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	private static function refusedMessage(string $field): string
	{
		return "pfBlockerNG Core refused the DNS settings: dns.{$field}: refused by the stand-in";
	}

	// ----- W1: DNS > General -----

	public function testACoreRefusalBlocksTheDnsGeneralSaveAndShowsTheError(): void
	{
		$socket = $this->core(['ValidateSettings' => self::refusal('replyLogging')]);

		$result = $this->save('DnsSaveWorker', 'plain', ['core' => ['socket' => $socket]]);

		$this->assertSame([self::refusedMessage('replyLogging')], $result['inputErrors']);
		$this->assertSame([], $result['writes'], 'nothing is written');
		$this->assertSame($result['before'], $result['disk'], 'config.xml is as it was');
		$this->assertTrue($result['returned'], 'the page renders the errors, rather than exiting through its redirect');
		$this->assertFalse($result['pendingMarked']);
		$this->assertFalse($result['lockHeld'], 'the lock is released');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'a refused save tells Core nothing');
	}

	/** @return array<string, array{0: string, 1: ?string, 2: bool}> posted value, stored value, the replyLogging the dry run judges */
	public static function replyLoggingSaves(): array
	{
		return ['unticked over a stored on' => [NULL, 'on', FALSE], 'ticked over a stored off' => ['on', '', TRUE]];
	}

	#[DataProvider('replyLoggingSaves')]
	public function testAnAcceptedDnsGeneralSaveValidatesTheSavedValuesThenTellsCoreAfterTheWrite(?string $posted, string $stored, bool $expected): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsSaveWorker', 'plain', ['core' => ['socket' => $socket], 'stored' => ['dnsbl/pfb_py_reply' => $stored], 'post' => ['pfb_py_reply' => $posted]]);

		$this->assertSame($stored, $result['before']['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_py_reply'], 'before the save config.xml holds the other value');
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::DNS_SAVE], $result['writes']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$requests = $this->requests();
		$this->assertSame(['ValidateSettings', 'SettingsChanged'], array_column($requests, 'method'));
		$this->assertSame($expected, $requests[0]['body']['changes']['dns']['replyLogging'], 'the dry run judges the values this save leaves, in memory');
		$this->assertSame([], $requests[1]['body'], 'Core reads the saved values itself: the notice carries none');
		$this->assertNull($result['settingsFailed']);
	}

	public function testTheDnsGeneralNoticeIsForcedSoCoreIsToldWithoutAskingItsRevision(): void
	{
		$socket = $this->core(self::accepting());

		$this->save('DnsSaveWorker', 'plain', ['core' => ['socket' => $socket]]);

		$this->assertSame(['ValidateSettings', 'SettingsChanged'], $this->methods(), 'an unforced notice would call GetSettings first');
	}

	/** @return array<string, array{string}> pfSense returns FALSE for a refusal, -1 for a file-write failure */
	public static function failedWrites(): array
	{
		return ['write refused' => ['write_refused'], 'file write failed' => ['write_failed']];
	}

	#[DataProvider('failedWrites')]
	public function testAFailedDnsGeneralWriteIsNotNotifiedToCore(string $scenario): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsSaveWorker', $scenario, ['core' => ['socket' => $socket]]);

		$this->assertNotSame([], $result['inputErrors'], 'a refused write is a save error');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'the dry run ran before the write; Core was not told after it');
	}

	public function testACoreThatDoesNotAnswerNeverBlocksTheDnsGeneralSaveAndLeavesTheFailure(): void
	{
		$result = $this->save('DnsSaveWorker', 'plain', []);

		$this->assertSame([self::DNS_SAVE], $result['writes']);
		$this->assertSame([], $result['inputErrors']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$this->assertIsString($result['settingsFailed']);
		$this->assertStringContainsString('did not answer', $result['settingsFailed']);
	}

	// ----- W2: DNS > DNSBL -----

	public function testACoreRefusalBlocksTheDnsblSaveAndShowsTheError(): void
	{
		$socket = $this->core(['ValidateSettings' => self::refusal('hstsNullBlocking')]);

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on']]);

		$this->assertSame([self::refusedMessage('hstsNullBlocking')], $result['inputErrors']);
		$this->assertSame([], $result['writes'], 'nothing is written');
		$this->assertSame($result['before'], $result['disk'], 'config.xml is as it was');
		$this->assertTrue($result['returned'], 'the page renders the errors, rather than exiting through its redirect');
		$this->assertSame('8082', $result['postedPort'], 'the form re-displays what was submitted');
		$this->assertFalse($result['pendingMarked']);
		$this->assertFalse($result['lockHeld'], 'the lock is released');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'a refused save tells Core nothing');
	}

	public function testAnAcceptedDnsblSaveValidatesTheSavedValuesThenTellsCoreAfterTheWrite(): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on']]);

		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::DNSBL_SAVE], $result['writes']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$requests = $this->requests();
		$this->assertSame(['ValidateSettings', 'SettingsChanged'], array_column($requests, 'method'));
		$dns = $requests[0]['body']['changes']['dns'];
		$this->assertTrue($dns['hstsNullBlocking'], 'the dry run judges the posted HSTS');
		$this->assertTrue($dns['tldWildcard'], 'the dry run judges the posted TLD wildcard');
		$this->assertSame('confusable', $dns['idnMode'], 'the dry run judges the posted IDN mode');
		$this->assertNull($result['settingsFailed']);
	}

	public function testTheDnsblNoticeIsForcedSoCoreIsToldWithoutAskingItsRevision(): void
	{
		$socket = $this->core(self::accepting());

		$this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on']]);

		$this->assertSame(['ValidateSettings', 'SettingsChanged'], $this->methods());
	}

	#[DataProvider('failedWrites')]
	public function testAFailedDnsblWriteIsNotNotifiedToCore(string $scenario): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsblSaveWorker', $scenario, ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on']]);

		$this->assertNotSame([], $result['inputErrors'], 'a refused write is a save error');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'the dry run ran before the write; Core was not told after it');
	}

	public function testACoreThatDoesNotAnswerNeverBlocksTheDnsblSaveAndLeavesTheFailure(): void
	{
		$result = $this->save('DnsblSaveWorker', 'plain', []);

		$this->assertSame([self::DNSBL_SAVE], $result['writes']);
		$this->assertSame([], $result['inputErrors']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$this->assertIsString($result['settingsFailed']);
		$this->assertStringContainsString('did not answer', $result['settingsFailed']);
	}

	// ----- W2: the DNSBL save's file side effects (issue #3922) -----

	/** The TOP1M download's baseline files the save invalidates when the provider changes: all of them, as the worker seeds them. */
	private const BASELINE = ['.orig', '.xxhash128', '.md5', '.source', '.orig.etag', '.orig.lastmod'];
	/** The posts that give every side effect its trigger: a new TOP1M provider (baseline), a new count (rebuild marker). */
	private const TRIGGERS = ['top1m_source' => 'majestic', 'top1m_count' => '2000'];

	/** @return array<string, array{string, bool, bool}> the worker scenario, whether Core refuses the dry run, and whether the page reports an input error */
	public static function unwrittenSaves(): array
	{
		return [
			'Core refuses the settings' => ['plain', TRUE, TRUE],
			'write refused'             => ['write_refused', FALSE, TRUE],
			'file write failed'         => ['write_failed', FALSE, TRUE],
			'write throws'              => ['write_throws', FALSE, FALSE],
		];
	}

	#[DataProvider('unwrittenSaves')]
	public function testASaveThatIsNotWrittenLeavesTheTop1mBaselineTheRebuildMarkerAndTheBlockPageAlone(string $scenario, bool $coreRefuses, bool $inputError): void
	{
		// Given a Core that refuses the settings (or accepts them, with pfSense then failing the write), and a save that posts a new
		// block page, a new TOP1M provider and a new TOP1M count
		$socket = $this->core($coreRefuses ? ['ValidateSettings' => self::refusal('hstsNullBlocking')] : self::accepting());

		$result = $this->save('DnsblSaveWorker', $scenario, ['core' => ['socket' => $socket], 'post' => self::TRIGGERS + ['pfb_hsts' => 'on']]);

		// Then the save failed, and before it all three effects were waiting to happen: the baseline in place, no marker, the old page
		$this->assertSame($inputError, $result['inputErrors'] !== [], 'the save was not written, and the page says so unless it threw');
		['before' => $before, 'after' => $after] = $result['effects'];
		$this->assertSame(['baseline' => self::BASELINE, 'updateMarker' => FALSE, 'activePage' => 'ACTIVE ORIGINAL'], $before, 'before the save');
		$this->assertSame($before, $after, 'a save that was not written must leave the TOP1M baseline, the TOP1M rebuild marker and the served block page as they were');
		$this->assertSame([$before], $result['effects']['atUnlock'], 'the lock was released once, with nothing done yet');
	}

	public function testAnAcceptedDnsblSaveInvalidatesTheTop1mBaselineRequestsTheRebuildAndServesTheNewBlockPage(): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => self::TRIGGERS]);

		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::DNSBL_SAVE], $result['writes']);
		['before' => $before, 'after' => $after] = $result['effects'];
		$this->assertSame(['baseline' => self::BASELINE, 'updateMarker' => FALSE, 'activePage' => 'ACTIVE ORIGINAL'], $before, 'before the save');
		$this->assertSame(['baseline' => [], 'updateMarker' => TRUE, 'activePage' => 'ALTERNATIVE PAGE'], $after, 'after the save');
	}

	public function testAnAcceptedDnsblSaveRunsItsFileSideEffectsBeforeItReleasesTheConfigLock(): void
	{
		// Given an accepted save that gives every effect its trigger
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => self::TRIGGERS]);

		// Then the lock was released once, and by then the baseline, the marker and the served page were all done: another save
		// cannot take the lock between the write and the effects and leave the served block page out of step with config.xml
		$effects = $result['effects'];
		$this->assertSame([self::DNSBL_SAVE], $result['writes']);
		$this->assertSame(['baseline' => self::BASELINE, 'updateMarker' => FALSE, 'activePage' => 'ACTIVE ORIGINAL'], $effects['before'], 'before the save');
		$this->assertSame([$effects['after']], $effects['atUnlock'], 'the effects belong under the config lock');
		$this->assertSame(['baseline' => [], 'updateMarker' => TRUE, 'activePage' => 'ALTERNATIVE PAGE'], $effects['after'], 'after the save');
	}

	private const MIGRATION_SAVE = 'pfBlockerNG: migrated DNSBL global logging policy to Default/Override (issue #3288)';
	private const BLOCK_PAGE = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_webpage';

	/** @param array<string, mixed> $config */
	private static function storedBlockPage(array $config): mixed
	{
		return $config['installedpackages']['pfblockerngdnsblsettings']['config'][0]['dnsbl_webpage'] ?? NULL;
	}

	public function testACoreRefusedSaveOverAPreMigrationPolicyDoesNotStoreTheChosenBlockPageThroughTheUpgradeFacade(): void
	{
		// Given a stored policy the upgrade facade has to migrate, which it writes to config.xml in the middle of the save, and a
		// Core that refuses the save that picks another block page
		$socket = $this->core(['ValidateSettings' => self::refusal('hstsNullBlocking')]);

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on'], 'seed' => ['migrated' => FALSE]]);

		// Then the facade's write happened (so the save was in a position to persist the page), config.xml still names the old page,
		// the served page is the old one, and a later save still copies the page it chooses
		$this->assertSame([self::refusedMessage('hstsNullBlocking')], $result['inputErrors']);
		$this->assertSame([self::MIGRATION_SAVE], $result['writes'], 'the facade wrote config.xml itself; the refused save wrote nothing');
		$this->assertSame('dnsbl_default.php', self::storedBlockPage($result['before']), 'before the save');
		$this->assertSame('dnsbl_default.php', self::storedBlockPage($result['disk']), 'a refused save stores the block page it chose');
		$this->assertSame('ACTIVE ORIGINAL', $result['effects']['after']['activePage']);
	}

	public function testAnAcceptedSaveOverAPreMigrationPolicyStoresTheChosenBlockPageAndServesIt(): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on'], 'seed' => ['migrated' => FALSE]]);

		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::MIGRATION_SAVE, self::DNSBL_SAVE], $result['writes'], 'the facade writes, then the save');
		$this->assertSame('dnsbl_default.php', self::storedBlockPage($result['before']), 'before the save');
		$this->assertSame('dnsbl_alt.php', self::storedBlockPage($result['disk']), 'the save stores the block page it chose');
		$this->assertSame('ALTERNATIVE PAGE', $result['effects']['after']['activePage'], 'and serves it');
	}

	/** @return array<string, array{array<string, string>, array<string, mixed>, list<string>, bool, string}> each trigger on its own: posts, case, baseline left, marker, served page */
	public static function sideEffectTriggers(): array
	{
		$still = ['webpageChanged' => FALSE];
		return [
			'a new TOP1M provider invalidates only the baseline'     => [['top1m_source' => 'majestic'], $still, [], FALSE, 'ACTIVE ORIGINAL'],
			'a new TOP1M count requests only the rebuild'            => [['top1m_count' => '2000'], $still, self::BASELINE, TRUE, 'ACTIVE ORIGINAL'],
			'a new block page replaces only the served page'         => [[], [], self::BASELINE, FALSE, 'ALTERNATIVE PAGE'],
			'a block page that is missing is served again unchanged' => [[], ['webpageChanged' => FALSE, 'activePage' => NULL], self::BASELINE, FALSE, 'ALTERNATIVE PAGE'],
			'an unchanged save touches none of them'                 => [[], $still, self::BASELINE, FALSE, 'ACTIVE ORIGINAL'],
		];
	}

	/**
	 * @param array<string, string> $post
	 * @param array<string, mixed> $case
	 * @param list<string> $baseline
	 */
	#[DataProvider('sideEffectTriggers')]
	public function testAnAcceptedDnsblSavePerformsEachFileSideEffectOnlyForItsOwnTrigger(array $post, array $case, array $baseline, bool $marker, string $servedPage): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => $post] + $case);

		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::DNSBL_SAVE], $result['writes'], 'the save was written');
		$this->assertSame(['baseline' => $baseline, 'updateMarker' => $marker, 'activePage' => $servedPage], $result['effects']['after']);
	}

	// ----- W3: General -----

	/**
	 * The General page's save over the doubles (its own region: pfb_test_general_save()). The setting is stored Off and posted On:
	 * the dry run sees the new value only if it runs after the section is written in memory.
	 *
	 * @return array<string, mixed> the region's variables afterwards
	 */
	private function generalSave(): array
	{
		$GLOBALS['pfb_test_write_config_calls'] = [];
		return pfb_test_general_save(['pfb_metrics_client_ip' => 'on']);
	}

	public function testACoreRefusalBlocksTheGeneralSaveAndIsReportedAsInputErrors(): void
	{
		$this->core(['ValidateSettings' => self::refusal('metricsClientIp')]);

		$scope = $this->generalSave();

		$this->assertSame([self::refusedMessage('metricsClientIp')], $scope['input_errors']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'a refused save tells Core nothing');
	}

	public function testAnAcceptedGeneralSaveValidatesTheSavedValuesThenTellsCoreAfterTheWrite(): void
	{
		$this->core(self::accepting());

		$scope = $this->generalSave();

		$this->assertSame([], $scope['input_errors']);
		$this->assertSame([self::GENERAL_SAVE], $GLOBALS['pfb_test_write_config_calls']);
		$requests = $this->requests();
		$this->assertSame(['ValidateSettings', 'SettingsChanged'], array_column($requests, 'method'), 'forced: Core is told without asking its revision');
		$this->assertTrue($requests[0]['body']['changes']['dns']['metricsClientIp'], 'the dry run judges the section as this save leaves it');
	}

	#[DataProvider('failedWriteResults')]
	public function testAFailedGeneralWriteIsNotNotifiedToCore(bool|int $result): void
	{
		$this->core(self::accepting());
		$GLOBALS['pfb_test_write_config_result'] = $result;

		$scope = $this->generalSave();

		$this->assertSame(['ValidateSettings'], $this->methods(), 'the dry run ran before the write; Core was not told after it');
		$this->assertSame(['Client IP metrics could not be changed: pfSense refused the configuration write. Client IP metrics remain disabled; retry Save. No General settings were saved.'], $scope['input_errors'], 'a refused write is reported, not shown as a save');
	}

	/** @return array<string, array{bool|int}> what pfSense's write_config() answers for a refusal and for a file-write failure */
	public static function failedWriteResults(): array
	{
		return ['write refused' => [FALSE], 'file write failed' => [-1]];
	}

	public function testACoreThatDoesNotAnswerNeverBlocksTheGeneralSaveAndLeavesTheFailure(): void
	{
		$scope = $this->generalSave();

		$this->assertSame([], $scope['input_errors']);
		$this->assertSame([self::GENERAL_SAVE], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertStringContainsString('did not answer', (string) @file_get_contents($GLOBALS['pfb']['core_settings_failed']));
	}

	// ----- W3: General, past the verdict: the schedule-cache branch and its redirect -----

	public function testACoreRefusedGeneralSaveSkipsTheScheduleCacheBranchAndRendersTheErrors(): void
	{
		$socket = $this->core(['ValidateSettings' => self::refusal('metricsClientIp')]);

		$result = $this->save('GeneralSaveWorker', 'plain', ['core' => ['socket' => $socket]]);

		$this->assertSame([self::refusedMessage('metricsClientIp')], $result['inputErrors']);
		$this->assertTrue($result['returned'], 'the page renders the errors, rather than exiting through its redirect');
		$this->assertFalse($result['synced'], 'a refused save applies nothing');
		$this->assertNull($result['syncSawSave']);
		$this->assertNull($result['redirect'], 'a refused save redirects nowhere');
		$this->assertSame([], $result['writes'], 'nothing is written');
	}

	public function testAnAcceptedGeneralSaveRunsTheScheduleCacheBranchSyncsAndRedirects(): void
	{
		$socket = $this->core(self::accepting());

		$result = $this->save('GeneralSaveWorker', 'plain', ['core' => ['socket' => $socket]]);

		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::GENERAL_SAVE], $result['writes'], 'the save was written');
		$this->assertTrue($result['synced'], 'the saved settings are applied');
		$this->assertTrue($result['syncSawSave'], 'the sync runs as a save: the page sets its save flag first');
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$this->assertSame('Location: /pfblockerng/pfblockerng_general.php', $result['redirect'], 'the schedule cache was generated: the plain page, no failure flag');
	}

	public function testAGeneralSaveKeepsWhatAnotherWriterChangedInAnotherSectionSinceThePageLoaded(): void
	{
		// Given the page loaded HSTS on, and the Core settings adapter then wrote it off under the config lock
		$hsts = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts';
		config_set_path($hsts, 'on');
		$this->configXmlOnDisk();
		$this->disk['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_hsts'] = '';
		$this->core(self::accepting());

		// When General is saved
		$scope = $this->generalSave();

		// Then the adapter's write survives it, and General's own field is saved
		$this->assertSame([], $scope['input_errors']);
		$this->assertSame([self::GENERAL_SAVE], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame('', $this->onDisk($hsts), 'the other section is what the adapter wrote, not the copy the page loaded');
		$this->assertSame('on', $this->onDisk('installedpackages/pfblockerng/config/0/pfb_metrics_client_ip'));
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
	}

	public function testAGeneralSaveWritesUnderTheDnsConfigLockAndInsideItTheMetricsLock(): void
	{
		$this->core(self::accepting());
		$held = [];
		$GLOBALS['pfb_test_write_config_hook'] = static function () use (&$held): void {
			$metrics = pfb_metrics_lock(0.0);
			if ($metrics !== FALSE) {
				fclose($metrics);
			}
			$held = ['dns' => !empty($GLOBALS['pfb_test_lock_held']), 'metrics' => $metrics === FALSE];
		};

		$this->generalSave();

		$this->assertSame(['dns' => TRUE, 'metrics' => TRUE], $held, 'write_config() runs under both locks');
		$this->assertSame('pfb_dns_config', $GLOBALS['pfb_test_lock_events'][0][1] ?? NULL, 'the DNS config lock is the outer one: it is taken before anything else');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the DNS config lock is released');
		$this->assertSame(['ValidateSettings', 'SettingsChanged'], $this->methods());
	}

	public function testAGeneralSaveWhoseConfigLockStaysTakenWritesNothingAndShowsAnError(): void
	{
		$this->core(self::accepting());
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		$scope = $this->generalSave();

		$this->assertSame(['General: another save of the pfSense configuration is in progress. No General settings were saved.'], $scope['input_errors']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$this->assertSame([], $this->methods(), 'a save that was refused asks Core nothing and tells it nothing');
	}

	// ----- DNS General: the notice that Core has not read the saved settings -----

	/** @return list<array{0: string, 1: string}> the info boxes DNS General's notice about Core not having read the settings prints (its own region of the page) */
	private function dnsGeneralBoxes(): array
	{
		$GLOBALS['pfb_test_info_boxes'] = [];
		pfb_test_page_eval(pfb_test_page_region(self::DNS_PAGE, "if (is_file(\$pfb['core_settings_failed'])) {", 'pfb_print_pending_changes_box();'), ['pfb' => $GLOBALS['pfb']]);
		return $GLOBALS['pfb_test_info_boxes'];
	}

	public function testDnsGeneralShowsTheEscapedFailureInAWarningBox(): void
	{
		file_put_contents($GLOBALS['pfb']['core_settings_failed'], 'the Core API did not answer: <b>"refused"</b> & more');

		$boxes = array_values(array_filter($this->dnsGeneralBoxes(), static fn (array $box): bool => str_contains($box[0], 'has not read the saved settings yet')));

		$this->assertSame([[
			'pfBlockerNG Core has not read the saved settings yet: the Core API did not answer: &lt;b&gt;&quot;refused&quot;&lt;/b&gt; &amp; more. '
			. 'They are saved in the pfSense configuration; the next tick tells Core again.',
			'warning',
		]], $boxes);
	}

	public function testDnsGeneralShowsNoNoticeWhenThereIsNoFailure(): void
	{
		$boxes = array_filter($this->dnsGeneralBoxes(), static fn (array $box): bool => str_contains($box[0], 'has not read the saved settings yet'));

		$this->assertSame([], array_values($boxes));
	}
}
