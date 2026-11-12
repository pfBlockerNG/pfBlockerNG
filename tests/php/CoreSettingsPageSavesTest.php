<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';
require_once __DIR__ . '/PageStatementLoader.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3913: every page that writes a `settings/dns` field asks Core's dry run (ValidateSettings) after its own checks and its
 * in-memory writes and before write_config(), and pushes the settings to Core (forced: always asks Core) after a successful
 * write_config() only. A Core refusal is shown as input errors and nothing is written; a Core that does not answer never blocks
 * the save and leaves the push failure for DNS General to show. The writers: DNS > General (`dnsbl/pfb_py_reply`), DNS > DNSBL (the
 * other DNSBL fields) and General (`gen/pfb_metrics_client_ip`).
 *
 * The saves of DNS > General and DNS > DNSBL are the pages' real POST code (support/DnsSaveWorker.php, DnsblSaveWorker.php) and
 * General's is the page's own callback region run in-process; each talks to a Core stand-in (support/CoreSettingsStandIn.php) that
 * answers from a script and records every request it gets.
 */
final class CoreSettingsPageSavesTest extends TestCase
{
	private const GENERAL_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_general.php';
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
		$GLOBALS['pfb']['core_pushed'] = "{$this->dir}/core_pushed";
		$GLOBALS['pfb']['core_push_failed'] = "{$this->dir}/core_push_failed";
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
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_write_config_result'], $GLOBALS['pfb_test_info_boxes']);
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
	 * A Core that accepts the dry run, holds `$held` for settings/dns and takes the push.
	 *
	 * @param array<string, bool|int|string> $held
	 * @return array<string, array{0: int, 1: array}>
	 */
	private static function accepting(array $held): array
	{
		return [
			'ValidateSettings' => [200, []],
			'GetSettings'      => [200, ['initialized' => TRUE, 'revision' => 3, 'projections' => [['resourceId' => 'settings/dns', 'generation' => 1, 'value' => $held]]]],
			'SaveSettings'     => [200, ['revision' => 4]],
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
		$this->assertSame(['ValidateSettings'], $this->methods(), 'a refused save pushes nothing');
	}

	/** @return array<string, array{0: string, 1: ?string, 2: bool}> posted value, stored value, the replyLogging Core is pushed */
	public static function replyLoggingSaves(): array
	{
		return ['unticked over a stored on' => [NULL, 'on', FALSE], 'ticked over a stored off' => ['on', '', TRUE]];
	}

	#[DataProvider('replyLoggingSaves')]
	public function testAnAcceptedDnsGeneralSaveValidatesTheSavedValuesThenPushesThemAfterTheWrite(?string $posted, string $stored, bool $expected): void
	{
		$socket = $this->core(self::accepting(['replyLogging' => !$expected]));

		$result = $this->save('DnsSaveWorker', 'plain', ['core' => ['socket' => $socket], 'stored' => ['dnsbl/pfb_py_reply' => $stored], 'post' => ['pfb_py_reply' => $posted]]);

		$this->assertSame($stored, $result['before']['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_py_reply'], 'before the save Core and config.xml differ');
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::DNS_SAVE], $result['writes']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$requests = $this->requests();
		$this->assertSame(['ValidateSettings', 'GetSettings', 'SaveSettings'], array_column($requests, 'method'));
		$this->assertSame($expected, $requests[0]['body']['changes']['dns']['replyLogging'], 'the dry run judges the values this save leaves, in memory');
		$this->assertSame($expected, $requests[2]['body']['changes']['dns']['replyLogging'], 'the push sends the saved value');
		$this->assertNull($result['pushFailed']);
	}

	public function testTheDnsGeneralPushIsForcedSoARecordOfTheSameSecondDoesNotSkipIt(): void
	{
		$socket = $this->core(self::accepting(['replyLogging' => TRUE]));

		$this->save('DnsSaveWorker', 'plain', ['core' => ['socket' => $socket, 'pushed' => ['time' => '', 'hash' => 'seeded']]]);

		$this->assertSame(['ValidateSettings', 'GetSettings', 'SaveSettings'], $this->methods(), 'config.xml has no revision time and the record has none: an unforced push would skip');
	}

	/** @return array<string, array{string}> pfSense returns FALSE for a refusal, -1 for a file-write failure */
	public static function failedWrites(): array
	{
		return ['write refused' => ['write_refused'], 'file write failed' => ['write_failed']];
	}

	#[DataProvider('failedWrites')]
	public function testAFailedDnsGeneralWriteIsNotPushed(string $scenario): void
	{
		$socket = $this->core(self::accepting(['replyLogging' => TRUE]));

		$result = $this->save('DnsSaveWorker', $scenario, ['core' => ['socket' => $socket]]);

		$this->assertNotSame([], $result['inputErrors'], 'a refused write is a save error');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'the dry run ran before the write; nothing was pushed after it');
	}

	public function testACoreThatDoesNotAnswerNeverBlocksTheDnsGeneralSaveAndLeavesThePushFailure(): void
	{
		$result = $this->save('DnsSaveWorker', 'plain', []);

		$this->assertSame([self::DNS_SAVE], $result['writes']);
		$this->assertSame([], $result['inputErrors']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$this->assertIsString($result['pushFailed']);
		$this->assertStringContainsString('did not answer', $result['pushFailed']);
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
		$this->assertSame(['ValidateSettings'], $this->methods(), 'a refused save pushes nothing');
	}

	public function testAnAcceptedDnsblSaveValidatesTheSavedValuesThenPushesThemAfterTheWrite(): void
	{
		$socket = $this->core(self::accepting(['hstsNullBlocking' => FALSE, 'tldWildcard' => FALSE, 'idnMode' => 'off']));

		$result = $this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on']]);

		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::DNSBL_SAVE], $result['writes']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$requests = $this->requests();
		$this->assertSame(['ValidateSettings', 'GetSettings', 'SaveSettings'], array_column($requests, 'method'));
		foreach ([0, 2] as $index) {
			$dns = $requests[$index]['body']['changes']['dns'];
			$this->assertTrue($dns['hstsNullBlocking'], "{$requests[$index]['method']}: the posted HSTS");
			$this->assertTrue($dns['tldWildcard'], "{$requests[$index]['method']}: the posted TLD wildcard");
			$this->assertSame('confusable', $dns['idnMode'], "{$requests[$index]['method']}: the posted IDN mode");
		}
		$this->assertNull($result['pushFailed']);
	}

	public function testTheDnsblPushIsForcedSoARecordOfTheSameSecondDoesNotSkipIt(): void
	{
		$socket = $this->core(self::accepting(['hstsNullBlocking' => FALSE]));

		$this->save('DnsblSaveWorker', 'plain', ['core' => ['socket' => $socket, 'pushed' => ['time' => '', 'hash' => 'seeded']], 'post' => ['pfb_hsts' => 'on']]);

		$this->assertSame(['ValidateSettings', 'GetSettings', 'SaveSettings'], $this->methods());
	}

	#[DataProvider('failedWrites')]
	public function testAFailedDnsblWriteIsNotPushed(string $scenario): void
	{
		$socket = $this->core(self::accepting(['hstsNullBlocking' => FALSE]));

		$result = $this->save('DnsblSaveWorker', $scenario, ['core' => ['socket' => $socket], 'post' => ['pfb_hsts' => 'on']]);

		$this->assertNotSame([], $result['inputErrors'], 'a refused write is a save error');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'the dry run ran before the write; nothing was pushed after it');
	}

	public function testACoreThatDoesNotAnswerNeverBlocksTheDnsblSaveAndLeavesThePushFailure(): void
	{
		$result = $this->save('DnsblSaveWorker', 'plain', []);

		$this->assertSame([self::DNSBL_SAVE], $result['writes']);
		$this->assertSame([], $result['inputErrors']);
		$this->assertFalse($result['returned'], 'the save ends in its redirect');
		$this->assertIsString($result['pushFailed']);
		$this->assertStringContainsString('did not answer', $result['pushFailed']);
	}

	// ----- W3: General -----

	/**
	 * The General page's save of `gen/pfb_metrics_client_ip`: its own region, from the posted value to the verdict on the privacy
	 * save, run over the doubles. The setting is stored Off and posted On: the dry run sees the new value only if it runs after
	 * the section is written in memory.
	 *
	 * @return array<string, mixed> the region's variables afterwards
	 */
	private function generalSave(): array
	{
		$region = pfb_test_page_region(self::GENERAL_PAGE, "\$pfb['gconfig']['pfb_metrics_client_ip'] = pfb_filter(", 'if ($privacy_error !== NULL) {');
		$_POST['pfb_metrics_client_ip'] = 'on';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		return pfb_test_page_eval($region, ['pfb' => ['gconfig' => ['enable_cb' => 'on']], 'input_errors' => []]);
	}

	public function testACoreRefusalBlocksTheGeneralSaveAndIsReportedAsInputErrors(): void
	{
		$this->core(['ValidateSettings' => self::refusal('metricsClientIp')]);

		$scope = $this->generalSave();

		$this->assertSame([self::refusedMessage('metricsClientIp')], $scope['input_errors']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$this->assertSame(['ValidateSettings'], $this->methods(), 'a refused save pushes nothing');
	}

	public function testAnAcceptedGeneralSaveValidatesTheSavedValuesThenPushesThemAfterTheWrite(): void
	{
		$this->core(self::accepting(['metricsClientIp' => FALSE]));

		$scope = $this->generalSave();

		$this->assertSame([], $scope['input_errors']);
		$this->assertSame([self::GENERAL_SAVE], $GLOBALS['pfb_test_write_config_calls']);
		$requests = $this->requests();
		$this->assertSame(['ValidateSettings', 'GetSettings', 'SaveSettings'], array_column($requests, 'method'));
		$this->assertTrue($requests[0]['body']['changes']['dns']['metricsClientIp'], 'the dry run judges the section as this save leaves it');
		$this->assertTrue($requests[2]['body']['changes']['dns']['metricsClientIp'], 'the push sends the saved value');
	}

	public function testAGeneralSaveForcesThePushSoARecordOfTheSameSecondDoesNotSkipIt(): void
	{
		$this->core(self::accepting(['metricsClientIp' => FALSE]));
		file_put_contents($GLOBALS['pfb']['core_pushed'], json_encode(['time' => '', 'hash' => 'seeded']));

		$this->generalSave();

		$this->assertSame(['ValidateSettings', 'GetSettings', 'SaveSettings'], $this->methods());
	}

	#[DataProvider('failedWriteResults')]
	public function testAFailedGeneralWriteIsNotPushed(bool|int $result): void
	{
		$this->core(self::accepting(['metricsClientIp' => FALSE]));
		$GLOBALS['pfb_test_write_config_result'] = $result;

		$this->generalSave();

		$this->assertSame(['ValidateSettings'], $this->methods(), 'the dry run ran before the write; nothing was pushed after it');
	}

	/** @return array<string, array{bool|int}> what pfSense's write_config() answers for a refusal and for a file-write failure */
	public static function failedWriteResults(): array
	{
		return ['write refused' => [FALSE], 'file write failed' => [-1]];
	}

	public function testACoreThatDoesNotAnswerNeverBlocksTheGeneralSaveAndLeavesThePushFailure(): void
	{
		$scope = $this->generalSave();

		$this->assertSame([], $scope['input_errors']);
		$this->assertSame([self::GENERAL_SAVE], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertStringContainsString('did not answer', (string) @file_get_contents($GLOBALS['pfb']['core_push_failed']));
	}

	// ----- DNS General: the push-failure notice -----

	/** @return list<array{0: string, 1: string}> the info boxes DNS General's push-failure notice prints (its own region of the page) */
	private function dnsGeneralBoxes(): array
	{
		$GLOBALS['pfb_test_info_boxes'] = [];
		pfb_test_page_eval(pfb_test_page_region(self::DNS_PAGE, "if (is_file(\$pfb['core_push_failed'])) {", 'pfb_print_pending_changes_box();'), ['pfb' => $GLOBALS['pfb']]);
		return $GLOBALS['pfb_test_info_boxes'];
	}

	public function testDnsGeneralShowsTheEscapedPushFailureInAWarningBox(): void
	{
		file_put_contents($GLOBALS['pfb']['core_push_failed'], 'the Core API did not answer: <b>"refused"</b> & more');

		$boxes = array_values(array_filter($this->dnsGeneralBoxes(), static fn (array $box): bool => str_contains($box[0], 'does not have the saved settings yet')));

		$this->assertSame([[
			'pfBlockerNG Core does not have the saved settings yet: the Core API did not answer: &lt;b&gt;&quot;refused&quot;&lt;/b&gt; &amp; more. '
			. 'They are saved in the pfSense configuration; the next tick sends them again.',
			'warning',
		]], $boxes);
	}

	public function testDnsGeneralShowsNoPushFailureNoticeWhenThereIsNoFailure(): void
	{
		$boxes = array_filter($this->dnsGeneralBoxes(), static fn (array $box): bool => str_contains($box[0], 'does not have the saved settings yet'));

		$this->assertSame([], array_values($boxes));
	}
}
