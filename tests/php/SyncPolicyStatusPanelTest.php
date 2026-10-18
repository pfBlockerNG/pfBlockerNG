<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3453 -- Sync page receiver and sender panels (docs/specs/xmlrpc-per-field-sync.md,
 * "Reporting" and acceptance 9 and 14).
 *
 * The receiver panel shows only what this node recorded when a peer sent it a policy: the receive
 * record, the apply record (a row of its own, never folded into the receipt), drift, effective-policy
 * findings and copied-object findings. The sender panel shows only what this node did on its last sync
 * pass ({dbdir}/pfb_sync_send.json, one entry per target) and never claims what a peer did with it:
 * it must not say supported, accepted, applied, drifting or "in sync". Every stored value, including a
 * peer-controlled client error, is escaped on output and a client error never carries the password.
 */
#[CoversFunction('pfb_sync_send_state_read')]
#[CoversFunction('pfb_sync_send_record')]
#[CoversFunction('pfb_sync_receiver_panel')]
#[CoversFunction('pfb_sync_sender_panel')]
#[CoversFunction('pfblockerng_sync_on_changes')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_send')]
#[CoversFunction('pfblockerng_do_xmlrpc_sync')]
final class SyncPolicyStatusPanelTest extends TestCase
{
	private const SCRIPT     = '<script>alert("pfb3453")</script>';
	private const SCRIPT_ESC = '&lt;script&gt;alert(&quot;pfb3453&quot;)&lt;/script&gt;';
	private const ATTR       = '"onmouseover="x';
	private const ATTR_ESC   = '&quot;onmouseover=&quot;x';
	private const AMP        = '&amp;';
	private const AMP_ESC    = '&amp;amp;';
	private const BOLD       = '<b>x</b>';
	private const BOLD_ESC   = '&lt;b&gt;x&lt;/b&gt;';
	private const PASSWORD   = 'S3cr3t/p@ss&w0rd';
	private const T0         = 1700000000;
	private const T0_TEXT    = '2023-11-14 22:13:20';
	private const BANNED     = '/\b(supported|accepted|applied|drifting)\b/i';
	private const IN_SYNC    = '/\bin sync\b/i';

	private string $dir = '';
	private mixed $savedPfb = NULL;
	private mixed $savedConfig = NULL;
	private bool $hadConfig = FALSE;
	private string $savedTz = '';

	protected function setUp(): void
	{
		$this->savedPfb    = $GLOBALS['pfb'];
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedTz     = date_default_timezone_get();
		date_default_timezone_set('UTC');

		$this->dir = sys_get_temp_dir() . '/pfb_sync_panel_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_logger_calls'] = [];
		unset($GLOBALS['pfb_test_xmlrpc_connection'], $GLOBALS['pfb_test_xmlrpc_connections'], $GLOBALS['pfb_test_xmlrpc_calls'], $GLOBALS['pfb_test_xmlrpc_fail']);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/{,.}*', GLOB_BRACE) ?: [] as $entry) {
			if (is_file($entry)) {
				unlink($entry);
			}
		}
		rmdir($this->dir);

		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		date_default_timezone_set($this->savedTz);
		unset($GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_xmlrpc_connection'], $GLOBALS['pfb_test_xmlrpc_connections'], $GLOBALS['pfb_test_xmlrpc_calls'], $GLOBALS['pfb_test_xmlrpc_fail']);
	}

	// ---- helpers -----------------------------------------------------------------------

	/** Runs $fn and fails on any PHP diagnostic: wrong-typed stored values are tolerated, never warned about. */
	private function quiet(callable $fn): mixed
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			if (error_reporting() & $errno) {
				$diagnostics[] = $errstr;
			}
			return TRUE;
		});
		try {
			$result = $fn();
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $diagnostics, 'must not raise a PHP diagnostic: ' . implode('; ', $diagnostics));
		return $result;
	}

	private function sendFile(): string
	{
		return "{$this->dir}/pfb_sync_send.json";
	}

	private function sendBytes(): string
	{
		return (string) @file_get_contents($this->sendFile());
	}

	/** An earlier pass on disk: a regression that records on a no-send path replaces these bytes. */
	private function seedEarlierPass(): string
	{
		$bytes = json_encode(['time' => 1, 'attempts' => [['target' => 'earlier:1', 'time' => 1, 'outcome' => 'sent']]]);
		file_put_contents($this->sendFile(), $bytes);
		return $bytes;
	}

	/** @return list<array{priority:int,message:string,prefix:?string}> */
	private function logged(): array
	{
		return $GLOBALS['pfb_test_logger_calls'];
	}

	/** @return array<string,mixed> */
	private static function alpha(): array
	{
		return [
			'aliasname' => 'Alpha', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay',
			'row' => [0 => ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/Alpha', 'header' => 'HdrAlpha']],
		];
	}

	/** @return array<string,string> */
	private static function target(string $ip, string $password, bool $enabled = TRUE): array
	{
		return [
			'varsyncdestinenable' => $enabled ? 'on' : '',
			'varsyncipaddress'    => $ip,
			'varsyncport'         => '443',
			'varsyncpassword'     => $password,
			'varsyncprotocol'     => 'https',
			'varsyncusername'     => 'admin',
		];
	}

	/**
	 * This node's config: a Deny_Inbound list (so the policy digest is not that of an empty policy)
	 * and a Sync section; $scope NULL leaves the scope leaf unstored.
	 *
	 * @param list<array<string,string>> $rows
	 */
	private function seedNode(string $mode, ?string $scope, array $rows): void
	{
		$sync = ['varsynconchanges' => $mode, 'varsynctimeout' => '5'];
		if ($scope !== NULL) {
			$sync['syncscope'] = $scope;
		}
		if ($rows !== []) {
			$sync['row'] = $rows;
		}
		$GLOBALS['config'] = ['installedpackages' => [
			'pfblockernglistsv4' => ['config' => [0 => self::alpha()]],
			'pfblockerngsync'    => ['config' => [0 => $sync]],
		]];
	}

	/** Targets: A answers, B fails with a hostile error carrying B's own password, C has no password. */
	private function seedThreeTargets(string $mode, ?string $scope): void
	{
		$this->seedNode($mode, $scope, [
			self::target('192.0.2.10', 'secret-a'),
			self::target('192.0.2.11', self::PASSWORD),
			self::target('192.0.2.12', ''),
		]);
		$GLOBALS['pfb_test_xmlrpc_fail']['192.0.2.11'] = 'Exception calling XMLRPC method restore_config_section #-1 : https://admin:' . rawurlencode(self::PASSWORD)
			. '@192.0.2.11:443 with ' . self::PASSWORD . ' ' . self::SCRIPT;
	}

	private function runPass(): void
	{
		$this->quiet(static function (): void {
			pfblockerng_sync_on_changes();
		});
	}

	/** @return array<string,mixed> the receive record of a changed receive */
	private static function receive(array $last = [], array $extra = []): array
	{
		return $extra + ['accepted_digest' => NULL, 'last' => $last + ['time' => self::T0, 'outcome' => 'changed']];
	}

	/** A receiver that holds an accepted digest: only it reports effective-policy findings. */
	private static function accepting(): array
	{
		return ['accepted_digest' => str_repeat('c', 64)] + self::receive();
	}

	/** @return array{time:?int,findings:list<string>} */
	private static function findings(string ...$findings): array
	{
		return ['time' => NULL, 'findings' => array_values($findings)];
	}

	/** @param array<string,mixed> $copied */
	private function receiverPanel(array $receive, ?bool $drift = NULL, array $findings = [], array $copied = []): string
	{
		return $this->quiet(static fn (): string => pfb_sync_receiver_panel($receive, $drift, $findings, $copied));
	}

	/** The inner HTML of one receiver row's value cell, failing when the row is missing. */
	private function cell(string $html, string $key): string
	{
		$this->assertSame(1, preg_match('#<tr id="pfb-sync-receiver-' . $key . '"><th>(.*?)</th><td>(.*?)</td></tr>#s', $html, $m), "row {$key} present exactly once");
		return $m[2];
	}

	/** @return list<list<string>> value cells (Target, Time, Payload digest, Result) of each attempt row */
	private function senderRows(string $html): array
	{
		preg_match_all('#<tr><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td><td>(.*?)</td></tr>#s', $html, $m, PREG_SET_ORDER);
		return array_map(static fn (array $row): array => array_slice($row, 1), $m);
	}

	private function assertEscaped(string $html, string $raw, string $escaped): void
	{
		$this->assertStringContainsString($escaped, $html, "escaped form of {$raw} must be rendered");
		$this->assertStringNotContainsString($raw, str_replace($escaped, '', $html), "raw {$raw} must never reach the page");
	}

	// ---- 1. the send state reader --------------------------------------------------------

	public function testSendStateReadsAsEmptyWhenTheFileIsMissing(): void
	{
		$this->assertSame(['time' => NULL, 'attempts' => []], $this->quiet(fn (): array => pfb_sync_send_state_read($this->dir)));
		$this->assertSame(['time' => NULL, 'attempts' => []], $this->quiet(fn (): array => pfb_sync_send_state_read($this->dir . '/nope')));
	}

	/** @return array<string,array{string}> */
	public static function unreadableSendProvider(): array
	{
		return [
			'empty file'  => [''],
			'corrupt'     => ['{"time": 5, "attempts": ['],
			'string'      => ['"attempts"'],
			'int'         => ['5'],
			'null'        => ['null'],
			'true'        => ['true'],
			'plain list'  => ['[1, 2, 3]'],
		];
	}

	#[DataProvider('unreadableSendProvider')]
	public function testCorruptOrNonObjectSendStateReadsAsEmpty(string $bytes): void
	{
		file_put_contents($this->sendFile(), $bytes);

		$this->assertSame(['time' => NULL, 'attempts' => []], $this->quiet(fn (): array => pfb_sync_send_state_read($this->dir)));
	}

	public function testSendStateKeepsWellFormedAttemptsAndDropsMalformedOnes(): void
	{
		$digest = str_repeat('a', 64);
		$good   = ['target' => '192.0.2.10:443', 'time' => self::T0, 'outcome' => 'sent', 'digest' => $digest];
		file_put_contents($this->sendFile(), json_encode(['time' => self::T0 + 1, 'attempts' => [
			$good,
			['target' => 5, 'time' => 1, 'outcome' => 'sent'],
			['target' => 't', 'time' => '1', 'outcome' => 'sent'],
			['target' => 't', 'time' => 1.5, 'outcome' => 'sent'],
			['target' => 't', 'time' => 1, 'outcome' => 'accepted'],
			['target' => 't', 'time' => 1, 'outcome' => ['sent']],
			['target' => 't', 'time' => 1],
			'junk', 7, NULL, [],
			['target' => 't2', 'time' => 2, 'outcome' => 'failed', 'digest' => ['x'], 'error' => 7, 'password' => self::PASSWORD],
			['target' => 't3', 'time' => 3, 'outcome' => 'handed', 'error' => 'boom'],
		]]));

		$state = $this->quiet(fn (): array => pfb_sync_send_state_read($this->dir));

		$this->assertSame(self::T0 + 1, $state['time']);
		$this->assertSame([
			$good,
			['target' => 't2', 'time' => 2, 'outcome' => 'failed'],
			['target' => 't3', 'time' => 3, 'outcome' => 'handed', 'error' => 'boom'],
		], $state['attempts'], 'wrong-typed digest/error keys and unknown keys are dropped; a malformed entry is dropped whole');
	}

	public function testSendStateWithWrongTypedTopLevelKeysReadsAsEmpty(): void
	{
		file_put_contents($this->sendFile(), json_encode(['time' => '5', 'attempts' => 'junk']));

		$this->assertSame(['time' => NULL, 'attempts' => []], $this->quiet(fn (): array => pfb_sync_send_state_read($this->dir)));
	}

	// ---- 2. the send record publisher ----------------------------------------------------

	public function testRecordPublishesTimeAndReindexedAttemptsRootOnlyWithoutLogging(): void
	{
		$a = ['target' => 'a:1', 'time' => 7, 'outcome' => 'sent'];
		$b = ['target' => 'b:2', 'time' => 8, 'outcome' => 'failed', 'error' => 'boom'];

		$before = time();
		$this->assertTrue(pfb_sync_send_record([5 => $a, 9 => $b], $this->dir));
		$after = time();

		$doc = json_decode($this->sendBytes(), TRUE);
		$this->assertSame(['time', 'attempts'], array_keys($doc));
		$this->assertIsInt($doc['time']);
		$this->assertGreaterThanOrEqual($before, $doc['time']);
		$this->assertLessThanOrEqual($after, $doc['time']);
		$this->assertSame([$a, $b], $doc['attempts'], 'attempts are a re-indexed list');
		$this->assertSame(0600, fileperms($this->sendFile()) & 0777, 'root-only like the other state files');
		$this->assertSame([], $this->logged(), 'a published record logs nothing');
	}

	public function testUnpublishedRecordLogsOneValueFreeLineAndLeavesTheFileAlone(): void
	{
		$earlier = $this->seedEarlierPass();
		$attempt = ['target' => self::PASSWORD . self::SCRIPT, 'time' => 1, 'outcome' => 'failed', 'error' => self::PASSWORD];

		$this->assertFalse(pfb_sync_send_record([$attempt], $this->dir, ['fail_rename' => TRUE]));

		$this->assertSame($earlier, $this->sendBytes());
		$this->assertSame([
			['priority' => LOG_WARNING, 'message' => 'XMLRPC sync attempts: state not published.', 'prefix' => LOG_PREFIX_PKG_PFBLOCKERNG],
		], $this->logged());
	}

	public function testRecordIntoAMissingDirectoryLogsTheSameLineAndWritesNothing(): void
	{
		$this->assertFalse($this->quiet(fn (): bool => pfb_sync_send_record([['target' => 'a:1', 'time' => 1, 'outcome' => 'sent']], $this->dir . '/nope')));

		$this->assertCount(1, $this->logged());
		$this->assertSame('XMLRPC sync attempts: state not published.', $this->logged()[0]['message']);
		$this->assertDirectoryDoesNotExist($this->dir . '/nope');
	}

	// ---- 3. the client error ----------------------------------------------------------------

	/** @return array<string,array{string,string}> client error text, the class stored for it */
	public static function clientErrorClassProvider(): array
	{
		return [
			'authentication' => ['An authentication failure occurred while trying to access https://h:443/xmlrpc.php (restore_config_section).', 'authentication failed'],
			'fault'          => ['Exception calling XMLRPC method restore_config_section #-1 : anything the peer says', 'the peer returned an XMLRPC fault'],
			'timeout'        => ['A communications error occurred while attempting to call XMLRPC method restore_config_section: Operation timed out after 5000 milliseconds', 'timeout'],
			'tls'            => ['CurlException calling XMLRPC method restore_config_section #SSL certificate problem', 'TLS error'],
			'connection'     => ['A communications error occurred while attempting to call XMLRPC method restore_config_section: Failed to connect', 'connection error'],
			'unreachable https target'  => ['A communications error occurred while attempting to call XMLRPC method restore_config_section: Unable to connect to tls://172.30.254.2:443. Error: Host is down', 'connection error'],
			'unanswered https target'   => ['A communications error occurred while attempting to call XMLRPC method restore_config_section: Unable to connect to tls://172.30.254.2:443. Error: Operation timed out', 'timeout'],
			'tls failure at a tls:// target' => ['A communications error occurred while attempting to call XMLRPC method restore_config_section: Unable to connect to tls://172.30.254.2:443. Error: TLS handshake failed', 'TLS error'],
			'handshake failure, warnings as the error' => ['A communications error occurred while attempting to call XMLRPC method restore_config_section: Unable to connect to tls://172.30.254.2:443. Error: stream_socket_client(): SSL operation failed with code 1. OpenSSL Error messages: error:0A00010B:SSL routines::wrong version number', 'TLS error'],
			'unknown'        => ['Exception calling XMLRPC method x # boom', 'transport error'],
			'empty'          => ['', 'no response from the XMLRPC client'],
		];
	}

	#[DataProvider('clientErrorClassProvider')]
	public function testClientFailureStoresOnlyTheClassOfTheErrorAndKeepsTheReturnValue(string $text, string $class): void
	{
		$this->seedNode('manual', 'all', []);
		$GLOBALS['pfb_test_xmlrpc_fail']['192.0.2.20'] = $text;

		$ok = $this->quiet(static function () use (&$error): bool {
			return pfblockerng_do_xmlrpc_sync('192.0.2.20', '443', 'https', 'admin', self::PASSWORD, 5, $error);
		});

		$this->assertFalse($ok);
		$this->assertSame($class, $error);
	}

	public function testAHostileFaultEchoReachesNeitherTheStateNorThePanel(): void
	{
		$key = 'MMKEY-0123456789abcdef';
		$this->seedNode('manual', 'all', [self::target('192.0.2.20', self::PASSWORD)]);
		$GLOBALS['pfb_test_xmlrpc_fail']['192.0.2.20'] = 'Exception calling XMLRPC method restore_config_section #-1 : ' . $key . ' ' . self::PASSWORD . ' '
			. rawurlencode(self::PASSWORD) . ' ' . self::SCRIPT . ' accepted but not applied in sync';

		$this->runPass();

		$state = pfb_sync_send_state_read($this->dir);
		$raw   = $this->sendBytes();
		$panel = $this->senderPanel($state);
		$this->assertSame('the peer returned an XMLRPC fault', $state['attempts'][0]['error']);
		foreach ([$key, self::PASSWORD, rawurlencode(self::PASSWORD), '<script>', 'script&gt;', 'accepted', 'applied', 'in sync'] as $sentinel) {
			$this->assertStringNotContainsString($sentinel, $raw, "{$sentinel} never reaches the state file");
			$this->assertStringNotContainsString($sentinel, $panel, "{$sentinel} never reaches the sender panel");
		}
		$this->assertSame(0, preg_match(self::BANNED, $panel));
		$this->assertSame(0, preg_match(self::IN_SYNC, $panel));
	}

	public function testClientSuccessLeavesTheErrorUnset(): void
	{
		$this->seedNode('manual', 'all', []);
		$error = NULL;

		$ok = $this->quiet(static function () use (&$error): bool {
			return pfblockerng_do_xmlrpc_sync('192.0.2.20', '443', 'https', 'admin', self::PASSWORD, 5, $error);
		});

		$this->assertTrue($ok);
		$this->assertNull($error);
	}

	public function testAnInvalidUtf8ClientErrorStillPublishesEveryTarget(): void
	{
		$this->seedThreeTargets('manual', 'policy');
		$GLOBALS['pfb_test_xmlrpc_fail']['192.0.2.11'] = "fault \xC3\x28 \xFF end";

		$this->runPass();

		$attempts = pfb_sync_send_state_read($this->dir)['attempts'];
		$this->assertSame(['192.0.2.10:443', '192.0.2.11:443', '192.0.2.12:443'], array_column($attempts, 'target'), 'a peer text JSON cannot encode never hides the other targets');
		$this->assertSame('transport error', $attempts[1]['error']);
	}

	// ---- 4. the manual pass records every target -------------------------------------------

	public function testManualPolicyPassRecordsEachTargetInOrderWithItsOwnOutcome(): void
	{
		$this->seedThreeTargets('manual', 'policy');
		$digest = pfb_sync_policy_current_digest();
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $digest);
		$before = time();

		$this->runPass();

		$raw = $this->sendBytes();
		$this->assertStringNotContainsString(self::PASSWORD, $raw, 'the password never reaches the file');
		$this->assertStringNotContainsString(rawurlencode(self::PASSWORD), $raw, 'nor its URL-encoded form');
		$this->assertSame(['time', 'attempts'], array_keys(json_decode($raw, TRUE)));

		$attempts = pfb_sync_send_state_read($this->dir)['attempts'];
		$this->assertSame(['192.0.2.10:443', '192.0.2.11:443', '192.0.2.12:443'], array_column($attempts, 'target'));
		[$a, $b, $c] = $attempts;

		$this->assertSame('sent', $a['outcome']);
		$this->assertSame($digest, $a['digest']);
		$this->assertArrayNotHasKey('error', $a);

		$this->assertSame('failed', $b['outcome']);
		$this->assertSame($digest, $b['digest']);
		$this->assertSame('the peer returned an XMLRPC fault', $b['error']);

		$this->assertSame('failed', $c['outcome']);
		$this->assertSame('Password parameter missing.', $c['error']);
		$this->assertArrayNotHasKey('digest', $c, 'a local validation failure sent nothing, so it carries no digest');

		foreach ($attempts as $attempt) {
			$this->assertGreaterThanOrEqual($before, $attempt['time']);
		}
		$this->assertSame(['192.0.2.10', '192.0.2.11'], array_column($GLOBALS['pfb_test_xmlrpc_connections'], 'ip'), 'A and B were dialled; C never was');
		$this->assertCount(2, $GLOBALS['pfb_test_xmlrpc_calls']);
	}

	public function testLegacyScopePassRecordsSentWithoutADigest(): void
	{
		$this->seedThreeTargets('manual', 'all');

		$this->runPass();

		$attempts = pfb_sync_send_state_read($this->dir)['attempts'];
		$this->assertSame(['sent', 'failed', 'failed'], array_column($attempts, 'outcome'));
		foreach ($attempts as $attempt) {
			$this->assertArrayNotHasKey('digest', $attempt, 'a legacy scope has no policy digest');
		}
	}

	public function testAnIdnTargetIsRecordedAsConfigured(): void
	{
		$this->seedNode('manual', 'policy', [self::target('bücher.example', 'secret-a')]);

		$this->runPass();

		$this->assertSame(['bücher.example:443'], array_column(pfb_sync_send_state_read($this->dir)['attempts'], 'target'));
		$this->assertSame(['xn--bcher-kva.example'], array_column($GLOBALS['pfb_test_xmlrpc_connections'], 'ip'));
	}

	public function testALaterPassReplacesTheWholeFile(): void
	{
		$this->seedThreeTargets('manual', 'policy');
		$this->runPass();
		$this->assertCount(3, pfb_sync_send_state_read($this->dir)['attempts']);

		$this->seedNode('manual', 'policy', [self::target('192.0.2.10', 'secret-a')]);
		$this->runPass();

		$this->assertSame(['192.0.2.10:443'], array_column(pfb_sync_send_state_read($this->dir)['attempts'], 'target'));
	}

	/** @return array<string,array{string}> */
	public static function noPassProvider(): array
	{
		return [
			'sync disabled'       => ['disabled'],
			'receive suppressed'  => ['suppressed'],
			'no replication rows' => ['no rows'],
			'scope not stored'    => ['no scope'],
			'every target off'    => ['all off'],
		];
	}

	#[DataProvider('noPassProvider')]
	public function testANodeThatSendsNothingRecordsNothing(string $case): void
	{
		$rows = [self::target('192.0.2.10', 'secret-a'), self::target('192.0.2.11', 'secret-b')];
		switch ($case) {
			case 'sync disabled':
				$this->seedNode('disabled', 'policy', $rows);
				break;
			case 'receive suppressed':
				$this->seedNode('manual', 'policy', $rows);
				file_put_contents("{$this->dir}/pfb_sync_receive.json", json_encode(['accepted_digest' => pfb_sync_policy_current_digest(), 'last' => NULL]));
				$this->assertTrue(pfb_sync_receive_suppressed(), 'before-state: the node must not echo what it received');
				break;
			case 'no rows':
				$this->seedNode('manual', 'policy', []);
				break;
			case 'no scope':
				$this->seedNode('manual', NULL, $rows);
				break;
			case 'all off':
				$this->seedNode('manual', 'policy', [self::target('192.0.2.10', 'secret-a', FALSE), self::target('192.0.2.11', 'secret-b', FALSE)]);
				break;
		}
		$earlier = $this->seedEarlierPass();

		$this->runPass();

		$this->assertSame($earlier, $this->sendBytes(), 'an early return never touches the last pass');
		$this->assertArrayNotHasKey('pfb_test_xmlrpc_connections', $GLOBALS);
	}

	// ---- 5. the automatic send hands over to pfSense ---------------------------------------

	public function testAutoPolicyHandsOverWithTheDigestAndKeepsItsPaths(): void
	{
		$this->seedNode('auto', 'policy', []);
		$before = time();

		$paths = $this->quiet(static fn (): array => pfblockerng_plugin_xmlrpc_send());

		$this->assertSame(
			[PFB_SECTIONS['sync'] . '/syncscope', ...array_keys(pfb_sync_policy_projection(pfb_sync_stored_sections()))],
			$paths,
			'the returned paths are what they were before'
		);
		$this->assertGreaterThan(1, count($paths));
		$state = pfb_sync_send_state_read($this->dir);
		$this->assertCount(1, $state['attempts']);
		$attempt = $state['attempts'][0];
		$this->assertSame('pfSense HA sync', $attempt['target']);
		$this->assertSame('handed', $attempt['outcome']);
		$this->assertSame(pfb_sync_policy_current_digest(), $attempt['digest']);
		$this->assertGreaterThanOrEqual($before, $attempt['time']);
		$this->assertArrayNotHasKey('error', $attempt);
	}

	public function testAutoLegacyScopeHandsOverWithoutADigest(): void
	{
		$this->seedNode('auto', 'all', []);

		$paths = $this->quiet(static fn (): array => pfblockerng_plugin_xmlrpc_send());

		$this->assertContains('installedpackages/pfblockernglistsv4', $paths);
		$attempts = pfb_sync_send_state_read($this->dir)['attempts'];
		$this->assertCount(1, $attempts);
		$this->assertSame('handed', $attempts[0]['outcome']);
		$this->assertArrayNotHasKey('digest', $attempts[0]);
	}

	public function testAutoHandOverReplacesAManualPass(): void
	{
		$this->seedThreeTargets('manual', 'policy');
		$this->runPass();
		$this->assertCount(3, pfb_sync_send_state_read($this->dir)['attempts']);

		$this->seedNode('auto', 'policy', []);
		$this->quiet(static fn (): array => pfblockerng_plugin_xmlrpc_send());

		$this->assertSame(['pfSense HA sync'], array_column(pfb_sync_send_state_read($this->dir)['attempts'], 'target'));
	}

	/** @return array<string,array{string}> */
	public static function noHandOverProvider(): array
	{
		return [
			'manual mode'        => ['manual'],
			'receive suppressed' => ['suppressed'],
			'scope not stored'   => ['no scope'],
		];
	}

	#[DataProvider('noHandOverProvider')]
	public function testAnAutoSendThatReturnsNothingRecordsNothing(string $case): void
	{
		match ($case) {
			'manual'     => $this->seedNode('manual', 'policy', [self::target('192.0.2.10', 'secret-a')]),
			'no scope'   => $this->seedNode('auto', NULL, []),
			'suppressed' => $this->seedNode('auto', 'policy', []),
		};
		if ($case === 'suppressed') {
			file_put_contents("{$this->dir}/pfb_sync_receive.json", json_encode(['accepted_digest' => pfb_sync_policy_current_digest(), 'last' => NULL]));
			$this->assertTrue(pfb_sync_receive_suppressed(), 'before-state: the node must not echo what it received');
		}
		$earlier = $this->seedEarlierPass();

		$paths = $this->quiet(static fn (): array => pfblockerng_plugin_xmlrpc_send());

		$this->assertSame([], $paths);
		$this->assertSame($earlier, $this->sendBytes());
	}

	// ---- 6. the receiver panel -------------------------------------------------------------

	/** @return array<string,array{array<string,mixed>}> */
	public static function noReceiveRecordProvider(): array
	{
		return [
			'no state'    => [['accepted_digest' => NULL, 'last' => NULL]],
			'no keys'     => [[]],
			'string last' => [['accepted_digest' => NULL, 'last' => 'accepted']],
			'int last'    => [['accepted_digest' => 'abc', 'last' => 5]],
			'only apply'  => [['accepted_digest' => 'abc', 'last' => NULL, 'apply' => ['outcome' => 'applied', 'time' => self::T0]]],
		];
	}

	/** @param array<string,mixed> $receive */
	#[DataProvider('noReceiveRecordProvider')]
	public function testNoPolicyReceiveRecordShowsNoReceiverPanel(array $receive): void
	{
		$this->assertSame('', $this->receiverPanel($receive, TRUE, self::findings('x'), ['findings' => ['aliases' => ['A' => ['b']]]]));
	}

	public function testReceiverPanelFrame(): void
	{
		$html = $this->receiverPanel(self::receive());

		$this->assertStringStartsWith('<div class="panel panel-default" id="pfb-sync-receiver"><div class="panel-heading"><h2 class="panel-title">Receiver: last policy receive</h2></div><div class="panel-body"><table class="table table-condensed">', $html);
		$labels = ['receive' => 'Last receive', 'incoming' => 'Incoming digest', 'accepted' => 'Accepted digest', 'ignored' => 'Ignored paths', 'apply' => 'Apply', 'drift' => 'Drift', 'findings' => 'Effective policy', 'copied' => 'Copied pfB objects'];
		$this->assertSame(8, preg_match_all('#<tr id="pfb-sync-receiver-([a-z]+)"><th>(.*?)</th>#', $html));
		foreach ($labels as $key => $label) {
			$this->assertStringContainsString('<tr id="pfb-sync-receiver-' . $key . '"><th>' . $label . '</th><td>', $html);
		}
		$this->assertSame(count($labels), substr_count($html, '<tr id="pfb-sync-receiver-'), 'exactly the eight rows');
	}

	/** @return array<string,array{array<string,mixed>,string}> */
	public static function receiveWordingProvider(): array
	{
		$at = self::T0_TEXT . ' — ';
		return [
			'changed'              => [['outcome' => 'changed'], $at . 'accepted with changes'],
			'unchanged'            => [['outcome' => 'unchanged'], $at . 'accepted unchanged'],
			'refused with reason'  => [['outcome' => 'refused', 'reason' => 'syncscope is not policy'], $at . 'refused: syncscope is not policy'],
			'refused no reason'    => [['outcome' => 'refused'], $at . 'refused'],
			'refused array reason' => [['outcome' => 'refused', 'reason' => ['x']], $at . 'refused'],
			'unknown accepted'     => [['outcome' => 'accepted'], $at . 'unknown outcome'],
			'unknown markup'       => [['outcome' => self::BOLD], $at . 'unknown outcome'],
			'array outcome'        => [['outcome' => ['changed']], $at . 'unknown outcome'],
			'no outcome'           => [['outcome' => NULL], $at . 'unknown outcome'],
			'string time'          => [['outcome' => 'changed', 'time' => 'noon'], 'unknown time — accepted with changes'],
			'float time'           => [['outcome' => 'unchanged', 'time' => 1.5], 'unknown time — accepted unchanged'],
		];
	}

	/** @param array<string,mixed> $last */
	#[DataProvider('receiveWordingProvider')]
	public function testEachReceiveOutcomeHasItsOwnWording(array $last, string $expected): void
	{
		$html = $this->receiverPanel(self::receive($last));

		$this->assertSame($expected, $this->cell($html, 'receive'));
	}

	public function testAnUnknownOutcomeNeverRendersTheWordAcceptedInTheReceiveRow(): void
	{
		foreach (['accepted', 'Accepted', 'accepted with changes', 'acceptedx'] as $outcome) {
			$cell = $this->cell($this->receiverPanel(self::receive(['outcome' => $outcome])), 'receive');

			$this->assertStringEndsWith('unknown outcome', $cell);
			$this->assertStringNotContainsStringIgnoringCase('accepted', $cell);
		}
	}

	public function testDigestsRenderOrADash(): void
	{
		$html = $this->receiverPanel(self::receive(['incoming_digest' => str_repeat('a', 64), 'accepted_digest' => str_repeat('b', 64)]));
		$this->assertSame(str_repeat('a', 64), $this->cell($html, 'incoming'));
		$this->assertSame(str_repeat('b', 64), $this->cell($html, 'accepted'));

		$html = $this->receiverPanel(self::receive(['incoming_digest' => 5, 'accepted_digest' => ['x']]));
		$this->assertSame('—', $this->cell($html, 'incoming'));
		$this->assertSame('—', $this->cell($html, 'accepted'));

		$html = $this->receiverPanel(self::receive());
		$this->assertSame('—', $this->cell($html, 'incoming'));
		$this->assertSame('—', $this->cell($html, 'accepted'));
	}

	public function testIgnoredPaths(): void
	{
		$long = str_repeat('p', 300);
		$html = $this->receiverPanel(self::receive(['ignored' => ['a/b', $long, ['x'], 7], 'ignored_count' => 250]));
		$this->assertSame('250 ignored path(s)<ul><li>a/b</li><li>' . $long . '</li></ul>', $this->cell($html, 'ignored'), 'the count is the recorded one, the list the stored strings');

		$html = $this->receiverPanel(self::receive(['ignored' => ['a/b', 'c/d', ['x']]]));
		$this->assertSame('2 ignored path(s)<ul><li>a/b</li><li>c/d</li></ul>', $this->cell($html, 'ignored'), 'without a recorded count it is the number of strings');

		foreach ([[], ['ignored' => []], ['ignored' => [], 'ignored_count' => 0], ['ignored' => ['a/b'], 'ignored_count' => 0], ['ignored' => 'junk'], ['ignored_count' => ['n']]] as $last) {
			$this->assertSame('none', $this->cell($this->receiverPanel(self::receive($last)), 'ignored'), json_encode($last));
		}
	}

	public function testApplyRowIsSeparateFromTheReceipt(): void
	{
		$cases = [
			'no record'      => [self::receive(), 'no apply record'],
			'junk record'    => [self::receive([], ['apply' => 'applied']), 'no apply record'],
			'waiting'        => [self::receive([], ['apply' => ['outcome' => 'waiting', 'time' => self::T0 + 60, 'opened' => self::T0]]), 'waiting for the quiet-hours window (opened ' . self::T0_TEXT . ')'],
			'waiting legacy' => [self::receive([], ['apply' => ['outcome' => 'waiting', 'time' => self::T0]]), 'waiting for the quiet-hours window (opened ' . self::T0_TEXT . ')'],
			'failed'         => [self::receive([], ['apply' => ['outcome' => 'failed', 'reason' => 'the update pass failed', 'time' => self::T0]]), 'failed: the update pass failed (' . self::T0_TEXT . ')'],
			'failed bare'    => [self::receive([], ['apply' => ['outcome' => 'failed', 'time' => self::T0]]), 'failed (' . self::T0_TEXT . ')'],
			'applied'        => [self::receive([], ['apply' => ['outcome' => 'applied', 'time' => self::T0]]), 'applied: the update pass completed (' . self::T0_TEXT . ')'],
			'unknown'        => [self::receive([], ['apply' => ['outcome' => 'accepted', 'time' => self::T0]]), 'unknown apply state'],
			'unknown array'  => [self::receive([], ['apply' => ['outcome' => ['applied'], 'time' => self::T0]]), 'unknown apply state'],
			'no outcome'     => [self::receive([], ['apply' => ['time' => self::T0]]), 'unknown apply state'],
		];
		foreach ($cases as $name => [$receive, $expected]) {
			$html = $this->receiverPanel($receive);

			$this->assertSame($expected, $this->cell($html, 'apply'), $name);
			$this->assertSame(self::T0_TEXT . ' — accepted with changes', $this->cell($html, 'receive'), "{$name}: the apply record never changes the receipt");
		}
	}

	public function testAFailedApplyDoesNotTurnTheReceiptIntoAFailureNorTheReverse(): void
	{
		$failed = $this->receiverPanel(self::receive([], ['apply' => ['outcome' => 'failed', 'reason' => 'boom', 'time' => self::T0]]));
		$receipt = $this->cell($failed, 'receive');
		$this->assertStringContainsString('accepted with changes', $receipt);
		$this->assertStringNotContainsString('failed', $receipt);
		$this->assertStringNotContainsString('applied', $receipt);
		$this->assertSame('failed: boom (' . self::T0_TEXT . ')', $this->cell($failed, 'apply'));

		$refused = $this->receiverPanel(self::receive(['outcome' => 'refused', 'reason' => 'bad'], ['apply' => ['outcome' => 'applied', 'time' => self::T0]]));
		$this->assertSame(self::T0_TEXT . ' — refused: bad', $this->cell($refused, 'receive'));
		$this->assertSame('applied: the update pass completed (' . self::T0_TEXT . ')', $this->cell($refused, 'apply'));
	}

	public function testDriftWording(): void
	{
		$receive = self::receive();

		$this->assertSame('policy changed locally since the last accepted receive', $this->cell($this->receiverPanel($receive, TRUE), 'drift'));
		$this->assertSame('none', $this->cell($this->receiverPanel($receive, FALSE), 'drift'));
		$this->assertSame('no accepted digest to compare', $this->cell($this->receiverPanel($receive, NULL), 'drift'));
	}

	public function testEffectivePolicyFindings(): void
	{
		$this->assertSame('none', $this->cell($this->receiverPanel(self::receive(), NULL, self::findings()), 'findings'));
		$this->assertSame('none', $this->cell($this->receiverPanel(self::receive(), NULL, []), 'findings'));
		$this->assertSame('none', $this->cell($this->receiverPanel(self::receive(), NULL, ['findings' => 'junk']), 'findings'));
		$this->assertSame(
			'<ul><li>MaxMind: license key missing</li><li>ASN: IPinfo token missing</li></ul>',
			$this->cell($this->receiverPanel(self::accepting(), NULL, ['time' => 1, 'findings' => ['MaxMind: license key missing', ['x'], 5, NULL, 'ASN: IPinfo token missing']]), 'findings')
		);
	}

	public function testCopiedObjectsSkipANonStringKindAndRenderAnIntLabelAsAString(): void
	{
		$copied = ['recorded' => [], 'findings' => [
			7        => ['Alpha' => ['srcint']],
			'aliases' => [5 => ['srcint']],
		]];
		$this->assertSame('<ul><li>aliases: 5 (srcint)</li></ul>', $this->cell($this->receiverPanel(self::receive(), NULL, [], $copied), 'copied'));
	}

	public function testCopiedObjectFindings(): void
	{
		$this->assertSame('none', $this->cell($this->receiverPanel(self::receive()), 'copied'));
		$this->assertSame('none', $this->cell($this->receiverPanel(self::receive(), NULL, [], ['recorded' => [], 'findings' => []]), 'copied'));
		$this->assertSame('none', $this->cell($this->receiverPanel(self::receive(), NULL, [], ['findings' => 'junk']), 'copied'));

		$copied = ['recorded' => [], 'findings' => [
			'aliases' => ['Alpha' => ['srcint', 'dstint'], 'Beta' => ['srcint']],
			'nat'     => ['Gamma' => ['target', 5, ['x']], 'Delta' => [5]],
			'filter'  => 'junk',
			'dot_filter' => ['Eps' => 'junk'],
		]];
		$this->assertSame(
			'<ul><li>aliases: Alpha (srcint, dstint)</li><li>aliases: Beta (srcint)</li><li>nat: Gamma (target)</li><li>nat: Delta</li><li>dot_filter: Eps</li></ul>',
			$this->cell($this->receiverPanel(self::receive(), NULL, [], $copied), 'copied')
		);
	}

	public function testCopiedObjectFindingsFromTheStateFileRenderThroughTheRealReader(): void
	{
		$digest = hash('sha256', 'pfb3453');
		file_put_contents("{$this->dir}/pfb_sync_copied.json", json_encode([
			'recorded' => ['aliases' => [$digest => $digest], 'nat' => [$digest => $digest]],
			'findings' => [
				'aliases' => ['pfB_Alpha' => ['address', '(unexpected)']],
				'nat'     => ['pfB_Beta#2' => ['destination/port', '(missing)']],
			],
		]));

		$copied = pfb_sync_copied_read($this->dir);

		$this->assertSame(['pfB_Alpha' => ['address', '(unexpected)']], $copied['findings']['aliases'], 'before-state: the reader returns the seeded findings');
		$this->assertSame(
			'<ul><li>aliases: pfB_Alpha (address, (unexpected))</li><li>nat: pfB_Beta#2 (destination/port, (missing))</li></ul>',
			$this->cell($this->receiverPanel(self::receive(), NULL, [], $copied), 'copied')
		);
	}

	/** @return array<string,array{string}> */
	public static function hostileFieldProvider(): array
	{
		$fields  = ['refused reason', 'incoming digest', 'accepted digest', 'ignored path', 'apply reason', 'finding', 'copied label', 'copied attr', 'copied kind'];
		$values  = ['script' => [self::SCRIPT, self::SCRIPT_ESC], 'attribute' => [self::ATTR, self::ATTR_ESC], 'ampersand' => [self::AMP, self::AMP_ESC], 'markup' => [self::BOLD, self::BOLD_ESC]];
		$cases   = [];
		foreach ($fields as $field) {
			foreach ($values as $name => [$raw, $escaped]) {
				$cases["{$field}: {$name}"] = [$field, $raw, $escaped];
			}
		}
		return $cases;
	}

	#[DataProvider('hostileFieldProvider')]
	public function testEveryStoredStringIsEscapedInTheReceiverPanel(string $field, string $raw, string $escaped): void
	{
		$last     = ['outcome' => 'changed'];
		$extra    = [];
		$findings = [];
		$copied   = [];
		switch ($field) {
			case 'refused reason':
				$last = ['outcome' => 'refused', 'reason' => $raw];
				break;
			case 'incoming digest':
				$last['incoming_digest'] = $raw;
				break;
			case 'accepted digest':
				$last['accepted_digest'] = $raw;
				break;
			case 'ignored path':
				$last['ignored'] = [$raw];
				break;
			case 'apply reason':
				$extra['apply'] = ['outcome' => 'failed', 'reason' => $raw, 'time' => self::T0];
				break;
			case 'finding':
				$findings = self::findings($raw);
				$extra['accepted_digest'] = str_repeat('c', 64); // only an accepting receiver lists findings
				break;
			case 'copied label':
				$copied = ['findings' => ['aliases' => [$raw => ['srcint']]]];
				break;
			case 'copied attr':
				$copied = ['findings' => ['aliases' => ['Alpha' => [$raw]]]];
				break;
			case 'copied kind':
				$copied = ['findings' => [$raw => ['Alpha' => ['srcint']]]];
				break;
		}

		$this->assertEscaped($this->receiverPanel(self::receive($last, $extra), NULL, $findings, $copied), $raw, $escaped);
	}

	public function testWrongTypedStoredValuesRaiseNoDiagnosticAndRenderNothingOfThem(): void
	{
		$receive = [
			'accepted_digest' => [1],
			'last' => ['time' => ['x'], 'outcome' => ['changed'], 'reason' => ['r'], 'incoming_digest' => 5, 'accepted_digest' => ['a'], 'ignored' => 'str', 'ignored_count' => ['n']],
			'apply' => ['time' => 'x', 'opened' => [], 'outcome' => ['waiting'], 'reason' => 9],
		];
		$html = $this->receiverPanel($receive, NULL, ['time' => 'x', 'findings' => [['a'], 7]], ['recorded' => 5, 'findings' => ['aliases' => 'x', 'nat' => ['L' => 5], 5 => ['M' => ['a']]]]);

		$this->assertSame('unknown time — unknown outcome', $this->cell($html, 'receive'));
		$this->assertSame('unknown apply state', $this->cell($html, 'apply'));
		$this->assertSame('none', $this->cell($html, 'ignored'));
		$this->assertSame('none', $this->cell($html, 'findings'));
		$this->assertStringNotContainsString('Array', $html);

		$html = $this->receiverPanel(['last' => ['outcome' => 'refused', 'reason' => 9], 'apply' => ['outcome' => 'failed', 'time' => 'x', 'reason' => ['r']]]);
		$this->assertSame('unknown time — refused', $this->cell($html, 'receive'));
		$this->assertSame('failed (unknown time)', $this->cell($html, 'apply'));

		$html = $this->receiverPanel(['last' => ['outcome' => 'unchanged'], 'apply' => ['outcome' => 'waiting', 'time' => 'x', 'opened' => []]]);
		$this->assertSame('waiting for the quiet-hours window (opened unknown time)', $this->cell($html, 'apply'));
	}

	// ---- 7. the sender panel ---------------------------------------------------------------

	/** @param array<string,mixed> $send */
	private function senderPanel(array $send): string
	{
		return $this->quiet(static fn (): string => pfb_sync_sender_panel($send));
	}

	public function testNoAttemptsShowsNoSenderPanel(): void
	{
		$this->assertSame('', $this->senderPanel(['time' => NULL, 'attempts' => []]));
		$this->assertSame('', $this->senderPanel([]));
		$this->assertSame('', $this->senderPanel(['time' => 1, 'attempts' => 'junk']));
		$this->assertSame('', $this->senderPanel(['time' => 1, 'attempts' => ['junk', 5, NULL]]));
	}

	public function testSenderPanelShowsEachAttemptWithItsResult(): void
	{
		$digest = str_repeat('c', 64);
		$html = $this->senderPanel(['time' => self::T0, 'attempts' => [
			['target' => '192.0.2.10:443', 'time' => self::T0, 'outcome' => 'sent', 'digest' => $digest],
			['target' => '192.0.2.11:443', 'time' => self::T0 + 1, 'outcome' => 'failed', 'error' => 'timed out', 'digest' => $digest],
			['target' => '192.0.2.12:443', 'time' => self::T0 + 2, 'outcome' => 'failed'],
			['target' => 'pfSense HA sync', 'time' => self::T0 + 3, 'outcome' => 'handed'],
		]]);

		$this->assertStringStartsWith('<div class="panel panel-default" id="pfb-sync-sender"><div class="panel-heading"><h2 class="panel-title">Sender: last sync attempts</h2></div>', $html);
		$this->assertStringContainsString('<th>Target</th><th>Time</th><th>Payload digest</th><th>Result</th>', $html);
		$this->assertSame([
			['192.0.2.10:443', '2023-11-14 22:13:20', $digest, 'sent, acceptance unconfirmed'],
			['192.0.2.11:443', '2023-11-14 22:13:21', $digest, 'failed: timed out'],
			['192.0.2.12:443', '2023-11-14 22:13:22', 'n/a', 'failed'],
			['pfSense HA sync', '2023-11-14 22:13:23', 'n/a', 'handed to pfSense HA sync'],
		], $this->senderRows($html));
		$this->assertStringEndsWith('<p class="help-block">A returned call does not show what the peer did with it; the receiving firewall\'s own Sync page shows its receive. A failure shows its class; the system log keeps the client\'s full message.</p></div></div>', $html);
	}

	public function testSenderPanelEscapesEveryStoredValue(): void
	{
		foreach ([[self::SCRIPT, self::SCRIPT_ESC], [self::ATTR, self::ATTR_ESC], [self::AMP, self::AMP_ESC], [self::BOLD, self::BOLD_ESC]] as [$raw, $escaped]) {
			foreach (['target', 'digest', 'error'] as $field) {
				$attempt = ['target' => 'peer:443', 'time' => self::T0, 'outcome' => 'failed', 'digest' => 'abc', 'error' => 'e', $field => $raw];

				$this->assertEscaped($this->senderPanel(['time' => self::T0, 'attempts' => [$attempt]]), $raw, $escaped);
			}
		}
	}

	public function testSenderPanelNeverUsesTheReceiversVocabulary(): void
	{
		$html = $this->senderPanel(['time' => self::T0, 'attempts' => [
			['target' => '192.0.2.10:443', 'time' => self::T0, 'outcome' => 'sent', 'digest' => str_repeat('c', 64)],
			['target' => '192.0.2.11:443', 'time' => self::T0, 'outcome' => 'failed', 'error' => self::SCRIPT . ' ' . self::ATTR . ' unsupported acceptance'],
			['target' => 'pfSense HA sync', 'time' => self::T0, 'outcome' => 'handed'],
			// outcomes the reader never lets through: a helper that echoed one would say what the packet forbids
			['target' => 't1', 'time' => self::T0, 'outcome' => 'accepted'],
			['target' => 't2', 'time' => self::T0, 'outcome' => 'applied'],
			['target' => 't3', 'time' => self::T0, 'outcome' => 'supported'],
			['target' => 't4', 'time' => self::T0, 'outcome' => 'drifting'],
			['target' => 't5', 'time' => self::T0, 'outcome' => 'in sync'],
			['target' => 't6', 'time' => 'noon', 'outcome' => ['accepted']],
		]]);

		$this->assertSame(0, preg_match(self::BANNED, $html), 'the sender panel never says supported, accepted, applied or drifting');
		$this->assertSame(0, preg_match(self::IN_SYNC, $html), 'the sender panel never says in sync');
		$this->assertCount(9, $this->senderRows($html), 'unknown outcomes are still listed');
	}

	public function testTheVocabularyCheckCanFail(): void
	{
		$html = $this->receiverPanel(self::receive([], ['apply' => ['outcome' => 'applied', 'time' => self::T0]]));
		$this->assertSame(1, preg_match(self::BANNED, $html), 'the receiver panel does say accepted and applied');
		$this->assertSame(1, preg_match('/\baccepted\b/i', $this->cell($html, 'receive')));
		$this->assertSame(1, preg_match('/\bapplied\b/i', $this->cell($html, 'apply')));
		$this->assertSame(1, preg_match(self::IN_SYNC, 'the nodes are in sync'));
		$this->assertSame(0, preg_match(self::BANNED, 'unsupported acceptance'));
	}

	public function testSenderPanelToleratesWrongTypes(): void
	{
		$html = $this->senderPanel(['time' => ['x'], 'attempts' => [
			['target' => ['a'], 'time' => ['x'], 'outcome' => 'failed', 'digest' => 5, 'error' => ['e']],
			['target' => 'ok:1', 'time' => 1.5, 'outcome' => 'sent', 'digest' => ['d']],
			'junk',
		]]);

		$this->assertSame([
			['', 'unknown time', 'n/a', 'failed'],
			['ok:1', 'unknown time', 'n/a', 'sent, acceptance unconfirmed'],
		], $this->senderRows($html));
		$this->assertStringNotContainsString('Array', $html);
	}

	// ---- 8. the page ---------------------------------------------------------------------------

	public function testThePageRendersBothPanelsAfterTheForm(): void
	{
		$page = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_sync.php');

		$form     = strpos($page, 'print ($form);');
		$receiver = strpos($page, "print pfb_sync_receiver_panel(pfb_sync_receive_state_read(\$pfb['dbdir']), pfb_sync_receive_drift(\$pfb['dbdir']), pfb_sync_findings_read(\$pfb['dbdir']), pfb_sync_copied_read(\$pfb['dbdir']));");
		$sender   = strpos($page, "print pfb_sync_sender_panel(pfb_sync_send_state_read(\$pfb['dbdir']));");

		$this->assertNotFalse($form);
		$this->assertNotFalse($receiver, 'the receiver panel is built from this node\'s own records');
		$this->assertNotFalse($sender);
		$this->assertLessThan($receiver, $form);
		$this->assertLessThan($sender, $receiver);
		$this->assertSame(1, substr_count($page, 'pfb_sync_receiver_panel('));
		$this->assertSame(1, substr_count($page, 'pfb_sync_sender_panel('));
	}
}
