<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 Amendment 1 — pfb_syslog_event() tests.
 *
 * pfb_syslog_event() is the PHP IP-leg syslog emitter.  It reads the log_syslog
 * toggle fresh on every call (no static cache).  When the toggle is on it records
 * calls via $GLOBALS['pfb_test_syslog_spy'] using a hardcoded facility (LOG_LOCAL6)
 * and severity (LOG_INFO).  log_syslog_facility and log_syslog_priority no longer
 * exist as registered config keys; the function no longer reads them.
 *
 * Contract under test (ADR-38 Amendment 1):
 *   - Toggle OFF  => zero syslog calls (no emission, no side effect).
 *   - Toggle ON   => exactly one call per pfb_syslog_event() invocation, with the
 *                    exact body passed, ident 'pfblockerng', facility LOG_LOCAL6,
 *                    and severity LOG_INFO (both hardcoded — not configurable).
 */
final class SyslogEventTest extends TestCase
{
	private const DAEMON_DEADLINE_S = 3.0;

	private bool $hadConfig = false;
	private mixed $savedConfig = null;
	private bool $hadSyslogSpy = false;
	private mixed $savedSyslogSpy = null;
	private bool $hadSyslogCalls = false;
	private mixed $savedSyslogCalls = null;
	private bool $hadSyslogReset = false;
	private mixed $savedSyslogReset = null;
	/** @var string[] */
	private array $daemonTempFiles = [];

	/** Install clean owned state; no cache-reset needed (function reads fresh each call). */
	protected function setUp(): void
	{
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? null;
		$this->hadSyslogSpy = array_key_exists('pfb_test_syslog_spy', $GLOBALS);
		$this->savedSyslogSpy = $GLOBALS['pfb_test_syslog_spy'] ?? null;
		$this->hadSyslogCalls = array_key_exists('pfb_test_syslog_calls', $GLOBALS);
		$this->savedSyslogCalls = $GLOBALS['pfb_test_syslog_calls'] ?? null;
		$this->hadSyslogReset = array_key_exists('pfb_test_syslog_reset', $GLOBALS);
		$this->savedSyslogReset = $GLOBALS['pfb_test_syslog_reset'] ?? null;

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_syslog_spy']   = TRUE;
		$GLOBALS['pfb_test_syslog_calls'] = [];
		unset($GLOBALS['pfb_test_syslog_reset']);
	}

	protected function tearDown(): void
	{
		foreach (
			[
				'config'                => [$this->hadConfig, $this->savedConfig],
				'pfb_test_syslog_spy'   => [$this->hadSyslogSpy, $this->savedSyslogSpy],
				'pfb_test_syslog_calls' => [$this->hadSyslogCalls, $this->savedSyslogCalls],
				'pfb_test_syslog_reset' => [$this->hadSyslogReset, $this->savedSyslogReset],
			] as $name => [$had, $value]
		) {
			if ($had) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		foreach ($this->daemonTempFiles as $path) {
			if (is_file($path)) {
				unlink($path);
			}
		}
		$this->daemonTempFiles = [];
	}

	/** @return array{0: array<int, array<string, mixed>>, 1: string} */
	private function runFilterlogDaemon(string $row): array
	{
		$unilog = tempnam(sys_get_temp_dir(), 'pfb_dnsbl_unilog_');
		$calls = tempnam(sys_get_temp_dir(), 'pfb_dnsbl_calls_');
		$done = tempnam(sys_get_temp_dir(), 'pfb_dnsbl_done_');
		$stderr = tempnam(sys_get_temp_dir(), 'pfb_dnsbl_stderr_');
		foreach ([$unilog, $calls, $done, $stderr] as $path) {
			$this->assertIsString($path, 'test setup: temp file creation failed');
			$this->daemonTempFiles[] = $path;
		}
		unlink($done);
		$bootstrap = __DIR__ . '/bootstrap.php';
		$childCode = <<<'PHP'
			$args = $argv;
			require $args[4];
			$GLOBALS['pfb']['unilog'] = $args[1];
			$GLOBALS['pfb']['asn_reporting'] = 'disabled';
			$GLOBALS['pfb']['geoipshare'] = '';
			$GLOBALS['config'] = [];
			config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');
			$GLOBALS['pfb_test_syslog_spy'] = TRUE;
			$GLOBALS['pfb_test_syslog_calls'] = [];
			pfb_daemon_filterlog();
			file_put_contents($args[2], json_encode($GLOBALS['pfb_test_syslog_calls'], JSON_THROW_ON_ERROR));
			file_put_contents($args[3], 'done');
			PHP;
		$descriptors = [
			0 => ['pipe', 'r'],
			1 => ['file', '/dev/null', 'w'],
			2 => ['file', $stderr, 'w'],
		];
		$proc = proc_open([PHP_BINARY, '-r', $childCode, $unilog, $calls, $done, $bootstrap], $descriptors, $pipes);
		$this->assertIsResource($proc, 'test setup: failed to spawn filterlog daemon child');
		fwrite($pipes[0], $row . "\n");
		fclose($pipes[0]);

		$deadline = microtime(TRUE) + self::DAEMON_DEADLINE_S;
		while (!is_file($done) && microtime(TRUE) < $deadline) {
			$status = proc_get_status($proc);
			if (!$status['running']) {
				break;
			}
			usleep(10000);
		}
		$status = proc_get_status($proc);
		if (!is_file($done)) {
			if ($status['running']) {
				proc_terminate($proc, 9);
				proc_close($proc);
				$this->fail('STUCK/ENVIRONMENT: filterlog daemon child did not complete before the hard deadline');
			}
			$exitCode = proc_close($proc);
			$this->fail(
				'filterlog daemon child exited before completion (exit ' . $exitCode . '): '
				. (string) file_get_contents($stderr)
			);
		}
		$exitCode = proc_close($proc);
		$this->assertSame(0, $exitCode, 'filterlog daemon child must exit cleanly');
		$decoded = json_decode((string) file_get_contents($calls), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertIsArray($decoded, 'child syslog spy output must be an array');
		return [$decoded, (string) file_get_contents($unilog)];
	}

	// -----------------------------------------------------------------------
	// Toggle OFF — no emission
	// -----------------------------------------------------------------------

	/**
	 * pfb_syslog_event is a no-op when log_syslog is off.
	 *
	 * Scenario:
	 *   Background: log_syslog toggle follows PfbToggle (off = '').
	 *     Given log_syslog is '' (off, the default).
	 *     When  pfb_syslog_event('act=block dir=in if=em0 ...') is called.
	 *     Then  no syslog call is recorded.
	 */
	public function testToggleOffProducesNoSyslogCall(): void
	{
		// Given: toggle explicitly off.
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', '');

		// Before: spy installed, no calls yet.
		$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'], 'before: no calls before event');

		// When.
		pfb_syslog_event('act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4');

		// Then: no syslog call.
		$calls = $GLOBALS['pfb_test_syslog_calls'] ?? [];
		$this->assertSame([], $calls, 'toggle off: pfb_syslog_event() must produce no syslog call');
	}

	/**
	 * Toggle absent (key not set in config) — treated as off, no emission.
	 *
	 * Scenario:
	 *   Background: PfbConfig returns PfbToggle::Off for absent log_syslog (default '').
	 *     Given log_syslog is absent from config (key not present).
	 *     When  pfb_syslog_event() is called.
	 *     Then  no syslog call is recorded.
	 */
	public function testToggleAbsentProducesNoSyslogCall(): void
	{
		// Before: no log_syslog key in config (setUp already cleared it).

		pfb_syslog_event('act=pass dir=out if=wan proto=UDP src=10.0.0.1 dst=8.8.8.8 ipver=4');

		$calls = $GLOBALS['pfb_test_syslog_calls'] ?? [];
		$this->assertSame([], $calls, 'toggle absent: pfb_syslog_event() must produce no syslog call');
	}

	// -----------------------------------------------------------------------
	// Toggle ON — exactly one call, hardcoded facility LOG_LOCAL6 + severity LOG_INFO
	// -----------------------------------------------------------------------

	/**
	 * pfb_syslog_event emits exactly one syslog call with the supplied body when on.
	 *
	 * Scenario:
	 *   Background: toggle on; facility hardcoded to LOG_LOCAL6, severity to LOG_INFO.
	 *     Given log_syslog is 'on' (PfbToggle::On).
	 *     When  pfb_syslog_event('act=block dir=in ...') is called once.
	 *     Then  exactly one syslog call is recorded.
	 *     And   the recorded body equals the argument passed to pfb_syslog_event().
	 *     And   the ident is 'pfblockerng'.
	 *     And   the facility is LOG_LOCAL6 (hardcoded).
	 *     And   the severity is LOG_INFO (hardcoded).
	 */
	public function testToggleOnEmitsExactlyOneCallWithCorrectBody(): void
	{
		// Before: confirm no calls before enabling.
		$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'], 'before: no calls before toggle on');

		// Given: enable syslog toggle.
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');

		$body = 'act=block dir=in if=em0 proto=TCP src=203.0.113.1 dst=192.168.1.1 sport=54321 dport=80 ipver=4 geoip=US alias=pfB_DENY feed=EasyList';

		// When: call once.
		pfb_syslog_event($body);

		// Then: exactly one call.
		$calls = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(1, $calls, 'toggle on: exactly one syslog call per pfb_syslog_event() invocation');

		// And: correct body.
		$this->assertSame($body, $calls[0]['body'], 'toggle on: syslog body equals the argument passed');

		// And: correct ident.
		$this->assertSame('pfblockerng', $calls[0]['ident'], 'toggle on: ident is pfblockerng');

		// And: hardcoded facility LOG_LOCAL6 (not configurable — Amendment 1).
		$this->assertSame(LOG_LOCAL6, $calls[0]['facility'], 'toggle on: facility is hardcoded LOG_LOCAL6');

		// And: hardcoded severity LOG_INFO (not configurable — Amendment 1).
		$this->assertSame(LOG_INFO, $calls[0]['severity'], 'toggle on: severity is hardcoded LOG_INFO');
	}

	/**
	 * pfb_syslog_event called twice emits two records when on.
	 *
	 * Scenario:
	 *   Background: toggle on; two independent events.
	 *     Given log_syslog is 'on'.
	 *     When  pfb_syslog_event() is called twice with different bodies.
	 *     Then  two syslog calls are recorded, each with the correct body.
	 */
	public function testMultipleCallsEachEmitOneRecord(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');

		$body1 = 'act=block dir=in if=em0 proto=TCP src=203.0.113.1 dst=10.0.0.1 ipver=4';
		$body2 = 'act=pass dir=out if=wan proto=UDP src=10.0.0.1 dst=8.8.8.8 sport=12345 dport=53 ipver=4';

		// Before: no calls yet.
		$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'], 'before: no calls yet');

		pfb_syslog_event($body1);
		pfb_syslog_event($body2);

		$calls = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(2, $calls, 'two events => two syslog calls');
		$this->assertSame($body1, $calls[0]['body'], 'first call: correct body');
		$this->assertSame($body2, $calls[1]['body'], 'second call: correct body');
	}

	// -----------------------------------------------------------------------
	// Toggle flip: off then on — before/after
	// -----------------------------------------------------------------------

	/**
	 * Flipping the toggle from off to on changes emission — before/after asserted.
	 *
	 * Since pfb_syslog_event() reads the toggle fresh on every call (no static cache),
	 * switching the stored value between calls is sufficient to change behaviour.
	 *
	 * Scenario:
	 *   Background: function reads log_syslog fresh each call.
	 *     Given log_syslog starts as '' (off).
	 *     When  pfb_syslog_event() is called => no emission (before).
	 *     Then  toggle is set to 'on'.
	 *     When  pfb_syslog_event() is called again => one emission (after).
	 *     Then  the change in emission was CAUSED by the toggle flip.
	 */
	public function testToggleFlipOffToOnChangesEmission(): void
	{
		// --- BEFORE: toggle off ---
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', '');

		pfb_syslog_event('act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4');

		$calls_before = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertSame([], $calls_before, 'before flip: no emission when toggle is off');

		// Reset accumulated calls for the next assertion.
		$GLOBALS['pfb_test_syslog_calls'] = [];

		// --- AFTER: toggle on (fresh read, no reset flag needed) ---
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');

		$body = 'act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4';
		pfb_syslog_event($body);

		$calls_after = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(1, $calls_after, 'after flip: exactly one emission when toggle is on');
		$this->assertSame($body, $calls_after[0]['body'], 'after flip: body matches');
		$this->assertSame(LOG_LOCAL6, $calls_after[0]['facility'], 'after flip: facility is LOG_LOCAL6');
		$this->assertSame(LOG_INFO, $calls_after[0]['severity'], 'after flip: severity is LOG_INFO');
	}

	/**
	 * The daemon reads Python's RFC4180 DNSBL rows at its public stdin boundary.
	 * Each row must be written to unified.log byte-for-byte, while only a logical
	 * 11-field row emits the dedicated DNSBL syslog event.
	 */
	public function testFilterlogDaemonPreservesDnsblRowsAndParsesQuotedFields(): void
	{
		$plain = 'DNSBL-python,2026-08-02 12:34:56,plain.example.com,192.0.2.7,Python,DNSBL_Python,real_group,example.com,real_feed,+,A';
		$quoted = 'DNSBL-python,2026-08-02 12:34:56,"a,""quoted"".example.com",192.0.2.7,Python,DNSBL_Python,real_group,example.com,real_feed,+,A';
		$malformed = 'DNSBL-python,2026-08-02 12:34:56,too-short,192.0.2.7,Python,DNSBL_Python';

		$cases = [
			[
				'label' => 'plain 11-field row',
				'row' => $plain,
				'body' => 'act=dnsbl qname=plain.example.com qip=192.0.2.7 qtype=A group=real_group feed=real_feed btype=DNSBL_Python eval=example.com',
			],
			[
				'label' => 'quoted comma and quote q_name',
				'row' => $quoted,
				'body' => 'act=dnsbl qname="a,\\"quoted\\".example.com" qip=192.0.2.7 qtype=A group=real_group feed=real_feed btype=DNSBL_Python eval=example.com',
			],
			[
				'label' => 'malformed row',
				'row' => $malformed,
				'body' => NULL,
			],
		];

		foreach ($cases as $case) {
			[$calls, $unified] = $this->runFilterlogDaemon($case['row']);
			$this->assertSame($case['row'] . "\n", $unified, $case['label'] . ': unified.log must preserve raw row bytes');
			if ($case['body'] === NULL) {
				$this->assertSame([], $calls, $case['label'] . ': malformed row must emit no syslog event');
				continue;
			}
			$this->assertCount(1, $calls, $case['label'] . ': exactly one syslog event expected');
			$this->assertSame($case['body'], $calls[0]['body'], $case['label'] . ': syslog body fields must remain exact');
		}
	}
}
