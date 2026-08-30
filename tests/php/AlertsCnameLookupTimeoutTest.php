<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #2083: the Alerts CNAME lookup is bounded and never consumes incomplete data. */
final class AlertsCnameLookupTimeoutTest extends TestCase
{
	private const ALERTS_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	/**
	 * Salvage cap for the worker's end-of-run signal. It exists only to reap a stuck
	 * run; whether the lookup completed is decided by the worker's own result file.
	 */
	private const LOOKUP_SALVAGE_SECONDS = 60;

	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb alerts cname ' . bin2hex(random_bytes(6));
		mkdir($this->tmp, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmp);
	}

	public function testSuccessfulCnameOutputIsReadFromFile(): void
	{
		$run = $this->runLookup(stall: FALSE);

		$this->assertTrue($run['completed'], 'lookup worker must complete; child output: ' . $run['child_log']);
		$this->assertSame(['alias.example.com'], $run['cname_list'], 'completed CNAME output must be read from the regular file');
		$this->assertCount(1, $run['timeout_calls'], 'a completed lookup must still use bounded timeout wrapper');
		$this->assertStringNotContainsString('TIMED OUT', $run['log'], 'a completed lookup must not log timeout');
		$this->assertSame([], $run['capture_files'], 'lookup capture files must be cleaned up after read');
	}

	public function testTimeoutDiscardsPartialOutputAndLogsExpiry(): void
	{
		$run = $this->runLookup(stall: TRUE);

		$this->assertTrue($run['completed'], 'bounded lookup must return after the fixture stalls; child output: ' . $run['child_log']);
		$this->assertTrue($run['partial_seen'], 'drill must emit partial output before the timeout fires');
		$this->assertSame([], $run['cname_list'], 'partial CNAME output must be discarded on timeout');
		$this->assertCount(1, $run['timeout_calls'], 'timeout shim must receive one bounded lookup');
		$argv = $run['timeout_calls'][0];
		$this->assertSame(['-s', 'TERM', '-k', '5', '30'], array_slice($argv, 0, 5), 'lookup must use default-mode timeout with named 30-second budget and 5-second grace');
		$this->assertSame(['/bin/sh', '-c'], array_slice($argv, 5, 2), 'timeout must invoke the complete pipeline through /bin/sh -c');
		$this->assertCount(8, $argv, 'timeout argv must contain exactly one complete pipeline argument');
		$pipeline = $argv[7];
		$this->assertStringContainsString(escapeshellarg($run['drill_path']), $pipeline, 'pipeline must carry the escaped injected drill fixture path');
		$this->assertStringContainsString(escapeshellarg('example.com'), $pipeline, 'pipeline must carry the escaped domain argument');
		$this->assertStringContainsString(escapeshellarg('@127.0.0.1'), $pipeline, 'pipeline must carry the escaped resolver argument');
		$this->assertStringContainsString("/usr/bin/awk '/CNAME/ {sub(\"[.]\$\", \"\", \$5); print \$5;}'", $pipeline, 'pipeline must retain the CNAME awk transform');
		$this->assertNotContains('--foreground', $argv, 'pipeline timeout must retain FreeBSD default reaper mode');
		$this->assertNotContains('-f', $argv, 'pipeline timeout must retain FreeBSD default reaper mode');
		$this->assertStringContainsString('CNAME lookup TIMED OUT', $run['log']);
		$this->assertSame([], $run['capture_files'], 'timed-out capture files must be cleaned up');
	}

	public function testDrillFailureDiscardsPartialOutput(): void
	{
		$run = $this->runLookup(stall: FALSE, drillFails: TRUE);

		$this->assertTrue($run['completed'], 'failed drill must not abort the request; child output: ' . $run['child_log']);
		$this->assertTrue($run['partial_seen'], 'drill must emit partial output before failing');
		$this->assertSame([], $run['cname_list'], 'output from a failed drill must be discarded');
		$this->assertCount(1, $run['timeout_calls']);
		$this->assertStringContainsString('CNAME lookup FAILED (exit 7)', $run['log']);
		$this->assertSame([], $run['capture_files']);
	}

	public function testCaptureFailureIsLoggedWithoutReadingMissingFile(): void
	{
		$run = $this->runLookup(stall: FALSE, captureAvailable: FALSE);

		$this->assertTrue($run['completed'], 'capture failure must not abort the request; child output: ' . $run['child_log']);
		$this->assertSame([], $run['cname_list'], 'capture failure must not produce CNAME data');
		$this->assertSame([], $run['timeout_calls'], 'failed outer redirection must not launch the lookup');
		$this->assertStringContainsString('CNAME lookup FAILED', $run['log']);
		$this->assertStringNotContainsString('file(', $run['child_log'], 'missing capture file must not emit a PHP warning');
	}

	public function testMissingCaptureAfterSuccessfulLookupIsLogged(): void
	{
		$run = $this->runLookup(stall: FALSE, removeCapture: TRUE);

		$this->assertTrue($run['completed'], 'missing capture must not abort the request; child output: ' . $run['child_log']);
		$this->assertSame([], $run['cname_list'], 'missing capture must not produce CNAME data');
		$this->assertCount(1, $run['timeout_calls'], 'the lookup must succeed before its capture disappears');
		$this->assertStringContainsString('CNAME lookup FAILED (capture missing)', $run['log']);
		$this->assertStringNotContainsString('file(', $run['child_log'], 'missing capture file must not emit a PHP warning');
		$this->assertSame([], $run['capture_files']);
	}

	public function testLookupUsesDefaultReaperAndRegularFileCapture(): void
	{
		$source = file_get_contents(self::ALERTS_PHP);
		$start = strpos((string) $source, '$cname_list = array();');
		$end = strpos((string) $source, "// Remove 'www.' prefix", $start === FALSE ? 0 : $start);
		$this->assertNotFalse($start, 'CNAME lookup source anchor must remain present');
		$this->assertNotFalse($end, 'CNAME lookup source end anchor must remain present');
		$block = substr($source, $start, $end - $start);
		$this->assertStringContainsString('$cname_lookup_timeout = 30', $block);
		$this->assertStringContainsString('$cname_lookup_kill_grace = 5', $block);
		$this->assertStringContainsString('2>&1 < /dev/null', $block);
		$this->assertStringContainsString('escapeshellarg($cname_lookup_file)', $block);
		$this->assertStringNotContainsString('exec("/usr/bin/drill', $block);
	}

	/**
	 * @return array{completed:bool,cname_list:list<string>,timeout_calls:list<list<string>>,log:string,capture_files:list<string>,child_log:string,drill_path:string,partial_seen:bool}
	 */
	private function runLookup(bool $stall, bool $captureAvailable = TRUE, bool $removeCapture = FALSE, bool $drillFails = FALSE): array
	{
		$marker = "{$this->tmp}/stall marker.log";
		$timeout_log = "{$this->tmp}/timeout args.log";
		$timeout_flag = "{$this->tmp}/timeout fired";
		$result = "{$this->tmp}/lookup result.json";
		$child_log = "{$this->tmp}/child output.log";
		// Two signals carry the events this harness used to poll a clock for: the drill
		// announcing its partial output, and the worker reaching end of run.
		$partial_signal = "{$this->tmp}/partial signal";
		$done_signal = "{$this->tmp}/done signal";
		$this->assertTrue(posix_mkfifo($partial_signal, 0600), 'could not create the partial-output signal');
		$this->assertTrue(posix_mkfifo($done_signal, 0600), 'could not create the end-of-run signal');

		$drill = $this->fixture('drill fixture.sh',
			"printf '%s\\n' --START-- \"\$\$\" >> " . escapeshellarg($marker) . "\n"
			. "printf '%b\\n' 'partial.example.com.\\t300\\tIN\\tCNAME\\talias.example.com.'\n"
			. "printf '%s\\n' --PARTIAL-WRITTEN-- >> " . escapeshellarg($marker) . "\n"
			// '1<>' opens read-write, so announcing partial output can never block the
			// drill on a reader, in the runs where nobody is listening for it.
			. "printf 'partial\\n' 1<> " . escapeshellarg($partial_signal) . "\n"
			. ($drillFails ? "exit 7\n" : '')
			. ($stall ? "while true; do sleep 1; done\n" : '')
		);
		$timeout = $this->fixture('timeout fixture.sh',
			"printf '%s\\n' --CALL-- >> " . escapeshellarg($timeout_log) . "\n"
			. "printf '%s\\n' \"\$@\" >> " . escapeshellarg($timeout_log) . "\n"
			. "shift 5\n"
			// Hold the signal open BEFORE the drill starts, so its announcement cannot be
			// written into a pipe this shim has not attached to yet.
			. ($stall ? "exec 9<> " . escapeshellarg($partial_signal) . "\n" : '')
			. "\"\$@\" & child=\$!\n"
			. ($stall
				// Block on the drill's announcement instead of budgeting poll attempts:
				// a starved drill now delays this shim rather than being declared silent.
				? "read -r _ <&9\n"
					. "touch " . escapeshellarg($timeout_flag) . "; kill -TERM \$child 2>/dev/null\n"
				: '')
			. "wait \$child; rc=\$?\n"
			. ($removeCapture ? "rm -f " . escapeshellarg($this->tmp) . "/pfb_alerts_cname_*\n" : '')
			. "[ -f " . escapeshellarg($timeout_flag) . " ] && exit 124\n"
			. "exit \$rc\n"
		);
		$function = $this->lookupFunction($drill);
		$worker = "{$this->tmp}/lookup worker.php";
		$bootstrap = realpath(__DIR__ . '/bootstrap.php');
		if ($bootstrap === FALSE) {
			throw new RuntimeException('test bootstrap path unavailable');
		}
		$worker_code = "<?php\n"
			. 'require_once ' . var_export($bootstrap, TRUE) . ";\n"
			. "if (function_exists('posix_setsid')) { posix_setsid(); }\n"
			// Announce end of run from a shutdown handler, so a worker that dies before
			// writing its result still reports in and is graded as a failed lookup rather
			// than as a stuck host.
			. 'register_shutdown_function(static function (): void { $signal = fopen('
				. var_export($done_signal, TRUE) . ", 'r+'); fwrite(\$signal, \"done\\n\"); fclose(\$signal); });\n"
			. 'eval(' . var_export($function, TRUE) . ");\n"
			. '$GLOBALS[\'pfb\'][\'extdns\'] = \'127.0.0.1\';' . "\n"
			. '$GLOBALS[\'pfb\'][\'drill\'] = ' . var_export($drill, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'timeout\'] = ' . var_export($timeout, TRUE) . ";\n"
			. '$GLOBALS[\'g\'][\'tmp_path\'] = ' . var_export($captureAvailable ? $this->tmp : "{$this->tmp}/missing", TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'log\'] = ' . var_export("{$this->tmp}/pfblockerng.log", TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'errlog\'] = ' . var_export("{$this->tmp}/pfblockerng.errlog", TRUE) . ";\n"
			. '$list = pfb_alerts_test_cname_lookup(\'example.com\');' . "\n"
			. 'file_put_contents(' . var_export($result, TRUE) . ', json_encode(['
				. "'list' => \$list, 'log' => file_exists(\$GLOBALS['pfb']['log']) ? file_get_contents(\$GLOBALS['pfb']['log']) : '',"
				. ' ]));' . "\n";
		file_put_contents($worker, $worker_code);

		$descriptors = [
			0 => ['file', '/dev/null', 'r'],
			1 => ['file', $child_log, 'ab'],
			2 => ['file', $child_log, 'ab'],
		];
		// Hold the signal open BEFORE the worker starts: a worker that finishes at once
		// must not be able to report into a pipe this side has not attached to yet.
		$done = fopen($done_signal, 'r+');
		$this->assertIsResource($done, 'could not open the end-of-run signal');
		$process = proc_open([PHP_BINARY, $worker], $descriptors, $pipes);
		if (!is_resource($process)) {
			throw new RuntimeException('could not start lookup worker');
		}
		$worker_status = proc_get_status($process);
		$worker_pid = (int) ($worker_status['pid'] ?? 0);

		$reported = FALSE;
		try {
			// Consume the worker's own end-of-run event. The cap is a salvage bound whose
			// only job is reaping a stuck run -- it never decides whether the lookup
			// completed, which is what the result file below says.
			$read = [$done];
			$write = NULL;
			$except = NULL;
			$reported = stream_select($read, $write, $except, self::LOOKUP_SALVAGE_SECONDS) === 1
				&& fgets($done) === "done\n";
		} finally {
			if (!$reported) {
				$group_killed = $worker_pid > 0 && function_exists('posix_kill') && @posix_kill(-$worker_pid, 9);
				if (!$group_killed) {
					proc_terminate($process, 9);
				}
			}
			proc_close($process);
			fclose($done);
		}
		$drill_pid = $this->fixturePid($marker);
		if ($drill_pid !== NULL && function_exists('posix_kill')) {
			@posix_kill($drill_pid, 9);
		}
		if (!$reported) {
			$this->fail(sprintf(
				'STUCK/ENVIRONMENT: the lookup worker never reached its end-of-run signal within %ds, '
				. 'so this run is stuck or its host starved the worker -- not a CNAME lookup verdict '
				. '(drill marker %s, child output: %s)',
				self::LOOKUP_SALVAGE_SECONDS,
				is_file($marker) ? 'seen' : 'missing',
				is_file($child_log) ? (string) file_get_contents($child_log) : '(none)'
			));
		}
		$completed = is_file($result);

		$payload = is_file($result) ? json_decode((string) file_get_contents($result), TRUE) : [];
		$timeout_calls = $this->timeoutCalls($timeout_log);
		return [
			'completed' => $completed,
			'cname_list' => $payload['list'] ?? [],
			'timeout_calls' => $timeout_calls,
			'log' => $payload['log'] ?? '',
			'capture_files' => glob("{$this->tmp}/pfb_alerts_cname_*") ?: [],
			'child_log' => is_file($child_log) ? (string) file_get_contents($child_log) : '',
			'drill_path' => $drill,
			'partial_seen' => is_file($marker) && str_contains((string) file_get_contents($marker), '--PARTIAL-WRITTEN--'),
		];
	}

	private function lookupFunction(string $drill): string
	{
		$source = file_get_contents(self::ALERTS_PHP);
		if ($source === FALSE) {
			throw new RuntimeException('test oracle: failed to read pfblockerng_alerts.php');
		}
		$start = strpos($source, "\t\t\$cname_list = array();");
		$end = strpos($source, "\n\t\t// Remove 'www.' prefix", $start === FALSE ? 0 : $start);
		if ($start === FALSE || $end === FALSE || $end <= $start) {
			throw new RuntimeException('test oracle: CNAME lookup block bounds not found');
		}
		$block = substr($source, $start, $end - $start);
		if (!str_contains($block, '$pfb[\'drill\']')) {
			$block = str_replace('/usr/bin/drill', escapeshellarg($drill), $block);
		}
		return 'function pfb_alerts_test_cname_lookup(string $domain): array { global $pfb, $g; ' . $block . ' return $cname_list; }';
	}

	private function fixture(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	private function fixturePid(string $marker): ?int
	{
		$lines = @file($marker, FILE_IGNORE_NEW_LINES);
		foreach ($lines ?: [] as $line) {
			if ($line !== '--START--' && ctype_digit($line)) {
				return (int) $line;
			}
		}
		return NULL;
	}

	/** @return list<list<string>> */
	private function timeoutCalls(string $path): array
	{
		$lines = @file($path, FILE_IGNORE_NEW_LINES);
		$calls = [];
		$call = [];
		foreach ($lines ?: [] as $line) {
			if ($line === '--CALL--') {
				if ($call !== []) {
					$calls[] = $call;
					$call = [];
				}
				continue;
			}
			$call[] = $line;
		}
		if ($call !== []) {
			$calls[] = $call;
		}
		return $calls;
	}
}
