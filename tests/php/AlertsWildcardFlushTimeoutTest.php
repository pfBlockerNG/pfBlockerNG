<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2880: the Alerts wildcard-delete resolver flush is bounded and its
 * expiry/failure is never reported as an ordinary success.
 *
 * The delete_domainwildcard POST path runs `unbound-control flush_zone +c .`
 * synchronously inside the page request. Unbounded, a resolver-control IPC
 * stall leaves the HTTP request without any terminal state; and a control
 * failure was silently swallowed. This test drives the SHIPPED POST-path block
 * (carved verbatim from pfblockerng_alerts.php, located from its unique reload
 * anchor) in a worker process with a deterministic `$pfb['chroot_cmd']`
 * double, so the same byte-identical test is red against the unbounded shape
 * and green once the established bounded-wait seam lands.
 */
final class AlertsWildcardFlushTimeoutTest extends TestCase
{
	private const ALERTS_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	/** The success message the delete_domainwildcard case seeds before the flush. */
	private const SUCCESS_MSG = 'The Wildcard Domain [ .example.com ] has been deleted from the DNSBL Whitelist customlist!';

	/**
	 * Salvage cap for the worker's end-of-run signal. It exists only to reap a
	 * stuck run. On the unbounded pre-#2880 path the hanging flush never
	 * returns, so the RED run fails HERE by design: the worker cannot reach
	 * its signal within the cap, which is exactly the defect being fixed.
	 */
	private const FLUSH_SALVAGE_SECONDS = 30;

	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_alerts_flush_test_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0777, TRUE), 'could not create the test sandbox');
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmp);
	}

	/**
	 * A hung resolver control must not block the request forever: the flush
	 * runs under the bounded wrapper (exact established limits), the request
	 * terminates, and the page distinguishes expiry from success while naming
	 * the persisted mutation state and the next recovery action.
	 */
	public function testHungResolverFlushIsBoundedAndNeverReportsOrdinarySuccess(): void
	{
		$r = $this->runFlush('stall');

		$this->assertTrue(
			$r['completed'],
			"the flush worker never terminated within the salvage cap, i.e. the POST path still blocks on resolver-control IPC\n"
			. "child log: {$r['child_log']}"
		);
		$this->assertBoundedFlushCall($r['timeout_calls'], $r['chroot']);
		$this->assertStringContainsString('TIMED OUT', $r['savemsg'], 'expiry must be user-visible');
		$this->assertStringContainsString('saved', $r['savemsg'], 'persisted mutation state must be explicit after expiry');
		$this->assertStringContainsString('unbound-control flush_zone', $r['savemsg'], 'next recovery action must be explicit after expiry');
		$this->assertNotSame(self::SUCCESS_MSG, $r['savemsg'], 'expiry must not be reported as an ordinary success');
		$this->assertStringContainsString('TIMED OUT', $r['log'], 'expiry must be logged');
		$this->assertNoOrphan($r['marker'], 'hung row');
	}

	/** An immediate nonzero control status must be distinguishable from success. */
	public function testImmediateNonzeroFlushIsDistinguishedFromSuccess(): void
	{
		$r = $this->runFlush('fail');

		$this->assertTrue($r['completed'], "worker did not terminate\nchild log: {$r['child_log']}");
		$this->assertBoundedFlushCall($r['timeout_calls'], $r['chroot']);
		$this->assertStringContainsString('FAILED (exit 3)', $r['savemsg'], 'control failure must be user-visible with its status');
		$this->assertStringContainsString('saved', $r['savemsg'], 'persisted mutation state must be explicit after failure');
		$this->assertNotSame(self::SUCCESS_MSG, $r['savemsg'], 'control failure must not be reported as an ordinary success');
		$this->assertStringContainsString('FAILED', $r['log'], 'control failure must be logged');
	}

	/** A control binary that cannot even launch must be distinguishable from success. */
	public function testMissingControlBinaryIsDistinguishedFromSuccess(): void
	{
		$r = $this->runFlush('missing');

		$this->assertTrue($r['completed'], "worker did not terminate\nchild log: {$r['child_log']}");
		$this->assertBoundedFlushCall($r['timeout_calls'], $r['chroot']);
		$this->assertStringContainsString('FAILED (exit 127)', $r['savemsg'], 'launch failure must be user-visible with its status');
		$this->assertNotSame(self::SUCCESS_MSG, $r['savemsg'], 'launch failure must not be reported as an ordinary success');
	}

	/** A healthy flush just below the budget preserves the existing success UI. */
	public function testHealthyFlushPreservesExistingSuccessBehavior(): void
	{
		$r = $this->runFlush('ok');

		$this->assertTrue($r['completed'], "worker did not terminate\nchild log: {$r['child_log']}");
		$this->assertBoundedFlushCall($r['timeout_calls'], $r['chroot']);
		$this->assertSame(self::SUCCESS_MSG, $r['savemsg'], 'a successful flush must not alter the existing success message');
		$this->assertStringNotContainsString('TIMED OUT', $r['savemsg']);
		$this->assertStringNotContainsString('FAILED', $r['savemsg']);
		$this->assertStringNotContainsString('TIMED OUT', $r['log']);
		$this->assertStringNotContainsString('FAILED', $r['log']);
	}

	/**
	 * Concurrent-reload row: when the resolver reload did not swap, no flush
	 * runs and the page makes no cache-flush claim at all.
	 */
	public function testReloadSwapFailureRunsNoFlushAndMakesNoCacheClaim(): void
	{
		$r = $this->runFlush('ok', FALSE);

		$this->assertTrue($r['completed'], "worker did not terminate\nchild log: {$r['child_log']}");
		$this->assertSame(array(), $r['timeout_calls'], 'no flush may run when the reload did not swap');
		$this->assertSame(self::SUCCESS_MSG, $r['savemsg'], 'no cache-flush outcome may be claimed without a flush');
		$this->assertStringNotContainsString('TIMED OUT', $r['savemsg']);
		$this->assertStringNotContainsString('FAILED', $r['savemsg']);
	}

	/**
	 * The bounded wrapper must carry the established Alerts DNS limits:
	 * timeout(1) default reaper mode, 30s TERM budget, 5s kill grace — the
	 * exact configured limits of the in-file CNAME lookup seam (issue #2083).
	 *
	 * @param list<list<string>> $calls
	 */
	private function assertBoundedFlushCall(array $calls, string $chroot): void
	{
		$this->assertNotEmpty($calls, 'the flush ran without the bounded timeout(1) wrapper');
		$this->assertSame(
			array('-s', 'TERM', '-k', '5', '30', $chroot, 'flush_zone', '+c', '.'),
			$calls[0],
			'the wildcard flush wrapper does not use the established 30s TERM + 5s kill-grace limits'
		);
	}

	/** The hanging double must be reaped by the flush itself, never orphaned. */
	private function assertNoOrphan(string $marker, string $context): void
	{
		$pid = $this->markerPid($marker);
		if ($pid === NULL) {
			$this->fail("flush double never announced its pid ({$context})");
		}
		$deadline = microtime(TRUE) + 10;
		while (microtime(TRUE) < $deadline) {
			if (!@posix_kill($pid, 0)) {
				return;
			}
			usleep(50000);
		}
		$this->fail("orphan: the hanging flush double (pid {$pid}) outlived the bounded flush ({$context})");
	}

	/**
	 * Run one flush scenario in a worker process against the SHIPPED POST-path
	 * block. $mode: 'stall' (double hangs forever), 'fail' (double exits 3),
	 * 'missing' (control binary does not exist -> 127), 'ok' (double exits 0
	 * quickly). The timeout(1) seam is a shim that logs its exact invocation
	 * and emulates the wrapper deterministically (kill + 124 on the hung row)
	 * so no wall-clock budget can make a verdict flake.
	 *
	 * @return array{completed:bool,savemsg:string,log:string,timeout_calls:list<list<string>>,child_log:string,marker:string,chroot:string}
	 */
	private function runFlush(string $mode, bool $swapped = TRUE): array
	{
		$marker = "{$this->tmp}/flush marker.log";
		$timeout_log = "{$this->tmp}/timeout args.log";
		$timeout_flag = "{$this->tmp}/timeout fired";
		$result = "{$this->tmp}/flush result.json";
		$child_log = "{$this->tmp}/child output.log";
		$done_signal = "{$this->tmp}/done signal";
		$this->assertTrue(posix_mkfifo($done_signal, 0600), 'could not create the end-of-run signal');

		$double = $this->fixture('flush_double.sh',
			"printf '%s\\n' \"--START-- \$\$\" >> " . escapeshellarg($marker) . "\n"
			. match ($mode) {
				'stall' => "while true; do :; done\n",
				'fail' => "exit 3\n",
				default => "sleep 0.2\n",
			}
		);
		$chroot = $mode === 'missing' ? "{$this->tmp}/missing-unbound-control" : $double;

		$timeout = $this->fixture('timeout_shim.sh',
			"printf '%s\\n' --CALL-- >> " . escapeshellarg($timeout_log) . "\n"
			. "printf '%s\\n' \"\$@\" >> " . escapeshellarg($timeout_log) . "\n"
			. "shift 5\n"
			. "\"\$@\" & child=\$!\n"
			. ($mode === 'stall' ?
				// Kill only after the double announced its pid, so the reaped-pid
				// assertion is deterministic rather than a race.
				"i=0\n"
				. "while [ ! -s " . escapeshellarg($marker) . " ] && [ \$i -lt 400 ]; do sleep 0.05; i=\$((i + 1)); done\n"
				. "touch " . escapeshellarg($timeout_flag) . "\n"
				. "kill -TERM \$child 2>/dev/null\n"
				: '')
			. "wait \$child; rc=\$?\n"
			. "[ -f " . escapeshellarg($timeout_flag) . " ] && exit 124\n"
			. "exit \$rc\n"
		);

		$block = $this->flushBlock();
		$function = 'function pfb_alerts_test_wildcard_flush(bool $swapped): void { '
			. 'global $pfb, $g, $savemsg, $entry; '
			. "\$entry = 'example.com'; "
			. '$savemsg = ' . var_export(self::SUCCESS_MSG, TRUE) . '; '
			. $block
			. ' }';

		$worker = "{$this->tmp}/flush worker.php";
		$bootstrap = realpath(__DIR__ . '/bootstrap.php');
		if ($bootstrap === FALSE) {
			throw new RuntimeException('test bootstrap path unavailable');
		}
		$worker_code = "<?php\n"
			. 'require_once ' . var_export($bootstrap, TRUE) . ";\n"
			. "if (function_exists('posix_setsid')) { posix_setsid(); }\n"
			// Announce end of run from a shutdown handler, so a worker that dies
			// before writing its result still reports in and is graded by the
			// salvage logic rather than hanging the whole suite.
			. 'register_shutdown_function(static function (): void { $signal = fopen('
				. var_export($done_signal, TRUE) . ", 'r+'); fwrite(\$signal, \"done\\n\"); fclose(\$signal); });\n"
			. 'eval(' . var_export($function, TRUE) . ");\n"
			. '$GLOBALS[\'g\'][\'tmp_path\'] = ' . var_export($this->tmp, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'log\'] = ' . var_export("{$this->tmp}/pfblockerng.log", TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'errlog\'] = ' . var_export("{$this->tmp}/pfblockerng.errlog", TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'chroot_cmd\'] = ' . var_export($chroot, TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'][\'timeout\'] = ' . var_export($timeout, TRUE) . ";\n"
			. '$_POST[\'entry_delete\'] = \'delete_domainwildcard\';' . "\n"
			. 'pfb_alerts_test_wildcard_flush(' . var_export($swapped, TRUE) . ');' . "\n"
			. 'file_put_contents(' . var_export($result, TRUE) . ', json_encode(['
				. "'savemsg' => \$savemsg, "
				. "'log' => (is_file(\$GLOBALS['pfb']['log']) ? file_get_contents(\$GLOBALS['pfb']['log']) : '')"
				. ' . (is_file($GLOBALS[\'pfb\'][\'errlog\']) ? file_get_contents($GLOBALS[\'pfb\'][\'errlog\']) : \'\'),'
			. ' ]));' . "\n";
		file_put_contents($worker, $worker_code);

		$descriptors = array(
			0 => array('file', '/dev/null', 'r'),
			1 => array('file', $child_log, 'ab'),
			2 => array('file', $child_log, 'ab'),
		);
		// Hold the signal open BEFORE the worker starts: a worker that finishes
		// at once must not report into a pipe this side has not attached to yet.
		$done = fopen($done_signal, 'r+');
		$this->assertIsResource($done, 'could not open the end-of-run signal');
		$process = proc_open(array(PHP_BINARY, $worker), $descriptors, $pipes);
		if (!is_resource($process)) {
			throw new RuntimeException('could not start flush worker');
		}
		$worker_status = proc_get_status($process);
		$worker_pid = (int) ($worker_status['pid'] ?? 0);

		$reported = FALSE;
		try {
			$read = array($done);
			$write = NULL;
			$except = NULL;
			$reported = stream_select($read, $write, $except, self::FLUSH_SALVAGE_SECONDS) === 1
				&& fgets($done) === "done\n";
		} finally {
			if (!$reported) {
				// The worker sits in exec() on the hung double; only SIGKILL of
				// its whole session gets it back.
				$killed = $worker_pid > 0 && function_exists('posix_kill') && @posix_kill(-$worker_pid, 9);
				if (!$killed) {
					proc_terminate($process, 9);
				}
			}
			proc_close($process);
			fclose($done);
			// Never leak the flush double, whatever happened above.
			$leftover = $this->markerPid($marker);
			if ($leftover !== NULL && function_exists('posix_kill')) {
				@posix_kill($leftover, 9);
			}
		}
		if (!$reported) {
			$this->fail(sprintf(
				'STUCK/ENVIRONMENT: the flush worker never reached its end-of-run signal within %ds. '
				. 'Against the unbounded pre-#2880 POST path this IS the expected red (the request blocks on resolver-control IPC); '
				. 'otherwise the run is stuck or its host starved the worker (child output: %s)',
				self::FLUSH_SALVAGE_SECONDS,
				is_file($child_log) ? (string) file_get_contents($child_log) : '(none)'
			));
		}

		$payload = is_file($result) ? json_decode((string) file_get_contents($result), TRUE) : array();
		return array(
			'completed' => is_file($result),
			'savemsg' => (string) ($payload['savemsg'] ?? ''),
			'log' => (string) ($payload['log'] ?? ''),
			'timeout_calls' => $this->timeoutCalls($timeout_log),
			'child_log' => is_file($child_log) ? (string) file_get_contents($child_log) : '',
			'marker' => $marker,
			'chroot' => $chroot,
		);
	}

	/**
	 * Carve the shipped `if ($swapped) { ... }` wildcard-flush block from the
	 * page's delete_domainwildcard POST tail. It is located from the block's
	 * unique `pfb_reload_unbound('enabled', FALSE, FALSE, TRUE)` anchor (the
	 * page has two other `if ($swapped)` sites) and brace-matched through the
	 * tokenizer, so string-interpolated braces (`{$pfb['chroot_cmd']}`) can
	 * never truncate it and the same extraction drives the pre-#2880
	 * unbounded shape and the bounded rewrite alike. The anchor assignment
	 * itself is deliberately NOT carved: the harness supplies $swapped so no
	 * row depends on the real reload's off-appliance verdict.
	 */
	private function flushBlock(): string
	{
		$source = file_get_contents(self::ALERTS_PHP);
		if ($source === FALSE) {
			throw new RuntimeException('test oracle: failed to read pfblockerng_alerts.php');
		}
		$anchor = "\$swapped = pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);";
		$anchor_pos = strpos($source, $anchor);
		if ($anchor_pos === FALSE) {
			throw new RuntimeException('test oracle: wildcard flush anchor not found');
		}
		$block_head = 'if ($swapped) {';
		$pos = strpos($source, $block_head, $anchor_pos + strlen($anchor));
		if ($pos === FALSE) {
			throw new RuntimeException('test oracle: wildcard flush block head not found after anchor');
		}
		$tokens = token_get_all($source);
		$offset = 0;
		$head_idx = NULL;
		foreach ($tokens as $idx => $tok) {
			if ($head_idx === NULL && $offset === $pos) {
				$head_idx = $idx;
			}
			$offset += strlen(is_array($tok) ? $tok[1] : $tok);
		}
		if ($head_idx === NULL) {
			throw new RuntimeException('test oracle: block head does not align with a token boundary');
		}
		$offset = $pos;
		// `if ($swapped)` carries no braces of its own, so the first opening
		// brace after the head token opens the block. Bare '{'/'}' tokens and
		// the interpolation openers are tracked; quoted strings arrive as
		// single tokens, so shell braces inside them cannot skew the depth.
		$depth = 0;
		$end_offset = NULL;
		$seen_open = FALSE;
		for ($i = $head_idx, $n = count($tokens); $i < $n; $i++) {
			$tok = $tokens[$i];
			$len = strlen(is_array($tok) ? $tok[1] : $tok);
			if ($seen_open) {
				if ($tok === '{' || (is_array($tok) && in_array($tok[0], array(T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES), TRUE))) {
					$depth++;
				} elseif ($tok === '}') {
					$depth--;
					if ($depth === 0) {
						$end_offset = $offset + $len - 1;
						break;
					}
				}
			} elseif ($tok === '{') {
				$seen_open = TRUE;
				$depth = 1;
			}
			$offset += $len;
		}
		if ($end_offset === NULL) {
			throw new RuntimeException('test oracle: wildcard flush block braces do not close');
		}
		return substr($source, $pos, $end_offset + 1 - $pos);
	}

	private function fixture(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	private function markerPid(string $marker): ?int
	{
		$lines = @file($marker, FILE_IGNORE_NEW_LINES);
		foreach ($lines ?: array() as $line) {
			if (str_starts_with($line, '--START--')) {
				$pid = (int) substr($line, strlen('--START--'));
				if ($pid > 0) {
					return $pid;
				}
			}
		}
		return NULL;
	}

	/** @return list<list<string>> */
	private function timeoutCalls(string $path): array
	{
		$lines = @file($path, FILE_IGNORE_NEW_LINES);
		$calls = array();
		$call = array();
		foreach ($lines ?: array() as $line) {
			if ($line === '--CALL--') {
				if ($call !== array()) {
					$calls[] = $call;
					$call = array();
				}
				continue;
			}
			$call[] = $line;
		}
		if ($call !== array()) {
			$calls[] = $call;
		}
		return $calls;
	}
}
