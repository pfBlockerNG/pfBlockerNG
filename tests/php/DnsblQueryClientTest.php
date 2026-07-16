<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 query-channel client: pfb_dnsbl_query().
 *
 * Scenario: the client writes a request onto the read-only query channel
 * (here redirected to a temp dnsbldir) and bounded-waits for the id-matching
 * reply, returning the parsed six-key verdict or NULL. In production,
 * pfb_log_event() reaches it from two independent Lighttpd parsers. These tests pin:
 *   - PFBL-01 domain validation at the choke point (invalid domain -> NULL,
 *     no request written, no wait);
 *   - lock-open and request-publish failures -> NULL before any reply wait;
 *   - complete-transaction serialization across overlapping callers and timeouts;
 *   - the request's JSON schema (id/domain/qtype) and 0660 permission,
 *     observed by an independent child reader that plays the Python
 *     side of the channel;
 *   - a fresh, unique id per call;
 *   - strict reply validation (7 typed keys) -- every hostile shape (missing
 *     field, mistyped field, truncated/non-JSON/oversized bytes, foreign id)
 *     is ignored, never a fatal, and the call times out to NULL;
 *   - blocked=false with empty attribution is a VALID verdict, not NULL;
 *   - the bounded wait behaviorally obeys its deadline, while a source pin
 *     records the independent hard poll cap that protects a stalled clock;
 *   - cleanup: reply+request unlinked on a matched verdict or timeout, no
 *     ".pfbctl_" staging residue.
 *
 * Test mode: issue #1352 behaviour-changing regression coverage. The frozen
 * overlapping-caller and lock-open rows fail against the pre-fix production
 * source and pass with the serialized transaction, alongside the established
 * round-trip, timeout, hostile-reply, and permission contracts.
 *
 * Round-trip technique: a tracked/reaped `pcntl_fork()` child plays the Python
 * side -- it polls the sandbox's request file under a deadline, decodes it,
 * records the observed request + permission bits into observed.json, and
 * writes a reply (substituting the request's real id into a template) --
 * this exercises the request-schema/perms assertions AND every
 * matching-id hostile row from one helper. Id-independent hostile rows
 * (never matchable regardless of id) are pre-seeded directly, no responder.
 */
#[CoversFunction('pfb_dnsbl_query')]
final class DnsblQueryClientTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private bool $hadPfb = false;
	/** @var array<int, true> */
	private array $children = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_query_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $this->tmp,
			'supp'     => 'off',	// pfb_filter()'s private/reserved IP exclusion off for the test
			'log'      => "{$this->tmp}/pfblockerng.log",
			'errlog'   => "{$this->tmp}/error.log",
		]);

		foreach (['pcntl_fork', 'pcntl_waitpid', 'pcntl_wifexited', 'pcntl_wexitstatus', 'pcntl_wifstopped', 'posix_kill'] as $function) {
			if (!function_exists($function)) {
				$this->markTestSkipped("{$function}() is unavailable -- cannot run cross-process query-channel tests.");
			}
		}
	}

	protected function tearDown(): void
	{
		$failure = null;
		try {
			foreach (array_keys($this->children) as $pid) {
				try {
					$this->reapChild($pid);
				} catch (Throwable $e) {
					$failure ??= $e;
				}
			}
		} finally {
			if ($this->hadPfb) {
				$GLOBALS['pfb'] = $this->originalPfb;
			} else {
				unset($GLOBALS['pfb']);
			}
			$this->rrmdir($this->tmp);
		}
		if ($failure !== null) {
			throw $failure;
		}
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $f) {
			if ($f === '.' || $f === '..') {
				continue;
			}
			$p = "{$dir}/{$f}";
			is_dir($p) ? $this->rrmdir($p) : @unlink($p);
		}
		@rmdir($dir);
	}

	private function channel(): string
	{
		return "{$this->tmp}/pfb_py_query";
	}

	private function replyPath(): string
	{
		return "{$this->tmp}/pfb_py_query.reply";
	}

	private function lockPath(): string
	{
		return "{$this->tmp}/pfb_py_query.lock";
	}

	/** Publish a cross-process test artifact without exposing partial bytes. */
	private function atomicWrite(string $path, string $contents): void
	{
		$tmp = "{$path}.tmp." . getmypid() . '.' . uniqid('', true);
		try {
			if (file_put_contents($tmp, $contents) !== strlen($contents) || !rename($tmp, $path)) {
				throw new RuntimeException("failed to publish {$path}");
			}
		} finally {
			@unlink($tmp);
		}
	}

	private function atomicWriteJson(string $path, mixed $value): void
	{
		$json = json_encode($value);
		if ($json === false) {
			throw new RuntimeException('failed to encode cross-process test artifact');
		}
		$this->atomicWrite($path, $json);
	}

	/** Fork a tracked child; the closure must communicate through temp files. */
	private function forkChild(callable $task): int
	{
		$pid = pcntl_fork();
		if ($pid === -1) {
			$this->markTestSkipped('pcntl_fork() failed.');
		}
		if ($pid === 0) {
			try {
				$task();
				exit(0);
			} catch (Throwable $e) {
				@file_put_contents("{$this->tmp}/child-error-" . getmypid(), $e->getMessage());
				exit(1);
			}
		}
		$this->children[$pid] = true;
		return $pid;
	}

	/** Reap a tracked child under a hard deadline; kill it rather than orphaning it. */
	private function reapChild(int $pid, float $timeout_s = 5.0): void
	{
		$deadline = microtime(true) + $timeout_s;
		do {
			$waited = pcntl_waitpid($pid, $status, WNOHANG);
			if ($waited === $pid) {
				unset($this->children[$pid]);
				$failure = $this->childFailureMessage($pid);
				$this->assertTrue(pcntl_wifexited($status), $failure);
				$this->assertSame(0, pcntl_wexitstatus($status), $failure);
				return;
			}
			usleep(20000);
		} while (microtime(true) < $deadline);

		@posix_kill($pid, 9);
		pcntl_waitpid($pid, $status);
		unset($this->children[$pid]);
		$this->fail("child {$pid} exceeded the {$timeout_s}s test deadline");
	}

	private function childFailureMessage(int $pid): string
	{
		$error = @file_get_contents("{$this->tmp}/child-error-{$pid}");
		return $error !== false && $error !== '' ? "child {$pid} failed: {$error}" : "child {$pid} failed";
	}

	/** Prove SIGSTOP reached a live child rather than an already-exited zombie. */
	private function waitForStoppedChild(int $pid, float $timeout_s = 1.0): void
	{
		$deadline = microtime(true) + $timeout_s;
		do {
			$waited = pcntl_waitpid($pid, $status, WNOHANG | WUNTRACED);
			if ($waited === $pid) {
				if (!pcntl_wifstopped($status)) {
					unset($this->children[$pid]);
					$this->fail("child {$pid} exited before SIGSTOP was observed");
				}
				return;
			}
			if ($waited === -1) {
				unset($this->children[$pid]);
				$this->fail("child {$pid} was not waitable after SIGSTOP");
			}
			usleep(20000);
		} while (microtime(true) < $deadline);
		$this->fail("child {$pid} did not stop within {$timeout_s}s");
	}

	/** Read a non-empty file under a bounded test-side deadline. */
	private function readMarker(string $name, float $timeout_s = 4.0): string
	{
		$path = "{$this->tmp}/{$name}";
		$deadline = microtime(true) + $timeout_s;
		do {
			$raw = @file_get_contents($path);
			if ($raw !== false && $raw !== '') {
				return $raw;
			}
			usleep(20000);
		} while (microtime(true) < $deadline);
		$this->fail("marker {$name} did not appear within {$timeout_s}s");
	}

	/** Wait for a request with the requested domain and return its decoded record. */
	private function waitForRequest(string $domain, float $timeout_s = 4.0): array
	{
		$deadline = microtime(true) + $timeout_s;
		do {
			$raw = @file_get_contents($this->channel());
			$record = $raw === false ? null : json_decode($raw, true);
			if (is_array($record) && ($record['domain'] ?? null) === $domain) {
				return $record;
			}
			usleep(20000);
		} while (microtime(true) < $deadline);
		throw new RuntimeException("request for {$domain} did not appear within {$timeout_s}s");
	}

	private function verdictReply(string $id, string $group): string
	{
		return (string) json_encode([
			'id' => $id, 'blocked' => true, 'b_type' => 'dataDB', 'group' => $group,
			'b_eval' => 'exact', 'feed' => "{$group}-feed", 'p_type' => 'A',
		]);
	}

	private function forkQuery(string $domain, float $timeout_s, string $marker): int
	{
		return $this->forkChild(function () use ($domain, $timeout_s, $marker): void {
			file_put_contents("{$this->tmp}/{$marker}.started", '1');
			$result = pfb_dnsbl_query($domain, 'A', $timeout_s);
			$this->atomicWriteJson("{$this->tmp}/{$marker}.json", $result);
		});
	}

	private function readQueryResult(string $marker, float $timeout_s = 4.0): ?array
	{
		$raw = $this->readMarker("{$marker}.json", $timeout_s);
		$result = json_decode($raw, true);
		$this->assertSame(JSON_ERROR_NONE, json_last_error(), json_last_error_msg());
		if ($result !== null && !is_array($result)) {
			$this->fail('expected query result array or NULL, got: ' . var_export($result, true));
		}
		return $result;
	}

	/** Run a query child while this process owns the channel lock. */
	private function queryUnderContention(string $domain, float $timeout_s): array
	{
		$lock = fopen($this->lockPath(), 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));

		$marker = "contended-{$domain}.json";
		$ready = "contended-{$domain}.ready";
		$go = "contended-{$domain}.go";
		$child = $this->forkChild(function () use ($lock, $domain, $timeout_s, $marker, $ready, $go): void {
			fclose($lock);
			$probe = fopen($this->lockPath(), 'c');
			if ($probe === false) {
				throw new RuntimeException('failed to open contention probe lock');
			}
			$wouldBlock = 0;
			if (flock($probe, LOCK_EX | LOCK_NB, $wouldBlock) || $wouldBlock !== 1) {
				throw new RuntimeException('contention probe did not observe the parent lock');
			}
			fclose($probe);
			$this->atomicWrite("{$this->tmp}/{$ready}", '1');
			$this->readMarker($go);
			$start = microtime(true);
			$result = pfb_dnsbl_query($domain, 'A', $timeout_s);
			$this->atomicWriteJson("{$this->tmp}/{$marker}", [
				'result' => $result,
				'elapsed' => microtime(true) - $start,
			]);
		});
		$this->readMarker($ready);
		$this->atomicWrite("{$this->tmp}/{$go}", '1');

		$path = "{$this->tmp}/{$marker}";
		$deadline = microtime(true) + 0.75;
		$raw = false;
		do {
			$raw = @file_get_contents($path);
			if ($raw !== false && $raw !== '') {
				break;
			}
			usleep(20000);
		} while (microtime(true) < $deadline);
		$completedWhileLocked = $raw !== false && $raw !== '';
		$requestPublished = file_exists($this->channel());

		flock($lock, LOCK_UN);
		fclose($lock);
		if (!$completedWhileLocked) {
			$raw = $this->readMarker($marker, 2.0);
		}
		$this->reapChild($child);
		$record = json_decode((string) $raw, true);
		$this->assertIsArray($record);

		return [$record, $completedWhileLocked, $requestPublished];
	}

	/**
	 * Spawn a background PHP process that plays the Python side of the
	 * channel: it polls for the request (up to ~3s, 20ms steps), records
	 * the decoded request JSON + the request file's permission bits into
	 * observed.json, substitutes the request's real id for the literal
	 * "__ID__" placeholder in $replyTemplateJson, and writes the reply.
	 */
	private function spawnResponder(string $replyTemplateJson): void
	{
		$this->forkChild(function () use ($replyTemplateJson): void {
			$deadline = microtime(true) + 3.0;
			$request = null;
			do {
				$raw = @file_get_contents($this->channel());
				$record = $raw === false ? null : json_decode($raw, true);
				if (is_array($record) && isset($record['id'])) {
					$request = $record;
					break;
				}
				usleep(20000);
			} while (microtime(true) < $deadline);
			if ($request === null) {
				throw new RuntimeException('responder did not observe a request');
			}
			$perm = substr(sprintf('%o', fileperms($this->channel())), -4);
			$this->atomicWriteJson("{$this->tmp}/observed.json", [
				'request' => $request,
				'perm' => $perm,
			]);
			$reply = str_replace('__ID__', (string) $request['id'], $replyTemplateJson);
			$this->atomicWrite($this->replyPath(), $reply);
		});
	}

	/** Poll (bounded, test-side only) for the responder's observed.json. */
	private function readObserved(float $timeout_s = 4.0): array
	{
		$path = "{$this->tmp}/observed.json";
		$deadline = microtime(true) + $timeout_s;
		while (microtime(true) < $deadline) {
			if (file_exists($path)) {
				$raw = @file_get_contents($path);
				if ($raw !== false && trim($raw) !== '') {
					$dec = json_decode($raw, true);
					if (is_array($dec)) {
						return $dec;
					}
				}
			}
			usleep(50000);
		}
		$this->fail('responder never observed a request within the test timeout');
	}

	// --- invalid input -> NULL, no request written, no wait ----------------

	public function testNoDotDomainRejectedNoRequestWritten(): void
	{
		@unlink($GLOBALS['pfb']['errlog']);
		mkdir($this->lockPath());
		$this->assertFileDoesNotExist($this->channel());
		$this->assertNull(pfb_dnsbl_query('nodotsatall'));
		$this->assertFileDoesNotExist($this->channel());
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringNotContainsString('query channel lock open failed', $logs);
	}

	public function testEmptyDomainRejected(): void
	{
		$this->assertNull(pfb_dnsbl_query(''));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDomainWithEmbeddedControlCharacterRejected(): void
	{
		// A literal tab between labels fails pfb_filter's pre-switch control-char gate.
		$this->assertNull(pfb_dnsbl_query("bad\tdomain.example"));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDoubleDotDomainRejected(): void
	{
		// PFB_FILTER_DOMAIN explicitly excludes a double dot.
		$this->assertNull(pfb_dnsbl_query('bad..domain.example'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testOverlongDomainRejected(): void
	{
		// PFB_FILTER_DOMAIN requires strlen() < 255.
		$overlong = str_repeat('a', 250) . '.example';
		$this->assertGreaterThanOrEqual(255, strlen($overlong));
		$this->assertNull(pfb_dnsbl_query($overlong));
		$this->assertFileDoesNotExist($this->channel());
	}

	// --- publish failure -> NULL, no wait ------------------------------------

	public function testWriteFailureReturnsNullNoRequestWritten(): void
	{
		// The lock can be opened, but publishing onto a directory cannot succeed.
		// After that failure, removing the obstruction permits a second call to
		// acquire the same lock and complete, proving the failure released it.
		mkdir($this->channel());
		$start = microtime(true);
		$result = pfb_dnsbl_query('write-fail-case.example', 'A', 5.0);
		$elapsed = microtime(true) - $start;

		$this->assertNull($result);
		$this->assertLessThan(1.0, $elapsed, 'a publish failure must return immediately, never wait');
		rmdir($this->channel());
		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => false, 'b_type' => '', 'group' => '',
			'b_eval' => '', 'feed' => '', 'p_type' => '',
		]));
		$this->assertIsArray(pfb_dnsbl_query('write-fail-recovery.example', 'A', 2.0));
	}

	public function testLockOpenFailureReturnsNullBeforePublishing(): void
	{
		mkdir($this->lockPath());
		@unlink($GLOBALS['pfb']['log']);
		@unlink($GLOBALS['pfb']['errlog']);

		$start = microtime(true);
		$result = pfb_dnsbl_query('lock-open-failure.example', 'A', 5.0);
		$elapsed = microtime(true) - $start;

		$this->assertNull($result);
		$this->assertLessThan(1.0, $elapsed, 'a lock-open failure must return before publishing or polling');
		$this->assertFileDoesNotExist($this->channel());
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('ADR-65', $logs);
		$this->assertStringContainsString('query channel lock open failed', $logs);
	}

	public function testExistingGarbageLockFileIsNotTruncated(): void
	{
		$garbage = "arbitrary lock bytes\x00remain";
		file_put_contents($this->lockPath(), $garbage);
		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => false, 'b_type' => '', 'group' => '',
			'b_eval' => '', 'feed' => '', 'p_type' => '',
		]));

		$this->assertIsArray(pfb_dnsbl_query('garbage-lock.example', 'A', 2.0));
		$this->assertSame($garbage, file_get_contents($this->lockPath()));
	}

	public function testContendedLockWithZeroTimeoutReturnsWithoutPublishing(): void
	{
		[$record, $completedWhileLocked, $requestPublished] = $this->queryUnderContention(
			'zero-lock-timeout.example',
			0.0
		);

		$this->assertTrue($completedWhileLocked, 'zero-timeout query blocked on the occupied channel lock');
		$this->assertNull($record['result']);
		$this->assertLessThan(0.5, $record['elapsed'], 'zero-timeout query exceeded its total wait budget');
		$this->assertFalse($requestPublished, 'lock timeout must not publish a query request');
	}

	/** Source pin: stalled-clock behavior has no deterministic production seam. */
	public function testSourcePinLockWaitContainsIndependentHardPollCap(): void
	{
		$function = new ReflectionFunction('pfb_dnsbl_query');
		$lines = file($function->getFileName());
		$this->assertIsArray($lines);
		$source = implode('', array_slice(
			$lines,
			$function->getStartLine() - 1,
			$function->getEndLine() - $function->getStartLine() + 1
		));

		$this->assertStringContainsString('$lock_polls++;', $source);
		$this->assertStringContainsString('$lock_polls >= $max_lock_polls', $source);
	}

	public function testContendedLockWithShortTimeoutReturnsWithoutPublishing(): void
	{
		[$record, $completedWhileLocked, $requestPublished] = $this->queryUnderContention(
			'short-lock-timeout.example',
			0.1
		);

		$this->assertTrue($completedWhileLocked, 'short-timeout query blocked past its channel-lock deadline');
		$this->assertNull($record['result']);
		$this->assertGreaterThanOrEqual(0.08, $record['elapsed'], 'contended query abandoned before its wait budget');
		$this->assertLessThan(0.5, $record['elapsed'], 'short-timeout query exceeded its total wait budget');
		$this->assertFalse($requestPublished, 'lock timeout must not publish a query request');
	}

	public function testResumedLockWaiterCannotPublishAfterDeadline(): void
	{
		if (!defined('SIGSTOP') || !defined('SIGCONT') || !defined('WUNTRACED')) {
			$this->markTestSkipped('SIGSTOP/SIGCONT/WUNTRACED are unavailable -- cannot suspend the lock waiter.');
		}

		$lock = fopen($this->lockPath(), 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		$child = $this->forkChild(function () use ($lock): void {
			fclose($lock);
			file_put_contents("{$this->tmp}/late-lock.started", '1');
			$result = pfb_dnsbl_query('late-lock.example', 'A', 0.5);
			$this->atomicWriteJson("{$this->tmp}/late-lock.json", $result);
		});

		$this->readMarker('late-lock.started');
		usleep(40000);
		$this->assertTrue(posix_kill($child, (int) constant('SIGSTOP')));
		$this->waitForStoppedChild($child);
		usleep(600000);
		flock($lock, LOCK_UN);
		fclose($lock);
		$this->assertTrue(posix_kill($child, (int) constant('SIGCONT')));

		$this->assertNull($this->readQueryResult('late-lock', 2.0));
		$this->reapChild($child);
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('query channel lock timed out', $logs);
		$this->assertStringNotContainsString('timed out waiting for a verdict', $logs);
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testResumedReplyPollerRejectsVerdictPublishedAfterDeadline(): void
	{
		if (!defined('SIGSTOP') || !defined('SIGCONT')) {
			$this->markTestSkipped('SIGSTOP/SIGCONT are unavailable -- cannot suspend the reply poller.');
		}

		$child = $this->forkQuery('late-reply.example', 0.5, 'late-reply');
		$request = $this->waitForRequest('late-reply.example');
		$this->assertTrue(posix_kill($child, (int) constant('SIGSTOP')));
		usleep(600000);
		$late_reply = $this->verdictReply($request['id'], 'late-group');
		$this->atomicWrite($this->replyPath(), $late_reply);
		$this->assertFileExists($this->replyPath());
		$this->assertTrue(posix_kill($child, (int) constant('SIGCONT')));

		$this->assertNull($this->readQueryResult('late-reply', 2.0));
		$this->reapChild($child);
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('timed out waiting for a verdict', $logs);
		$this->assertFileDoesNotExist($this->channel());
		$this->assertFileDoesNotExist($this->replyPath());
	}

	// --- happy path: blocked verdict, request schema + perms, cleanup -------

	public function testRoundTripBlockedVerdictAndRequestSchema(): void
	{
		$this->spawnResponder(json_encode([
			'id'      => '__ID__',
			'blocked' => true,
			'b_type'  => 'dataDB',
			'group'   => 'malware',
			'b_eval'  => 'exact',
			'feed'    => 'testfeed',
			'p_type'  => 'A',
		]));

		$result = pfb_dnsbl_query('blocked-case.example', 'A', 4.0);

		$this->assertSame([
			'blocked' => true,
			'b_type'  => 'dataDB',
			'group'   => 'malware',
			'b_eval'  => 'exact',
			'feed'    => 'testfeed',
			'p_type'  => 'A',
		], $result, 'expected the responder-shaped verdict, got: ' . var_export($result, true));

		// Independent-reader assertions: the request the client actually wrote.
		$observed = $this->readObserved();
		$this->assertSame('blocked-case.example', $observed['request']['domain']);
		$this->assertSame('A', $observed['request']['qtype']);
		$this->assertNotEmpty($observed['request']['id']);
		$this->assertSame('0660', $observed['perm'], 'request file must be group-writable 0660 (ADR-65 SS2.1)');

		// Cleanup: both request and reply are gone after a matched verdict.
		clearstatcache();
		$this->assertFileDoesNotExist($this->channel());
		$this->assertFileDoesNotExist($this->replyPath());

		// No atomic-write staging residue.
		$leftover = array_filter(scandir($this->tmp), static function ($f) {
			return strpos($f, '.pfbctl_') === 0;
		});
		$this->assertSame([], array_values($leftover));
	}

	public function testRoundTripCleanVerdictIsNotNull(): void
	{
		// blocked=false with all five attribution fields empty is a VALID verdict
		// (a clean/unknown name) -- never confused with a NULL (no-verdict) miss.
		$this->spawnResponder(json_encode([
			'id'      => '__ID__',
			'blocked' => false,
			'b_type'  => '',
			'group'   => '',
			'b_eval'  => '',
			'feed'    => '',
			'p_type'  => '',
		]));

		$result = pfb_dnsbl_query('clean-case.example', 'A', 4.0);

		$this->assertNotNull($result, 'a clean verdict must be a valid array, not NULL');
		$this->assertFalse($result['blocked']);
		$this->assertSame('', $result['b_type']);
		$this->assertSame('', $result['group']);
		$this->assertSame('', $result['b_eval']);
		$this->assertSame('', $result['feed']);
		$this->assertSame('', $result['p_type']);
	}

	public function testConcurrentCallersAreSerializedAndReceiveOwnReplies(): void
	{
		// The responder deliberately withholds the first reply while caller B
		// enters pfb_dnsbl_query(). With a shared unlocked slot B overwrites A;
		// with the query lock B cannot publish until A consumes its own reply.
		$server = $this->forkChild(function (): void {
			$first = $this->waitForRequest('concurrent-a.example');
			file_put_contents("{$this->tmp}/server-first-ready", '1');
			$this->readMarker('release-first');
			$this->atomicWrite($this->replyPath(), $this->verdictReply($first['id'], 'group-a'));

			$deadline = microtime(true) + 2.0;
			while (file_exists($this->replyPath()) && microtime(true) < $deadline) {
				usleep(20000);
			}
			if (file_exists($this->replyPath())) {
				throw new RuntimeException('first caller did not consume its reply');
			}
			$second = $this->waitForRequest('concurrent-b.example');
			$this->atomicWrite($this->replyPath(), $this->verdictReply($second['id'], 'group-b'));
		});

		$callerA = $this->forkQuery('concurrent-a.example', 2.5, 'caller-a');
		$this->readMarker('server-first-ready');
		$callerB = $this->forkQuery('concurrent-b.example', 2.5, 'caller-b');
		$this->readMarker('caller-b.started');
		usleep(100000);
		file_put_contents("{$this->tmp}/release-first", '1');

		$resultA = $this->readQueryResult('caller-a', 4.0);
		$resultB = $this->readQueryResult('caller-b', 4.0);
		$this->assertSame('group-a', $resultA['group'] ?? null);
		$this->assertSame('group-b', $resultB['group'] ?? null);
		$this->reapChild($callerA);
		$this->reapChild($callerB);
		$this->reapChild($server);
		$this->assertFileDoesNotExist($this->channel());
		$this->assertFileDoesNotExist($this->replyPath());
	}

	public function testTimedOutCallerCannotDeleteNextCallersRequest(): void
	{
		// A receives no reply and must time out. The server records B's request,
		// then waits until after A's timeout before replying. Without serialization
		// A unlinks B's live request; with the lock B publishes only after A cleans
		// up and releases, so B's request remains intact for its own responder.
		$server = $this->forkChild(function (): void {
			$this->waitForRequest('timeout-a.example');
			file_put_contents("{$this->tmp}/timeout-a-ready", '1');
			$second = $this->waitForRequest('timeout-b.example');
			usleep(500000);
			$raw = @file_get_contents($this->channel());
			$current = $raw === false ? null : json_decode($raw, true);
			$intact = is_array($current) && (($current['id'] ?? null) === $second['id']);
			file_put_contents("{$this->tmp}/timeout-b-intact", $intact ? 'yes' : 'no');
			if ($intact) {
				$this->atomicWrite($this->replyPath(), $this->verdictReply($second['id'], 'group-b'));
			}
		});

		$callerA = $this->forkQuery('timeout-a.example', 0.3, 'timeout-caller-a');
		$this->readMarker('timeout-a-ready');
		$callerB = $this->forkQuery('timeout-b.example', 1.8, 'timeout-caller-b');

		$this->assertNull($this->readQueryResult('timeout-caller-a', 2.0));
		$resultB = $this->readQueryResult('timeout-caller-b', 3.0);
		$this->assertSame('yes', $this->readMarker('timeout-b-intact'));
		$this->assertSame('group-b', $resultB['group'] ?? null);
		$this->reapChild($callerA);
		$this->reapChild($callerB);
		$this->reapChild($server);
		$this->assertFileDoesNotExist($this->channel());
		$this->assertFileDoesNotExist($this->replyPath());
	}

	public function testFreshIdIsUsedOnEachCall(): void
	{
		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => false, 'b_type' => '', 'group' => '',
			'b_eval' => '', 'feed' => '', 'p_type' => '',
		]));
		pfb_dnsbl_query('fresh-id-case-one.example', 'A', 4.0);
		$firstId = $this->readObserved()['request']['id'];

		@unlink("{$this->tmp}/observed.json");
		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => false, 'b_type' => '', 'group' => '',
			'b_eval' => '', 'feed' => '', 'p_type' => '',
		]));
		pfb_dnsbl_query('fresh-id-case-two.example', 'A', 4.0);
		$secondId = $this->readObserved()['request']['id'];

		$this->assertNotSame($firstId, $secondId, 'each call must publish a fresh, unique id');
	}

	// --- bounded wait: deadline AND hard cap --------------------------------

	public function testNoReplyTimesOutToNullWithinDeadlineBounds(): void
	{
		$start = microtime(true);
		$result = pfb_dnsbl_query('no-reply-case.example', 'A', 0.6);
		$elapsed = microtime(true) - $start;

		$this->assertNull($result);
		$this->assertGreaterThanOrEqual(0.6, $elapsed, "expected elapsed >= 0.6s, got {$elapsed}");
		$this->assertLessThan(2.0, $elapsed, "expected elapsed < 2.0s (bounded wait), got {$elapsed}");
		clearstatcache();
		$this->assertFileDoesNotExist($this->channel(), 'request file must be cleaned up on timeout');
	}

	public function testZeroTimeoutDegeneratesToOneReadAttempt(): void
	{
		// No reply ever appears; a timeout_s <= 0 must still return promptly (a
		// single read attempt, never an unbounded or long-blocking wait).
		$start = microtime(true);
		$result = pfb_dnsbl_query('zero-timeout-case.example', 'A', 0.0);
		$elapsed = microtime(true) - $start;

		$this->assertNull($result);
		$this->assertLessThan(0.5, $elapsed, "expected a near-instant single attempt, got {$elapsed}");
	}

	public function testShortReplyTimeoutDoesNotOversleepItsDeadline(): void
	{
		$start = microtime(true);
		$result = pfb_dnsbl_query('short-reply-timeout.example', 'A', 0.001);
		$elapsed = microtime(true) - $start;

		$this->assertNull($result);
		$this->assertLessThan(0.1, $elapsed, "short reply timeout overslept its deadline: {$elapsed}s");
	}

	// --- hostile reply rows: id-independent (pre-seeded, no responder) -----

	public function testTruncatedJsonReplyIgnoredTimesOutToNull(): void
	{
		file_put_contents($this->replyPath(), '{"id":"whatever","blocked":');
		$result = pfb_dnsbl_query('truncated-json-case.example', 'A', 0.6);
		$this->assertNull($result);
	}

	public function testNonJsonBytesReplyIgnoredTimesOutToNull(): void
	{
		file_put_contents($this->replyPath(), "not json at all, just bytes\x00\x01");
		$result = pfb_dnsbl_query('non-json-case.example', 'A', 0.6);
		$this->assertNull($result);
	}

	public function testOversizedReplyIgnoredTimesOutToNull(): void
	{
		// > 65536 bytes is treated as malformed regardless of content shape.
		$huge = str_repeat('x', 70000);
		file_put_contents($this->replyPath(), $huge);
		$result = pfb_dnsbl_query('oversized-reply-case.example', 'A', 0.6);
		$this->assertNull($result);
	}

	public function testForeignIdReplyIgnoredTimesOutToNull(): void
	{
		// Well-shaped, valid reply -- but for an id our fresh uniqid() call can
		// never match.
		file_put_contents($this->replyPath(), json_encode([
			'id'      => 'a-foreign-id-that-will-never-match',
			'blocked' => true,
			'b_type'  => 'dataDB',
			'group'   => 'malware',
			'b_eval'  => 'exact',
			'feed'    => 'testfeed',
			'p_type'  => 'A',
		]));
		$result = pfb_dnsbl_query('id-mismatch-case.example', 'A', 0.6);
		$this->assertNull($result);
	}

	// --- hostile reply rows: matching id (via responder) --------------------

	public function testMissingFieldReplyIgnoredTimesOutToNull(): void
	{
		// Matches the real id but omits 'group' -- must be ignored, never a fatal.
		$this->spawnResponder(json_encode([
			'id'      => '__ID__',
			'blocked' => true,
			'b_type'  => 'dataDB',
			'b_eval'  => 'exact',
			'feed'    => 'testfeed',
			'p_type'  => 'A',
		]));
		$result = pfb_dnsbl_query('missing-field-case.example', 'A', 0.8);
		$this->assertNull($result);
	}

	public function testMistypedBlockedFieldReplyIgnoredTimesOutToNull(): void
	{
		// 'blocked' as a string, not bool -- must be ignored, never coerced.
		$this->spawnResponder(json_encode([
			'id'      => '__ID__',
			'blocked' => 'true',
			'b_type'  => 'dataDB',
			'group'   => 'malware',
			'b_eval'  => 'exact',
			'feed'    => 'testfeed',
			'p_type'  => 'A',
		]));
		$result = pfb_dnsbl_query('mistyped-blocked-case.example', 'A', 0.8);
		$this->assertNull($result);
	}

	public function testMistypedAttributionFieldReplyIgnoredTimesOutToNull(): void
	{
		// 'b_type' as an int, not string -- must be ignored, never a fatal cast.
		$this->spawnResponder(json_encode([
			'id'      => '__ID__',
			'blocked' => true,
			'b_type'  => 5,
			'group'   => 'malware',
			'b_eval'  => 'exact',
			'feed'    => 'testfeed',
			'p_type'  => 'A',
		]));
		$result = pfb_dnsbl_query('mistyped-attribution-case.example', 'A', 0.8);
		$this->assertNull($result);
	}

	// --- request encode failure -> NULL, no request written -----------------

	public function testUnencodableQtypeReturnsNullNoRequestWritten(): void
	{
		// Invalid-UTF-8 bytes in $qtype make json_encode() of the whole record
		// fail -- even an unusable lock path must not be reached before that
		// rejection, and no broken request may be emitted.
		@unlink($GLOBALS['pfb']['errlog']);
		mkdir($this->lockPath());
		$result = pfb_dnsbl_query('encode-fail-case.example', "\xB1\x31");
		$this->assertNull($result);
		$this->assertFileDoesNotExist($this->channel());
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringNotContainsString('query channel lock open failed', $logs);
	}
}
