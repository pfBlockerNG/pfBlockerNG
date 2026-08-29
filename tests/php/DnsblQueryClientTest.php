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
 *   - timeout paths emit the expected verdict/lock signals and clean up;
 *     an injected stalled clock proves the independent hard poll cap runs;
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
	/** Salvage only: expiry means the run is stuck or the box is broken, never that behaviour is wrong. */
	private const SALVAGE_CAP_S = 30.0;
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

		foreach (['pcntl_fork', 'pcntl_waitpid', 'pcntl_wifexited', 'pcntl_wexitstatus', 'pcntl_wifstopped', 'posix_kill', 'stream_socket_pair'] as $function) {
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

	/** Reap a tracked child under a salvage cap; kill it rather than orphaning it. */
	private function reapChild(int $pid, float $timeout_s = self::SALVAGE_CAP_S): void
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
		$this->fail("STUCK/ENVIRONMENT: child {$pid} did not exit within the {$timeout_s}s salvage cap -- the run is stuck or the environment is broken, not a behavioural failure");
	}

	private function childFailureMessage(int $pid): string
	{
		$error = @file_get_contents("{$this->tmp}/child-error-{$pid}");
		return $error !== false && $error !== '' ? "child {$pid} failed: {$error}" : "child {$pid} failed";
	}

	/** Prove SIGSTOP reached a live child rather than an already-exited zombie. */
	private function waitForStoppedChild(int $pid, float $timeout_s = self::SALVAGE_CAP_S): void
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
		$this->fail("STUCK/ENVIRONMENT: child {$pid} did not stop within the {$timeout_s}s salvage cap -- the run is stuck or the environment is broken, not a behavioural failure");
	}

	/** Read a non-empty file under a bounded test-side deadline. */
	private function readMarker(string $name, float $timeout_s = self::SALVAGE_CAP_S): string
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
		$this->fail("STUCK/ENVIRONMENT: marker {$name} did not appear within the {$timeout_s}s salvage cap -- the run is stuck or the environment is broken, not a behavioural failure");
	}

	/** Wait for a request with the requested domain and return its decoded record. */
	private function waitForRequest(string $domain, float $timeout_s = self::SALVAGE_CAP_S): array
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
		throw new RuntimeException("STUCK/ENVIRONMENT: no request for {$domain} arrived within the {$timeout_s}s salvage cap -- the run is stuck or the environment is broken, not a behavioural failure");
	}

	private function verdictReply(string $id, string $group): string
	{
		return (string) json_encode([
			'id' => $id, 'blocked' => true, 'b_type' => 'dataDB', 'group' => $group,
			'b_eval' => 'exact', 'feed' => "{$group}-feed", 'p_type' => 'A',
		]);
	}

	/** Open a bidirectional pipe for parent/child event signalling. */
	private function signalPair(): array
	{
		$pair = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
		if ($pair === false) {
			$this->markTestSkipped('stream_socket_pair() failed -- cannot signal across the fork.');
		}
		return $pair;
	}

	/** Block until a "\n"-terminated payload is readable on $stream; salvage-capped. */
	private function awaitSignal($stream, string $what, ?int $pid = null): string
	{
		$buffer = '';
		$deadline = microtime(true) + self::SALVAGE_CAP_S;
		while (true) {
			$newlineAt = strpos($buffer, "\n");
			if ($newlineAt !== false) {
				return substr($buffer, 0, $newlineAt);
			}
			$remaining = $deadline - microtime(true);
			if ($remaining <= 0.0) {
				$this->fail("STUCK/ENVIRONMENT: no {$what} arrived on the pipe within the " . self::SALVAGE_CAP_S . "s salvage cap -- the run is stuck or the environment is broken, not a behavioural failure");
			}
			$read = [$stream]; $write = []; $except = [];
			$tv_sec = (int) floor($remaining);
			$tv_usec = (int) (($remaining - $tv_sec) * 1000000);
			$ready = @stream_select($read, $write, $except, $tv_sec, $tv_usec);
			if ($ready === false || $ready === 0) {
				continue; // re-check the deadline at the loop top
			}
			$chunk = fread($stream, 8192);
			if ($chunk === false || $chunk === '') {
				$detail = $pid !== null ? $this->childFailureMessage($pid) : 'no child pid was given to inspect';
				$this->fail("{$what} never arrived: the child closed the pipe without writing -- {$detail}");
			}
			$buffer .= $chunk;
		}
	}

	/** Fork a query child; its verdict comes back over a pipe the parent blocks on. */
	private function forkQuery(string $domain, float $timeout_s, string $marker, $inheritedLock = null): array
	{
		[$parentEnd, $childEnd] = $this->signalPair();
		$pid = $this->forkChild(function () use ($domain, $timeout_s, $marker, $parentEnd, $childEnd, $inheritedLock): void {
			fclose($parentEnd);
			if (is_resource($inheritedLock)) {
				fclose($inheritedLock);
			}
			file_put_contents("{$this->tmp}/{$marker}.started", '1');
			$result = pfb_dnsbl_query($domain, 'A', $timeout_s);
			fwrite($childEnd, json_encode($result) . "\n");
			fclose($childEnd);
		});
		fclose($childEnd);
		return ['pid' => $pid, 'signal' => $parentEnd, 'label' => $marker];
	}

	/** Block on a forkQuery() handle's verdict pipe. */
	private function awaitQueryResult(array $child): ?array
	{
		try {
			$raw = $this->awaitSignal($child['signal'], "{$child['label']} query result", $child['pid']);
		} finally {
			fclose($child['signal']); // also on the salvage-cap and EOF failure paths
		}
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
			$result = pfb_dnsbl_query($domain, 'A', $timeout_s);
			$probe = fopen($this->lockPath(), 'c');
			if ($probe === false) {
				throw new RuntimeException('failed to open post-query contention probe lock');
			}
			$wouldBlock = 0;
			$acquired = flock($probe, LOCK_EX | LOCK_NB, $wouldBlock);
			$parentLockHeld = !$acquired && $wouldBlock === 1;
			if ($acquired) {
				flock($probe, LOCK_UN);
			}
			fclose($probe);
			$this->atomicWriteJson("{$this->tmp}/{$marker}", [
				'result'                       => $result,
				'parent_lock_held_after_return' => $parentLockHeld,
			]);
		});
		$this->readMarker($ready);
		$this->atomicWrite("{$this->tmp}/{$go}", '1');

		$raw = $this->readMarker($marker);
		$requestPublished = file_exists($this->channel());

		flock($lock, LOCK_UN);
		fclose($lock);
		$this->reapChild($child);
		$record = json_decode((string) $raw, true);
		$this->assertIsArray($record);

		return [$record, $requestPublished];
	}

	/**
	 * Spawn a background PHP process that plays the Python side of the
	 * channel: it polls for the request under the salvage cap (20ms steps), records
	 * the decoded request JSON + the request file's permission bits into
	 * observed.json, substitutes the request's real id for the literal
	 * "__ID__" placeholder in $replyTemplateJson, and writes the reply.
	 */
	private function spawnResponder(string $replyTemplateJson): void
	{
		$this->forkChild(function () use ($replyTemplateJson): void {
			$deadline = microtime(true) + self::SALVAGE_CAP_S;
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
				throw new RuntimeException('STUCK/ENVIRONMENT: the responder never observed a request within the ' . self::SALVAGE_CAP_S . 's salvage cap -- the run is stuck or the environment is broken, not a behavioural failure');
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
	private function readObserved(float $timeout_s = self::SALVAGE_CAP_S): array
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
		$this->fail("STUCK/ENVIRONMENT: responder never observed a request within the {$timeout_s}s salvage cap -- the run is stuck or the environment is broken, not a behavioural failure");
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
		$result = pfb_dnsbl_query('write-fail-case.example', 'A', 5.0);

		$this->assertNull($result);
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('failed to publish the request', $logs);
		$this->assertStringNotContainsString('timed out waiting for a verdict', $logs);
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

		$result = pfb_dnsbl_query('lock-open-failure.example', 'A', 5.0);

		$this->assertNull($result);
		$this->assertFileDoesNotExist($this->channel());
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('ADR-65', $logs);
		$this->assertStringContainsString('query channel lock open failed', $logs);
		$this->assertStringNotContainsString('timed out waiting for a verdict', $logs);
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
		[$record, $requestPublished] = $this->queryUnderContention(
			'zero-lock-timeout.example',
			0.0
		);

		$this->assertNull($record['result']);
		$this->assertTrue($record['parent_lock_held_after_return'], 'zero-timeout query must return while the parent still owns the channel lock');
		$this->assertFalse($requestPublished, 'lock timeout must not publish a query request');
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('query channel lock timed out', $logs);
	}

	public function testLockWaitHardPollCapStopsEvenWhenClockStalls(): void
	{
		$lock = fopen($this->lockPath(), 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		$reads = 0;
		$stalledClock = static function () use (&$reads): float {
			$reads++;
			return 100.0;
		};
		$started = microtime(TRUE);
		try {
			$this->assertNull(pfb_dnsbl_query('stalled-clock.example', 'A', 0.01, $stalledClock));
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
		}
		$this->assertGreaterThan(1, $reads, 'the shipped wait must consult the injected clock');
		$this->assertLessThan(0.5, microtime(TRUE) - $started, 'the independent poll cap must stop a stalled clock');
	}

	public function testContendedLockWithShortTimeoutReturnsWithoutPublishing(): void
	{
		[$record, $requestPublished] = $this->queryUnderContention(
			'short-lock-timeout.example',
			0.1
		);

		$this->assertNull($record['result']);
		$this->assertTrue($record['parent_lock_held_after_return'], 'short-timeout query must return while the parent still owns the channel lock');
		$this->assertFalse($requestPublished, 'lock timeout must not publish a query request');
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('query channel lock timed out', $logs);
	}

	public function testResumedLockWaiterCannotPublishAfterDeadline(): void
	{
		if (!defined('SIGSTOP') || !defined('SIGCONT') || !defined('WUNTRACED')) {
			$this->markTestSkipped('SIGSTOP/SIGCONT/WUNTRACED are unavailable -- cannot suspend the lock waiter.');
		}

		$lock = fopen($this->lockPath(), 'c');
		$this->assertIsResource($lock);
		$this->assertTrue(flock($lock, LOCK_EX));
		$child = $this->forkQuery('late-lock.example', 0.5, 'late-lock', $lock);

		$this->readMarker('late-lock.started');
		usleep(40000);
		$this->assertTrue(posix_kill($child['pid'], (int) constant('SIGSTOP')));
		$this->waitForStoppedChild($child['pid']);
		usleep(600000);
		flock($lock, LOCK_UN);
		fclose($lock);
		$this->assertTrue(posix_kill($child['pid'], (int) constant('SIGCONT')));

		$this->assertNull($this->awaitQueryResult($child));
		$this->reapChild($child['pid']);
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
		$this->assertTrue(posix_kill($child['pid'], (int) constant('SIGSTOP')));
		usleep(600000);
		$late_reply = $this->verdictReply($request['id'], 'late-group');
		$this->atomicWrite($this->replyPath(), $late_reply);
		$this->assertFileExists($this->replyPath());
		$this->assertTrue(posix_kill($child['pid'], (int) constant('SIGCONT')));

		$this->assertNull($this->awaitQueryResult($child));
		$this->reapChild($child['pid']);
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

			$deadline = microtime(true) + self::SALVAGE_CAP_S;
			while (file_exists($this->replyPath()) && microtime(true) < $deadline) {
				usleep(20000);
			}
			if (file_exists($this->replyPath())) {
				throw new RuntimeException('salvage cap expired / stuck or environment: waiting for first caller to consume its reply; reply file still exists');
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

		$resultA = $this->awaitQueryResult($callerA);
		$resultB = $this->awaitQueryResult($callerB);
		$this->assertSame('group-a', $resultA['group'] ?? null);
		$this->assertSame('group-b', $resultB['group'] ?? null);
		$this->reapChild($callerA['pid']);
		$this->reapChild($callerB['pid']);
		$this->reapChild($server);
		$this->assertFileDoesNotExist($this->channel());
		$this->assertFileDoesNotExist($this->replyPath());
	}

	public function testTimedOutCallerCannotDeleteNextCallersRequest(): void
	{
		// Scenario: caller A's request occupies the channel slot only for A's own
		// timeout window, then pfb_dnsbl_query() unlinks it. Without the channel
		// lock, caller B's live request can land in that window and A's cleanup
		// destroys it; with the lock B cannot publish until A's timeout path has
		// released it, so B's request survives untouched. This process plays the
		// responder role itself -- it is already warm and scheduled, unlike a
		// cold fork racing to catch A's transient window.
		$callerA = $this->forkQuery('timeout-a.example', 1.5, 'timeout-caller-a');
		$this->waitForRequest('timeout-a.example');

		// B's timeout is generous on purpose: on the passing path it returns the
		// instant its reply lands, so a large production timeout costs nothing here.
		// It must stay below SALVAGE_CAP_S, or a regression would expire the cap
		// below and be reported as STUCK/ENVIRONMENT instead of behaviourally.
		$callerB = $this->forkQuery('timeout-b.example', 6.0, 'timeout-caller-b');

		// Event: A's call returned, so its timeout cleanup has already run.
		$this->assertNull($this->awaitQueryResult($callerA));

		// Wait for B's request to land on the cleaned slot, or for B to give up
		// first, whichever happens first; stream_select()'s own timeout doubles
		// as the poll cadence, no separate usleep().
		$requestB = null;
		$bGaveUp  = false;
		$deadline = microtime(true) + self::SALVAGE_CAP_S;
		while (microtime(true) < $deadline) {
			$raw    = @file_get_contents($this->channel());
			$record = $raw === false ? null : json_decode($raw, true);
			if (is_array($record) && isset($record['id']) && ($record['domain'] ?? null) === 'timeout-b.example') {
				$requestB = $record;
				break;
			}
			$read = [$callerB['signal']]; $write = []; $except = [];
			if (@stream_select($read, $write, $except, 0, 20000) === 1) {
				$bGaveUp = true;
				break;
			}
		}

		// Behavioural verdict first: B giving up means A's cleanup raced B's publish.
		// Read B's own verdict into the message rather than attributing a cause blind.
		$bVerdict = $bGaveUp ? var_export($this->awaitQueryResult($callerB), true) : '';
		$this->assertFalse($bGaveUp, "caller B returned without ever reaching the channel: caller A's timeout cleanup removed caller B's live request -- caller B returned {$bVerdict}");
		$this->assertNotNull($requestB, 'STUCK/ENVIRONMENT: neither caller B\'s request nor caller B\'s verdict was observed within the ' . self::SALVAGE_CAP_S . 's salvage cap -- the run is stuck or the environment is broken, not a behavioural failure');

		$this->atomicWrite($this->replyPath(), $this->verdictReply($requestB['id'], 'group-b'));
		$resultB = $this->awaitQueryResult($callerB);
		$this->assertSame('group-b', $resultB['group'] ?? null, 'caller B must receive its own verdict');

		$this->reapChild($callerA['pid']);
		$this->reapChild($callerB['pid']);
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

	// --- bounded wait: timeout events and cleanup ----------------------------

	public function testNoReplyTimesOutToNullAndCleansUp(): void
	{
		$result = pfb_dnsbl_query('no-reply-case.example', 'A', 0.6);

		$this->assertNull($result);
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('timed out waiting for a verdict', $logs);
		clearstatcache();
		$this->assertFileDoesNotExist($this->channel(), 'request file must be cleaned up on timeout');
	}

	public function testZeroTimeoutReturnsNullAndCleansUp(): void
	{
		// No reply ever appears; timeout_s <= 0 still exercises the zero-timeout branch.
		$result = pfb_dnsbl_query('zero-timeout-case.example', 'A', 0.0);

		$this->assertNull($result);
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('timed out waiting for a verdict', $logs);
		clearstatcache();
		$this->assertFileDoesNotExist($this->channel(), 'request file must be cleaned up on timeout');
	}

	public function testShortReplyTimeoutReturnsNullAndCleansUp(): void
	{
		// Start expiry only after publication, so scheduler latency cannot select the lock branch.
		$now = fn (): float => file_exists($this->channel()) ? 1.0 : 0.0;
		$result = pfb_dnsbl_query('short-reply-timeout.example', 'A', 0.001, $now);

		$this->assertNull($result);
		$logs = (string) @file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertStringContainsString('timed out waiting for a verdict', $logs);
		clearstatcache();
		$this->assertFileDoesNotExist($this->channel(), 'request file must be cleaned up on timeout');
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
