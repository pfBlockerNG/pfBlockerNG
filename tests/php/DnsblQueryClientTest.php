<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 query-channel client: pfb_dnsbl_query().
 *
 * Scenario: the client writes a request onto the read-only query channel
 * (here redirected to a temp dnsbldir) and bounded-waits for the id-matching
 * reply, returning the parsed six-key verdict or NULL. Production-dormant:
 * no caller exists yet (Phase 4 wires the first one). These tests pin:
 *   - PFBL-01 domain validation at the choke point (invalid domain -> NULL,
 *     no request written, no wait);
 *   - a request-publish failure (missing staging dir) -> NULL, no wait;
 *   - the request's JSON schema (id/domain/qtype) and 0660 permission,
 *     observed by an independent background reader that plays the Python
 *     side of the channel;
 *   - a fresh, unique id per call;
 *   - strict reply validation (7 typed keys) -- every hostile shape (missing
 *     field, mistyped field, truncated/non-JSON/oversized bytes, foreign id)
 *     is ignored, never a fatal, and the call times out to NULL;
 *   - blocked=false with empty attribution is a VALID verdict, not NULL;
 *   - the bounded wait obeys both the deadline and the hard poll cap;
 *   - cleanup: reply+request unlinked on a matched verdict, request unlinked
 *     on timeout, no ".pfbctl_" staging residue.
 *
 * Test mode (CLAUDE.md Test coverage #1, second exception): brand-new,
 * production-dormant code with no pre-existing behaviour to regress -- no
 * red run against the void. Every assertion below still fails on a real
 * regression (round-trip shape, timeout bounds, permission bits).
 *
 * Round-trip technique: a background PHP process (`php -r`, backgrounded)
 * plays the Python side -- it polls the sandbox's request file, decodes it,
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

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_query_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $this->tmp,
			'supp'     => 'off',	// pfb_filter()'s private/reserved IP exclusion off for the test
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		$this->rrmdir($this->tmp);
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

	/**
	 * Spawn a background PHP process that plays the Python side of the
	 * channel: it polls for the request (up to ~3s, 50ms steps), records
	 * the decoded request JSON + the request file's permission bits into
	 * observed.json, substitutes the request's real id for the literal
	 * "__ID__" placeholder in $replyTemplateJson, and writes the reply.
	 */
	private function spawnResponder(string $replyTemplateJson): void
	{
		$code = <<<'PHP'
			$dir = $argv[1];
			$tpl = $argv[2];
			$reqPath = $dir . '/pfb_py_query';
			$deadline = microtime(true) + 3.0;
			$req = null;
			while (microtime(true) < $deadline) {
				if (file_exists($reqPath)) {
					$raw = @file_get_contents($reqPath);
					if ($raw !== false && trim($raw) !== '') {
						$dec = json_decode($raw, true);
						if (is_array($dec) && isset($dec['id'])) {
							$req = $dec;
							break;
						}
					}
				}
				usleep(50000);
			}
			if ($req === null) {
				exit(1);
			}
			$perm = substr(sprintf('%o', fileperms($reqPath)), -4);
			file_put_contents($dir . '/observed.json', json_encode(['request' => $req, 'perm' => $perm]));
			$reply = str_replace('__ID__', (string) $req['id'], $tpl);
			file_put_contents($dir . '/pfb_py_query.reply', $reply);
			PHP;

		$cmd = escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code)
			. ' ' . escapeshellarg($this->tmp) . ' ' . escapeshellarg($replyTemplateJson)
			. ' > /dev/null 2>&1 &';
		exec($cmd);
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
		$this->assertFileDoesNotExist($this->channel());
		$this->assertNull(pfb_dnsbl_query('nodotsatall'));
		$this->assertFileDoesNotExist($this->channel());
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
		// Point dnsbldir at a path whose parent does not exist -- tempnam() fails
		// inside pfb_unbound_py_atomic_write_root(), so the write is rejected
		// before any wait begins (fail-fast, no pointless poll).
		$GLOBALS['pfb']['dnsbldir'] = "{$this->tmp}/nope/deep";
		$start = microtime(true);
		$result = pfb_dnsbl_query('write-fail-case.example', 'A', 5.0);
		$elapsed = microtime(true) - $start;

		$this->assertNull($result);
		$this->assertLessThan(1.0, $elapsed, 'a publish failure must return immediately, never wait');
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
		// fail -- the client must reject before any write, never emit a broken
		// request or crash.
		$result = pfb_dnsbl_query('encode-fail-case.example', "\xB1\x31");
		$this->assertNull($result);
		$this->assertFileDoesNotExist($this->channel());
	}
}
