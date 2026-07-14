<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 Phase 4 (D4): pfb_log_event() attributes a webserver-hit (VIP block-page)
 * event via the live query channel (pfb_dnsbl_query()) instead of grepping the
 * retired .txt interchange files via pfb_dnsbl_parse('daemon', ...).
 *
 * Sandbox: a fresh $pfb carrying BOTH the OLD grep-path globals (grep/extdns/
 * unbound_py_data/unbound_py_zone/dnsbl_cache/sqlite_timeout, DnsblPrefetchTest's
 * shape) AND the query-channel globals (dnsbldir, DnsblQueryClientTest's shape) AND
 * the log-event globals (dnslog/dnsbl_resolver/dnsbl_info/errlog,
 * LogTimestampBaselineTest's shape). Each test seeds an NDJSON row under a
 * "GrepGroup"/"GrepFeed" pair the OLD grep would find, so a RED run (which still
 * calls pfb_dnsbl_parse) is deterministic; a background responder plays the query
 * channel's Python side and answers with a DISTINCT "LiveGroup"/"LiveFeed" pair, so
 * GREEN is only possible by asking the live matcher.
 *
 * Every method drives pfb_log_event() through its NON-duplicate branch (the
 * lastevent row is pre-seeded for a DIFFERENT domain/IP, so the entry never matches
 * and no undefined-array-key noise is produced -- mirrors
 * LogTimestampBaselineTest::seedLogEventSandbox(), inverted for the non-dup case).
 */
#[CoversFunction('pfb_log_event')]
final class DnsblLogEventQueryAttributionTest extends TestCase
{
	private string $tmp;
	private array $savedPfb = [];

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_logevent_qa_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);
		mkdir("{$this->tmp}/query", 0777, true);

		$dnsblInfoDb = "{$this->tmp}/dnsbl_info.sqlite3";
		$dnsblResolverDb = "{$this->tmp}/dnsbl_resolver.sqlite3";

		// Pre-seed lastevent for an UNRELATED entry, so every test's domain/src_ip
		// misses the dup comparison (non-dup branch) without ever reading an
		// undefined 'entry'/'details' array key off a genuinely-empty table.
		$db = new SQLite3($dnsblResolverDb);
		$db->exec('CREATE TABLE IF NOT EXISTS lastevent ( row INTEGER, groupname TEXT, entry TEXT, details TEXT )');
		$stmt = $db->prepare('INSERT INTO lastevent (row, groupname, entry, details) VALUES (0, :g, :e, :d)');
		$stmt->bindValue(':g', 'PriorGroup', SQLITE3_TEXT);
		$stmt->bindValue(':e', 'unrelated-entry-never-matches', SQLITE3_TEXT);
		$stmt->bindValue(':d', 'priordetails', SQLITE3_TEXT);
		$stmt->execute();
		$db->close();

		$GLOBALS['pfb'] = [
			// log-event sandbox (LogTimestampBaselineTest shape)
			'dnslog'         => "{$this->tmp}/dnsbl.log",
			'dnsbl_resolver' => $dnsblResolverDb,
			'dnsbl_info'     => $dnsblInfoDb,
			'errlog'         => "{$this->tmp}/error.log",
			'log'            => "{$this->tmp}/pfblockerng.log",
			'sqlite_timeout' => 2000,
			// grep-path sandbox (DnsblPrefetchTest shape) -- exercised by the RED run
			'grep'            => '/usr/bin/grep',
			'extdns'          => '203.0.113.53', // TEST-NET-3 (RFC 5737); drill is absent off-appliance anyway
			'unbound_py_data' => "{$this->tmp}/pfb_py_data.txt",
			'unbound_py_zone' => "{$this->tmp}/pfb_py_zone.txt",
			'dnsbl_cache'     => "{$this->tmp}/dnsblcache.sqlite3",
			// query-channel sandbox (DnsblQueryClientTest shape)
			'dnsbldir' => "{$this->tmp}/query",
			'supp'     => 'off',
		];
		touch($GLOBALS['pfb']['unbound_py_zone']);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
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

	/** Seed the OLD grep path's data file with one NDJSON row for $domain (schema v1). */
	private function seedGrepRow(string $domain, string $group = 'GrepGroup', string $feed = 'GrepFeed'): void
	{
		$row = json_encode(['kind' => 'domain', 'domain' => $domain, 'log' => 'DNSBL', 'feed' => $feed, 'group' => $group]);
		file_put_contents($GLOBALS['pfb']['unbound_py_data'], "{$row}\n");
	}

	/** Pre-seed a dnsbl-widget counter row (table 1) at $counter for $groupname. */
	private function seedCounterRow(string $groupname, int $counter = 0): void
	{
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$db->exec('CREATE TABLE IF NOT EXISTS dnsbl ( groupname TEXT, timestamp TEXT, entries INTEGER, counter INTEGER )');
		$stmt = $db->prepare('INSERT INTO dnsbl (groupname, timestamp, entries, counter) VALUES (:g, :t, :e, :c)');
		$stmt->bindValue(':g', $groupname, SQLITE3_TEXT);
		$stmt->bindValue(':t', '2026-01-01 00:00:00', SQLITE3_TEXT);
		$stmt->bindValue(':e', 0, SQLITE3_INTEGER);
		$stmt->bindValue(':c', $counter, SQLITE3_INTEGER);
		$stmt->execute();
		$db->close();
	}

	/** Read the counter column for $groupname from table 1 (0 if the row is absent). */
	private function readCounter(string $groupname): int
	{
		$db = new SQLite3($GLOBALS['pfb']['dnsbl_info']);
		$stmt = $db->prepare('SELECT counter FROM dnsbl WHERE groupname = :g');
		$stmt->bindValue(':g', $groupname, SQLITE3_TEXT);
		$result = $stmt->execute();
		$row = $result ? $result->fetchArray(SQLITE3_ASSOC) : false;
		$db->close();
		return $row ? (int) $row['counter'] : 0;
	}

	/**
	 * Spawn a background PHP process playing the query channel's Python side --
	 * mirrors DnsblQueryClientTest::spawnResponder(). Answers with $replyTemplateJson
	 * (its "__ID__" placeholder substituted for the request's real id).
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
			$reply = str_replace('__ID__', (string) $req['id'], $tpl);
			file_put_contents($dir . '/pfb_py_query.reply', $reply);
			PHP;

		$cmd = escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code)
			. ' ' . escapeshellarg("{$this->tmp}/query") . ' ' . escapeshellarg($replyTemplateJson)
			. ' > /dev/null 2>&1 &';
		exec($cmd);
	}

	/**
	 * Calls $work() with every raised PHP warning/notice captured (not printed),
	 * minus pfb_open_sqlite()'s @chown/@chgrp-to-'unbound' noise (the 'unbound' OS
	 * user is absent on a dev/CI box -- same harness-noise filter as
	 * LogTimestampBaselineTest/DnsblParseComputeMetacharTest).
	 *
	 * @return string[] unexpected warning messages (empty = none)
	 */
	private function callCapturingUnexpectedWarnings(callable $work): array
	{
		$caught = [];
		set_error_handler(function (int $errno, string $errstr) use (&$caught): bool {
			$caught[] = $errstr;
			return true;
		});
		try {
			$work();
		} finally {
			restore_error_handler();
		}

		return array_values(array_filter($caught, static function (string $msg): bool {
			// pfb_dnsbl_query() -> pfb_unbound_py_atomic_write_root()'s @chown($tmp,'root')
			// is a documented no-op for a non-root test runner (UnboundPyControlWriteTest).
			return !str_contains($msg, 'Unable to find uid for unbound')
				&& !str_contains($msg, 'Unable to find gid for unbound')
				&& !str_contains($msg, "chown(): Operation not permitted");
		}));
	}

	/** Split a written dnsbl.log line into its 0-based CSV fields (trailing "\n" dropped). */
	private function logFields(): array
	{
		$written = (string) file_get_contents($GLOBALS['pfb']['dnslog']);
		return explode(',', rtrim($written, "\n"));
	}

	// -------------------------------------------------------------------
	// blocked=true -> LiveGroup/LiveFeed attribution + LiveGroup counter bump
	// -------------------------------------------------------------------

	public function testBlockedVerdictAttributesLiveGroupAndBumpsLiveCounter(): void
	{
		$domain = 'uuid-qa-blocked-7f31.example.com';
		$this->seedGrepRow($domain);
		$this->seedCounterRow('LiveGroup', 0);
		$this->seedCounterRow('GrepGroup', 0);

		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => true, 'b_type' => 'DNSBL',
			'group' => 'LiveGroup', 'b_eval' => $domain, 'feed' => 'LiveFeed', 'p_type' => 'Python',
		]));

		$unexpected = $this->callCapturingUnexpectedWarnings(function () use ($domain) {
			pfb_log_event('DNSBL-HTTPS', $domain, '203.0.113.10', 'Mozilla/5.0');
		});
		$this->assertSame([], $unexpected, 'expected no unrelated PHP warning; got: ' . var_export($unexpected, true));

		$fields = $this->logFields();
		$this->assertSame('DNSBL', $fields[5], "expected mode field(5)='DNSBL', got: {$fields[5]}");
		$this->assertSame('LiveGroup', $fields[6], "expected group field(6)='LiveGroup' (query channel), got: {$fields[6]}");
		$this->assertSame($domain, $fields[7], "expected b_eval field(7)='{$domain}', got: {$fields[7]}");
		$this->assertSame('LiveFeed', $fields[8], "expected feed field(8)='LiveFeed' (query channel), got: {$fields[8]}");
		$this->assertStringNotContainsString('GrepGroup', implode(',', $fields), 'the grep-path group must never appear');

		$this->assertSame(1, $this->readCounter('LiveGroup'), 'expected the LiveGroup widget counter incremented');
		$this->assertSame(0, $this->readCounter('GrepGroup'), 'expected the GrepGroup widget counter untouched');
	}

	// -------------------------------------------------------------------
	// blocked=false -> "Unknown" attribution, no counter move
	// -------------------------------------------------------------------

	public function testCleanVerdictAttributesUnknownNoCounterMove(): void
	{
		$domain = 'uuid-qa-clean-2b48.example.com';
		$this->seedGrepRow($domain);
		$this->seedCounterRow('GrepGroup', 0);

		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => false, 'b_type' => '', 'group' => '', 'b_eval' => '', 'feed' => '', 'p_type' => '',
		]));

		pfb_log_event('DNSBL-HTTPS', $domain, '203.0.113.11', 'Mozilla/5.0');

		$fields = $this->logFields();
		$this->assertSame('Unknown', $fields[5], "expected mode(5)='Unknown', got: {$fields[5]}");
		$this->assertSame('Unknown', $fields[6], "expected group(6)='Unknown', got: {$fields[6]}");
		$this->assertSame('Unknown', $fields[7], "expected b_eval(7)='Unknown', got: {$fields[7]}");
		$this->assertSame('Unknown', $fields[8], "expected feed(8)='Unknown', got: {$fields[8]}");
		$this->assertStringNotContainsString('GrepGroup', implode(',', $fields), 'the grep-path group must never appear');
		$this->assertSame(0, $this->readCounter('GrepGroup'), 'a clean verdict must never bump any counter');
	}

	// -------------------------------------------------------------------
	// no responder -> NULL (timeout) -> "Unknown", no counter move, no fatal
	// -------------------------------------------------------------------

	public function testNoResponderTimesOutToUnknownNoWarning(): void
	{
		$domain = 'uuid-qa-timeout-9c17.example.com';
		$this->seedGrepRow($domain);
		$this->seedCounterRow('GrepGroup', 0);

		// No responder spawned -- pfb_dnsbl_query() times out at its 5.0s default.
		$unexpected = $this->callCapturingUnexpectedWarnings(function () use ($domain) {
			pfb_log_event('DNSBL-HTTPS', $domain, '203.0.113.12', 'Mozilla/5.0');
		});
		$this->assertSame([], $unexpected, 'a query-channel timeout must never raise a PHP warning/fatal; got: ' . var_export($unexpected, true));

		$fields = $this->logFields();
		$this->assertSame('Unknown', $fields[6], "expected group(6)='Unknown' on timeout, got: {$fields[6]}");
		$this->assertSame('Unknown', $fields[8], "expected feed(8)='Unknown' on timeout, got: {$fields[8]}");
		$this->assertStringNotContainsString('GrepGroup', implode(',', $fields), 'the grep-path group must never appear');
		$this->assertSame(0, $this->readCounter('GrepGroup'), 'a timeout must never bump any counter');
	}

	// -------------------------------------------------------------------
	// blocked=true, empty attribution strings -> per-field "Unknown", never ""
	// -------------------------------------------------------------------

	public function testBlockedEmptyAttributionFallsBackToUnknownPerField(): void
	{
		$domain = 'uuid-qa-emptyattr-4d62.example.com';
		$this->seedGrepRow($domain);

		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => true, 'b_type' => '', 'group' => '', 'b_eval' => '', 'feed' => '', 'p_type' => '',
		]));

		pfb_log_event('DNSBL-HTTPS', $domain, '203.0.113.13', 'Mozilla/5.0');

		$fields = $this->logFields();
		$this->assertSame('Unknown', $fields[5], "expected mode(5)='Unknown' (never empty), got: '{$fields[5]}'");
		$this->assertSame('Unknown', $fields[6], "expected group(6)='Unknown' (never empty), got: '{$fields[6]}'");
		$this->assertSame('Unknown', $fields[7], "expected b_eval(7)='Unknown' (never empty), got: '{$fields[7]}'");
		$this->assertSame('Unknown', $fields[8], "expected feed(8)='Unknown' (never empty), got: '{$fields[8]}'");
		$this->assertStringNotContainsString('GrepGroup', implode(',', $fields), 'the grep-path group must never appear');
	}

	// -------------------------------------------------------------------
	// hostile group -> PFB_FILTER_HTML-encoded in the log line and the counter bind
	// -------------------------------------------------------------------

	public function testHostileGroupIsHtmlEncodedNeverRaw(): void
	{
		$domain = 'uuid-qa-hostile-8e93.example.com';
		$this->seedGrepRow($domain);

		$hostileGroup = '"<Bad>&Grp';
		// pfb_log_event's counter block re-filters $pfb_group a SECOND time (its own
		// PFB_FILTER_HTML call, unchanged by this phase) -- the bound groupname is the
		// DOUBLE-encoded form, so the pre-seeded row must key on that exact value.
		$doubleEncoded = htmlspecialchars(htmlspecialchars($hostileGroup));
		$this->seedCounterRow($doubleEncoded, 0);

		$this->spawnResponder(json_encode([
			'id' => '__ID__', 'blocked' => true, 'b_type' => 'DNSBL',
			'group' => $hostileGroup, 'b_eval' => $domain, 'feed' => 'CleanFeed', 'p_type' => 'Python',
		]));

		pfb_log_event('DNSBL-HTTPS', $domain, '203.0.113.14', 'Mozilla/5.0');

		$fields = $this->logFields();
		// (before) the raw responder value carries live HTML metacharacters.
		$this->assertStringContainsString('<', $hostileGroup);
		// The log line carries the SINGLE-encoded form (composed before the counter
		// block's second pass) -- never the raw '<'/'"'.
		$this->assertSame(htmlspecialchars($hostileGroup), $fields[6], "expected the HTML-encoded group in field(6), got: '{$fields[6]}'");
		$this->assertStringNotContainsString('<Bad>', implode(',', $fields), 'no raw metacharacter may reach the log line');
		$this->assertStringNotContainsString('GrepGroup', implode(',', $fields), 'the grep-path group must never appear');

		$this->assertSame(1, $this->readCounter($doubleEncoded), 'expected the counter UPDATE to bind the (double-)filtered group as a TEXT param');
	}
}
