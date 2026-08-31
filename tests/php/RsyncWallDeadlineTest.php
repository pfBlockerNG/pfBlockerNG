<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #2876 — the RSYNC feed transport has no whole-transfer wall deadline.
 *
 * rsync's own --timeout=5 is a maximum I/O timeout: it fires only when NO data
 * moves for that interval, so a peer that trickles a byte per interval resets
 * it forever while pfb_download_fetch()'s exec() waits unboundedly. The byte
 * ceiling (#2667) bounds disk, not elapsed time.
 *
 * The fix routes the spawn through the package's established bounded-wait seam:
 * timeout(1) in its default (reaper) mode so the whole transient transfer tree
 * (rsync plus any remote-shell descendant) dies on expiry, carrying the SAME
 * per-feed wall budget the cURL path already applies to the same download
 * (CURLOPT_TIMEOUT, PfbDownloadRequest::$timeout; every caller passes 300) and
 * the package kill grace before the SIGKILL. $pfb['timeout'] and
 * $pfb['rsync_bin'] are the off-appliance injection points, mirroring
 * pfb_reentry_cmd()'s $pfb['timeout'] / $pfb['php'].
 *
 * Every behavioural row drives the REAL pfb_download() rsync branch against an
 * rsync double (a sh script injected through $pfb['rsync_bin']). The double
 * records its own PID through $PFB_RSYNC_PIDFILE, and each row asserts that
 * marker BEFORE asserting what the deadline did — so a site that ignores the
 * injected binary (e.g. the pre-fix hardcoded /usr/local/bin/rsync path, which
 * does not exist on this host) fails loudly at "the site never spawned the
 * double" instead of passing on an unrelated fast-fail. Every double scenario
 * self-terminates within ~12 s, so a missing deadline reads as a completed
 * transfer in the assertions (a behavioural red), never as a hung runner.
 */
#[CoversFunction('pfb_download')]
#[CoversFunction('pfb_rsync_transfer_cmd')]
final class RsyncWallDeadlineTest extends TestCase
{
	/** Per-feed wall budget under test — the timeout the cURL path already shares. */
	private const FEED_TIMEOUT = 2;

	/** Silent-peer row: the wall budget must sit ABOVE rsync's own 5 s I/O timeout. */
	private const SILENT_PEER_TIMEOUT = 12;

	/** Generous salvage cap whose expiry means "stuck/environment", never behaviour. */
	private const SALVAGE_CAP_SECONDS = 90.0;

	/** Body the near-budget double lands (plain text the ingest gates accept). */
	private const QUICK_BODY_BYTES = 2048;

	private string $workdir = '';

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	/** @var array<string,mixed> saved fixture globals (absent key = was unset) */
	private array $savedGlobals = [];

	/** @var resource|null the silent-peer stall server (closed in tearDown) */
	private $stallServer = NULL;

	protected function setUp(): void
	{
		$timeout_bin = NULL;
		foreach (['/usr/bin/timeout', '/opt/homebrew/bin/timeout', '/usr/local/bin/gtimeout', '/usr/local/bin/timeout'] as $bin) {
			if (is_executable($bin)) {
				$timeout_bin = $bin;
				break;
			}
		}
		if ($timeout_bin === NULL) {
			$this->markTestSkipped('no timeout(1) binary available on this host');
		}

		$workdir = tempnam(sys_get_temp_dir(), 'pfbrwl');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['config'] as $g) {
			if (array_key_exists($g, $GLOBALS)) {
				$this->savedGlobals[$g] = $GLOBALS[$g];
			}
		}
		$GLOBALS['config'] = [];
		// Documented opt-out for the resolve+pin guard (General settings
		// 'pfb_feed_internal_filter'); a local/double rsync source has no host
		// for the guard to vet (same opt-out RsyncSizeRefusalTest uses).
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter', 'off');

		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active', 'dbdir', 'rsync_max_bytes', 'mime_types', 'timeout', 'rsync_bin'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']   = 'now';
		// PFB_FILTER_URL's local-path arm accepts sources under $pfb['dbdir'].
		$GLOBALS['pfb']['dbdir']  = $workdir;
		// The MIME gate on the ingested body reads $pfb['mime_types']; restore the
		// shipped allow-list (bootstrap snapshot) so this fixture is order-independent.
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? [];

		// The bounded-wait injection points under test (see pfb_rsync_transfer_cmd()).
		$GLOBALS['pfb']['timeout']   = $timeout_bin;
		$GLOBALS['pfb']['rsync_bin'] = "{$workdir}/rsync-double.sh";

		// The double announces itself and records PIDs here; exec()'s child
		// inherits the environment, so this is the site-spawn discriminator.
		putenv("PFB_RSYNC_PIDFILE={$workdir}/double.pids");

		$this->writeDouble("{$workdir}/rsync-double.sh");
	}

	protected function tearDown(): void
	{
		putenv('PFB_RSYNC_PIDFILE');
		if ($this->stallServer !== NULL) {
			fclose($this->stallServer);
			$this->stallServer = NULL;
		}
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->savedGlobals as $g => $prev) {
			$GLOBALS[$g] = $prev;
		}
		$this->savedGlobals = [];
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
		$this->workdir = '';
	}

	/**
	 * Write the rsync double. It receives the site's spawn shape:
	 * --timeout=5 SRC DST. The scenario comes from the source basename.
	 */
	private function writeDouble(string $path): void
	{
		$script = <<<'SH'
#!/bin/sh
# Test double for the rsync feed transfer (issue #2876).
# argv: --timeout=5 SRC DST. Scenario = basename of SRC.
# $PFB_RSYNC_PIDFILE records this process ($$) and, for the reap scenario,
# a descendant ($!) the deadline must also reap.

src="$2"
dst="$3"
scenario="$(basename "$src")"
printf '%s\n' "$$" > "${PFB_RSYNC_PIDFILE}" 2>/dev/null
printf 'started\n' > "${PFB_RSYNC_PIDFILE}.started" 2>/dev/null

i=0
case "$scenario" in
trickle)
	# The hostile peer: land a partial write, then trickle one byte per
	# 0.2 s interval forever (self-capped at ~12 s).
	printf 'partial' > "$dst" 2>/dev/null || exit 23
	while [ "$i" -lt 60 ]; do
		printf 'x' >> "$dst" 2>/dev/null
		sleep 0.2
		i=$((i + 1))
	done
	;;
reap)
	# Start a descendant the deadline must also reap, then idle forever.
	sleep 30 &
	printf '%s\n' "$!" >> "${PFB_RSYNC_PIDFILE}" 2>/dev/null
	while [ "$i" -lt 60 ]; do
		sleep 0.2
		i=$((i + 1))
	done
	;;
quick)
	# A compliant transfer: completes just under the deadline with a
	# plain-text body the ingest gates accept.
	sleep 1
	dd if=/dev/zero bs=1024 count=2 2>/dev/null | tr '\0' 'A' > "$dst" 2>/dev/null || exit 23
	;;
*)
	exit 23
	;;
esac
SH;
		$this->assertNotFalse(file_put_contents($path, $script), 'the rsync double must be writable');
		$this->assertTrue(chmod($path, 0755));
	}

	private function logText(): string
	{
		return (string) @file_get_contents((string) $GLOBALS['pfb']['log']);
	}

	private function fetch(string $header, string $scenario, int $timeout = self::FEED_TIMEOUT,
	    ?string $listUrl = NULL): PfbDownloadResult
	{
		// The source file's BASENAME selects the double's scenario, so it must
		// be exactly the scenario name.
		$listUrl ??= "{$this->workdir}/{$scenario}";
		if (!str_starts_with($listUrl, 'rsync://')) {
			touch($listUrl);
		}
		return pfb_download(new PfbDownloadRequest(
			listUrl: $listUrl,
			downloadPath: "{$this->workdir}/feed",
			flex: FALSE,
			header: $header,
			format: 'rsync',
			logType: 1,
			versionType: '',
			timeout: $timeout,
			type: '',
			username: '',
			password: '',
			sourceInterface: FALSE,
			extraHeaders: array(),
		));
	}

	/**
	 * The double must announce itself: the discriminator every behavioural row
	 * leans on, pinned in its own test so a red never hides behind a later
	 * assertion. A site that ignores the injected binary fails here.
	 */
	public function testTheSiteSpawnsTheInjectedRsyncDouble(): void
	{
		$result = $this->fetch('RsyncSpawn', 'quick');

		$this->assertFileExists("{$this->workdir}/double.pids.started",
			"the site must spawn the injected rsync double through the \$pfb['rsync_bin'] seam "
			. '(it saw neither the double nor its marker; the transfer is not running the bounded spawn)');
		$this->assertTrue($result->success,
			'the compliant double must complete normally once the site actually spawns it');
	}

	/**
	 * Scenario: a peer that keeps making slow progress past the wall budget.
	 *
	 * Given a transfer double that writes a partial body and then trickles one
	 *   byte per 0.2 s interval forever (rsync's own I/O timeout never fires —
	 *   data keeps moving), a per-feed wall budget of 2 s, and a
	 *   last-known-good publication already on disk
	 * When pfb_download() fetches with format 'rsync'
	 * Then the fetch fails at the deadline (never succeeding once the double
	 *   self-terminates), the partial body is gone, the prior good publication
	 *   is untouched, and the log carries the distinguishable TIMED OUT
	 *   failure — not the size refusal.
	 */
	public function testTricklingRsyncTransferIsKilledAtTheFeedDeadline(): void
	{
		$prior_good = "{$this->workdir}/feed.orig";
		file_put_contents($prior_good, 'prior-good');

		$started = microtime(TRUE);
		$result  = $this->fetch('RsyncTrickle', 'trickle');
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CAP_SECONDS, $elapsed,
			"stuck/environment: the fetch returned after {$elapsed}s, above the salvage cap — "
			. 'the deadline must end the transfer, not the harness');
		$this->assertFileExists("{$this->workdir}/double.pids.started",
			"the site must spawn the injected rsync double through the \$pfb['rsync_bin'] seam "
			. '(no marker: the site is not running the bounded spawn at all)');
		$this->assertFalse($result->success,
			'a peer that trickles progress past the whole-transfer deadline must not deliver '
			. 'a successful fetch');
		$this->assertFileDoesNotExist("{$this->workdir}/feed.raw",
			'a transfer killed at the deadline must not leave its partial body on disk');
		$this->assertSame('prior-good', (string) @file_get_contents($prior_good),
			'the deadline must leave the last-known-good publication untouched');
		$this->assertStringContainsString('TIMED OUT', $this->logText(),
			'the deadline expiry must be logged distinguishably from other rsync failures; log: '
			. $this->logText());
		$this->assertStringNotContainsString('reason=rsync_too_large', $this->logText(),
			'the deadline refusal must not masquerade as the size refusal');
	}

	/**
	 * Scenario: a transfer that starts descendants.
	 *
	 * Given a transfer double that spawns a sleep descendant and idles forever
	 * When the deadline expires
	 * Then both the double and its descendant are gone — the default (reaper)
	 *   mode kills the whole transient tree; --foreground would orphan the
	 *   descendant exactly like the docs' transform-pipeline row warns (whose
	 *   inherited stdio could even hold exec()'s capture pipe open).
	 */
	public function testDeadlineExpiryReapsTheWholeRsyncTree(): void
	{
		$result = $this->fetch('RsyncReap', 'reap');

		$this->assertFileExists("{$this->workdir}/double.pids.started",
			"the site must spawn the injected rsync double through the \$pfb['rsync_bin'] seam");
		$pids = array_values(array_filter(array_map('trim',
			explode("\n", (string) @file_get_contents("{$this->workdir}/double.pids"))), 'strlen'));
		$this->assertCount(2, $pids,
			'the double must record its own PID and its descendant for the reaping check: '
			. var_export($pids, TRUE));

		$deadline = microtime(TRUE) + 15.0;
		$alive    = TRUE;
		while ($alive && microtime(TRUE) < $deadline) {
			$alive = FALSE;
			foreach ($pids as $pid) {
				if (@posix_kill((int) $pid, 0)) {
					$alive = TRUE;
					break;
				}
			}
			if ($alive) {
				usleep(200000);
			}
		}

		foreach ($pids as $idx => $pid) {
			$this->assertFalse(@posix_kill((int) $pid, 0),
				'the deadline must reap the whole transient transfer tree: '
				. ($idx === 0 ? 'the transfer double' : 'its descendant') . " (pid {$pid}) is still alive");
		}
		$this->assertFalse($result->success, 'the reaped transfer must read as a failed fetch');
	}

	/**
	 * Scenario: a transfer that completes just below the wall budget.
	 *
	 * Given a transfer double that finishes in 1 s under a 2 s budget
	 * When pfb_download() fetches with format 'rsync'
	 * Then the transfer publishes exactly as today — the deadline must never
	 *   kill a compliant transfer.
	 */
	public function testRsyncTransferCompletingJustBelowTheDeadlineStillSucceeds(): void
	{
		$result = $this->fetch('RsyncQuick', 'quick');

		$this->assertFileExists("{$this->workdir}/double.pids.started",
			"the site must spawn the injected rsync double through the \$pfb['rsync_bin'] seam");
		$this->assertTrue($result->success,
			'a transfer that completes just below the wall budget must publish exactly as today');
		$this->assertStringNotContainsString('TIMED OUT', $this->logText(),
			'a compliant transfer must not be reported as a deadline expiry; log: ' . $this->logText());
		$size = @filesize("{$this->workdir}/feed.orig");
		$this->assertNotFalse($size, 'the published body must survive as feed.orig');
		$this->assertGreaterThanOrEqual(self::QUICK_BODY_BYTES, $size,
			'the whole body must arrive intact');
	}

	/**
	 * Scenario: a peer that accepts and then sends no data at all.
	 *
	 * Given a REAL rsync binary (through the same seam) pointed at a local
	 *   socket that accepts but never speaks, and a wall budget ABOVE rsync's
	 *   own 5 s I/O timeout
	 * When pfb_download() fetches with format 'rsync'
	 * Then the site reaches the stalled peer, and the transfer still fails
	 *   finitely through rsync's own I/O timeout — the deadline is there for
	 *   the slow-progress peer, not to rescue (or shadow) the silent one.
	 */
	public function testSilentRsyncPeerStillFailsFinitelyThroughTheExistingIoTimeout(): void
	{
		$real = NULL;
		foreach (['/usr/local/bin/rsync', '/usr/bin/rsync', '/usr/local/bin/openrsync', '/opt/homebrew/bin/rsync'] as $bin) {
			if (is_executable($bin)) {
				$real = $bin;
				break;
			}
		}
		if ($real === NULL) {
			$this->markTestSkipped('no real rsync binary available on this host');
		}
		$GLOBALS['pfb']['rsync_bin'] = $real;

		$errno  = 0;
		$errstr = '';
		$this->stallServer = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
		$this->assertNotFalse($this->stallServer, "stall server: {$errstr} (errno {$errno})");
		$name = (string) stream_socket_get_name($this->stallServer, FALSE);
		$port = (int) substr($name, strrpos($name, ':') + 1);

		$started = microtime(TRUE);
		$result  = $this->fetch('RsyncSilent', 'silent', self::SILENT_PEER_TIMEOUT,
			"rsync://127.0.0.1:{$port}/list.txt");
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CAP_SECONDS, $elapsed,
			"stuck/environment: the silent-peer fetch returned after {$elapsed}s — neither "
			. "rsync's own I/O timeout nor the wall deadline ended it");
		$this->assertNotFalse(@stream_socket_accept($this->stallServer, 0),
			"the site must reach the stalled peer through the injected rsync binary ({$real})");
		$this->assertFalse($result->success, 'a silent peer must still fail finitely');
		$this->assertStringContainsString('RSYNC Failed (exit', $this->logText(),
			'the silent peer must fail through rsync\'s own I/O timeout (rsync\'s exit), not '
			. 'the wall deadline; log: ' . $this->logText());
	}

	/**
	 * The spawn-shape contract of the seam itself: timeout(1) in default
	 * (reaper) mode — never --foreground — carrying the caller's wall budget
	 * and the package kill grace, passing --timeout=5 through to rsync, and
	 * keeping pfb_extract_cmd()'s kernel backstop in front.
	 */
	public function testRsyncTransferCommandCarriesTheWallDeadlineSeams(): void
	{
		$GLOBALS['pfb']['timeout']   = '/bin/timeout-fake';
		$GLOBALS['pfb']['rsync_bin'] = '/bin/rsync-fake';

		$cmd = pfb_rsync_transfer_cmd('host::module/list', '/tmp/feed.raw', 8192, 300);

		// pfb_extract_cmd() keeps its kernel write backstop in front of the
		// bounded spawn.
		$this->assertStringContainsString('ulimit -f 8192 || exit 1; ', $cmd,
			'pfb_extract_cmd()\'s kernel write backstop must stay in front of the bounded spawn: '
			. $cmd);
		// timeout(1) in DEFAULT (reaper) mode — never --foreground: a hung rsync
		// with remote-shell descendants must die as a whole tree — carrying the
		// package kill grace and the caller's whole-transfer budget.
		$this->assertStringContainsString(
			escapeshellarg('/bin/timeout-fake') . ' -s TERM -k ' . PFB_HOOK_KILL_GRACE . ' 300 ',
			$cmd,
			'the transfer must run under the injected timeout(1) in default (reaper) mode, '
			. 'with the package kill grace and the caller\'s whole-transfer budget: ' . $cmd);
		$this->assertStringContainsString(
			escapeshellarg('/bin/rsync-fake') . ' --timeout=5 '
			. escapeshellarg('host::module/list') . ' ' . escapeshellarg('/tmp/feed.raw'),
			$cmd,
			'the injected rsync binary must carry rsync\'s own I/O timeout and the escaped '
			. 'source/destination: ' . $cmd);
		$this->assertStringContainsString(' -k 5 1 ', pfb_rsync_transfer_cmd('s', 'd', 8192, 0),
			'a degenerate budget must floor at one second, never disable the bound');
	}
}
