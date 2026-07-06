<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #886 -- pfblockerng_top1m() must never wipe a previously-good TOP1M whitelist
 * when the top-1m.csv feed is empty/invalid; it must warn instead of silently "completing".
 *
 * Root cause (pre-change): the function opened pfbalexawhitelist.txt with fopen(...,'w')
 * UP FRONT -- before knowing the parse would find anything -- so a 0-byte/garbage
 * top-1m.csv truncated a good whitelist to empty while logging only an info-level
 * "Parsed 0 lines" line. Fix: build into a temp file (tempnam(), collision-safe), and
 * only swap it into place -- via a CHECKED @rename() -- when the parse actually found
 * rows with a numeric rank column; otherwise discard the temp and warn (level 2) that
 * the previous whitelist was kept. A prose/HTML/error body that merely happens to
 * contain a '.' and a ',' no longer counts as "valid data found" (2nd review round).
 *
 * Feature: TOP1M whitelist rebuild survives an empty/invalid feed
 *   Background:
 *     Given $pfb['dbdir'] holds the feed at top-1m.csv and the whitelist at
 *           pfbalexawhitelist.txt
 *     And   $pfb['dnsbl_top1m_inc'] names at least one TLD to include
 *
 * Branch coverage (every condition, both sides):
 *   * dead feed (0 usable source lines) WITH a prior whitelist -> preserved + WARN
 *   * dead feed WITH NO prior whitelist -> stays absent + WARN ("no list available")
 *   * garbage-but-nonempty feed (numeric-rank guard) -> preserved + WARN, same as dead
 *   * @rename() FAILURE (publish denied, two distinct real-world triggers: an occupied
 *     destination path and a read-only dbdir) -> preserved + WARN, not reported as
 *     success. The tempnam()/fopen()-returns-FALSE branch itself needs an
 *     `open_basedir`-restricted child process to force deterministically (see
 *     DnsblPrefetchTest/IpPrefetchTest's sandbox helper) -- left as a documented
 *     out-of-CI/covered-by-guard gap rather than a further locally-flaky sandboxed test.
 *   * valid feed with matches -> whitelist REPLACED with the fresh build
 *   * valid feed with zero TLD matches -> whitelist replaced (with empty content) + a
 *     mild info note, NOT the dead-feed warning (a real feed just matched nothing)
 */
#[CoversFunction('pfblockerng_top1m')]
final class Top1mPreserveOnEmptyFeedTest extends TestCase
{
	private string $dbdir;

	/** Saved $GLOBALS['pfb'] keys this test touches, restored in tearDown for isolation. */
	private array $savedPfb = [];

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_top1m_' . getmypid() . '_' . uniqid();
		$this->assertTrue(@mkdir($this->dbdir, 0777, true), "could not create sandbox {$this->dbdir}");

		foreach (['dbdir', 'log', 'errlog', 'dnsbl_top1m_inc', 'dnsbl_top1m_cnt', 'runlog',
			  'runlog_active', 'hook_lifecycle', 'pnow'] as $key) {
			$this->savedPfb[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$key] : false;
		}

		$GLOBALS['pfb']['dbdir']		= $this->dbdir;
		$GLOBALS['pfb']['log']			= "{$this->dbdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']		= "{$this->dbdir}/pfblockerng_error.log";
		$GLOBALS['pfb']['dnsbl_top1m_inc']	= 'com';
		$GLOBALS['pfb']['dnsbl_top1m_cnt']	= '1000';
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active'],
		      $GLOBALS['pfb']['hook_lifecycle'], $GLOBALS['pfb']['pnow']);

		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['log'], ''), 'could not create main log');
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['errlog'], ''), 'could not create error log');
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $key => $val) {
			if ($val === false) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $val;
			}
		}
		// A rename-failure test occupies the whitelist path with a directory; restore
		// write access from any temp-open-failure test before removing entries.
		@chmod($this->dbdir, 0777);
		foreach ((array) (@glob("{$this->dbdir}/*") ?: []) as $f) {
			if (is_dir($f)) {
				@rmdir($f);
			} else {
				@unlink($f);
			}
		}
		@rmdir($this->dbdir);
	}

	private function whitelistPath(): string
	{
		return "{$this->dbdir}/pfbalexawhitelist.txt";
	}

	private function csvPath(): string
	{
		return "{$this->dbdir}/top-1m.csv";
	}

	/** Stray '.pfbtop1m_*' staging files left in dbdir after a run (should always be empty). */
	private function tempFilesLeftBehind(): array
	{
		return (array) (@glob("{$this->dbdir}/.pfbtop1m_*") ?: []);
	}

	private function readErrLog(): string
	{
		$raw = file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertNotFalse($raw, 'could not read error log');
		return (string) $raw;
	}

	private function readMainLog(): string
	{
		$raw = file_get_contents($GLOBALS['pfb']['log']);
		$this->assertNotFalse($raw, 'could not read main log');
		return (string) $raw;
	}

	/**
	 * THE core proof: a prior good whitelist survives a 0-byte top-1m.csv (empty feed),
	 * and the run warns instead of silently completing. On pre-change code this FAILS --
	 * the fopen(...,'w') truncates pfbalexawhitelist.txt to empty before the parse even
	 * runs (verified by stashing the fix and re-running).
	 */
	public function testEmptyFeedPreservesPriorWhitelistAndWarns(): void
	{
		// Given: a prior good whitelist and an empty (0-byte) top-1m.csv.
		$priorContent = ".example.com,,\n,example.com,,\n,www.example.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$this->assertNotFalse(file_put_contents($this->csvPath(), ''), 'setup: empty top-1m.csv');
		// Assert the before-state explicitly so the post-call assertion proves preservation,
		// not merely "some content happens to be there".
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When
		pfblockerng_top1m();

		// Then: unchanged, no leftover temp file, and a level-2 (main log + error log) warning.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a dead feed must NOT wipe the previously-good TOP1M whitelist');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no temp build file left behind');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/**
	 * THE #886-review proof: a garbage-but-nonempty top-1m.csv (a prose/error body, not
	 * real CSV data) must classify the SAME as a dead feed -- not as "valid data found".
	 * Pre-fix code's only filter was a '.' AND a ',' present on the line, so a body like
	 * "error, service temporarily unavailable." passed it, $linecnt went > 0, and the
	 * "valid feed" branch replaced (wiped) a good whitelist with the empty temp build --
	 * reporting success ("Parsed N lines"), not a warning.
	 */
	public function testGarbageNonemptyFeedPreservesPriorWhitelistAndWarns(): void
	{
		// Given: a prior good whitelist and a top-1m.csv whose only line has a '.' AND a
		// ',' (passes the old filter) but no numeric rank column (not real CSV data).
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$this->assertNotFalse(
			file_put_contents($this->csvPath(), "error, service temporarily unavailable.\n"),
			'setup: garbage (non-CSV) top-1m.csv'
		);
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When
		pfblockerng_top1m();

		// Then: unchanged, no leftover temp file, and a level-2 warning -- a garbage body
		// must never be mistaken for a valid feed.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a garbage-but-nonempty feed must NOT wipe the previously-good TOP1M whitelist');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no temp build file left behind');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/**
	 * #886-review guard (finding 2 -- guard the temp-file open): a read-only dbdir must
	 * warn and keep the previous whitelist, never fatal. RED on pre-fix code (verified
	 * directly): the old code opened a FIXED "{$whitelist_file}.tmp" path with a plain
	 * @fopen(..., 'w') -- which the read-only dbdir genuinely fails outright -- and then
	 * @fwrite()'d to the FALSE handle, throwing an uncaught `TypeError: fwrite(): Argument
	 * #1 ($stream) must be of type resource, false given` (a real PHP 8 fatal, exactly
	 * finding 2). GREEN after: the guarded fopen() is checked up front.
	 *
	 * NOTE on the fixed code path actually exercised here: PHP's tempnam() (used by the
	 * fix, unlike the old fixed name) silently FALLS BACK to the system temp dir when the
	 * given directory exists but isn't writable (verified empirically -- it does not
	 * return FALSE merely for "not writable"), so post-fix staging still succeeds; it is
	 * the final @rename() into the read-only dbdir that then fails, landing in the
	 * "failed to publish" branch (a second, realistic real-world trigger for the same
	 * guard as testRenameFailurePreservesPriorWhitelistAndWarns below). The genuine
	 * tempnam()/fopen()-returns-FALSE branch (both the given dir AND the system temp dir
	 * refuse the create) is only deterministically forceable via an
	 * `open_basedir`-restricted child process -- the same mechanism already used by
	 * DnsblPrefetchTest/IpPrefetchTest's `runInRestrictedTempDirSandbox()`, which is
	 * known-flaky in this local dev environment (see this suite's pre-existing 3
	 * failures) -- so THAT exact branch is left as a documented out-of-CI/covered-by-
	 * guard gap rather than a fourth locally-flaky sandboxed test; this test still pins
	 * the finding-2 crash fix via the read-only-dbdir trigger.
	 */
	public function testReadOnlyDbdirCausesRenameFailurePreservesPriorWhitelistAndWarns(): void
	{
		// Given: a prior good whitelist, a valid+matching top-1m.csv, but a dbdir made
		// read-only AFTER seeding both files.
		$priorContent = ".kept2.com,,\n,kept2.com,,\n,www.kept2.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$this->assertNotFalse(file_put_contents($this->csvPath(), "1,example.com\n"), 'setup: valid top-1m.csv');
		$this->assertTrue(@chmod($this->dbdir, 0555), 'setup: make dbdir read-only (deny new-file create)');

		try {
			// When
			pfblockerng_top1m();
		} finally {
			// Restore write access up front so tearDown() can clean the sandbox.
			@chmod($this->dbdir, 0777);
		}

		// Then: unchanged, no fatal, and a level-2 warning naming the publish failure.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a read-only dbdir must NOT wipe the previously-good TOP1M whitelist');
		$this->assertStringContainsString('failed to publish the new whitelist build', $this->readErrLog());
	}

	/**
	 * #886-review guard: an @rename() FAILURE (the parse looked valid, but publishing it
	 * did not happen -- perms/cross-device/disk) must warn, not report "Parsed N lines"
	 * success while silently keeping a stale whitelist.
	 */
	public function testRenameFailurePreservesPriorWhitelistAndWarns(): void
	{
		// Given: a valid feed that WILL find a match, but the whitelist path is occupied
		// by a DIRECTORY -- rename(file, existing_directory) fails (EISDIR) without
		// needing a platform-specific cross-device/perm trick.
		$this->assertTrue(@mkdir($this->whitelistPath(), 0777), 'setup: occupy whitelist path with a directory');
		$this->assertNotFalse(file_put_contents($this->csvPath(), "1,example.com\n"), 'setup: valid top-1m.csv');

		// When
		pfblockerng_top1m();

		// Then: the occupying directory survives (a failed rename must not destroy it),
		// no leftover temp file, and a level-2 warning naming the publish failure.
		$this->assertDirectoryExists($this->whitelistPath(), 'a failed rename must not destroy the existing path');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no leftover temp file after a failed rename');
		$this->assertStringContainsString('failed to publish the new whitelist build', $this->readErrLog());
	}

	/** Same dead-feed path, but with NO prior whitelist -- says so, and still no wipe/creation. */
	public function testEmptyFeedWithNoPriorWhitelistWarnsNoListAvailable(): void
	{
		// Given: an empty (0-byte) top-1m.csv and no prior whitelist.
		$this->assertNotFalse(file_put_contents($this->csvPath(), ''), 'setup: empty top-1m.csv');
		$this->assertFileDoesNotExist($this->whitelistPath(), 'before-state: no prior whitelist');

		// When
		pfblockerng_top1m();

		// Then: still absent, and the warning names the "no list available" case.
		$this->assertFileDoesNotExist($this->whitelistPath(), 'a dead feed must not fabricate an empty whitelist');
		$this->assertStringContainsString('no TOP1M whitelist available', $this->readErrLog());
	}

	/** Regression guard: an absent top-1m.csv (download never landed) already preserved + warned. */
	public function testAbsentCsvPreservesPriorWhitelistAndWarns(): void
	{
		$priorContent = ".kept.com,,\n,kept.com,,\n,www.kept.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$this->assertFileDoesNotExist($this->csvPath(), 'before-state: no top-1m.csv');

		pfblockerng_top1m();

		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a missing feed file must not wipe the previously-good TOP1M whitelist');
		$this->assertStringContainsString('TOP1M conversion Failed', $this->readErrLog());
	}

	/** Valid feed with matches -- the whitelist IS replaced with the fresh build. */
	public function testValidFeedReplacesWhitelist(): void
	{
		$staleContent = ".stale.com,,\n,stale.com,,\n,www.stale.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $staleContent), 'setup: seed stale whitelist');
		// 3 usable source lines, 1 '.com' TLD match ('other.net'/'sample.org' don't match).
		$csv = "1,example.com\n2,other.net\n3,sample.org\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: valid top-1m.csv');

		pfblockerng_top1m();

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertStringNotContainsString('stale.com', $got, 'the stale build must be replaced, not appended to');
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got);
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no temp build file left behind');
		$this->assertStringContainsString('Parsed 3 lines | Found 1 of 1000', $this->readMainLog());
	}

	/**
	 * A valid feed with a SMALL dnsbl_top1m_cnt must still classify as valid.
	 * Regression for the #886-review off-by-one: $linecnt was incremented AFTER
	 * the "$x >= dnsbl_top1m_cnt" break, so cnt=1 matching the first line broke
	 * with $linecnt still 0 -- wrongly tripping the dead-feed path and keeping the
	 * stale whitelist instead of publishing the (valid) 1-entry build.
	 */
	public function testValidFeedWithSmallCountReplacesNotPreserved(): void
	{
		$staleContent = ".stale.com,,\n,stale.com,,\n,www.stale.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $staleContent), 'setup: seed stale whitelist');
		$GLOBALS['pfb']['dnsbl_top1m_cnt'] = '1';	// break on the very first match
		// First line matches '.com' -> $x reaches 1 and the loop breaks immediately.
		$csv = "1,example.com\n2,other.com\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: valid top-1m.csv');

		pfblockerng_top1m();

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertStringNotContainsString('stale.com', $got, 'a valid small-count feed must replace the stale whitelist');
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got);
		$this->assertStringNotContainsString('keeping the previous TOP1M whitelist', $this->readErrLog(),
			'a valid feed must NOT emit the dead-feed warning');
		$this->assertStringContainsString('Parsed 1 lines | Found 1 of 1', $this->readMainLog());
	}

	/** Valid feed, zero TLD matches -- replaced (with empty content) + a mild note, NOT the dead-feed warning. */
	public function testValidFeedWithZeroMatchesReplacesAndNotesNoMatches(): void
	{
		$staleContent = ".stale.com,,\n,stale.com,,\n,www.stale.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $staleContent), 'setup: seed stale whitelist');
		$csv = "1,example.net\n2,other.net\n";	// valid source lines, but no '.com' TLD present
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: valid feed, no TLD match');

		pfblockerng_top1m();

		$this->assertSame('', file_get_contents($this->whitelistPath()),
			'a valid feed that matched nothing still replaces the stale build (it is not a dead feed)');
		$this->assertStringContainsString('0 domains matched the configured TLD inclusions', $this->readMainLog());
		$this->assertStringNotContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
		$this->assertStringNotContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
	}
}
