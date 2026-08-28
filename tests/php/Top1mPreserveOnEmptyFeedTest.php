<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
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
 *     IpPrefetchTest's sandbox helper) -- left as a documented
 *     out-of-CI/covered-by-guard gap rather than a further locally-flaky sandboxed test.
 *   * valid feed with matches -> whitelist REPLACED with the fresh build
 *   * valid feed with zero TLD matches -> whitelist replaced (with empty content) + a
 *     mild info note, NOT the dead-feed warning (a real feed just matched nothing)
 *
 * ADR-59 P2 addendum: pfblockerng_top1m() now drives header-skip/domain-column/the
 * numeric-rank guard from the active provider descriptor (pfb_top1m_providers()) instead
 * of a hardcoded rank,domain-at-column-1 shape.
 *   * a SYNTHETIC descriptor's header/domain_col knobs are honoured (below) -- no live
 *     non-Tranco/Cisco provider exists yet (ADR-59 Phase 4 adds one)
 *
 * ADR-59 P4 addendum: the two live non-Tranco/Cisco providers (OpenPageRank, Majestic)
 * added by this phase -- their REAL sample shape parses correctly via the registered
 * descriptor, and a wrong domain_col genuinely mis-reads (fail-before/pass-after).
 * (OpenPageRank was originally DomCop; the list's hosting moved, #928 -- same
 * descriptor shape/index, only the URL/label/token changed.)
 *
 * ADR-59 P5 addendum: Cloudflare Radar (token-authenticated) parses its REAL shape too
 * (a single 'domain' column, no rank) -- this exposed a genuine latent bug the OpenPageRank/
 * Majestic tests couldn't: the generic content filter required a comma on every data
 * line, but a single-column CSV line has none, so every Cloudflare row was silently
 * skipped regardless of domain_col. Fixed (pfblockerng.inc) by only requiring a comma
 * when domain_col > 0. A missing/invalid top1m_token means the download never writes a
 * fresh top-1m.csv, which hits the SAME generic "csv absent -> preserve + warn" path
 * every provider's download failure already hits (no Cloudflare-specific branch exists
 * to bypass) -- proven below alongside a direct "no token in any log" assertion.
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
	 * `open_basedir`-restricted child process -- the same mechanism used by
	 * IpPrefetchTest's `runInRestrictedTempDirSandbox()` -- so THAT
	 * exact branch is left as a documented out-of-CI/covered-by-guard gap rather than
	 * adding a fourth sandboxed test here; this test still pins the finding-2 crash fix
	 * via the read-only-dbdir trigger.
	 */
	public function testReadOnlyDbdirCausesRenameFailurePreservesPriorWhitelistAndWarns(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('running as root -- permission-based failure injection cannot be simulated');
		}

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

	/**
	 * Issue #1646: a failed or short record write must abort publication instead of
	 * renaming a truncated staging file over the previous valid whitelist.
	 */
	#[DataProvider('recordWriteFailures')]
	public function testRecordWriteFailurePreservesPriorWhitelistAndWarns(string $failure): void
	{
		$priorContent = "kept.example\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$this->assertNotFalse(file_put_contents($this->csvPath(), "1,example.com\n"), 'setup: valid top-1m.csv');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		$write = match ($failure) {
			'false' => static fn($stream, string $bytes) => FALSE,
			'short' => static fn($stream, string $bytes) => strlen($bytes) - 1,
		};

		pfblockerng_top1m(NULL, ['write' => $write]);

		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			"a {$failure} record write must preserve the previous TOP1M whitelist");
		$this->assertSame([], $this->tempFilesLeftBehind(), "no staging file left after a {$failure} write");
		$this->assertStringContainsString('failed to write the new whitelist build', $this->readErrLog());
		$this->assertStringNotContainsString('Parsed 1 lines', $this->readMainLog(),
			"a {$failure} write must not report successful publication");
	}

	/** @return array<string, array{string}> */
	public static function recordWriteFailures(): array
	{
		return [
			'fwrite false' => ['false'],
			'fwrite short' => ['short'],
		];
	}

	/** Issue #1646: a write failure without a prior whitelist aborts without publishing. */
	public function testRecordWriteFailureWithoutPriorWhitelistAbortsPublication(): void
	{
		$this->assertFileDoesNotExist($this->whitelistPath(), 'before-state: no prior whitelist');
		$this->assertNotFalse(file_put_contents($this->csvPath(), "1,example.com\n"), 'setup: valid top-1m.csv');

		pfblockerng_top1m(NULL, [
			'write' => static fn($stream, string $bytes) => FALSE,
		]);

		$this->assertFileDoesNotExist($this->whitelistPath(),
			'a failed record write must not publish a new TOP1M whitelist');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no staging file left after a failed first publication');
		$this->assertStringContainsString('failed to write the new whitelist build', $this->readErrLog());
		$this->assertStringContainsString('publication aborted', $this->readErrLog());
		$this->assertStringNotContainsString('Parsed 1 lines', $this->readMainLog(),
			'a failed first publication must not report success');
	}

	/** Issue #1646: the injected full-write boundary still publishes canonical bytes. */
	public function testCompleteRecordWritePublishesCanonicalBytes(): void
	{
		$this->assertNotFalse(file_put_contents($this->csvPath(), "1,example.com\n"), 'setup: valid top-1m.csv');

		pfblockerng_top1m(NULL, [
			'write' => static fn($stream, string $bytes) => fwrite($stream, $bytes),
		]);

		$this->assertSame("example.com\n", file_get_contents($this->whitelistPath()));
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no staging file left after a complete write');
		$this->assertStringContainsString('Parsed 1 lines | Found 1 of 1000', $this->readMainLog());
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
		$this->assertSame("example.com\n", $got);
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
		$this->assertSame("example.com\n", $got);
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

	/**
	 * ADR-59 P2 -- the builder reads its header-skip/domain-column knobs from the active
	 * provider descriptor instead of the original hardcoded "domain always at CSV index 1,
	 * never a header row" shape. Proven via the $provider_override test seam (no live
	 * provider needs this shape yet -- Phase 4 adds one) against a synthetic 'csv' parse
	 * descriptor whose header row itself contains a '.'/',' (so it would otherwise pass the
	 * dead-feed content filter) and whose domain sits at index 2, not 1.
	 *
	 * RED on the pre-P2 parser: it has no header-skip at all and always reads index 1, so
	 * the header row is misread as data (accidentally dropped by the rank-column guard) and
	 * the real data row's domain is read from the wrong column ('1', the tld_rank field) --
	 * producing an EMPTY whitelist + "Found 0". GREEN after: the header row is skipped, the
	 * domain comes from index 2, and the whitelist is populated.
	 */
	public function testSyntheticDescriptorAppliesHeaderSkipAndDomainColumn(): void
	{
		// Given: a header row containing a '.' and a ',' (so skipping it must be driven by
		// the 'header' knob, not merely by the pre-existing content/rank filters) followed
		// by one data row whose domain is the THIRD CSV field (0-indexed domain_col 2).
		$csv = "rank,tld.rank,domain\n1,1,example.com\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: synthetic-shape top-1m.csv');
		$syntheticDescriptor = ['parse' => 'csv', 'header' => true, 'domain_col' => 2];

		// When
		pfblockerng_top1m($syntheticDescriptor);

		// Then: the header row was skipped (only 1 line parsed) and the domain came from
		// index 2 -- not the rank_domain default's index 1 (which would have read '1' and
		// matched nothing).
		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame("example.com\n", $got,
			'the domain must come from domain_col (index 2), and the header row must not count as data');
		$this->assertStringContainsString('Parsed 1 lines | Found 1 of 1000', $this->readMainLog());
	}

	/**
	 * ADR-59 P4 -- pfblockerng_top1m() parses Majestic Million's REAL CSV shape
	 * (12-col unquoted header, Domain at str_getcsv() index 2) via its registered
	 * provider descriptor (pfb_top1m_providers()[PfbTop1mSource::Majestic->value]).
	 * Sample verified against the live downloads.majestic.com/majestic_million.csv
	 * format (fetched during development of this test).
	 *
	 * FAIL-BEFORE/PASS-AFTER: the BEFORE run reproduces the exact pre-ADR-59-Phase-2
	 * hardcoded shape -- pfblockerng_top1m(array()) resolves every knob to its
	 * default (parse=rank_domain, header=false, domain_col=1), precisely what every
	 * call site used before Phase 2 generalized the builder. Applied to Majestic's
	 * real layout, domain_col=1 reads the TldRank column (a bare digit, e.g. "1")
	 * as the "domain" instead of the real Domain field at index 2 -- a bare digit
	 * is not hostname-shaped, so the #954 domain-shape guard (which now covers the
	 * rank_domain parse too) rejects every row as no-real-data and no whitelist is
	 * built at all (RED). The AFTER run, using the actual registered Majestic
	 * descriptor (domain_col 2, header skipped), correctly extracts both domains
	 * (GREEN) -- proving domain_col is genuinely read from the descriptor, not
	 * hardcoded.
	 */
	public function testMajesticRealShapeSampleMisreadsOnLegacyColumnAndParsesCorrectlyViaItsDescriptor(): void
	{
		// Given: a real-shape Majestic Million sample -- 12-col unquoted header,
		// Domain at index 2, two real '.com' domains matching the 'com' TLD
		// inclusion configured in setUp().
		$csv = "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n"
			. "1,1,google.com,com,501790,2223489,google.com,com,1,1,500432,2222282\n"
			. "2,2,facebook.com,com,473621,2232852,facebook.com,com,2,2,472323,2232281\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: real-shape Majestic Million sample');

		// When (BEFORE): the pre-Phase-2 legacy shape -- domain_col 1, no header skip.
		pfblockerng_top1m(array());

		// Then (RED): the real domains are misread as the numeric TldRank column
		// ("1"/"2" -- dotless, not hostname-shaped), which the #954 domain-shape
		// guard rejects before TLD matching is ever reached -- no whitelist can be
		// built (none existed before this run).
		$this->assertFileDoesNotExist($this->whitelistPath(),
			"the legacy col-1 parser must MIS-read Majestic's real shape -- Domain sits at index 2, not 1");
		$this->assertStringContainsString('no TOP1M whitelist available', $this->readMainLog());
		$this->assertStringNotContainsString('Parsed 2 lines', $this->readMainLog());

		// Reset the log so the GREEN assertion below is unambiguous.
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['log'], ''), 'reset main log between runs');

		// When (AFTER): the actual registered Majestic descriptor.
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Majestic->value]);

		// Then (GREEN): both real domains are correctly extracted from index 2.
		$this->assertSame(
			"google.com\nfacebook.com\n",
			file_get_contents($this->whitelistPath()),
			'the registered Majestic descriptor must extract Domain from index 2'
		);
		$this->assertStringContainsString('Parsed 2 lines | Found 2 of 1000', $this->readMainLog());
	}

	/**
	 * ADR-59 P4 -- pfblockerng_top1m() parses OpenPageRank's REAL CSV shape (unquoted
	 * 5-col header, Domain at str_getcsv() index 1) via its registered provider
	 * descriptor. Sample verified against the live
	 * openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv format
	 * (fetched 2026-07-07; #928 -- this list was formerly hosted by DomCop, whose
	 * URL froze 2026-03-29).
	 *
	 * OpenPageRank's own Domain column happens to sit at the SAME index (1) the
	 * pre-Phase-2 legacy default already used, so replaying that legacy shape
	 * verbatim (as the Majestic test above does) would coincidentally still
	 * parse OpenPageRank's real sample correctly -- on its own it would NOT prove
	 * domain_col is read from the descriptor rather than hardcoded. To still
	 * assert "the col index matters" for OpenPageRank, this FAIL-BEFORE/PASS-AFTER
	 * instead probes a WRONG column for OpenPageRank's shape (domain_col 2 -- the
	 * "Extension" field, e.g. "com": dotless, so it cannot be mistaken for a
	 * hostname) and shows it likewise mis-reads; the registered OpenPageRank
	 * descriptor (domain_col 1) is correct.
	 *
	 * #892 review addendum: the wrong column's value ("com") also doesn't look
	 * like a hostname, so the domain-validity guard (finding 1) now rejects it as
	 * no-real-data rather than "valid data, zero TLD matches" -- the BEFORE
	 * assertions reflect that (no whitelist file at all, not an empty one).
	 */
	public function testOpenPageRankRealShapeSampleMisreadsOnWrongColumnAndParsesCorrectlyViaItsDescriptor(): void
	{
		// Given: a real-shape OpenPageRank sample -- unquoted 5-col header
		// (Rank,Domain,Extension,Open Page Rank,Referring Domains), Domain at
		// index 1, two real '.com' domains matching the 'com' TLD inclusion.
		$csv = "Rank,Domain,Extension,Open Page Rank,Referring Domains\n"
			. "1,www.facebook.com,com,10,2059716\n"
			. "2,fonts.googleapis.com,com,10,2059716\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: real-shape OpenPageRank sample');

		// When (BEFORE): the WRONG column for this shape -- index 2 ("Extension",
		// a bare dotless string like "com" -- the hostname-shape guard rejects it
		// before TLD matching is ever reached).
		$wrongColumn = ['parse' => 'csv', 'header' => true, 'domain_col' => 2];
		pfblockerng_top1m($wrongColumn);

		// Then (RED): the real domains are misread as the Extension value ("com"),
		// which the domain-validity guard rejects as not hostname-shaped (no dot),
		// so TLD matching is never reached -- no whitelist can be built (none
		// existed before this run).
		$this->assertFileDoesNotExist($this->whitelistPath(),
			"domain_col 2 must MIS-read OpenPageRank's real shape -- Domain sits at index 1, not 2");
		$this->assertStringContainsString('no TOP1M whitelist available', $this->readMainLog());
		$this->assertStringNotContainsString('Parsed 2 lines', $this->readMainLog());

		// Reset the log so the GREEN assertion below is unambiguous.
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['log'], ''), 'reset main log between runs');

		// When (AFTER): the actual registered OpenPageRank descriptor.
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		// Then (GREEN): both real domains are correctly extracted from index 1
		// ('www.' stripped per the existing whitelist-building convention).
		$this->assertSame(
			"facebook.com\nfonts.googleapis.com\n",
			file_get_contents($this->whitelistPath()),
			'the registered OpenPageRank descriptor must extract Domain from index 1'
		);
		$this->assertStringContainsString('Parsed 2 lines | Found 2 of 1000', $this->readMainLog());
	}

	/**
	 * ADR-59 P5 -- pfblockerng_top1m() parses Cloudflare Radar's REAL CSV shape (a
	 * SINGLE 'domain' column, no rank -- confirmed against Cloudflare's own docs during
	 * this phase, NOT the ADR's original 2-column guess) via its registered descriptor
	 * (domain_col 0, header skipped).
	 *
	 * Unlike the OpenPageRank/Majestic column-index bug above, this shape exposed a DIFFERENT
	 * latent bug: the generic content filter demanded BOTH a '.' AND a ',' on every data
	 * line (a guard against a prose/error body that would otherwise reach the parser).
	 * A single-column CSV line has NO comma at all (nothing to delimit), so every one of
	 * Cloudflare's real data lines was silently skipped regardless of domain_col -- the
	 * whitelist came out EMPTY even though the fixture data is genuinely well-formed.
	 * FAIL-BEFORE/PASS-AFTER: manually verified by reverting just the comma-relaxation
	 * hunk in pfblockerng.inc (`git stash`) and re-running this exact test -- it goes RED
	 * (empty whitelist, same as the OpenPageRank/Majestic BEFORE runs above); restoring the fix
	 * makes it GREEN. This test's own body only exercises the (permanent) AFTER state --
	 * see RESULTS/05_Results.txt for the stash verification transcript.
	 */
	public function testCloudflareRealShapeSampleParsesViaItsDescriptorAndTheSingleColumnCommaFix(): void
	{
		// Given: a real-shape Cloudflare Radar sample -- single 'domain' column header,
		// two real '.com' domains, no rank/second column (no comma anywhere in the data).
		$csv = "domain\n"
			. "google.com\n"
			. "facebook.com\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: real-shape Cloudflare Radar sample');

		// When: the actual registered Cloudflare descriptor (domain_col 0, header skipped).
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Cloudflare->value]);

		// Then: both real domains are correctly extracted from the single column despite
		// carrying no comma -- proves the comma-requirement relaxation for domain_col 0.
		$this->assertSame(
			"google.com\nfacebook.com\n",
			file_get_contents($this->whitelistPath()),
			'the registered Cloudflare descriptor must extract the single-column domain despite no comma in the data'
		);
		$this->assertStringContainsString('Parsed 2 lines | Found 2 of 1000', $this->readMainLog());
	}

	/**
	 * #892 review (finding 1) -- the #886 silent-whitelist-wipe must not re-open for the
	 * 'csv' parse providers (OpenPageRank/Majestic/Cloudflare). Pre-fix, the domain-validity
	 * guard only covered 'rank_domain' (Tranco/Cisco); a 'csv'-mode garbage/HTML/JSON
	 * error body (a CDN 503 page, a Cloudflare auth-error response, etc -- the MIME
	 * allow-list accepts text/html and ADR-49's sanity scan is opt-in/default-off) still
	 * has a '.' and a ',' somewhere, so it passed the generic content filter, counted as
	 * a "valid" parsed row, and the "valid feed" branch swapped the (empty) build over a
	 * good whitelist -- reporting success, not a warning. Each provider gets its own
	 * real-descriptor-driven proof below; the FAIL-BEFORE state is proven by the shared
	 * mechanism (the 'csv' branch had NO validity guard at all before this fix -- every
	 * garbage row here has a non-hostname domain field but would still have incremented
	 * $linecnt on the pre-fix code, taking the wipe path).
	 */
	public function testOpenPageRankGarbageHtmlBodyPreservesPriorWhitelistAndWarns(): void
	{
		// Given: a prior good whitelist and a multi-line HTML error body (a CDN 503 page,
		// NOT OpenPageRank's real unquoted rank/domain/extension/pagerank/refdomains CSV)
		// written as top-1m.csv.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$garbage = "<html><head><title>503 Backend fetch failed</title></head>\n"
			. "<body><h1>Error 503 Backend fetch failed</h1>\n"
			. "<p>Guru meditation, please retry. ref.12345</p></body></html>\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $garbage), 'setup: garbage HTML body as top-1m.csv');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When: the real registered OpenPageRank descriptor drives the parse (header=TRUE skips
		// line 1; domain_col=1).
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		// Then: the HTML body must never be mistaken for real OpenPageRank CSV data -- the prior
		// whitelist survives byte-identical and the run warns instead of "succeeding".
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a garbage HTML body must NOT wipe the previously-good TOP1M whitelist (OpenPageRank, #892 review)');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no temp build file left behind');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/** Same proof as above, for Majestic's registered descriptor (header=TRUE, domain_col=2). */
	public function testMajesticGarbagePlaintextBodyPreservesPriorWhitelistAndWarns(): void
	{
		// Given: a prior good whitelist and a garbage body shaped like Majestic's real CSV
		// (12-col header + a data row) but whose Domain column is a prose error message.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$garbage = "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n"
			. "1,1,Service temporarily unavailable. Please retry.,text,0,0,,,0,0,0,0\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $garbage), 'setup: garbage Domain-column body as top-1m.csv');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When: the real registered Majestic descriptor drives the parse.
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Majestic->value]);

		// Then: the prose "domain" must never be mistaken for real Majestic CSV data.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a garbage Domain-column body must NOT wipe the previously-good TOP1M whitelist (Majestic, #892 review)');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no temp build file left behind');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/**
	 * Same proof as above, for Cloudflare's registered descriptor (header=TRUE,
	 * domain_col=0 -- the single-column shape where the comma requirement is relaxed, so
	 * this is the strictest case: only the new domain-validity regex stands between a
	 * JSON error body and a "valid feed" verdict.
	 */
	public function testCloudflareGarbageJsonBodyPreservesPriorWhitelistAndWarns(): void
	{
		// Given: a prior good whitelist and a Cloudflare-shaped ('domain' header, single
		// column) body whose only "data" line is a JSON auth-error response, not a domain.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$garbage = "domain\n"
			. "{\"success\":false,\"errors\":[{\"code\":10000,\"message\":\"Authentication error.\"}]}\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $garbage), 'setup: garbage JSON body as top-1m.csv');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When: the real registered Cloudflare descriptor drives the parse.
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Cloudflare->value]);

		// Then: the JSON error body must never be mistaken for a real Cloudflare domain row.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a garbage JSON body must NOT wipe the previously-good TOP1M whitelist (Cloudflare, #892 review)');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no temp build file left behind');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/**
	 * ADR-59 P5 -- safe-on-missing/invalid-token behaviour (ADR §4 requirement 3): when
	 * Cloudflare's download fails (missing/invalid top1m_token -> pfb_top1m_auth_headers()
	 * returns no Authorization header -> pfb_download() sends no auth and the request is
	 * rejected -> top-1m.csv is never written/refreshed), pfblockerng_top1m() hits the SAME
	 * generic "csv absent -> preserve + warn" path every other provider's download failure
	 * already hits (see testAbsentCsvPreservesPriorWhitelistAndWarns above) -- there is no
	 * Cloudflare-specific failure branch to bypass. This is the Cloudflare-scoped proof of
	 * that reuse. (The "no token in any log" guarantee itself is proven in
	 * Top1mAuthHeadersTest.php / PfbFilterTest.php -- pfblockerng_top1m() never reads
	 * $pfb['top1m_token'] or any header at all, so asserting it here would be vacuous:
	 * the function never receives the token in the first place.)
	 */
	public function testMissingOrInvalidCloudflareTokenPreservesWhitelistAndLogsNoToken(): void
	{
		// Given: a prior good whitelist (a previous successful run/provider) and top-1m.csv
		// ABSENT -- exactly what a failed Cloudflare download (no/invalid token) leaves
		// behind (pfb_download() never wrote a fresh file).
		$priorContent = ".oldsite.com,,\n,oldsite.com,,\n,www.oldsite.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: prior good whitelist');
		$this->assertFileDoesNotExist($this->csvPath(), 'before-state: no top-1m.csv (simulates a failed download)');

		// When: the Cloudflare descriptor is active but top-1m.csv never arrived.
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Cloudflare->value]);

		// Then: the prior whitelist is untouched and a warning was logged (same generic
		// path as testAbsentCsvPreservesPriorWhitelistAndWarns).
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a missing top-1m.csv (failed Cloudflare download) must preserve the prior whitelist');
		$this->assertStringContainsString('TOP1M conversion Failed', $this->readErrLog());
	}

	/**
	 * Issue #904 -- the 'csv' parse guard's final-label class (`[A-Za-z]{2,}`)
	 * rejected every punycode TLD (they contain digits/hyphens, e.g.
	 * 'xn--p1ai' == .рф), so a user selecting a punycode TLD inclusion with a
	 * csv-parse provider (OpenPageRank/Majestic/Cloudflare) got ZERO matching
	 * whitelist entries -- silently -- while the identical config on
	 * Tranco/Cisco ('rank_domain' parse, no such guard) whitelisted them.
	 * Fixed by widening the final-label alternative to also accept an
	 * 'xn--...' label: `(?:[A-Za-z]{2,}|[Xx][Nn]--[A-Za-z0-9-]{2,})`.
	 *
	 * RED on pre-fix code (verified by stashing just this regex hunk and
	 * re-running this exact test): preg_match() on 'example.xn--p1ai' returns
	 * 0, so the row is `continue`d, $linecnt stays 0 -- classifying as a dead
	 * feed -- and with no prior whitelist file the run logs "no TOP1M
	 * whitelist available" instead of building one; the whitelist file assert
	 * below fails (file never created). GREEN after: the row is counted as
	 * valid data and whitelisted.
	 */
	public function testCsvModeAcceptsPunycodeTldDomainIntoWhitelist(): void
	{
		// Given: an OpenPageRank-shaped csv row whose domain ends in a punycode TLD
		// (xn--p1ai == .рф), and the TOP1M inclusion set names that exact TLD.
		$GLOBALS['pfb']['dnsbl_top1m_inc'] = 'xn--p1ai';
		$csv = "Rank,Domain,Extension,Open Page Rank,Referring Domains\n"
			. "1,example.xn--p1ai,xn--p1ai,10,2059716\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: OpenPageRank-shaped punycode-TLD row');

		// When
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		// Then: the punycode-TLD row is counted as valid data and whitelisted
		// -- not silently dropped by the final-label guard.
		$this->assertSame(
			"example.xn--p1ai\n",
			file_get_contents($this->whitelistPath()),
			'a punycode TLD (xn--p1ai) row must be accepted by the csv-mode hostname guard, not dropped'
		);
		$this->assertStringContainsString('Parsed 1 lines | Found 1 of 1000', $this->readMainLog());
	}

	/**
	 * Issue #904 negative guard -- the punycode widening must not also open
	 * the door to a bare numeric "TLD". A domain field whose final label is
	 * all-digits (IP-shaped, e.g. no real TLD at all) matches neither
	 * alternative ([A-Za-z]{2,} nor xn--...) and must still be dropped.
	 */
	public function testCsvModeStillRejectsNumericTldJunkRow(): void
	{
		// Given: a prior good whitelist and an OpenPageRank-shaped row whose "Domain"
		// field is an IP-shaped string -- garbage, not a TLD in any form.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$csv = "Rank,Domain,Extension,Open Page Rank,Referring Domains\n"
			. "1,192.168.1.1,com,10,2059716\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: numeric-TLD junk row');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		// Then: the numeric-final-label row is still rejected.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a numeric-TLD junk row must still be dropped by the csv-mode hostname guard');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
	}

	/**
	 * Issue #904 negative guard -- a Domain field with no dot at all must
	 * still be dropped, even though the CSV LINE itself contains a '.'
	 * elsewhere (the 'Open Page Rank' field here) and so still passes the
	 * coarser line-level content filter upstream of this guard.
	 */
	public function testCsvModeStillRejectsDomainFieldWithNoDot(): void
	{
		// Given: a prior good whitelist and an OpenPageRank-shaped row whose Domain
		// field has no dot at all.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$csv = "Rank,Domain,Extension,Open Page Rank,Referring Domains\n"
			. "1,nodomainhere,v1.0,10,2059716\n";
		$this->assertNotFalse(
			file_put_contents($this->csvPath(), $csv),
			'setup: dotless Domain field, dot elsewhere on the line'
		);
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		// Then: a dotless Domain field is still rejected even though the line
		// itself contains a '.' (in another column).
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a dotless Domain field must still be dropped by the csv-mode hostname guard');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
	}

	/**
	 * Issue #904 review follow-up -- pin the WIDENED alternative's own lower
	 * boundary: the punycode branch must require an alphanumeric first
	 * character after the 'xn--' prefix, so a suffix made only of hyphens
	 * (never a real RFC 3492 ACE label) is still rejected. Only 'xn----' is
	 * reachable exclusively through the new branch (the other two rows are
	 * rejected by both the old and new regex), so it is the row that proves
	 * the tightened alternative -- RED against the first-cut widening
	 * (`xn--[A-Za-z0-9-]{2,}`, which accepted it), GREEN with the
	 * alnum-first form (`xn--[A-Za-z0-9][A-Za-z0-9-]+`).
	 */
	#[DataProvider('malformedPunycodeTldRows')]
	public function testCsvModeStillRejectsMalformedPunycodeTldRow(string $domain): void
	{
		// Given: a prior good whitelist and an OpenPageRank-shaped row whose Domain
		// field ends in a malformed punycode-shaped TLD.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$csv = "Rank,Domain,Extension,Open Page Rank,Referring Domains\n"
			. "1,{$domain},com,10,2059716\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), "setup: malformed punycode row {$domain}");
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When
		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		// Then: the malformed punycode-shaped TLD is rejected -- the widening
		// admits real ACE labels only, not hyphen-runs or truncated prefixes.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			"a malformed punycode TLD ({$domain}) must still be dropped by the csv-mode hostname guard");
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
	}

	/** @return array<string, array{string}> */
	public static function malformedPunycodeTldRows(): array
	{
		return [
			'hyphen-only suffix (xn----)'      => ['example.xn----'],
			'empty suffix (bare xn--)'         => ['example.xn--'],
			'missing second hyphen (xn-p1ai)'  => ['example.xn-p1ai'],
		];
	}

	/**
	 * Issue #954 -- THE red->green pinning test. The 'rank_domain' parse (Tranco/Cisco)
	 * validated only the rank column (ctype_digit on $csvline[0]); the domain field itself
	 * went unchecked. A row whose domain field is dotless still satisfies the line-level
	 * '.'+',' pre-filter (the dot sits in another column) and the rank-column check (a
	 * numeric rank), so it reached the TLD-extraction strrpos($domain, '.') below with no
	 * '.' to find -- strrpos() returns FALSE, and substr($domain, FALSE + 1) silently
	 * produces a garbage "TLD" (the domain minus its first character) instead of the row
	 * being rejected. Pre-fix, $linecnt still incremented for every such row regardless, so
	 * an all-garbage feed classified as "valid" and WIPED a good prior whitelist -- the same
	 * dead-feed-wipe class as #886/#892/#920.
	 */
	public function testRankDomainRejectsDotlessDomainFieldPreservesPriorWhitelist(): void
	{
		// Given: a prior good whitelist and a Tranco/Cisco-shaped ('rank_domain' parse) feed
		// whose every row has a numeric rank column but a DOTLESS domain field -- each row's
		// LINE still carries a '.' and a ',' elsewhere, so it passes the line-level filter.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$csv = "1,garbage,extra.dot\n2,another,more.dots\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: rank_domain feed, dotless domain field');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When: the default descriptor resolves to Tranco's 'rank_domain' parse (domain_col 1).
		pfblockerng_top1m();

		// Then: every row is rejected by the domain-shape guard -- $linecnt never leaves 0 --
		// so the feed classifies as dead and the prior whitelist survives byte-identical.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a rank_domain feed with dotless domain fields must NOT wipe the previously-good TOP1M whitelist (#954)');
		$this->assertSame([], $this->tempFilesLeftBehind(), 'no temp build file left behind');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/**
	 * Issue #954 -- hostile-input sweep for the same rank_domain domain-field guard: each
	 * row below carries a numeric rank column (satisfies the rank-only check by itself) but
	 * a domain field that fails the hostname-shape regex in a different way. Every one must
	 * still be rejected now that the regex applies to rank_domain rows too.
	 */
	#[DataProvider('rankDomainHostileRows')]
	public function testRankDomainRejectsNonHostnameDomainFieldRow(string $csvLine): void
	{
		// Given: a prior good whitelist and a single-row rank_domain-shaped feed whose
		// domain field is hostile in one specific way (see the data provider).
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csvLine), "setup: hostile rank_domain row {$csvLine}");
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When
		pfblockerng_top1m();

		// Then: rejected by the domain-shape guard -- the feed classifies as dead, never a
		// whitelist write.
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			"a hostile rank_domain domain field ({$csvLine}) must NOT wipe the previously-good TOP1M whitelist (#954)");
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
	}

	/** @return array<string, array{string}> */
	public static function rankDomainHostileRows(): array
	{
		return [
			'empty domain field'                          => ["1,,x.y\n"],
			'numeric-shaped "TLD"'                         => ["1,foo.123,x.y\n"],
			'prose rank/domain, trailing-dot empty TLD'    => ["503, service unavailable.\n"],
			'unterminated-quoted domain field (#920 class)' => ["1,\"foo.com\n"],
			'leading-hyphen domain field'                  => ["1,-foo.com,x.y\n"],
		];
	}

	/**
	 * Issue #954 -- the hostname-shape regex newly applied to rank_domain rows must not
	 * regress its existing punycode-TLD acceptance (mirrors
	 * testCsvModeAcceptsPunycodeTldDomainIntoWhitelist for the 'csv' parse, issue #904).
	 * GREEN on both pre- and post-#954 code -- the rank_domain parse had no domain-field
	 * guard at all before this change, so it already accepted this row; this test only pins
	 * that the newly-added guard keeps accepting it (the red proof rides the two tests
	 * above).
	 */
	public function testRankDomainAcceptsPunycodeTldDomainIntoWhitelist(): void
	{
		// Given: a Tranco/Cisco-shaped ('rank_domain' parse) row whose domain ends in a
		// punycode TLD (xn--p1ai == .рф), and the TOP1M inclusion set names that exact TLD.
		$GLOBALS['pfb']['dnsbl_top1m_inc'] = 'xn--p1ai';
		$csv = "1,example.xn--p1ai\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: rank_domain punycode-TLD row');

		// When
		pfblockerng_top1m();

		// Then: the punycode-TLD row is counted as valid data and whitelisted -- not
		// wrongly dropped by the newly-applied hostname-shape guard.
		$this->assertSame(
			"example.xn--p1ai\n",
			file_get_contents($this->whitelistPath()),
			'a punycode TLD (xn--p1ai) rank_domain row must be accepted by the hostname-shape guard, not dropped'
		);
		$this->assertStringContainsString('Parsed 1 lines | Found 1 of 1000', $this->readMainLog());
	}
}
