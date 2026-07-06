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
 *
 * ADR-59 P2 addendum: pfblockerng_top1m() now drives header-skip/domain-column/the
 * numeric-rank guard from the active provider descriptor (pfb_top1m_providers()) instead
 * of a hardcoded rank,domain-at-column-1 shape.
 *   * a SYNTHETIC descriptor's header/domain_col knobs are honoured (below) -- no live
 *     non-Tranco/Cisco provider exists yet (ADR-59 Phase 4 adds one)
 *
 * ADR-59 P4 addendum: the two live non-Tranco/Cisco providers (DomCop, Majestic) added
 * by this phase -- their REAL sample shape parses correctly via the registered
 * descriptor, and a wrong domain_col genuinely mis-reads (fail-before/pass-after).
 *
 * ADR-59 P5 addendum: Cloudflare Radar (token-authenticated) parses its REAL shape too
 * (a single 'domain' column, no rank) -- this exposed a genuine latent bug the DomCop/
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
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got,
			'the domain must come from domain_col (index 2), and the header row must not count as data');
		$this->assertStringContainsString('Parsed 1 lines | Found 1 of 1000', $this->readMainLog());
	}

	/**
	 * ADR-59 P4 -- pfblockerng_top1m() parses Majestic Million's REAL CSV shape
	 * (12-col unquoted header, Domain at str_getcsv() index 2) via its registered
	 * provider descriptor (pfb_top1m_providers()[Top1mSource::Majestic->value]).
	 * Sample verified against the live downloads.majestic.com/majestic_million.csv
	 * format (fetched during development of this test).
	 *
	 * FAIL-BEFORE/PASS-AFTER: the BEFORE run reproduces the exact pre-ADR-59-Phase-2
	 * hardcoded shape -- pfblockerng_top1m(array()) resolves every knob to its
	 * default (parse=rank_domain, header=false, domain_col=1), precisely what every
	 * call site used before Phase 2 generalized the builder. Applied to Majestic's
	 * real layout, domain_col=1 reads the TldRank column (a bare digit, e.g. "1")
	 * as the "domain" instead of the real Domain field at index 2 -- neither digit
	 * contains a '.', so no TLD ever matches and the whitelist ends up EMPTY despite
	 * two real .com domains being present in the feed (RED). The AFTER run, using
	 * the actual registered Majestic descriptor (domain_col 2, header skipped),
	 * correctly extracts both domains (GREEN) -- proving domain_col is genuinely
	 * read from the descriptor, not hardcoded.
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

		// Then (RED): the real domains are misread as the numeric TldRank column;
		// neither matches a TLD (both rows still count as valid CSV lines -- the
		// rank_domain guard passes on the numeric GlobalRank column), so the
		// whitelist is replaced with EMPTY content, not "keeping previous".
		$this->assertSame('', file_get_contents($this->whitelistPath()),
			"the legacy col-1 parser must MIS-read Majestic's real shape -- Domain sits at index 2, not 1");
		$this->assertStringContainsString('Parsed 2 lines | Found 0 of 1000', $this->readMainLog());
		$this->assertStringContainsString('0 domains matched the configured TLD inclusions', $this->readMainLog());
		$this->assertStringNotContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());

		// Reset the log so the GREEN assertion below is unambiguous.
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['log'], ''), 'reset main log between runs');

		// When (AFTER): the actual registered Majestic descriptor.
		pfblockerng_top1m(pfb_top1m_providers()[Top1mSource::Majestic->value]);

		// Then (GREEN): both real domains are correctly extracted from index 2.
		$this->assertSame(
			".google.com,,\n,google.com,,\n,www.google.com,,\n.facebook.com,,\n,facebook.com,,\n,www.facebook.com,,\n",
			file_get_contents($this->whitelistPath()),
			'the registered Majestic descriptor must extract Domain from index 2'
		);
		$this->assertStringContainsString('Parsed 2 lines | Found 2 of 1000', $this->readMainLog());
	}

	/**
	 * ADR-59 P4 -- pfblockerng_top1m() parses DomCop's REAL CSV shape (quoted
	 * 3-col header, Domain at str_getcsv() index 1) via its registered provider
	 * descriptor. Sample verified against the live
	 * domcop.com/files/top/top10milliondomains.csv format (fetched during
	 * development of this test).
	 *
	 * DomCop's own Domain column happens to sit at the SAME index (1) the
	 * pre-Phase-2 legacy default already used, so replaying that legacy shape
	 * verbatim (as the Majestic test above does) would coincidentally still
	 * parse DomCop's real sample correctly -- on its own it would NOT prove
	 * domain_col is read from the descriptor rather than hardcoded. To still
	 * assert "the col index matters" for DomCop, this FAIL-BEFORE/PASS-AFTER
	 * instead probes a WRONG column for DomCop's shape (domain_col 2 -- the
	 * "Open Page Rank" field, Majestic's own domain_col) and shows it likewise
	 * mis-reads; the registered DomCop descriptor (domain_col 1) is correct.
	 *
	 * #892 review addendum: the wrong column's value ("10.00") also doesn't look
	 * like a hostname, so the domain-validity guard (finding 1) now rejects it as
	 * no-real-data rather than "valid data, zero TLD matches" -- the BEFORE
	 * assertions reflect that (no whitelist file at all, not an empty one).
	 */
	public function testDomCopRealShapeSampleMisreadsOnWrongColumnAndParsesCorrectlyViaItsDescriptor(): void
	{
		// Given: a real-shape DomCop sample -- quoted 3-col header, Domain at
		// index 1, two real '.com' domains matching the 'com' TLD inclusion.
		$csv = "\"Rank\",\"Domain\",\"Open Page Rank\"\n"
			. "\"1\",\"www.facebook.com\",\"10.00\"\n"
			. "\"2\",\"fonts.googleapis.com\",\"10.00\"\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: real-shape DomCop sample');

		// When (BEFORE): the WRONG column for this shape -- index 2 ("Open Page
		// Rank", a decimal string with no matching TLD, and no matching hostname shape).
		$wrongColumn = ['parse' => 'csv', 'header' => true, 'domain_col' => 2];
		pfblockerng_top1m($wrongColumn);

		// Then (RED): the real domains are misread as the Open Page Rank value
		// ("10.00"), which is neither a valid TLD match NOR a hostname-shaped value --
		// no whitelist can be built (none existed before this run).
		$this->assertFileDoesNotExist($this->whitelistPath(),
			"domain_col 2 must MIS-read DomCop's real shape -- Domain sits at index 1, not 2");
		$this->assertStringContainsString('no TOP1M whitelist available', $this->readMainLog());
		$this->assertStringNotContainsString('Parsed 2 lines', $this->readMainLog());

		// Reset the log so the GREEN assertion below is unambiguous.
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['log'], ''), 'reset main log between runs');

		// When (AFTER): the actual registered DomCop descriptor.
		pfblockerng_top1m(pfb_top1m_providers()[Top1mSource::DomCop->value]);

		// Then (GREEN): both real domains are correctly extracted from index 1
		// ('www.' stripped per the existing whitelist-building convention).
		$this->assertSame(
			".facebook.com,,\n,facebook.com,,\n,www.facebook.com,,\n"
			. ".fonts.googleapis.com,,\n,fonts.googleapis.com,,\n,www.fonts.googleapis.com,,\n",
			file_get_contents($this->whitelistPath()),
			'the registered DomCop descriptor must extract Domain from index 1'
		);
		$this->assertStringContainsString('Parsed 2 lines | Found 2 of 1000', $this->readMainLog());
	}

	/**
	 * ADR-59 P5 -- pfblockerng_top1m() parses Cloudflare Radar's REAL CSV shape (a
	 * SINGLE 'domain' column, no rank -- confirmed against Cloudflare's own docs during
	 * this phase, NOT the ADR's original 2-column guess) via its registered descriptor
	 * (domain_col 0, header skipped).
	 *
	 * Unlike the DomCop/Majestic column-index bug above, this shape exposed a DIFFERENT
	 * latent bug: the generic content filter demanded BOTH a '.' AND a ',' on every data
	 * line (a guard against a prose/error body that would otherwise reach the parser).
	 * A single-column CSV line has NO comma at all (nothing to delimit), so every one of
	 * Cloudflare's real data lines was silently skipped regardless of domain_col -- the
	 * whitelist came out EMPTY even though the fixture data is genuinely well-formed.
	 * FAIL-BEFORE/PASS-AFTER: manually verified by reverting just the comma-relaxation
	 * hunk in pfblockerng.inc (`git stash`) and re-running this exact test -- it goes RED
	 * (empty whitelist, same as the DomCop/Majestic BEFORE runs above); restoring the fix
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
		pfblockerng_top1m(pfb_top1m_providers()[Top1mSource::Cloudflare->value]);

		// Then: both real domains are correctly extracted from the single column despite
		// carrying no comma -- proves the comma-requirement relaxation for domain_col 0.
		$this->assertSame(
			".google.com,,\n,google.com,,\n,www.google.com,,\n.facebook.com,,\n,facebook.com,,\n,www.facebook.com,,\n",
			file_get_contents($this->whitelistPath()),
			'the registered Cloudflare descriptor must extract the single-column domain despite no comma in the data'
		);
		$this->assertStringContainsString('Parsed 2 lines | Found 2 of 1000', $this->readMainLog());
	}

	/**
	 * #892 review (finding 1) -- the #886 silent-whitelist-wipe must not re-open for the
	 * 'csv' parse providers (DomCop/Majestic/Cloudflare). Pre-fix, the domain-validity
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
	public function testDomCopGarbageHtmlBodyPreservesPriorWhitelistAndWarns(): void
	{
		// Given: a prior good whitelist and a multi-line HTML error body (a CDN 503 page,
		// NOT DomCop's real quoted rank/domain/pagerank CSV) written as top-1m.csv.
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$garbage = "<html><head><title>503 Backend fetch failed</title></head>\n"
			. "<body><h1>Error 503 Backend fetch failed</h1>\n"
			. "<p>Guru meditation, please retry. ref.12345</p></body></html>\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $garbage), 'setup: garbage HTML body as top-1m.csv');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		// When: the real registered DomCop descriptor drives the parse (header=TRUE skips
		// line 1; domain_col=1).
		pfblockerng_top1m(pfb_top1m_providers()[Top1mSource::DomCop->value]);

		// Then: the HTML body must never be mistaken for real DomCop CSV data -- the prior
		// whitelist survives byte-identical and the run warns instead of "succeeding".
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a garbage HTML body must NOT wipe the previously-good TOP1M whitelist (DomCop, #892 review)');
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
		pfblockerng_top1m(pfb_top1m_providers()[Top1mSource::Majestic->value]);

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
		pfblockerng_top1m(pfb_top1m_providers()[Top1mSource::Cloudflare->value]);

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
		pfblockerng_top1m(pfb_top1m_providers()[Top1mSource::Cloudflare->value]);

		// Then: the prior whitelist is untouched and a warning was logged (same generic
		// path as testAbsentCsvPreservesPriorWhitelistAndWarns).
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a missing top-1m.csv (failed Cloudflare download) must preserve the prior whitelist');
		$this->assertStringContainsString('TOP1M conversion Failed', $this->readErrLog());
	}
}
