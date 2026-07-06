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
 * "Parsed 0 lines" line. Fix: build into a temp file, and only swap it into place when
 * the parse actually found usable source lines; otherwise discard the temp and warn
 * (level 2) that the previous whitelist was kept.
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
		foreach ((array) (@glob("{$this->dbdir}/*") ?: []) as $f) {
			@unlink($f);
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
		$this->assertFileDoesNotExist("{$this->whitelistPath()}.tmp", 'no temp build file left behind');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
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
		$this->assertFileDoesNotExist("{$this->whitelistPath()}.tmp", 'no temp build file left behind');
		$this->assertStringContainsString('Parsed 3 lines | Found 1 of 1000', $this->readMainLog());
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
