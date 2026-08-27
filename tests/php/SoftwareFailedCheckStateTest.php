<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2674 — a catalogue refresh that FAILED must be distinguishable from one that
 * succeeded, at the read layer, on the cache, and on the Software page.
 *
 * The defect: `pkg update -f -r <repo>` ran with its return value discarded, so
 * pfb_pkg_latest() could not tell its caller whether the version it returned came from a
 * catalogue it had just refreshed or from a stale local DB — and a live read that produced
 * nothing left NO field on the cache document naming the failure. With the cron tick still
 * writing a good cache from a context where `pkg` works, the page rendered a version, an
 * "Up to date" verdict and a recent "Last checked" while its own forced check failed every
 * time. Probe on the pre-fix tree: a failed forced check added zero keys to the cache and
 * the page's display expressions were byte-identical to the success case.
 *
 * What must NOT change is issue #2379's fallback: a failed live read keeps the cached
 * `latest` rather than regressing it to '', and a benign deferral (pkg locked, no DNS) is
 * not a failure at all. Observability here is a STATE, never a raw `pkg` error dump.
 *
 * Branch map, so every side of every decision is pinned:
 *   read rule      refresh ok / refresh failed x rquery ok / rquery failed x version / none
 *   attempt state  succeeded (TRUE) / failed (FALSE) / not attempted (NULL)
 *   cache          record a failure / clear one on success / keep one across a skip /
 *                  never carry a foreign install's failure
 *   page           show the failed-attempt row / hide it / Check-now feedback both ways
 */
#[CoversFunction('pfb_pkg_read_ok')]
#[CoversFunction('pfb_pkg_latest')]
#[CoversFunction('pfb_software_update_check')]
#[CoversFunction('pfb_software_failed_at')]
#[CoversFunction('pfb_software_check_redirect')]
final class SoftwareFailedCheckStateTest extends TestCase
{
	/** The page whose handler + render wiring the reachability cases below read. */
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_software.php';

	/** The shipped orchestrator + read helpers, read by the wiring case below. */
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private const NAME = 'pfSense-pkg-pfBlockerNG';
	private const REPO = 'pfblockerng-nightly';

	/** Every key the software cache writer is allowed to store (issue #2674: a state, not a dump). */
	private const CACHE_KEYS = [
		'pkgname', 'repo', 'channel', 'installed', 'latest',
		'last_notified', 'last_checked', 'last_failed',
	];

	private string $dbdir = '';

	private bool $hadDbdir = FALSE;
	private mixed $savedDbdir = NULL;
	private bool $hadConfig = FALSE;
	private mixed $savedConfig = NULL;

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_2674_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
		$this->hadDbdir   = isset($GLOBALS['pfb']) && array_key_exists('dbdir', $GLOBALS['pfb']);
		$this->savedDbdir = $GLOBALS['pfb']['dbdir'] ?? NULL;
		$GLOBALS['pfb']['dbdir'] = $this->dbdir;

		$GLOBALS['pfb_test_file_notices']   = [];
		$GLOBALS['pfb_test_pkg_locked']     = FALSE;
		$GLOBALS['pfb_test_dns_available']  = TRUE;

		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [
			'installedpackages' => ['pfblockerng' => ['config' => [0 => ['pfb_software_check' => 'on']]]],
		];
	}

	protected function tearDown(): void
	{
		$file = $this->dbdir . '/software_update.json';
		if (is_file($file)) {
			unlink($file);
		}
		if (is_dir($this->dbdir)) {
			rmdir($this->dbdir);
		}
		unset(
			$GLOBALS['pfb_test_file_notices'],
			$GLOBALS['pfb_test_pkg_locked'],
			$GLOBALS['pfb_test_dns_available']
		);
		if ($this->hadDbdir) {
			$GLOBALS['pfb']['dbdir'] = $this->savedDbdir;
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	private function readCache(): ?array
	{
		$file = $this->dbdir . '/software_update.json';
		if (!is_file($file)) {
			return NULL;
		}
		$data = json_decode((string) file_get_contents($file), TRUE);
		return is_array($data) ? $data : NULL;
	}

	/**
	 * A cache exactly as a cron tick with a WORKING pkg leaves it: a known latest and a
	 * successful-check timestamp, no failure recorded. This is the state the field report
	 * describes — the page looks healthy because some other producer keeps it warm.
	 */
	private function seedCronWarmedCache(int $checkedAt = 1000, string $latest = '3.3.2'): array
	{
		pfb_software_write_cache([
			'pkgname'       => self::NAME,
			'repo'          => self::REPO,
			'channel'       => 'nightly',
			'installed'     => '3.3.2',
			'latest'        => $latest,
			'last_checked'  => $checkedAt,
			'last_notified' => '',
		]);
		$seeded = (array) $this->readCache();
		$this->assertArrayNotHasKey(
			'last_failed',
			$seeded,
			'before: a cron-warmed cache records no failed attempt'
		);
		return $seeded;
	}

	/** The orchestrator's documented $io seam, scoped to this install. */
	private function io(string $latest, ?bool $readOk = NULL, bool $withReadOk = TRUE): array
	{
		$io = [
			'installed_name' => self::NAME,
			'installed'      => '3.3.2',
			'installed_repo' => self::REPO,
			'record_channel' => 'nightly',
			'provenance_ok'  => TRUE,
			'latest'         => $latest,
		];
		if ($withReadOk) {
			$io['read_ok'] = $readOk;
		}
		return $io;
	}

	/*
	 * ---- The read rule: the catalogue refresh's return value is load-bearing ----
	 */

	/**
	 * The defect's direct oracle. `pkg update -f` exited non-zero, so the catalogue was
	 * NOT refreshed — but the stale local DB still answers rquery, so a version comes back.
	 * That version is the best value we have, and it is NOT a successful check: reporting it
	 * as one is exactly how a stale answer got presented as a fresh one.
	 *
	 * Asserts the success side first, so green proves the refresh rc — not the version —
	 * caused the verdict to flip.
	 */
	public function testAFailedRefreshIsNotASuccessfulReadEvenWhenTheStaleDbAnswers(): void
	{
		$this->assertTrue(
			pfb_pkg_read_ok(0, 0, '3.3.2'),
			'a refresh that succeeded and an rquery that named a version IS a successful read'
		);
		$this->assertFalse(
			pfb_pkg_read_ok(1, 0, '3.3.2'),
			'the SAME version off a catalogue that failed to refresh is NOT a successful read'
		);
	}

	/**
	 * The other two ways a live read fails, and the two versions of each: rquery itself
	 * exiting non-zero, and rquery exiting clean but naming nothing (repo present, package
	 * absent from the catalogue).
	 */
	public function testAFailedOrEmptyRqueryIsNotASuccessfulRead(): void
	{
		$this->assertFalse(pfb_pkg_read_ok(0, 1, ''), 'rquery failed and named nothing');
		$this->assertFalse(pfb_pkg_read_ok(0, 1, '3.3.2'), 'rquery failed, so what it printed is not trusted');
		$this->assertFalse(pfb_pkg_read_ok(0, 0, ''), 'rquery clean but the catalogue names no version');
		$this->assertFalse(pfb_pkg_read_ok(1, 1, ''), 'both calls failed — the field report shape');
	}

	/**
	 * pfb_pkg_latest() reports the outcome to its CALLER, which it previously could not:
	 * off-appliance there is no /usr/local/sbin/pkg, so both calls exit non-zero and the
	 * attempt is a recorded FAILURE rather than an indistinguishable empty string.
	 */
	public function testPkgLatestReportsAFailedAttemptToItsCaller(): void
	{
		$readOk = NULL;
		$latest = pfb_pkg_latest(self::NAME, self::REPO, $readOk);

		$this->assertSame('', $latest, 'no pkg binary here, so no version can be read');
		$this->assertFalse($readOk, 'and the caller is TOLD the attempt failed, not just handed an empty string');
	}

	/**
	 * The benign side, which #2379 established and #2674 must not turn into a scary page:
	 * a deliberate deferral is NOT a failed attempt. pkg locked (never fight a base update),
	 * no DNS (never stall on a network read) and an unnamed package/repo all leave the
	 * outcome UNDECIDED (NULL) so nothing is recorded against them.
	 */
	public function testADeliberateDeferralIsNotAFailedAttempt(): void
	{
		$GLOBALS['pfb_test_pkg_locked'] = TRUE;
		$readOk = TRUE;
		$this->assertSame('', pfb_pkg_latest(self::NAME, self::REPO, $readOk), 'locked: no read');
		$this->assertNull($readOk, 'pkg locked is a deferral, not a failure');

		$GLOBALS['pfb_test_pkg_locked'] = FALSE;
		$GLOBALS['pfb_test_dns_available'] = FALSE;
		$readOk = TRUE;
		$this->assertSame('', pfb_pkg_latest(self::NAME, self::REPO, $readOk), 'no DNS: no read');
		$this->assertNull($readOk, 'no DNS is a deferral, not a failure');

		$GLOBALS['pfb_test_dns_available'] = TRUE;
		$readOk = TRUE;
		$this->assertSame('', pfb_pkg_latest('', self::REPO, $readOk), 'no package name: no read');
		$this->assertNull($readOk, 'an unnamed package was never attempted');
	}

	/**
	 * The wiring the off-appliance case above cannot isolate: pfb_pkg_latest() must CAPTURE
	 * the refresh return value and feed it to the read rule, and both `pkg` calls must keep
	 * their stderr redirected so no `pkg` diagnostic can ever reach the page (issue #2674:
	 * observability is a state, not an error dump).
	 */
	public function testPkgLatestCapturesBothReturnValuesAndKeepsPkgStderrOffThePage(): void
	{
		$src = (string) file_get_contents(self::INC);
		$start = strpos($src, 'function pfb_pkg_latest(');
		$this->assertNotFalse($start, 'pfb_pkg_latest must exist');
		$body = substr($src, $start, (int) strpos($src, "\n}\n", $start) - $start);

		$this->assertMatchesRegularExpression(
			'/update -f -r \{\$repo\} 2>\/dev\/null",\s*\$refresh_out,\s*\$refresh_ret\)/',
			$body,
			'the catalogue refresh must capture its return value, not discard it'
		);
		$this->assertStringContainsString(
			'pfb_pkg_read_ok($refresh_ret, $ret, $latest)',
			$body,
			'both captured return values must reach the read rule'
		);
		$this->assertSame(
			2,
			substr_count($body, '2>/dev/null'),
			'both pkg calls keep stderr redirected — no pkg diagnostic may reach the page'
		);
	}

	/*
	 * ---- The cache records the outcome of the last attempt ----
	 */

	/**
	 * Scenario: the field report. A cron tick from a context where `pkg` works left a good
	 * cache; the page's forced Check now runs in a context where it does not.
	 *
	 * Given a cron-warmed cache with a known latest and a successful-check time,
	 * When a forced check's live read fails,
	 * Then the cache records the failed attempt, keeps the cached latest (#2379), and does
	 *      NOT advance the successful-check time.
	 */
	public function testAFailedCheckRecordsTheFailedAttemptOnTheCache(): void
	{
		$this->seedCronWarmedCache();

		$before = time();
		$cache = pfb_software_update_check(TRUE, $this->io('', FALSE));

		$this->assertArrayHasKey('last_failed', $cache, 'after: the failed attempt must be recorded');
		$this->assertGreaterThanOrEqual($before, (int) $cache['last_failed'], 'recorded at attempt time');
		$this->assertSame('3.3.2', $cache['latest'], 'the last-known latest must not regress (issue #2379)');
		$this->assertSame(1000, $cache['last_checked'], 'a failed attempt is not a successful check');
		$this->assertSame($cache, $this->readCache(), 'the state reached disk, not just the return value');
	}

	/**
	 * The stale-catalogue near-miss, at the orchestrator: the refresh failed but the stale
	 * DB named a version. The version is adopted (it is newer information than the cache),
	 * and the successful-check time still does not move — otherwise the page reports
	 * "Last checked: just now" beside an answer nothing refreshed.
	 */
	public function testAStaleCatalogueReadDoesNotAdvanceTheSuccessfulCheckTime(): void
	{
		$this->seedCronWarmedCache(1000, '3.3.2');

		$cache = pfb_software_update_check(TRUE, $this->io('3.3.4', FALSE));

		$this->assertSame('3.3.4', $cache['latest'], 'the version that was read is still reported');
		$this->assertSame(1000, $cache['last_checked'], 'but a failed refresh is not a successful check');
		$this->assertArrayHasKey('last_failed', $cache, 'and the failed attempt is recorded');
	}

	/**
	 * Transition: a recorded failure is transient state, not a sticky label. Asserts the
	 * failure is present FIRST, so green proves the successful check cleared it.
	 */
	public function testASuccessfulCheckClearsARecordedFailure(): void
	{
		$this->seedCronWarmedCache();
		$failed = pfb_software_update_check(TRUE, $this->io('', FALSE));
		$this->assertArrayHasKey('last_failed', $failed, 'before: a failure is on the cache');

		$before = time();
		$cache = pfb_software_update_check(TRUE, $this->io('3.3.2', TRUE));

		$this->assertArrayNotHasKey('last_failed', $cache, 'after: a successful check clears the failure');
		$this->assertGreaterThanOrEqual($before, (int) $cache['last_checked'], 'and advances the successful-check time');
		$this->assertSame($cache, $this->readCache(), 'the cleared state reached disk');
	}

	/**
	 * A deferral neither invents a failure nor erases the one that stands. pkg locked is
	 * the real short-circuit (no injected latest), so this drives the shipped
	 * pfb_pkg_latest() guard rather than the $io seam.
	 */
	public function testADeferredTickNeitherInventsNorErasesAFailure(): void
	{
		$this->seedCronWarmedCache();

		// A deferral on a clean cache records nothing.
		$GLOBALS['pfb_test_pkg_locked'] = TRUE;
		$clean = pfb_software_update_check(FALSE, [
			'installed_name' => self::NAME,
			'installed'      => '3.3.2',
			'installed_repo' => self::REPO,
			'record_channel' => 'nightly',
			'provenance_ok'  => TRUE,
		]);
		$this->assertArrayNotHasKey('last_failed', $clean, 'a deferral is not a failure');
		$this->assertSame(1000, $clean['last_checked'], 'and does not advance the successful-check time');

		// A real failure, then a deferral: the failure that stands is preserved.
		$GLOBALS['pfb_test_pkg_locked'] = FALSE;
		$failed = pfb_software_update_check(TRUE, $this->io('', FALSE));
		$recorded = (int) $failed['last_failed'];
		$this->assertGreaterThan(0, $recorded, 'before: a failure is recorded');

		$GLOBALS['pfb_test_pkg_locked'] = TRUE;
		$deferred = pfb_software_update_check(FALSE, [
			'installed_name' => self::NAME,
			'installed'      => '3.3.2',
			'installed_repo' => self::REPO,
			'record_channel' => 'nightly',
			'provenance_ok'  => TRUE,
		]);
		$this->assertSame($recorded, (int) $deferred['last_failed'], 'after: the standing failure is kept, not rewritten');
	}

	/**
	 * A failure belongs to the install it happened on. The Software page trusts cache values
	 * only while they describe the CURRENT install, and the orchestrator rescopes the cache
	 * on a change — so a failure left by a previous catalogue must not be carried into the
	 * rescoped document and shown against the new one (the issue #2148 rule, applied to the
	 * new field).
	 */
	public function testAFailureFromAnotherInstallIsNotCarriedForward(): void
	{
		pfb_software_write_cache([
			'pkgname'      => self::NAME,
			'repo'         => 'pfblockerng-stable',
			'channel'      => 'stable',
			'installed'    => '3.3.0',
			'latest'       => '3.3.0',
			'last_checked' => 500,
			'last_failed'  => 600,
		]);
		$this->assertSame(600, $this->readCache()['last_failed'], 'before: the stable install recorded a failure');

		// Same package name, now on the nightly catalogue, and this tick is DEFERRED, so
		// nothing about this install failed yet.
		$GLOBALS['pfb_test_pkg_locked'] = TRUE;
		$cache = pfb_software_update_check(FALSE, [
			'installed_name' => self::NAME,
			'installed'      => '3.3.2',
			'installed_repo' => self::REPO,
			'record_channel' => 'nightly',
			'provenance_ok'  => TRUE,
		]);

		$this->assertSame(self::REPO, $cache['repo'], 'the cache is rescoped to the current install');
		$this->assertArrayNotHasKey(
			'last_failed',
			$cache,
			"the previous catalogue's failure must not be shown against this install"
		);
	}

	/**
	 * Observability is a STATE, never a raw `pkg` error dump: the document a failed attempt
	 * leaves carries only known scalar fields, so no captured stderr or command output can
	 * ride to the page inside the cache.
	 */
	public function testAFailedAttemptWritesAStateNotAnErrorDump(): void
	{
		$this->seedCronWarmedCache();
		$cache = pfb_software_update_check(TRUE, $this->io('', FALSE));

		$this->assertArrayHasKey('last_failed', $cache, 'the failure is recorded as a timestamp field');
		$this->assertSame(
			[],
			array_diff(array_keys($cache), self::CACHE_KEYS),
			'a failed attempt introduces no field outside the known cache shape'
		);
		foreach ($cache as $key => $value) {
			$this->assertIsScalar($value, "cache field '{$key}' must be a scalar state, not captured output");
		}
	}

	/*
	 * ---- The Software page: the state the admin sees ----
	 */

	/**
	 * The page's failed-attempt gate. A recorded failure surfaces only while the cache
	 * describes the install the box carries now, and a garbage or absent value shows
	 * nothing rather than a 1970 timestamp.
	 */
	public function testTheFailedAttemptRowIsGatedOnTheCurrentInstall(): void
	{
		$this->assertSame(1700000000, pfb_software_failed_at(['last_failed' => 1700000000], TRUE));
		$this->assertSame(0, pfb_software_failed_at(['last_failed' => 1700000000], FALSE), 'a foreign cache shows nothing');
		$this->assertSame(0, pfb_software_failed_at([], TRUE), 'no recorded failure, no row');
		$this->assertSame(0, pfb_software_failed_at(['last_failed' => ''], TRUE), 'an empty value is not a failure');
		$this->assertSame(0, pfb_software_failed_at(['last_failed' => 'yesterday'], TRUE), 'a non-numeric value shows nothing');
		$this->assertSame(0, pfb_software_failed_at(['last_failed' => ['x']], TRUE), 'a non-scalar value shows nothing');
		$this->assertSame(0, pfb_software_failed_at(['last_failed' => 0], TRUE), 'a zero timestamp is not a failure');
	}

	/**
	 * Check now must not redirect an admin who explicitly asked for a fresh answer back to
	 * an unchanged page. Both branches, plus the round trip: the query the failure redirect
	 * carries is the one the page's render arm reads, so a rename on either side is caught.
	 */
	public function testCheckNowReportsAForcedRefreshThatFailed(): void
	{
		$this->assertSame(
			'/pfblockerng/pfblockerng_software.php',
			pfb_software_check_redirect(TRUE),
			'a check that worked redirects to the plain page'
		);

		$failed = pfb_software_check_redirect(FALSE);
		$this->assertSame(
			'/pfblockerng/pfblockerng_software.php?check=failed',
			$failed,
			'a check that failed redirects carrying feedback'
		);

		$query = [];
		parse_str((string) parse_url($failed, PHP_URL_QUERY), $query);
		$page = (string) file_get_contents(self::PAGE);
		$this->assertStringContainsString(
			"(\$_GET['check'] ?? '') === '" . $query['check'] . "'",
			$page,
			'the page must read back the exact token its own failure redirect writes'
		);
	}

	/**
	 * The page wiring, read out of the page rather than assumed.
	 *
	 * LIMITATION, established by execution and shared with issue #2525: the page's top level
	 * cannot run under this harness at all — including it after tests/php/bootstrap.php exits
	 * 255 at require_once('guiconfig.inc'), before any page logic, and the sibling page
	 * loaders sidestep that deliberately by eval()ing function definitions only. So these
	 * assertions prove the wiring TEXT, not its reachability: an inverted condition is caught
	 * because the branch's opening line is pinned, but a rewrite that keeps the sequence and
	 * makes it unreachable (inside a dead `if (FALSE)`, after an unconditional exit) survives
	 * them. Harness work to close that gap is issue #2768. The executable proof for this
	 * behaviour is the four cases above, which drive the functions the page calls; the LIVE
	 * proof is tests/smoke/ui (Tier A renders the failed-attempt row off a seeded cache;
	 * Tier B drives the ?check=failed feedback in a browser).
	 */
	public function testThePageDrivesTheExtractedHelpers(): void
	{
		$page = (string) file_get_contents(self::PAGE);

		$handler = strpos($page, "if (\$pfb_sw_action === 'check') {");
		$this->assertNotFalse($handler, 'the Check now handler must still be the page entry point');
		$block = substr($page, $handler, (int) strpos($page, 'exit;', $handler) - $handler);
		$this->assertStringContainsString(
			'pfb_software_update_check(TRUE)',
			$block,
			'Check now still forces the check'
		);
		$this->assertStringContainsString(
			'pfb_software_check_redirect(',
			$block,
			'and routes its outcome through the redirect helper instead of discarding it'
		);

		$this->assertStringContainsString(
			'pfb_software_failed_at(',
			$page,
			'the Status section must gate the failed-attempt row on the shared helper'
		);
		$this->assertMatchesRegularExpression(
			'/print_info_box\(\s*gettext\(/',
			$page,
			'the Check now feedback renders through the house warning box'
		);
		$this->assertStringContainsString(
			"'warning'",
			$page,
			'a failed forced check is a warning, not a silent redisplay'
		);
	}
}
