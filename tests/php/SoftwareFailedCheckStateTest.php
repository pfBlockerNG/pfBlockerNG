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
 * not a failure at all. Observability here is a STATE, never a raw `pkg` error dump. And a
 * read that FAILED contributes no version at all: promoting the stale catalogue's answer
 * would let the cron notice announce an update off a catalogue nothing refreshed.
 *
 * Branch map, so every side of every decision is pinned:
 *   read rule      refresh ok / refresh failed x rquery ok / rquery failed x version / none
 *   attempt state  succeeded (TRUE) / failed (FALSE) / not attempted (NULL) / uninterpretable
 *   version        promoted only on a successful read; cached kept otherwise; never a
 *                  stale-catalogue answer, and never a notice naming one
 *   cache          record a failure / clear one on success / keep one across a skip /
 *                  never carry a foreign install's failure
 *   timestamps     a plain epoch renders; negative, future, oversized, non-finite and
 *                  non-decimal values render nothing, silently
 *   page           show the failed-attempt row / hide it / Check-now feedback keyed on THIS
 *                  attempt's outcome, both ways, never on the cache's history
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

	/** The Tier-A module, read for the phrase both live tiers key on (issue #2674). */
	private const TIER_A = __DIR__ . '/../smoke/ui/test_render_smoke.py';

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
	 * with no pkg(8) to run, both calls exit non-zero and the attempt is a recorded FAILURE
	 * rather than an indistinguishable empty string.
	 *
	 * This drives the real shellout, so it asserts a fixed outcome only where that shellout
	 * cannot succeed. On a host that carries the port binary the result depends on that
	 * host's repository configuration, which is not this case's subject: it skips there
	 * rather than reporting a red for an environment difference.
	 */
	public function testPkgLatestReportsAFailedAttemptToItsCaller(): void
	{
		if (is_executable(PFB_PKG_BIN)) {
			$this->markTestSkipped(
				'host carries ' . PFB_PKG_BIN . ' — the live read outcome is then repository state, not this rule'
			);
		}

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

		// The rc variable is pinned; the output buffer is not, because the two calls may
		// legitimately share one (pfb_pkg_exec() clears it at entry) and its name is not
		// the thing that has to hold.
		$this->assertMatchesRegularExpression(
			'/update -f -r \{\$repo\} 2>\/dev\/null",\s*\$\w+,\s*\$refresh_ret\)/',
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
	 * DB named a version. The successful-check time does not move, and the version is NOT
	 * adopted — a catalogue nothing refreshed cannot produce a new "latest".
	 */
	public function testAStaleCatalogueReadDoesNotAdvanceTheSuccessfulCheckTime(): void
	{
		$this->seedCronWarmedCache(1000, '3.3.2');

		$cache = pfb_software_update_check(TRUE, $this->io('3.3.4', FALSE));

		$this->assertSame('3.3.2', $cache['latest'], 'the last SUCCESSFULLY read version still stands');
		$this->assertSame(1000, $cache['last_checked'], 'a failed refresh is not a successful check');
		$this->assertArrayHasKey('last_failed', $cache, 'and the failed attempt is recorded');
	}

	/**
	 * Scenario: the field report's near-miss, followed all the way to the notice.
	 *
	 * `pkg update -f` exits non-zero, the stale catalogue DB still answers rquery, and what
	 * it answers is NEWER than the last version a successful read produced. Promoting that
	 * would make the page announce — and the cron file_notice ANNOUNCE BY EMAIL — an update
	 * read off a catalogue nothing refreshed. A read that failed contributes no version.
	 *
	 * Given a cache holding the last successfully read latest, already notified,
	 * When a forced check's refresh fails but the stale DB names a newer version,
	 * Then the cached latest and de-dupe state both stand, and NO notice fires.
	 */
	public function testAFailedRefreshNeverPromotesAStaleCatalogueVersion(): void
	{
		pfb_software_write_cache([
			'pkgname'       => self::NAME,
			'repo'          => self::REPO,
			'channel'       => 'nightly',
			'installed'     => '3.3.2',
			'latest'        => '3.3.2',
			'last_checked'  => 1000,
			'last_notified' => '3.3.2',
		]);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'before: no notice raised');

		$cache = pfb_software_update_check(TRUE, $this->io('3.3.4', FALSE));

		$this->assertSame('3.3.2', $cache['latest'], 'a version off an unrefreshed catalogue is not promoted');
		$this->assertSame('3.3.2', $cache['last_notified'], 'and cannot rewrite the de-dupe state');
		$this->assertSame(
			[],
			$GLOBALS['pfb_test_file_notices'],
			'after: a failed refresh must never announce a version it could not verify'
		);
		$this->assertSame(1000, $cache['last_checked'], 'and is not a successful check');
		$this->assertArrayHasKey('last_failed', $cache, 'the failure itself is what gets recorded');
	}

	/**
	 * The same rule where the update is genuinely un-notified: the notice may still fire for
	 * the last SUCCESSFULLY read version, but never for the stale one. Asserts the notice
	 * text, so a promotion that slipped through would be visible rather than merely counted.
	 */
	public function testANoticeAfterAFailedRefreshNamesOnlyTheVerifiedVersion(): void
	{
		pfb_software_write_cache([
			'pkgname'       => self::NAME,
			'repo'          => self::REPO,
			'channel'       => 'nightly',
			'installed'     => '3.3.0',
			'latest'        => '3.3.2',
			'last_checked'  => 1000,
			'last_notified' => '',
		]);

		$cache = pfb_software_update_check(TRUE, [
			'installed_name' => self::NAME,
			'installed'      => '3.3.0',
			'installed_repo' => self::REPO,
			'record_channel' => 'nightly',
			'provenance_ok'  => TRUE,
			'latest'         => '3.3.4',
			'read_ok'        => FALSE,
		]);

		$this->assertSame('3.3.2', $cache['latest'], 'the verified version is what is reported');
		// A notice MUST fire here, or the loop below would assert nothing: installed 3.3.0 is
		// older than the cached 3.3.2 and nothing has been notified yet.
		$this->assertCount(
			1,
			$GLOBALS['pfb_test_file_notices'],
			'the un-notified update from the last successful read is still announced'
		);
		$this->assertStringContainsString(
			'3.3.2 available',
			$GLOBALS['pfb_test_file_notices'][0]['notice'],
			'and it names the version a successful read produced'
		);
		foreach ($GLOBALS['pfb_test_file_notices'] as $notice) {
			$this->assertStringNotContainsString(
				'3.3.4',
				$notice['notice'],
				'no notice may name a version read off a catalogue that failed to refresh'
			);
		}
	}

	/**
	 * A contradictory injected outcome fails CLOSED. The $io seam takes an explicit outcome;
	 * anything that is not a bool names no outcome, and a version paired with no outcome
	 * must not be promoted, timestamped or notified as if the read had succeeded.
	 */
	public function testAnUninterpretableInjectedOutcomeFailsClosed(): void
	{
		foreach ([['x'], 'false', 0, 1.0] as $bogus) {
			$this->seedCronWarmedCache(1000, '3.3.2');
			$cache = pfb_software_update_check(TRUE, [
				'installed_name' => self::NAME,
				'installed'      => '3.3.2',
				'installed_repo' => self::REPO,
				'record_channel' => 'nightly',
				'provenance_ok'  => TRUE,
				'latest'         => '3.3.4',
				'read_ok'        => $bogus,
			]);
			$label = gettype($bogus);
			$this->assertSame('3.3.2', $cache['latest'], "{$label}: no promotion without a stated outcome");
			$this->assertSame(1000, $cache['last_checked'], "{$label}: and no successful-check time");
			$this->assertSame([], $GLOBALS['pfb_test_file_notices'], "{$label}: and no notice");
			@unlink($this->dbdir . '/software_update.json');
		}
	}

	/**
	 * Check now's feedback describes THIS attempt, never the cache's history.
	 *
	 * The cache deliberately keeps a standing failure across a deferral, so reading the
	 * feedback off the cache made an identical deferral report "failed" or "fine" depending
	 * only on what a previous tick had recorded. The outcome of the attempt just made is a
	 * separate value.
	 *
	 * Given a cache that already records a failure,
	 * When a forced check DEFERS (pkg locked — nothing failed now),
	 * Then Check now redirects clean;
	 * And when a forced check actually fails,
	 * Then it redirects carrying feedback.
	 */
	public function testCheckNowFeedbackFollowsThisAttemptNotTheCachedHistory(): void
	{
		$this->seedCronWarmedCache();
		pfb_software_update_check(TRUE, $this->io('', FALSE));
		$this->assertArrayHasKey(
			'last_failed',
			(array) $this->readCache(),
			'before: a failure from an earlier tick stands on the cache'
		);

		// A deferral now: the standing failure is preserved, but nothing failed THIS time.
		$GLOBALS['pfb_test_pkg_locked'] = TRUE;
		$deferred_ok = TRUE;
		pfb_software_update_check(TRUE, [
			'installed_name' => self::NAME,
			'installed'      => '3.3.2',
			'installed_repo' => self::REPO,
			'record_channel' => 'nightly',
			'provenance_ok'  => TRUE,
		], $deferred_ok);
		$this->assertNull($deferred_ok, 'a deferred check reports no outcome');
		$this->assertSame(
			'/pfblockerng/pfblockerng_software.php',
			pfb_software_check_redirect($deferred_ok !== FALSE),
			'so Check now must not claim the check failed'
		);

		// A real failure now: the same call reports it, and the redirect carries feedback.
		$GLOBALS['pfb_test_pkg_locked'] = FALSE;
		$failed_ok = TRUE;
		pfb_software_update_check(TRUE, $this->io('', FALSE), $failed_ok);
		$this->assertFalse($failed_ok, 'a failed check reports its outcome');
		$this->assertSame(
			'/pfblockerng/pfblockerng_software.php?check=failed',
			pfb_software_check_redirect($failed_ok !== FALSE),
			'and Check now says so'
		);
	}

	/**
	 * The reported outcome is reset at ENTRY, so a caller reusing a by-ref variable can never
	 * read a previous call's answer. Two gates return before any catalogue read — a build that
	 * cannot show the page, and background checking switched off without a force — and on both
	 * of those paths nothing was attempted, which is NULL rather than whatever the caller
	 * happened to be holding. Each arm pre-sets the variable TRUE so the reset has to do work.
	 */
	public function testAGateThatRefusesBeforeAnyReadReportsNoOutcome(): void
	{
		$io = [
			'installed_name' => self::NAME,
			'installed'      => '3.3.2',
			'installed_repo' => self::REPO,
			'record_channel' => 'nightly',
			'provenance_ok'  => FALSE,
			'latest'         => '3.3.4',
			'read_ok'        => TRUE,
		];
		$read_ok = TRUE;
		pfb_software_update_check(TRUE, $io, $read_ok);
		$this->assertNull($read_ok, 'a build that cannot show the page attempted no read');

		// The other early return: checking disabled and not forced.
		$GLOBALS['config'] = [
			'installedpackages' => ['pfblockerng' => ['config' => [0 => ['pfb_software_check' => '']]]],
		];
		$io['provenance_ok'] = TRUE;
		$read_ok = TRUE;
		pfb_software_update_check(FALSE, $io, $read_ok);
		$this->assertNull($read_ok, 'a disabled background check attempted no read');

		// And the control: with both gates open the same call DOES report an outcome, so the
		// two assertions above are about the gates and not about an out-param nobody writes.
		$read_ok = NULL;
		pfb_software_update_check(TRUE, $io, $read_ok);
		$this->assertTrue($read_ok, 'with the gates open the read outcome is reported');
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
	 * A timestamp this box cannot have recorded shows nothing, and says nothing doing it.
	 *
	 * The cache is a JSON file, so `last_failed` can arrive as a hand-edited negative, a
	 * scientific-notation string, or an integer too large for a PHP int — which json_decode
	 * hands back as a FLOAT. Casting one of those emits "not representable as an int" into
	 * php_error.log (which the UI tiers read as a page defect, issue #2367) and PHP_INT_MAX
	 * renders a year-292277 date in the Status section. Warnings are CAPTURED rather than
	 * converted, so the assertion is about what the helper emitted and not merely that it
	 * did not throw.
	 */
	public function testTheFailedAttemptRowRefusesATimeThisBoxCannotHaveRecorded(): void
	{
		$cases = [
			'a negative timestamp'          => -1,
			'the integer ceiling'           => PHP_INT_MAX,
			'a far-future time'             => time() + 86400 * 365,
			'an oversized JSON integer'     => 1.0e54,
			'a non-finite float'            => NAN,
			'an infinite float'             => INF,
			'scientific notation'           => '1e5',
			'a negative decimal string'     => '-1',
			'a fractional string'           => '1700000000.5',
			'a whitespace-padded number'    => ' 1700000000 ',
			// PCRE's $ matches before a final newline, so a regex-based digit test accepts
			// this; the house ctype_digit() convention does not.
			'a trailing newline'            => "1700000000\n",
			'an oversized decimal string'   => '99999999999999999999999999',
			'a boolean'                     => TRUE,
		];

		foreach ($cases as $label => $value) {
			$seen = [];
			set_error_handler(static function (int $errno, string $msg) use (&$seen): bool {
				$seen[] = $msg;
				return TRUE;
			});
			try {
				$at = pfb_software_failed_at(['last_failed' => $value], TRUE);
			} finally {
				restore_error_handler();
			}
			$this->assertSame(0, $at, "{$label} must show no failed-attempt row");
			$this->assertSame([], $seen, "{$label} must reach that verdict silently");
		}

		// The branch that must keep working: a plain epoch this box could have recorded.
		$this->assertSame(1700000000, pfb_software_failed_at(['last_failed' => 1700000000], TRUE));
		$this->assertSame(
			1700000000,
			pfb_software_failed_at(['last_failed' => '1700000000'], TRUE),
			'a decimal integer string is the same time (json_decode can hand back either)'
		);
	}

	/**
	 * The phrase the UI tiers key on must identify the Check-now feedback and NOTHING ELSE
	 * on the page.
	 *
	 * The page says two things about a failed read: the info box is about the action the
	 * admin just took, the Status row is about standing state. Both tiers assert "the plain
	 * page does not carry the Check-now feedback" by searching the rendered HTML for one
	 * phrase, so a phrase the Status row ALSO contains makes that assertion trip on the row
	 * and report a defect that is not there.
	 *
	 * This reads the tier's own constant rather than a phrase of its own, because the
	 * coupling is the whole point: it is the tier's chosen string that has to discriminate,
	 * and a hermetic gate settles it without a live-VM round trip.
	 */
	public function testTheUiTiersFeedbackPhraseMatchesOnlyTheCheckNowBox(): void
	{
		$tier = (string) file_get_contents(self::TIER_A);
		$phrase = $this->pageString($tier, '_SOFTWARE_CHECK_FAILED_TEXT = "', '"');
		$this->assertNotSame('', $phrase, 'the Tier-A module must define the feedback phrase');

		$page = (string) file_get_contents(self::PAGE);
		$this->assertSame(
			1,
			substr_count($page, $phrase),
			"the tiers key on '{$phrase}', which must appear EXACTLY once in the page — the "
				. 'Status row restating it makes the plain-load assertion trip on the row'
		);

		// And the one occurrence is the info box, not something else that happens to match.
		$box = $this->pageString($page, "print_info_box(gettext('", "')");
		$this->assertStringContainsString(
			$phrase,
			$box,
			'the single occurrence must be the Check now info box itself'
		);

		$row = $this->pageString($page, "))->setHelp('The most recent version check", "');");
		$this->assertNotSame('', $row, 'the failed-attempt row must still carry its own help text');
		$this->assertStringNotContainsString(
			$phrase,
			$row,
			'the failed-attempt row must say its own thing, not restate the Check-now feedback'
		);
	}

	/** The literal between $open and the next $close in $src, or '' when absent. */
	private function pageString(string $src, string $open, string $close): string
	{
		$at = strpos($src, $open);
		if ($at === FALSE) {
			return '';
		}
		$from = $at + strlen($open);
		$end = strpos($src, $close, $from);
		return ($end === FALSE) ? '' : substr($src, $from, $end - $from);
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
	 * assertions prove the wiring TEXT, not its reachability. Precisely: every branch below
	 * has its OPENING LINE pinned, so inverting one of those conditions is caught; a rewrite
	 * that keeps the whole sequence and makes it unreachable — inside a dead `if (FALSE)`,
	 * after an unconditional exit — is NOT, and neither is a row that renders the wrong
	 * value. Harness work to close that gap is issue #2768. The executable proof for this
	 * behaviour is the cases above, which drive the functions the page calls; the LIVE proof
	 * is tests/smoke/ui — Tier A renders the failed-attempt row off a seeded cache and
	 * asserts its time differs from the last successful check's (which catches the
	 * wrong-value class), Tier B drives the ?check=failed feedback in a browser.
	 */
	public function testThePageDrivesTheExtractedHelpers(): void
	{
		$page = (string) file_get_contents(self::PAGE);

		$handler = strpos($page, "if (\$pfb_sw_action === 'check') {");
		$this->assertNotFalse($handler, 'the Check now handler must still be the page entry point');
		$block = substr($page, $handler, (int) strpos($page, 'exit;', $handler) - $handler);
		$this->assertStringContainsString(
			'pfb_software_update_check(TRUE',
			$block,
			'Check now still forces the check'
		);
		$this->assertStringContainsString(
			'pfb_software_check_redirect(',
			$block,
			'and routes its outcome through the redirect helper instead of discarding it'
		);
		$this->assertStringContainsString(
			'$pfb_sw_read_ok',
			$block,
			"and the outcome it routes is THIS attempt's, not the cache's history"
		);

		$this->assertStringContainsString(
			'$failed_at	= pfb_software_failed_at($cache, $cache_current);',
			$page,
			'the Status section must derive the failed-attempt time from the shared helper'
		);
		$this->assertStringContainsString(
			'if ($failed_at > 0) {',
			$page,
			'and gate the row on it — a gate rewritten to a constant renders the row never'
		);
		// Scoped to the feedback arm, not searched page-wide: the page happens to carry
		// exactly one print_info_box and one 'warning' today, so a page-wide search still
		// fails on a regression -- but it would go quietly vacuous the moment a second
		// info box is added anywhere on the page.
		$feedback_at = strpos($page, "(\$_GET['check'] ?? '') === 'failed'");
		$this->assertNotFalse($feedback_at, 'the failure token must gate the feedback box');
		$feedback = substr($page, $feedback_at, (int) strpos($page, "\n}\n", $feedback_at) - $feedback_at);
		$this->assertMatchesRegularExpression(
			'/print_info_box\(\s*gettext\(/',
			$feedback,
			'the Check now feedback renders through the house warning box'
		);
		$this->assertStringContainsString(
			"'warning'",
			$feedback,
			'a failed forced check is a warning, not a silent redisplay'
		);
	}
}
