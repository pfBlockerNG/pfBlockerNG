<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1173 — a config save that merely REORDERS IPv4/IPv6 Deny lists (priority change)
 * flips no feed-change repcheck, so the #1084 batch recompute never re-runs and cross-list
 * dedup/reputation ownership lags the new priority order until an unrelated feed changes.
 *
 *   pfb_ip_recompute_memberlist_content() the single memberlist serialization -- shared by
 *                                         the checker below and the invocation loop's write
 *                                         site, so their formats can never drift.
 *   pfb_ip_recompute_order_changed()      TRUE when the family's would-be recompute
 *                                         memberlist order differs from the memberlist file
 *                                         the last recompute pass wrote (or none exists yet).
 *   pfb_ip_recompute_memberlist_write()   the invocation loop's baseline write: LOCK_EX via
 *                                         the shared serializer, strict FALSE check, logged
 *                                         failure (issue #1184).
 *
 * Part A exercises the pure helpers directly; Part B drives the whole order-check decision
 * matrix; Part C does the same for the write helper's success/failure/empty-content behaviour.
 */
#[CoversFunction('pfb_ip_recompute_memberlist_content')]
#[CoversFunction('pfb_ip_recompute_memberlist_write')]
#[CoversFunction('pfb_ip_recompute_order_changed')]
final class IpRecomputeOrderChangeTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private string $root;
	private string $snapdir;
	private string $memberlist;

	protected function setUp(): void
	{
		$this->root       = sys_get_temp_dir() . '/pfb_rec_order_' . getmypid() . '_' . uniqid();
		$this->snapdir    = "{$this->root}/snapshot";
		$this->memberlist = "{$this->root}/pfb_recompute_v4.members";
		$this->assertTrue(@mkdir($this->snapdir, 0777, TRUE), "could not create {$this->snapdir}");
	}

	protected function tearDown(): void
	{
		foreach (@glob("{$this->snapdir}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->snapdir);
		foreach (@glob("{$this->root}/*.members") ?: [] as $f) {
			@unlink($f);
		}
		@chmod($this->memberlist, 0644);
		@unlink($this->memberlist);
		@rmdir($this->root);
	}

	/** Baseline content the invocation loop would write for these headers, in order. */
	private function writeBaseline(array $headers): void
	{
		$this->writeBaselineFor($this->memberlist, $headers);
	}

	private function applyScope(string $source, string $start, string $end): string
	{
		$from = strpos($source, $start);
		if ($from === FALSE) {
			throw new RuntimeException("missing apply scope start: {$start}");
		}
		$to = strpos($source, $end, $from + strlen($start));
		if ($to === FALSE) {
			throw new RuntimeException("missing apply scope end: {$end}");
		}
		return substr($source, $from, $to - $from);
	}

	// --- Part A: pfb_ip_recompute_order_changed() behaviour rows -----------------------

	public function testReturnsFalseWhenHeadersMatchStoredBaselineInOrder(): void
	{
		$headers = array('FeedA_v4', 'FeedB_v4');
		$this->writeBaseline($headers);

		$got = pfb_ip_recompute_order_changed($headers, $this->snapdir, $this->memberlist);

		$this->assertFalse($got, 'same headers, same order, matching baseline must not trigger a recompute');
	}

	public function testReturnsTrueWhenTwoHeadersAreSwappedVersusBaseline(): void
	{
		$this->writeBaseline(array('FeedA_v4', 'FeedB_v4'));

		// Before-state: the un-swapped order still matches the baseline.
		$before = pfb_ip_recompute_order_changed(array('FeedA_v4', 'FeedB_v4'), $this->snapdir, $this->memberlist);
		$this->assertFalse($before, 'before-state: matching order must read as unchanged');

		$after = pfb_ip_recompute_order_changed(array('FeedB_v4', 'FeedA_v4'), $this->snapdir, $this->memberlist);
		$this->assertTrue($after, 'a pure priority swap versus the baseline must trigger a recompute');
	}

	public function testReturnsTrueWhenAHeaderIsAddedNotInBaseline(): void
	{
		$this->writeBaseline(array('FeedA_v4'));

		$got = pfb_ip_recompute_order_changed(array('FeedA_v4', 'FeedB_v4'), $this->snapdir, $this->memberlist);

		$this->assertTrue($got, 'a header present in the family but absent from the baseline must trigger a recompute');
	}

	public function testReturnsTrueWhenAHeaderIsRemovedFromBaseline(): void
	{
		$this->writeBaseline(array('FeedA_v4', 'FeedB_v4'));

		$got = pfb_ip_recompute_order_changed(array('FeedA_v4'), $this->snapdir, $this->memberlist);

		$this->assertTrue($got, 'a header present in the baseline but absent from the family must trigger a recompute');
	}

	public function testReturnsTrueWhenBaselineFileIsMissing(): void
	{
		$this->assertFileDoesNotExist($this->memberlist, 'precondition: no baseline written yet');

		$got = pfb_ip_recompute_order_changed(array('FeedA_v4'), $this->snapdir, $this->memberlist);

		$this->assertTrue($got, 'no baseline to compare against is a fail-safe TRUE -- one recompute establishes it');
	}

	public function testReturnsTrueWhenBaselineFileIsUnreadable(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions; cannot simulate an unreadable baseline');
		}
		$this->writeBaseline(array('FeedA_v4'));
		$this->assertFileExists($this->memberlist, 'before-state: the baseline file exists and is readable');

		chmod($this->memberlist, 0000);

		$got = pfb_ip_recompute_order_changed(array('FeedA_v4'), $this->snapdir, $this->memberlist);

		$this->assertTrue($got, 'an unreadable baseline is treated the same as a missing one -- fail-safe TRUE');
	}

	public function testReturnsFalseWhenHeadersAndBaselineAreBothEmpty(): void
	{
		$this->writeBaseline(array());
		$this->assertSame('', file_get_contents($this->memberlist), 'precondition: empty-headers baseline is a zero-byte file');

		$got = pfb_ip_recompute_order_changed(array(), $this->snapdir, $this->memberlist);

		$this->assertFalse($got, 'no headers in this family and an empty baseline both agree: nothing to reconcile');
	}

	public function testReturnsTrueWhenHeadersEmptyButBaselineMissing(): void
	{
		$this->assertFileDoesNotExist($this->memberlist);

		$got = pfb_ip_recompute_order_changed(array(), $this->snapdir, $this->memberlist);

		$this->assertTrue($got, 'a missing baseline is fail-safe TRUE regardless of what the empty-headers content would have matched');
	}

	public function testHeaderContainingADotComparesLiterallyViaItsSnapshotPath(): void
	{
		$headers = array('Feed.A_v4');
		$this->writeBaseline($headers);

		$got = pfb_ip_recompute_order_changed($headers, $this->snapdir, $this->memberlist);

		$this->assertFalse($got, 'a dotted header name must round-trip through its snapshot path unchanged when the baseline matches');
	}

	public function testMemberlistContentSerializationIsNewlineJoinedWithTrailingNewline(): void
	{
		$this->assertSame('', pfb_ip_recompute_memberlist_content(array()), 'no paths serializes to an empty string');
		$this->assertSame("a\nb\n", pfb_ip_recompute_memberlist_content(array('a', 'b')), 'paths are newline-joined with a trailing newline');
	}

	// --- Part B: complete order-check decision matrix -------------------------------

	public function testOrderCheckRequiresLiveEnabledCrossListScope(): void
	{
		$this->assertTrue(pfb_ip_recompute_order_scope(FALSE, TRUE, TRUE, FALSE, FALSE));
		$this->assertTrue(pfb_ip_recompute_order_scope(NULL, TRUE, TRUE, FALSE, FALSE));
		$this->assertTrue(pfb_ip_recompute_order_scope(FALSE, TRUE, FALSE, TRUE, FALSE));
		$this->assertTrue(pfb_ip_recompute_order_scope(FALSE, TRUE, FALSE, FALSE, TRUE));
		$this->assertFalse(pfb_ip_recompute_order_scope(TRUE, TRUE, TRUE, FALSE, FALSE));
		$this->assertFalse(pfb_ip_recompute_order_scope(FALSE, FALSE, TRUE, FALSE, FALSE));
		$this->assertFalse(pfb_ip_recompute_order_scope(FALSE, TRUE, FALSE, FALSE, FALSE));
	}

	public function testOrderCheckFamiliesKeepV6ScopedToDedup(): void
	{
		$this->assertSame(['v4', 'v6'], pfb_ip_recompute_order_families(TRUE));
		$this->assertSame(['v4'], pfb_ip_recompute_order_families(FALSE));
	}

	public function testV4AndV6OrderChangesAreIndependent(): void
	{
		$v4 = $this->root . '/v4.members';
		$v6 = $this->root . '/v6.members';
		$this->writeBaselineFor($v4, ['FeedA_v4', 'FeedB_v4']);
		$this->writeBaselineFor($v6, ['FeedA_v6', 'FeedB_v6']);

		$this->assertFalse(pfb_ip_recompute_order_changed(['FeedA_v4', 'FeedB_v4'], $this->snapdir, $v4));
		$this->assertTrue(pfb_ip_recompute_order_changed(['FeedB_v4', 'FeedA_v4'], $this->snapdir, $v4));
		$this->assertFalse(pfb_ip_recompute_order_changed(['FeedA_v6', 'FeedB_v6'], $this->snapdir, $v6));
		$this->assertTrue(pfb_ip_recompute_order_changed(['FeedB_v6', 'FeedA_v6'], $this->snapdir, $v6));
	}

	private function writeBaselineFor(string $path, array $headers): void
	{
		$paths = array_map(
			fn (string $header): string => pfb_ip_recompute_snapshot_path($this->snapdir, $header),
			$headers
		);
		file_put_contents($path, pfb_ip_recompute_memberlist_content($paths));
	}

	/**
	 * #993: recompute orchestration is embedded in the appliance apply pass; it cannot be
	 * safely executed off-appliance. These comment-free windows pin each decision binding,
	 * while the helper matrix and write behavior above remain executable unit coverage.
	 */
	public function testApplyBindsRecomputeScopeFamilyChangeAndWriteSeparately(): void
	{
		$source  = php_strip_whitespace(self::APPLY);
		$scope   = $this->applyScope($source, 'if (pfb_ip_recompute_order_scope(', 'foreach (pfb_ip_recompute_order_families(');
		$family  = $this->applyScope($source, 'foreach (pfb_ip_recompute_order_families(', 'if (pfb_ip_recompute_order_changed(');
		$changed = $this->applyScope($source, 'if (pfb_ip_recompute_order_changed(', '$pfb_rec_trigger =');
		$write   = $this->applyScope($source, "foreach (array('v4', 'v6') as \$pfb_rec_family) {", 'pfb_ip_recompute_mark_ran(');

		$this->assertSame(1, substr_count($scope, 'if (pfb_ip_recompute_order_scope('), 'apply must bind the live recompute scope once');
		$this->assertSame(1, substr_count($family, 'foreach (pfb_ip_recompute_order_families('), 'apply must select families through the order helper');
		$this->assertSame(1, substr_count($changed, 'if (pfb_ip_recompute_order_changed('), 'apply must compare each selected family order');
		$this->assertSame(1, substr_count($write, 'pfb_ip_recompute_memberlist_write($pfb_rec_memberlist, $pfb_rec_paths)'), 'each recompute pass must write the shared memberlist');
	}

	// --- Part C: pfb_ip_recompute_memberlist_write() behaviour rows (issue #1184) --------

	/** Count of $marker in the CURRENT log (see AliasDeltaApplyTest::countLogMarker). */
	private function countLogMarker(string $marker): int
	{
		global $pfb;
		@mkdir($pfb['logdir'], 0777, TRUE);
		$contents = @file_get_contents($pfb['log'] ?? '');
		if ($contents === FALSE || $contents === '') {
			return 0;
		}
		return substr_count($contents, $marker);
	}

	public function testWriteSucceedsSilentlyAndRoundTripsThroughOrderChanged(): void
	{
		$headers = array('FeedA_v4', 'FeedB_v4');
		$paths   = array();
		foreach ($headers as $header) {
			$paths[] = pfb_ip_recompute_snapshot_path($this->snapdir, $header);
		}
		$marker = "write failed for [ {$this->memberlist} ]";
		$before = $this->countLogMarker($marker);

		$got = pfb_ip_recompute_memberlist_write($this->memberlist, $paths);

		$this->assertNotFalse($got, 'a writable target must not report failure');
		$this->assertSame($before, $this->countLogMarker($marker), 'a successful write must not log a failure');
		$this->assertSame(
			pfb_ip_recompute_memberlist_content($paths),
			file_get_contents($this->memberlist),
			'the written content must be exactly the shared serialization'
		);
		$this->assertFalse(
			pfb_ip_recompute_order_changed($headers, $this->snapdir, $this->memberlist),
			'the just-written memberlist must round-trip as unchanged against its own headers'
		);
	}

	public function testWriteToNonexistentParentDirLogsTheTargetPath(): void
	{
		$target = "{$this->root}/missing-parent/pfb_recompute_v4.members";
		$marker = "write failed for [ {$target} ]";
		$before = $this->countLogMarker($marker);

		$got = pfb_ip_recompute_memberlist_write($target, array('a'));

		$this->assertFalse($got, 'a nonexistent parent directory must fail the write');
		$this->assertSame($before + 1, $this->countLogMarker($marker), 'the failure must be logged with the target path');
	}

	public function testWriteToReadOnlyTargetLogsFailure(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions; cannot simulate a write-denied target');
		}
		file_put_contents($this->memberlist, 'stale');
		chmod($this->memberlist, 0444);
		$marker = "write failed for [ {$this->memberlist} ]";
		$before = $this->countLogMarker($marker);

		$got = pfb_ip_recompute_memberlist_write($this->memberlist, array('a'));

		$this->assertFalse($got, 'a 0444 target must fail the write');
		$this->assertSame($before + 1, $this->countLogMarker($marker), 'the failure must be logged');
	}

	public function testEmptyPathsWritesZeroByteContentWithoutLogging(): void
	{
		$marker = "write failed for [ {$this->memberlist} ]";
		$before = $this->countLogMarker($marker);

		$got = pfb_ip_recompute_memberlist_write($this->memberlist, array());

		$this->assertSame(0, $got, 'file_put_contents of an empty string returns int 0, not FALSE');
		$this->assertNotFalse($got, 'int 0 must not be misread as a failure by a loose comparison');
		$this->assertSame($before, $this->countLogMarker($marker), 'int 0 (zero bytes written) must never be logged as a failure');
	}
}
