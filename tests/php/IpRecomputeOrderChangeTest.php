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
 *
 * Part A exercises both pure helpers directly. Part B is a source tripwire suite: the
 * detection wiring lives in sync_package_pfblockerng(), thousands of lines of top-level
 * script code that PHPUnit cannot call as a function -- so wiring correctness is pinned by
 * exact substring assertions against the CURRENT file content (house pattern:
 * IpRecomputeRanWiringTest), which fail for as long as the old (missing) wiring is what is
 * actually shipped.
 */
#[CoversFunction('pfb_ip_recompute_memberlist_content')]
#[CoversFunction('pfb_ip_recompute_order_changed')]
final class IpRecomputeOrderChangeTest extends TestCase
{
	private string $root;
	private string $snapdir;
	private string $memberlist;

	protected function setUp(): void
	{
		$this->root       = sys_get_temp_dir() . '/pfb_rec_order_' . getmypid() . '_' . uniqid();
		$this->snapdir    = "{$this->root}/snapshot";
		$this->memberlist = "{$this->root}/pfb_recompute_v4.members";
		$this->assertTrue(@mkdir($this->snapdir, 0777, true), "could not create {$this->snapdir}");
	}

	protected function tearDown(): void
	{
		foreach (@glob("{$this->snapdir}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->snapdir);
		@chmod($this->memberlist, 0644);
		@unlink($this->memberlist);
		@rmdir($this->root);
	}

	/** Baseline content the invocation loop would write for these headers, in order. */
	private function writeBaseline(array $headers): void
	{
		$paths = array();
		foreach ($headers as $header) {
			$paths[] = pfb_ip_recompute_snapshot_path($this->snapdir, $header);
		}
		file_put_contents($this->memberlist, pfb_ip_recompute_memberlist_content($paths));
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

	// --- Part B: sync_package_pfblockerng() wiring tripwires ----------------------------

	private function source(): string
	{
		return (string) file_get_contents(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc');
	}

	public function testDetectionGuardCombinesTheSaveEnableGateWithCrossListScope(): void
	{
		$needle = <<<'EOT'
	if (!$pfb['save'] && $pfb['enable'] == 'on' &&
	    pfb_cross_list_scope($pfb['dup'] == 'on', $pfb['drep'] == 'on' || $pfb['prep'] == 'on')) {
EOT;
		$this->assertStringContainsString(
			$needle,
			$this->source(),
			'the order-change detection block must gate on !save && enable, scoped by pfb_cross_list_scope() -- order only matters when dedup or reputation is on'
		);
	}

	public function testDetectionBlockCallsOrderChangedWithFamilyHeadersAndTheMemberlistPath(): void
	{
		$needle = <<<'EOT'
			if (pfb_ip_recompute_order_changed(
			    pfb_ip_recompute_family_headers($pfb['existing']['deny'] ?? [], $pfb_rec_family),
			    $pfb['snapdir'],
			    "{$pfb['dbdir']}/pfb_recompute_{$pfb_rec_family}.members")) {
EOT;
		$this->assertStringContainsString(
			$needle,
			$this->source(),
			'the checker must be called with the config-order family headers and the exact memberlist path the invocation loop writes'
		);
	}

	public function testDetectionBlockOnlyChecksV6UnderDedup(): void
	{
		$needle = <<<'EOT'
		foreach (array('v4', 'v6') as $pfb_rec_family) {
			if ($pfb_rec_family === 'v6' && $pfb['dup'] != 'on') {
				continue;
			}
EOT;
		$this->assertStringContainsString(
			$needle,
			$this->source(),
			"v6 joins recompute only via dedup (pfb_ip_recompute_matrix's contract: invoke_v6 TRUE only when dedup is on)"
		);
	}

	public function testMemberlistWriteSiteRoutesThroughTheSharedSerializationHelper(): void
	{
		$source = $this->source();
		$this->assertStringContainsString(
			"\t\t@file_put_contents(\$pfb_rec_memberlist, pfb_ip_recompute_memberlist_content(\$pfb_rec_paths), LOCK_EX);",
			$source,
			'the invocation loop must write the memberlist through the shared helper, not an inline implode'
		);
		$this->assertStringNotContainsString(
			"\$pfb_rec_paths ? (implode(\"\\n\", \$pfb_rec_paths) . \"\\n\") : ''",
			$source,
			'the old inline implode ternary must be gone -- otherwise the checker and the writer could drift out of format sync'
		);
	}
}
