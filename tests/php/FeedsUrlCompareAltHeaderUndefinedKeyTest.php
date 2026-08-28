<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Pins url_compare()'s no-match branch (pfblockerng_feeds.php:284, issue #1694):
 * once ANY alternate has matched for a given $ftype/$aliasname (so the
 * `$alt_feeds[$ftype][$aliasname]` bucket exists), reaching that branch again for a
 * SIBLING alternate whose own `$alt_header` sentinel was never written must not read
 * `$alt_feeds[$ftype][$aliasname][$alt_header]` as if it were guaranteed to exist --
 * doing so raised "Undefined array key" under E_ALL (the sentinel is only ever written
 * together with the match record at :272-274, so an alt_header that has not yet
 * matched anything has no sentinel at all) while STILL evaluating truthy-negated
 * (missing key negates to TRUE), so the branch happened to run anyway. The fix must
 * keep running that branch silently, not skip it.
 *
 * Calls url_compare() directly (loaded via FeedsPredefinedTypeLoader.php, same
 * eval-extraction FeedsUrlCompareIconRenderTest.php uses -- pfblockerng_feeds.php
 * carries top-level execution and cannot be require()d off-appliance).
 */
final class FeedsUrlCompareAltHeaderUndefinedKeyTest extends TestCase
{
	private mixed $savedAltFeeds = null;
	private mixed $savedExFeeds  = null;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/FeedsPredefinedTypeLoader.php';
		pfb_test_load_feeds_predefined_type_functions();
	}

	protected function setUp(): void
	{
		$this->savedAltFeeds = $GLOBALS['alt_feeds'] ?? null;
		$this->savedExFeeds  = $GLOBALS['ex_feeds'] ?? null;
		$GLOBALS['alt_feeds'] = [];
		$GLOBALS['ex_feeds']  = [];
	}

	protected function tearDown(): void
	{
		if ($this->savedAltFeeds === null) {
			unset($GLOBALS['alt_feeds']);
		} else {
			$GLOBALS['alt_feeds'] = $this->savedAltFeeds;
		}
		if ($this->savedExFeeds === null) {
			unset($GLOBALS['ex_feeds']);
		} else {
			$GLOBALS['ex_feeds'] = $this->savedExFeeds;
		}
	}

	/**
	 * Runs $fn with an error handler active for the full E_ALL mask and returns the
	 * (errno, errstr) pairs it captured. Always restores whatever handler was
	 * previously installed, even if $fn throws, so a failure here cannot leak into
	 * sibling tests.
	 *
	 * @return list<array{0: int, 1: string}>
	 */
	private function captureDiagnostics(callable $fn): array
	{
		$diagnostics = [];
		set_error_handler(
			static function (int $errno, string $errstr) use (&$diagnostics): bool {
				$diagnostics[] = [$errno, $errstr];
				return true;
			},
			E_ALL
		);
		try {
			$fn();
		} finally {
			restore_error_handler();
		}
		return $diagnostics;
	}

	/** @param list<array{0: int, 1: string}> $diagnostics */
	private function assertNoUndefinedArrayKeyDiagnostic(array $diagnostics): void
	{
		$matches = array_values(array_filter(
			$diagnostics,
			static fn(array $d): bool => str_contains($d[1], 'Undefined array key')
		));
		$this->assertSame(
			[],
			$matches,
			"expected no 'Undefined array key' diagnostic, got:\n" . var_export($diagnostics, true)
		);
	}

	// Vacuity guard (coverage matrix row 6): proves captureDiagnostics()'s handler is
	// genuinely active and genuinely observes this exact class of warning, so the
	// "no diagnostics" assertions elsewhere in this file cannot pass merely because
	// the handler never fired.
	public function testHandlerCapturesADeliberateUndefinedArrayKeyWarning(): void
	{
		$probe = [];
		$diagnostics = $this->captureDiagnostics(static function () use ($probe): void {
			$unused = $probe['does_not_exist'];
		});

		$hasUndefinedKeyWarning = false;
		foreach ($diagnostics as [$errno, $errstr]) {
			if ($errno === E_WARNING && str_contains($errstr, 'Undefined array key')) {
				$hasUndefinedKeyWarning = true;
				break;
			}
		}
		$this->assertTrue(
			$hasUndefinedKeyWarning,
			"vacuity guard failed -- the error handler did not observe a deliberately-triggered "
				. "'Undefined array key' warning; captured:\n" . var_export($diagnostics, true)
		);
	}

	// Coverage matrix rows 1+2 -- the red-before/green-after row. Two alternates
	// under the same $ftype/$aliasname: the first (a_key=0, header 'FirstAlt')
	// matches its row and writes both the match record and the 'FirstAlt' sentinel
	// (:271-274). The second (a_key=1, header 'SecondAlt') is a SIBLING that has
	// never matched anything -- its own sentinel key was never written -- yet the
	// bucket `$alt_feeds['ipv4']['MyAlias']` now exists from the first call, so the
	// no-match branch (:283-287) is reached with `[$alt_header]` absent.
	public function testSecondAlternateReachedAfterFirstMatchTriggersNoUndefinedKeyWarning(): void
	{
		$ftype      = 'ipv4';
		$aliasname  = 'MyAlias';
		$feedHeader = 'PrimaryFeedHeader';

		// First alternate: row_url == feed_url (alt url) -> real match, writes the
		// record AND the 'FirstAlt' sentinel together.
		url_compare(
			$ftype, 0, 10, $aliasname, $aliasname,
			'https://example.test/first-alt.txt', 'https://example.test/first-alt.txt',
			'Enabled', $feedHeader, 0, TRUE, 'FirstAlt', '', ''
		);
		$this->assertTrue(
			isset($GLOBALS['alt_feeds'][$ftype][$aliasname]['FirstAlt']),
			'setup precondition failed: first alternate must have written its sentinel'
		);

		// Second alternate: row_url does NOT match this alt's feed_url -> no match,
		// falls into the :283 else -- and 'SecondAlt' has no sentinel at all.
		$diagnostics = $this->captureDiagnostics(function () use ($ftype, $aliasname, $feedHeader): void {
			url_compare(
				$ftype, 0, 10, $aliasname, $aliasname,
				'https://example.test/unrelated-row.txt', 'https://example.test/second-alt.txt',
				'Enabled', $feedHeader, 1, TRUE, 'SecondAlt', '', ''
			);
		});

		$this->assertNoUndefinedArrayKeyDiagnostic($diagnostics);

		// Functional outcome (row 2): the branch must still have run and written the
		// alternate record for a_key=1 under $feed_header, not silently skipped it.
		$slice = $GLOBALS['alt_feeds'][$ftype][$aliasname][$feedHeader] ?? null;
		$this->assertIsArray(
			$slice,
			"expected \$alt_feeds[{$ftype}][{$aliasname}][{$feedHeader}] to be an array, got:\n"
				. var_export($GLOBALS['alt_feeds'], true)
		);
		$this->assertArrayHasKey(
			1,
			$slice,
			"expected the a_key=1 record to be written; \$alt_feeds slice was:\n" . var_export($slice, true)
		);
		$this->assertSame('SecondAlt', $slice[1]['header'] ?? null);
		$this->assertSame('https://example.test/second-alt.txt', $slice[1]['url'] ?? null);
		$this->assertSame('', $slice[1]['icon'] ?? 'not-empty', 'no-match branch must store an empty icon');
	}

	// Coverage matrix row 3: alt_header present and TRUE (already matched) -> the
	// branch must NOT run again, so a later no-match call for the SAME alt_header
	// must not clobber the record written when it first matched.
	public function testAlreadyMatchedAlternateSentinelTrueDoesNotRewriteRecord(): void
	{
		$ftype      = 'ipv4';
		$aliasname  = 'MyAlias';
		$feedHeader = 'PrimaryFeedHeader';

		url_compare(
			$ftype, 0, 10, $aliasname, $aliasname,
			'https://example.test/first-alt.txt', 'https://example.test/first-alt.txt',
			'Enabled', $feedHeader, 0, TRUE, 'FirstAlt', '', ''
		);
		$recordAfterMatch = $GLOBALS['alt_feeds'][$ftype][$aliasname][$feedHeader][0] ?? null;
		$this->assertNotNull($recordAfterMatch, 'setup precondition failed: first match must write a_key=0');
		$this->assertNotSame('', $recordAfterMatch['icon'], 'setup precondition failed: match must carry a non-empty icon');

		// A different existing row references the SAME alt_header ('FirstAlt') but
		// this row's URL does not match it -- sentinel is already TRUE, so :284 must
		// evaluate FALSE and skip the write entirely.
		$diagnostics = $this->captureDiagnostics(function () use ($ftype, $aliasname, $feedHeader): void {
			url_compare(
				$ftype, 1, 11, $aliasname, $aliasname,
				'https://example.test/another-unrelated-row.txt', 'https://example.test/first-alt.txt-does-not-match-this-row',
				'Enabled', $feedHeader, 0, TRUE, 'FirstAlt', '', ''
			);
		});

		$this->assertNoUndefinedArrayKeyDiagnostic($diagnostics);
		$this->assertSame(
			$recordAfterMatch,
			$GLOBALS['alt_feeds'][$ftype][$aliasname][$feedHeader][0],
			"record must be unchanged when the sentinel was already TRUE; before:\n"
				. var_export($recordAfterMatch, true) . "\nafter:\n"
				. var_export($GLOBALS['alt_feeds'][$ftype][$aliasname][$feedHeader][0], true)
		);
	}

	// Coverage matrix row 4: alt_header present but falsy (not merely absent) ->
	// the branch must still run, same as the absent-key case. This isolates :284's
	// boolean-negation semantics from the presence/absence of the key itself.
	public function testFalsySentinelValuePresentStillTriggersWrite(): void
	{
		$ftype      = 'ipv4';
		$aliasname  = 'MyAlias';
		$feedHeader = 'PrimaryFeedHeader';

		// Seed the bucket so isset($alt_feeds[$ftype]) / isset($alt_feeds[$ftype][$aliasname])
		// are both TRUE, with the 'ThirdAlt' sentinel explicitly present and FALSE
		// (a state the production write path never produces on its own -- the
		// sentinel is only ever set to TRUE -- but :284's own boolean logic must
		// treat it the same as "absent" per the coverage matrix).
		$GLOBALS['alt_feeds'][$ftype][$aliasname]['ThirdAlt'] = FALSE;

		$diagnostics = $this->captureDiagnostics(function () use ($ftype, $aliasname, $feedHeader): void {
			url_compare(
				$ftype, 2, 12, $aliasname, $aliasname,
				'https://example.test/unrelated-row-2.txt', 'https://example.test/third-alt.txt',
				'Enabled', $feedHeader, 2, TRUE, 'ThirdAlt', '', ''
			);
		});

		$this->assertNoUndefinedArrayKeyDiagnostic($diagnostics);
		$slice = $GLOBALS['alt_feeds'][$ftype][$aliasname][$feedHeader] ?? null;
		$this->assertIsArray($slice, 'expected the a_key=2 write to have created the feed_header slice');
		$this->assertArrayHasKey(
			2,
			$slice,
			"expected a_key=2 to be written for a present-but-falsy sentinel; slice:\n" . var_export($slice, true)
		);
	}

	// Coverage matrix row 5: $alternate === FALSE short-circuits the whole guard --
	// nothing written, no diagnostic, regardless of whether $alt_feeds[$ftype]
	// already exists.
	public function testAlternateFalseShortCircuitsGuardEntirely(): void
	{
		$ftype      = 'ipv4';
		$aliasname  = 'MyAlias';
		$feedHeader = 'PrimaryFeedHeader';

		// Pre-seed the bucket so the isset() legs of :284 WOULD be TRUE, isolating
		// that it is $alternate itself short-circuiting the expression.
		$GLOBALS['alt_feeds'][$ftype][$aliasname]['SomeOtherAlt'] = TRUE;
		$before = $GLOBALS['alt_feeds'];

		$diagnostics = $this->captureDiagnostics(function () use ($ftype, $aliasname, $feedHeader): void {
			url_compare(
				$ftype, 3, 13, $aliasname, $aliasname,
				'https://example.test/unrelated-row-3.txt', 'https://example.test/non-alt-url.txt',
				'Enabled', $feedHeader, 5, FALSE, 'UnusedHeader', '', ''
			);
		});

		$this->assertNoUndefinedArrayKeyDiagnostic($diagnostics);
		$this->assertSame([], $diagnostics, "expected zero diagnostics of any kind, got:\n" . var_export($diagnostics, true));
		$this->assertSame(
			$before,
			$GLOBALS['alt_feeds'],
			"\$alternate=FALSE must write nothing; before:\n" . var_export($before, true)
				. "\nafter:\n" . var_export($GLOBALS['alt_feeds'], true)
		);
	}
}
