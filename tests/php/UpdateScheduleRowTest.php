<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #3941 (C3): the Update page's Schedule rows are Core's GetSchedule. What a row says when Core gave no entry, when
 * Core did not answer, and the DNSBL Category row's own Disabled / None selected wording (unchanged by the cutover).
 * The formatters live in the page, so UpdatePageLoader evals exactly their span.
 */
final class UpdateScheduleRowTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/UpdatePageLoader.php';
		pfb_test_load_update_page_functions();
	}

	public function testAnEntryShowsItsLastAndNextTimeWithSeconds(): void
	{
		$last = mktime(9, 0, 45, 1, 1, 2025);

		$html = pfb_schedule_entry_html(NULL, ['last_run' => $last, 'next_due' => $last + 900]);

		$this->assertSame('Last: <strong>2025-01-01 09:00:45</strong>&emsp;Next: <strong>2025-01-01 09:15:45</strong>', $html);
	}

	public function testAJobThatNeverRanShowsNoLastTime(): void
	{
		$next = mktime(3, 0, 0, 1, 2, 2025);

		$html = pfb_schedule_entry_html(NULL, ['next_due' => $next]);

		$this->assertSame('Last: <strong>—</strong>&emsp;Next: <strong>2025-01-02 03:00:00</strong>', $html);
	}

	public function testWhatCoreDoesNotScheduleIsSaidSo(): void
	{
		$this->assertSame('<em>Not scheduled</em>', pfb_schedule_entry_html(NULL, NULL));
	}

	public function testACoreThatDidNotAnswerIsSaidSoWithItsReasonOnHover(): void
	{
		$html = pfb_schedule_entry_html('the Core API did not answer: Failed to connect', NULL, TRUE);

		$this->assertSame('<em title="the Core API did not answer: Failed to connect">Core is not answering</em>', $html);
	}

	public function testATransportFailureIsEscapedAndWinsOverAnEntry(): void
	{
		$html = pfb_schedule_entry_html('the Core API did not answer: "<b>x</b>"', ['last_run' => 1, 'next_due' => 2], TRUE);

		$this->assertSame('<em title="the Core API did not answer: &quot;&lt;b&gt;x&lt;/b&gt;&quot;">Core is not answering</em>', $html);
	}

	/**
	 * Core answered and refused the schedule (not initialized, or a value the schedule refuses): it is up, so the row says what Core
	 * said instead of calling it down (issue #3941 review: a reachable Core must not read "not answering").
	 */
	public function testACoreThatAnsweredWithAnErrorShowsItsMessageAndIsNotCalledDown(): void
	{
		$html = pfb_schedule_entry_html('unavailable: the settings are not initialized', NULL);

		$this->assertSame('<em>Core cannot give the schedule: unavailable: the settings are not initialized</em>', $html);
		$this->assertStringNotContainsString('not answering', $html);
	}

	public function testACoreErrorMessageIsEscapedAndWinsOverAnEntry(): void
	{
		$html = pfb_schedule_entry_html('unavailable: "<b>x</b>"', ['last_run' => 1, 'next_due' => 2], FALSE);

		$this->assertSame('<em>Core cannot give the schedule: unavailable: &quot;&lt;b&gt;x&lt;/b&gt;&quot;</em>', $html);
	}

	/** @param array<string, mixed> $blconfig */
	private static function category(array $blconfig, ?array $entry, ?string $error = NULL, bool $unreachable = FALSE): string
	{
		return pfb_dnsbl_category_schedule_html(['enable' => PfbToggle::On, 'blconfig' => $blconfig], $entry, $error, $unreachable);
	}

	public function testTheCategoryRowSaysDisabledWhenTheFeatureIsOffWhateverCoreSays(): void
	{
		$this->assertSame('<em>Disabled</em>', self::category(['blacklist_enable' => 'Disable'], ['next_due' => 5]));
		$this->assertSame('<em>Disabled</em>', self::category([], NULL, 'the Core API did not answer: x', TRUE));
	}

	public function testTheCategoryRowSaysNoneSelectedWhenNoCategoryIsSelected(): void
	{
		$blconfig = ['blacklist_enable' => 'Enable', 'blacklist_selected' => 'abc', 'item' => [['xml' => 'abc', 'selected' => '']]];

		$this->assertSame('<em>None selected</em>', self::category($blconfig, ['next_due' => 5]));
	}

	public function testAnActiveCategoryRowShowsCoresEntryOrSaysItIsNotScheduled(): void
	{
		$blconfig = ['blacklist_enable' => 'Enable', 'blacklist_selected' => 'abc', 'item' => [['xml' => 'abc', 'selected' => 'cat']]];
		$next = mktime(3, 0, 0, 1, 2, 2025);

		$this->assertSame('Last: <strong>—</strong>&emsp;Next: <strong>2025-01-02 03:00:00</strong>', self::category($blconfig, ['next_due' => $next]));
		$this->assertSame('<em>Not scheduled</em>', self::category($blconfig, NULL));
		$this->assertStringContainsString('Core is not answering', self::category($blconfig, NULL, 'down', TRUE));
		$this->assertStringContainsString('Core cannot give the schedule: unavailable: not ready', self::category($blconfig, NULL, 'unavailable: not ready'));
	}

	public function testTheCategoryRowSaysDisabledWhenPfBlockerNgIsOff(): void
	{
		$html = pfb_dnsbl_category_schedule_html(['enable' => PfbToggle::Off, 'blconfig' => ['blacklist_enable' => 'Enable']], NULL, NULL);

		$this->assertSame('<em>Disabled</em>', $html);
	}
}
