<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The category editor names which schedule-cache check failed, as the General page does.
 *
 * Issue #2888: it went through pfb_schedule_cache_candidate_validate(), which returned a
 * bare bool, so the page could only say "this is likely a package bug" and only the
 * config stage reached the log -- via pfb_schedule_runtime_config(), not this path.
 */
final class CategoryScheduleStageTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';

	private const GENERAL = [
		'pfb_scheduled_feed_updates' => 'on',
		'pfb_schedule_weekday'       => '7',
		'pfb_schedule_hour'          => '2',
		'pfb_schedule_minute'        => '15',
	];

	private function model(): array
	{
		$model = pfb_schedule_runtime_model(self::GENERAL, ['ipv4' => [], 'ipv6' => [], 'dnsbl' => []]);
		$this->assertIsArray($model);
		return $model;
	}

	/** Each check reports its own stage, and a clean candidate reports none. */
	public function testCandidateStageNamesTheFailingCheck(): void
	{
		$model = $this->model();
		$state = ['schema' => 1, 'items' => []];

		$this->assertSame('config', pfb_schedule_cache_candidate_stage(NULL, $state, 'UTC'));
		$this->assertSame('state', pfb_schedule_cache_candidate_stage($model, NULL, 'UTC'));
		$this->assertSame('timezone', pfb_schedule_cache_candidate_stage($model, $state, ['not-a-zone']));
		$this->assertSame('refresh',
			pfb_schedule_cache_candidate_stage($model, $state, 'UTC', NULL, ['fail_rename' => TRUE]),
			'a candidate that cannot be published must name the publication stage');
		$this->assertSame('', pfb_schedule_cache_candidate_stage($model, $state, 'UTC'),
			'a candidate that publishes and reads back cleanly names no stage');
	}

	/** The bool the other callers use stays consistent with the stage. */
	public function testValidateAgreesWithTheStage(): void
	{
		$model = $this->model();
		$state = ['schema' => 1, 'items' => []];

		$this->assertTrue(pfb_schedule_cache_candidate_validate($model, $state, 'UTC'));
		$this->assertFalse(pfb_schedule_cache_candidate_validate(NULL, $state, 'UTC'));
		$this->assertFalse(
			pfb_schedule_cache_candidate_validate($model, $state, 'UTC', NULL, ['fail_rename' => TRUE]));
	}

	/** A failure leaves an actionable line behind, not just a redirect. */
	public function testCandidateFailureRaisesANoticeNamingTheStage(): void
	{
		$GLOBALS['pfb_test_logger_calls'] = [];
		$model = $this->model();

		pfb_schedule_cache_candidate_stage($model, ['schema' => 1, 'items' => []], 'UTC', NULL,
			['fail_rename' => TRUE]);

		$notices = array_column(array_filter($GLOBALS['pfb_test_logger_calls'] ?? [],
			static fn (array $c): bool => $c['priority'] === LOG_NOTICE), 'message');
		// Compared against the label map itself, so the assertion cannot drift from the wording.
		$label = pfb_schedule_cache_stage_label('refresh');
		$named = array_filter($notices, static fn (string $m): bool => str_contains($m, $label));
		$this->assertNotSame([], $named,
			'a failed candidate must raise a LOG_NOTICE naming the stage; notices were: '
			. var_export($notices, TRUE));
		$GLOBALS['pfb_test_logger_calls'] = [];
	}

	/** The page carries the stage through the redirect and renders its label. */
	public function testPageCarriesTheStageAndNamesIt(): void
	{
		$source = php_strip_whitespace(self::PAGE);
		$this->assertStringContainsString('pfb_schedule_cache_candidate_stage(', $source,
			'the save must resolve which check failed, not just whether one did');
		$this->assertStringContainsString('schstage=', $source,
			'the failure redirect must carry the stage');
		$this->assertStringContainsString('pfb_schedule_cache_stage_label(', $source,
			'the warning must render the stage through the fixed label map');
		$this->assertStringNotContainsString('This is likely a package bug', $source,
			'the warning must stop calling it a probable bug with no detail attached');
	}
}
