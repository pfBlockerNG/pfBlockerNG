<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941 (C3): the Update page starts and views the one Update through Core, and the PHP scheduler's leftovers that
 * served the page, the General page's and the Group edit page's save are gone. The pages cannot be included off-box
 * (head.inc, the Form classes), so the page is pinned by its code (comments and whitespace stripped) and the retired
 * functions by their absence; the behaviour behind each call is in UpdateViewResponseTest.
 */
final class UpdatePageCoreTest extends TestCase
{
	private const WWW = __DIR__ . '/../../src/usr/local/www/pfblockerng';

	private static function code(string $file): string
	{
		$stripped = php_strip_whitespace(self::WWW . "/{$file}");
		self::assertNotSame('', $stripped, "{$file} must be readable");
		return $stripped;
	}

	public function testThePollEndpointRelaysGetUpdateAfterReleasingTheSessionLock(): void
	{
		$page = self::code('pfblockerng_update.php');

		$this->assertStringContainsString("'ajax']??'')==='update'", str_replace(' ', '', $page), 'the poll is ?ajax=update');
		$close = strpos($page, 'session_write_close();');
		$relay = strpos($page, 'pfb_update_view_response($_GET');
		$this->assertNotFalse($close, 'a poll must not hold the session write lock');
		$this->assertNotFalse($relay, 'the poll is answered by pfb_update_view_response()');
		$this->assertLessThan($relay, $close, 'the lock is released before Core is asked');
	}

	public function testRunNowAndTheWizardStartTheUpdateThroughCore(): void
	{
		$page = self::code('pfblockerng_update.php');

		$this->assertStringContainsString('pfb_update_start(', $page);
		$this->assertSame(1, substr_count($page, 'pfb_update_start('), 'Run Now, Force and the Wizard reload are one dispatch');
	}

	public function testTheStatusLineAndTheScheduleSectionComeFromCore(): void
	{
		$page = self::code('pfblockerng_update.php');

		$this->assertStringContainsString("'GetUpdate'", $page, 'the status line is GetUpdate.running');
		$this->assertStringContainsString('pfb_update_schedule_view(', $page, 'the Schedule section is GetSchedule');
	}

	public function testThePollerFollowsTheCursorCoreHandedBackAndNoticesANewUpdate(): void
	{
		$page = self::code('pfblockerng_update.php');

		$this->assertStringContainsString('ajax=update', $page);
		$this->assertStringContainsString('r.next', $page, 'the cursor is the next of the last reply, as Core gave it');
		$this->assertStringContainsString('startedAt', $page, 'a new Update (or a restarted Core) is noticed by update.startedAt');
		$this->assertStringContainsString("out.value = ''", $page, 'a new Update starts a clean log');
	}

	/** @return array<string, array{string}> */
	public static function retiredFromThePage(): array
	{
		return [
			'detached dispatch'            => ['daemon -p'],
			'detached dispatch (helper)'   => ['mwexec_bg'],
			'Run Now dispatcher'           => ['pfb_runnow'],
			'the run log'                  => ['runlog'],
			'the byte-offset tail'         => ['ajax=tail'],
			'the tail payload'             => ['pfb_log_tail_payload'],
			'the tail response'            => ['pfb_update_tail_response'],
			'the ps-scan task guard'       => ['pfb_active_task_running'],
			'the ps-scan task guard (inc)' => ['pfb_feed_task_running'],
			'the PHP schedule state'       => ['pfb_schedule_state_read'],
			'the PHP due ledger'           => ['pfb_due_ledger_read_entry'],
			'the pfb_trigger verb'         => ['pfb_trigger'],
			'the forcecheck verb'          => ['forcecheck'],
		];
	}

	#[DataProvider('retiredFromThePage')]
	public function testTheUpdatePageNoLongerUses(string $needle): void
	{
		$this->assertStringNotContainsString($needle, self::code('pfblockerng_update.php'));
	}

	/** @return array<string, array{string}> */
	public static function pagesThatSavedSchedules(): array
	{
		return ['General' => ['pfblockerng_general.php'], 'Group edit' => ['pfblockerng_category_edit.php']];
	}

	#[DataProvider('pagesThatSavedSchedules')]
	public function testASaveNoLongerBuildsAPhpScheduleCacheCandidate(string $file): void
	{
		$page = self::code($file);

		foreach (['pfb_schedule_cache', 'pfb_schedule_state_read', 'pfb_schedule_runtime_config', 'schcache', 'schstage', 'pfb_general_schedule_save_redirect'] as $retired) {
			$this->assertStringNotContainsString($retired, $page, "{$file} still has the PHP schedule check ({$retired})");
		}
		$this->assertStringContainsString('pfb_core_settings_changed(NULL, TRUE)', $page, 'Core is still told of the saved settings');
	}

	/** @return array<string, array{string}> */
	public static function retiredFunctions(): array
	{
		$names = [
			'pfb_update_tail_response', 'pfb_log_tail_payload', 'pfb_feed_task_running',
			'pfb_schedule_cache_refresh', 'pfb_schedule_cache_stage', 'pfb_schedule_cache_stage_label',
			'pfb_schedule_cache_candidate_stage', 'pfb_schedule_cache_candidate_validate', 'pfb_general_schedule_save_redirect',
			'pfb_due_ledger_read_cache', 'pfb_due_ledger_write_cache', 'pfb_schedule_state_read', 'pfb_schedule_state_valid',
			'pfb_schedule_runtime_model_valid', 'pfb_schedule_runtime_hash_projection', 'pfb_schedule_plan', 'pfb_schedule_next_occurrence',
		];
		return array_combine($names, array_map(static fn (string $name): array => [$name], $names));
	}

	#[DataProvider('retiredFunctions')]
	public function testTheFunctionIsRetiredWithItsLastCaller(string $name): void
	{
		$this->assertFalse(function_exists($name), "{$name}() has no caller left: Core serves what it did");
	}

	public function testTheCliVerbsStayForTheirOtherCallers(): void
	{
		$cli = self::code('pfblockerng.php');

		$this->assertStringContainsString("'forcecheck'", $cli, 'the forcecheck verb stays: live smoke callers and hand use run it');
		$this->assertStringContainsString("'pfb_trigger'", $cli, 'the pfb_trigger verb stays: the dcc verb dispatches it for a changed TOP1M');
	}
}
