<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_update_autotail — the Update page's "auto-tail an in-progress update on a plain load"
 * decision. On a plain page load while a feed task is running, the page should stream the live
 * log (passive 'view' livetail, like the View button) instead of pre-filling the last-run tail.
 *
 * It must NOT auto-tail when there is no running task, when the request is a Run-Now/wizard
 * dispatch ($run_dispatch — that path drives its own 'force' livetail), or when it is a
 * View/End-View button click ($logview_posted — handled by the existing log_view branch).
 *
 * Each of the three inputs is asserted both ways so every branch of the AND is a real gate.
 * Red→green: pfb_update_autotail() does not exist before the change, so every case fatals with
 * "undefined function"; green after.
 */
#[CoversFunction('pfb_update_autotail')]
final class PfbUpdateAutotailTest extends TestCase
{
	/**
	 * The target case: a task is running and this is a plain load (no run dispatch, no view
	 * click) → auto-tail.
	 */
	public function testRunningPlainLoadAutoTails(): void
	{
		$this->assertTrue(pfb_update_autotail(TRUE, FALSE, FALSE));
	}

	/**
	 * No task running → never auto-tail (nothing to stream; the static last-run prefill stands).
	 */
	public function testNotRunningDoesNotAutoTail(): void
	{
		$this->assertFalse(pfb_update_autotail(FALSE, FALSE, FALSE));
	}

	/**
	 * A Run-Now / wizard dispatch ($run_dispatch) drives its own 'force' livetail → no auto-tail,
	 * even with a task running.
	 */
	public function testRunDispatchDoesNotAutoTail(): void
	{
		$this->assertFalse(pfb_update_autotail(TRUE, TRUE, FALSE));
	}

	/**
	 * A View / End-View button click ($logview_posted) is handled by the existing log_view
	 * branch → no auto-tail, even with a task running.
	 */
	public function testLogViewClickDoesNotAutoTail(): void
	{
		$this->assertFalse(pfb_update_autotail(TRUE, FALSE, TRUE));
	}
}
