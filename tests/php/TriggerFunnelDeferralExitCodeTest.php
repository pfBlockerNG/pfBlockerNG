<?php

declare(strict_types=1);

require_once __DIR__ . '/SyncPrereqSeedTrait.php';
require_once __DIR__ . '/DeferralLockHarnessTrait.php';

use PHPUnit\Framework\TestCase;

/**
 * Issue #2591: lock identity is reported separately from the established internal bool.
 *
 * Unattended trigger=cron requests retain TRUE and operator-triggered requests retain
 * FALSE so existing in-process callers keep their semantics. Both lock guards also set
 * the optional by-reference reason; the CLI maps that reason to EX_TEMPFAIL independently
 * of the bool. Durable pending state and dispatcher-lock syslog visibility remain covered.
 */
final class TriggerFunnelDeferralExitCodeTest extends TestCase
{
	use SyncPrereqSeedTrait;
	use DeferralLockHarnessTrait;

	private string $dbdir = '';
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];
	private bool $hadConfig = FALSE;
	private mixed $originalConfig = NULL;
	private bool $hadChrootPath = FALSE;
	private mixed $originalChrootPath = NULL;

	protected function setUp(): void
	{
		$this->hadPfb             = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb        = $GLOBALS['pfb'] ?? [];
		$this->hadConfig          = array_key_exists('config', $GLOBALS);
		$this->originalConfig     = $GLOBALS['config'] ?? NULL;
		$this->hadChrootPath      = array_key_exists('unbound_chroot_path', $GLOBALS['g'] ?? []);
		$this->originalChrootPath = $GLOBALS['g']['unbound_chroot_path'] ?? NULL;

		$this->dbdir = sys_get_temp_dir() . '/pfb_trigger_defer_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dbdir'              => $this->dbdir,
			'schedule_state_dir' => $this->dbdir,
			'log'                => "{$this->dbdir}/pfblockerng.log",
			'errlog'             => "{$this->dbdir}/error.log",
			'runlog'             => "{$this->dbdir}/run.log",
			'pending_marker'     => "{$this->dbdir}/pfb_pending_changes",
		]);
		$GLOBALS['config'] = [];
		$this->seedSyncPrereqs();

		// Safety net: were a guard regression to let the pass continue, the
		// boot/install early-return stops it before real feed work. The
		// before-state log assertions below prove the deferral path was taken,
		// so no row can go green through this early-return.
		$GLOBALS['g']['pfblockerng_install'] = TRUE;

		$this->resetDeferralLocks();

		// Fresh syslog capture (pfsense_doubles.php logger() double).
		$GLOBALS['pfb_test_logger_calls'] = [];
	}

	protected function tearDown(): void
	{
		$this->releaseDeferralLocks();
		unset($GLOBALS['g']['pfblockerng_install']);
		unset($GLOBALS['pfb_test_logger_calls']);

		foreach (glob("{$this->dbdir}/*") ?: [] as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->dbdir);

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		if ($this->hadChrootPath) {
			$GLOBALS['g']['unbound_chroot_path'] = $this->originalChrootPath;
		} else {
			unset($GLOBALS['g']['unbound_chroot_path']);
		}
	}

	/**
	 * Assert one captured syslog entry matches the dispatcher-deferral notice —
	 * message AND priority, so a LOG_NOTICE -> other-priority regression fails too
	 * (feed-pass parity is specifically LOG_NOTICE, per pfb_feed_pass_begin()).
	 */
	private function assertDispatcherDeferralNotice(): void
	{
		$this->assertStringContainsString('dispatcher lock', $this->syslogMessages(),
			'a wedged dispatcher-lock holder must be visible on syslog, not only in pfblockerng.log (issue #2505)');
		$priorities = [];
		foreach ($GLOBALS['pfb_test_logger_calls'] ?? [] as $call) {
			if (str_contains($call['message'], 'dispatcher lock')) {
				$priorities[] = $call['priority'];
			}
		}
		$this->assertContains(LOG_NOTICE, $priorities,
			'the dispatcher-lock deferral notice must be LOG_NOTICE (feed-pass parity) — got priorities: '
			. var_export($priorities, TRUE));
	}

	private static function cronTrigger(): array
	{
		return ['scope' => 'both', 'force' => FALSE, 'trigger' => 'cron'];
	}

	// The unattended tick dispatch retains its established TRUE return on deferral.

	public function testCronTriggerDispatcherDeferralPreservesTrueAndNamesLock(): void
	{
		$this->holdDispatcherLock();
		$deferredBy = NULL;

		$result = sync_package_pfblockerng(self::cronTrigger(), $deferredBy);

		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertTrue(pfb_pending_changes(),
			'the durable retry marker must survive the benign deferral (the next tick retries)');
		$this->assertTrue($result, 'trigger=cron must retain its established TRUE internal return');
		$this->assertSame('dispatcher-lock', $deferredBy);
	}

	public function testCronTriggerFeedPassDeferralPreservesTrueAndNamesLock(): void
	{
		$this->holdFeedPassLock();
		$deferredBy = NULL;

		$result = sync_package_pfblockerng(self::cronTrigger(), $deferredBy);

		$this->assertStringContainsString('Feed pass [ sync ] skipped', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertTrue(pfb_pending_changes(),
			'the durable retry marker must survive the benign deferral (the next tick retries)');
		$this->assertTrue($result, 'trigger=cron must retain its established TRUE internal return');
		$this->assertSame('feed-pass-lock', $deferredBy);
	}

	// Dispatcher-lock deferrals remain syslog-visible.

	public function testSyncFunnelDispatcherDeferralRaisesSyslogNotice(): void
	{
		$this->holdDispatcherLock();

		sync_package_pfblockerng(self::cronTrigger());

		$this->assertDispatcherDeferralNotice();
	}

	public function testCronFunnelDispatcherDeferralRaisesSyslogNotice(): void
	{
		$this->holdDispatcherLock();

		$this->assertTrue(pfblockerng_sync_cron(),
			'the unattended cron funnel must retain its established TRUE internal return');
		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertDispatcherDeferralNotice();
	}

	// Operator-triggered requests retain their established FALSE internal return.

	public function testManualTriggerDispatcherDeferralPreservesFalseAndNamesLock(): void
	{
		$this->holdDispatcherLock();
		$deferredBy = NULL;

		$result = sync_package_pfblockerng(
			['scope' => 'both', 'force' => FALSE, 'trigger' => 'manual'],
			$deferredBy
		);

		$this->assertStringContainsString('dispatcher lock unavailable', $this->mainLog(),
			'before-state: the run must actually have taken the dispatcher-deferral path');
		$this->assertFalse($result, 'operator-triggered requests must retain their established FALSE internal return');
		$this->assertSame('dispatcher-lock', $deferredBy);
	}

	public function testForcedCronTriggerFeedPassDeferralPreservesFalseAndNamesLock(): void
	{
		$this->holdFeedPassLock();
		$deferredBy = NULL;

		$result = sync_package_pfblockerng(
			['scope' => 'both', 'force' => TRUE, 'trigger' => 'cron'],
			$deferredBy
		);

		$this->assertStringContainsString('Feed pass [ sync ] skipped', $this->mainLog(),
			'before-state: the run must actually have taken the feed-pass deferral path');
		$this->assertFalse($result, 'force=true must retain its established FALSE internal return');
		$this->assertSame('feed-pass-lock', $deferredBy);
	}
}
