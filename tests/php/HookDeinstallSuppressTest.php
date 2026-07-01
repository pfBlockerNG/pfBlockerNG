<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #682: pfb_run_hooks() must fire NO ADR-12 hooks during a package removal.
 *
 * The pre-deinstall (pfblockerng_php_pre_deinstall_command) runs sync_package_pfblockerng()
 * to DISABLE and tear pfBlockerNG down, but that pass still reached the hook runner -- so a
 * user's pre/post hook (e.g. a HAProxy graceful reload) fired during "Removing pfBlockerNG...".
 * A hook that (re)starts a service blocks the pkg operation indefinitely (the #662 pipe/daemon
 * class, here under pkg's context) -- the reported "stuck on Removing pfBlockerNG" hang. The
 * fix marks the removal pass with $pfb['deinstall'] and makes pfb_run_hooks() short-circuit on
 * it, before it ever processes the configured hooks.
 *
 * Observable seam (no hook is executed off-appliance): a configured hook whose script is absent
 * from PFB_HOOK_SCRIPT_DIR makes pfb_run_hooks() log an allow-list "not a valid file; skipping"
 * line when it PROCESSES the hook. The presence of that line proves the runner reached its
 * per-hook loop; its ABSENCE proves the deinstall guard returned first. The runner's actual
 * exec path stays ADR-04 live-smoke territory (see PfbGetHooksTest's note).
 */
#[CoversFunction('pfb_run_hooks')]
final class HookDeinstallSuppressTest extends TestCase
{
	private string $logfile = '';
	private string $errfile = '';
	/** @var array<string, mixed> snapshot of the $pfb keys this test mutates, restored in tearDown. */
	private array $pfbSaved = [];
	private mixed $configSaved = null;

	protected function setUp(): void
	{
		global $pfb;

		// Snapshot every global this test touches so no mutation leaks to sibling suites
		// (a stray unset of e.g. $pfb['runlog'] would break the live-log tail tests).
		$this->pfbSaved = [
			'log'           => $pfb['log'] ?? null,
			'errlog'        => $pfb['errlog'] ?? null,
			'deinstall'     => $pfb['deinstall'] ?? null,
			'runlog_active' => $pfb['runlog_active'] ?? null,
		];
		$this->configSaved = $GLOBALS['config'] ?? null;

		$this->logfile = tempnam(sys_get_temp_dir(), 'pfb_hooklog_');
		$this->errfile = tempnam(sys_get_temp_dir(), 'pfb_hookerr_');
		// pfb_logger() (logtype 2) appends to both of these; seed them so the runner's
		// "skipping" line has somewhere to land and stays isolated to this test.
		$pfb['log']    = $this->logfile;
		$pfb['errlog'] = $this->errfile;
		// A clean slate: neither a removal pass nor a live per-run mirror (do NOT unset
		// $pfb['runlog'] itself -- sibling tests read it).
		unset($pfb['deinstall'], $pfb['runlog_active']);

		// One ENABLED post hook whose script does not exist on this (non-appliance) box, in the
		// canonical 'row' listtag storage shape pfb_get_hooks() reads.
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerng' => ['config' => [0 => [
			'hooks' => ['row' => [
				['script' => 'hook_post_bogus.sh', 'when' => 'post', 'enabled' => 'on',
					'description' => 'deinstall-suppress-test'],
			]],
		]]]]];
	}

	protected function tearDown(): void
	{
		global $pfb;

		foreach ($this->pfbSaved as $key => $val) {
			if ($val === null) {
				unset($pfb[$key]);
			} else {
				$pfb[$key] = $val;
			}
		}
		$GLOBALS['config'] = $this->configSaved;
		@unlink($this->logfile);
		@unlink($this->errfile);
	}

	/**
	 * Baseline (before-state): with NO removal in progress, pfb_run_hooks() PROCESSES the
	 * configured hook and reaches the script allow-list gate -- proven by the "not a valid file"
	 * line for its absent script. This is the state the suppression test flips away from.
	 */
	public function testEnabledHookIsProcessedWhenNotDeinstalling(): void
	{
		pfb_run_hooks('post', ['TRIGGER' => 'cron']);

		$this->assertStringContainsString(
			'not a valid file',
			(string) file_get_contents($this->logfile),
			'baseline: a normal (non-removal) pass must PROCESS the configured hook (reach the script gate)'
		);
	}

	/**
	 * The fix: during a package-removal pass ($pfb['deinstall']), pfb_run_hooks() must return
	 * immediately and touch NO hook -- so the log stays empty (not even the "skipping" line).
	 *
	 * Red -> green: without the guard, the deinstall flag has no effect, the runner still
	 * processes the hook and logs the "not a valid file" line, so this assertSame('') FAILS.
	 * With the guard it short-circuits and the log is empty.
	 */
	public function testHooksSuppressedDuringDeinstall(): void
	{
		global $pfb;

		$pfb['deinstall'] = TRUE;
		pfb_run_hooks('post', ['TRIGGER' => 'cron']);

		$this->assertSame(
			'',
			(string) file_get_contents($this->logfile),
			'during a deinstall pass pfb_run_hooks() must fire NO hooks and log nothing (#682)'
		);
	}
}
