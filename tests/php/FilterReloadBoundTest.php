<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Firewall-configuration reload -- DETACHED (owner directive 2026-09-05,
 * superseding the issue #2878 bound): pfb_filter_reload_exec() fires
 * /etc/rc.filter_configure_sync as a fire-and-forget background child. No wait,
 * no timeout kill: pfSense's reload is uncontrollable, and the script signals
 * filterd asynchronously anyway (its exit never meant the rules were live).
 * The ONE failure pfBlockerNG owns is the launch itself -- a missing or
 * non-executable script gate returns -1 and names itself in both logs. The
 * command is built inline (shape not observable), so these rows pin BEHAVIOR
 * with deterministic reload doubles in a temp dir, never the network or the
 * appliance; a detached leftover is pfSense's own domain, reaped by pidfile.
 */
final class FilterReloadBoundTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_reload_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
		]);
	}

	protected function tearDown(): void
	{
		// A detached double must never outlive the test -- reap it by its pidfile.
		$pidfile = "{$this->tmp}/detached.pid";
		if (is_file($pidfile)) {
			$pid = trim((string) file_get_contents($pidfile));
			if ($pid !== '') {
				exec('kill ' . escapeshellarg($pid) . ' 2>/dev/null');
			}
		}
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		// Recursive: the path-with-spaces row nests a directory under tmp, so a flat
		// glob+unlink would leave the tree behind and rmdir would fail silently.
		$items = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->tmp, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($items as $item) {
			$item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
		}
		@rmdir($this->tmp);
	}

	private function log(string $name): string
	{
		return (string) @file_get_contents("{$this->tmp}/{$name}");
	}

	/**
	 * Stand-in for /etc/rc.filter_configure_sync (which takes no arguments): the row's
	 * behavior IS the script body, so an executed row never starts a real reload.
	 */
	private function fakeReload(string $body = 'exit 0'): string
	{
		$path = "{$this->tmp}/rc.filter_configure_sync";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	/** Poll (bounded) for the detached double's side-effect file. */
	private function waitFor(string $path): bool
	{
		$deadline = microtime(TRUE) + 5.0;
		while (microtime(TRUE) < $deadline) {
			if (is_file($path)) {
				return TRUE;
			}
			usleep(50000);
		}
		return is_file($path);
	}

	/** Slice a php_strip_whitespace()'d source between two code anchors (comments cannot satisfy it). */
	private function scope(string $source, string $start, string $end): string
	{
		$from = strpos($source, $start);
		if ($from === FALSE) {
			throw new RuntimeException('route-pin scope start not found: ' . $start);
		}
		$to = strpos($source, $end, $from + strlen($start));
		if ($to === FALSE) {
			throw new RuntimeException('route-pin scope end not found: ' . $end);
		}
		return substr($source, $from, $to + strlen($end) - $from);
	}

	/**
	 * sync_package_pfblockerng() runs to the end of the apply pass, so its route-pin
	 * scope is the stripped source from the declaration to end-of-file.
	 */
	private function syncScope(string $source): string
	{
		$from = strpos($source, 'function sync_package_pfblockerng(');
		if ($from === FALSE) {
			throw new RuntimeException('route-pin scope start not found: sync_package_pfblockerng');
		}
		return substr($source, $from);
	}


	// ── Detached fire ───────────────────────────────────────────────────────────

	public function testHealthyReloadReturnsZero(): void
	{
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload();

		$status = pfb_filter_reload_exec();

		$this->assertSame(0, $status, 'a healthy detached fire must read as launched');
		$this->assertSame('', $this->log('pfblockerng.log'),
			'a clean launch must stay silent in the pfBlockerNG log');
	}

	public function testDetachedFireDoesNotWaitForASlowDouble(): void
	{
		// No-wait property, not a duration assertion: the double sleeps 30s, the
		// launcher must be back well under that, leaving the sleeper to pfSense.
		// The double records its own pid (pre-exec $$) so teardown can reap it.
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload(
			'echo $$ > "$(dirname "$0")/detached.pid"' . "\n" . 'exec sleep 30'
		);

		$started = microtime(TRUE);
		$status  = pfb_filter_reload_exec();
		$elapsed = microtime(TRUE) - $started;

		$this->assertSame(0, $status, 'a detached fire returns the launch status, never the child outcome');
		$this->assertLessThan(10.0, $elapsed, sprintf(
			'stuck/environment: the launcher blocked %.1fs on a detached double sleeping 30s',
			$elapsed,
		));
	}

	public function testChildOutputAndExitStayTheChildsOwn(): void
	{
		// Hostile row: the double prints to stdout and stderr, then exits non-zero.
		// The launcher owns only the launch -- output stays discarded (no capture
		// pipe to hold) and the child's exit is pfSense's own domain, so this must
		// read as launched AND return immediately.
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload(
			'echo "reload noise"; echo "more noise" >&2; exit 7'
		);

		$started = microtime(TRUE);
		$status  = pfb_filter_reload_exec();
		$elapsed = microtime(TRUE) - $started;

		$this->assertSame(0, $status,
			"a detached child's own output and exit status are not the launcher's failure");
		$this->assertLessThan(5.0, $elapsed,
			sprintf('stuck/environment: the launcher waited %.1fs for a double that exits instantly', $elapsed));
	}

	public function testDetachedChildNeverInheritsTheLauncherStdin(): void
	{
		// What this pins: the child never reads the launcher's stdin. Give a CHILD
		// launcher a readable stdin, fire the reload from there, and let the double
		// record what it saw. Killed mutant: making the launch synchronous (dropping
		// the trailing '&') makes the double read the payload, so this row is the
		// guard against a foreground launch creeping back.
		// What it deliberately does NOT pin: the explicit `< /dev/null` alone. POSIX
		// assigns /dev/null to an async list's stdin before any explicit redirection,
		// verified here: `printf PAYLOAD | sh -c 'read l && echo got || echo closed &'`
		// prints `closed`, the same foreground command prints `got` -- so removing the
		// redirect is behaviourally undetectable and stays as documented intent only.
		$probe  = "{$this->tmp}/stdin.seen";
		$script = $this->fakeReload(
			'if IFS= read -r line; then printf "inherited:%s" "$line" > ' . escapeshellarg($probe)
			. '; else printf closed > ' . escapeshellarg($probe) . '; fi'
		);
		// require_once: the PHPUnit bootstrap already loads the apply include.
		$child = sprintf(
			'require_once %s; require_once %s; $GLOBALS[%s] = %s; pfb_filter_reload_exec();',
			var_export(__DIR__ . '/bootstrap.php', TRUE),
			var_export(self::APPLY, TRUE),
			var_export('pfb', TRUE),
			var_export([
				'log'                   => "{$this->tmp}/pfblockerng.log",
				'errlog'                => "{$this->tmp}/error.log",
				'filter_configure_sync' => $script,
			], TRUE),
		);
		$proc = proc_open(
			[PHP_BINARY, '-r', $child],
			[
				0 => ['pipe', 'r'],
				1 => ['file', "{$this->tmp}/child.out", 'w'],
				2 => ['file', "{$this->tmp}/child.err", 'w'],
			],
			$pipes
		);
		$this->assertIsResource($proc, 'the stdin-bearing child launcher must start');
		fwrite($pipes[0], "PAYLOAD\n");
		fclose($pipes[0]);
		$this->assertSame(0, proc_close($proc), sprintf(
			'the child launcher must exit clean: %s',
			(string) @file_get_contents("{$this->tmp}/child.err"),
		));

		$this->assertTrue($this->waitFor($probe),
			'the detached double must record what it saw on stdin');
		$this->assertSame('closed', (string) file_get_contents($probe),
			"the detached child must read EOF on stdin, never the launcher's own payload");
	}

	// ── The launch gate: the one failure we own ─────────────────────────────────

	public function testMissingScriptIsTheOneOwnedLaunchFailure(): void
	{
		$GLOBALS['pfb']['filter_configure_sync'] = "{$this->tmp}/no-such-reload";

		$status = pfb_filter_reload_exec();

		$this->assertSame(-1, $status, 'a launch that cannot happen must never read as success');
		$this->assertStringContainsString('missing or not executable', $this->log('pfblockerng.log'),
			'the launch gate must name itself in the pfBlockerNG log');
		$this->assertStringContainsString('missing or not executable', $this->log('error.log'),
			'the launch gate must name itself in the error log');
	}

	public function testNonExecutableScriptIsRejectedByTheLaunchGate(): void
	{
		// 0644: no execute bit anywhere, so this holds for root and non-root alike.
		$path = $this->fakeReload();
		chmod($path, 0644);
		$GLOBALS['pfb']['filter_configure_sync'] = $path;

		$status = pfb_filter_reload_exec();

		$this->assertSame(-1, $status, 'a non-executable script is a launch failure, not a reload');
		$this->assertStringContainsString('missing or not executable', $this->log('error.log'));
	}

	public function testAbsentInjectionFallsBackToTheAppliancePath(): void
	{
		// The null-coalesce default is the ONLY reload path that runs on a real
		// appliance, and every other row injects a script -- so pin it here: with no
		// injection the gate must resolve /etc/rc.filter_configure_sync itself, and a
		// drifted default would name a different path in the log.
		unset($GLOBALS['pfb']['filter_configure_sync']);
		if (is_file('/etc/rc.filter_configure_sync')) {
			$this->markTestSkipped(
				'a real /etc/rc.filter_configure_sync is present: firing it is appliance behaviour, not a unit row'
			);
		}

		$status = pfb_filter_reload_exec();

		$this->assertSame(-1, $status, 'an absent appliance script is a launch failure, never success');
		// Bracket-delimited, NOT a bare substring: '/etc/rc.filter_configure_sync_TYPO'
		// contains the plain path, so a drifted default would slip past containment.
		$this->assertStringContainsString('[ /etc/rc.filter_configure_sync ]', $this->log('error.log'),
			'the gate must name exactly the appliance path the fallback resolved, not a drifted one');
	}

	public function testInjectedPathWithSpacesIsExecutedDetached(): void
	{
		// The command is built inline (escapeshellarg), so the pin is behavioral:
		// the injected path-with-spaces script IS the script that runs, proven by
		// its side-effect file appearing after the detached fire.
		$dir = "{$this->tmp}/dir with spaces";
		$this->assertTrue(mkdir($dir, 0700, TRUE));
		$side_effect = "{$dir}/detached-ran";
		$path = "{$dir}/rc.filter_configure_sync";
		file_put_contents($path, "#!/bin/sh\necho $$ > " . escapeshellarg("{$dir}/detached.pid") . "\n"
			. 'touch ' . escapeshellarg($side_effect) . "\n");
		chmod($path, 0755);
		$GLOBALS['pfb']['filter_configure_sync'] = $path;

		$this->assertSame(0, pfb_filter_reload_exec(), 'the injected script must launch');
		$this->assertTrue($this->waitFor($side_effect),
			'the detached child must actually have executed the injected path-with-spaces script');
	}

	// ── Route pins: the one launch call site ────────────────────────────────────
	//
	// POSITIVE (the site reaches the seam) AND NEGATIVE (no builder, no unbounded
	// mwexec boundary, no budget survives there) -- the negatives are what a
	// "restore the bound here" mutant has to kill. php_strip_whitespace() keeps
	// comments out of every half.

	public function testSyncPassRoutesTheFilterReloadThroughTheDetachedSeam(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		$scope = $this->syncScope($stripped);

		$this->assertSame(1, substr_count($scope, 'pfb_filter_reload_exec('),
			'the sync pass must preserve exactly one reload launch');
		$deleted_builder = 'pfb_filter_reload_' . 'cmd(';
		$this->assertSame(0, substr_count($stripped, $deleted_builder),
			'the superseded command builder must be gone (clean cutover)');
		$this->assertSame(0, substr_count($stripped, 'mwexec('),
			'no bare mwexec() boundary may survive anywhere in the apply pass');
	}

	public function testTheReloadStaysAheadOfTheFilterDaemonStage(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		$scope = $this->syncScope($stripped);

		$reload = strpos($scope, 'pfb_filter_reload_exec(');
		$daemon = strpos($scope, 'Restarting firewall filter daemon');
		$this->assertNotFalse($reload);
		$this->assertNotFalse($daemon);
		$this->assertLessThan($daemon, $reload,
			'the required ordering holds: the reload must precede the filter-daemon management stage');
	}

	public function testOnlyALaunchFailureLeavesTheFirewallStateUnknown(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		// The pin's scope is the call site's recovery region, never everything after
		// the seam's definition: that wider slice matched the definition's own text
		// and the pass's other pfb_mark_pending_changes() calls.
		$scope = $this->scope($this->syncScope($stripped), 'pfb_filter_reload_exec(',
			'Stopping firewall filter daemon');

		$this->assertStringContainsString('pfb_mark_pending_changes();', $scope,
			'the recovery branch must mark the pass pending so the next tick re-applies');
		$this->assertStringContainsString('$pfb_filter_reload_unknown = TRUE;', $scope,
			'only a launch failure may leave the firewall state unknown');
		$this->assertStringNotContainsString('124', $scope,
			'the budget concept is gone from this seam -- no expiry status may gate anything');
	}

	public function testClosingClearDoesNotWipeALaunchFailurePendingMark(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		$scope = $this->syncScope($stripped);
		$clear = strpos($scope, 'pfb_clear_pending_changes();');
		$this->assertNotFalse($clear, 'the pass still has a closing pending-marker clear');
		$window = substr($scope, max(0, $clear - 250), 350);
		$this->assertStringContainsString('$pfb_filter_reload_unknown', $window,
			'the closing clear must be gated so a launch-failure pending mark survives the rest of the pass');
	}
}
