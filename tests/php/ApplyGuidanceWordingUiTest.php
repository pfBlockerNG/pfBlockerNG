<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3237 — user-facing apply guidance must name the actions that exist.
 *
 * The GUI's apply model is ADR-43's Update tab (Run Scope: Both/IP/DNSBL x Force:
 * None/Parse/Download/Both, "Run Now") plus the scheduled update, with #738's
 * pending-changes banner pointing at them. The retired button names ("Force Update",
 * "Force Reload", "Force Reload - DNSBL/IP") and the "applied via CRON or 'Force
 * Update|Reload' only!" footer must not instruct users anywhere under src/usr/local:
 * a user who follows them has no control to click. Per the #886 precedent, an
 * Update (Run Now / scheduled) is the action that applies these settings.
 *
 * Tier A render coverage for the changed pages lives in
 * tests/smoke/ui/test_render_smoke.py::test_apply_guidance_names_run_now_not_retired_actions.
 */
final class ApplyGuidanceWordingUiTest extends TestCase
{
	/** Retired GUI action names — no source line may carry them. */
	private const RETIRED_NEEDLES = ['Force Reload', 'Force Update', 'applied via CRON', 'next CRON update'];

	/**
	 * Page => guidance needles with the EXACT number of occurrences expected in that
	 * source. The count pins each independently rendered branch/template (a contains()
	 * check alone stays green when one of several identical callouts is dropped).
	 *
	 * @var array<string, array<string, int>>
	 */
	private const PAGE_NEEDLES = [
		'src/usr/local/www/pfblockerng/pfblockerng_general.php' => [
			'Setting changes are applied on the next scheduled update.' => 1,
			"Re-check it and run an Update (\\'Run Now\\' on the Update tab)" => 1,
			'<strong>Run Now</strong> on the Update tab' => 1,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php' => [
			'Setting changes are applied on the next scheduled update.' => 1,
			"A DNSBL reload is required for changes to take effect: run \\'Run Now\\'"
				. ' (Run Scope: DNSBL or Both) on the Update tab, or wait for the next scheduled update.' => 1,
			'Changes to this option will require an Update to take effect.' => 3,
			'These entries are applied with the next' => 1,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_ip.php' => [
			'Setting changes are applied on the next scheduled update.' => 1,
			'you must run a forced IP reload for the changes to take effect: on the Update tab,'
				. " run <strong>\\'Run Now\\' (Run Scope: IP, Force: Parse)</strong>." => 2,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_blacklist.php' => [
			'Setting changes are applied on the next scheduled update.' => 1,
			'A DNSBL reload is required for changes to take effect' => 1,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_category.php' => [
			'Setting changes are applied on the next scheduled update.' => 3,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php' => [
			'Click to SAVE Settings and/or Rule edits.&emsp;Changes are applied on the next scheduled update.' => 1,
			'A DNSBL reload is required for changes to take effect' => 1,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_safesearch.php' => [
			'Setting changes are applied on the next scheduled update.' => 1,
			"Run an Update ('Run Now' on the Update tab) to apply the changes!" => 1,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_sync.php' => [
			'Sync settings are used by the XMLRPC engine on each sync' => 1,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_hooks.php' => [
			"Hooks run on every update: the scheduled update and each \\'Run Now\\'." => 1,
			'a Run Now with Force: Download or Both' => 1,
			'a Run Now with Force: Parse' => 1,
		],
		'src/usr/local/www/pfblockerng/pfblockerng_alerts.php' => [
			'TLD Exclusions require an Update when a Domain is initially added.' => 1,
			'An Update is required to add the associated Firewall Permit Rule!' => 2,
			"use 'Run Now' (Run Scope: DNSBL, Force: Parse) on the Update tab"
				. " or run 'unbound-control flush_zone' to clear them." => 2,
		],
		'src/usr/local/www/widgets/widgets/pfblockerng.widget.php' => [
			'pfBlockerNG deDuplication is out of sync. Run an Update with Force: Parse to correct.' => 1,
			'is missing; run an Update with Run Scope: DNSBL (Force: Parse) to recover!' => 1,
		],
		'src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc' => [
			'Setting changes are applied on the next scheduled update.' => 2,
		],
		'src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc' => [
			'Changes to this option will require an Update to take effect.' => 1,
		],
		'src/usr/local/pkg/pfblockerng/pfblockerng.inc' => [
			'Fix error(s) and run an Update (Run Scope: DNSBL)!' => 2,
		],
	];

	/**
	 * @return list<string> every .php/.inc source path under src/usr/local, sorted
	 */
	private static function sources(): array
	{
		$paths = [];
		foreach (['src/usr/local/www', 'src/usr/local/pkg'] as $root) {
			$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
			foreach ($iterator as $file) {
				if (!$file->isFile()) {
					continue;
				}
				if (!in_array($file->getExtension(), ['php', 'inc'], TRUE)) {
					continue;
				}
				$paths[] = $file->getPathname();
			}
		}
		sort($paths);
		return $paths;
	}

	private static function repoPath(string $relative): string
	{
		return dirname(__DIR__, 2) . '/' . $relative;
	}

	public function testRetiredActionNamesAreAbsentFromSource(): void
	{
		$offenders = [];
		foreach (self::sources() as $path) {
			$lines = file($path) ?: [];
			foreach ($lines as $n => $line) {
				foreach (self::RETIRED_NEEDLES as $needle) {
					if (str_contains($line, $needle)) {
						$offenders[] = "{$path}:" . ($n + 1) . " still names the retired action '{$needle}'";
					}
				}
			}
		}
		$this->assertSame([], $offenders, "\n" . implode("\n", $offenders));
	}

	public function testSettingsPagesNameTheActionsThatExist(): void
	{
		$failures = [];
		foreach (self::PAGE_NEEDLES as $page => $needles) {
			$source = file_get_contents(self::repoPath($page));
			if ($source === FALSE) {
				$failures[] = "{$page}: unreadable";
				continue;
			}
			foreach ($needles as $needle => $expected) {
				$actual = substr_count($source, $needle);
				if ($actual !== $expected) {
					$failures[] = "{$page}: guidance '{$needle}' occurs {$actual}x, expected {$expected}x";
				}
			}
		}
		$this->assertSame([], $failures, "\n" . implode("\n", $failures));
	}
}
