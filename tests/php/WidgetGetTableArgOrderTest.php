<?php

declare(strict_types=1);

require_once __DIR__ . '/PidShimHarnessTrait.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WidgetGetTableArgOrderTest extends TestCase
{
	use PidShimHarnessTrait;

	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	protected function pidShimPrefix(): string
	{
		return 'pfb_widget_shim_';
	}

	public function testAjaxWidgetBranchExecutesTheShippedTableCall(): void
	{
		$result = $this->runWidget(['getNewWidget' => '1'], []);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringEndsWith('after-include', trim($result['stdout']));
	}

	public function testDefaultWidgetRenderExecutesTheShippedTableCall(): void
	{
		$result = $this->runWidget([], []);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringContainsString('<tbody id="pfBNG-table">', $result['stdout']);
	}

	/**
	 * Scenario: Combined sort (IP/DNSBL) is on (issue #3600).
	 * Given the stored widget-sortmix setting is 'on',
	 * When the widget renders,
	 * Then the table tells the header-sort handler so, and IP and DNSBL rows may interleave.
	 */
	public function testWidgetTableCarriesTheStoredCombinedSortSetting(): void
	{
		$result = $this->runWidget([], [], FALSE, "\$GLOBALS['config'] = ['installedpackages' => ['pfblockerngglobal' => ['widget-sortmix' => 'on']]];");
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertMatchesRegularExpression('/<table id="pfb-tbl"[^>]*\sdata-pfb-sortmix="on"/', $result['stdout']);
	}

	/**
	 * Scenario: the Upstream DNSBL row renders as a DNSBL group (issue #3602).
	 * Given an Upstream row as pfBlockerNG_update_table() builds it from the dnsbl table,
	 *   on a box where the pf table read failed,
	 * When the widget renders it,
	 * Then no PHP warning is raised, its packets link filters DNSBL (not IP) alerts,
	 *   its status icon is its own, not the pf error icon IP aliases get, its name gets
	 *   no firewall-alias popup, and the row is tagged dnsbl for the header-sort handler.
	 */
	public function testUpstreamRowRendersAsADnsblGroup(): void
	{
		$row = var_export(['count' => '5', 'img' => 'ROW_ICON', 'update' => '2026-10-26 10:00:00', 'packets' => '3', 'type' => 'DNSBL'], TRUE);
		$after = <<<PHP
\$pfb['pfctlerr'] = TRUE;
\$pfb['popup'] = 'on';
error_reporting(E_ALL);
\$diag = [];
set_error_handler(static function (int \$severity, string \$message) use (&\$diag): bool {
	\$diag[] = \$message;
	return TRUE;
});
echo "\\n__ROW__";
pfBlockerNG_get_table(['Upstream' => {$row}], 'js');
echo "__DIAG__" . json_encode(\$diag) . "\\n";
PHP;
		$result = $this->runWidget([], [], FALSE, '', $after);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$row = substr($result['stdout'], (int) strpos($result['stdout'], '__ROW__') + 7);
		$this->assertStringContainsString("\n__DIAG__[]\n", $row, 'rendering the Upstream row must raise no PHP diagnostic');
		$cols = explode('||', (string) strtok($row, "\n"));
		$this->assertCount(6, $cols, 'one js-mode row: alias||count||packets||update||img||group');
		$this->assertStringNotContainsString('firewall_aliases_edit.php', $cols[0]);
		$this->assertStringContainsString('filterdnsbl=Upstream', $cols[2]);
		$this->assertSame('ROW_ICON', $cols[4]);
		$this->assertSame('dnsbl', $cols[5]);
	}

	/**
	 * Scenario: an IP alias row as pfBlockerNG_update_table() builds it from a block rule.
	 * When the widget renders it,
	 * Then its packets link filters IP (not DNSBL) alerts and the row is tagged ip.
	 */
	public function testIpAliasRowRendersAsAnIpGroup(): void
	{
		$row = var_export(['count' => '5', 'img' => 'ROW_ICON', 'update' => '', 'packets' => '3', 'rule' => 2, 'type' => 'Block', 'id' => 7], TRUE);
		$after = <<<PHP
echo "\\n__ROW__";
pfBlockerNG_get_table(['pfB_Top_v4' => {$row}], 'js');
PHP;
		$result = $this->runWidget([], [], FALSE, '', $after);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$cols = explode('||', (string) strtok(substr($result['stdout'], (int) strpos($result['stdout'], '__ROW__') + 7), "\n"));
		$this->assertStringContainsString('filterip=pfB_Top_v4', $cols[2]);
		$this->assertSame('ip', $cols[5]);
	}

	/**
	 * Scenario: the header counts a row by its group too (issue #3602).
	 * Given a block rule with 77 packets on an IP alias that has no aliases/alias entry,
	 *   so its row carries no alias id,
	 * When the widget refreshes,
	 * Then those packets count as Deny, not DNSBL.
	 */
	public function testHeaderCountsAnIpRowWithoutAnAliasIdAsIp(): void
	{
		$setup = "\$GLOBALS['config'] = ['filter' => ['rule' => [['tracker' => '100', 'type' => 'block', 'descr' => 'x', 'destination' => ['address' => 'pfB_Stale_v4']]]]];"
			. "\$GLOBALS['pfb_test_pf_rules'] = [['tracker' => '100', 'packets' => 77]];";
		$result = $this->runWidget(['getNewWidget' => '1'], [], FALSE, $setup);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringContainsString('Deny||Number of BLOCK & REJECT packet(s) blocked: 77_BR_', $result['stdout']);
	}

	/**
	 * Scenario: a row's group comes from where the server built it, not from its name.
	 * Given an IP alias row named like a DNSBL group, and a DNSBL row named like an IP alias,
	 * When the widget renders them for the first page load,
	 * Then each <tr> carries its real group for the header-sort handler (issue #3602).
	 */
	public function testRowsAreTaggedByTheirGroupNotTheirName(): void
	{
		$ip = var_export(['count' => '1', 'img' => '', 'update' => '', 'packets' => 0, 'rule' => 1, 'type' => 'Block', 'id' => 3], TRUE);
		$dnsbl = var_export(['count' => '1', 'img' => '', 'update' => '', 'packets' => '0', 'type' => 'DNSBL'], TRUE);
		$after = <<<PHP
echo "\\n__ROWS__";
pfBlockerNG_get_table(['DNSBL_lookalike' => {$ip}, 'pfB_lookalike' => {$dnsbl}]);
PHP;
		$result = $this->runWidget([], [], FALSE, '', $after);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$rows = substr($result['stdout'], (int) strpos($result['stdout'], '__ROWS__'));
		$this->assertMatchesRegularExpression('/<tr data-pfb-group="ip">\s*<td><small>DNSBL_lookalike</', $rows);
		$this->assertMatchesRegularExpression('/<tr data-pfb-group="dnsbl">\s*<td><small>pfB_lookalike</', $rows);
	}

	/**
	 * Does the widget collect DNSBL statistics (pfBlockerNG_update_table() looks for the DNSBL database, and flags it missing when
	 * it holds nothing) on a box with DNSBL stored On, an empty DNSBL database of its own and these two enables stored ('on' or '')?
	 */
	private function widgetCollectsDnsblStatistics(string $package, string $pfbDns): bool
	{
		$stored = ['installedpackages' => [
			'pfblockerng' => ['config' => [['enable_cb' => $package]]],
			'pfblockerngdns' => ['config' => [['pfb_dns' => $pfbDns]]],
			'pfblockerngdnsblsettings' => ['config' => [['pfb_dnsbl' => 'on']]],
		]];
		$database = sys_get_temp_dir() . '/pfb_widget_dnsbl_' . getmypid() . '_' . bin2hex(random_bytes(4)) . '.sqlite';
		try {
			$result = $this->runWidget(
				['getNewWidget' => '1'], [], FALSE,
				"\$GLOBALS['config'] = " . var_export($stored, TRUE) . ";\$GLOBALS['pfb']['dnsbl_info'] = " . var_export($database, TRUE) . ';',
				'echo "\n__DNSBL_MISSING__" . (isset($GLOBALS[\'pfb\'][\'dnsbl_missing\']) ? \'yes\' : \'no\');'
			);
		} finally {
			@unlink($database);
		}
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertMatchesRegularExpression('/\n__DNSBL_MISSING__(yes|no)/', $result['stdout']);
		return str_contains($result['stdout'], "\n__DNSBL_MISSING__yes");
	}

	/** @return array<string,array{string,string}> the stored pfBlockerNG enable and pfB-DNS enable of a box with DNSBL stored On, one of them off */
	public static function dnsblParentSwitchOffRows(): array
	{
		return ['pfBlockerNG off' => ['', 'on'], 'pfB-DNS off' => ['on', '']];
	}

	/**
	 * Scenario: pfB-DNS is a parent switch of DNSBL, as the pfBlockerNG enable is (issue #3770).
	 * Given a box with DNSBL stored On and no DNSBL database rows yet,
	 * When the widget refreshes with both switches on, and again with one of them off,
	 * Then it looks for DNSBL statistics (and flags the empty database) only while DNSBL runs: not with a parent switch off.
	 */
	#[DataProvider('dnsblParentSwitchOffRows')]
	public function testTheWidgetCollectsDnsblStatisticsOnlyWhileBothParentSwitchesOfDnsblAreOn(string $package, string $pfbDns): void
	{
		$this->assertTrue($this->widgetCollectsDnsblStatistics('on', 'on'), 'before: DNSBL runs, so its statistics are collected');

		$this->assertFalse($this->widgetCollectsDnsblStatistics($package, $pfbDns));
	}

	/**
	 * Scenario: the include shim is per-invocation scratch.
	 * Given a render of the real widget,
	 * When the subprocess exits,
	 * Then the temp directory holds nothing keyed to that run -- a shim left
	 * behind is what lets a later run on a recycled PID collide (issue #2834).
	 */
	public function testWidgetRunLeavesNoShimResidue(): void
	{
		// A checkout without this fix, sharing the host, can already hold a bare
		// pfb_widget_shim_<pid>, so only what this run added counts.
		$before = glob(sys_get_temp_dir() . '/pfb_widget_shim_*') ?: [];
		$result = $this->runWidget([], []);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertSame([], array_diff($this->shimResidue($result['pid']), $before));
	}

	/**
	 * Scenario: the OS recycles a PID an earlier suite run already used.
	 * Given a shim directory already sitting at this run's PID-keyed path,
	 * When the real widget renders,
	 * Then it renders as usual, never writes into the directory it inherited,
	 * and adds no residue of its own beside it.
	 */
	public function testWidgetSurvivesAShimLeftOverFromARecycledPid(): void
	{
		$result = $this->runWidget([], [], TRUE);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringContainsString('<tbody id="pfBNG-table">', $result['stdout']);
		$this->assertSame([], glob($this->planted[0] . '/*') ?: [], 'a per-invocation shim path must never adopt an inherited directory');
		$this->assertSame([], array_diff($this->shimResidue($result['pid']), $this->planted));
	}

	/** @return array{status:int,stdout:string,stderr:string,pid:int} */
	private function runWidget(array $get, array $post, bool $plantStaleShim = FALSE, string $setup = '', string $after = ''): array
	{
		$root = var_export(self::ROOT, TRUE);
		$widget = var_export(self::WIDGET, TRUE);
		$getCode = var_export($get, TRUE);
		$postCode = var_export($post, TRUE);
		$preamble = $this->pidShimPreamble('widget include shim creation failed');
		$script = <<<PHP
stream_get_contents(STDIN);
\$GLOBALS['argv'] = ['widget'];
error_reporting(E_ERROR | E_PARSE);
\$_GET = {$getCode};
\$_POST = {$postCode};
\$_SERVER = [];\$widgetname = 'pfblockerng';
{$preamble}
require {$root} . '/tests/php/bootstrap.php';
{$setup}
require {$widget};
{$after}
echo 'after-include';
PHP;
		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$pid = (int) proc_get_status($process)['pid'];
		if ($plantStaleShim) {
			// The child blocks on STDIN until the pipe is closed below, so the
			// plant always lands before it creates its own shim.
			$this->plantStaleShim($pid);
		}
		fclose($pipes[0]);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		return ['status' => $status, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr, 'pid' => $pid];
	}
}
