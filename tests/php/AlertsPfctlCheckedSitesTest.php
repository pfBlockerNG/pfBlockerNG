<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1505: four `pfctl -T add/delete` exec() calls in
 * pfblockerng_alerts.php ignored the exec status outright -- a failed
 * mutation still got the config/store write and a success savemsg (fail-open
 * unblocking, or store/table drift): delete_ip's re-add, delete_ipwhitelist's
 * delete, ip_remove=lock's re-add, and ip_white's add. The fix routes each
 * through pfb_pfctl_checked_op() (pfblockerng_extra.inc, built on the
 * fail-closed pfb_live_punch_apply()) and gates every store write + the
 * success savemsg on the outcome.
 *
 * The four handlers live in top-level script code (a switch/if chain inside
 * pfblockerng_alerts.php's `if (isset($_POST))` block), not functions, so
 * each region is eval-extracted verbatim from the REAL source -- same
 * technique as CategoryEditPostGuardTest -- anchored on text stable across
 * both the pre-fix and post-fix code, so this one file proves red on the old
 * code and green on the new. delete_ip/delete_ipwhitelist keep their case's
 * own trailing `break;`, so those two are wrapped in a `switch (1) { case 1:
 * ... }` shell; the lock/ip_white regions are plain statement lists and are
 * eval'd directly. ip_white's extraction stops BEFORE the header() call
 * (calling header()/exit() inside a test would kill the process) -- this
 * only works because the fix hoists header()+exit() to run once after the
 * if/else (never duplicated per-branch), which is also why the SAME
 * extraction anchor resolves in both the pre-fix and post-fix source.
 *
 * Uses the same injectable pfctl shim pattern as AlertsLivePunchApplyTest
 * (writeShim() + PFB_TEST_LOG argv log + PFB_TEST_RULES scripted per-op
 * failures) since pfb_pfctl_checked_op() ultimately execs through the same
 * `pfctl -t <table> -T <op> <entry>` shape.
 */
final class AlertsPfctlCheckedSitesTest extends TestCase
{
	private string $tmp;
	private string $shim;
	private string $logPath;
	private string $rulesPath;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_alerts.php');
		}

		// Region 1: the delete_ip case body (own trailing break;) -- wrapped in a
		// throwaway switch so `break;` has a valid target.
		if (!function_exists('pfb_alerts_oracle_delete_ip')) {
			if (!preg_match(
				'/case \'delete_ip\':\n(.*?)\n\t\t\tcase \'delete_ipwhitelist\':/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: delete_ip region not found');
			}
			eval(
				'function pfb_alerts_oracle_delete_ip(string $entry, string $table, array &$clists): array {'
				. ' global $pfb; $pfb_found = TRUE; $savemsg = \'\'; $type = \'\';'
				. ' switch (1) { case 1:'
				. $m[1]
				. ' }'
				. ' return [\'pfb_found\' => $pfb_found, \'savemsg\' => $savemsg]; }'
			);
		}

		// Region 2: the delete_ipwhitelist case body (own trailing break;).
		if (!function_exists('pfb_alerts_oracle_delete_ipwhitelist')) {
			if (!preg_match(
				'/case \'delete_ipwhitelist\':\n(.*?)\n\t\t\tdefault:/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: delete_ipwhitelist region not found');
			}
			eval(
				'function pfb_alerts_oracle_delete_ipwhitelist(string $entry, string $table, array &$clists): array {'
				. ' global $pfb; $pfb_found = TRUE; $savemsg = \'\'; $type = \'\';'
				. ' switch (1) { case 1:'
				. $m[1]
				. ' }'
				. ' return [\'pfb_found\' => $pfb_found, \'savemsg\' => $savemsg]; }'
			);
		}

		// Region 3: the ip_remove=='lock' elseif branch (its own open+close braces).
		// The anchor is `elseif (...) {` since it sits alongside an `if ($_POST[
		// 'ip_remove'] == 'unlock')` sibling -- rewritten to `if` so it evals as a
		// standalone statement. The end anchor skips over the trailing catch-all
		// `else { ... }` (invalid ip_remove action) to the shared header() call
		// after the whole if/elseif/else chain (2-tab indent, blank line before it).
		if (!function_exists('pfb_alerts_oracle_ip_lock')) {
			if (!preg_match(
				'/(elseif \(\$_POST\[\'ip_remove\'\] == \'lock\'\) \{\n.*?\n\t\t\})\n\n\t\telse \{\n.*?\n\t\t\}\n\n\t\theader\(/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: ip_remove lock region not found');
			}
			$body = preg_replace('/^elseif\b/', 'if', $m[1], 1);
			eval(
				'function pfb_alerts_oracle_ip_lock(string $ip, string $table, array $ip_unlock = []): string {'
				. ' global $pfb; $_POST[\'ip_remove\'] = \'lock\';'
				. ' $table_esc = escapeshellarg($table); $savemsg = \'\';'
				. $body
				. ' return $savemsg; }'
			);
		}

		// Region 4: the ip_white if(!isset(...)) body -- captured WITHOUT its
		// enclosing braces (the wrapper always wants this branch to run) and
		// stopping BEFORE the header() call (3-tab indent, no blank line before
		// it): calling header()/exit() inside PHPUnit would abort the process.
		if (!function_exists('pfb_alerts_oracle_ip_white')) {
			if (!preg_match(
				'/if \(!isset\(\$clists\[\'ipwhitelist\' \. \$vtype\]\[\$table\]\[\'data\'\]\[\$ip\]\)\) \{\n(.*?)\n\t\t\theader\(/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: ip_white region not found');
			}
			eval(
				'function pfb_alerts_oracle_ip_white(string $ip, string $table, string $vtype, string $descr, array &$clists): array {'
				. ' global $pfb; $ip_esc = escapeshellarg($ip); $table_esc = escapeshellarg($table);'
				. ' $savemsg = \'\';'
				. $m[1]
				. ' return [\'savemsg\' => $savemsg, \'clists\' => $clists]; }'
			);
		}
	}

	protected function setUp(): void
	{
		global $pfb;

		$this->tmp       = sys_get_temp_dir() . '/pfb_alerts_checked_sites_' . getmypid() . '_' . bin2hex(random_bytes(6));
		mkdir($this->tmp, 0777, TRUE);
		mkdir("{$this->tmp}/alias", 0777, TRUE);
		mkdir("{$this->tmp}/permit", 0777, TRUE);

		$this->logPath   = "{$this->tmp}/calls.log";
		$this->rulesPath = "{$this->tmp}/rules.tsv";
		putenv("PFB_TEST_LOG={$this->logPath}");
		putenv("PFB_TEST_RULES={$this->rulesPath}");
		$this->shim = $this->writeShim();

		$pfb['pfctl']     = $this->shim;
		$pfb['aliasdir']  = "{$this->tmp}/alias";
		$pfb['permitdir'] = "{$this->tmp}/permit";
		$pfb['ip_unlock'] = "{$this->tmp}/ip_unlock.txt";
		$pfb['supptxt']    = "{$this->tmp}/pfbsuppression.txt";
		$pfb['supptxt_v6'] = "{$this->tmp}/pfbsuppression_v6.txt";
		$pfb['ipconfig']   = ['v4suppression' => '', 'v6suppression' => ''];

		// pfb_logger() (called on a scripted pfctl failure) needs a writable log dir --
		// same seeding as AlertsLivePunchApplyTest/AliasDeltaApplyTest.
		$pfb['logdir'] = "{$this->tmp}/log";
		$pfb['log']    = "{$pfb['logdir']}/pfblockerng.log";
		$pfb['errlog'] = "{$pfb['logdir']}/pfblockerng_error.log";
		@mkdir($pfb['logdir'], 0777, TRUE);
		@file_put_contents($pfb['log'], '');
		@file_put_contents($pfb['errlog'], '');

		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		putenv('PFB_TEST_LOG');
		putenv('PFB_TEST_RULES');
		rmdir_recursive($this->tmp);
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['config']);
	}

	/** Same shim shape as AlertsLivePunchApplyTest::writeShim(). */
	private function writeShim(): string
	{
		$shim = "{$this->tmp}/pfctl_shim.sh";
		file_put_contents($shim, <<<'SH'
#!/bin/sh
table=""
op=""
entry=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		-t) table="$2"; shift 2 ;;
		-T) op="$2"; shift 2 ;;
		*) entry="$1"; shift ;;
	esac
done
printf '%s|%s|%s\n' "$op" "$table" "$entry" >> "$PFB_TEST_LOG"
if [ -z "$entry" ]; then
	printf 'pfctl: no address specified\n' >&2
	exit 1
fi
if [ -f "$PFB_TEST_RULES" ]; then
	while IFS='|' read -r r_op r_entry r_rc r_err; do
		if [ "$r_op" = "$op" ] && [ "$r_entry" = "$entry" ]; then
			if [ -n "$r_err" ]; then
				printf '%s\n' "$r_err" >&2
			fi
			exit "$r_rc"
		fi
	done < "$PFB_TEST_RULES"
fi
if [ "$op" = "add" ]; then
	printf '1/1 addresses added.\n'
else
	printf '1/1 addresses deleted.\n'
fi
exit 0
SH
		);
		chmod($shim, 0755);
		return $shim;
	}

	/** Script the shim to fail a specific op+entry call. */
	private function scriptFailure(string $op, string $entry, int $rc = 1, string $err = 'pfctl: forced failure'): void
	{
		file_put_contents($this->rulesPath, "{$op}|{$entry}|{$rc}|{$err}\n", FILE_APPEND);
	}

	// =====================================================================
	// delete_ip
	// =====================================================================

	public function testDeleteIpV4FailureKeepsSuppressionEntryAndSkipsWrite(): void
	{
		$this->scriptFailure('add', '198.51.100.5');
		$clists = ['ipsuppression' => ['data' => ['198.51.100.5' => "198.51.100.5\r\n"]]];

		$result = pfb_alerts_oracle_delete_ip("'198.51.100.5'", "'pfB_Deny_v4'", $clists);

		$this->assertFalse($result['pfb_found'], 'a failed re-add must not report success ($pfb_found)');
		$this->assertStringContainsString('failed', $result['savemsg'], 'savemsg must name the failure');
		$this->assertArrayHasKey(
			'198.51.100.5',
			$clists['ipsuppression']['data'],
			'a failed re-add must KEEP the suppression customlist entry'
		);
	}

	public function testDeleteIpV4SuccessRemovesEntryAndWrites(): void
	{
		$clists = ['ipsuppression' => ['data' => ['198.51.100.5' => "198.51.100.5\r\n"]]];

		$result = pfb_alerts_oracle_delete_ip("'198.51.100.5'", "'pfB_Deny_v4'", $clists);

		$this->assertTrue($result['pfb_found']);
		$this->assertStringContainsString('Removed', $result['savemsg']);
		$this->assertArrayNotHasKey('198.51.100.5', $clists['ipsuppression']['data']);
		$this->assertSame(
			['add', 'pfB_Deny_v4', '198.51.100.5'],
			$this->lastLogRow(),
			'the re-add must reach pfctl as -t pfB_Deny_v4 -T add 198.51.100.5'
		);
	}

	public function testDeleteIpV6FailureKeepsSuppressionEntryAndSkipsWrite(): void
	{
		$this->scriptFailure('add', '2001:db8::5');
		$clists = ['ipsuppression_v6' => ['data' => ['2001:db8::5' => "2001:db8::5\r\n"]]];

		$result = pfb_alerts_oracle_delete_ip("'2001:db8::5'", "'pfB_Deny_v6'", $clists);

		$this->assertFalse($result['pfb_found']);
		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertArrayHasKey('2001:db8::5', $clists['ipsuppression_v6']['data']);
	}

	public function testDeleteIpV6SuccessRemovesEntryAndWrites(): void
	{
		$clists = ['ipsuppression_v6' => ['data' => ['2001:db8::5' => "2001:db8::5\r\n"]]];

		$result = pfb_alerts_oracle_delete_ip("'2001:db8::5'", "'pfB_Deny_v6'", $clists);

		$this->assertTrue($result['pfb_found']);
		$this->assertArrayNotHasKey('2001:db8::5', $clists['ipsuppression_v6']['data']);
	}

	// =====================================================================
	// delete_ipwhitelist
	// =====================================================================

	public function testDeleteIpWhitelistV4FailureKeepsEntryAndSkipsWrite(): void
	{
		$this->scriptFailure('delete', '198.51.100.9');
		$clists = ['ipwhitelist4' => ['pfB_Permit_v4' => ['base64_idx' => 0, 'data' => ['198.51.100.9' => "198.51.100.9\r\n"]]]];

		$result = pfb_alerts_oracle_delete_ipwhitelist("'198.51.100.9'", "'pfB_Permit_v4'", $clists);

		$this->assertFalse($result['pfb_found'], 'a failed delete must not report success ($pfb_found)');
		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertArrayHasKey(
			'198.51.100.9',
			$clists['ipwhitelist4']['pfB_Permit_v4']['data'],
			'a failed delete must KEEP the Permit customlist entry'
		);
	}

	public function testDeleteIpWhitelistV4SuccessRemovesEntryAndWrites(): void
	{
		$clists = ['ipwhitelist4' => ['pfB_Permit_v4' => ['base64_idx' => 0, 'data' => ['198.51.100.9' => "198.51.100.9\r\n"]]]];

		$result = pfb_alerts_oracle_delete_ipwhitelist("'198.51.100.9'", "'pfB_Permit_v4'", $clists);

		$this->assertTrue($result['pfb_found']);
		$this->assertStringContainsString('deleted', $result['savemsg']);
		$this->assertArrayNotHasKey('198.51.100.9', $clists['ipwhitelist4']['pfB_Permit_v4']['data']);
		$this->assertSame(
			['delete', 'pfB_Permit_v4', '198.51.100.9'],
			$this->lastLogRow(),
			'the delete must reach pfctl as -t pfB_Permit_v4 -T delete 198.51.100.9'
		);
	}

	public function testDeleteIpWhitelistV6FailureKeepsEntryAndSkipsWrite(): void
	{
		$this->scriptFailure('delete', '2001:db8::9');
		$clists = ['ipwhitelist6' => ['pfB_Permit_v6' => ['base64_idx' => 0, 'data' => ['2001:db8::9' => "2001:db8::9\r\n"]]]];

		$result = pfb_alerts_oracle_delete_ipwhitelist("'2001:db8::9'", "'pfB_Permit_v6'", $clists);

		$this->assertFalse($result['pfb_found']);
		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertArrayHasKey('2001:db8::9', $clists['ipwhitelist6']['pfB_Permit_v6']['data']);
	}

	public function testDeleteIpWhitelistV6SuccessRemovesEntryAndWrites(): void
	{
		$clists = ['ipwhitelist6' => ['pfB_Permit_v6' => ['base64_idx' => 0, 'data' => ['2001:db8::9' => "2001:db8::9\r\n"]]]];

		$result = pfb_alerts_oracle_delete_ipwhitelist("'2001:db8::9'", "'pfB_Permit_v6'", $clists);

		$this->assertTrue($result['pfb_found']);
		$this->assertArrayNotHasKey('2001:db8::9', $clists['ipwhitelist6']['pfB_Permit_v6']['data']);
	}

	// =====================================================================
	// ip_remove == 'lock'
	// =====================================================================

	// Seeding a non-empty $ip_unlock (with a leftover 'keepme' entry) matters:
	// pfb_unlock('lock', ...) always fopen()s the store file and, when the
	// resulting set is empty, unlinks it right back -- an empty seed would make
	// "no write happened" and "wrote then self-deleted" indistinguishable. With
	// a leftover entry, a genuine write leaves an observable file.

	public function testIpRemoveLockFailureSkipsUnlockStoreWrite(): void
	{
		$this->scriptFailure('add', '198.51.100.20');
		$ip_unlock = ['198.51.100.20' => 'pfB_Deny_v4', 'keepme.example' => 'pfB_Keep_v4'];

		$savemsg = pfb_alerts_oracle_ip_lock('198.51.100.20', 'pfB_Deny_v4', $ip_unlock);

		$this->assertStringContainsString('failed', $savemsg);
		$this->assertFileDoesNotExist(
			$GLOBALS['pfb']['ip_unlock'],
			'a failed re-lock must NOT write the unlock store -- the IP genuinely stays unlocked'
		);
	}

	public function testIpRemoveLockSuccessAppliesUnlockStoreWrite(): void
	{
		$ip_unlock = ['198.51.100.20' => 'pfB_Deny_v4', 'keepme.example' => 'pfB_Keep_v4'];

		$savemsg = pfb_alerts_oracle_ip_lock('198.51.100.20', 'pfB_Deny_v4', $ip_unlock);

		$this->assertStringContainsString('re-locked', $savemsg);
		$this->assertFileExists($GLOBALS['pfb']['ip_unlock'], 'a successful re-lock must apply the unlock store write');
		$content = file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content, 'the untouched leftover entry must survive the rewrite');
		$this->assertStringNotContainsString('198.51.100.20', $content, 'the re-locked IP must be removed from the unlock store');
	}

	public function testIpRemoveLockZoneIdHostileEntryFailureSkipsStoreWrite(): void
	{
		// PFB_FILTER_IP passes zone-id IPv6 shapes (fe80::1%em0) -- a zone-id host
		// recorded in the unlock store, then fed back into the lock re-add.
		$this->scriptFailure('add', 'fe80::1%em0');
		$ip_unlock = ['fe80::1%em0' => 'pfB_Deny_v6', 'keepme.example' => 'pfB_Keep_v4'];

		$savemsg = pfb_alerts_oracle_ip_lock('fe80::1%em0', 'pfB_Deny_v6', $ip_unlock);

		$this->assertStringContainsString('failed', $savemsg);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['ip_unlock']);
	}

	// =====================================================================
	// ip_white
	// =====================================================================

	public function testIpWhiteV4FailureSkipsAllWrites(): void
	{
		$this->scriptFailure('add', '198.51.100.30');
		$clists = ['ipwhitelist4' => ['pfB_Whitelist_v4' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_oracle_ip_white('198.51.100.30', 'pfB_Whitelist_v4', '4', '', $clists);

		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertArrayNotHasKey(
			'198.51.100.30',
			$result['clists']['ipwhitelist4']['pfB_Whitelist_v4']['data'],
			'a failed add must not update the in-memory customlist'
		);
		$this->assertFileDoesNotExist(
			"{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v4.txt",
			'a failed add must NOT append to the aliasdir .txt file'
		);
		$this->assertArrayNotHasKey(
			'installedpackages',
			$GLOBALS['config'] ?? [],
			'a failed add must NOT call config_set_path()'
		);
		$this->assertEmpty(
			$GLOBALS['pfb_test_write_config_calls'] ?? [],
			'a failed add must NOT call write_config()'
		);
		$this->assertFileDoesNotExist(
			"{$GLOBALS['pfb']['permitdir']}/Whitelist_custom_v4.update",
			'a failed add must NOT touch the cron/update flag file'
		);
	}

	public function testIpWhiteV4SuccessAppendsAndWrites(): void
	{
		$clists = ['ipwhitelist4' => ['pfB_Whitelist_v4' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_oracle_ip_white('198.51.100.31', 'pfB_Whitelist_v4', '4', '', $clists);

		$this->assertStringContainsString('added', $result['savemsg']);
		$this->assertFileExists("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v4.txt");
		$this->assertStringContainsString('198.51.100.31', file_get_contents("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v4.txt"));
		$this->assertNotEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
		$this->assertFileExists("{$GLOBALS['pfb']['permitdir']}/Whitelist_custom_v4.update");
	}

	public function testIpWhiteV6FailureSkipsAllWrites(): void
	{
		$this->scriptFailure('add', '2001:db8::30');
		$clists = ['ipwhitelist6' => ['pfB_Whitelist_v6' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_oracle_ip_white('2001:db8::30', 'pfB_Whitelist_v6', '6', '', $clists);

		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertArrayNotHasKey('2001:db8::30', $result['clists']['ipwhitelist6']['pfB_Whitelist_v6']['data']);
		$this->assertFileDoesNotExist("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v6.txt");
		$this->assertEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	public function testIpWhiteV6SuccessAppendsAndWrites(): void
	{
		$clists = ['ipwhitelist6' => ['pfB_Whitelist_v6' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_oracle_ip_white('2001:db8::31', 'pfB_Whitelist_v6', '6', '', $clists);

		$this->assertStringContainsString('added', $result['savemsg']);
		$this->assertFileExists("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v6.txt");
		$this->assertNotEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	/** @return string[] the last [op, table, entry] row the shim logged. */
	private function lastLogRow(): array
	{
		$content = trim((string) @file_get_contents($this->logPath));
		$this->assertNotSame('', $content, 'the shim must have logged at least one call');
		$lines = explode("\n", $content);
		return explode('|', end($lines), 3);
	}
}
