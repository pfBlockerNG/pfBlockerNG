<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

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
 * delete_ip/delete_ipwhitelist remain top-level page code and keep their
 * source-evaluated oracle coverage. Alerts IP mutations use the package seam
 * directly so store/config ordering and explicit redirect results are tested
 * without executing page headers or exits.
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

	/**
	 * issue #1666: setUp() below overrides every $pfb['pfctl']/['aliasdir']/
	 * ['dbdir']/['permitdir']/['ip_unlock']/['supptxt']/['supptxt_v6']/
	 * ['ipconfig']/['logdir']/['log']/['errlog'] key (11 total) to point inside
	 * $this->tmp, and tearDown() deletes $this->tmp -- without a restore, every
	 * LATER test class inherits those keys pointing at an already-deleted
	 * directory (mirrors the DnsblVipInterfaceValidationTest save/restore idiom
	 * used elsewhere in this suite). $GLOBALS['config'] is likewise replaced and
	 * must be restored (mirrors CollectLocalIpAliasTest's hadConfig/savedConfig).
	 */
	private array $savedPfb = [];
	private array $hadPfb   = [];
	private bool $hadConfig   = false;
	private mixed $savedConfig = null;

	public static function setUpBeforeClass(): void
	{
		$src = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
		);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free pfblockerng_alerts.php');
		}

		// Region 1: the delete_ip case body (own trailing break;) -- wrapped in a
		// throwaway switch so `break;` has a valid target.
		if (!function_exists('pfb_alerts_oracle_delete_ip')) {
			$start = strpos($src, "case 'delete_ip':");
			$end = strpos($src, "case 'delete_ipwhitelist':", $start === FALSE ? 0 : $start);
			if ($start === FALSE || $end === FALSE || $end <= $start) {
				throw new RuntimeException('test bootstrap: delete_ip region not found');
			}
			$region = substr($src, $start + strlen("case 'delete_ip':"), $end - $start - strlen("case 'delete_ip':"));
			eval(
				'function pfb_alerts_oracle_delete_ip(string $entry, string $table, array &$clists): array {'
				. ' global $pfb; $pfb_found = TRUE; $savemsg = \'\'; $type = \'\';'
				. ' switch (1) { case 1:'
				. $region
				. ' }'
				. ' return [\'pfb_found\' => $pfb_found, \'savemsg\' => $savemsg]; }'
			);
		}

		// Region 2: the delete_ipwhitelist case body (own trailing break;).
		if (!function_exists('pfb_alerts_oracle_delete_ipwhitelist')) {
			$start = strpos($src, "case 'delete_ipwhitelist':");
			$end = strpos($src, 'default:', $start === FALSE ? 0 : $start);
			if ($start === FALSE || $end === FALSE || $end <= $start) {
				throw new RuntimeException('test bootstrap: delete_ipwhitelist region not found');
			}
			$region = substr($src, $start + strlen("case 'delete_ipwhitelist':"), $end - $start - strlen("case 'delete_ipwhitelist':"));
			eval(
				'function pfb_alerts_oracle_delete_ipwhitelist(string $entry, string $table, array &$clists): array {'
				. ' global $pfb; $pfb_found = TRUE; $savemsg = \'\'; $type = \'\';'
				. ' switch (1) { case 1:'
				. $region
				. ' }'
				. ' if ($pfb_found) { write_config("pfBlockerNG: Deleted [ {$entry} ] from {$type} customlist", FALSE); }'
				. ' return [\'pfb_found\' => $pfb_found, \'savemsg\' => $savemsg]; }'
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
		mkdir("{$this->tmp}/db", 0777, TRUE);

		$this->logPath   = "{$this->tmp}/calls.log";
		$this->rulesPath = "{$this->tmp}/rules.tsv";
		putenv("PFB_TEST_LOG={$this->logPath}");
		putenv("PFB_TEST_RULES={$this->rulesPath}");
		$this->shim = $this->writeShim();

		// issue #1666: save every $pfb key this test overrides below, before
		// overriding them, so tearDown() can restore them once $this->tmp (which
		// most of them point inside) is deleted.
		foreach (['pfctl', 'aliasdir', 'dbdir', 'permitdir', 'ip_unlock', 'dnsbl_unlock', 'supptxt',
			  'supptxt_v6', 'ipconfig', 'logdir', 'log', 'errlog'] as $k) {
			$this->hadPfb[$k]   = array_key_exists($k, $GLOBALS['pfb'] ?? []);
			$this->savedPfb[$k] = $GLOBALS['pfb'][$k] ?? NULL;
		}
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? NULL;

		$pfb['pfctl']     = $this->shim;
		$pfb['aliasdir']  = "{$this->tmp}/alias";
		$pfb['dbdir']     = "{$this->tmp}/db";
		$pfb['permitdir'] = "{$this->tmp}/permit";
		$pfb['ip_unlock'] = "{$this->tmp}/ip_unlock.txt";
		$pfb['dnsbl_unlock'] = "{$this->tmp}/dnsbl_unlock.txt";
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
		putenv('PFB_TEST_SHOW_ENTRY');
		rmdir_recursive($this->tmp);
		unset($GLOBALS['pfb_test_write_config_calls']);

		// issue #1666: restore every $pfb key overridden in setUp() -- otherwise
		// every later test class inherits $pfb['log'] etc. pointing at the tree
		// just deleted above.
		foreach ($this->savedPfb as $k => $value) {
			if ($this->hadPfb[$k]) {
				$GLOBALS['pfb'][$k] = $value;
			} else {
				unset($GLOBALS['pfb'][$k]);
			}
		}
		$this->savedPfb = [];
		$this->hadPfb   = [];

		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		$this->savedConfig = null;
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
if [ "$op" != "show" ] && [ -z "$entry" ]; then
	printf 'pfctl: no address specified\n' >&2
	exit 1
fi
if [ "$op" = "show" ] && [ -n "$PFB_TEST_SHOW_ENTRY" ]; then
	printf '%s\n' "$PFB_TEST_SHOW_ENTRY"
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

	public function testDeleteIpWhitelistV4NotFoundSkipsWrite(): void
	{
		$clists = ['ipwhitelist4' => ['pfB_Permit_v4' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_oracle_delete_ipwhitelist("'198.51.100.9'", "'pfB_Permit_v4'", $clists);

		$this->assertEmpty(
			$GLOBALS['pfb_test_write_config_calls'] ?? [],
			'a missing Permit entry must NOT call write_config()'
		);
		$this->assertFalse($result['pfb_found']);
		$this->assertStringContainsString('not found', $result['savemsg']);
	}

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
		$this->assertNotEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
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
		$before = "198.51.100.20,pfB_Deny_v4\nkeepme.example,pfB_Keep_v4\n";
		file_put_contents($GLOBALS['pfb']['ip_unlock'], $before);

		$clists = [];
		$result = pfb_alerts_ip_action('lock', '198.51.100.20', 'pfB_Deny_v4', '', $clists, $ip_unlock);
		$savemsg = $result['savemsg'];

		$this->assertStringContainsString('failed', $savemsg);
		$this->assertTrue($result['redirect']);
		$this->assertFileExists($GLOBALS['pfb']['ip_unlock']);
		$this->assertSame($before, file_get_contents($GLOBALS['pfb']['ip_unlock']));
	}

	public function testIpRemoveLockSuccessAppliesUnlockStoreWrite(): void
	{
		$ip_unlock = ['198.51.100.20' => 'pfB_Deny_v4', 'keepme.example' => 'pfB_Keep_v4'];

		$clists = [];
		$result = pfb_alerts_ip_action('lock', '198.51.100.20', 'pfB_Deny_v4', '', $clists, $ip_unlock);
		$savemsg = $result['savemsg'];

		$this->assertStringContainsString('re-locked', $savemsg);
		$this->assertTrue($result['redirect']);
		$this->assertFileExists($GLOBALS['pfb']['ip_unlock'], 'a successful re-lock must apply the unlock store write');
		$content = file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content, 'the untouched leftover entry must survive the rewrite');
		$this->assertStringNotContainsString('198.51.100.20', $content, 'the re-locked IP must be removed from the unlock store');
	}

	public function testIpRemoveLockV6SuccessRemovesExactHostOnly(): void
	{
		$ip_unlock = ['2001:db8::20' => 'pfB_Deny_v6', 'keepme.example' => 'pfB_Keep_v4'];
		$clists = [];

		$result = pfb_alerts_ip_action('lock', '2001:db8::20', 'pfB_Deny_v6', '', $clists, $ip_unlock);

		$this->assertStringContainsString('re-locked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$content = file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content);
		$this->assertStringNotContainsString('2001:db8::20', $content);
	}

	public function testIpRemoveLockZoneIdHostileEntryFailureSkipsStoreWrite(): void
	{
		// PFB_FILTER_IP passes zone-id IPv6 shapes (fe80::1%em0) -- a zone-id host
		// recorded in the unlock store, then fed back into the lock re-add.
		$this->scriptFailure('add', 'fe80::1%em0');
		$ip_unlock = ['fe80::1%em0' => 'pfB_Deny_v6', 'keepme.example' => 'pfB_Keep_v4'];

		$clists = [];
		$result = pfb_alerts_ip_action('lock', 'fe80::1%em0', 'pfB_Deny_v6', '', $clists, $ip_unlock);
		$savemsg = $result['savemsg'];

		$this->assertStringContainsString('failed', $savemsg);
		$this->assertTrue($result['redirect']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['ip_unlock']);
	}

	#[DataProvider('invalidActionProvider')]
	public function testUnexpectedAlertActionIsInert(mixed $action): void
	{
		$clists = [];
		$result = pfb_alerts_ip_action($action, '198.51.100.21', 'pfB_Deny_v4', '', $clists, []);

		$this->assertTrue($result['redirect']);
		$this->assertSame('Cannot Lock/Unlock - Invalid action.', $result['savemsg']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['ip_unlock']);
		$this->assertFileDoesNotExist("{$GLOBALS['pfb']['aliasdir']}/pfB_Deny_v4.txt");
	}

	public static function invalidActionProvider(): array
	{
		return [['bogus'], [''], [[]]];
	}

	public function testIpRemoveUnlockAppliedRecordsV4Host(): void
	{
		putenv('PFB_TEST_SHOW_ENTRY=198.51.100.22');
		$clists = [];
		$result = pfb_alerts_ip_action('unlock', '198.51.100.22', 'pfB_Deny_v4', '', $clists, []);

		$this->assertStringContainsString('temporarily Unlocked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileExists($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('198.51.100.22,pfB_Deny_v4', file_get_contents($GLOBALS['pfb']['ip_unlock']));
	}

	public function testIpRemoveUnlockAppliedRecordsV6Host(): void
	{
		putenv('PFB_TEST_SHOW_ENTRY=2001:db8::22');
		$clists = [];
		$result = pfb_alerts_ip_action('unlock', '2001:db8::22', 'pfB_Deny_v6', '', $clists, []);

		$this->assertStringContainsString('temporarily Unlocked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertStringContainsString('2001:db8::22,pfB_Deny_v6', file_get_contents($GLOBALS['pfb']['ip_unlock']));
	}

	public function testIpRemoveUnlockStorePersistenceFailureKeepsLivePunchAndSuccessMessage(): void
	{
		putenv('PFB_TEST_SHOW_ENTRY=198.51.100.26');
		$store = $GLOBALS['pfb']['ip_unlock'];
		$this->assertTrue(mkdir($store), 'setup: unlock-store failure target must be a directory');

		$result = pfb_alerts_ip_action('unlock', '198.51.100.26', 'pfB_Deny_v4', '', [], []);

		$this->assertStringContainsString('temporarily Unlocked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertSame(['delete', 'pfB_Deny_v4', '198.51.100.26'], $this->lastLogRow());
		$this->assertDirectoryExists($store, 'unlock-store persistence failure must leave the target directory untouched');
	}

	public function testIpRemoveUnlockNotBlockedRecordsNothing(): void
	{
		$clists = [];
		$result = pfb_alerts_ip_action('unlock', '198.51.100.23', 'pfB_Deny_v4', '', $clists, []);

		$this->assertStringContainsString('not currently blocked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['ip_unlock']);
	}

	public function testIpRemoveUnlockFailedRecordsNothing(): void
	{
		$this->scriptFailure('show', '');
		$clists = [];
		$result = pfb_alerts_ip_action('unlock', '198.51.100.24', 'pfB_Deny_v4', '', $clists, []);

		$this->assertStringContainsString('live unlock', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['ip_unlock']);
	}

	public function testIpRemoveUnlockBusyRecordsNothing(): void
	{
		$lock = fopen("{$GLOBALS['pfb']['dbdir']}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($lock);
		$this->assertTrue(flock($lock, LOCK_EX | LOCK_NB));
		try {
			$clists = [];
			$result = pfb_alerts_ip_action('unlock', '198.51.100.25', 'pfB_Deny_v4', '', $clists, []);
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
		}

		$this->assertStringContainsString('mid-update', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['ip_unlock']);
	}

	// =====================================================================
	// ip_white
	// =====================================================================

	public function testIpWhiteV4FailureSkipsAllWrites(): void
	{
		$this->scriptFailure('add', '198.51.100.30');
		$clists = ['ipwhitelist4' => ['pfB_Whitelist_v4' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_ip_action('ip_white', '198.51.100.30', 'pfB_Whitelist_v4', '', $clists, []);

		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertTrue($result['redirect']);
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

		$result = pfb_alerts_ip_action('ip_white', '198.51.100.31', 'pfB_Whitelist_v4', '', $clists, []);

		$this->assertStringContainsString('added', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileExists("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v4.txt");
		$this->assertStringContainsString('198.51.100.31', file_get_contents("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v4.txt"));
		// config_set_path() persistence is observable through the global config on success.
		$this->assertArrayHasKey('installedpackages', $GLOBALS['config'] ?? [], 'the success path must persist via config_set_path()');
		$this->assertNotEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
		$this->assertFileExists("{$GLOBALS['pfb']['permitdir']}/Whitelist_custom_v4.update");
	}

	public function testIpWhiteV6FailureSkipsAllWrites(): void
	{
		$this->scriptFailure('add', '2001:db8::30');
		$clists = ['ipwhitelist6' => ['pfB_Whitelist_v6' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_ip_action('ip_white', '2001:db8::30', 'pfB_Whitelist_v6', '', $clists, []);

		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileDoesNotExist("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v6.txt");
		$this->assertEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	public function testIpWhiteV6SuccessAppendsAndWrites(): void
	{
		$clists = ['ipwhitelist6' => ['pfB_Whitelist_v6' => ['base64_idx' => 0, 'data' => []]]];

		$result = pfb_alerts_ip_action('ip_white', '2001:db8::31', 'pfB_Whitelist_v6', '', $clists, []);

		$this->assertStringContainsString('added', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileExists("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v6.txt");
		$this->assertNotEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame(
			base64_encode("2001:db8::31\n"),
			$GLOBALS['config']['installedpackages']['pfblockernglistsv6']['config'][0]['custom']
		);
		$this->assertFileExists("{$GLOBALS['pfb']['permitdir']}/Whitelist_custom_v6.update");
	}

	public function testIpWhiteDescriptionRejectsMissingNestedDataShape(): void
	{
		$table = 'pfB_Hostile_v4';
		$alias_path = "{$GLOBALS['pfb']['aliasdir']}/{$table}.txt";
		$update_path = "{$GLOBALS['pfb']['permitdir']}/Hostile_custom_v4.update";

		$result = pfb_alerts_ip_action('ip_white', '198.51.100.33', $table, 'memo', [], []);

		$this->assertStringContainsString('metadata missing', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertFileDoesNotExist($this->logPath, 'missing alias metadata must not call pfctl');
		$this->assertFileDoesNotExist($alias_path, 'missing alias metadata must not write the alias file');
		$this->assertArrayNotHasKey('installedpackages', $GLOBALS['config'] ?? [], 'missing alias metadata must not call config_set_path()');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'] ?? [], 'missing alias metadata must not call write_config()');
		$this->assertFileDoesNotExist($update_path, 'missing alias metadata must not touch the update flag');
	}

	public function testIpWhiteAliasPersistenceFailureKeepsConfigWriteAndSuccessMessage(): void
	{
		$table = 'pfB_Whitelist_v4';
		$alias_path = "{$GLOBALS['pfb']['aliasdir']}/{$table}.txt";
		$this->assertTrue(mkdir($alias_path), 'setup: alias-file failure target must be a directory');

		$result = pfb_alerts_ip_action(
			'ip_white',
			'198.51.100.34',
			$table,
			'',
			['ipwhitelist4' => [$table => ['base64_idx' => 0, 'data' => []]]],
			[]
		);

		$this->assertStringContainsString('added', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertSame(['add', $table, '198.51.100.34'], $this->lastLogRow());
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame(
			base64_encode("198.51.100.34\n"),
			$GLOBALS['config']['installedpackages']['pfblockernglistsv4']['config'][0]['custom']
		);
		$this->assertNotEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
		$this->assertDirectoryExists($alias_path, 'alias-file persistence failure must leave the target directory untouched');
	}

	public function testIpWhiteDuplicateSkipsPfctlAndRedirect(): void
	{
		$clists = ['ipwhitelist4' => ['pfB_Whitelist_v4' => ['base64_idx' => 0, 'data' => ['198.51.100.32' => "198.51.100.32\r\n"]]]];

		$result = pfb_alerts_ip_action('ip_white', '198.51.100.32', 'pfB_Whitelist_v4', '', $clists, []);

		$this->assertFalse($result['redirect']);
		$this->assertSame('', $result['savemsg']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'] ?? []);
		$this->assertFileDoesNotExist("{$GLOBALS['pfb']['aliasdir']}/pfB_Whitelist_v4.txt");
		$this->assertSame('', (string) @file_get_contents($this->logPath));
	}

	public function testAddSuppressNotBlockedPersistsExactV4Host(): void
	{
		$clists = ['ipsuppression' => ['data' => []]];

		$result = pfb_alerts_ip_action('addsuppress', '198.51.100.40', 'pfB_Deny_v4', 'note', $clists, []);

		$this->assertStringContainsString('Not currently blocked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame("198.51.100.40/32 # note\n", base64_decode(PfbConfig::read('ip/v4suppression')));
		$this->assertFileExists($GLOBALS['pfb']['supptxt']);
	}

	public function testAddSuppressSuppressionFilePersistenceFailureKeepsConfigAndSuccessMessage(): void
	{
		$suppression_file = $GLOBALS['pfb']['supptxt'];
		$this->assertTrue(mkdir($suppression_file), 'setup: suppression-file failure target must be a directory');

		$result = pfb_alerts_ip_action('addsuppress', '198.51.100.45', 'pfB_Deny_v4', '', ['ipsuppression' => ['data' => []]], []);

		$this->assertStringContainsString('Not currently blocked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame("198.51.100.45/32\n", base64_decode(PfbConfig::read('ip/v4suppression')));
		$this->assertNotEmpty($GLOBALS['pfb_test_write_config_calls'] ?? []);
		$this->assertDirectoryExists($suppression_file, 'suppression-file persistence failure must leave the target directory untouched');
	}

	public function testAddSuppressNotBlockedPersistsExactV6Host(): void
	{
		$clists = ['ipsuppression_v6' => ['data' => []]];

		$result = pfb_alerts_ip_action('addsuppress', '2001:db8::40', 'pfB_Deny_v6', '', $clists, []);

		$this->assertStringContainsString('Not currently blocked', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame("2001:db8::40/128\n", base64_decode(PfbConfig::read('ip/v6suppression')));
		$this->assertFileExists($GLOBALS['pfb']['supptxt_v6']);
	}

	public function testAddSuppressAppliedPersistsAfterLivePunch(): void
	{
		putenv('PFB_TEST_SHOW_ENTRY=198.51.100.42');
		$clists = ['ipsuppression' => ['data' => []]];

		$result = pfb_alerts_ip_action('addsuppress', '198.51.100.42', 'pfB_Deny_v4', '', $clists, []);

		$this->assertStringContainsString('Removed 1 entry, added 0 covering CIDRs', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame("198.51.100.42/32\n", base64_decode(PfbConfig::read('ip/v4suppression')));
	}

	public function testAddSuppressFailedStillPersistsStandingSuppression(): void
	{
		$this->scriptFailure('show', '');
		$clists = ['ipsuppression' => ['data' => []]];

		$result = pfb_alerts_ip_action('addsuppress', '198.51.100.43', 'pfB_Deny_v4', '', $clists, []);

		$this->assertStringContainsString('Live punch failed', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame("198.51.100.43/32\n", base64_decode(PfbConfig::read('ip/v4suppression')));
	}

	public function testAddSuppressBusyStillPersistsStandingSuppression(): void
	{
		$lock = fopen("{$GLOBALS['pfb']['dbdir']}/pfb_feed_pass.lock", 'c');
		$this->assertNotFalse($lock);
		$this->assertTrue(flock($lock, LOCK_EX | LOCK_NB));
		try {
			$clists = ['ipsuppression' => ['data' => []]];
			$result = pfb_alerts_ip_action('addsuppress', '198.51.100.44', 'pfB_Deny_v4', '', $clists, []);
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
		}

		$this->assertStringContainsString('update/reload pass', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		// issue #1723: pfb_text_area_encode() normalizes the trailing CRLF to LF.
		$this->assertSame("198.51.100.44/32\n", base64_decode(PfbConfig::read('ip/v4suppression')));
	}

	public function testAddSuppressExactDuplicateSkipsConfigRefresh(): void
	{
		$clists = ['ipsuppression' => ['data' => ['198.51.100.41/32' => "198.51.100.41/32\r\n"], 'base64' => base64_encode("198.51.100.41/32\r\n")]];

		$result = pfb_alerts_ip_action('addsuppress', '198.51.100.41', 'pfB_Deny_v4', '', $clists, []);

		$this->assertStringContainsString('already exists', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'] ?? []);
		$this->assertSame('', (string) @file_get_contents($GLOBALS['pfb']['supptxt']));
	}

	public function testAddSuppressV6ExactDuplicateSkipsConfigRefresh(): void
	{
		$clists = ['ipsuppression_v6' => ['data' => ['2001:db8::41/128' => "2001:db8::41/128\r\n"], 'base64' => base64_encode("2001:db8::41/128\r\n")]];

		$result = pfb_alerts_ip_action('addsuppress', '2001:db8::41', 'pfB_Deny_v6', '', $clists, []);

		$this->assertSame('Host IP address 2001:db8::41 already exists in the IPv6 Suppression customlist.', $result['savemsg']);
		$this->assertTrue($result['redirect']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'] ?? []);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['supptxt_v6']);
	}

	public function testAddSuppressBroaderEntryRefreshesSuppressionFileWithoutAppend(): void
	{
		$line = "198.51.100.0/24\r\n";
		$clists = ['ipsuppression' => ['data' => ['198.51.100.0/24' => $line], 'base64' => base64_encode($line)]];

		$result = pfb_alerts_ip_action('addsuppress', '198.51.100.41', 'pfB_Deny_v4', '', $clists, []);

		$this->assertStringContainsString('already covered', $result['savemsg']);
		$this->assertSame("198.51.100.0/24\n", file_get_contents($GLOBALS['pfb']['supptxt']));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'] ?? []);
	}

	// =====================================================================
	// issue #2670: successful suppress / whitelist must drop the unlock store
	// =====================================================================

	public function testAddSuppressNotBlockedClearsMatchingUnlockStoreKeepsOthers(): void
	{
		$ip = '198.51.100.40';
		$table = 'pfB_Deny_v4';
		$ip_unlock = [$ip => $table, 'keepme.example' => 'pfB_Keep_v4'];
		file_put_contents($GLOBALS['pfb']['ip_unlock'], "{$ip},{$table}\nkeepme.example,pfB_Keep_v4\n");

		$result = pfb_alerts_ip_action('addsuppress', $ip, $table, 'note', ['ipsuppression' => ['data' => []]], $ip_unlock);

		$this->assertStringContainsString('Not currently blocked', $result['savemsg']);
		$content = (string) file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content, 'unrelated unlock entries must survive suppress');
		$this->assertStringNotContainsString($ip, $content, 'issue #2670: suppress must drop the matching unlock-store row');
	}

	public function testAddSuppressAlreadyExistsStillClearsUnlockStore(): void
	{
		$ip = '198.51.100.41';
		$table = 'pfB_Deny_v4';
		$host_line = "{$ip}/32";
		$ip_unlock = [$ip => $table, 'keepme.example' => 'pfB_Keep_v4'];
		file_put_contents($GLOBALS['pfb']['ip_unlock'], "{$ip},{$table}\nkeepme.example,pfB_Keep_v4\n");

		$result = pfb_alerts_ip_action(
			'addsuppress',
			$ip,
			$table,
			'',
			['ipsuppression' => ['data' => [$host_line => "{$host_line}\r\n"], 'base64' => base64_encode("{$host_line}\r\n")]],
			$ip_unlock
		);

		$this->assertStringContainsString('already exists', $result['savemsg']);
		$content = (string) file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content);
		$this->assertStringNotContainsString($ip, $content, 'issue #2670: already-suppressed still drops the unlock-store row');
	}

	public function testAddSuppressAlreadyCoveredClearsUnlockStore(): void
	{
		$ip = '198.51.100.41';
		$table = 'pfB_Deny_v4';
		$ip_unlock = [$ip => $table, 'keepme.example' => 'pfB_Keep_v4'];
		file_put_contents($GLOBALS['pfb']['ip_unlock'], "{$ip},{$table}\nkeepme.example,pfB_Keep_v4\n");
		$line = "198.51.100.0/24\r\n";

		$result = pfb_alerts_ip_action(
			'addsuppress',
			$ip,
			$table,
			'',
			['ipsuppression' => ['data' => ['198.51.100.0/24' => $line], 'base64' => base64_encode($line)]],
			$ip_unlock
		);

		$this->assertStringContainsString('already covered', $result['savemsg']);
		$content = (string) file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content);
		$this->assertStringNotContainsString($ip, $content, 'issue #2670: already-covered still drops the unlock-store row');
	}

	public function testIpWhiteSuccessClearsMatchingUnlockStore(): void
	{
		$ip = '198.51.100.31';
		$table = 'pfB_Whitelist_v4';
		$ip_unlock = [$ip => 'pfB_Deny_v4', 'keepme.example' => 'pfB_Keep_v4'];
		file_put_contents($GLOBALS['pfb']['ip_unlock'], "{$ip},pfB_Deny_v4\nkeepme.example,pfB_Keep_v4\n");

		$result = pfb_alerts_ip_action(
			'ip_white',
			$ip,
			$table,
			'',
			['ipwhitelist4' => [$table => ['base64_idx' => 0, 'data' => []]]],
			$ip_unlock
		);

		$this->assertStringContainsString('added', $result['savemsg']);
		$content = (string) file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content);
		$this->assertStringNotContainsString($ip, $content, 'issue #2670: permit whitelist must drop the matching unlock-store row');
	}

	public function testIpWhiteDuplicateStillClearsUnlockStore(): void
	{
		$ip = '198.51.100.32';
		$table = 'pfB_Whitelist_v4';
		$ip_unlock = [$ip => 'pfB_Deny_v4', 'keepme.example' => 'pfB_Keep_v4'];
		file_put_contents($GLOBALS['pfb']['ip_unlock'], "{$ip},pfB_Deny_v4\nkeepme.example,pfB_Keep_v4\n");

		$result = pfb_alerts_ip_action(
			'ip_white',
			$ip,
			$table,
			'',
			['ipwhitelist4' => [$table => ['base64_idx' => 0, 'data' => [$ip => "{$ip}\r\n"]]]],
			$ip_unlock
		);

		$this->assertFalse($result['redirect']);
		$content = (string) file_get_contents($GLOBALS['pfb']['ip_unlock']);
		$this->assertStringContainsString('keepme.example', $content);
		$this->assertStringNotContainsString($ip, $content, 'issue #2670: already-whitelisted still drops the unlock-store row');
	}

	public function testIpWhiteFailureLeavesUnlockStoreUnchanged(): void
	{
		$ip = '198.51.100.30';
		$table = 'pfB_Whitelist_v4';
		$before = "{$ip},pfB_Deny_v4\nkeepme.example,pfB_Keep_v4\n";
		$ip_unlock = [$ip => 'pfB_Deny_v4', 'keepme.example' => 'pfB_Keep_v4'];
		file_put_contents($GLOBALS['pfb']['ip_unlock'], $before);
		$this->scriptFailure('add', $ip);

		$result = pfb_alerts_ip_action(
			'ip_white',
			$ip,
			$table,
			'',
			['ipwhitelist4' => [$table => ['base64_idx' => 0, 'data' => []]]],
			$ip_unlock
		);

		$this->assertStringContainsString('failed', $result['savemsg']);
		$this->assertSame($before, file_get_contents($GLOBALS['pfb']['ip_unlock']), 'a failed permit add must not touch the unlock store');
	}

	public function testAddwhitelistdomDispatchClearsUnlockStore(): void
	{
		$src = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$start = strpos($src, "elseif (isset(\$_POST['addwhitelistdom'])");
		$end = strpos($src, "elseif (isset(\$_POST['entry_delete'])", $start === FALSE ? 0 : $start);
		$this->assertNotFalse($start, 'addwhitelistdom handler must exist');
		$this->assertNotFalse($end, 'entry_delete must follow addwhitelistdom');
		$region = substr($src, $start, $end - $start);
		$this->assertStringContainsString(
			"pfb_alerts_whitelist_unlock_tokens(\$domain_unlock, \$domain, \$dnsbl_exclude, \$cname_list)",
			$region,
			'issue #2670: addwhitelistdom token list must follow the write-set (www. except on TLD exclusion)'
		);
		$this->assertStringContainsString(
			"pfb_alerts_unlock_drop('dnsbl', \$dnsbl_unlock, \$unlock_drop)",
			$region,
			'issue #2670: addwhitelistdom must drop unlock tokens via \$unlock_drop'
		);
	}

	public function testUnlockDropBareDomainAlsoClearsWwwUnlockRow(): void
	{
		$store = ['www.example.com' => 'TLD', 'keepme.example' => 'python'];
		file_put_contents($GLOBALS['pfb']['dnsbl_unlock'], "www.example.com,TLD\nkeepme.example,python\n");

		$store = pfb_alerts_unlock_drop('dnsbl', $store, ['example.com', 'example.com', 'www.example.com']);

		$content = (string) file_get_contents($GLOBALS['pfb']['dnsbl_unlock']);
		$this->assertStringContainsString('keepme.example', $content, 'unrelated unlock rows must survive');
		$this->assertStringNotContainsString(
			'www.example.com',
			$content,
			'issue #2670: locking the bare domain must also drop the www.<domain> unlock row'
		);
		$this->assertArrayNotHasKey('www.example.com', $store);
		$this->assertArrayNotHasKey('example.com', $store);
	}

	public function testUnlockDropUnsetsBetweenTokensSoTheFirstKeyCannotReturn(): void
	{
		$store = ['example.com' => 'python', 'www.example.com' => 'python'];
		file_put_contents(
			$GLOBALS['pfb']['dnsbl_unlock'],
			"example.com,python\nwww.example.com,python\n"
		);

		$store = pfb_alerts_unlock_drop('dnsbl', $store, ['example.com', 'www.example.com']);

		$content = (string) file_get_contents($GLOBALS['pfb']['dnsbl_unlock']);
		$this->assertSame('', trim($content), 'both tokens must be gone after sequential lock+unset');
		$this->assertSame([], $store);
	}

	public function testUnlockDropClearsWhitelistedCnameAndWwwSibling(): void
	{
		$store = [
			'alias.example.net' => 'python',
			'www.alias.example.net' => 'python',
			'keepme.example' => 'python',
		];
		file_put_contents(
			$GLOBALS['pfb']['dnsbl_unlock'],
			"alias.example.net,python\nwww.alias.example.net,python\nkeepme.example,python\n"
		);

		$store = pfb_alerts_unlock_drop('dnsbl', $store, [
			'example.com', 'www.example.com',
			'alias.example.net', 'www.alias.example.net',
		]);

		$content = (string) file_get_contents($GLOBALS['pfb']['dnsbl_unlock']);
		$this->assertStringContainsString('keepme.example', $content);
		$this->assertStringNotContainsString('alias.example.net', $content, 'issue #2670: a CNAME written to the whitelist must leave the unlock store');
		$this->assertStringNotContainsString('www.alias.example.net', $content);
		$this->assertArrayNotHasKey('alias.example.net', $store);
	}

	public function testWhitelistUnlockTokensNonWildcardIncludesWwwAndCnames(): void
	{
		$tokens = pfb_alerts_whitelist_unlock_tokens(
			'www.example.com',
			'example.com',
			FALSE,
			['alias.example.net', '', 'alias.example.net']
		);
		$this->assertSame(
			['www.example.com', 'example.com', 'alias.example.net', 'www.alias.example.net'],
			array_values(array_unique($tokens)),
			'whitelist matcher www-strips unconditionally, so every token also drops www.<token>'
		);
		$this->assertContains('www.example.com', $tokens);
		$this->assertContains('www.alias.example.net', $tokens);
	}

	public function testWhitelistUnlockTokensWildcardDropsWwwBecauseDotDomainCoversIt(): void
	{
		$tokens = pfb_alerts_whitelist_unlock_tokens('example.com', 'example.com', FALSE, ['alias.example.net']);
		$this->assertContains(
			'www.example.com',
			$tokens,
			'wildcard writes .domain; the matcher covers www.domain, so the unlock row must drop or the Unlocked panel stays stale'
		);
		$this->assertContains('example.com', $tokens);
		$this->assertContains('alias.example.net', $tokens);
		$this->assertContains('www.alias.example.net', $tokens);
	}

	public function testWhitelistUnlockTokensExclusionOmitsWwwKeepsCname(): void
	{
		$tokens = pfb_alerts_whitelist_unlock_tokens('example.com', 'example.com', TRUE, ['alias.example.net']);
		$this->assertNotContains(
			'www.example.com',
			$tokens,
			'TLD exclusion classify is exact-string; dropping www.example.com would re-lock an unlocked name the exclusion does not cover'
		);
		$this->assertNotContains('www.alias.example.net', $tokens);
		$this->assertContains('example.com', $tokens);
		$this->assertContains('alias.example.net', $tokens);
	}

	public function testWhitelistUnlockTokensExclusionPostedWwwDoesNotDropWww(): void
	{
		$tokens = pfb_alerts_whitelist_unlock_tokens(
			'www.example.com',
			'example.com',
			TRUE,
			['alias.example.net']
		);
		$this->assertNotContains(
			'www.example.com',
			$tokens,
			'exclusion writes foo.com only; a www.foo.com POST must not revoke the www. unlock row'
		);
		$this->assertContains('example.com', $tokens);
		$this->assertContains('alias.example.net', $tokens);
		$this->assertNotContains('www.alias.example.net', $tokens);
	}

	public function testAlertsPageDispatchKeepsFiltersNavigationAndStrictIpActions(): void
	{
		// Top-level POST dispatch has no off-appliance callable seam; this retained
		// pin uses comment-free PHP tokens so nearby production prose is irrelevant.
		$src = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		$this->assertNotSame('', $src, 'comment-free Alerts source must be readable');

		$this->assertStringContainsString("pfb_filter(\$_POST['ip'], PFB_FILTER_IP, 'alerts addsuppress')", $src);
		$this->assertStringContainsString("pfb_filter(\$_POST['table'], PFB_FILTER_WORD, 'alerts addsuppress')", $src);
		$this->assertStringContainsString("pfb_filter(\$_POST['descr'], PFB_FILTER_HTML, 'alerts ip_white')", $src);
		$this->assertStringContainsString("str_starts_with(\$table, 'NEW_')", $src);
		$this->assertStringContainsString("pfb_alerts_ip_action('ip_white'", $src);
		$this->assertStringContainsString("pfb_filter(\$_POST['ip'], PFB_FILTER_IP, 'alerts ip_remove')", $src);
		$this->assertStringContainsString("pfb_filter(\$_POST['table'], PFB_FILTER_WORD, 'alerts ip_remove')", $src);
		$this->assertStringContainsString('header("Location: /pfblockerng/pfblockerng_category_edit.php?type=ipv{$vtype}&act=addgroup', $src);

		$remove_start = strpos($src, "} elseif (isset(\$_POST['ip_remove'])");
		$remove_end = strpos($src, "} elseif (isset(\$_POST['ip_white'])", $remove_start === FALSE ? 0 : $remove_start);
		$this->assertNotFalse($remove_start);
		$this->assertNotFalse($remove_end);
		$remove = substr($src, $remove_start, $remove_end - $remove_start);
		$this->assertStringNotContainsString("pfb_alerts_ip_action(\$_POST['ip_remove']", $remove);
		$this->assertStringContainsString("is_string(\$_POST['ip_remove'])", $remove);
		$this->assertStringContainsString("=== 'unlock'", $remove);
		$this->assertStringContainsString("=== 'lock'", $remove);
		$this->assertStringNotContainsString('pfb_live_punch_run(', $remove);
		$this->assertStringNotContainsString('pfb_pfctl_checked_op(', $remove);
		$this->assertStringNotContainsString('pfb_unlock(', $remove);
		$this->assertStringContainsString('header(', $remove);
		$this->assertStringContainsString('exit;', $remove);
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
