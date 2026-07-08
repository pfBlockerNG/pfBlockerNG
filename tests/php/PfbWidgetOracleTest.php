<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-61 — Golden oracles pinning TODAY's dashboard-widget icon/report logic,
 * BEFORE any ledger rewrite touches it. A later phase replaces the underlying
 * checks (dedup-sanity grep, dead OUT-OF-SYNC grep, py_error.log filesize,
 * error.log FAIL-grep) with the sync-status ledger; these oracles are the
 * regression net that catches an unintended behaviour change along the way —
 * once that rewrite lands, it supersedes (not merely extends) these pins.
 *
 * The widget file (src/usr/local/www/widgets/widgets/pfblockerng.widget.php)
 * carries top-level page execution and cannot be require()d off-appliance, so
 * — like WidgetAliasHiddenTest/WidgetSortTableTest — this suite eval-extracts
 * the REAL shipped source (the icon-decision block verbatim, and the whole
 * pfBlockerNG_get_failed() function verbatim) rather than reimplementing the
 * logic. No production file is modified.
 *
 * Coverage (ADR-61 §6 Phase 1 action plan item 2):
 *   (a) IP icon    — disabled; enabled+dedup-off; enabled+dedup-on+PASSED;
 *                     enabled+dedup-on+FAILED; enabled+dedup-on+absent.
 *   (b) DNSBL icon — each "is it live" gate off (enable/dnsbl/unbound_state/
 *                     unbound.conf reference) in turn; live+clean; live+OUT OF
 *                     SYNC (dead code, still pinned as today's behaviour);
 *                     live+py_error.log content; disabled+py_error.log content.
 *   (c) pfBlockerNG_get_failed() — a recognized alias builds the expected deep
 *                     link; an unrecognized one still renders without crashing.
 */
final class PfbWidgetOracleTest extends TestCase
{
	private const ICON_GREEN  = 'fa-solid fa-check-circle text-success';
	private const ICON_YELLOW = 'fa-solid fa-exclamation-circle text-warning';
	private const ICON_RED    = 'fa-solid fa-times-circle text-danger';

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.widget.php');
		}

		if (!function_exists('pfb_widget_oracle_status')) {
			// Extract the icon-decision block VERBATIM (the two "Status indicator"
			// sections), up to (not including) the next section's comment, which
			// serves only as a unique end-anchor via lookahead.
			if (!preg_match(
				'/\/\/ Status indicator if pfBlockerNG is enabled\/disabled.*?\n\t\}(?=\n\n\t\/\/ Collect folder\/file counts)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: icon-status block not found in widget source');
			}
			eval(
				'function pfb_widget_oracle_status(array $pfb): array { ' . $m[0]
				. ' return [$pfb_status, $pfb_msg, $dnsbl_status, $dnsbl_msg]; }'
			);
		}

		if (!function_exists('pfBlockerNG_get_failed')) {
			if (!preg_match('/function\s+pfBlockerNG_get_failed\s*\([^)]*\).*?\n\}/s', $src, $m)) {
				throw new RuntimeException('test bootstrap: pfBlockerNG_get_failed() not found in widget source');
			}
			eval($m[0]);
		}
	}

	private string $dir;

	/** Saved $GLOBALS['pfb']/['config'], restored in tearDown (repo convention). */
	private bool $hadPfb = false;
	private mixed $savedPfb = null;
	private bool $hadConfig = false;
	private mixed $savedConfig = null;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_widget_oracle_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);

		$this->hadPfb   = array_key_exists('pfb', $GLOBALS);
		$this->savedPfb = $GLOBALS['pfb'] ?? null;
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? null;
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);

		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->savedPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	/** @return array<string,mixed> */
	private function basePfb(): array
	{
		return [
			'enable'         => 'on',
			'dnsbl'          => 'on',
			'unbound_state'  => 'on',
			'grep'           => '/usr/bin/grep',
			'logdir'         => $this->dir,
			'dnsbldir'       => $this->dir,
			'pyerrlog'       => $this->dir . '/py_error.log',
			'dnsbl_vip4'     => '198.51.100.1',
			'dnsbl_port'     => '8080',
			'dnsbl_port_ssl' => '8443',
			'config'         => [],
		];
	}

	private function writeLog(string $contents): void
	{
		file_put_contents($this->dir . '/pfblockerng.log', $contents);
	}

	private function writeUnboundConf(bool $referencesPfbUnbound): void
	{
		file_put_contents(
			$this->dir . '/unbound.conf',
			$referencesPfbUnbound ? "python:\n\tpython-script: pfb_unbound.py\n" : "# no python module\n"
		);
	}

	private function writePyErrLog(string $contents): void
	{
		file_put_contents($this->dir . '/py_error.log', $contents);
	}

	// -----------------------------------------------------------------------
	// (a) IP icon.
	// -----------------------------------------------------------------------

	public function testIpDisabledIsRed(): void
	{
		$pfb = $this->basePfb();
		$pfb['enable'] = '';
		$this->writeLog('');

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('pfBlockerNG is Disabled.', $msg);
	}

	public function testIpEnabledDedupOffIsGreenRegardlessOfLogContent(): void
	{
		$pfb = $this->basePfb();
		$pfb['config']['enable_dup'] = '';	// dedup off
		$this->writeLog("Sanity check [ FAILED ]\n");	// even with a failing line present

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_GREEN, $status, 'dedup off must never look at the sanity line');
		$this->assertSame('pfBlockerNG is Active.', $msg);
	}

	public function testIpEnabledDedupOnSanityPassedIsGreen(): void
	{
		$pfb = $this->basePfb();
		$pfb['config']['enable_dup'] = 'on';
		$this->writeLog("Some other line\nDatabase Sanity check [ PASSED ]\n");

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_GREEN, $status);
		$this->assertSame('pfBlockerNG is Active.', $msg);
	}

	public function testIpEnabledDedupOnSanityFailedIsYellow(): void
	{
		$pfb = $this->basePfb();
		$pfb['config']['enable_dup'] = 'on';
		$this->writeLog("Database Sanity check [ FAILED ]\n");

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame('pfBlockerNG deDuplication is out of sync. Perform a Force Reload to correct.', $msg);
	}

	public function testIpEnabledDedupOnSanityAbsentIsYellow(): void
	{
		$pfb = $this->basePfb();
		$pfb['config']['enable_dup'] = 'on';
		$this->writeLog("no sanity line at all here\n");

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status, 'no Sanity check line at all must be treated the same as FAILED');
	}

	// -----------------------------------------------------------------------
	// (b) DNSBL icon — each "is it live" gate, individually off -> red.
	// -----------------------------------------------------------------------

	/** A baseline $pfb that is fully "live" for the DNSBL check, log clean. */
	private function liveDnsblPfb(): array
	{
		$pfb = $this->basePfb();
		$this->writeUnboundConf(TRUE);
		$this->writeLog("DNSBL update [ completed ]\n");
		$this->writePyErrLog('');
		return $pfb;
	}

	public function testDnsblEnableOffIsRed(): void
	{
		$pfb = $this->liveDnsblPfb();
		$pfb['enable'] = '';

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('DNSBL is Disabled.', $msg);
	}

	public function testDnsblToggleOffIsRed(): void
	{
		$pfb = $this->liveDnsblPfb();
		$pfb['dnsbl'] = '';

		[, , $status] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
	}

	public function testDnsblUnboundStateOffIsRed(): void
	{
		$pfb = $this->liveDnsblPfb();
		$pfb['unbound_state'] = '';

		[, , $status] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
	}

	public function testDnsblUnboundConfMissingPyReferenceIsRed(): void
	{
		$pfb = $this->liveDnsblPfb();
		$this->writeUnboundConf(FALSE);	// present, but no pfb_unbound.py reference

		[, , $status] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
	}

	public function testDnsblUnboundConfAbsentIsRed(): void
	{
		$pfb = $this->liveDnsblPfb();
		unlink($this->dir . '/unbound.conf');

		[, , $status] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
	}

	public function testDnsblDisabledWithPyErrorsUsesTheErrorMessage(): void
	{
		$pfb = $this->liveDnsblPfb();
		$pfb['enable'] = '';
		$this->writePyErrLog("Traceback...\n");

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('DNSBL is Disabled with errors! Review py_error.log', $msg);
	}

	// -----------------------------------------------------------------------
	// (b) DNSBL icon — live states.
	// -----------------------------------------------------------------------

	public function testDnsblLiveCleanIsGreen(): void
	{
		$pfb = $this->liveDnsblPfb();

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_GREEN, $status);
		$this->assertSame('DNSBL is Active on vip: 198.51.100.1 ports: 8080 & 8443', $msg);
	}

	// The dead OUT-OF-SYNC grep (ADR-61 §1.1 — no writer exists in the current
	// tree) is still today's CODE, so still pinned here: a later phase retires
	// it, and this oracle documents exactly what is being replaced.
	public function testDnsblLiveOutOfSyncLineIsYellow(): void
	{
		$pfb = $this->liveDnsblPfb();
		$this->writeLog("DNSBL update [ OUT OF SYNC ]\n");

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame('DNSBL is out of sync. Perform a Force Reload to correct.', $msg);
	}

	public function testDnsblLiveWithPyErrorContentIsYellow(): void
	{
		$pfb = $this->liveDnsblPfb();
		$this->writePyErrLog("Traceback...\n");

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame('DNSBL errors Found! Review py_error.log', $msg);
	}

	// -----------------------------------------------------------------------
	// (c) pfBlockerNG_get_failed().
	// -----------------------------------------------------------------------

	/**
	 * Build one realistic error.log FAIL line, matching pfb_download_failure()'s
	 * "\n\n [ {$alias} - {$header} ] Download FAIL [ NOW ]\n" shape with NOW
	 * resolved to today (pfb_logger's ISO date, which the widget's own grep
	 * matches — see the lockstep comment at pfblockerng.inc:3096-3098).
	 */
	private function writeFailLine(string $alias, string $header): void
	{
		$now = date('Y-m-d H:i:s');
		file_put_contents(
			$this->dir . '/error.log',
			"\n\n [ {$alias} - {$header} ] Download FAIL [ {$now} ]\n"
		);
	}

	public function testGetFailedRecognizedAliasBuildsDeepLink(): void
	{
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockernglistsv4' => [
					'config' => [
						0 => ['aliasname' => 'Example'],
					],
				],
			],
		];
		$pfb = $this->basePfb();
		$pfb['errlog']   = $this->dir . '/error.log';
		$pfb['maxfails'] = 3;
		$this->writeFailLine('pfB_Example_v4', 'pfB_Example_v4');
		$GLOBALS['pfb'] = $pfb;

		// @-suppressed: the shipped function reads $p_alias before its first
		// assignment on the very first log line, an existing PHP 8 undefined-
		// variable warning we pin as-is (not our bug to fix in this phase).
		ob_start();
		@pfBlockerNG_get_failed();
		$html = ob_get_clean();

		$this->assertStringContainsString(
			'pfblockerng_category_edit.php?type=ipv4&act=edit&rowid=0',
			$html,
			'a recognized alias must build the alias-editor deep link'
		);
		$this->assertStringContainsString('pfB_Example', $html);
	}

	public function testGetFailedUnrecognizedAliasRendersWithoutCrashing(): void
	{
		$GLOBALS['config'] = ['installedpackages' => []];
		$pfb = $this->basePfb();
		$pfb['errlog']   = $this->dir . '/error.log';
		$pfb['maxfails'] = 3;
		$this->writeFailLine('pfB_NoSuchAlias_v4', 'pfB_NoSuchAlias_v4');
		$GLOBALS['pfb'] = $pfb;

		ob_start();
		@pfBlockerNG_get_failed();
		$html = ob_get_clean();

		$this->assertStringNotContainsString(
			'pfblockerng_category_edit.php',
			$html,
			'an unrecognized alias must render plain text, no deep link'
		);
		$this->assertStringContainsString('pfB_NoSuchAlias', $html, 'the raw log line must still render');
	}
}
