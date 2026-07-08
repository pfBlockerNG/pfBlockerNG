<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 6 — golden oracles for the LEDGER-DRIVEN dashboard-widget icon/
 * report logic, superseding Phase 1's frozen-old-behavior pins (scaffolding,
 * not a permanent contract -- Phase 1's own handoff flagged this explicitly).
 *
 * The widget file (src/usr/local/www/widgets/widgets/pfblockerng.widget.php)
 * carries top-level page execution and cannot be require()d off-appliance, so
 * — like WidgetAliasHiddenTest/WidgetSortTableTest — this suite eval-extracts
 * the REAL shipped source (the icon-decision block verbatim, and the whole
 * pfBlockerNG_get_failed() function verbatim) rather than reimplementing the
 * logic. No production file is modified.
 *
 * Coverage (ADR-61 SS2.5 / SS4 items 1-3):
 *   (a) IP icon    — disabled (unchanged, red); enabled+no open entries (green);
 *                     enabled+dedup-only entry (yellow, dedup wording preserved);
 *                     enabled+non-dedup entry, e.g. an apply-stage failure
 *                     (yellow, regardless of enable_dup -- the asymmetry this
 *                     ADR retires).
 *   (b) DNSBL icon — each "is it live" gate off (unchanged, red), both with and
 *                     without an open dnsbl entry present (an open entry never
 *                     turns the red branch yellow, but its wording DOES still
 *                     distinguish "errors remain" from a clean disable); live+no
 *                     open entries (green); live+an open PHP entry (yellow);
 *                     live+only a Python-side entry (yellow, merged).
 *   (c) pfBlockerNG_get_failed() — a recognized (pfB_/DNSBL_-prefixed) item
 *                     builds the alias-editor deep link; a Python-side (file-
 *                     path) item renders as plain text, no link attempted, no
 *                     crash; an empty ledger falls back to the MaxMind version
 *                     line exactly as today.
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
			'dbdir'          => $this->dir,	// PHP-owned ledger (pfb_sync_status.json)
			'dnsbldir'       => $this->dir,	// Python-owned ledger (pfb_py_status.json)
			'dnsbl_vip4'     => '198.51.100.1',
			'dnsbl_port'     => '8080',
			'dnsbl_port_ssl' => '8443',
			'config'         => [],
		];
	}

	private function writeUnboundConf(bool $referencesPfbUnbound): void
	{
		file_put_contents(
			$this->dir . '/unbound.conf',
			$referencesPfbUnbound ? "python:\n\tpython-script: pfb_unbound.py\n" : "# no python module\n"
		);
	}

	private function writePyStatusFile(array $entries): void
	{
		file_put_contents($this->dir . '/pfb_py_status.json', json_encode($entries));
	}

	// -----------------------------------------------------------------------
	// (a) IP icon.
	// -----------------------------------------------------------------------

	public function testIpDisabledIsRed(): void
	{
		$pfb = $this->basePfb();
		$pfb['enable'] = '';

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('pfBlockerNG is Disabled.', $msg);
	}

	public function testIpDisabledStaysRedEvenWithAnOpenIpEntry(): void
	{
		// Semantics #1: the red/green "is it running" gate is untouched by the
		// ledger -- a disabled facility must never read as yellow just because
		// a stale entry is still open.
		$pfb = $this->basePfb();
		$pfb['enable'] = '';
		pfb_sync_status_open('ip', 'pfB_Stale_v4', 'apply', 'stale entry', $this->dir);

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('pfBlockerNG is Disabled.', $msg);
	}

	public function testIpEnabledNoOpenEntriesIsGreen(): void
	{
		$pfb = $this->basePfb();

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_GREEN, $status);
		$this->assertSame('pfBlockerNG is Active.', $msg);
	}

	public function testIpEnabledDedupOnlyEntryIsYellowWithDedupWording(): void
	{
		$pfb = $this->basePfb();
		pfb_sync_status_open('ip', 'dedup', 'dedup', 'Database Sanity check [ FAILED ]', $this->dir);

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame('pfBlockerNG deDuplication is out of sync. Perform a Force Reload to correct.', $msg);
	}

	public function testIpEnabledNonDedupEntryIsYellowRegardlessOfEnableDup(): void
	{
		// The exact asymmetry this ADR targets: a real apply-stage failure must
		// turn the row yellow even though enable_dup was never turned on.
		$pfb = $this->basePfb();
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'apply', '[pfctl] op=replace table=pfB_Example_v4 failed (rc=1)', $this->dir);

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame('pfBlockerNG has 1 open issue(s). See the Failed Downloads list below.', $msg);
	}

	public function testIpAliasLiterallyNamedDedupIsNotMisclassifiedAsTheDedupSentinel(): void
	{
		// The dedup-sanity sentinel key is (item='dedup', stage='dedup') -- an admin's
		// own alias/feed named "dedup" opens a DIFFERENT stage (e.g. 'download') under
		// the SAME item string. Classifying by item alone would wrongly show the
		// dedup-specific wording for what is really an unrelated download failure.
		$pfb = $this->basePfb();
		pfb_sync_status_open('ip', 'dedup', 'download', 'HTTP 404', $this->dir);

		[$status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame(
			'pfBlockerNG has 1 open issue(s). See the Failed Downloads list below.',
			$msg,
			'a real download failure for an alias named "dedup" must not be mistaken for the dedup-sanity sentinel'
		);
	}

	// -----------------------------------------------------------------------
	// (b) DNSBL icon — each "is it live" gate, individually off -> red.
	// -----------------------------------------------------------------------

	/** A baseline $pfb that is fully "live" for the DNSBL check, no open entries. */
	private function liveDnsblPfb(): array
	{
		$pfb = $this->basePfb();
		$this->writeUnboundConf(TRUE);
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

	public function testDnsblDisabledIsRedWithPlainWordingWhenNoOpenEntries(): void
	{
		// Before-state for the pair below: disabled + a clean ledger keeps the
		// plain "Disabled." wording (Semantics #1: never yellow, but wording still
		// distinguishes "nothing open" from "something open" while disabled).
		$pfb = $this->liveDnsblPfb();
		$pfb['enable'] = '';

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('DNSBL is Disabled.', $msg);
	}

	public function testDnsblDisabledStaysRedButShowsErrorsWordingWithAnOpenDnsblEntry(): void
	{
		// Semantics #1: an open entry must never leak a yellow read into a
		// genuinely-disabled facility -- but the disabled message DOES still
		// distinguish "errors remain" from a clean disable, now sourced from the
		// merged ledger instead of py_error.log's filesize (which the widget no
		// longer reads at all).
		$pfb = $this->liveDnsblPfb();
		$pfb['enable'] = '';
		pfb_sync_status_open('dnsbl', 'dnsbl', 'apply', 'stale dnsbl entry', $this->dir);

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_RED, $status);
		$this->assertSame('DNSBL is Disabled with errors! See the Failed Downloads list below.', $msg);
	}

	// -----------------------------------------------------------------------
	// (b) DNSBL icon — live states.
	// -----------------------------------------------------------------------

	public function testDnsblLiveNoOpenEntriesIsGreen(): void
	{
		$pfb = $this->liveDnsblPfb();

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_GREEN, $status);
		$this->assertSame('DNSBL is Active on vip: 198.51.100.1 ports: 8080 & 8443', $msg);
	}

	public function testDnsblLiveWithOpenPhpEntryIsYellow(): void
	{
		$pfb = $this->liveDnsblPfb();
		pfb_sync_status_open('dnsbl', 'dnsbl', 'apply', 'DNSBL apply not converged', $this->dir);

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame('DNSBL has 1 open issue(s). See the Failed Downloads list below.', $msg);
	}

	public function testDnsblLiveWithOnlyAPythonSideEntryIsYellow(): void
	{
		// No py_error.log content anywhere -- the OLD monotonic filesize trigger
		// would have missed this entirely; the merged ledger read catches it.
		$pfb = $this->liveDnsblPfb();
		$this->writePyStatusFile([
			['facility' => 'dnsbl', 'item' => 'pfb_py_zone.txt', 'stage' => 'parse', 'message' => 'Failed to load: pfb_py_zone.txt: boom', 'first_seen' => 1, 'last_seen' => 1],
		]);

		[, , $status, $msg] = pfb_widget_oracle_status($pfb);

		$this->assertSame(self::ICON_YELLOW, $status);
		$this->assertSame('DNSBL has 1 open issue(s). See the Failed Downloads list below.', $msg);
	}

	// -----------------------------------------------------------------------
	// (c) pfBlockerNG_get_failed().
	// -----------------------------------------------------------------------

	public function testGetFailedEmptyLedgerShowsMaxmindFallback(): void
	{
		$pfb = $this->basePfb();
		$pfb['maxfails'] = 3;
		$GLOBALS['pfb'] = $pfb;

		ob_start();
		pfBlockerNG_get_failed();
		$html = ob_get_clean();

		$this->assertStringContainsString('MaxMind:', $html, 'an empty ledger must fall back to the MaxMind version line');
		$this->assertStringNotContainsString('<ol', $html, 'an empty ledger must not render the issues list');
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
		$pfb['maxfails'] = 3;
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'apply', '[pfctl] op=replace table=pfB_Example_v4 failed (rc=1)', $this->dir);
		$GLOBALS['pfb'] = $pfb;

		ob_start();
		pfBlockerNG_get_failed();
		$html = ob_get_clean();

		$this->assertStringContainsString(
			'pfblockerng_category_edit.php?type=ipv4&act=edit&rowid=0',
			$html,
			'a recognized item must build the alias-editor deep link'
		);
		$this->assertStringContainsString('pfB_Example', $html);
	}

	public function testGetFailedRecognizedAliasBuildsDeepLinkEvenWhenMessageOmitsTheAliasText(): void
	{
		// The message is free-text and does NOT echo "pfB_Example" anywhere -- the link
		// must still be built from the structured 'item' field, not spliced into the
		// message by a substring match (which would silently find nothing here).
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
		$pfb['maxfails'] = 3;
		pfb_sync_status_open('ip', 'pfB_Example_v4', 'dedup', 'N open issue(s). See the report.', $this->dir);
		$GLOBALS['pfb'] = $pfb;

		ob_start();
		pfBlockerNG_get_failed();
		$html = ob_get_clean();

		$this->assertStringContainsString(
			'pfblockerng_category_edit.php?type=ipv4&act=edit&rowid=0',
			$html,
			'the deep link must appear even when the message text never mentions the alias'
		);
	}

	public function testGetFailedPythonSideEntryRendersAsPlainTextWithoutCrashing(): void
	{
		$GLOBALS['config'] = ['installedpackages' => []];
		$pfb = $this->basePfb();
		$pfb['maxfails'] = 3;
		$this->writePyStatusFile([
			['facility' => 'dnsbl', 'item' => 'pfb_py_zone.txt', 'stage' => 'parse', 'message' => 'Failed to load: pfb_py_zone.txt: boom', 'first_seen' => 1, 'last_seen' => 1],
		]);
		$GLOBALS['pfb'] = $pfb;

		ob_start();
		pfBlockerNG_get_failed();
		$html = ob_get_clean();

		$this->assertStringNotContainsString(
			'pfblockerng_category_edit.php',
			$html,
			'a Python-side file-path item must never attempt a deep link'
		);
		$this->assertStringContainsString('pfb_py_zone.txt', $html, 'the entry message must still render');
	}
}
