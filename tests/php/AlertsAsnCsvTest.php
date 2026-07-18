<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1369 (ADR-38 Amendment 3) -- ASN CSV-column coverage for the Alerts
 * page's IP-row converter.
 *
 * The internal pipe-delimited ASN blob (mmdblookup output flattened by
 * pfblockerng.sh's iptoasn()) is replaced, on the IP feature-log write path,
 * by 3 plain CSV columns -- asn, asn_domain, asn_name -- CSV-escaped via
 * native fputcsv() (pfb_asn_csv_fields(), pfblockerng_extra.inc). The
 * owner's 2026-07-18 amendment to issue #1369 drops ALL back-compat for log
 * entries: convert_ip_log() parses ONLY the current 23-field feature-row /
 * 24-field Unified-row schema; any other field count -- including every
 * pre-upgrade legacy row still on disk -- is skipped silently, with zero PHP
 * warnings/notices, until log rotation removes it.
 *
 * Coverage matrix (issue #1369 packet, amended):
 *   Schema:    new schema OK; legacy (old field count) SKIPPED silently;
 *              malformed (any other count) SKIPPED silently
 *   View:      Block (non_unified) + Unified (24-field, leading event type)
 *   Family:    IPv4, IPv6
 *   ASN state: found, 'Unknown', null/missing metadata
 *   Text:      comma, quote, colon, Unicode, empty, CR/LF in asn_name/domain
 *              -- round-trips through real fgetcsv() parsing, no bespoke
 *              escaping needed by the reader
 *   Consumers: Alerts table + tooltip (built from domain+name), ASN filter
 *
 * Harness mirrors AlertsIpConvertPrefetchParityTest's off-appliance load +
 * real-tmpdir technique (AlertsPageLoader.php; no mocking of the lookup
 * layer convert_ip_log() itself drives for the non-ASN parts of the row).
 */
#[CoversFunction('convert_ip_log')]
#[CoversFunction('pfb_ip_log_row_schema_ok')]
final class AlertsAsnCsvTest extends TestCase
{
	private string $tmpDir;
	private string $denydir;
	private string $nativedir;
	private string $ccdir;
	private string $etdir;
	private string $aliasdir;
	private string $matchdir;
	private string $matchgendir;

	/** @var array<string, mixed> */
	private array $savedGlobals = [];

	public static function setUpBeforeClass(): void
	{
		// See AlertsPageLoader.php for the off-appliance load mechanics.
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach ([
			'pfb', 'continents', 'filterfieldsarray', 'clists', 'ip_unlock', 'counter',
			'pfbentries', 'skipcount', 'dup', 'ipfilterlimit', 'ipfilterlimitentries', 'config',
		] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}

		$this->tmpDir    = sys_get_temp_dir() . '/pfb_asn_csv_' . bin2hex(random_bytes(6));
		$this->denydir   = "{$this->tmpDir}/deny";
		$this->nativedir = "{$this->tmpDir}/native";
		$this->ccdir     = "{$this->tmpDir}/geoip";
		$this->etdir     = "{$this->tmpDir}/et";
		$this->aliasdir  = "{$this->tmpDir}/alias";
		$this->matchdir  = "{$this->tmpDir}/match";
		$this->matchgendir = "{$this->matchdir}/generated";
		foreach ([
			$this->denydir, $this->nativedir, $this->ccdir, $this->etdir, $this->aliasdir,
			$this->matchdir, $this->matchgendir,
		] as $d) {
			mkdir($d, 0777, TRUE);
		}
		// Keeps nativedir/matchdir/matchgendir non-empty (avoids the shell literal-glob
		// edge case on an otherwise-empty dir) -- same rationale as
		// AlertsIpConvertPrefetchParityTest's setUp().
		file_put_contents("{$this->nativedir}/NativePlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchdir}/MatchPlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchgendir}/MatchGenPlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->aliasdir}/AliasPlaceholder.txt", "10.0.0.3\n");
		// The reported host is present in its logged feed, so the render never
		// falls into find_reported_header()'s miss path -- irrelevant to the
		// ASN column under test, kept simple/deterministic.
		file_put_contents("{$this->denydir}/DefaultFeed.txt", "192.0.2.11\n2001:db8:dead::5\n");

		$GLOBALS['pfb'] = [
			'grep'             => '/usr/bin/grep',
			'denydir'          => $this->denydir,
			'nativedir'        => $this->nativedir,
			'permitdir'        => "{$this->tmpDir}/permit",
			'matchdir'         => $this->matchdir,
			'matchgendir'      => $this->matchgendir,
			'etdir'            => $this->etdir,
			'ccdir'            => $this->ccdir,
			'aliasdir'         => $this->aliasdir,
			'filterlogentries' => FALSE,
			'asn_reporting'    => 'week',	// enabled (any non-'disabled' vocabulary value)
			'supp'             => '',	// PfbToggle::Off -- suppression-list lookup skipped
			// Unified-mode row background CSS class (light/dark theme) -- pre-existing
			// keys with no seeded default anywhere in production (used only by the
			// Unified row's <tr> background pick); needed here only so a Unified-mode
			// render doesn't trip on an unrelated, pre-existing undefined-key gap.
			'uniblock'         => 'pfb-row-light',
			'uniblock2'        => 'pfb-row-dark',
		];
		// Unified mode reads this to pick the light/dark row background class
		// (see 'uniblock'/'uniblock2' above); seeded so strpos() never receives null.
		$GLOBALS['config']['system']['webgui']['webguicss'] = '';
		$GLOBALS['continents'] = array_flip(array(
			'pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe',
			'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top',
		));
		$GLOBALS['filterfieldsarray'] = [];
		$GLOBALS['clists']              = ['ipwhitelist4' => [], 'ipwhitelist6' => []];
		$GLOBALS['ip_unlock']           = [];
		$GLOBALS['counter']             = ['Block' => 0, 'Unified' => 0];
		$GLOBALS['pfbentries']          = 1000;
		$GLOBALS['skipcount']           = 0;
		$GLOBALS['dup']                 = ['Block' => 0, 'Unified' => 0];
		$GLOBALS['ipfilterlimit']       = FALSE;
		$GLOBALS['ipfilterlimitentries'] = 0;

		pfb_ip_render_memos_reset();
	}

	protected function tearDown(): void
	{
		pfb_ip_render_memos_reset();

		foreach ($this->savedGlobals as $g => $v) {
			if ($v === null) {
				unset($GLOBALS[$g]);
			} else {
				$GLOBALS[$g] = $v;
			}
		}

		rmdir_recursive($this->tmpDir);
	}

	/**
	 * Build a raw, PRE-reorder, NEW-SCHEMA (22-element) $fields row -- the
	 * exact non_unified shape the page's log reader delivers to
	 * convert_ip_log() (dup marker already popped, timestamp still at [0]).
	 * Same base as AlertsIpConvertPrefetchParityTest::rawFields(), extended
	 * with the 2 new ASN columns at [20]/[21].
	 */
	private function rawFields(array $overrides): array
	{
		$base = [
			0  => '2026-07-18 00:00:00',	// Date/Timestamp
			1  => 'rule1',			// Rulenum
			2  => 'em0',			// Real Interface
			3  => 'WAN',			// Friendly Interface name
			4  => 'block',			// Action
			5  => 4,			// Version
			6  => 'tcp',			// Protocol ID
			7  => 'TCP',			// Protocol
			8  => '192.0.2.11',		// SRC IP
			9  => '198.51.100.1',		// DST IP
			10 => '12345',			// SRC Port
			11 => '443',			// DST Port
			12 => 'in',			// Direction
			13 => 'US',			// GeoIP code
			14 => 'pfB_Default_v4',	// IP Alias Name
			15 => '192.0.2.11',		// IP evaluated
			16 => 'DefaultFeed',		// Feed Name
			17 => '',			// gethostbyaddr resolved hostname
			18 => '',			// Client Hostname
			19 => 'Unknown',		// ASN
			20 => '',			// ASN Domain
			21 => '',			// ASN Name
		];
		return array_replace($base, $overrides);
	}

	/** Render one row via the real page function, capturing its printed HTML + warnings. */
	private function render(array $fields, string $mode, string $rtype): array
	{
		$GLOBALS['dup'][$rtype]     = 0;
		$GLOBALS['counter'][$rtype] = 0;
		$GLOBALS['ipfilterlimit']   = FALSE;
		$counterBefore = $GLOBALS['counter'][$rtype];

		$warnings = [];
		set_error_handler(function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return true;
		});
		ob_start();
		try {
			$ret = convert_ip_log($mode, $fields, '', $rtype);
		} finally {
			$html = (string) ob_get_clean();
			restore_error_handler();
		}

		return [$ret, $html, $warnings, $counterBefore];
	}

	// -----------------------------------------------------------------------
	// Schema axis: new OK; legacy SKIPPED; malformed SKIPPED
	// -----------------------------------------------------------------------

	/**
	 * A well-formed new-schema (22-element) non_unified row renders normally
	 * -- baseline for the skip tests below (proves the harness itself works
	 * before proving what gets rejected).
	 */
	public function testNewSchemaRowRenders(): void
	{
		$fields = $this->rawFields([]);

		[$ret, $html, $warnings] = $this->render($fields, 'non_unified', 'Block');

		$this->assertFalse($ret[0], 'a rendered row must not signal "stop the render loop"');
		$this->assertNotSame('', $html, 'a well-formed new-schema row must render SOME output');
		$this->assertSame([], $warnings, 'a well-formed row must render with zero PHP warnings');
	}

	/**
	 * A pre-upgrade LEGACY row (old 20-element non_unified shape -- the
	 * single pipe-blob ASN field, no asn_domain/asn_name columns) is skipped
	 * silently: no output, no warnings, and the row does not consume a
	 * render-limit slot ($counter untouched).
	 */
	public function testLegacyTwentyFieldRowIsSkippedSilently(): void
	{
		$legacy = [
			0  => '2026-07-18 00:00:00', 1 => 'rule1', 2 => 'em0', 3 => 'WAN', 4 => 'block',
			5  => 4, 6 => 'tcp', 7 => 'TCP', 8 => '192.0.2.11', 9 => '198.51.100.1',
			10 => '12345', 11 => '443', 12 => 'in', 13 => 'US', 14 => 'pfB_Default_v4',
			15 => '192.0.2.11', 16 => 'DefaultFeed', 17 => '', 18 => '',
			19 => '|ASN:  AS50360 | domain:  4vendeta.com | name:  Tamatiya EOOD |',	// old blob shape
		];
		$this->assertCount(20, $legacy, 'fixture sanity: this must be the OLD 20-element shape');

		[$ret, $html, $warnings, $counterBefore] = $this->render($legacy, 'non_unified', 'Block');

		$this->assertSame([FALSE, ''], $ret);
		$this->assertSame('', $html, 'a legacy-schema row must render NOTHING, not a partial/garbled row');
		$this->assertSame([], $warnings, 'skipping a legacy row must never raise a PHP warning/notice');
		$this->assertSame($counterBefore, $GLOBALS['counter']['Block'], 'a skipped row must not consume a render-limit slot');
	}

	/**
	 * A genuinely malformed row (arbitrary short field count, matching
	 * neither the legacy nor the current schema) is skipped exactly the same
	 * way -- zero warnings despite having far fewer elements than every
	 * index the render path would otherwise touch.
	 */
	public function testMalformedShortRowIsSkippedSilently(): void
	{
		$malformed = [0 => '2026-07-18 00:00:00', 1 => 'rule1', 2 => 'em0', 3 => 'WAN', 4 => 'block'];

		[$ret, $html, $warnings, $counterBefore] = $this->render($malformed, 'non_unified', 'Block');

		$this->assertSame([FALSE, ''], $ret);
		$this->assertSame('', $html);
		$this->assertSame([], $warnings, 'a malformed row must never raise a PHP warning/notice');
		$this->assertSame($counterBefore, $GLOBALS['counter']['Block']);
	}

	/**
	 * pfb_ip_log_row_schema_ok() directly, both modes -- the exact boundary
	 * convert_ip_log() relies on.
	 */
	public function testSchemaGateExactCounts(): void
	{
		$this->assertTrue(pfb_ip_log_row_schema_ok(array_fill(0, 22, ''), 'non_unified'), '22 elements = new non_unified schema');
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 20, ''), 'non_unified'), '20 elements = old legacy schema, must reject');
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 21, ''), 'non_unified'), '21 elements = old Unified count under the wrong mode, must reject');
		$this->assertTrue(pfb_ip_log_row_schema_ok(array_fill(0, 23, ''), 'Unified'), '23 elements = new Unified schema');
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 21, ''), 'Unified'), '21 elements = old legacy Unified count, must reject');
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 0, ''), 'non_unified'), 'empty row must reject');
		// The gate is an EXACT count, not a minimum -- an over-long row (extra
		// commas from any source) is just as unsupported as a short one.
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 23, ''), 'non_unified'), '23 elements = one field too many for non_unified, must reject');
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 24, ''), 'non_unified'), '24 elements = over-long non_unified row, must reject');
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 24, ''), 'Unified'), '24 elements = one field too many for Unified, must reject');
		$this->assertFalse(pfb_ip_log_row_schema_ok(array_fill(0, 25, ''), 'Unified'), '25 elements = over-long Unified row, must reject');
	}

	// -----------------------------------------------------------------------
	// View axis: Unified (24-field, leading event type already stripped by
	// the caller, trailing dup marker still attached)
	// -----------------------------------------------------------------------

	/**
	 * A well-formed new-schema Unified-mode row (23 raw elements: timestamp
	 * + 21 body fields + trailing dup marker, matching what
	 * pfblockerng_alerts.php's Unified loop hands convert_ip_log() after
	 * stripping the leading event-type field) renders the ASN + tooltip
	 * exactly like the non_unified view.
	 */
	public function testUnifiedModeNewSchemaRowRendersAsnAndTooltip(): void
	{
		$fields = $this->rawFields([
			19 => 'AS50360', 20 => '4vendeta.com', 21 => 'Tamatiya EOOD',
		]);
		$fields[22] = '+';	// trailing duplicate marker -- Unified mode does NOT pop it
		$this->assertCount(23, $fields, 'fixture sanity: Unified non_unified+1 shape');

		[$ret, $html, $warnings] = $this->render($fields, 'Unified', 'Block');

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('AS50360', $html, 'the visible ASN must render in Unified mode too');
		$this->assertStringContainsString('title="domain:', $html, 'the tooltip must render in Unified mode too');
	}

	/**
	 * A legacy-shape Unified row (22 raw elements -- the old count) is
	 * skipped silently, mirroring the non_unified legacy case.
	 */
	public function testUnifiedModeLegacyRowIsSkippedSilently(): void
	{
		$legacy = [
			0 => '2026-07-18 00:00:00', 1 => 'rule1', 2 => 'em0', 3 => 'WAN', 4 => 'block',
			5 => 4, 6 => 'tcp', 7 => 'TCP', 8 => '192.0.2.11', 9 => '198.51.100.1',
			10 => '12345', 11 => '443', 12 => 'in', 13 => 'US', 14 => 'pfB_Default_v4',
			15 => '192.0.2.11', 16 => 'DefaultFeed', 17 => '', 18 => '',
			19 => 'Unknown', 20 => '+',	// old 20-body-field shape + trailing dup marker = 21
		];
		$this->assertCount(21, $legacy, 'fixture sanity: OLD Unified shape (20 body fields + dup)');

		[$ret, $html, $warnings, $counterBefore] = $this->render($legacy, 'Unified', 'Block');

		$this->assertSame([FALSE, ''], $ret);
		$this->assertSame('', $html);
		$this->assertSame([], $warnings);
		$this->assertSame($counterBefore, $GLOBALS['counter']['Block']);
	}

	// -----------------------------------------------------------------------
	// ASN state axis: found / Unknown / null
	// -----------------------------------------------------------------------

	public function testFoundAsnRendersVisibleAsnAndTooltipFromDomainAndName(): void
	{
		$fields = $this->rawFields([
			19 => 'AS50360', 20 => '4vendeta.com', 21 => 'Tamatiya EOOD',
		]);

		[, $html, $warnings] = $this->render($fields, 'non_unified', 'Block');

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS50360<', $html, 'the visible ASN text must render');
		$this->assertStringContainsString('title="domain:  4vendeta.com | name:  Tamatiya EOOD"', $html, 'the tooltip must be built from the domain + name columns');
	}

	public function testUnknownAsnRendersNoAsnMarkup(): void
	{
		$fields = $this->rawFields([19 => 'Unknown', 20 => '', 21 => '']);

		[, $html, $warnings] = $this->render($fields, 'non_unified', 'Block');

		$this->assertSame([], $warnings);
		$this->assertStringNotContainsString('<span title="domain:', $html, "an 'Unknown' ASN state must render no ASN span");
	}

	/**
	 * 'null' -- the write-time literal when ASN reporting was OFF when the
	 * event was logged but is enabled now at render time (the "missing
	 * metadata" state distinct from a completed-but-empty lookup).
	 */
	public function testNullAsnRendersNoAsnMarkup(): void
	{
		$fields = $this->rawFields([19 => 'null', 20 => '', 21 => '']);

		[, $html, $warnings] = $this->render($fields, 'non_unified', 'Block');

		$this->assertSame([], $warnings);
		$this->assertStringNotContainsString('<span title="domain:', $html, "a 'null' ASN state must render no ASN span");
	}

	public function testAsnReportingDisabledRendersNoAsnMarkupEvenWhenFound(): void
	{
		$GLOBALS['pfb']['asn_reporting'] = 'disabled';
		$fields = $this->rawFields([
			19 => 'AS50360', 20 => '4vendeta.com', 21 => 'Tamatiya EOOD',
		]);

		[, $html, $warnings] = $this->render($fields, 'non_unified', 'Block');

		$this->assertSame([], $warnings);
		$this->assertStringNotContainsString('AS50360', $html, 'ASN reporting disabled must suppress the column regardless of a found value');
	}

	// -----------------------------------------------------------------------
	// Family axis: IPv4, IPv6
	// -----------------------------------------------------------------------

	public function testFoundAsnRendersForIpv6Row(): void
	{
		$fields = $this->rawFields([
			5 => 6, 8 => '2001:db8:dead::5', 9 => '2001:db8:2::1',
			15 => '2001:db8:dead::5', 16 => 'DefaultFeed',
			19 => 'AS64500', 20 => 'v6.example', 21 => 'V6 Org',
		]);

		[, $html, $warnings] = $this->render($fields, 'non_unified', 'Block');

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS64500<', $html);
		$this->assertStringContainsString('title="domain:  v6.example | name:  V6 Org"', $html);
	}

	// -----------------------------------------------------------------------
	// Text handling axis: comma, quote, colon, Unicode, empty, CR/LF --
	// driven through a REAL fgetcsv() parse (not hand-typed array literals),
	// proving the writer+reader round trip end to end.
	// -----------------------------------------------------------------------

	/**
	 * Build a raw CSV line the way pfb_daemon_filterlog() does (log fields,
	 * then $details ending in pfb_asn_csv_fields()'s encoded tail), parse it
	 * back with the SAME escape argument the page's read loop now uses, pop
	 * the trailing dup marker (mirroring the non_unified read-loop caller),
	 * and hand the result straight to convert_ip_log() -- exercising the
	 * real write -> real CSV parse -> render pipeline for one row.
	 */
	private function renderFromRealAsnBlob(string $blob, array $overrides = []): array
	{
		$asnCsv = pfb_asn_csv_fields($blob);
		$o = array_replace([
			'ts' => '2026-07-18 00:00:00', 'rule' => 'rule1', 'int' => 'em0', 'fint' => 'WAN',
			'action' => 'block', 'ver' => 4, 'protoid' => 'tcp', 'proto' => 'TCP',
			'src' => '192.0.2.11', 'dst' => '198.51.100.1', 'sport' => '12345', 'dport' => '443',
			'dir' => 'in', 'geoip' => 'US', 'alias' => 'pfB_Default_v4', 'eval' => '192.0.2.11',
			'feed' => 'DefaultFeed', 'resolved' => '', 'client' => '',
		], $overrides);

		$line = implode(',', [
			$o['ts'], $o['rule'], $o['int'], $o['fint'], $o['action'], $o['ver'], $o['protoid'], $o['proto'],
			$o['src'], $o['dst'], $o['sport'], $o['dport'], $o['dir'], $o['geoip'], $o['alias'], $o['eval'],
			$o['feed'], $o['resolved'], $o['client'],
		]) . ',' . $asnCsv . ',+';

		$fh = fopen('php://temp', 'r+');
		$this->assertNotFalse($fh);
		fwrite($fh, $line . "\n");
		rewind($fh);
		$fields = fgetcsv($fh, 0, ',', '"', '');
		fclose($fh);
		$this->assertNotFalse($fields, 'the synthetic line must parse as valid CSV');

		$dup = array_pop($fields);	// mirrors the page's non_unified read loop
		$this->assertSame('+', $dup);
		$this->assertCount(22, $fields, 'fixture sanity: 22-element new non_unified schema after popping dup');

		return $this->render($fields, 'non_unified', 'Block');
	}

	public function testTextHandlingCommaInDomainRoundTripsAndRenders(): void
	{
		[, $html, $warnings] = $this->renderFromRealAsnBlob(
			'|ASN:  AS64510 | domain:  ex,ample.com | name:  CommaOrg |'
		);

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS64510<', $html);
		$this->assertStringContainsString('ex,ample.com', $html, 'the comma-bearing domain must reach the tooltip intact');
	}

	public function testTextHandlingQuoteInNameRoundTripsAndRenders(): void
	{
		[, $html, $warnings] = $this->renderFromRealAsnBlob(
			'|ASN:  AS64511 | domain:  example.net | name:  "Quoted" Org |'
		);

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS64511<', $html);
		// pfb_hsc() HTML-encodes the literal double quote for safe attribute embedding.
		$this->assertStringContainsString('&quot;Quoted&quot; Org', $html, 'the quote-bearing name must reach the tooltip, HTML-encoded');
	}

	public function testTextHandlingColonInNameRoundTripsAndRenders(): void
	{
		[, $html, $warnings] = $this->renderFromRealAsnBlob(
			'|ASN:  AS64512 | domain:  example.org | name:  Org: EMEA Division |'
		);

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS64512<', $html);
		$this->assertStringContainsString('Org: EMEA Division', $html, 'the colon-bearing name must reach the tooltip intact');
	}

	public function testTextHandlingUnicodeInNameRoundTripsAndRenders(): void
	{
		[, $html, $warnings] = $this->renderFromRealAsnBlob(
			'|ASN:  AS64513 | domain:  xn--ls8h.example | name:  Ünïcödé Örg 日本 |'
		);

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS64513<', $html);
		$this->assertStringContainsString('Ünïcödé Örg 日本', $html, 'the Unicode name must reach the tooltip byte-identical');
	}

	public function testTextHandlingEmptyDomainAndNameRenderBlankTooltipSegments(): void
	{
		[, $html, $warnings] = $this->renderFromRealAsnBlob(
			'|ASN:  AS64514 | domain:   | name:   |'
		);

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS64514<', $html);
		$this->assertStringContainsString('title="domain:   | name:  "', $html, 'empty domain/name must render as blank tooltip segments, not warnings/placeholders');
	}

	public function testTextHandlingCrLfInNameRoundTripsAsNormalizedSpace(): void
	{
		[, $html, $warnings] = $this->renderFromRealAsnBlob(
			"|ASN:  AS64515 | domain:  example.io | name:  Line One\r\nLine Two |"
		);

		$this->assertSame([], $warnings);
		$this->assertStringContainsString('>AS64515<', $html);
		$this->assertStringContainsString('Line One Line Two', $html, 'CR/LF in the name must have been normalized to a space before it ever reached the log');
		$this->assertStringNotContainsString("Line One\r\nLine Two", $html);
	}

	// -----------------------------------------------------------------------
	// Consumer axis: ASN filter (pfb_match_filter_field key==18 special-case)
	// -----------------------------------------------------------------------

	/**
	 * The ASN filter (Alerts page "Filter" fields, keyed on the ASN column
	 * position) continues to match against the new plain ASN token -- no
	 * change needed to pfb_match_filter_field(), which already strips a
	 * leading 'AS' from the query and regex-matches the raw field value.
	 */
	public function testAsnFilterMatchesNewPlainAsnField(): void
	{
		$GLOBALS['pfb']['filterlogentries'] = TRUE;
		$GLOBALS['filterfieldsarray'] = [[18 => 'AS50360']];

		$matching = $this->rawFields([19 => 'AS50360', 20 => '4vendeta.com', 21 => 'Tamatiya EOOD']);
		[, $htmlMatch, $warnings1] = $this->render($matching, 'non_unified', 'Block');

		$GLOBALS['dup']['Block'] = 0;
		$GLOBALS['counter']['Block'] = 0;
		$nonMatching = $this->rawFields([19 => 'AS99999', 20 => 'other.example', 21 => 'Other Org']);
		[$retNoMatch, $htmlNoMatch, $warnings2] = $this->render($nonMatching, 'non_unified', 'Block');

		$this->assertSame([], $warnings1);
		$this->assertSame([], $warnings2);
		$this->assertStringContainsString('>AS50360<', $htmlMatch, 'a row whose ASN matches the filter must render');
		$this->assertSame('', $htmlNoMatch, 'a row whose ASN does NOT match the filter must render nothing');
		$this->assertSame([FALSE, ''], $retNoMatch);
	}

	/**
	 * A schema-invalid (legacy) row is skipped BEFORE the filter match ever
	 * runs against it -- proves the schema gate is unconditional, not
	 * dependent on whether filtering is active.
	 */
	public function testAsnFilterNeverEvaluatesAgainstALegacyRow(): void
	{
		$GLOBALS['pfb']['filterlogentries'] = TRUE;
		$GLOBALS['filterfieldsarray'] = [[18 => 'AS50360']];

		$legacy = [
			0 => '2026-07-18 00:00:00', 1 => 'rule1', 2 => 'em0', 3 => 'WAN', 4 => 'block',
			5 => 4, 6 => 'tcp', 7 => 'TCP', 8 => '192.0.2.11', 9 => '198.51.100.1',
			10 => '12345', 11 => '443', 12 => 'in', 13 => 'US', 14 => 'pfB_Default_v4',
			15 => '192.0.2.11', 16 => 'DefaultFeed', 17 => '', 18 => '',
			19 => '|ASN:  AS50360 | domain:  4vendeta.com | name:  Tamatiya EOOD |',
		];

		[$ret, $html, $warnings] = $this->render($legacy, 'non_unified', 'Block');

		$this->assertSame([FALSE, ''], $ret);
		$this->assertSame('', $html);
		$this->assertSame([], $warnings, 'a legacy row must never reach pfb_match_filter_field() at all');
	}
}
