<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1815: the 10 byte-substr() display-truncation sites in
 * pfblockerng_alerts.php's row builders (convert_dnsbl_log / convert_dns_reply_log /
 * convert_ip_log) cut on BYTES, not characters. A multibyte character straddling the
 * cut leaves a dangling lead byte; pfb_hsc()'s ENT_SUBSTITUTE (issue #1814) then
 * renders that dangling byte as a spurious U+FFFD instead of keeping the character
 * whole. This file pins every site converted to mb_substr(..., 'UTF-8') (the #1069
 * exemplar's own form, pfb_stat_hostname_cell()).
 *
 * Coverage matrix (rows 1-10 = the 10 sites; 12-16 = branch/hostile-input axes;
 * 17-19 = Unified-view narrow-width arms):
 *   1  convert_dnsbl_log     $hostname (SRC-IP resolved name)          cut=24
 *   2  convert_dnsbl_log     $f2 (blocked domain)                      cut=59 (wide arm)
 *   3  convert_dnsbl_log     $f7 (CNAME evaluated domain)              cut=51 (wide arm)
 *   4  convert_dnsbl_log     $fields[4] (DNSBL Type / agent string)    cut=24
 *   5  convert_dns_reply_log $hostname (SRC-IP resolved name)          cut=24
 *   6  convert_dns_reply_log $fields[5] (TTL)                         cut=5
 *   7  convert_dns_reply_log $fields[6] (replied domain)                cut=44 (wide arm)
 *   8  convert_dns_reply_log $fields[8] (resolved value)               cut=16
 *   9  convert_ip_log        $fields[15] (logged Feed Name)             cut=16
 *   10 convert_ip_log        $feed_new (re-attributed feed)             cut=16
 *   12 short-side branch coverage, one per builder (no truncation, no U+FFFD)
 *   13 4-byte character (emoji) straddling the cut
 *   14 invalid UTF-8 byte before the cut -- see that test's docblock
 *   15 HTML metacharacter at the character-cut boundary -- entity stays complete
 *   16 punycode/xn-- domain whose idn_to_utf8()-produced text straddles the cut
 *   17 Unified DNSBL domain narrow cut=39 (wide side remains row 2)
 *   18 Unified DNSBL CNAME narrow cut=31 (wide side remains row 3)
 *   19 Unified DNS reply domain narrow cut=29 (wide side remains row 7)
 *
 * Every test drives the value through the row builder's OWN production surface
 * (convert_dnsbl_log() / convert_dns_reply_log() / convert_ip_log()), capturing
 * printed output via ob_start()/ob_get_clean() -- never asserts against a
 * hand-built string. Harness combines AlertsRowOutputEncodingTest's dnsbl globals,
 * AlertsDnsReplyWhitelistTypeTest's dns-reply globals, and
 * AlertsIpConvertPrefetchParityTest/AlertsIpUnlockIconTest's real fixture-dir IP
 * harness (find/grep exec() calls against a temp sandbox, no mocking of the lookup
 * layer) into one setUp() so all three builders are available to every test method.
 */
#[CoversFunction('convert_dnsbl_log')]
#[CoversFunction('convert_dns_reply_log')]
#[CoversFunction('convert_ip_log')]
#[CoversFunction('pfb_hsc')]
#[CoversFunction('dnsbl_log_details')]
#[CoversFunction('pfb_ip_render_attribution')]
#[CoversFunction('pfb_ip_feed_match_cell')]
final class AlertsMultibyteTruncationTest extends TestCase
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
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach ([
			'pfb', 'local_hosts', 'dnsbl_int', 'filterfieldsarray', 'clists',
			'dnsbl_unlock', 'dup', 'counter', 'pfbentries', 'skipcount',
			'dnsblfilterlimit', 'dnsblfilterlimitentries',
			'dnsfilterlimit', 'dnsfilterlimitentries',
			'continents', 'ip_unlock', 'ipfilterlimit', 'ipfilterlimitentries',
		] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}

		$this->tmpDir       = sys_get_temp_dir() . '/pfb_alerts_mb_truncation_' . bin2hex(random_bytes(6));
		$this->denydir      = "{$this->tmpDir}/deny";
		$this->nativedir    = "{$this->tmpDir}/native";
		$this->ccdir        = "{$this->tmpDir}/geoip";
		$this->etdir        = "{$this->tmpDir}/et";
		$this->aliasdir     = "{$this->tmpDir}/alias";
		$this->matchdir     = "{$this->tmpDir}/match";
		$this->matchgendir  = "{$this->matchdir}/generated";
		foreach ([
			$this->denydir, $this->nativedir, $this->ccdir, $this->etdir, $this->aliasdir,
			$this->matchdir, $this->matchgendir,
		] as $d) {
			mkdir($d, 0777, TRUE);
		}
		// Keeps multi-glob dirs non-empty so grep's output carries the "path:" prefix
		// (see AlertsIpConvertPrefetchParityTest's setUp() for the full rationale).
		file_put_contents("{$this->nativedir}/NativePlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchdir}/MatchPlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchgendir}/MatchGenPlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->aliasdir}/AliasPlaceholder.txt", "10.0.0.3\n");

		$GLOBALS['pfb'] = [
			'filterlogentries' => FALSE,
			'grep'             => '/usr/bin/grep',
			'denydir'          => $this->denydir,
			'nativedir'        => $this->nativedir,
			'permitdir'        => "{$this->tmpDir}/permit",
			'matchdir'         => $this->matchdir,
			'matchgendir'      => $this->matchgendir,
			'etdir'            => $this->etdir,
			'ccdir'            => $this->ccdir,
			'aliasdir'         => $this->aliasdir,
			'asn_reporting'    => 'disabled',
			'supp'             => '',	// PfbToggle::Off -- suppression-list lookup skipped
			'unidnsbl'         => '#f0f0f0',
			'unidnsbl2'        => '#202020',
			'unireply'         => '#f0f0f0',
			'unireply2'        => '#202020',
		];
		$GLOBALS['local_hosts']              = [];
		$GLOBALS['dnsbl_int']                = [];
		$GLOBALS['filterfieldsarray']        = [];
		$GLOBALS['clists']                   = [
			'dnsbl'                  => ['options' => []],
			'dnsblwhitelist'         => ['data' => []],
			'tld_wildcard_exclusion' => ['data' => []],
			'ipwhitelist4'           => [],
			'ipwhitelist6'           => [],
		];
		$GLOBALS['dnsbl_unlock']             = [];
		$GLOBALS['dup']                      = ['DNSBL' => 0, 'DNS' => 0, 'Block' => 0];
		$GLOBALS['counter']                  = ['DNSBL' => 0, 'DNS' => 0, 'Unified' => 0, 'Block' => 0];
		$GLOBALS['pfbentries']               = 1000;
		$GLOBALS['skipcount']                = 0;
		$GLOBALS['dnsblfilterlimit']         = FALSE;
		$GLOBALS['dnsblfilterlimitentries']  = 100;
		$GLOBALS['dnsfilterlimit']           = FALSE;
		$GLOBALS['dnsfilterlimitentries']    = 100;
		$GLOBALS['continents']               = array_flip(array(
			'pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe',
			'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top',
		));
		$GLOBALS['ip_unlock']                = [];
		$GLOBALS['ipfilterlimit']            = FALSE;
		$GLOBALS['ipfilterlimitentries']     = 0;

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

	// -----------------------------------------------------------------------
	// Straddle-string builders
	// -----------------------------------------------------------------------

	/**
	 * A byte string whose CUT-th byte (0-based index CUT-1) is the LEAD byte of
	 * $mbChar: a byte-based substr($v, 0, CUT) keeps that lead byte alone (a
	 * dangling, invalid sequence), while a character-based mb_substr($v, 0, CUT,
	 * 'UTF-8') keeps $mbChar whole. $marker is a short ASCII prefix that survives
	 * inside the retained text, proving THIS seeded value produced the cell.
	 */
	private function mbStraddle(int $cut, string $marker, string $mbChar, string $tail): string
	{
		return $marker . str_repeat('a', $cut - 1 - strlen($marker)) . $mbChar . $tail;
	}

	/**
	 * Two copies of $mbChar followed by $metachar, sized so a CHARACTER cut of
	 * length CUT keeps all of "$marker + a's + $mbChar + $mbChar + $metachar"
	 * whole (metachar included) while a BYTE cut of the same numeric length
	 * dangles mid-SECOND $mbChar and never reaches $metachar at all -- proving
	 * both that the multibyte run survives AND that the truncate-raw-then-encode
	 * ordering (#1069) still yields a COMPLETE entity for $metachar, never split.
	 */
	private function doubleMbStraddle(int $cut, string $marker, string $mbChar, string $metachar, string $tail): string
	{
		return $marker . str_repeat('a', $cut - 3 - strlen($marker)) . $mbChar . $mbChar . $metachar . $tail;
	}

	/**
	 * Build a value that reaches a byte gate but stays below that gate in UTF-8
	 * code points, so the gate itself (not the cut) is the regression oracle.
	 */
	private function characterGateValue(int $gate, string $marker): string
	{
		$value = $marker;
		while (strlen($value) < $gate) {
			$value .= '界';
		}
		$this->assertGreaterThanOrEqual($gate, strlen($value));
		$this->assertLessThan($gate, mb_strlen($value, 'UTF-8'));
		return $value;
	}

	// -----------------------------------------------------------------------
	// convert_dnsbl_log() harness
	// -----------------------------------------------------------------------

	/** Field layout per convert_dnsbl_log()'s own "dnsbl.log Fields Reference" comment. */
	private function dnsblFields(
		string $domain,
		string $srcIp,
		string $group,
		string $feed,
		string $agent = '',
		string $btype = 'Python A',
		?string $evalDomain = null
	): array {
		return [
			0  => 'DNSBL-python',
			1  => '2026-01-01 00:00:00',
			2  => $domain,
			3  => $srcIp,
			4  => $agent,
			5  => $btype,
			6  => $group,
			7  => $evalDomain ?? $domain,
			8  => $feed,
			9  => 0,
			10 => 'A',
		];
	}

	private function renderDnsblRow(array $fields, string $mode = 'Reports'): string
	{
		ob_start();
		convert_dnsbl_log($mode, $fields);
		return (string) ob_get_clean();
	}

	// -----------------------------------------------------------------------
	// convert_dns_reply_log() harness
	// -----------------------------------------------------------------------

	/** Field layout per AlertsDnsReplyWhitelistTypeTest::replyFields(). */
	private function replyFields(string $domain, string $srcIp): array
	{
		return [
			0 => 'DNS-Reply',
			1 => '2026-01-01 00:00:00',
			2 => 'Reply',
			3 => 'A',
			4 => 'A',
			5 => '300',
			6 => $domain,
			7 => $srcIp,
			8 => '198.51.100.9',
			9 => 'US',
		];
	}

	private function renderReplyRow(array $fields, string $mode = 'Reports'): string
	{
		ob_start();
		convert_dns_reply_log($mode, $fields);
		return (string) ob_get_clean();
	}

	// -----------------------------------------------------------------------
	// convert_ip_log() harness
	// -----------------------------------------------------------------------

	/**
	 * Raw, PRE-reorder $fields row -- same 22-element shape/reference as
	 * AlertsIpConvertPrefetchParityTest::rawFields() / AlertsIpUnlockIconTest::rawFields().
	 */
	private function ipRawFields(array $overrides): array
	{
		$base = [
			0  => '2026-08-01 00:00:00',	// Date/Timestamp
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

	private function renderIpRow(array $fields, string $rtype): string
	{
		$GLOBALS['dup'][$rtype]     = 0;
		$GLOBALS['counter'][$rtype] = 0;
		$GLOBALS['ipfilterlimit']   = FALSE;

		ob_start();
		convert_ip_log('non_unified', $fields, '', $rtype);
		return (string) ob_get_clean();
	}

	// =========================================================================
	// Rows 1-10: the 10 truncation sites
	// =========================================================================

	public function test_row01_dnsbl_srcip_hostname_truncation_keeps_multibyte_char_whole(): void
	{
		$srcIp = '10.1.0.1';
		$value = $this->mbStraddle(24, 'R01', 'é', 'trailing-host.example');
		$GLOBALS['local_hosts'] = [$srcIp => $value];
		$fields = $this->dnsblFields('benign-domain-01.example', $srcIp, 'Grp01', 'Feed01');

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString('R01', $html, 'the seeded marker must reach the rendered cell');
		$this->assertStringContainsString('<small>...</small>', $html, 'the value must actually be truncated');
		$this->assertStringNotContainsString("\u{FFFD}", $html, 'mb_substr must keep the multibyte char whole, not dangle its lead byte');
		$this->assertStringContainsString('é', $html, 'the straddling multibyte character must survive intact');
	}

	public function test_row02_dnsbl_domain_truncation_keeps_multibyte_char_whole(): void
	{
		$domain = $this->mbStraddle(59, 'R02', 'é', 'trailing-domain-suffix.example');
		$fields = $this->dnsblFields($domain, '10.1.0.2', 'Grp02', 'Feed02');

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString('R02', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	public function test_row03_dnsbl_cname_truncation_keeps_multibyte_char_whole(): void
	{
		$cname  = $this->mbStraddle(51, 'R03', 'é', 'trailing-cname-suffix.example');
		// 'DNSBL_CNAME' trips dnsbl_log_details()'s isCNAME gate (strpos '_CNAME'),
		// which routes $fields[7] (here $cname) into the $f7 truncation site.
		$fields = $this->dnsblFields('blocked-domain-03.example', '10.1.0.3', 'Grp03', 'Feed03', '', 'DNSBL_CNAME', $cname);

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString('R03', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	public function test_row04_dnsbl_agent_field_truncation_keeps_multibyte_char_whole(): void
	{
		$agent  = $this->mbStraddle(24, 'R04', 'é', 'trailing-agent-suffix');
		$fields = $this->dnsblFields('benign-domain-04.example', '10.1.0.4', 'Grp04', 'Feed04', $agent);

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString('R04', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	public function test_row05_dnsreply_srcip_hostname_truncation_keeps_multibyte_char_whole(): void
	{
		$srcIp = '10.1.0.5';
		$value = $this->mbStraddle(24, 'R05', 'é', 'trailing-host.example');
		$GLOBALS['local_hosts'] = [$srcIp => $value];
		$fields = $this->replyFields('reply-domain-05.example', $srcIp);

		$html = $this->renderReplyRow($fields);

		$this->assertStringContainsString('R05', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	public function test_row06_dnsreply_ttl_truncation_keeps_multibyte_char_whole(): void
	{
		$srcIp = '10.1.0.6';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$fields    = $this->replyFields('reply-domain-06.example', $srcIp);
		$fields[5] = $this->mbStraddle(5, 'R06', 'é', '0000');

		$html = $this->renderReplyRow($fields);

		$this->assertStringContainsString('R06', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	public function test_row07_dnsreply_domain_truncation_keeps_multibyte_char_whole(): void
	{
		$srcIp = '10.1.0.7';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$domain = $this->mbStraddle(44, 'R07', 'é', 'trailing-domain-suffix.example');
		$fields = $this->replyFields($domain, $srcIp);

		$html = $this->renderReplyRow($fields);

		$this->assertStringContainsString('R07', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	public function test_row08_dnsreply_resolved_value_truncation_keeps_multibyte_char_whole(): void
	{
		$srcIp = '10.1.0.8';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$fields    = $this->replyFields('reply-domain-08.example', $srcIp);
		$fields[8] = $this->mbStraddle(16, 'R08', 'é', 'trailing-suffix');

		$html = $this->renderReplyRow($fields);

		$this->assertStringContainsString('R08', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	/** "Still-listed" shape (AlertsIpConvertPrefetchParityTest case 1): the reported IP is
	 * still an exact line in its OWN logged feed file, so $feed_new stays empty and only
	 * the logged $fields[15] (site 9) is exercised. */
	public function test_row09_ip_feed_name_truncation_keeps_multibyte_char_whole(): void
	{
		$feed = $this->mbStraddle(16, 'R09', 'é', 'trailing-feed');
		file_put_contents("{$this->denydir}/{$feed}.txt", "192.0.2.90\n");

		$fields = $this->ipRawFields([
			8 => '192.0.2.90', 15 => '192.0.2.90',
			14 => 'pfB_Row09_v4', 16 => $feed,
		]);

		$html = $this->renderIpRow($fields, 'Block');

		$this->assertStringContainsString('R09', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	/** "Moved-feed" shape (AlertsIpConvertPrefetchParityTest case 3): the logged feed name
	 * has no on-disk file, forcing the attribution seam's miss path to re-locate the IP
	 * under a DIFFERENT feed file -- driving $feed_new (site 10) non-empty for real. */
	public function test_row10_ip_feed_new_truncation_keeps_multibyte_char_whole(): void
	{
		$newFeed = $this->mbStraddle(16, 'R10', 'é', 'trailing-feed-new');
		file_put_contents("{$this->denydir}/{$newFeed}.txt", "192.0.2.100\n");

		// Kept under the site-9 gate (17 chars) so the OLD feed name itself renders
		// verbatim in the struck-through markup below, not ALSO truncated -- that
		// would make the non-vacuity assertion fail for the wrong reason.
		$oldFeed = 'R10OldFeed';
		$this->assertLessThan(17, strlen($oldFeed), 'fixture sanity: the OLD feed name must not itself trip the site-9 gate');

		$fields = $this->ipRawFields([
			8 => '192.0.2.100', 15 => '192.0.2.100',
			14 => 'pfB_Row10_v4', 16 => $oldFeed,
		]);

		$html = $this->renderIpRow($fields, 'Block');

		// Non-vacuity: the attribution seam actually re-attributed to a new feed
		// (the struck-through old-feed markup pfb_ip_feed_match_cell() emits) --
		// otherwise $feed_new would still be empty and site 10 never exercised.
		$this->assertStringContainsString(
			"<s>{$oldFeed}</s>",
			$html,
			'the attribution seam must have produced a non-empty feed_new to exercise this site'
		);

		$this->assertStringContainsString('R10', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
		$this->assertStringContainsString('é', $html);
	}

	// =========================================================================
	// Row 12: branch coverage, SHORT side (one per builder) -- proves the fix is
	// not an always-truncate/always-mangle path.
	// =========================================================================

	public function test_row12_dnsbl_short_hostname_renders_verbatim_no_truncation(): void
	{
		$srcIp = '10.1.0.12';
		$value = 'short-host.example';
		$this->assertLessThan(25, strlen($value), 'fixture sanity: must be under the 25-char gate');
		$GLOBALS['local_hosts'] = [$srcIp => $value];
		$fields = $this->dnsblFields('benign-domain-12.example', $srcIp, 'Grp12', 'Feed12');

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString($value, $html, 'a short value must render verbatim');
		$this->assertStringNotContainsString('<small>...</small>', $html, 'a short value must not be truncated');
		$this->assertStringNotContainsString("\u{FFFD}", $html);
	}

	public function test_row12_dnsreply_short_resolved_value_renders_verbatim_no_truncation(): void
	{
		$srcIp = '10.1.0.13';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$fields    = $this->replyFields('reply-domain-13.example', $srcIp);
		$fields[8] = 'short-val';
		$this->assertLessThan(17, strlen($fields[8]), 'fixture sanity: must be under the 17-char gate');

		$html = $this->renderReplyRow($fields);

		$this->assertStringContainsString('short-val', $html);
		$this->assertStringNotContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
	}

	public function test_row12_ip_short_feed_name_renders_verbatim_no_truncation(): void
	{
		file_put_contents("{$this->denydir}/ShortFeed12.txt", "192.0.2.120\n");
		$this->assertLessThan(17, strlen('ShortFeed12'), 'fixture sanity: must be under the 17-char gate');

		$fields = $this->ipRawFields([
			8 => '192.0.2.120', 15 => '192.0.2.120',
			14 => 'pfB_Row12_v4', 16 => 'ShortFeed12',
		]);

		$html = $this->renderIpRow($fields, 'Block');

		$this->assertStringContainsString('ShortFeed12', $html);
		$this->assertStringNotContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html);
	}

	// =========================================================================
	// Row 13: 4-byte character (emoji) straddling the cut -- a 2-byte char alone
	// does not prove the fix handles every multibyte width.
	// =========================================================================

	public function test_row13_dnsbl_hostname_truncation_keeps_4byte_emoji_whole(): void
	{
		$srcIp = '10.1.0.14';
		$value = $this->mbStraddle(24, 'R13', "\u{1F600}", 'trailing-host.example');
		$GLOBALS['local_hosts'] = [$srcIp => $value];
		$fields = $this->dnsblFields('benign-domain-14.example', $srcIp, 'Grp14', 'Feed14');

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString('R13', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html, 'a byte-based cut dangles mid-emoji (4 bytes) and renders substituted');
		$this->assertStringContainsString("\u{1F600}", $html, 'the whole 4-byte emoji must survive the cut');
	}

	// =========================================================================
	// Row 14: invalid UTF-8 byte before the cut -- the #1814 contract (invalid byte
	// substituted with U+FFFD, never blanked/fabricated) must survive truncation.
	// =========================================================================

	/**
	 * A raw 0xFF byte (never valid in any UTF-8 sequence) sitting inside the
	 * truncated prefix must still render as U+FFFD -- the exact symbol pfb_hsc()'s
	 * ENT_SUBSTITUTE produces for it elsewhere (issue #1814) -- and must NEVER
	 * render as a literal '?': mb_substr()'s own default substitute character
	 * would otherwise fabricate a character the input never carried, before
	 * pfb_hsc() ever sees the string. pfb_truncate() pins
	 * mb_substitute_character(0xFFFD) around its mb_substr() call for exactly this
	 * reason.
	 */
	public function test_row14_dnsbl_agent_field_invalid_byte_before_cut_renders_fffd_not_a_fabricated_question_mark(): void
	{
		$agent  = 'R14Agent' . "\xFF" . str_repeat('a', 30) . '.trailing-tail';
		$fields = $this->dnsblFields('benign-domain-15.example', '10.1.0.15', 'Grp15', 'Feed15', $agent);

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString('<small>...</small>', $html, 'the value must actually be truncated');
		$this->assertStringContainsString('R14Agent', $html, 'the text before the invalid byte must survive');
		$this->assertStringContainsString('aaaaaaaaaaaaaaa', $html, 'the text after the invalid byte must survive (not blanked)');
		// Anchored with the immediately-following ellipsis marker so this checks ONLY the
		// DISPLAYED (truncated) span text, never the title="" attribute (which carries the
		// FULL, untruncated value and legitimately shows this same U+FFFD substitution
		// regardless -- pfb_hsc() alone, unaffected by truncation).
		$this->assertStringContainsString(
			'R14Agent' . "\u{FFFD}" . 'aaaaaaaaaaaaaaa<small>...</small>',
			$html,
			'the invalid byte inside the truncated prefix must render substituted as U+FFFD (issue #1814 contract), not silently dropped'
		);
		$this->assertStringNotContainsString(
			'R14Agent?aaaaaaaaaaaaaaa<small>...</small>',
			$html,
			"the truncated span must never show a literal '?' at this position -- that character was NOT in the input; "
				. 'mb_substr()\'s own default substitute character would fabricate it if pfb_truncate() did not pin '
				. 'mb_substitute_character(0xFFFD) around the cut'
		);
	}

	// =========================================================================
	// Row 15: HTML metacharacter landing exactly at the character-cut boundary --
	// the truncate-RAW-then-encode ordering (#1069) must still yield a COMPLETE
	// entity, never a split "&qu".
	// =========================================================================

	public function test_row15_dnsreply_resolved_value_truncation_keeps_html_entity_complete(): void
	{
		$srcIp = '10.1.0.16';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$fields    = $this->replyFields('reply-domain-16.example', $srcIp);
		$fields[8] = $this->doubleMbStraddle(16, 'R15', 'é', '"', 'trailing-tail-suffix');

		$html = $this->renderReplyRow($fields);

		$this->assertStringContainsString('R15', $html);
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html, 'the earlier straddling multibyte char must not dangle');
		$this->assertStringContainsString('éé', $html, 'both multibyte characters ahead of the metacharacter must survive intact');
		$this->assertStringContainsString('&quot;', $html, 'the HTML metacharacter at the character-cut boundary must render as a COMPLETE entity');
		$this->assertStringNotContainsString('&qu<', $html, 'the entity must never be split mid-sequence');
	}

	// =========================================================================
	// Row 16: punycode/xn-- domain whose idn_to_utf8()-produced text (appended in
	// brackets by convert_dnsbl_log() just before the cut) is what straddles the
	// cut, not the raw ASCII label.
	// =========================================================================

	public function test_row16_dnsbl_idn_domain_conversion_truncation_keeps_multibyte_char_whole(): void
	{
		// idn_to_utf8('xn--e1aybc') => 'тест' (Cyrillic, 2 bytes/char); the leading
		// 15-char ASCII label positions the appended bracketed conversion so its
		// SECOND Cyrillic character's lead byte lands exactly on the cut.
		$domain = 'R16' . str_repeat('a', 12) . '.xn--e1aybc.example';
		$fields = $this->dnsblFields($domain, '10.1.0.17', 'Grp17', 'Feed17');

		$html = $this->renderDnsblRow($fields);

		$this->assertStringContainsString('xn--e1aybc', $html, 'the raw punycode label must still render before the appended bracket');
		$this->assertStringContainsString('<small>...</small>', $html);
		$this->assertStringNotContainsString("\u{FFFD}", $html, 'the idn_to_utf8()-produced text must not dangle at the cut');
		$this->assertStringContainsString('тест', $html, 'the whole IDN-converted Cyrillic word must survive the cut');
	}

	// =========================================================================
	// Rows 17-19: Unified-view narrow-width arms. Values stay below the Reports
	// gates so a still-wide implementation renders them verbatim.
	// =========================================================================

	public function test_row17_unified_dnsbl_domain_uses_narrow_truncation_width(): void
	{
		$domain = 'R17' . str_repeat('a', 36) . 'TAIL';
		$expected = 'R17' . str_repeat('a', 36);
		$this->assertGreaterThanOrEqual(40, strlen($domain));
		$this->assertLessThan(60, strlen($domain));
		$fields = $this->dnsblFields($domain, '10.1.0.20', 'Grp17', 'Feed17');

		$html = $this->renderDnsblRow($fields, 'Unified');

		$this->assertStringContainsString("<td>{$expected}<small>...</small></td>", $html);
		$this->assertStringNotContainsString("<td>{$domain}</td>", $html);
	}

	public function test_row18_unified_dnsbl_cname_uses_narrow_truncation_width(): void
	{
		$cname = 'R18' . str_repeat('b', 28) . 'TAIL';
		$expected = 'R18' . str_repeat('b', 28);
		$this->assertGreaterThanOrEqual(32, strlen($cname));
		$this->assertLessThan(52, strlen($cname));
		$fields = $this->dnsblFields(
			'blocked-domain-18.example',
			'10.1.0.21',
			'Grp18',
			'Feed18',
			'',
			'DNSBL_CNAME',
			$cname
		);

		$html = $this->renderDnsblRow($fields, 'Unified');

		$this->assertStringContainsString("CNAME: {$expected}<small>...</small>", $html);
		$this->assertStringNotContainsString("CNAME: {$cname}", $html);
	}

	public function test_row19_unified_dnsreply_domain_uses_narrow_truncation_width(): void
	{
		$domain = 'R19' . str_repeat('c', 26) . 'TAIL';
		$expected = 'R19' . str_repeat('c', 26);
		$this->assertGreaterThanOrEqual(30, strlen($domain));
		$this->assertLessThan(45, strlen($domain));
		$srcIp = '10.1.0.22';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$fields = $this->replyFields($domain, $srcIp);

		$html = $this->renderReplyRow($fields, 'Unified');

		$this->assertStringContainsString("<td title=\"{$domain}\">{$expected}<small>...</small></td>", $html);
		$this->assertStringNotContainsString("<td title=\"{$domain}\">{$domain}</td>", $html);
	}

	// =========================================================================
	// Character-count gates: byte length reaches each gate while code-point
	// length stays below it, so no display ellipsis is justified.
	// =========================================================================

	public function test_character_gate_dnsbl_srcip_hostname_renders_complete_value(): void
	{
		$srcIp = '10.1.0.31';
		$value = $this->characterGateValue(25, 'CG01');
		$GLOBALS['local_hosts'] = [$srcIp => $value];
		$html = $this->renderDnsblRow($this->dnsblFields('cg-domain-01.example', $srcIp, 'CG', 'Feed'));
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString("<span title=\"\">{$escaped}</span>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_dnsbl_domain_renders_complete_value(): void
	{
		$value = $this->characterGateValue(40, 'CG02');
		$html = $this->renderDnsblRow(
			$this->dnsblFields($value, '10.1.0.32', 'CG', 'Feed'),
			'Unified'
		);
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString("<td>{$escaped}</td>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_dnsbl_cname_renders_complete_value(): void
	{
		$value = $this->characterGateValue(32, 'CG03');
		$fields = $this->dnsblFields('cg-domain-03.example', '10.1.0.33', 'CG', 'Feed', '', 'DNSBL_CNAME', $value);
		$html = $this->renderDnsblRow($fields, 'Unified');
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString("CNAME: {$escaped}</td>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_dnsbl_agent_renders_complete_value(): void
	{
		$value = $this->characterGateValue(25, 'CG04');
		$html = $this->renderDnsblRow($this->dnsblFields('cg-domain-04.example', '10.1.0.34', 'CG', 'Feed', $value));
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString("<br /><small>DNSBL-python | {$escaped} | A</small>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_dnsreply_srcip_hostname_renders_complete_value(): void
	{
		$srcIp = '10.1.0.35';
		$value = $this->characterGateValue(25, 'CG05');
		$GLOBALS['local_hosts'] = [$srcIp => $value];
		$html = $this->renderReplyRow($this->replyFields('cg-domain-05.example', $srcIp));
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString("<td title=\"\">{$srcIp}<br /><small>{$escaped}</small></td>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_dnsreply_ttl_renders_complete_value(): void
	{
		$srcIp = '10.1.0.36';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$fields = $this->replyFields('cg-domain-06.example', $srcIp);
		$fields[5] = $this->characterGateValue(6, 'CG');
		$html = $this->renderReplyRow($fields);
		$escaped = pfb_hsc($fields[5]);

		$this->assertStringContainsString("<td title=\"\">{$escaped}</td>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_dnsreply_domain_renders_complete_value(): void
	{
		$srcIp = '10.1.0.37';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$value = $this->characterGateValue(30, 'CG07');
		$html = $this->renderReplyRow($this->replyFields($value, $srcIp), 'Unified');
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString("<td title=\"\">{$escaped}</td>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_dnsreply_resolved_value_renders_complete_value(): void
	{
		$srcIp = '10.1.0.38';
		$GLOBALS['local_hosts'] = [$srcIp => ''];
		$fields = $this->replyFields('cg-domain-08.example', $srcIp);
		$fields[8] = $this->characterGateValue(17, 'CG08');
		$html = $this->renderReplyRow($fields);
		$escaped = pfb_hsc($fields[8]);

		$this->assertStringContainsString("<td title=\"\">{$escaped}</td>", $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_ip_logged_feed_renders_complete_value(): void
	{
		$value = $this->characterGateValue(17, 'CG09');
		file_put_contents("{$this->denydir}/{$value}.txt", "192.0.2.190\n");
		$fields = $this->ipRawFields([
			8 => '192.0.2.190', 15 => '192.0.2.190',
			14 => 'pfB_CG09_v4', 16 => $value,
		]);
		$html = $this->renderIpRow($fields, 'Block');
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString($escaped . '<br /><small>', $html);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	public function test_character_gate_ip_re_attributed_feed_renders_complete_value(): void
	{
		$value = $this->characterGateValue(17, 'CG10');
		file_put_contents("{$this->denydir}/{$value}.txt", "192.0.2.191\n");
		$oldFeed = 'CG10Old';
		$fields = $this->ipRawFields([
			8 => '192.0.2.191', 15 => '192.0.2.191',
			14 => 'pfB_CG10_v4', 16 => $oldFeed,
		]);
		$html = $this->renderIpRow($fields, 'Block');
		$escaped = pfb_hsc($value);

		$this->assertStringContainsString(
			"<s>{$oldFeed}</s><br /><small><s>192.0.2.191</s></small><br />{$escaped}<br /><small>",
			$html
		);
		$this->assertStringNotContainsString($escaped . '<small>...</small>', $html);
	}

	// =========================================================================
	// State restoration: pfb_truncate() pins mb_substitute_character(0xFFFD)
	// around its mb_substr() call -- mb_substitute_character()
	// is REQUEST-GLOBAL state, so a row render must never leave it changed for
	// whatever renders next on the same page load.
	// =========================================================================

	public function test_truncation_sites_restore_prior_mb_substitute_character_across_all_three_builders(): void
	{
		// A conspicuously non-default sentinel: if pfb_truncate() ever failed to
		// restore this, every OTHER render in the same request would silently start
		// substituting invalid bytes with 'Z' instead of the caller's own setting.
		$sentinel = ord('Z');
		$original = mb_substitute_character();

		try {
			$cases = [
				'convert_dnsbl_log' => function (): string {
					$fields = $this->dnsblFields(
						str_repeat('a', 70) . 'é' . 'trailing-domain.example',
						'10.1.0.18', 'GrpRestore', 'FeedRestore'
					);
					return $this->renderDnsblRow($fields);
				},
				'convert_dns_reply_log' => function (): string {
					$srcIp = '10.1.0.19';
					$GLOBALS['local_hosts'] = [$srcIp => ''];
					$fields = $this->replyFields(str_repeat('a', 50) . 'é' . 'trailing-domain.example', $srcIp);
					return $this->renderReplyRow($fields);
				},
				'convert_ip_log' => function (): string {
					$fields = $this->ipRawFields([
						8 => '192.0.2.130', 15 => '192.0.2.130',
						14 => 'pfB_RowRestore_v4', 16 => str_repeat('a', 20) . 'é' . 'trailing-feed',
					]);
					return $this->renderIpRow($fields, 'Block');
				},
			];

			foreach ($cases as $builder => $render) {
				mb_substitute_character($sentinel);
				$html = $render();

				$this->assertNotSame('', $html, "fixture sanity: {$builder} must actually render a row");
				$this->assertSame(
					$sentinel,
					mb_substitute_character(),
					"pfb_truncate() must restore mb_substitute_character() to its caller's prior value -- "
						. "a {$builder} row render leaked a changed request-global substitute-character state"
				);
			}
		} finally {
			// Never leak a changed global state to sibling tests in this same process.
			mb_substitute_character($original);
		}
	}

	/**
	 * The pinned substitute character is restored even when the truncation itself
	 * throws. pfb_truncate() casts $value to string INSIDE the pinned region, so an
	 * object with no __toString() raises after the pin and before any ordinary
	 * return -- without the finally, the caller's setting stays clobbered for the
	 * rest of the request and every later render silently substitutes the wrong
	 * symbol.
	 */
	public function test_pfb_truncate_restores_substitute_character_when_the_cut_throws(): void
	{
		$sentinel = ord('Z');
		$original = mb_substitute_character();

		try {
			mb_substitute_character($sentinel);

			$threw = FALSE;
			try {
				pfb_truncate(new stdClass(), 10);
			} catch (Throwable $e) {
				$threw = TRUE;
			}

			$this->assertTrue($threw, 'fixture sanity: casting a stdClass to string must raise, or this proves nothing');
			$this->assertSame(
				$sentinel,
				mb_substitute_character(),
				'pfb_truncate() must restore mb_substitute_character() on the throwing path too, '
					. 'not just on a normal return'
			);
		} finally {
			mb_substitute_character($original);
		}
	}
}
