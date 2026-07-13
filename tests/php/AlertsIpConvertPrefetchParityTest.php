<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end producer<->consumer parity for the issue #809 Phase 3b Alerts IP-table
 * prefetch (PR #825 review nitpick T3): IpPrefetchTest.php pins pfb_ip_prefetch() and
 * its helpers in isolation, but nothing drives convert_ip_log() itself (the page
 * consumer) to prove the batched producer and the per-row consumer actually agree on
 * the memo keys -- a wrong validate/miss key would either silently discard the
 * prefetch (falling back to per-row exec, still correct but unbatched) or, worse,
 * hand convert_ip_log() the WRONG cached value for a different row.
 *
 * Feature: pfb_ip_prefetch()'s seeded memos are consumed by convert_ip_log() through
 *          the exact same keys, so a render is byte-identical whether or not the
 *          batched prefetch ran first
 *
 *   Scenario: for every reported-IP shape convert_ip_log() renders, seeding
 *             pfb_ip_render_memos() via pfb_ip_prefetch() (as the page's Pass 1.5
 *             does) and then rendering must produce IDENTICAL output to resetting the
 *             memos (forcing convert_ip_log()'s own per-row exec fallback) and
 *             rendering again -- that parity IS the contract PR #825 claims.
 *
 * Every case drives REAL fixture files on disk through REAL find/grep exec() calls
 * (no mocking of the lookup layer) -- exactly the boundary IpPrefetchTest itself
 * uses -- so a real command-shape or key-derivation regression shows up as a genuine
 * mismatch, not a mocked-away no-op.
 */
#[CoversFunction('convert_ip_log')]
#[CoversFunction('pfb_ip_prefetch')]
#[CoversFunction('pfb_ip_render_query')]
#[CoversFunction('pfb_ip_render_memos')]
#[CoversFunction('pfb_ip_render_memos_reset')]
#[CoversFunction('pfb_render_memo')]
final class AlertsIpConvertPrefetchParityTest extends TestCase
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
		// See AlertsPageLoader.php for the off-appliance load mechanics (shared with
		// WhitelistTrashIconTest / AlertsRowOutputEncodingTest).
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach ([
			'pfb', 'continents', 'filterfieldsarray', 'clists', 'ip_unlock', 'counter',
			'pfbentries', 'skipcount', 'dup', 'ipfilterlimit', 'ipfilterlimitentries',
		] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}

		$this->tmpDir    = sys_get_temp_dir() . '/pfb_ip_convert_parity_' . bin2hex(random_bytes(6));
		$this->denydir   = "{$this->tmpDir}/deny";
		$this->nativedir = "{$this->tmpDir}/native";
		$this->ccdir     = "{$this->tmpDir}/geoip";
		$this->etdir     = "{$this->tmpDir}/et";
		$this->aliasdir  = "{$this->tmpDir}/alias";
		$this->matchdir  = "{$this->tmpDir}/match";
		// issue #1250: a real subdirectory of matchdir (mirrors production -- matchdir
		// nests matchgendir on-disk), distinct enough to prove the 'match' folder
		// derivation names BOTH, not just one.
		$this->matchgendir = "{$this->matchdir}/generated";
		foreach ([
			$this->denydir, $this->nativedir, $this->ccdir, $this->etdir, $this->aliasdir,
			$this->matchdir, $this->matchgendir,
		] as $d) {
			mkdir($d, 0777, TRUE);
		}
		// Keeps nativedir/matchdir/matchgendir non-empty (avoids the shell literal-glob
		// edge case on an otherwise-empty dir); mirrors IpPrefetchTest's
		// fixtures/ip_prefetch/native. Every 'match'-action case below adds its own file
		// to ONE of matchdir/matchgendir, leaving the other empty otherwise.
		file_put_contents("{$this->nativedir}/NativePlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchdir}/MatchPlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchgendir}/MatchGenPlaceholder.txt", "placeholder\n");
		// ccdir/etdir/aliasdir each need a SECOND, non-matching file: grep only
		// prefixes a matched line with "path:" when >1 file is searched, and
		// find_reported_header()'s pfb_parse_query() (feed/alias name split) and
		// convert_ip_log()'s own alias-name ltrim/strrchr/strstr chain both depend on
		// that "path:content" shape. A lone-file dir would silently break the parse
		// for cases E/G/H regardless of prefetch -- not what this test is about.
		file_put_contents("{$this->ccdir}/OtherRegionPlaceholder.txt", "10.0.0.1\n");
		file_put_contents("{$this->etdir}/EtPlaceholder.txt", "10.0.0.2\n");
		file_put_contents("{$this->aliasdir}/AliasPlaceholder.txt", "10.0.0.3\n");

		$GLOBALS['pfb'] = [
			'grep'             => '/usr/bin/grep',
			'denydir'          => $this->denydir,
			'nativedir'        => $this->nativedir,
			'permitdir'        => "{$this->tmpDir}/permit",	// unused by these cases (Action is 'block' or 'match')
			'matchdir'         => $this->matchdir,
			'matchgendir'      => $this->matchgendir,
			'etdir'            => $this->etdir,
			'ccdir'            => $this->ccdir,
			'aliasdir'         => $this->aliasdir,
			'filterlogentries' => FALSE,
			'asn_reporting'    => 'disabled',
			'supp'             => '',	// PfbToggle::Off -- suppression-list lookup skipped
		];
		// Same continents registry pfblockerng_alerts.php builds (array_flip of the
		// GeoIP continent alias basenames); pfb_ip_render_query() checks
		// isset($continents[substr($fields[13], 0, -3)]) to detect a GeoIP row.
		$GLOBALS['continents'] = array_flip(array(
			'pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe',
			'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top',
		));
		$GLOBALS['filterfieldsarray'] = [];
		// Empty (falsy) whitelist arrays -- pfb_whitelist_trash_icon() takes its
		// documented "no whitelist configured" NULL branch either way, identically in
		// both renders; irrelevant to the memo/prefetch surface under test.
		$GLOBALS['clists']              = ['ipwhitelist4' => [], 'ipwhitelist6' => []];
		$GLOBALS['ip_unlock']           = [];
		$GLOBALS['counter']             = ['Block' => 0];
		$GLOBALS['pfbentries']          = 1000;
		$GLOBALS['skipcount']           = 0;
		$GLOBALS['dup']                 = ['Block' => 0];
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

		// rmdir_recursive() is the bootstrap-loaded pfsense_doubles.php double for
		// pfSense's util.inc function of the same name (tests/php/pfsense_doubles.php:195).
		rmdir_recursive($this->tmpDir);
	}

	/**
	 * Build a raw, PRE-reorder $fields row -- the exact shape the page's log reader
	 * delivers to convert_ip_log() (after popping the trailing dup marker, BEFORE the
	 * function's own `$fields[99] = array_shift($fields);` timestamp reorder). Layout
	 * per convert_ip_log()'s own "(Removed and re-ordered)" + "(Final $fields array
	 * reference)" doc comment: index 0 is the timestamp that gets shifted out, and
	 * every field from convert_ip_log()'s reference list follows shifted up by one.
	 */
	private function rawFields(array $overrides): array
	{
		$base = [
			0  => '2026-07-04 00:00:00',	// Date/Timestamp
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
			14 => 'pfB_Default_v4',		// IP Alias Name
			15 => '192.0.2.11',		// IP evaluated
			16 => 'DefaultFeed',		// Feed Name
			17 => '',			// gethostbyaddr resolved hostname
			18 => '',			// Client Hostname
			19 => 'Unknown',		// ASN
		];
		return array_replace($base, $overrides);
	}

	/**
	 * Build the SAME prefetch-row shape pfblockerng_alerts.php's Pass 1.5 builds
	 * (pfblockerng_alerts.php, the $ip_prefetch_rows loop) from a RAW pre-reorder
	 * $fields row: a page-copy reorder, then pfb_ip_render_query() -- the identical
	 * derivation convert_ip_log() itself runs on its own copy.
	 */
	private function prefetchRowFor(array $rawFields): array
	{
		$copy = $rawFields;
		$copy[99] = array_shift($copy);
		$rq = pfb_ip_render_query($copy);

		return [
			'host'              => $rq['host'],
			'folder'            => $rq['folder'],
			'validate_file_cmd' => $rq['validate_file_cmd'],
			'validate_cmd'      => $rq['validate_cmd'],
			'eval_ip_raw'       => $copy[14],
		];
	}

	/**
	 * Render one row via the real page function, capturing its printed HTML.
	 *
	 * @return array{0: array{0: bool, 1: string}, 1: string} [convert_ip_log() return, captured HTML]
	 */
	private function render(array $rawFields, string $rtype): array
	{
		// Reset the render-bookkeeping globals convert_ip_log() mutates as a side
		// effect ($dup[$rtype] read-then-zeroed, $counter[$rtype]++, $ipfilterlimit
		// settable once the counter trips $pfbentries) so every call -- seeded or
		// cold -- starts from the identical baseline; only the memo store differs.
		$GLOBALS['dup'][$rtype]     = 0;
		$GLOBALS['counter'][$rtype] = 0;
		$GLOBALS['ipfilterlimit']   = FALSE;

		ob_start();
		$ret = convert_ip_log('non_unified', $rawFields, '', $rtype);
		$html = (string) ob_get_clean();

		return [$ret, $html];
	}

	/**
	 * Given/When/Then core shared by every scenario below: prefetch-seed then render,
	 * reset-then-render cold, and assert the two renders are byte-identical.
	 *
	 * @return string the (identical) rendered HTML -- callers needing to assert its
	 *                 CONTENT (not just that both renders agree) reuse this instead of
	 *                 re-driving convert_ip_log() themselves.
	 */
	private function assertParity(array $fields, string $rtype, string $scenario): string
	{
		// Given: the batched prefetch pass seeds pfb_ip_render_memos() from the SAME
		// row-derivation the page's Pass 1.5 uses.
		pfb_ip_render_memos_reset();
		$row = $this->prefetchRowFor($fields);
		pfb_ip_prefetch([$row]);

		$seededMemos = &pfb_ip_render_memos();

		// Guard against a vacuous pass: prove the EXACT key convert_ip_log() will
		// consult was actually seeded by this prefetch call -- the producer<->consumer
		// memo-key wiring itself -- not merely that the store is non-empty.
		$this->assertArrayHasKey(
			$row['validate_cmd'],
			$seededMemos['validate'],
			"[{$scenario}] expected pfb_ip_prefetch() to seed the exact validate_cmd key "
				. "convert_ip_log() will look up: " . var_export($row['validate_cmd'], TRUE)
		);

		// When: convert_ip_log() renders while the prefetch memos are seeded.
		[$retSeeded, $htmlSeeded] = $this->render($fields, $rtype);

		// Given: a COLD render -- the memo store reset, so convert_ip_log() must take
		// its own per-row exec fallback for every lookup this row needs.
		pfb_ip_render_memos_reset();
		$coldMemos = &pfb_ip_render_memos();
		$this->assertSame(
			['validate' => [], 'miss' => []],
			$coldMemos,
			"[{$scenario}] expected a genuinely empty memo store before the cold render, "
				. 'guarding against a leaked seed from the prefetch pass above'
		);

		// When: convert_ip_log() renders again, cold.
		[$retCold, $htmlCold] = $this->render($fields, $rtype);

		// Then: the prefetch-seeded render and the cold per-row render are IDENTICAL --
		// this parity IS the contract PR #825 claims (review nitpick T3).
		$this->assertSame(
			$retCold,
			$retSeeded,
			"[{$scenario}] expected the convert_ip_log() return value to match between the "
				. 'prefetch-seeded and cold render, got seeded=' . var_export($retSeeded, TRUE)
				. ', cold=' . var_export($retCold, TRUE)
		);
		$this->assertSame(
			$htmlCold,
			$htmlSeeded,
			"[{$scenario}] expected the rendered HTML to be IDENTICAL between the prefetch-seeded "
				. "and cold render.\n--- cold (expected) ---\n{$htmlCold}\n"
				. "--- prefetch-seeded (actual) ---\n{$htmlSeeded}"
		);

		return $htmlCold;
	}

	/**
	 * Case 1 -- still-listed: the reported IP is still an exact line in its logged
	 * feed file, so the VALIDATE round hits directly (no miss round runs at all).
	 */
	public function test_still_listed_v4_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->denydir}/DenyFeedA.txt", "192.0.2.11\n");

		$fields = $this->rawFields([
			8 => '192.0.2.11', 15 => '192.0.2.11',
			14 => 'pfB_StillListed_v4', 16 => 'DenyFeedA',
		]);

		$this->assertParity($fields, 'Block', 'still-listed v4');
	}

	/**
	 * Case 2 -- de-listed: nothing anywhere (its old feed file, or any other) still
	 * mentions this IP -- a genuine total miss ('Unknown'/'Unknown' -> 'Not listed!').
	 */
	public function test_delisted_v4_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->denydir}/DenyFeedB.txt", "198.51.100.250\n");

		$fields = $this->rawFields([
			8 => '198.51.100.20', 15 => '198.51.100.20',
			14 => 'pfB_Delisted_v4', 16 => 'DenyFeedB',
		]);

		$this->assertParity($fields, 'Block', 'de-listed v4');
	}

	/**
	 * Case 3 -- moved-feed: the logged feed (DenyFeedOldC, deliberately absent) no
	 * longer covers this host; the exact SAME IP now lives, verbatim, in a different
	 * feed file within the same folder glob.
	 */
	public function test_moved_feed_v4_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->denydir}/DenyFeedNewC.txt", "192.0.2.50\n");

		$fields = $this->rawFields([
			8 => '192.0.2.50', 15 => '192.0.2.50',
			14 => 'pfB_SameAlias_v4', 16 => 'DenyFeedOldC',
		]);

		$this->assertParity($fields, 'Block', 'moved feed v4');
	}

	/**
	 * Case 4 -- CIDR containment: the feed holds a /24, the reported host is a single
	 * address inside it -- exercises pfb_match_reported_cidr()'s v4 mask-math branch
	 * end-to-end (not just the direct exact-match round).
	 */
	public function test_cidr_containment_v4_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->denydir}/DenyFeedCidrD.txt", "203.0.113.0/24\n");

		$fields = $this->rawFields([
			8 => '203.0.113.55', 15 => '203.0.113.55',
			14 => 'pfB_CidrAlias_v4', 16 => 'DenyFeedCidrD',
		]);

		$this->assertParity($fields, 'Block', 'CIDR containment v4');
	}

	/**
	 * Case 5 -- GeoIP row: the IP Alias Name is a continent alias (pfB_Top_v4), which
	 * routes the lookup folder to $pfb['ccdir'] instead of deny/native -- exercises the
	 * GeoIP folder-derivation branch of pfb_ip_render_query() end-to-end.
	 */
	public function test_geoip_row_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->ccdir}/pfB_Top.txt", "198.51.100.90\n");

		$fields = $this->rawFields([
			8 => '198.51.100.90', 15 => '198.51.100.90',
			14 => 'pfB_Top_v4', 16 => 'CountryFeedOld',
		]);

		$this->assertParity($fields, 'Block', 'GeoIP row');
	}

	/**
	 * Case 6 -- IPv6 still-listed: same shape as case 1 (direct VALIDATE-round hit,
	 * no miss round) but over an IPv6 address/alias.
	 */
	public function test_still_listed_v6_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->denydir}/DenyFeedV6F.txt", "2001:db8:aaaa::10\n");

		$fields = $this->rawFields([
			5 => 6, 8 => '2001:db8:aaaa::10', 9 => '2001:db8:2::1',
			15 => '2001:db8:aaaa::10',
			14 => 'pfB_StillListedV6_v6', 16 => 'DenyFeedV6F',
		]);

		$this->assertParity($fields, 'Block', 'IPv6 still-listed');
	}

	/**
	 * Case 7 -- aliastable-changed: found under a NEW feed file, AND the aliastables
	 * round now attributes the IP to a DIFFERENT alias (pfB_NewAlias_v4) than the one
	 * logged at event time (pfB_OldAlias_v4) -- exercises the separate aliasdir round
	 * and its alias-name ltrim/strrchr/strstr parsing end-to-end.
	 */
	public function test_aliastable_changed_v4_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->denydir}/DenyFeedNewG.txt", "192.0.2.77\n");
		file_put_contents("{$this->aliasdir}/pfB_NewAlias_v4.txt", "192.0.2.77\n");

		$fields = $this->rawFields([
			8 => '192.0.2.77', 15 => '192.0.2.77',
			14 => 'pfB_OldAlias_v4', 16 => 'DenyFeedOldG',
		]);

		$this->assertParity($fields, 'Block', 'aliastable-changed v4');
	}

	/**
	 * Case 8 -- ET-header feed: a Proofpoint/IQRisk-style "Category:Feed" name routes
	 * the folder to $pfb['etdir'] with no filename filter (the et_header branch of
	 * pfb_ip_render_query()) -- exercises that folder derivation end-to-end.
	 */
	public function test_et_header_feed_renders_identically_prefetched_vs_cold(): void
	{
		file_put_contents("{$this->etdir}/EtFeedFile.txt", "192.0.2.201\n");

		$fields = $this->rawFields([
			8 => '192.0.2.201', 15 => '192.0.2.201',
			14 => 'pfB_ET_v4', 16 => 'IQRisk:Category1',
		]);

		$this->assertParity($fields, 'Block', 'ET-header feed');
	}

	/**
	 * Case 9 -- aliastable-changed, TRULY single-file aliasdir (issue #833).
	 *
	 * Case 7 above keeps aliasdir's setUp()-provided placeholder file precisely so
	 * grep already has >1 file and emits a "path:" prefix (see the class-level
	 * comment at setUp() explaining why that placeholder exists at all). This case
	 * removes it -- aliasdir holds ONLY the new alias's file, the exact shape issue
	 * #833 reports as broken.
	 *
	 * Given: pre-fix, `find aliasdir/*.txt | xargs grep` hands grep a single file,
	 * so its match comes back UNPREFIXED; convert_ip_log()'s alias-name parse chain
	 * (pfblockerng_alerts.php ltrim(strrchr(strstr(strstr(...))))) requires the
	 * "path:content" shape and silently collapses to '' without it -- the rendered
	 * row would show NO "moved to a new alias" cell at all, even though the IP
	 * genuinely moved.
	 * When: convert_ip_log() renders, both prefetch-seeded and cold.
	 * Then: parity holds (both paths went through the SAME now-fixed grep shape),
	 * AND the rendered HTML shows the REAL new alias name -- not a blank cell.
	 */
	public function test_aliastable_changed_single_file_aliasdir_renders_the_real_alias_name(): void
	{
		unlink("{$this->aliasdir}/AliasPlaceholder.txt");	// truly single-file aliasdir

		file_put_contents("{$this->denydir}/DenyFeedNewH.txt", "192.0.2.88\n");
		file_put_contents("{$this->aliasdir}/pfB_LoneNewAlias_v4.txt", "192.0.2.88\n");

		$fields = $this->rawFields([
			8 => '192.0.2.88', 15 => '192.0.2.88',
			14 => 'pfB_OldAlias_v4', 16 => 'DenyFeedOldH',
		]);

		$html = $this->assertParity($fields, 'Block', 'aliastable-changed, single-file aliasdir');

		// And: the rendered HTML shows the REAL new alias name, not a blank cell --
		// the actual issue #833 symptom this case targets.
		$this->assertStringContainsString(
			'pfB_LoneNewAlias_v4',
			$html,
			"expected the rendered row to show the real new alias name 'pfB_LoneNewAlias_v4', got:\n{$html}"
		);
	}

	/**
	 * Case 10 -- issue #1250: a 'match' event whose IP was relocated to a matchgendir
	 * reputation artifact (the logged feed name is the OLD one, before the relocation
	 * renamed/moved it -- same "moved feed" shape as case 3, but over the branch that
	 * was widened to search matchgendir).
	 *
	 * Given: the reported IP lives ONLY in a matchgendir artifact
	 *        (pfB_Match_Rep_Spam_v4.txt), not under the event's originally-logged feed
	 *        name.
	 * When: convert_ip_log() renders the 'match' event, both prefetch-seeded and cold.
	 * Then: parity holds, AND the rendered HTML attributes the event to the real
	 *       matchgendir feed -- not "Not listed!" (which is what a folder derivation
	 *       missing matchgendir would render).
	 */
	public function test_match_event_reputation_artifact_in_matchgendir_attributes_to_that_feed(): void
	{
		file_put_contents("{$this->matchgendir}/pfB_Match_Rep_Spam_v4.txt", "192.0.2.60\n");

		$fields = $this->rawFields([
			4 => 'match', 8 => '192.0.2.60', 15 => '192.0.2.60',
			14 => 'pfB_OldMatchAlias_v4', 16 => 'MatchFeedOldSpam',
		]);

		$html = $this->assertParity($fields, 'Match', 'match event, reputation artifact relocated to matchgendir');

		$this->assertStringContainsString(
			'pfB_Match_Rep_Spam_v4',
			$html,
			"expected the rendered row to attribute this match event to the matchgendir feed "
				. "'pfB_Match_Rep_Spam_v4' (issue #1250), got:\n{$html}"
		);
	}

	/**
	 * Case 11 -- issue #1250: a 'match' event caused by a user-chosen Match-list still
	 * attributes correctly -- the widening that added matchgendir must not have
	 * regressed the pre-existing matchdir half of the branch (same "still-listed"
	 * shape as case 1).
	 *
	 * Given: the reported IP is still an exact line in its logged user Match-list file
	 *        (Ads_v4.txt), which stays in matchdir (never relocated).
	 * When: convert_ip_log() renders the 'match' event, both prefetch-seeded and cold.
	 * Then: parity holds, AND the rendered HTML still attributes to the logged feed.
	 */
	public function test_match_event_user_list_in_matchdir_still_attributes_to_that_feed(): void
	{
		file_put_contents("{$this->matchdir}/Ads_v4.txt", "198.51.100.77\n");

		$fields = $this->rawFields([
			4 => 'match', 8 => '198.51.100.77', 15 => '198.51.100.77',
			14 => 'pfB_Ads_v4', 16 => 'Ads_v4',
		]);

		$html = $this->assertParity($fields, 'Match', 'match event, user Match-list in matchdir');

		$this->assertStringContainsString(
			'Ads_v4',
			$html,
			"expected the rendered row to still attribute this match event to the matchdir feed "
				. "'Ads_v4', got:\n{$html}"
		);
	}
}
