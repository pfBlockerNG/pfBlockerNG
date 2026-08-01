<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1792 sweep — site-level pins over the REAL statements (evaled out of
 * the www pages by Issue1792SweepSiteLoader.php), one representative per
 * defect family the sweep fixes:
 *
 *  1. `explode(',', $x ?? '') ?: $default` — the elvis arm is UNREACHABLE
 *     (explode() on a string subject is always truthy), so an empty scalar
 *     yielded [''] and an intended non-empty default NEVER applied.
 *  2. `base64_decode($x ?? '') ?: ''` — the arm eats a stored "0"
 *     (base64_decode('MA==') === '0', falsy) along with the FALSE it guards.
 *  3. `($data[1] ?? '') ?: $unknown_msg` — a stat label of literally '0'
 *     renders as "Unknown".
 *  4. `($l[1] ?? '') ?: ($e[1] ?? '')` — a category translation of literally
 *     '0' falls back to EN (the EMPTY-translation → EN fallback is
 *     load-bearing and must survive, pinned here too).
 *
 * Red against the pre-sweep sites, green after they move onto
 * pfb_csv_list()/pfb_b64_text()/pfb_is_empty() — zero test edits either side.
 */
#[CoversNothing]
final class Issue1792SweepSitesTest extends TestCase
{
	private const DNSBL_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
	private const IP_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_ip.php';
	private const ALERTS_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_alerts.php';
	private const BLACKLIST_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_blacklist.php';

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/Issue1792SweepSiteLoader.php';
	}

	// --- family 1: csv list with an intended (but dead) non-empty default --

	public function testEmptyGtldConfigYieldsTheIntendedDefaultTlds(): void
	{
		$default_tlds = ['com', 'net', 'org'];
		$out = pfb_test_1792_eval_site(self::DNSBL_PAGE, "\$pconfig['tld_allow_gtld']", [
			'pfb'          => ['dconfig' => []],
			'pconfig'      => [],
			'default_tlds' => $default_tlds,
		]);
		$this->assertSame($default_tlds, $out['pconfig']['tld_allow_gtld'],
			'an absent tld_allow_gtld scalar must yield the intended default TLD set, never [\'\']');
	}

	public function testEmptyAlexaInclusionYieldsItsInlineDefault(): void
	{
		$out = pfb_test_1792_eval_site(self::DNSBL_PAGE, "\$pconfig['top1m_inclusion']", [
			'pfb'     => ['dconfig' => ['top1m_inclusion' => '']],
			'pconfig' => [],
		]);
		$this->assertSame(['com', 'net', 'org', 'ca', 'co', 'io'], $out['pconfig']['top1m_inclusion'],
			'an empty top1m_inclusion scalar must yield the inline default list, never [\'\']');
	}

	// --- family 1b: csv list whose downstream wants "no entries" -----------

	public function testEmptyInboundInterfaceYieldsNoEntries(): void
	{
		$out = pfb_test_1792_eval_site(self::IP_PAGE, "\$pconfig['inbound_interface']", [
			'pfb'     => ['iconfig' => []],
			'pconfig' => [],
		]);
		$this->assertSame([], $out['pconfig']['inbound_interface'],
			'an absent inbound_interface scalar must yield NO entries, not the phantom [\'\']');
	}

	public function testZeroIsARealCsvEntryNotAnAbsence(): void
	{
		$out = pfb_test_1792_eval_site(self::IP_PAGE, "\$pconfig['inbound_interface']", [
			'pfb'     => ['iconfig' => ['inbound_interface' => '0']],
			'pconfig' => [],
		]);
		$this->assertSame(['0'], $out['pconfig']['inbound_interface']);
	}

	// --- family 2: base64 text field eats a stored "0" ---------------------

	public function testStoredZeroWhitelistSurvivesToTheForm(): void
	{
		$out = pfb_test_1792_eval_site(self::DNSBL_PAGE, "\$pconfig['whitelist']", [
			'pfb'     => ['dconfig' => ['whitelist' => base64_encode('0')]],
			'pconfig' => [],
		]);
		$this->assertSame('0', $out['pconfig']['whitelist'],
			'a whitelist textarea holding exactly "0" must re-render as "0", not empty');
	}

	public function testAbsentWhitelistStillRendersEmpty(): void
	{
		$out = pfb_test_1792_eval_site(self::DNSBL_PAGE, "\$pconfig['whitelist']", [
			'pfb'     => ['dconfig' => []],
			'pconfig' => [],
		]);
		$this->assertSame('', $out['pconfig']['whitelist']);
	}

	// --- family 3: alerts stat label '0' reads as "Unknown" ----------------

	public function testZeroStatLabelIsNotUnknown(): void
	{
		$out = pfb_test_1792_eval_site(self::ALERTS_PAGE, '$alert_stats[$alert_view][$stat_type][', [
			'alert_stats' => [],
			'alert_view'  => 'ip_block_stat',
			'stat_type'   => 'interface',
			'data'        => ['3', '0'],
			'unknown_msg' => 'Unknown',
		]);
		$stats = $out['alert_stats']['ip_block_stat']['interface'];
		$this->assertArrayHasKey('0', $stats,
			'a stat label of literally "0" must key as "0", never collapse into "Unknown"');
		$this->assertArrayNotHasKey('Unknown', $stats);
		$this->assertSame(3, (int) $stats['0']);
	}

	public function testEmptyStatLabelStillReadsUnknown(): void
	{
		$out = pfb_test_1792_eval_site(self::ALERTS_PAGE, '$alert_stats[$alert_view][$stat_type][', [
			'alert_stats' => [],
			'alert_view'  => 'ip_block_stat',
			'stat_type'   => 'interface',
			'data'        => ['3'],
			'unknown_msg' => 'Unknown',
		]);
		$this->assertArrayHasKey('Unknown', $out['alert_stats']['ip_block_stat']['interface'],
			'the load-bearing empty-label -> "Unknown" fallback must survive the sweep');
	}

	// --- family 4: blacklist category translation '0' falls back to EN -----

	public function testZeroCategoryTranslationSurvives(): void
	{
		$out = pfb_test_1792_eval_site(self::BLACKLIST_PAGE, '$category_lang = ', [
			'l' => ['cat_key', '0'],
			'e' => ['cat_key', 'English name'],
		]);
		$this->assertSame('0', $out['category_lang'],
			'a category translation of literally "0" is a real translation, not an absence');
	}

	public function testEmptyCategoryTranslationStillFallsBackToEn(): void
	{
		$out = pfb_test_1792_eval_site(self::BLACKLIST_PAGE, '$category_lang = ', [
			'l' => ['cat_key', ''],
			'e' => ['cat_key', 'English name'],
		]);
		$this->assertSame('English name', $out['category_lang'],
			'the load-bearing EMPTY-translation -> EN fallback must survive the sweep');
	}
}
