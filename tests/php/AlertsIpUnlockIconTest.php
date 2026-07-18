<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin convert_ip_log()'s Unlock/Lock icon render-eligibility gate (issue
 * #1412 -- ADR-53 parity for the Alerts page's temporary IP Unlock/Re-Lock
 * action).
 *
 * BEHAVIOUR CHANGE (#1412): before this change the gate was
 * ``$rtype == 'Block' && ($mask_suppression || $mask_unlock)`` -- both flags
 * were computed ONLY ``if ($pfb_ipv4)`` (an IPv6 Block row got neither, so
 * the icon NEVER rendered for v6) and, for v4, TRUE only for an exact /32 or
 * /24 mask, or a mask strictly narrower than /24 (any BROADER mask, e.g.
 * /16, got neither flag either). The icon's id/title also embedded
 * $eval_ip -- the feed's (possibly CIDR) matched entry -- instead of the
 * exact alerted host, and the "already unlocked" check
 * (``isset($ip_unlock[$eval_ip])``) was keyed the same wrong way.
 *
 * The gate is now ``$rtype == 'Block' && !$pfb_geoip`` -- the exact
 * eligibility the Suppression icon already uses (any family, any mask,
 * GeoIP rows excluded) -- and the icon embeds $host (the exact alerted
 * host), with $ip_unlock keyed by that same $host (matching how the
 * ip_remove handler now stores it).
 *
 * Harness mirrors AlertsIpConvertPrefetchParityTest's off-appliance load +
 * fixture-file technique (real find/grep exec() calls against a temp
 * sandbox, no mocking of the lookup layer) but drives a single render per
 * case instead of the prefetch/cold parity dance -- this file is about the
 * RENDERED MARKUP, not the prefetch producer/consumer contract.
 */
#[CoversFunction('convert_ip_log')]
final class AlertsIpUnlockIconTest extends TestCase
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
			'pfb', 'continents', 'filterfieldsarray', 'clists', 'ip_unlock', 'counter',
			'pfbentries', 'skipcount', 'dup', 'ipfilterlimit', 'ipfilterlimitentries',
		] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}

		$this->tmpDir    = sys_get_temp_dir() . '/pfb_ip_unlock_icon_' . bin2hex(random_bytes(6));
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
		// A second, non-matching file in each multi-glob dir -- same "path:" grep-prefix
		// requirement AlertsIpConvertPrefetchParityTest's setUp documents.
		file_put_contents("{$this->nativedir}/NativePlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchdir}/MatchPlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->matchgendir}/MatchGenPlaceholder.txt", "placeholder\n");
		file_put_contents("{$this->aliasdir}/AliasPlaceholder.txt", "10.0.0.3\n");

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
			'asn_reporting'    => 'disabled',
			'supp'             => '',	// PfbToggle::Off -- suppression-list lookup skipped
		];
		$GLOBALS['continents'] = array_flip(array(
			'pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe',
			'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top',
		));
		$GLOBALS['filterfieldsarray'] = [];
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

		rmdir_recursive($this->tmpDir);
	}

	/**
	 * Build a raw, PRE-reorder $fields row -- same shape/reference as
	 * AlertsIpConvertPrefetchParityTest::rawFields().
	 *
	 * issue #1369: 22 elements (0-21) -- see that file's rawFields() docblock;
	 * convert_ip_log() silently skips any other field count.
	 */
	private function rawFields(array $overrides): array
	{
		$base = [
			0  => '2026-07-17 00:00:00',	// Date/Timestamp
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
			20 => '',			// ASN Domain (issue #1369)
			21 => '',			// ASN Name (issue #1369)
		];
		return array_replace($base, $overrides);
	}

	/** Render one row via the real page function, capturing its printed HTML. */
	private function render(array $rawFields, string $rtype): string
	{
		$GLOBALS['dup'][$rtype]     = 0;
		$GLOBALS['counter'][$rtype] = 0;
		$GLOBALS['ipfilterlimit']   = FALSE;

		ob_start();
		convert_ip_log('non_unified', $rawFields, '', $rtype);
		return (string) ob_get_clean();
	}

	/**
	 * Broad v4 mask (/16) -- the retired gate required an exact /32 or /24;
	 * ANY other v4 mask (narrower OR broader) got neither $mask_suppression
	 * nor $mask_unlock, so the icon never rendered. The evaluated entry
	 * (198.51.0.0/16) also differs from the alerted host -- pins that the
	 * icon embeds the EXACT host, never the feed's covering CIDR.
	 */
	public function testV4BroadMaskBlockRowRendersUnlockIconWithExactHost(): void
	{
		file_put_contents("{$this->denydir}/BroadFeed.txt", "198.51.0.0/16\n");

		$fields = $this->rawFields([
			8 => '198.51.5.9', 15 => '198.51.0.0/16',
			14 => 'pfB_Deny_v4', 16 => 'BroadFeed',
		]);

		$html = $this->render($fields, 'Block');

		$this->assertStringContainsString(
			'IPULCK|198.51.5.9|pfB_Deny_v4',
			$html,
			"expected the Unlock icon for a v4 host evaluated against a /16 mask -- the retired "
				. "mask_suppression/mask_unlock gate only accepted /32 or /24, got:\n{$html}"
		);
		$this->assertStringNotContainsString(
			'IPULCK|198.51.0.0',
			$html,
			"the Unlock icon must embed the EXACT alerted host (198.51.5.9), never the feed's "
				. "covering CIDR (198.51.0.0/16), got:\n{$html}"
		);
	}

	/** Exact /32 -- the ONE shape the retired gate already accepted; must keep working. */
	public function testV4Slash32BlockRowStillRendersUnlockIcon(): void
	{
		file_put_contents("{$this->denydir}/ExactFeed.txt", "192.0.2.11\n");

		$fields = $this->rawFields([
			8 => '192.0.2.11', 15 => '192.0.2.11',
			14 => 'pfB_Exact_v4', 16 => 'ExactFeed',
		]);

		$html = $this->render($fields, 'Block');

		$this->assertStringContainsString(
			'IPULCK|192.0.2.11|pfB_Exact_v4',
			$html,
			"expected the Unlock icon to still render for an exact /32 v4 host (unchanged legacy "
				. "shape), got:\n{$html}"
		);
	}

	/**
	 * IPv6 -- $mask_suppression/$mask_unlock were computed ONLY
	 * ``if ($pfb_ipv4)``, so a v6 Block row got neither flag and the icon
	 * NEVER rendered, regardless of mask. The evaluated entry is a /48 CIDR
	 * (broad, mirroring the v4 broad-mask case) to also confirm the icon
	 * embeds the exact host, not the CIDR.
	 */
	public function testV6BlockRowRendersUnlockIconWithExactHost(): void
	{
		file_put_contents("{$this->denydir}/V6Feed.txt", "2001:db8:dead::/48\n");

		$fields = $this->rawFields([
			5 => 6, 8 => '2001:db8:dead::5', 9 => '2001:db8:2::1',
			15 => '2001:db8:dead::/48',
			14 => 'pfB_Deny_v6', 16 => 'V6Feed',
		]);

		$html = $this->render($fields, 'Block');

		$this->assertStringContainsString(
			'IPULCK|2001:db8:dead::5|pfB_Deny_v6',
			$html,
			"expected the Unlock icon for a v6 host -- the retired gate was wired only for "
				. "\$pfb_ipv4 and never rendered for ANY v6 row, got:\n{$html}"
		);
		$this->assertStringNotContainsString(
			'IPULCK|2001:db8:dead::/48',
			$html,
			"the Unlock icon must embed the EXACT alerted v6 host, never the feed's covering "
				. "/48, got:\n{$html}"
		);
	}

	/**
	 * GeoIP rows stay excluded -- same "maintainer constraint" the
	 * Suppression icon already enforces (parity is the point of #1412).
	 */
	public function testGeoipBlockRowDoesNotRenderUnlockIcon(): void
	{
		file_put_contents("{$this->ccdir}/pfB_Top.txt", "198.51.100.90\n");

		$fields = $this->rawFields([
			8 => '198.51.100.90', 15 => '198.51.100.90',
			14 => 'pfB_Top_v4', 16 => 'CountryFeedOld',
		]);

		$html = $this->render($fields, 'Block');

		$this->assertStringNotContainsString('IPULCK|198.51.100.90', $html);
		$this->assertStringNotContainsString('IPLCK|198.51.100.90', $html);
	}

	/** Non-Block rows (Match, Permit, ...) stay excluded -- $rtype gate, FALSE arm. */
	public function testMatchRowDoesNotRenderUnlockIcon(): void
	{
		file_put_contents("{$this->matchdir}/Ads_v4.txt", "198.51.100.77\n");

		$fields = $this->rawFields([
			4 => 'match', 8 => '198.51.100.77', 15 => '198.51.100.77',
			14 => 'pfB_Ads_v4', 16 => 'Ads_v4',
		]);

		$html = $this->render($fields, 'Match');

		$this->assertStringNotContainsString('IPULCK|198.51.100.77', $html);
		$this->assertStringNotContainsString('IPLCK|198.51.100.77', $html);
	}

	/**
	 * Already-unlocked -- the "is this row's host currently unlocked" check
	 * must key on the SAME token the ip_remove handler now stores ($host),
	 * not $eval_ip. Re-locking a host must render the "IPLCK" (re-lock) icon,
	 * not "IPULCK".
	 */
	public function testAlreadyUnlockedHostRendersRelockIconKeyedByHost(): void
	{
		file_put_contents("{$this->denydir}/ExactFeed.txt", "192.0.2.11\n");
		$GLOBALS['ip_unlock'] = ['192.0.2.11' => 'pfB_Exact_v4'];

		$fields = $this->rawFields([
			8 => '192.0.2.11', 15 => '192.0.2.11',
			14 => 'pfB_Exact_v4', 16 => 'ExactFeed',
		]);

		$html = $this->render($fields, 'Block');

		$this->assertStringContainsString(
			'IPLCK|192.0.2.11|pfB_Exact_v4',
			$html,
			"expected the Re-Lock icon for a host present in \$ip_unlock (keyed by the exact "
				. "host), got:\n{$html}"
		);
		$this->assertStringNotContainsString('IPULCK|192.0.2.11|', $html);
	}

	public function testHostUnlockedInAnotherTableStillRendersUnlockIconForThisRow(): void
	{
		file_put_contents("{$this->denydir}/ExactFeed.txt", "192.0.2.11\n");
		// The host is unlocked in a DIFFERENT table -- this row's table is not.
		$GLOBALS['ip_unlock'] = ['192.0.2.11' => 'pfB_Other_v4'];

		$fields = $this->rawFields([
			8 => '192.0.2.11', 15 => '192.0.2.11',
			14 => 'pfB_Exact_v4', 16 => 'ExactFeed',
		]);

		$html = $this->render($fields, 'Block');

		$this->assertStringContainsString(
			'IPULCK|192.0.2.11|pfB_Exact_v4',
			$html,
			"expected the Unlock icon for this row's table when the host's \$ip_unlock entry "
				. "belongs to a DIFFERENT table, got:\n{$html}"
		);
		$this->assertStringNotContainsString('IPLCK|192.0.2.11|', $html);
	}
}
