<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1526: an Alerts-table row that is temporarily unlocked must still
 * render the permanent whitelist/suppression "+" next to the lock/unlock
 * icon. Temporary bypass and permanent whitelist are independent actions;
 * unlocking must not hide "+".
 *
 * Harness: AlertsPageLoader off-appliance load of convert_ip_log() /
 * convert_dnsbl_log() (same shape as AlertsIpUnlockIconTest /
 * AlertsDnsblLoggedFieldsRenderTest). IP rows seed a deny-folder feed file
 * so convert_ip_log() does not strip "+" via the 'Not listed!' gate.
 */
#[CoversFunction('convert_ip_log')]
#[CoversFunction('convert_dnsbl_log')]
#[CoversFunction('dnsbl_whitelist_type')]
#[CoversFunction('pfb_alerts_unlocked_entry_actions')]
#[CoversFunction('pfb_alerts_permit_option_suffix')]
final class AlertsUnlockedRowWhitelistIconTest extends TestCase
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
			'pfb', 'continents', 'filterfieldsarray', 'clists', 'ip_unlock',
			'dnsbl_unlock', 'local_hosts', 'dnsbl_int', 'counter', 'pfbentries',
			'skipcount', 'dup', 'ipfilterlimit', 'ipfilterlimitentries',
			'dnsblfilterlimit', 'dnsblfilterlimitentries', 'config',
		] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}

		$this->tmpDir      = sys_get_temp_dir() . '/pfb_unlock_wl_icon_' . bin2hex(random_bytes(6));
		$this->denydir     = "{$this->tmpDir}/deny";
		$this->nativedir   = "{$this->tmpDir}/native";
		$this->ccdir       = "{$this->tmpDir}/geoip";
		$this->etdir       = "{$this->tmpDir}/et";
		$this->aliasdir    = "{$this->tmpDir}/alias";
		$this->matchdir    = "{$this->tmpDir}/match";
		$this->matchgendir = "{$this->matchdir}/generated";
		foreach ([
			$this->denydir, $this->nativedir, $this->ccdir, $this->etdir,
			$this->aliasdir, $this->matchdir, $this->matchgendir,
		] as $d) {
			mkdir($d, 0777, TRUE);
		}
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
			'supp'             => '',
			'unidnsbl'         => '#f0f0f0',
			'unidnsbl2'        => '#202020',
			'uniupstream'      => '#f0f0f0',
			'uniupstream2'     => '#202020',
		];
		$GLOBALS['continents'] = array_flip(array(
			'pfB_Africa', 'pfB_Antarctica', 'pfB_Asia', 'pfB_Europe',
			'pfB_NAmerica', 'pfB_Oceania', 'pfB_SAmerica', 'pfB_Top',
		));
		$GLOBALS['filterfieldsarray']     = [];
		$GLOBALS['clists']               = [
			'ipwhitelist4'   => [],
			'ipwhitelist6'   => [],
			'dnsbl'          => ['options' => []],
			'dnsblwhitelist' => ['data' => []],
		];
		$GLOBALS['ip_unlock']            = [];
		$GLOBALS['dnsbl_unlock']         = [];
		$GLOBALS['local_hosts']          = [];
		$GLOBALS['dnsbl_int']            = [];
		$GLOBALS['counter']              = ['Block' => 0, 'DNSBL' => 0, 'Unified' => 0];
		$GLOBALS['pfbentries']           = 1000;
		$GLOBALS['skipcount']            = 0;
		$GLOBALS['dup']                  = ['Block' => 0, 'DNSBL' => 0];
		$GLOBALS['ipfilterlimit']        = FALSE;
		$GLOBALS['ipfilterlimitentries'] = 0;
		$GLOBALS['dnsblfilterlimit']     = FALSE;
		$GLOBALS['dnsblfilterlimitentries'] = 100;
		$GLOBALS['config']               = ['system' => ['webgui' => ['webguicss' => '']]];

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

	/** @param array<int, mixed> $overrides */
	private function rawIpFields(array $overrides): array
	{
		$base = [
			0  => '2026-07-17 00:00:00',
			1  => 'rule1',
			2  => 'em0',
			3  => 'WAN',
			4  => 'block',
			5  => 4,
			6  => 'tcp',
			7  => 'TCP',
			8  => '192.0.2.11',
			9  => '198.51.100.1',
			10 => '12345',
			11 => '443',
			12 => 'in',
			13 => 'US',
			14 => 'pfB_Default_v4',
			15 => '192.0.2.11',
			16 => 'DefaultFeed',
			17 => '',
			18 => '',
			19 => 'Unknown',
			20 => '',
			21 => '',
		];
		return array_replace($base, $overrides);
	}

	/** @param array<int, mixed> $rawFields */
	private function renderIp(array $rawFields): string
	{
		$GLOBALS['dup']['Block']     = 0;
		$GLOBALS['counter']['Block'] = 0;
		$GLOBALS['ipfilterlimit']    = FALSE;

		ob_start();
		convert_ip_log('non_unified', $rawFields, '', 'Block');
		return (string) ob_get_clean();
	}

	/** @return array<int, mixed> */
	private function dnsblFields(string $domain): array
	{
		return [
			0  => 'DNSBL-Full',
			1  => '2026-01-01 00:00:00',
			2  => $domain,
			3  => '10.0.0.5',
			4  => '',
			5  => 'DNSBL',
			6  => 'LoggedGroup',
			7  => $domain,
			8  => 'LoggedFeed',
			9  => 0,
			10 => 'A',
		];
	}

	/** @param array<int, mixed> $fields */
	private function renderDnsbl(array $fields): string
	{
		$GLOBALS['dup']['DNSBL']         = 0;
		$GLOBALS['counter']['DNSBL']     = 0;
		$GLOBALS['dnsblfilterlimit']     = FALSE;

		ob_start();
		convert_dnsbl_log('non_unified', $fields);
		return (string) ob_get_clean();
	}

	public function testLockedIpBlockRowRendersSuppressionPlus(): void
	{
		file_put_contents("{$this->denydir}/ExactFeed.txt", "192.0.2.11\n");
		$fields = $this->rawIpFields([
			8 => '192.0.2.11', 15 => '192.0.2.11',
			14 => 'pfB_Exact_v4', 16 => 'ExactFeed',
		]);

		$html = $this->renderIp($fields);

		$this->assertStringContainsString(
			'PFBIPSUP|add|192.0.2.11|pfB_Exact_v4',
			$html,
			"locked Block row must keep the suppression '+' (baseline), got:\n{$html}"
		);
	}

	public function testUnlockedIpBlockRowStillRendersSuppressionPlusBesideRelock(): void
	{
		file_put_contents("{$this->denydir}/ExactFeed.txt", "192.0.2.11\n");
		$GLOBALS['ip_unlock'] = ['192.0.2.11' => 'pfB_Exact_v4'];
		$fields = $this->rawIpFields([
			8 => '192.0.2.11', 15 => '192.0.2.11',
			14 => 'pfB_Exact_v4', 16 => 'ExactFeed',
		]);

		$html = $this->renderIp($fields);

		$this->assertStringContainsString(
			'IPLCK|192.0.2.11|pfB_Exact_v4',
			$html,
			"unlocked Block row must show Re-Lock, got:\n{$html}"
		);
		$this->assertStringContainsString(
			'PFBIPSUP|add|192.0.2.11|pfB_Exact_v4',
			$html,
			"issue #1526: unlocked Block row must still show suppression '+' next to Re-Lock, got:\n{$html}"
		);
	}

	public function testLockedDnsblRowRendersWhitelistPlus(): void
	{
		$domain = 'locked-wl.example.com';
		$html   = $this->renderDnsbl($this->dnsblFields($domain));

		$this->assertStringContainsString(
			'DNSBLWT|add|' . $domain,
			$html,
			"locked DNSBL row must keep whitelist '+', got:\n{$html}"
		);
	}

	public function testUnlockedDnsblRowStillRendersWhitelistPlusBesideRelock(): void
	{
		$domain = 'unlocked-wl.example.com';
		$GLOBALS['dnsbl_unlock'] = [$domain => 'DNSBL'];
		$html = $this->renderDnsbl($this->dnsblFields($domain));

		$this->assertStringContainsString(
			'DNSBL_LCK|' . $domain . '|DNSBL',
			$html,
			"unlocked DNSBL row must show Re-Lock, got:\n{$html}"
		);
		$this->assertStringContainsString(
			'DNSBLWT|add|' . $domain,
			$html,
			"issue #1526: unlocked DNSBL row must still show whitelist '+' next to Re-Lock, got:\n{$html}"
		);
	}

	public function testUnlockedIpPanelRowRendersSuppressionPlusBesideRelock(): void
	{
		$html = implode('', pfb_alerts_unlocked_entry_actions(
			'ip',
			'192.0.2.11',
			'pfB_Exact_v4',
			$GLOBALS['clists']
		));

		$this->assertStringContainsString(
			'IPLCK|192.0.2.11|pfB_Exact_v4',
			$html,
			"Unlocked panel IP row must keep Re-Lock, got:\n{$html}"
		);
		$this->assertStringContainsString(
			'PFBIPSUP|add|192.0.2.11|pfB_Exact_v4',
			$html,
			"issue #1526: Unlocked panel IP row must show suppression '+' next to Re-Lock, got:\n{$html}"
		);
	}

	public function testUnlockedDnsblPanelRowRendersWhitelistPlusBesideRelock(): void
	{
		$domain = 'unlocked-panel.example.com';
		$html = implode('', pfb_alerts_unlocked_entry_actions(
			'dnsbl',
			$domain,
			'DNSBL',
			$GLOBALS['clists']
		));

		$this->assertStringContainsString(
			'DNSBL_LCK|' . $domain . '|DNSBL',
			$html,
			"Unlocked panel DNSBL row must keep Re-Lock, got:\n{$html}"
		);
		$this->assertStringContainsString(
			'DNSBLWT|add|' . $domain . '|DNSBL',
			$html,
			"issue #1526: Unlocked panel DNSBL row must show whitelist '+' next to Re-Lock, got:\n{$html}"
		);
	}

	public function testUnlockedNonTldPanelRowOmitsTldExclusionIdField(): void
	{
		$domain = 'unlocked-panel.example.com';
		$html = implode('', pfb_alerts_unlocked_entry_actions(
			'dnsbl',
			$domain,
			'DNSBL',
			$GLOBALS['clists']
		));

		$this->assertStringNotContainsString(
			'|TLD"',
			$html,
			"non-TLD unlock type must not add the TLD-exclusion id field, got:\n{$html}"
		);
	}

	public function testUnlockedIpv6PanelRowUsesIpwhitelist6PermitOptions(): void
	{
		$GLOBALS['clists']['ipwhitelist4'] = [
			'options' => ['wrong-family-v4-sentinel'],
		];
		$GLOBALS['clists']['ipwhitelist6'] = [
			'options' => ['Create new pfB_Whitelist_v6', 'pfB_Permit_v6'],
		];
		$host = '2001:db8::5';
		$html = implode('', pfb_alerts_unlocked_entry_actions(
			'ip',
			$host,
			'pfB_Deny_v6',
			$GLOBALS['clists']
		));

		$this->assertStringContainsString(
			'IPLCK|' . $host . '|pfB_Deny_v6',
			$html,
			"Unlocked panel v6 row must keep Re-Lock, got:\n{$html}"
		);
		$this->assertStringContainsString(
			'PFBIPSUP|add|' . $host . '|pfB_Deny_v6|Create new pfB_Whitelist_v6|pfB_Permit_v6',
			$html,
			"v6 panel '+' must read ipwhitelist6 options (the live never-empty branch), got:\n{$html}"
		);
		$this->assertStringNotContainsString(
			'wrong-family-v4-sentinel',
			$html,
			"v6 panel '+' must not pick ipwhitelist4 options, got:\n{$html}"
		);
	}

	public function testUnlockedIpv4PanelRowIncludesLivePermitOptions(): void
	{
		$GLOBALS['clists']['ipwhitelist4'] = [
			'options' => ['Create new pfB_Whitelist_v4', 'pfB_Permit_v4'],
		];
		$html = implode('', pfb_alerts_unlocked_entry_actions(
			'ip',
			'192.0.2.11',
			'pfB_Exact_v4',
			$GLOBALS['clists']
		));

		$this->assertStringContainsString(
			'PFBIPSUP|add|192.0.2.11|pfB_Exact_v4|Create new pfB_Whitelist_v4|pfB_Permit_v4',
			$html,
			"v4 panel '+' must carry the live permit-options suffix, got:\n{$html}"
		);
	}

	public function testUnlockedTldPanelRowAddsTldExclusionIdField(): void
	{
		$domain = 'blocked.tld-unlock.example';
		$html = implode('', pfb_alerts_unlocked_entry_actions(
			'dnsbl',
			$domain,
			'DNSBL_TLD',
			$GLOBALS['clists']
		));

		$this->assertStringContainsString(
			'DNSBLWT|add|' . $domain . '|DNSBL_TLD|TLD',
			$html,
			"TLD unlock type must emit the 5th id field so JS offers TLD Exclusion, got:\n{$html}"
		);
	}
}
