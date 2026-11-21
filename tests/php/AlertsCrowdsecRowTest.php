<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4164 -- how the Alerts page renders a drop by the CrowdSec bouncer's rule, which the filterlog daemon logs under the
 * bouncer's table with CrowdSec as the feed and the matched entry Unknown.
 *
 * Intent pinned here:
 *   - the row shows as logged: the bouncer's tables are no feed and no pfB alias table, so the render-time re-check against
 *     the feed lists and alias tables does not apply, and a pfB feed that lists the address now is no drift;
 *   - the Rule cell's tooltip names the bouncer's rule its tracker identifies ("CrowdSec IPv4", "CrowdSec IPv6 out");
 *   - pfBlockerNG's suppress, unlock and whitelist actions do not apply (the decisions live on the CrowdSec engine, and the
 *     bouncer's rules come before every pfB rule), so the row offers none; it links the external host to the CrowdSec Status
 *     subtab's lookup, beside the Threat Source lookup every row has.
 *
 * Harness: AlertsIpUnlockIconTest's off-appliance page load and fixture directories (real find/grep against a sandbox).
 */
#[CoversFunction('convert_ip_log')]
#[CoversFunction('pfb_ip_render_attribution')]
final class AlertsCrowdsecRowTest extends TestCase
{
	private string $tmpDir;

	/** @var array<string, mixed> */
	private array $savedGlobals = [];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach (['pfb', 'continents', 'filterfieldsarray', 'clists', 'ip_unlock', 'counter', 'pfbentries', 'skipcount', 'dup',
		    'ipfilterlimit', 'ipfilterlimitentries'] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? NULL;
		}

		$this->tmpDir = sys_get_temp_dir() . '/pfb_alerts_crowdsec_' . bin2hex(random_bytes(6));
		foreach (['deny', 'native', 'permit', 'match/generated', 'et', 'geoip', 'alias'] as $d) {
			mkdir("{$this->tmpDir}/{$d}", 0777, TRUE);
		}
		// The banned addresses are in a pfB feed and its alias table too: a re-check would report them there
		file_put_contents("{$this->tmpDir}/deny/Other_Feed.txt", "192.0.2.10\n2001:db8:4074::1\n");
		file_put_contents("{$this->tmpDir}/native/Placeholder.txt", "placeholder\n");
		file_put_contents("{$this->tmpDir}/alias/pfB_Other_v4.txt", "192.0.2.10\n");
		file_put_contents("{$this->tmpDir}/alias/pfB_Other_v6.txt", "2001:db8:4074::1\n");

		$GLOBALS['pfb'] = [
			'grep' => '/usr/bin/grep', 'denydir' => "{$this->tmpDir}/deny", 'nativedir' => "{$this->tmpDir}/native",
			'permitdir' => "{$this->tmpDir}/permit", 'matchdir' => "{$this->tmpDir}/match",
			'matchgendir' => "{$this->tmpDir}/match/generated", 'etdir' => "{$this->tmpDir}/et", 'ccdir' => "{$this->tmpDir}/geoip",
			'aliasdir' => "{$this->tmpDir}/alias", 'filterlogentries' => FALSE, 'asn_reporting' => 'disabled', 'supp' => '',
			'uniblock' => 'none', 'uniblock2' => 'none',
		];
		$GLOBALS['continents'] = array_flip(['pfB_Africa', 'pfB_Asia', 'pfB_Europe', 'pfB_NAmerica', 'pfB_Top']);
		$GLOBALS['filterfieldsarray'] = [];
		// A Permit whitelist exists, so a row that offered whitelisting would show its icon
		$GLOBALS['clists'] = ['ipwhitelist4' => ['pfB_Whitelist_v4' => ['data' => []]], 'ipwhitelist6' => ['pfB_Whitelist_v6' => ['data' => []]]];
		$GLOBALS['ip_unlock'] = [];
		$GLOBALS['counter'] = ['Block' => 0, 'Unified' => 0];
		$GLOBALS['pfbentries'] = 1000;
		$GLOBALS['skipcount'] = 0;
		$GLOBALS['dup'] = ['Block' => 0];
		$GLOBALS['ipfilterlimit'] = FALSE;
		$GLOBALS['ipfilterlimitentries'] = 0;
		pfb_ip_render_memos_reset();
	}

	protected function tearDown(): void
	{
		pfb_ip_render_memos_reset();
		foreach ($this->savedGlobals as $g => $v) {
			if ($v === NULL) {
				unset($GLOBALS[$g]);
			} else {
				$GLOBALS[$g] = $v;
			}
		}
		rmdir_recursive($this->tmpDir);
	}

	/** An ip_block.log row as the filterlog daemon writes a drop by the bouncer's rule, duplicate marker popped. */
	private static function row(string $tracker, int $family, string $src, string $dst, string $dir, string $table): array
	{
		return ['2026-11-21 10:00:00', $tracker, 'vtnet0', 'WAN', 'block', $family, '6', 'TCP-S', $src, $dst, '51234', '22', $dir,
			'Unk', $table, 'Unknown', 'CrowdSec', 'Unknown', 'Unknown', 'Unknown', '', ''];
	}

	private function render(array $fields, string $mode = 'non_unified'): string
	{
		$GLOBALS['counter']['Block'] = $GLOBALS['counter']['Unified'] = 0;
		$GLOBALS['ipfilterlimit'] = FALSE;
		ob_start();
		convert_ip_log($mode, $fields, '', 'Block');
		return (string) ob_get_clean();
	}

	public function testAnInboundIpv4DropRendersAsLoggedWithTheCrowdsecLookup(): void
	{
		$html = $this->render(self::row('177400401', 4, '192.0.2.10', '10.0.0.5', 'in', 'crowdsec_v4'));

		$this->assertStringContainsString('<td><span title="CrowdSec IPv4">crowdsec_v4<br /><small>(177400401)</small></span></td>', $html,
			'the table and the rule tracker, the rule named in the tooltip');
		$this->assertStringContainsString('>CrowdSec<br /><small>Unknown</small></td>', $html, 'the feed and matched entry as logged');
		$this->assertStringNotContainsString('<s>', $html, 'no drift against pfB feeds or alias tables');
		$this->assertStringNotContainsString('Not listed', $html);
		$this->assertStringContainsString('href="/pfblockerng/pfblockerng_crowdsec_status.php?lookup=192.0.2.10"', $html, 'the CrowdSec lookup');
		$this->assertStringContainsString('pfblockerng_threats.php?host=192.0.2.10', $html, 'the Threat Source lookup stays');
		foreach (['IPULCK|', 'IPLCK|', 'PFBIPSUP|', 'PFBIPWHITE|', 'DNSBLWT|'] as $action) {
			$this->assertStringNotContainsString($action, $html, "no pfBlockerNG action {$action}");
		}
	}

	public function testAnOutboundIpv6DropLinksTheExternalHostInTheUnifiedView(): void
	{
		$fields = self::row('177400602', 6, '2001:db8:1::5', '2001:db8:4074::1', 'out', 'crowdsec_v6');
		$fields[] = '+';	// Unified rows keep their duplicate marker
		$html = $this->render($fields, 'Unified');

		$this->assertStringContainsString('href="/pfblockerng/pfblockerng_crowdsec_status.php?lookup=2001:db8:4074::1"', $html);
		$this->assertStringContainsString('<span title="CrowdSec IPv6 out">crowdsec_v6<br /><small>(177400602)</small></span>', $html);
		$this->assertStringNotContainsString('lookup=2001:db8:1::5', $html, 'the local host is not looked up');
		$this->assertStringContainsString('>CrowdSec<br /><small>Unknown</small></td>', $html);
		$this->assertStringNotContainsString('<s>', $html);
		foreach (['IPULCK|', 'PFBIPSUP|', 'PFBIPWHITE|'] as $action) {
			$this->assertStringNotContainsString($action, $html, "no pfBlockerNG action {$action}");
		}
	}

	public function testAPfbRowForTheSameAddressKeepsItsActionsAndNoCrowdsecLookup(): void
	{
		$fields = self::row('1770000001', 4, '192.0.2.10', '10.0.0.5', 'in', 'pfB_Other_v4');
		$fields[15] = '192.0.2.10';
		$fields[16] = 'Other_Feed';
		$html = $this->render($fields);

		$this->assertStringContainsString('IPULCK|192.0.2.10|pfB_Other_v4', $html);
		$this->assertStringContainsString('PFBIPSUP|add|192.0.2.10|pfB_Other_v4', $html);
		$this->assertStringNotContainsString('pfblockerng_crowdsec_status.php', $html);
		$this->assertStringNotContainsString('<span title=', $html, 'no rule-name tooltip on a pfB row');
	}
}
