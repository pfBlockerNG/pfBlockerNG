<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #1887/#1907: page checkbox decisions persist explicit Off tokens. */
final class ToggleEmptyPreservationTest extends TestCase
{
	private const DNSBL_PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
	private const IP_PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_ip.php';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/**
	 * The DNSBL page owns these save/render decisions. An absent checkbox must stay Off
	 * even when the registry default is On; a checked box must round-trip as On.
	 */
	public function testDnsblPageToggleSaveAndRenderDecisions(): void
	{
		$section = 'installedpackages/pfblockerngdnsblsettings/config/0';
		$fields = [
			'pfb_cache' => 'dnsbl/pfb_cache',
			'pfb_py_reply' => 'dnsbl/pfb_py_reply',
			'pfb_hsts' => 'dnsbl/pfb_hsts',
			'pfb_idn_block_malicious' => 'dnsbl/pfb_idn_block_malicious',
			'pfb_idn_escalate_suspicious' => 'dnsbl/pfb_idn_escalate_suspicious',
		];

		foreach ($fields as $bare => $key) {
			$GLOBALS['config'] = [];
			$unchecked = pfb_filter(NULL, PFB_FILTER_ON_OFF, 'dnsbl');
			PfbConfig::writeSection($section, [$bare => $unchecked]);
			$this->assertSame('', config_get_path("{$section}/{$bare}"), "{$bare}: absent POST must persist empty");
			$this->assertFalse(pfb_dnsbl_toggle_enabled(PfbConfig::read($key)), "{$bare}: unchecked render must be disabled");

			$checked = pfb_filter('on', PFB_FILTER_ON_OFF, 'dnsbl');
			PfbConfig::writeSection($section, [$bare => $checked]);
			$this->assertSame('on', config_get_path("{$section}/{$bare}"), "{$bare}: checked POST must persist On");
			$this->assertTrue(pfb_dnsbl_toggle_enabled(PfbConfig::read($key)), "{$bare}: checked render must be enabled");
		}
	}

	/** The IP page has its own suppression save/render decision and same polarity. */
	public function testIpPageSuppressionSaveAndRenderDecision(): void
	{
		$section = 'installedpackages/pfblockerngipsettings/config/0';
		$key = 'ip/suppression';

		$unchecked = pfb_filter(NULL, PFB_FILTER_ON_OFF, 'ip');
		PfbConfig::writeSection($section, ['suppression' => $unchecked]);
		$this->assertSame('', config_get_path("{$section}/suppression"), 'IP unchecked POST must persist empty');
		$this->assertFalse(pfb_ip_suppression_enabled(PfbConfig::read($key)), 'IP unchecked render must be disabled');

		$checked = pfb_filter('on', PFB_FILTER_ON_OFF, 'ip');
		PfbConfig::writeSection($section, ['suppression' => $checked]);
		$this->assertSame('on', config_get_path("{$section}/suppression"), 'IP checked POST must persist On');
		$this->assertTrue(pfb_ip_suppression_enabled(PfbConfig::read($key)), 'IP checked render must be enabled');
	}

	/**
	 * #993: these page-save branches require pfSense request/config globals and cannot run
	 * off-appliance; each shipped binding is pinned in its own comment-free source window.
	 * php_strip_whitespace() strips comments/docblocks, so they cannot satisfy the pins.
	 */
	public function testShippedSaveBindingsKeepEachToggleOnItsPage(): void
	{
		foreach ([
			"\$pfb['dconfig']['pfb_cache'] = pfb_filter(\$_POST['pfb_cache'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';" => self::DNSBL_PAGE,
			"\$pfb['dconfig']['pfb_py_reply'] = pfb_filter(\$_POST['pfb_py_reply'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';" => self::DNSBL_PAGE,
			"\$pfb['dconfig']['pfb_hsts'] = pfb_filter(\$_POST['pfb_hsts'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';" => self::DNSBL_PAGE,
			"\$pfb['dconfig']['pfb_idn_block_malicious'] = pfb_filter(\$_POST['pfb_idn_block_malicious'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';" => self::DNSBL_PAGE,
			"\$pfb['dconfig']['pfb_idn_escalate_suspicious'] = pfb_filter(\$_POST['pfb_idn_escalate_suspicious'] ?? '', PFB_FILTER_ON_OFF, 'dnsbl') ?: '';" => self::DNSBL_PAGE,
			"\$pfb['iconfig']['suppression'] = pfb_filter(\$_POST['suppression'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';" => self::IP_PAGE,
		] as $needle => $page) {
			$source = php_strip_whitespace($page);
			$start  = "if (isset(\$_POST['save'])) {";
			$end    = 'PfbConfig::writeSection(';
			$from   = strpos($source, $start);
			$to     = $from === FALSE ? FALSE : strpos($source, $end, $from + strlen($start));

			$this->assertNotFalse($from, "save branch missing for {$needle}");
			$this->assertNotFalse($to, "config gateway write missing for {$needle}");
			$window = substr($source, $from, $to - $from);
			$this->assertSame(1, substr_count($window, $needle), "save binding must be unique: {$needle}");

			$otherPage = $page === self::DNSBL_PAGE ? self::IP_PAGE : self::DNSBL_PAGE;
			$otherSource = php_strip_whitespace($otherPage);
			$otherFrom = strpos($otherSource, $start);
			$otherTo = $otherFrom === FALSE ? FALSE : strpos($otherSource, $end, $otherFrom + strlen($start));
			$this->assertNotFalse($otherFrom, "other-page save branch missing for {$needle}");
			$this->assertNotFalse($otherTo, "other-page config gateway write missing for {$needle}");
			$otherWindow = substr($otherSource, $otherFrom, $otherTo - $otherFrom);
			$this->assertStringNotContainsString($needle, $otherWindow, "save binding must stay off the other page: {$needle}");
		}
	}
}
