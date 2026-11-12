<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- DNS Reply Logging is ONE preference (dnsbl/pfb_py_reply, unchanged path and default) that both DNS modes
 * read: the DNSBL module's ini (python_reply) and, with DNSBL off, the pfB-DNS proxy's --reply-log. Its control therefore
 * lives on DNS General, which is reachable in either mode, and no longer on either mode-specific page. The pfB-DNS settings share that
 * page's one form (issue #3856: one form, one Save DNS settings button), so the contract is also that one save writes the preference with them.
 *
 * The pages are scripts that render on include, so the contract is pinned in their source (like DnsProxySettingsSaveTest):
 *   - DNS General renders the checkbox from the stored preference and saves it through the gateway, under the config
 *     lock and in the same write_config() as its pfB-DNS settings and resolver VIP settings;
 *   - the DNSBL page neither renders nor assigns it: its section save writes the section it read afresh under the config
 *     lock (DnsblSettingsSaveRaceTest), so a key it never assigns keeps what DNS General stored, even from a save
 *     that overlapped (assigning '' for the missing checkbox would turn logging off on every DNSBL save).
 * The key, its default (on) and its local sync scope are the registry's; the rc flag is DnsProxyServiceTest's.
 */
final class DnsReplyLoggingPreferencePageTest extends TestCase
{
	private const WWW = __DIR__ . '/../../src/usr/local/www/pfblockerng/';

	private static function page(string $name): string
	{
		return php_strip_whitespace(self::WWW . $name);
	}

	public function testDnsGeneralRendersTheStoredPreferenceAsTheDnsReplyLoggingCheckbox(): void
	{
		$page = self::page('pfblockerng_dns_general.php');

		$this->assertStringContainsString("\$pconfig['pfb_py_reply'] = PfbConfig::read('dnsbl/pfb_py_reply');", $page, 'reads the one existing key');
		$this->assertSame(1, preg_match("~new Form_Checkbox\\( 'pfb_py_reply', gettext\\('DNS Reply Logging'\\), 'Enable', pfb_dnsbl_toggle_enabled\\(\\\$pconfig\\['pfb_py_reply'\\] \\?\\? NULL\\), 'on' \\)~", $page), 'the checkbox the DNSBL page had, default-on reading included');
	}

	public function testTheDnsblPageNeitherRendersNorAssignsThePreference(): void
	{
		$page = self::page('pfblockerng_dnsbl.php');

		$this->assertStringNotContainsString('pfb_py_reply', $page, 'no control, no read, no write: its save keeps what DNS General stored');
		$this->assertStringContainsString("\$pfb['dconfig']['pfb_hsts']", $page, 'bystander: the sibling toggle is still this page\'s own');
	}

	/** The offset of the first match of $pattern in $page, or NULL. */
	private static function offsetOf(string $pattern, string $page): ?int
	{
		return preg_match($pattern, $page, $match, PREG_OFFSET_CAPTURE) === 1 ? (int) $match[0][1] : NULL;
	}

	public function testTheDnsGeneralPageHoldsTheOnlyReplyLoggingCheckboxInItsOneFormAndItsOneSaveReadsAndWritesThePreferenceInTheOneWrite(): void
	{
		$page = self::page('pfblockerng_dns_general.php');
		$form = self::offsetOf("~\\\$form = new Form\\(\\s*'Save DNS settings'\\s*\\)~", $page);
		$saveGate = self::offsetOf("~if \\(\\\$_POST && isset\\(\\\$_POST\\['save'\\]\\)\\)~", $page);
		$title = self::offsetOf('~\\$pgtitle = ~', $page);
		$replySection = self::offsetOf("~new Form_Section\\(\\s*'DNS Reply Logging'\\s*\\)~", $page);
		$addressesSection = self::offsetOf("~new Form_Section\\(\\s*'Resolver addresses'\\s*\\)~", $page);
		$this->assertNotNull($form, 'the page has the one form, with the one Save DNS settings button');
		$this->assertNotNull($saveGate, 'the one save is gated on that button, save');
		$this->assertNotNull($title, 'the save handler ends before the page title');
		$this->assertNotNull($replySection, 'the form has a DNS Reply Logging section');
		$this->assertNotNull($addressesSection, 'and a Resolver addresses section after it');
		$this->assertSame(1, substr_count($page, 'new Form('), 'one form');
		$this->assertSame(1, substr_count($page, "isset(\$_POST['save'])"), 'one save handler');

		// The single control is in the one form's own DNS Reply Logging section
		$checkboxes = (int) preg_match_all("~new Form_Checkbox\\(\\s*'pfb_py_reply'~", $page, $found, PREG_OFFSET_CAPTURE);
		$this->assertSame(1, $checkboxes, 'exactly one DNS Reply Logging checkbox');
		$this->assertGreaterThan($form, $replySection, 'the section is in the form');
		$this->assertGreaterThan($replySection, $found[0][0][1], 'and the checkbox is in the DNS Reply Logging section');
		$this->assertLessThan($addressesSection, $found[0][0][1], 'not in the Resolver addresses section');

		// The one save reads the posted preference, writes it once, and does so before its one write_config()
		$handler = substr($page, $saveGate, $title - $saveGate);
		$this->assertSame(1, substr_count($handler, "\$_POST['pfb_py_reply']"), 'the save reads the posted preference once');
		$this->assertSame(1, substr_count($handler, "PfbConfig::write('dnsbl/pfb_py_reply'"), 'and writes it once');
		$this->assertLessThan((int) strpos($handler, "write_config('[pfBlockerNG] save DNS settings')"), (int) strpos($handler, "PfbConfig::write('dnsbl/pfb_py_reply'"), 'before the write that saves it with the pfB-DNS settings');
	}
}
