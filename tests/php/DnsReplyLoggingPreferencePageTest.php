<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- DNS Reply Logging is ONE preference (dnsbl/pfb_py_reply, unchanged path and default) that both DNS modes
 * read: the DNSBL module's ini (python_reply) and, with DNSBL off, the pfB-DNS proxy's --reply-log. Its control therefore
 * lives on DNS General, which is reachable in either mode, and no longer on either mode-specific page. The pfB-DNS settings are a
 * second form on that same page (issue #3771), so the contract is also that this form and its save leave the preference alone.
 *
 * The pages are scripts that render on include, so the contract is pinned in their source (like DnsProxySettingsSaveTest):
 *   - DNS General renders the checkbox from the stored preference and saves it through the gateway, under the config
 *     lock and in the same write_config() as its resolver VIP settings;
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

	public function testTheDnsGeneralPageHoldsTheOnlyReplyLoggingCheckboxAndThePfbDnsFormAndItsSaveNeverTouchThePreference(): void
	{
		$page = self::page('pfblockerng_dns_general.php');
		$saveGate = self::offsetOf("~isset\\(\\\$_POST\\['save_pfb_dns'\\]\\)~", $page);
		$generalSave = self::offsetOf("~if \\(\\\$_POST && isset\\(\\\$_POST\\['save'\\]\\)\\)~", $page);
		$formOne = self::offsetOf("~new Form_Button\\(\\s*'save_pfb_dns'~", $page);
		$formTwo = self::offsetOf("~new Form\\(\\s*'Save DNS General settings'\\s*\\)~", $page);
		$this->assertNotNull($saveGate, 'the pfB-DNS save is gated on its own button, save_pfb_dns');
		$this->assertNotNull($generalSave, 'the DNS General save is gated on its own button, save');
		$this->assertNotNull($formOne, 'the pfB-DNS form has its own save button');
		$this->assertNotNull($formTwo, 'the DNS General form follows it');
		$this->assertLessThan($generalSave, $saveGate, 'the pfB-DNS save handler comes before the DNS General one');
		$this->assertLessThan($formTwo, $formOne, 'the pfB-DNS form comes before the DNS General form');

		// The single control is the DNS General form's own
		$checkboxes = (int) preg_match_all("~new Form_Checkbox\\(\\s*'pfb_py_reply'~", $page, $found, PREG_OFFSET_CAPTURE);
		$this->assertSame(1, $checkboxes, 'exactly one DNS Reply Logging checkbox');
		$this->assertGreaterThan($formTwo, $found[0][0][1], 'and it is in the DNS General form, not the pfB-DNS one');

		// Neither the pfB-DNS save handler nor the pfB-DNS form reads, assigns or posts the preference
		$this->assertStringNotContainsString('pfb_py_reply', substr($page, $saveGate, $generalSave - $saveGate), 'the pfB-DNS save never reads or writes it');
		$this->assertStringNotContainsString('pfb_py_reply', substr($page, $formOne, $formTwo - $formOne), 'the pfB-DNS form has no control for it');
	}
}
