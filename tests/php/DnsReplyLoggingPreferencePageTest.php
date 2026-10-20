<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- DNS Reply Logging is ONE preference (dnsbl/pfb_py_reply, unchanged path and default) that both DNS modes
 * read: the DNSBL module's ini (python_reply) and, with DNSBL off, the pfB-DNS proxy's --reply-log. Its control therefore
 * lives on the pfB-DNS page, which is reachable in either mode, and no longer on the DNSBL page.
 *
 * The pages are scripts that render on include, so the contract is pinned in their source (like DnsProxySettingsSaveTest):
 *   - the pfB-DNS page renders the checkbox from the stored preference and saves it through the gateway, under the config
 *     lock and in the same write_config() as its own toggle, so the two cannot be saved apart;
 *   - the DNSBL page neither renders nor assigns it: its section save writes the section it read afresh under the config
 *     lock (DnsblSettingsSaveRaceTest), so a key it never assigns keeps what the pfB-DNS page stored, even from a save
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

	public function testThePfbDnsPageRendersTheStoredPreferenceAsTheDnsReplyLoggingCheckbox(): void
	{
		$page = self::page('pfblockerng_dns.php');

		$this->assertStringContainsString("\$pconfig['pfb_py_reply'] = PfbConfig::read('dnsbl/pfb_py_reply');", $page, 'reads the one existing key');
		$this->assertSame(1, preg_match("~new Form_Checkbox\\( 'pfb_py_reply', gettext\\('DNS Reply Logging'\\), 'Enable', pfb_dnsbl_toggle_enabled\\(\\\$pconfig\\['pfb_py_reply'\\] \\?\\? NULL\\), 'on' \\)~", $page), 'the checkbox the DNSBL page had, default-on reading included');
	}

	public function testTheDnsblPageNeitherRendersNorAssignsThePreference(): void
	{
		$page = self::page('pfblockerng_dnsbl.php');

		$this->assertStringNotContainsString('pfb_py_reply', $page, 'no control, no read, no write: its save keeps what the pfB-DNS page stored');
		$this->assertStringContainsString("\$pfb['dconfig']['pfb_hsts']", $page, 'bystander: the sibling toggle is still this page\'s own');
	}
}
