<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNSBL settings page replaces the whole pfblockerngdnsblsettings section from the snapshot
 * of it taken when the page loaded. pfb_dns_proxy_resolver() writes the Resolver snapshot marker
 * (pfb_dns_proxy_saved) into that same section from the apply, which can finish between the page's read and its
 * write; the write would then erase the marker while the Resolver is still moved, and the Resolver could never be
 * put back. The page therefore re-reads the marker into its snapshot as the last step before the section write.
 *
 * The page is a script that renders on include, so the ordering is pinned in its source.
 */
final class DnsProxySettingsSaveTest extends TestCase
{
	private const SECTION_WRITE = "PfbConfig::writeSection('installedpackages/pfblockerngdnsblsettings/config/0', \$pfb['dconfig']);";
	private const MARKER_REREAD = "\$pfb['dconfig']['pfb_dns_proxy_saved'] = PfbConfig::read('dnsbl/pfb_dns_proxy_saved');";

	public function testThePageReReadsTheResolverSnapshotMarkerRightBeforeItWritesTheSection(): void
	{
		$page = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');

		$this->assertSame(1, substr_count($page, self::SECTION_WRITE), 'test bootstrap: the page writes the section once');
		$this->assertStringContainsString(
			self::MARKER_REREAD . ' ' . self::SECTION_WRITE,
			$page,
			'the marker is refreshed in the same statement run as the section write, with nothing in between'
		);
	}
}
