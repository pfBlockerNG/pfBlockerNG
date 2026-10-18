<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the DNSBL settings page replaces the whole pfblockerngdnsblsettings section from the snapshot
 * of it taken when the page loaded. pfb_dns_proxy_resolver() writes the Resolver snapshot marker
 * (pfb_dns_proxy_saved) into that same section from the apply, which can finish between the page's read and its
 * write; the write would then erase the marker while the Resolver is still moved, and the Resolver could never be
 * put back. The page therefore takes the named config lock pfb_dns_proxy_resolver() takes (pfb_dnsbl_config_lock():
 * bounded, and config.xml is read afresh under it), re-reads the marker into its snapshot as the last step before
 * the section write, and holds the lock through write_config(). A lock that stays taken is an input error: the
 * settings are not saved and the form comes back with the admin's input.
 *
 * The page is a script that renders on include, so the ordering is pinned in its source; the lock itself and the
 * Resolver side are exercised by DnsProxyConfigLockTest.
 */
final class DnsProxySettingsSaveTest extends TestCase
{
	private const SECTION_WRITE = "PfbConfig::writeSection('installedpackages/pfblockerngdnsblsettings/config/0', \$pfb['dconfig']);";
	private const MARKER_REREAD = "\$pfb['dconfig']['pfb_dns_proxy_saved'] = PfbConfig::read('dnsbl/pfb_dns_proxy_saved');";
	private const LOCK_TAKEN = "\$pfb_config_lock = pfb_dnsbl_config_lock();";
	private const SAVE = "write_config('[pfBlockerNG] save DNSBL settings');";

	private static function page(): string
	{
		return php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
	}

	public function testThePageReReadsTheResolverSnapshotMarkerRightBeforeItWritesTheSection(): void
	{
		$page = self::page();

		$this->assertSame(1, substr_count($page, self::SECTION_WRITE), 'test bootstrap: the page writes the section once');
		$this->assertStringContainsString(
			self::MARKER_REREAD . ' ' . self::SECTION_WRITE,
			$page,
			'the marker is refreshed in the same statement run as the section write, with nothing in between'
		);
	}

	public function testThePageHoldsTheConfigLockFromBeforeTheMarkerReReadThroughWriteConfig(): void
	{
		$page = self::page();

		$this->assertSame(1, substr_count($page, self::LOCK_TAKEN), 'the page takes the config lock once');
		$lock = (int) strpos($page, self::LOCK_TAKEN);
		$reread = (int) strpos($page, self::MARKER_REREAD);
		$this->assertLessThan($reread, $lock, 'the lock is taken (and config.xml read afresh) before the marker is read');

		$this->assertSame(1, substr_count($page, self::SAVE), 'test bootstrap: the page saves once');
		$this->assertStringContainsString(
			self::SAVE . ' unlock($pfb_config_lock);',
			$page,
			'the lock is released right after write_config(), so it covers the section write and the registered-field writes'
		);
		$this->assertSame(1, substr_count($page, 'unlock($pfb_config_lock);'), 'one release');
		$this->assertLessThan((int) strpos($page, "header('Location: /pfblockerng/pfblockerng_dnsbl.php');"), (int) strpos($page, 'unlock($pfb_config_lock);'),
			'released before the redirect and exit');
	}

	public function testALockThatStaysTakenIsAnInputErrorThatSavesNothing(): void
	{
		$page = self::page();

		// The lock is taken only when validation passed, and a NULL (another save holds it) joins the input errors
		// that make the page skip the save and render the form again.
		$this->assertStringContainsString(
			'if (!$input_errors) { $pfb_config_lock = pfb_dnsbl_config_lock(); if ($pfb_config_lock === NULL) { $input_errors[] =',
			$page
		);
		$gate = strpos($page, 'if ($pfb_config_lock === NULL) { $input_errors[] =');
		$save = strpos($page, 'if (!$input_errors) {', (int) $gate);
		$this->assertNotFalse($save, 'the save block follows, gated on the input errors again');
		$this->assertLessThan((int) strpos($page, self::SECTION_WRITE), (int) $save, 'and the section is written inside it');
	}
}
