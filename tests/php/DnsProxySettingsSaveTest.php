<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the pfB-DNS page saves the enable toggle into the pfblockerngdns section, which also holds the
 * Resolver snapshot marker (pfb_dns_saved) pfb_dns_proxy_resolver() writes from the apply. Both read-modify-write
 * config.xml from the copy their own process read at start (write_config() writes that whole copy back), so the page
 * takes the named config lock pfb_dns_proxy_resolver() takes (pfb_dns_config_lock(): bounded, config.xml read afresh
 * under it) and holds it through write_config(). It writes the one leaf it owns, never the section, so the marker it
 * does not render is carried through untouched. A lock that stays taken is an input error: nothing is saved and the
 * form comes back.
 *
 * The page is a script that renders on include, so the ordering is pinned in its source; the lock itself and the
 * Resolver side are exercised by DnsProxyConfigLockTest.
 */
final class DnsProxySettingsSaveTest extends TestCase
{
	private const TOGGLE_WRITE = "PfbConfig::write('dns/pfb_dns', \$pfb_dns);";
	private const LOCK_TAKEN = "\$pfb_config_lock = pfb_dns_config_lock();";
	private const SAVE = "write_config('[pfBlockerNG] save pfB-DNS settings');";

	private static function page(): string
	{
		return php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dns.php');
	}

	public function testThePageWritesOnlyItsOwnToggleLeafAndNeverTheSectionThatHoldsTheSnapshotMarker(): void
	{
		$page = self::page();

		$this->assertSame(1, substr_count($page, self::TOGGLE_WRITE), 'the page writes the toggle once, through the gateway');
		$this->assertStringNotContainsString('writeSection', $page, 'a section write would replace the marker the page does not carry');
		$this->assertStringNotContainsString('pfb_dns_saved', $page, 'the marker is not the page\'s to touch');
	}

	public function testThePageHoldsTheConfigLockFromBeforeTheToggleWriteThroughWriteConfig(): void
	{
		$page = self::page();

		$this->assertSame(1, substr_count($page, self::LOCK_TAKEN), 'the page takes the config lock once');
		$lock = (int) strpos($page, self::LOCK_TAKEN);
		$write = (int) strpos($page, self::TOGGLE_WRITE);
		$this->assertLessThan($write, $lock, 'the lock is taken (and config.xml read afresh) before the toggle is written');

		$this->assertSame(1, substr_count($page, self::SAVE), 'test bootstrap: the page saves once');
		$this->assertStringContainsString(
			self::TOGGLE_WRITE . ' ' . self::SAVE . ' unlock($pfb_config_lock);',
			$page,
			'the lock is released right after write_config(), so it covers the toggle write and the save'
		);
		$this->assertSame(1, substr_count($page, 'unlock($pfb_config_lock);'), 'one release');
		$this->assertLessThan((int) strpos($page, "header('Location: /pfblockerng/pfblockerng_dns.php');"), (int) strpos($page, 'unlock($pfb_config_lock);'),
			'released before the redirect and exit');
	}

	public function testALockThatStaysTakenIsAnInputErrorThatSavesNothing(): void
	{
		$page = self::page();

		// A NULL (another save holds it) joins the input errors that make the page skip the save and render the form
		// again; the write sits behind the input-error gate.
		$this->assertStringContainsString(
			self::LOCK_TAKEN . ' if ($pfb_config_lock === NULL) { $input_errors[] =',
			$page
		);
		$gate = strpos($page, 'if ($pfb_config_lock === NULL) { $input_errors[] =');
		$save = strpos($page, 'if (!$input_errors) {', (int) $gate);
		$this->assertNotFalse($save, 'the save block follows, gated on the input errors again');
		$this->assertLessThan((int) strpos($page, self::TOGGLE_WRITE), (int) $save, 'and the toggle is written inside it');
	}
}
