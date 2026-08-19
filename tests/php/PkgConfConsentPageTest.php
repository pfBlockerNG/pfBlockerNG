<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_pkgconf_ca_save')]
final class PkgConfConsentPageTest extends TestCase
{
	private const PAGE = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_software.php';
	private const CRON = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';
	private bool $hadConfig;
	private mixed $originalConfig;

	protected function setUp(): void
	{
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_allowed_pages'] = ['pkg_mgr_installed.php' => TRUE];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_allowed_pages']);
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	public function testSavePersistsOnlyWhenThePlusControlWasRendered(): void
	{
		PfbConfig::write('gen/pfb_pkg_ca_consent', PfbToggle::On);
		$this->assertSame('on', pfb_pkgconf_ca_save([]));
		$this->assertSame('', pfb_pkgconf_ca_save(['pfb_pkg_ca_consent_shown' => '1']));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_pkg_ca_consent'));
		$this->assertSame('on', pfb_pkgconf_ca_save([
			'pfb_pkg_ca_consent_shown' => '1',
			'pfb_pkg_ca_consent' => 'on',
		]));
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_pkg_ca_consent'));
	}

	public function testPagePersistsBeforeHookAndRendersOnlyForPlus(): void
	{
		$source = (string) file_get_contents(self::PAGE);
		$save = substr($source, strpos($source, 'if ($_POST && isset($_POST[\'save\'])) {'));
		$save = substr($save, 0, strpos($save, '// "Check now"'));
		$read = strpos($save, '$pfb_ca_was_consented =');
		$persist = strpos($save, '$pfb_ca_token = pfb_pkgconf_ca_save($_POST);');
		$flush = strpos($save, "write_config('[pfBlockerNG] save Software settings');");
		$apply = strpos($save, 'pfb_pkgconf_ca_apply($pfb_ca_token, $pfb_ca_was_consented)');
		$this->assertNotFalse($read);
		$this->assertNotFalse($persist);
		$this->assertNotFalse($flush);
		$this->assertNotFalse($apply);
		$this->assertTrue($read < $persist && $persist < $flush && $flush < $apply);
		$this->assertStringContainsString('$pfb_ca_plus = pfb_pkg_ca_is_plus();', $source);
		$this->assertStringContainsString('if ($pfb_ca_plus) {', $source);
		$this->assertStringContainsString("'pfb_pkg_ca_consent_shown'", $source);
		$this->assertStringContainsString('before package operations', $source);
	}

	public function testCronHasNoSecondPkgConfWriter(): void
	{
		$source = (string) file_get_contents(self::CRON);
		$this->assertStringContainsString('pfb_software_update_check();', $source);
		$this->assertStringNotContainsString('pfb_pkgconf_ca_tick', $source);
	}
}
