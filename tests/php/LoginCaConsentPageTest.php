<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_login_ca_consent_save')]
final class LoginCaConsentPageTest extends TestCase
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

	// The section always renders now (no "was it shown" marker), so an absent checkbox
	// in the POST is the explicit Off token -- exactly like pfb_software_check's save.
	public function testSaveAlwaysPersistsAnExplicitOffOrOnToken(): void
	{
		PfbConfig::write('gen/pfb_pkg_ca_consent', PfbToggle::On);
		$this->assertSame('', pfb_login_ca_consent_save([]));
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_pkg_ca_consent'));
		$this->assertSame('on', pfb_login_ca_consent_save(['pfb_pkg_ca_consent' => 'on']));
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_pkg_ca_consent'));
	}

	public function testPagePersistsBeforeHookAndAlwaysRendersTheSection(): void
	{
		$source = (string) file_get_contents(self::PAGE);
		$save = substr($source, strpos($source, 'if ($_POST && isset($_POST[\'save\'])) {'));
		$save = substr($save, 0, strpos($save, '// "Check now"'));
		$read = strpos($save, '$pfb_ca_was_consented =');
		$persist = strpos($save, '$pfb_ca_token = pfb_login_ca_consent_save($_POST);');
		$flush = strpos($save, "write_config('[pfBlockerNG] save Software settings');");
		$apply = strpos($save, 'pfb_login_ca_apply($pfb_ca_token, $pfb_ca_was_consented)');
		$this->assertNotFalse($read);
		$this->assertNotFalse($persist);
		$this->assertNotFalse($flush);
		$this->assertNotFalse($apply);
		$this->assertTrue($read < $persist && $persist < $flush && $flush < $apply);

		// The Plus-only render gate and the "was it shown" marker are both gone -- the
		// section is unconditional now.
		$this->assertStringNotContainsString('pfb_pkg_ca_is_plus', $source);
		$this->assertStringNotContainsString('pfb_pkg_ca_consent_shown', $source);
		$this->assertStringContainsString("'pfb_pkg_ca_consent'", $source);
		$this->assertStringContainsString('/etc/login.conf', $source);
	}

	public function testCronHasNoSecondLoginConfWriter(): void
	{
		$source = (string) file_get_contents(self::CRON);
		$this->assertStringContainsString('pfb_software_update_check();', $source);
		$this->assertStringNotContainsString('login_ca', $source);
		$this->assertStringNotContainsString('login.conf', $source);
	}

	// issue #2617: the login.conf editor lives in the installed rc.d hook (outside src/,
	// so out of this sweep's reach) and its consent-write path is the Software page above
	// -- nothing else under src/ should reference the literal path.
	public function testNothingOutsideTheSoftwarePageReferencesTheLoginConfPath(): void
	{
		$root = dirname(__DIR__, 2) . '/src';
		$page = realpath(self::PAGE);
		$hits = [];
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
		);
		foreach ($iterator as $file) {
			if (!$file->isFile()) {
				continue;
			}
			$path = (string) $file->getPathname();
			if ($path === $page) {
				continue;
			}
			$text = (string) file_get_contents($path);
			if (str_contains($text, '/etc/login.conf')) {
				$hits[] = $path;
			}
		}
		$this->assertSame([], $hits);
	}
}
