<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4071 -- where the bouncer service is declared, applied and removed (docs/specs/crowdsec-integration.md, D4).
 *
 *   - pfblockerng.xml declares the service pfb_crowdsec, whose status is the bouncer's own pidfile;
 *   - pfBlockerNG's update pass applies the "should run" decision before its filter reload, and asks for that reload when the
 *     bouncer started or stopped, so that its rules follow: the pass runs after a master enable change, an XMLRPC receive (the
 *     receive marks pending changes and runs a tick) and an install or upgrade (the resync);
 *   - the installer applies it once the package's services are registered (start_service() acts only on a registered one);
 *   - removal stops the service and leaves no rc file, config file, status file or pidfile (the binaries are package files);
 *   - the Settings page is covered by the package's page privilege.
 *
 * The pass and the installer cannot run off-appliance, so their wiring is read from source; the teardown runs for real.
 */
#[CoversFunction('pfb_crowdsec_teardown')]
final class CrowdsecWiringTest extends TestCase
{
	private const PKG = __DIR__ . '/../../src/usr/local/pkg';

	private string $dir = '';
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_crowdsec_wiring_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['pfb_test_service_calls'] = [];
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		$GLOBALS['pfb'] = $this->savedPfb;
		unset($GLOBALS['pfb_test_service_calls']);
	}

	private static function source(string $path): string
	{
		$text = file_get_contents(self::PKG . "/{$path}");
		self::assertIsString($text, $path);
		return $text;
	}

	public function testThePackageDeclaresTheServiceWithTheBouncersPidfileAsItsStatus(): void
	{
		$xml = simplexml_load_string(self::source('pfblockerng.xml'));
		$this->assertNotFalse($xml);
		$found = [];
		foreach ($xml->service as $service) {
			if ((string) $service->name === 'pfb_crowdsec') {
				$found[] = [(string) $service->rcfile, (string) $service->custom_php_service_status_command, (string) $service->description];
			}
		}
		$this->assertSame([['pfb_crowdsec.sh', "isvalidpid('/var/run/pfb_crowdsec.pid')", 'pfBlockerNG CrowdSec bouncer']], $found);
	}

	public function testTheUpdatePassAppliesTheDecisionBeforeItsFilterReloadAndReloadsWhenTheBouncerStartedOrStopped(): void
	{
		$apply = self::source('pfblockerng/pfblockerng_apply.inc');
		$pass = substr($apply, (int) strpos($apply, 'function sync_package_pfblockerng('));
		$boot = strpos($pass, "if (is_platform_booting() || \$g['pfblockerng_install'])");
		$call = strpos($pass, 'if (pfb_crowdsec_apply()) {');
		$reload = strpos($pass, "if (\$pfb['filter_configure']) {");
		$this->assertNotFalse($boot);
		$this->assertNotFalse($call, 'the pass applies the decision');
		$this->assertNotFalse($reload);
		$this->assertGreaterThan($boot, $call, 'after the boot and install early return: the rc script and the installer own those');
		$this->assertLessThan($reload, $call, 'before the one filter reload of the pass');
		$this->assertSame(1, preg_match("~if \\(pfb_crowdsec_apply\\(\\)\\) \\{\\s*\\\$pfb\\['filter_configure'\\] = TRUE;\\s*\\}~", $pass),
			'a started or stopped bouncer reloads the filter');
		$this->assertSame(1, substr_count($apply, 'pfb_crowdsec_apply('), 'once per pass');
	}

	public function testTheInstallerAppliesTheDecisionOnceTheServicesAreRegistered(): void
	{
		$install = self::source('pfblockerng/pfblockerng_install.inc');
		$register = strpos($install, 'pfb_package_services_register(');
		$call = strpos($install, 'pfb_crowdsec_apply();');
		$this->assertNotFalse($register);
		$this->assertNotFalse($call, 'install and upgrade apply the decision');
		$this->assertGreaterThan($register, $call);
	}

	public function testRemovalTearsTheBouncerDown(): void
	{
		$inc = self::source('pfblockerng/pfblockerng.inc');
		$hook = substr($inc, (int) strpos($inc, 'function pfblockerng_php_pre_deinstall_command('));
		$this->assertStringContainsString('pfb_crowdsec_teardown();', substr($hook, 0, (int) strpos($hook, "\n}\n")));
	}

	/**
	 * An aborted removal puts back what pfSense took before the hook ran (pfb_package_removal_recover()): pfSense unlinked the rc
	 * script and stopped the service, so the recovery writes the script again and starts the bouncer when it should run.
	 */
	public function testAnAbortedRemovalRestoresTheBouncerWhenItShouldRun(): void
	{
		$inc = self::source('pfblockerng/pfblockerng.inc');
		$recover = substr($inc, (int) strpos($inc, 'function pfb_package_removal_recover('));
		$recover = substr($recover, 0, (int) strpos($recover, "\n}\n"));
		$this->assertStringContainsString("pfb_core_service();\n\t\tpfb_crowdsec_service();", $recover, 'the rc script is written with the others');
		$this->assertSame(1, preg_match("~if \\(pfb_crowdsec_should_run\\(\\) && !is_service_running\\('pfb_crowdsec'\\)\\) \\{\\s*start_service\\('pfb_crowdsec'\\);~", $recover),
			'and the bouncer starts only when its settings say it should run');
	}

	public function testTheTeardownStopsTheServiceAndRemovesEveryFileItOwns(): void
	{
		$files = [
			'crowdsec_rcfile'         => "{$this->dir}/pfb_crowdsec.sh",
			'crowdsec_config'         => "{$this->dir}/pfb_crowdsec.json",
			'crowdsec_status'         => "{$this->dir}/run_pfb_crowdsec.json",
			'crowdsec_pidfile'        => "{$this->dir}/pfb_crowdsec.pid",
			'crowdsec_daemon_pidfile' => "{$this->dir}/pfb_crowdsec_daemon.pid",
		];
		foreach ($files as $key => $path) {
			$GLOBALS['pfb'][$key] = $path;
			file_put_contents($path, "x\n");
		}
		file_put_contents("{$this->dir}/unrelated", "kept\n");

		pfb_crowdsec_teardown();

		$this->assertSame([['stop_service', 'pfb_crowdsec']], $GLOBALS['pfb_test_service_calls']);
		$this->assertSame(['unrelated'], array_values(array_diff(scandir($this->dir), ['.', '..'])));
	}

	/** @return list<string> the top row's links after the shared tail is added */
	private static function tail(?bool $provenance_ok, bool $software_allowed): array
	{
		$GLOBALS['pfb_test_allowed_pages'] = ['pkg_mgr_installed.php' => $software_allowed];
		$tabs = [[gettext('Sync'), FALSE, '/pfblockerng/pfblockerng_sync.php']];
		pfb_software_add_tab($tabs, FALSE, $provenance_ok);
		unset($GLOBALS['pfb_test_allowed_pages']);
		return array_column($tabs, 2);
	}

	public function testEveryTopRowGetsTheCrowdsecTabAfterSyncWhetherOrNotItShowsSoftware(): void
	{
		$this->assertSame(['/pfblockerng/pfblockerng_sync.php', '/pfblockerng/pfblockerng_crowdsec.php', '/pfblockerng/pfblockerng_software.php'],
			self::tail(TRUE, TRUE));
		$this->assertSame(['/pfblockerng/pfblockerng_sync.php', '/pfblockerng/pfblockerng_crowdsec.php'], self::tail(FALSE, TRUE));
		$this->assertSame(['/pfblockerng/pfblockerng_sync.php', '/pfblockerng/pfblockerng_crowdsec.php'], self::tail(TRUE, FALSE));

		$tabs = [];
		pfb_software_add_tab($tabs, FALSE, FALSE);
		$this->assertSame([['CrowdSec', FALSE, '/pfblockerng/pfblockerng_crowdsec.php']], $tabs, 'never the selected tab: its own page selects it');
	}

	public function testEveryPageWithATopRowAddsTheSharedTail(): void
	{
		// The GeoIP pages are generated from pfblockerng_geoip.inc's templates, and the ones on disk already call the tail
		$files = array_merge(glob(__DIR__ . '/../../src/usr/local/www/pfblockerng/*.php') ?: [], [self::PKG . '/pfblockerng/pfblockerng_geoip.inc']);
		$checked = 0;
		foreach ($files as $file) {
			$text = (string) file_get_contents($file);
			$rows = preg_match_all("~\\\$tab_array\\[\\]\\s*=\\s*array\\(gettext\\('Sync'\\)~", $text);
			if ($rows === 0) {
				continue;
			}
			$checked++;
			$this->assertSame($rows, substr_count($text, 'pfb_software_add_tab($tab_array'), basename($file) . ': every top row ends with the shared tail');
			$this->assertSame(0, preg_match("~\\\$tab_array\\[\\]\\s*=\\s*array\\(gettext\\('CrowdSec'\\)~", $text),
				basename($file) . ': the tab comes from the tail, never a copy');
		}
		$this->assertGreaterThanOrEqual(17, $checked, 'vacuity guard: the package pages were read');
	}

	public function testTheSettingsPageIsCoveredByThePackagePrivilege(): void
	{
		$priv = (string) file_get_contents(__DIR__ . '/../../src/etc/inc/priv/pfblockerng.priv.inc');
		$this->assertStringContainsString("\$priv_list['page-firewall-pfblockerng']['match'][] = \"pfblockerng/pfblockerng_crowdsec.php\";", $priv);
	}
}
