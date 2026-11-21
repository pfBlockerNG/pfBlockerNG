<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4071 -- where the bouncer service is declared, applied and removed (docs/specs/crowdsec-integration.md, D4).
 *
 *   - pfblockerng.xml declares the service pfb_crowdsec, whose status is the bouncer's own pidfile;
 *   - the installer applies it once the package's services are registered (start_service() acts only on a registered one);
 *   - removal stops the service and leaves no rc file, config file, status file or pidfile (the binaries are package files);
 *   - the Settings page is covered by the package's page privilege;
 *   - both CrowdSec pages print the same two tab rows (pfb_crowdsec_display_tabs()): pfBlockerNG's top row with the CrowdSec tab
 *     selected, the pending-changes box, and the Settings/Status subtabs with the page's own selected.
 *
 * The pass and the installer cannot run off-appliance, so their wiring is read from source; the teardown runs for real.
 */
#[CoversFunction('pfb_crowdsec_teardown')]
#[CoversFunction('pfb_crowdsec_display_tabs')]
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
		unset($GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_top_tabs'], $GLOBALS['pfb_test_info_boxes'], $GLOBALS['pfb_test_allowed_pages']);
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

	public function testTheInstallerAppliesTheDecisionOnceTheServicesAreRegistered(): void
	{
		$install = self::source('pfblockerng/pfblockerng_install.inc');
		$register = strpos($install, 'pfb_package_services_register(');
		$call = strpos($install, 'pfb_crowdsec_resync();');
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
			'crowdsec_lockfile'       => "{$this->dir}/pfb_crowdsec.lock",
			'crowdsec_binary_record'  => "{$this->dir}/pfb_crowdsec.sha256",
		];
		foreach ($files as $key => $path) {
			$GLOBALS['pfb'][$key] = $path;
			file_put_contents($path, "x\n");
		}
		// The pidfiles are the stop's (as Core's): it removes them once nothing runs, and keeps them when a survivor does (#4135)
		foreach (['crowdsec_pidfile' => 'pfb_crowdsec.pid', 'crowdsec_daemon_pidfile' => 'pfb_crowdsec_daemon.pid'] as $key => $name) {
			$GLOBALS['pfb'][$key] = "{$this->dir}/{$name}";
			file_put_contents("{$this->dir}/{$name}", "x\n");
		}
		file_put_contents("{$this->dir}/unrelated", "kept\n");
		// The per-origin decision files (#4164)
		$GLOBALS['pfb']['crowdsec_decisions'] = "{$this->dir}/decisions";
		mkdir("{$this->dir}/decisions");
		file_put_contents("{$this->dir}/decisions/CAPI.txt", "192.0.2.7\n");

		pfb_crowdsec_teardown();

		$this->assertSame([['stop_service', 'pfb_crowdsec']], $GLOBALS['pfb_test_service_calls']);
		$this->assertEqualsCanonicalizing(['pfb_crowdsec.pid', 'pfb_crowdsec_daemon.pid', 'unrelated'], array_values(array_diff(scandir($this->dir), ['.', '..'])),
			'the teardown removes every file it owns and leaves the pidfiles to the stop');
	}

	public function testTheTeardownRemovesTheConfigFileBeforeItStopsSoAStartInBetweenStartsNothing(): void
	{
		$GLOBALS['pfb']['crowdsec_config'] = "{$this->dir}/pfb_crowdsec.json";
		file_put_contents($GLOBALS['pfb']['crowdsec_config'], "{}\n");
		$seen = [];
		$GLOBALS['pfb_test_service_hook'] = static function (string $fn) use (&$seen): void {
			$seen[] = [$fn, is_file($GLOBALS['pfb']['crowdsec_config'])];
		};

		pfb_crowdsec_teardown();
		unset($GLOBALS['pfb_test_service_hook']);

		$this->assertSame([['stop_service', FALSE]], $seen, 'the rc start\'s gate is gone before the stop runs');
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
		// and the CrowdSec pages' shared helper holds their row
		$files = array_merge(glob(__DIR__ . '/../../src/usr/local/www/pfblockerng/*.php') ?: [],
		    [self::PKG . '/pfblockerng/pfblockerng_geoip.inc', self::PKG . '/pfblockerng/pfblockerng_crowdsec.inc']);
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

	/** @return iterable<string, array{string, string, string, bool}> the page, its selected subtab's name, the Alerts default view, whether changes are pending */
	public static function tabRows(): iterable
	{
		yield 'Settings'                    => ['/pfblockerng/pfblockerng_crowdsec.php', 'Settings', '', FALSE];
		yield 'Status'                      => ['/pfblockerng/pfblockerng_crowdsec_status.php', 'Status', '', FALSE];
		yield 'Settings, a default view, pending changes' => ['/pfblockerng/pfblockerng_crowdsec.php', 'Settings', 'unified', TRUE];
		yield 'Status, a default view, pending changes'   => ['/pfblockerng/pfblockerng_crowdsec_status.php', 'Status', 'unified', TRUE];
	}

	#[DataProvider('tabRows')]
	public function testBothPagesPrintTheTopRowThePendingBoxAndTheirSubtabsInThatOrder(string $page, string $subtab, string $view, bool $pending): void
	{
		$GLOBALS['pfb']['config_global'] = $view === '' ? [] : ['pfbpageload' => $view];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		if ($pending) {
			file_put_contents($GLOBALS['pfb']['pending_marker'], 'v1');
		}
		$GLOBALS['pfb_test_top_tabs'] = [];
		$GLOBALS['pfb_test_info_boxes'] = [];
		$GLOBALS['pfb_test_allowed_pages'] = ['pkg_mgr_installed.php' => FALSE];

		pfb_crowdsec_display_tabs($page);

		$top = [['General', FALSE, '/pfblockerng/pfblockerng_general.php'], ['IP', FALSE, '/pfblockerng/pfblockerng_ip.php'],
			['DNS', FALSE, '/pfblockerng/pfblockerng_dns_general.php'], ['Update', FALSE, '/pfblockerng/pfblockerng_update.php'],
			['Reports', FALSE, '/pfblockerng/pfblockerng_alerts.php' . ($view === '' ? '' : "?view={$view}")],
			['Feeds', FALSE, '/pfblockerng/pfblockerng_feeds.php'], ['Logs', FALSE, '/pfblockerng/pfblockerng_log.php'],
			['Sync', FALSE, '/pfblockerng/pfblockerng_sync.php'], ['CrowdSec', TRUE, '/pfblockerng/pfblockerng_crowdsec.php']];
		$sub = [['Settings', $subtab === 'Settings', '/pfblockerng/pfblockerng_crowdsec.php'],
			['Status', $subtab === 'Status', '/pfblockerng/pfblockerng_crowdsec_status.php']];
		// Each row with the number of info boxes shown before it: the pending-changes box sits between the rows
		$this->assertSame([[$top, 0], [$sub, $pending ? 1 : 0]], $GLOBALS['pfb_test_top_tabs']);
		$this->assertCount($pending ? 1 : 0, $GLOBALS['pfb_test_info_boxes']);
	}

	public function testEachPageHandsItsOwnPageToTheTabHelperAfterAnyInputErrors(): void
	{
		$www = __DIR__ . '/../../src/usr/local/www/pfblockerng';
		$settings = (string) file_get_contents("{$www}/pfblockerng_crowdsec.php");
		$status = (string) file_get_contents("{$www}/pfblockerng_crowdsec_status.php");

		$this->assertSame(1, substr_count($settings, 'pfb_crowdsec_display_tabs(PFB_CROWDSEC_PAGE);'));
		$this->assertSame(1, substr_count($status, 'pfb_crowdsec_display_tabs(PFB_CROWDSEC_STATUS_PAGE);'));
		$this->assertSame(0, substr_count($settings . $status, 'display_top_tabs('), 'the rows are printed by the helper only');
		$this->assertLessThan(strpos($settings, 'pfb_crowdsec_display_tabs('), strpos($settings, 'print_input_errors('),
		    'the Settings page prints its input errors above the tabs');
	}

	public function testTheSettingsPageIsCoveredByThePackagePrivilege(): void
	{
		$priv = (string) file_get_contents(__DIR__ . '/../../src/etc/inc/priv/pfblockerng.priv.inc');
		$this->assertStringContainsString("\$priv_list['page-firewall-pfblockerng']['match'][] = \"pfblockerng/pfblockerng_crowdsec.php\";", $priv);
	}

	public function testTheStatusPageAndItsQueriesAreCoveredByThePackagePrivilege(): void
	{
		// issue #4073: the Status subtab pages its tables and runs its lookup through the query string
		$priv = (string) file_get_contents(__DIR__ . '/../../src/etc/inc/priv/pfblockerng.priv.inc');
		$this->assertStringContainsString("\$priv_list['page-firewall-pfblockerng']['match'][] = \"pfblockerng/pfblockerng_crowdsec_status.php*\";", $priv);
	}
}
