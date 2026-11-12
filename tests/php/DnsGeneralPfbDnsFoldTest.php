<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3771 -- the pfB-DNS enable and all its settings (DoT, DoH, DoQ, DDR) moved from DNS > pfB-DNS onto DNS > General. The pfB-DNS
 * subtab is gone and pfblockerng_dns.php only redirects to DNS > General. Stored keys and save semantics did not change.
 * issue #3856 -- DNS > General is ONE form with ONE "Save DNS settings" button; the settings of the two forms it replaced are saved together.
 *
 * Verification rows (the live UI half of each is tests/smoke/ui):
 *   V1 DNS > General shows the pfB-DNS enable, the DoT/DoH/DoQ/DDR sections, DNS Reply Logging and the Resolver addresses in one form with one
 *      submit button; one save writes the same keys the two old saves wrote, in one write_config(), or writes nothing when any field is invalid.
 *   V2 no page prints a pfB-DNS subtab; the old page's URL survives only in the privilege and the GeoIP navigation migration.
 *   V3 requesting pfblockerng_dns.php ends on DNS > General.
 *   V4 the DDR check endpoint and its refresh script now live on DNS > General.
 *
 * The pages render and exit, so their source is pinned; the saves are executed: support/DnsSaveWorker.php runs the page's real POST
 * region (the one handler, validation included) over the doubles in a child process, as a browser posts the form.
 */
final class DnsGeneralPfbDnsFoldTest extends TestCase
{
	private const WWW = __DIR__ . '/../../src/usr/local/www/pfblockerng/';
	private const SRC = __DIR__ . '/../../src/';
	private const DNS_GENERAL = 'pfblockerng_dns_general.php';
	private const SAVE = '[pfBlockerNG] save DNS settings';
	private const VIP_ONLY_REFUSAL = 'VIP-only mode requires pfB-DNS and Resolver addresses enabled';
	/** The DNS General fields a browser posts with VIP-only mode on: Resolver addresses on, a VIP created automatically. */
	private const VIP_ONLY_FORM = ['pfb_dns_listen_vip' => 'on', 'pfb_dns_listen_vip4' => 'auto', 'pfb_dns_listen_vip_only' => 'on'];

	/** The only sources that may still name the old page's URL: the privilege and the legacy GeoIP rows (both MATCH old pages), and the redirect stub itself. */
	private const OLD_URL_ALLOWED = [
		'etc/inc/priv/pfblockerng.priv.inc',
		'usr/local/pkg/pfblockerng/pfblockerng_geoip.inc',
		'usr/local/www/pfblockerng/pfblockerng_dns.php',
	];

	private static function page(string $name = self::DNS_GENERAL): string
	{
		$source = file_get_contents(self::WWW . $name);
		self::assertIsString($source, "cannot read {$name}");
		return $source;
	}

	/**
	 * The offsets of these patterns, each found after the one before it.
	 *
	 * @param list<string> $patterns
	 * @return list<int>
	 */
	private static function inOrder(string $page, array $patterns, string $what): array
	{
		$from = 0;
		$offsets = [];
		foreach ($patterns as $pattern) {
			$found = preg_match($pattern, $page, $match, PREG_OFFSET_CAPTURE, $from);
			self::assertSame(1, $found, "{$what}: {$pattern} follows the previous marker");
			$offsets[] = $from = (int) $match[0][1] + 1;
		}
		return array_map(static fn (int $offset): int => $offset - 1, $offsets);
	}

	/** A page is large: a failure names the missing text, it does not print the whole source. */
	private function assertHas(string $needle, string $source, string $why): void
	{
		$this->assertTrue(str_contains($source, $needle), "{$why}: expected to find `{$needle}`");
	}

	private function assertLacks(string $needle, string $source, string $why): void
	{
		$this->assertFalse(str_contains($source, $needle), "{$why}: found `{$needle}`");
	}

	/** @param array<mixed> $tree @return array<string,mixed> every leaf of a config tree by its path */
	private static function leaves(array $tree, string $path = ''): array
	{
		$leaves = [];
		foreach ($tree as $key => $value) {
			$here = $path === '' ? (string) $key : "{$path}/{$key}";
			$leaves += is_array($value) ? self::leaves($value, $here) : [$here => $value];
		}
		return $leaves;
	}

	/** @return list<string> the leaf paths that are new, gone or different in $after */
	private static function changedLeaves(array $before, array $after): array
	{
		$was = self::leaves($before);
		$now = self::leaves($after);
		$changed = [];
		foreach ($was + $now as $path => $_) {
			if (!array_key_exists($path, $was) || !array_key_exists($path, $now) || $was[$path] !== $now[$path]) {
				$changed[] = $path;
			}
		}
		sort($changed);
		return $changed;
	}

	private static function at(array $config, string $path): mixed
	{
		return self::leaves($config)[$path] ?? NULL;
	}

	/** The config.xml path of a registry key such as `gen/pfb_dns_listen_vip`. */
	private static function path(string $registryKey): string
	{
		[$alias, $bare] = explode('/', $registryKey, 2);
		return PFB_SECTIONS[$alias] . "/{$bare}";
	}

	/**
	 * The page's whole POST region run in a child process: the complete form a browser posts, shaped by $case (see support/DnsSaveWorker.php).
	 *
	 * @param array<string,mixed> $case `stored`: registry key => value config.xml holds; `post`: field => value posted (NULL: not posted)
	 * @return array<string,mixed> the worker's result: before, disk, posted, pconfig, writes, inputErrors, pendingMarked, returned, lockHeld
	 */
	private function runSave(array $case = []): array
	{
		$dir = sys_get_temp_dir() . '/pfb_dns_fold_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/DnsSaveWorker.php', 'plain', $result, json_encode($case, JSON_THROW_ON_ERROR | JSON_FORCE_OBJECT)], 60.0);
			$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}");
			$this->assertStringNotContainsString('worker:', $process['stdout'] . $process['stderr'], 'the worker found the save region on DNS General');
			return json_decode((string) file_get_contents($result), TRUE, 512, JSON_THROW_ON_ERROR);
		} finally {
			@unlink($result);
			@rmdir($dir);
		}
	}

	/** A save that was refused: no write, config.xml as it was, the page rendered again with its error instead of a redirect. */
	private function assertNothingSaved(array $result): void
	{
		$this->assertSame([], $result['writes'], 'no write_config() for a refused save');
		$this->assertSame($result['before'], $result['disk'], 'config.xml is exactly as it was');
		$this->assertFalse($result['pendingMarked'], 'a refused save marks no pending change');
		$this->assertTrue($result['returned'], 'the page renders its errors instead of redirecting');
		$this->assertFalse($result['lockHeld'], 'the config lock is released');
	}

	// -----------------------------------------------------------------------
	// V1: the page, as source
	// -----------------------------------------------------------------------

	public function testDnsGeneralHoldsOneFormWithOneSaveDnsSettingsButtonAndItsSevenSectionsInOrder(): void
	{
		$page = self::page();

		$this->assertSame(1, preg_match_all('/new Form\(/', $page), 'one form');
		self::inOrder($page, [
			"/\\\$form = new Form\\('Save DNS settings'\\);/",
			"/new Form_Section\\('pfB-DNS Settings'\\)/",
			"/new Form_Section\\('DNS over TLS \\(DoT\\)'\\)/",
			"/new Form_Section\\('DNS over HTTPS \\(DoH\\)'\\)/",
			"/new Form_Section\\('DNS over QUIC \\(DoQ\\)'\\)/",
			"/new Form_Section\\('Discovery of Designated Resolvers \\(DDR\\)'\\)/",
			"/new Form_Section\\('DNS Reply Logging'\\)/",
			"/new Form_Section\\('Resolver addresses'\\)/",
			'/print \(\$form\);/',
			'/pfb_dns_status_panel\(/',
			"/include\\('foot\\.inc'\\);/",
		], 'the page');
		$this->assertSame(1, substr_count($page, 'print ($form);'), 'the one form is printed once');
		$this->assertLacks('save_pfb_dns', $page, 'the pfB-DNS form and its own button are gone');
		$this->assertLacks('Form_Button(', $page, 'the save button is the default one of the form');
		$this->assertLacks('Save DNS General settings', $page, 'there is no second form');
		$this->assertSame(1, substr_count($page, "'pfb_dns',"), 'the pfB-DNS enable checkbox is on this page once');
	}

	public function testOneHandlerGatedOnTheSaveButtonSavesBothPartsUnderOneConfigLockInOneWrite(): void
	{
		$page = self::page();

		$this->assertSame(1, substr_count($page, '$input_errors = array();'), 'one error list');
		$this->assertSame(1, substr_count($page, "isset(\$_POST['save'])"), 'one handler');
		[, , , $gate, $title] = self::inOrder($page, [
			"/\\\$_GET\\['ajax'\\] \\?\\? ''\\) === 'ddr'/",	// the DDR endpoint answers before anything else loads
			'/pfb_dns_proxy_seed_values\(\) !== \[\]/',
			'/\$pconfig = array\(\);/',
			"/\\\$input_errors = array\\(\\);\\s*if \\(\\\$_POST && isset\\(\\\$_POST\\['save'\\]\\)\\) \\{/",
			'/\$pgtitle = /',
		], 'the page top');

		$handler = substr($page, $gate, $title - $gate);
		self::inOrder($handler, [
			'/pfb_validate_dns_proxy_listeners_post\(/',
			'/pfb_dns_config_lock\(\)/',
			'/pfb_dns_proxy_listeners_stored\(\$_POST\)/',
			'/pfb_validate_dns_listen_vip_only_post\(\$pconfig\)/',
			"/write_config\\('/",
			'/pfb_mark_pending_changes\(\)/',
			"/header\\('Location: \\/pfblockerng\\/pfblockerng_dns_general\\.php'\\);/",
		], 'the handler');
		$this->assertSame(1, substr_count($handler, 'pfb_dns_config_lock()'), 'the config lock is taken once, for both parts');
		$this->assertSame(1, substr_count($handler, "write_config('"), 'one write for both parts');
		$this->assertHas("write_config('" . self::SAVE . "')", $handler, 'the one write has the one description');
		$this->assertSame(1, substr_count($handler, "header('Location: /pfblockerng/pfblockerng_dns_general.php');"), 'a saved form comes back to DNS > General');
		$this->assertLacks('[pfBlockerNG] save pfB-DNS settings', $page, 'the old pfB-DNS write is gone');
		$this->assertLacks('[pfBlockerNG] save DNS General settings', $page, 'the old DNS General write is gone');
	}

	public function testThePageStaysTitledDnsGeneralAndPrintsTheDdrWarningsThenTheForeignWarningsRightAfterThePendingChangesBox(): void
	{
		$page = self::page();

		$this->assertHas("\$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('DNS'), gettext('General'));", $page, 'the page is DNS > General');
		$this->assertSame(1, preg_match(
			'/pfb_print_pending_changes_box\(\);\s*foreach \(pfb_dns_proxy_ddr_warnings\(\) as (\$\w+)\) \{\s*print_info_box\(\1, \'warning\', FALSE\);\s*\}'
			. '\s*foreach \(pfb_dns_listen_foreign_warnings\(\) as (\$\w+)\) \{\s*print_info_box\(\2, \'warning\', FALSE\);\s*\}\s*\$form = new Form\(\'Save DNS settings\'\);/',
			$page
		), 'pending changes box, the DDR certificate warnings, the foreign DNS server warnings, then the form');
	}

	// -----------------------------------------------------------------------
	// V1: the saves, executed
	// -----------------------------------------------------------------------

	public function testOnePostChangingBothPartsSavesBothInOneWriteAndWritesExactlyTheKeysOfBoth(): void
	{
		$result = $this->runSave();

		// Given pfB-DNS Off and DNS Reply Logging On, and one POST that turns pfB-DNS On (with its listeners) and DNS Reply Logging Off
		$this->assertArrayHasKey('save', $result['posted']);
		$this->assertSame('', self::at($result['before'], self::path('dns/pfb_dns')), 'before: pfB-DNS is Off');
		$this->assertSame('on', self::at($result['before'], self::path('dnsbl/pfb_py_reply')), 'before: DNS Reply Logging is On');

		// Then the save went through its redirect with no error, in one write
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::SAVE], $result['writes'], 'one write_config() for both parts');
		$this->assertTrue($result['pendingMarked'], 'applies on the next Update');
		$this->assertFalse($result['returned'], 'ends through the redirect');
		$this->assertFalse($result['lockHeld'], 'the config lock is released');

		// And the keys written are the enable and the canonical listener settings, then the preference and the Resolver address settings, each as the registry places them
		$expected = [self::path('dns/pfb_dns') => 'on'];
		foreach (pfb_dns_proxy_listeners_stored($result['posted']) as $key => $value) {
			$expected[self::path(pfb_dns_config_key($key))] = $value;
		}
		$expected += [
			self::path('dnsbl/pfb_py_reply') => '',
			self::path('gen/pfb_dns_listen_vip') => '', self::path('gen/pfb_dns_listen_vip_only') => '',
			self::path('gen/pfb_dns_listen_vip4') => '', self::path('gen/pfb_dns_listen_vip6') => '', self::path('gen/pfb_dns_listen_interface') => 'lo0',
		];
		$moved = array_keys(array_filter($expected, static fn (mixed $value, string $path): bool => self::at($result['before'], $path) !== $value, ARRAY_FILTER_USE_BOTH));
		sort($moved);
		$this->assertSame($moved, self::changedLeaves($result['before'], $result['disk']), 'the leaves the save changed: the union of both parts');
		foreach ($expected as $path => $value) {
			$this->assertSame($value, self::at($result['disk'], $path), $path);
		}
	}

	/** @return array<string,array{array<string,mixed>,string,array<string,mixed>}> a pfB-DNS field the validator refuses: the post, the one error, the posted value the form shows again */
	public static function invalidPfbDnsFields(): array
	{
		return [
			'a bad DoT port'               => [['pfb_dns_dot_port' => 'abc'], 'DoT Port must be a whole number from 1 to 65535.', ['pfb_dns_dot_port' => 'abc']],
			'an empty DNS interface list'  => [['pfb_dns_interface' => NULL], 'DNS: select at least one interface.', ['pfb_dns_interface' => []]],
		];
	}

	/**
	 * @param array<string,mixed> $post
	 * @param array<string,mixed> $shown
	 */
	#[DataProvider('invalidPfbDnsFields')]
	public function testAnInvalidPfbDnsFieldBesideAValidDnsGeneralChangeSavesNothingAndTheFormKeepsBothPartsAsPosted(array $post, string $error, array $shown): void
	{
		$result = $this->runSave(['post' => $post]);

		// Given pfB-DNS Off and DNS Reply Logging On, and a POST with an invalid pfB-DNS field, pfB-DNS On and DNS Reply Logging Off
		$this->assertSame('', self::at($result['before'], self::path('dns/pfb_dns')), 'before: pfB-DNS is Off');
		$this->assertSame('on', self::at($result['before'], self::path('dnsbl/pfb_py_reply')), 'before: DNS Reply Logging is On');

		// Then the save is refused whole: the error is shown, nothing is written, not even the valid DNS General change
		$this->assertSame([$error], $result['inputErrors']);
		$this->assertNothingSaved($result);

		// And the form comes back with what was posted in both parts
		foreach (['pfb_dns' => 'on', 'pfb_py_reply' => ''] + $shown as $field => $value) {
			$this->assertSame($value, $result['pconfig'][$field] ?? NULL, "the form shows the posted {$field}");
		}
	}

	public function testAnInvalidDnsGeneralFieldBesideAValidPfbDnsChangeSavesNothingAndTheFormKeepsBothPartsAsPosted(): void
	{
		// Given pfB-DNS Off and DNS Reply Logging On, and a POST with an IPv4 VIP that is not an option, a new DoT port and DNS Reply Logging Off
		$result = $this->runSave(['post' => ['pfb_dns_listen_vip4' => 'bogus', 'pfb_dns_dot_port' => '8530']]);
		$this->assertSame('', self::at($result['before'], self::path('dns/pfb_dns')), 'before: pfB-DNS is Off');
		$this->assertNotSame('8530', self::at($result['before'], self::path(pfb_dns_config_key('pfb_dns_dot_port'))), 'before: not the posted DoT port');

		// Then the save is refused whole: the error is shown, nothing is written, not even the valid pfB-DNS change
		$this->assertSame(['DNS General: select an available VIP and interface.'], $result['inputErrors']);
		$this->assertNothingSaved($result);

		// And the form comes back with what was posted in both parts
		foreach (['pfb_dns' => 'on', 'pfb_dns_dot_port' => '8530', 'pfb_py_reply' => '', 'pfb_dns_listen_vip4' => 'bogus'] as $field => $value) {
			$this->assertSame($value, $result['pconfig'][$field] ?? NULL, "the form shows the posted {$field}");
		}
	}

	public function testVipOnlyModeTurnedOnTogetherWithPfbDnsIsAcceptedAndBothAreStoredOn(): void
	{
		// Given pfB-DNS and VIP-only mode both Off, and one POST that turns pfB-DNS, Resolver addresses and VIP-only mode On
		$result = $this->runSave(['post' => self::VIP_ONLY_FORM]);
		$this->assertSame('', self::at($result['before'], self::path('dns/pfb_dns')), 'before: pfB-DNS is Off');
		$this->assertNotSame('on', self::at($result['before'], self::path('gen/pfb_dns_listen_vip_only')), 'before: VIP-only mode is not On');
		$this->assertSame('on', $result['posted']['pfb_dns'] ?? NULL);

		// Then the save is accepted: the pfB-DNS enable it writes first is what the VIP-only check judges
		$this->assertSame([], $result['inputErrors']);
		$this->assertContains(self::SAVE, $result['writes']);
		$this->assertFalse($result['returned'], 'ends through the redirect');
		$this->assertSame('on', self::at($result['disk'], self::path('dns/pfb_dns')), 'pfB-DNS is stored On');
		$this->assertSame('on', self::at($result['disk'], self::path('gen/pfb_dns_listen_vip_only')), 'VIP-only mode is stored On');
	}

	public function testPfbDnsTurnedOffWhileVipOnlyModeStaysOnIsAcceptedAndVipOnlyModeStaysStored(): void
	{
		// Given pfB-DNS and VIP-only mode On with Resolver addresses on a created VIP, and a POST that turns pfB-DNS Off and leaves VIP-only mode On
		$stored = ['dns/pfb_dns' => 'on', 'gen/pfb_dns_listen_vip' => 'on', 'gen/pfb_dns_listen_vip4' => 'auto', 'gen/pfb_dns_listen_vip_only' => 'on'];
		$result = $this->runSave(['stored' => $stored, 'post' => ['pfb_dns' => NULL] + self::VIP_ONLY_FORM]);
		$this->assertSame('on', self::at($result['before'], self::path('dns/pfb_dns')), 'before: pfB-DNS is On');
		$this->assertSame('on', self::at($result['before'], self::path('gen/pfb_dns_listen_vip_only')), 'before: VIP-only mode is On');
		$this->assertArrayNotHasKey('pfb_dns', $result['posted'], 'the form posts no pfB-DNS enable');

		// Then the save is accepted: VIP-only mode stays stored (inactive) while pfB-DNS is Off
		$this->assertSame([], $result['inputErrors']);
		$this->assertContains(self::SAVE, $result['writes']);
		$this->assertFalse($result['returned'], 'ends through the redirect');
		$this->assertSame('', self::at($result['disk'], self::path('dns/pfb_dns')), 'pfB-DNS is stored Off');
		$this->assertSame('on', self::at($result['disk'], self::path('gen/pfb_dns_listen_vip_only')), 'VIP-only mode stays stored On');
	}

	public function testVipOnlyModeNewlyTurnedOnWhilePfbDnsStaysOffIsRefusedAndNothingIsWritten(): void
	{
		// Given pfB-DNS and VIP-only mode both Off, and a POST that turns VIP-only mode On and leaves pfB-DNS Off
		$result = $this->runSave(['post' => ['pfb_dns' => NULL] + self::VIP_ONLY_FORM]);
		$this->assertSame('', self::at($result['before'], self::path('dns/pfb_dns')), 'before: pfB-DNS is Off');
		$this->assertNotSame('on', self::at($result['before'], self::path('gen/pfb_dns_listen_vip_only')), 'before: VIP-only mode is not On');

		// Then the save is refused whole with the VIP-only error, and the form shows VIP-only mode On again
		$this->assertCount(1, $result['inputErrors']);
		$this->assertStringContainsString(self::VIP_ONLY_REFUSAL, $result['inputErrors'][0]);
		$this->assertNothingSaved($result);
		$this->assertSame('on', $result['pconfig']['pfb_dns_listen_vip_only'] ?? NULL, 'the form shows the posted VIP-only mode');
	}

	// -----------------------------------------------------------------------
	// V2: no pfB-DNS subtab; the old URL only where it must stay
	// -----------------------------------------------------------------------

	private const PFB_DNS_TAB_ROW = "/\\\$tab_array\\[\\]\\s*=\\s*array\\(gettext\\('pfB-DNS'\\)/";

	public function testNoPageOfTheWebGuiPrintsAPfbDnsSubtabRow(): void
	{
		$this->assertSame(1, preg_match(self::PFB_DNS_TAB_ROW, "\$tab_array[]\t= array(gettext('pfB-DNS'),\tFALSE,\t'/pfblockerng/pfblockerng_dns.php');"), 'the check sees a tab row as the pages used to print it');
		$this->assertSame(0, preg_match(self::PFB_DNS_TAB_ROW, "new Form_Checkbox('pfb_dns', gettext('pfB-DNS'), 'Enable', TRUE, 'on')"), 'and not the enable checkbox\'s label');

		$offenders = [];
		$root = (string) realpath(self::SRC);
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("{$root}/usr/local/www", FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if ($file->isFile() && $file->getExtension() === 'php' && preg_match(self::PFB_DNS_TAB_ROW, (string) file_get_contents($file->getPathname())) === 1) {
				$offenders[] = substr($file->getPathname(), strlen($root) + 1);
			}
		}
		sort($offenders);
		$this->assertSame([], $offenders, 'pages that still print a pfB-DNS subtab row');
	}

	public function testOnlyThePrivilegeTheGeoipNavigationMigrationAndTheStubStillNameTheOldPageUrl(): void
	{
		$named = [];
		$root = (string) realpath(self::SRC);
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if ($file->isFile() && str_contains((string) file_get_contents($file->getPathname()), 'pfblockerng_dns.php')) {
				$named[] = substr($file->getPathname(), strlen($root) + 1);
			}
		}
		sort($named);
		$this->assertSame(self::OLD_URL_ALLOWED, $named, 'the sources that name pfblockerng_dns.php: nothing else may link or redirect to it');
	}

	public function testTheDnsblEnableHelpSendsTheOperatorToDnsGeneralToTurnPfbDnsOn(): void
	{
		$page = self::page('pfblockerng_dnsbl.php');

		$this->assertHas('(turned on in <strong>DNS &gt; General</strong>)', $page, 'the DNSBL enable help');
		$this->assertLacks('DNS &gt; pfB-DNS', $page, 'there is no such tab any more');
	}

	// -----------------------------------------------------------------------
	// V3: the old URL
	// -----------------------------------------------------------------------

	public function testTheOldPfbDnsUrlIsARedirectStubThatAuthenticatesThenSendsTheBrowserToDnsGeneralAndStops(): void
	{
		$code = trim((string) preg_replace('/\s+/', ' ', php_strip_whitespace(self::WWW . 'pfblockerng_dns.php')));

		foreach (['Form', '$_POST', 'PfbConfig', '$tab_array'] as $gone) {
			$this->assertLacks($gone, $code, 'the stub renders and saves nothing');
		}
		$expected = "<?php require_once('guiconfig.inc'); header('Location: /pfblockerng/pfblockerng_dns_general.php'); exit;";
		$this->assertSame($expected, $code, 'guiconfig.inc (authentication), the redirect, exit: nothing else');
	}

	// -----------------------------------------------------------------------
	// V4: the DDR check endpoint
	// -----------------------------------------------------------------------

	public function testDnsGeneralKeepsTheGetOnlyJsonDdrEndpointAndItsRefreshScriptCallsItOnThisPage(): void
	{
		$page = self::page();
		$from = strpos($page, "if ((\$_GET['ajax'] ?? '') === 'ddr') {");
		$this->assertNotFalse($from, 'DNS > General has the DDR endpoint block');
		$to = strpos($page, 'pfb_dns_proxy_seed_values()', $from);
		$this->assertNotFalse($to, 'the endpoint block is followed by the seed block: it comes first');
		$endpoint = substr($page, $from, $to - $from);

		foreach ([
			"header('Cache-Control: no-store');",
			"\$_SERVER['REQUEST_METHOD'] !== 'GET'",
			"header('Allow: GET');",
			'http_response_code(405);',
			"array_key_exists('listener', \$_GET)",
			'http_response_code(400);',
			"header('Content-Type: application/json');",
			"echo json_encode(['html' => pfb_dns_status_panel(pfb_dns_status())]);",
		] as $needle) {
			$this->assertHas($needle, $endpoint, 'the endpoint is GET-only JSON');
		}
		$this->assertLacks('write_config', $endpoint, 'the endpoint writes nothing');
		$this->assertLacks('PfbConfig::write', $endpoint, 'the endpoint writes nothing');
		$this->assertLessThan($from, strpos($page, "require_once('guiconfig.inc');"), 'the endpoint answers only after authentication');
		$this->assertSame(1, substr_count($page, "fetch('pfblockerng_dns_general.php?ajax=ddr'"), 'the refresh script fetches the whole status once');
		$this->assertLacks('ajax=ddr&listener', $page, 'and not one request per address');
		$this->assertLacks('encodeURIComponent(address)', $page, 'and not one request per address');
		$this->assertLacks('pfblockerng_dns.php?ajax', $page, 'and not the redirect stub, which would answer with a page, not JSON');
	}
}
