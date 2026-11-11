<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3771 -- the pfB-DNS enable and all its settings (DoT, DoH, DoQ, DDR) moved from DNS > pfB-DNS onto DNS > General. The pfB-DNS
 * subtab is gone and pfblockerng_dns.php only redirects to DNS > General. Stored keys and save semantics did not change.
 *
 * Verification rows (the live UI half of each is tests/smoke/ui):
 *   V1 DNS > General shows the pfB-DNS enable and the DoT/DoH/DoQ/DDR sections as the first of two independent forms, each with its own
 *      submit button; saving one writes the same keys the old page wrote and nothing of the other form's.
 *   V2 no page prints a pfB-DNS subtab; the old page's URL survives only in the privilege and the GeoIP navigation migration.
 *   V3 requesting pfblockerng_dns.php ends on DNS > General.
 *   V4 the DDR check endpoint and its refresh script now live on DNS > General.
 *
 * The pages render and exit, so their source is pinned; the saves are executed: support/DnsSaveWorker.php runs the page's real POST
 * region (both handlers, gates and validation included) over the doubles in a child process, as a browser posts either form.
 */
final class DnsGeneralPfbDnsFoldTest extends TestCase
{
	private const WWW = __DIR__ . '/../../src/usr/local/www/pfblockerng/';
	private const SRC = __DIR__ . '/../../src/';
	private const DNS_GENERAL = 'pfblockerng_dns_general.php';
	private const SAVE_PFB_DNS = '[pfBlockerNG] save pfB-DNS settings';
	private const SAVE_GENERAL = '[pfBlockerNG] save DNS General settings';

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

	/**
	 * The page's whole POST region run in a child process, with only this form's button and fields posted.
	 *
	 * @return array<string,mixed> the worker's result: before, disk, posted, writes, inputErrors, pendingMarked, returned, lockHeld
	 */
	private function runForm(string $button): array
	{
		$dir = sys_get_temp_dir() . '/pfb_dns_fold_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/DnsSaveWorker.php', 'plain', $result, 'region', $button], 60.0);
			$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}");
			$this->assertStringNotContainsString('worker:', $process['stdout'] . $process['stderr'], 'the worker found the save region on DNS General');
			return json_decode((string) file_get_contents($result), TRUE, 512, JSON_THROW_ON_ERROR);
		} finally {
			@unlink($result);
			@rmdir($dir);
		}
	}

	// -----------------------------------------------------------------------
	// V1: the page, as source
	// -----------------------------------------------------------------------

	public function testDnsGeneralHoldsThePfbDnsFormFirstWithItsOwnSaveButtonAndTheFiveSectionsInOrderThenTheDnsGeneralForm(): void
	{
		$page = self::page();

		$this->assertSame(2, preg_match_all('/new Form\(/', $page), 'two forms: pfB-DNS, then DNS General');
		self::inOrder($page, [
			"/new Form_Button\\(\\s*'save_pfb_dns',\\s*'Save pfB-DNS settings',\\s*NULL,\\s*'fa-solid fa-save'\\s*\\)/",
			"/\\\$btn->addClass\\('btn-primary'\\);/",
			'/\$form = new Form\(\$btn\);/',
			"/new Form_Section\\('pfB-DNS Settings'\\)/",
			"/new Form_Section\\('DNS over TLS \\(DoT\\)'\\)/",
			"/new Form_Section\\('DNS over HTTPS \\(DoH\\)'\\)/",
			"/new Form_Section\\('DNS over QUIC \\(DoQ\\)'\\)/",
			"/new Form_Section\\('Discovery of Designated Resolvers \\(DDR\\)'\\)/",
			'/print \(\$form\);/',
			"/new Form\\('Save DNS General settings'\\)/",
			"/new Form_Section\\('DNS Reply Logging'\\)/",
			"/new Form_Section\\('Resolver addresses'\\)/",
			'/print \(\$form\);/',
			'/pfb_dns_status_panel\(/',
			"/include\\('foot\\.inc'\\);/",
		], 'the page');
		$this->assertLacks("new Form('Save pfB-DNS settings')", $page, 'the pfB-DNS form is built from its own button, not the default save button');
		$this->assertSame(1, substr_count($page, "'pfb_dns',"), 'the pfB-DNS enable checkbox is on this page once');
	}

	public function testThePfbDnsHandlerIsGatedOnItsOwnButtonAndTheDnsGeneralHandlerOnItsOwnAndOnlyOneInputErrorsListIsStarted(): void
	{
		$page = self::page();

		$this->assertSame(1, substr_count($page, '$input_errors = array();'), 'one error list for both handlers');
		[, , , , $pfbDns, $general, $title] = self::inOrder($page, [
			"/\\\$_GET\\['ajax'\\] \\?\\? ''\\) === 'ddr'/",	// the DDR endpoint answers before anything else loads
			'/pfb_dns_proxy_seed_values\(\) !== \[\]/',
			'/\$pconfig = array\(\);/',
			'/\$input_errors = array\(\);/',
			"/isset\\(\\\$_POST\\['save_pfb_dns'\\]\\)/",
			"/if \\(\\\$_POST && isset\\(\\\$_POST\\['save'\\]\\)\\)/",
			'/\$pgtitle = /',
		], 'the page top');

		$pfbDnsHandler = substr($page, $pfbDns, $general - $pfbDns);
		$this->assertSame(1, substr_count($pfbDnsHandler, "header('Location: /pfblockerng/pfblockerng_dns_general.php');"), 'a saved pfB-DNS form comes back to DNS > General');
		$this->assertHas("write_config('" . self::SAVE_PFB_DNS . "')", $pfbDnsHandler, 'the pfB-DNS handler keeps its write');
		$this->assertHas('pfb_dns_proxy_listeners_stored($_POST)', $pfbDnsHandler, 'the same keys as before');
		$this->assertLacks("isset(\$_POST['save'])", $pfbDnsHandler, 'the pfB-DNS handler does not answer the DNS General button');

		$generalHandler = substr($page, $general, $title - $general);
		$this->assertHas("write_config('" . self::SAVE_GENERAL . "')", $generalHandler, 'the DNS General handler keeps its write');
		$this->assertLacks('save_pfb_dns', $generalHandler, 'the DNS General handler does not answer the pfB-DNS button');
	}

	public function testThePageStaysTitledDnsGeneralAndPrintsTheDdrWarningsThenTheForeignWarningsRightAfterThePendingChangesBox(): void
	{
		$page = self::page();

		$this->assertHas("\$pgtitle = array(gettext('Firewall'), gettext('pfBlockerNG'), gettext('DNS'), gettext('General'));", $page, 'the page is DNS > General');
		$this->assertSame(1, preg_match(
			'/pfb_print_pending_changes_box\(\);\s*foreach \(pfb_dns_proxy_ddr_warnings\(\) as (\$\w+)\) \{\s*print_info_box\(\1, \'warning\', FALSE\);\s*\}'
			. '\s*foreach \(pfb_dns_listen_foreign_warnings\(\) as (\$\w+)\) \{\s*print_info_box\(\2, \'warning\', FALSE\);\s*\}\s*\$btn = new Form_Button\(/',
			$page
		), 'pending changes box, the DDR certificate warnings, the foreign DNS server warnings, then the pfB-DNS form');
	}

	// -----------------------------------------------------------------------
	// V1: the saves, executed
	// -----------------------------------------------------------------------

	public function testSavingOnlyThePfbDnsFormWritesExactlyTheKeysTheOldPfbDnsPageWroteAndNoneOfDnsGeneral(): void
	{
		$result = $this->runForm('save_pfb_dns');

		// Given a box with pfB-DNS Off and a complete valid pfB-DNS form that turns it On, posted with its own button only
		$dns = PFB_SECTIONS['dns'];
		$this->assertArrayHasKey('save_pfb_dns', $result['posted']);
		$this->assertArrayNotHasKey('save', $result['posted'], 'a browser posts the clicked form only');
		$this->assertSame('', self::at($result['before'], "{$dns}/pfb_dns"), 'before: pfB-DNS is Off');
		$this->assertSame('on', self::at($result['before'], PFB_SECTIONS['dnsbl'] . '/pfb_py_reply'), 'before: DNS Reply Logging is On');

		// Then the save went through its redirect with no error, and the pfB-DNS handler alone ran
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame([self::SAVE_PFB_DNS], $result['writes'], 'one write_config(), the pfB-DNS one');
		$this->assertTrue($result['pendingMarked'], 'applies on the next Update');
		$this->assertFalse($result['returned'], 'ends through the redirect');
		$this->assertFalse($result['lockHeld'], 'the config lock is released');

		// And the keys written are exactly the enable and the canonical listener settings, each as the registry places them
		$expected = ["{$dns}/pfb_dns" => 'on'];
		foreach (pfb_dns_proxy_listeners_stored($result['posted']) as $key => $value) {
			[$alias, $bare] = explode('/', pfb_dns_config_key($key), 2);
			$expected[PFB_SECTIONS[$alias] . "/{$bare}"] = $value;
		}
		$paths = array_keys($expected);
		sort($paths);
		$this->assertSame($paths, self::changedLeaves($result['before'], $result['disk']), 'the leaves the save changed: only pfB-DNS ones');
		foreach ($expected as $path => $value) {
			$this->assertSame($value, self::at($result['disk'], $path), $path);
		}
		$this->assertSame('on', self::at($result['disk'], PFB_SECTIONS['dnsbl'] . '/pfb_py_reply'), 'the shared DNS Reply Logging preference is DNS General\'s: untouched');
	}

	public function testSavingOnlyTheDnsGeneralFormSavesItsOwnKeysAndLeavesEveryPfbDnsKeyAlone(): void
	{
		$result = $this->runForm('save');

		// Given pfB-DNS On and DNS Reply Logging On, and a DNS General form posted with its own button only and the reply logging box unticked
		$this->assertArrayHasKey('save', $result['posted']);
		$this->assertArrayNotHasKey('save_pfb_dns', $result['posted'], 'a browser posts the clicked form only');
		$this->assertSame('on', self::at($result['before'], PFB_SECTIONS['dns'] . '/pfb_dns'), 'before: pfB-DNS is On');
		$this->assertSame('on', self::at($result['before'], PFB_SECTIONS['dnsbl'] . '/pfb_py_reply'), 'before: DNS Reply Logging is On');

		// Then the DNS General handler alone ran and saved the unticked preference
		$this->assertSame([], $result['inputErrors'], 'the pfB-DNS handler did not run: it would refuse a form with no listener fields');
		$this->assertContains(self::SAVE_GENERAL, $result['writes']);
		$this->assertNotContains(self::SAVE_PFB_DNS, $result['writes']);
		$this->assertSame('', self::at($result['disk'], PFB_SECTIONS['dnsbl'] . '/pfb_py_reply'), 'DNS Reply Logging saved Off');
		$this->assertTrue($result['pendingMarked']);
		$this->assertFalse($result['returned'], 'ends through the redirect');

		// And not one pfB-DNS leaf (the enable, the listeners, the shared transport settings, the snapshot) moved
		$pfbDnsLeaves = array_values(array_filter(
			self::changedLeaves($result['before'], $result['disk']),
			static fn (string $path): bool => str_starts_with($path, PFB_SECTIONS['dns']) || str_starts_with($path, PFB_SECTIONS['dns_shared'])
		));
		$this->assertSame([], $pfbDnsLeaves);
		$this->assertSame('on', self::at($result['disk'], PFB_SECTIONS['dns'] . '/pfb_dns'), 'pfB-DNS stays On');
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
