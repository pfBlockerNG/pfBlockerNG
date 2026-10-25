<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PageStatementLoader.php';

/**
 * Issue #3593: navigation-only upgrade of GeoIP pages generated before the DNS cutover.
 *
 * Pages come from the production generator. The pre-cutover pair is literal input data and every
 * expectation is a literal byte string or the generator's own current output, never source text.
 */
final class GeoipNavigationUpgradeTest extends TestCase
{
	private const PAST = 1600000000;
	private const INSTALL = 'src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
	private const CONTINENTS = ['Top_Spammers', 'Africa', 'Antarctica', 'Asia', 'Europe', 'North_America', 'Oceania', 'South_America', 'Proxy_and_Satellite'];

	// Pre-cutover pair, per page kind (literal input data).
	private const CONTINENT_OLD = "\$tab_array[]\t= array(gettext('DNSBL'),\t\tFALSE,\t'/pfblockerng/pfblockerng_dnsbl.php');\n"
		. "\$tab_array[]\t= array(gettext('pfB-DNS'),\tFALSE,\t'/pfblockerng/pfblockerng_dns.php');";
	private const REPUTATION_OLD = "\$tab_array[]\t= array(gettext('DNSBL'),\tFALSE,\t'/pfblockerng/pfblockerng_dnsbl.php');\n"
		. "\$tab_array[]\t= array(gettext('pfB-DNS'),\tFALSE,\t'/pfblockerng/pfblockerng_dns.php');";
	// The single row the current generator emits; the migrated pair must become exactly this row.
	private const CONTINENT_NEW = "\$tab_array[]\t= array(gettext('DNS'),\t\t\tFALSE,\t'/pfblockerng/pfblockerng_dns.php');";
	private const REPUTATION_NEW = "\$tab_array[]\t= array(gettext('DNS'),\t\tFALSE,\t'/pfblockerng/pfblockerng_dns.php');";
	// Rows used only to build malformed fixtures.
	private const DNSBL_CONTINENT_ROW = "\$tab_array[]\t= array(gettext('DNSBL'),\t\tFALSE,\t'/pfblockerng/pfblockerng_dnsbl.php');";
	private const PFBDNS_CONTINENT_ROW = "\$tab_array[]\t= array(gettext('pfB-DNS'),\tFALSE,\t'/pfblockerng/pfblockerng_dns.php');";
	private const IP_ROW = "\$tab_array[]\t= array(gettext('IP'),\t\t\tTRUE,\t'/pfblockerng/pfblockerng_ip.php');";

	private string $tmp;
	private string $ccdir;
	private string $output;
	private mixed $originalPfb;
	private bool $hadPfb = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? NULL;

		$this->tmp = sys_get_temp_dir() . '/pfb_geoip_nav_' . getmypid() . '_' . bin2hex(random_bytes(8));
		$this->ccdir = "{$this->tmp}/cc";
		$this->output = "{$this->tmp}/www";
		$this->assertTrue(mkdir($this->ccdir, 0777, TRUE), "navigation upgrade cc directory creation failed: {$this->ccdir}");
		$this->assertTrue(mkdir($this->output, 0777, TRUE), "navigation upgrade www directory creation failed: {$this->output}");

		$GLOBALS['pfb']['ccdir'] = $this->ccdir;
		$GLOBALS['pfb']['ccdir_tmp'] = "{$this->tmp}/cc-tmp";
		$GLOBALS['pfb']['log'] = "{$this->tmp}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/error.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->tmp}/extras.log";
		$GLOBALS['pfb']['extras_update'] = FALSE;
		$GLOBALS['pfb']['complete'] = FALSE;
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->tmp);
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	public function testMigratesEveryKnownPageFromThePreCutoverPairAndLeavesTheRestByteForByte(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$before = [];
		foreach ($this->pages() as $page) {
			$before[$page] = $this->read($page);
		}
		$names = $this->listing($this->output);

		$this->assertTrue($this->refresh($this->output), 'a successful migration must report TRUE');

		foreach ($this->pages() as $page) {
			$this->assertSame(
				str_replace($this->oldPair($page), $this->currentRow($page), $before[$page]),
				$this->read($page),
				basename($page) . ': only the pre-cutover pair may change'
			);
		}
		$this->assertStringContainsString('"AA" => "Alpha AA (2)"', $this->read("{$this->output}/pfblockerng_Africa.php"),
			'populated continent options must survive the migration');
		$this->assertDoesNotMatchRegularExpression('/\$options_ccexclude\s*=\s*array\(\);/',
			$this->read("{$this->output}/pfblockerng_reputation.php"), 'populated Reputation options must survive the migration');

		$fresh = "{$this->tmp}/fresh";
		$this->assertTrue(mkdir($fresh, 0777, TRUE));
		$this->assertTrue(pfblockerng_get_countries($fresh), 'the production generator must rebuild the same fixture');
		foreach ($this->pages() as $page) {
			$this->assertSame($this->read("{$fresh}/" . basename($page)), $this->read($page),
				basename($page) . ': a migrated page must equal the current generator output');
		}
		$this->assertSame($names, $this->listing($this->output), 'migration must not add or remove files');
	}

	public function testAtomicPublicationKeepsExistingReadersOnTheCompleteOriginalPage(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$page = "{$this->output}/pfblockerng_reputation.php";
		$before = $this->read($page);
		$inode = fileinode($page);
		$reader = fopen($page, 'rb');
		$this->assertIsResource($reader);
		try {
			$this->assertTrue($this->refresh($this->output));
			clearstatcache(TRUE, $page);
			$this->assertNotSame($inode, fileinode($page), 'publication must replace the inode, not overwrite it');
			$this->assertSame($before, stream_get_contents($reader), 'an existing reader keeps the complete old page');
		} finally {
			fclose($reader);
		}
		$this->assertStringContainsString(self::REPUTATION_NEW, $this->read($page));
	}

	public function testMigratedPagesKeepTheirOriginalOwnerGroupAndMode(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$euid = function_exists('posix_geteuid') ? posix_geteuid() : getmyuid();
		$egid = function_exists('posix_getegid') ? posix_getegid() : getmygid();
		// As root the fixture is handed to another uid, so an ownership regression is visible.
		$owner = $euid === 0 ? 65534 : $euid;
		$group = $euid === 0 ? 65534 : $egid;
		foreach ($this->pages() as $page) {
			$this->assertTrue(chown($page, $owner) && chgrp($page, $group) && chmod($page, 0640), "fixture ownership for {$page}");
		}

		$this->assertTrue($this->refresh($this->output));

		foreach ($this->pages() as $page) {
			clearstatcache();
			$this->assertSame($owner, fileowner($page), basename($page) . ': owner must be preserved');
			$this->assertSame($group, filegroup($page), basename($page) . ': group must be preserved');
			$this->assertSame(0640, fileperms($page) & 0777, basename($page) . ': mode must be preserved');
		}
		$this->assertStringContainsString(self::CONTINENT_NEW, $this->read("{$this->output}/pfblockerng_Africa.php"));
	}

	public function testTheDeferredSwapSentinelAndCountryDatasetAreNeverTouched(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$sentinel = "{$this->ccdir}/.pfb_generation_swapping";
		$this->assertNotFalse(file_put_contents($sentinel, "deferred generation\n"));
		$ccdir = array_map(fn (string $name): string => "{$this->ccdir}/{$name}", $this->listing($this->ccdir));
		$this->assertContains($sentinel, $ccdir, 'the deferred sentinel must be present for this case');
		foreach ($ccdir as $path) {
			$this->pin($path);
		}
		$before = $this->snapshots($ccdir);

		$this->assertTrue($this->refresh($this->output));

		$this->assertSame($before, $this->snapshots($ccdir),
			'the deferred sentinel and country dataset must keep their bytes, inode and mtime');
		$this->assertStringContainsString(self::CONTINENT_NEW, $this->read("{$this->output}/pfblockerng_Africa.php"),
			'navigation is still refreshed while the sentinel is present');
	}

	public function testCurrentNavigationNavlessAndMissingPagesAreNeverRewritten(): void
	{
		$this->generateCurrentPages();
		$navless = "{$this->output}/pfblockerng_Oceania.php";
		$this->assertNotFalse(file_put_contents($navless, "<?php\n// navigation rows absent\n"));
		$missing = "{$this->output}/pfblockerng_Asia.php";
		$this->assertTrue(unlink($missing));
		$present = array_values(array_filter($this->pages(), fn (string $page): bool => is_file($page)));
		foreach ($present as $page) {
			$this->pin($page);
		}
		$before = $this->snapshots($present);

		$this->assertTrue($this->refresh($this->output));

		$this->assertSame($before, $this->snapshots($present),
			'current, navigation-less and unchanged pages must keep their inode, mtime and bytes');
		$this->assertFileDoesNotExist($missing, 'a missing generated page must not be created');
	}

	public function testASecondRunOverMigratedPagesRewritesNothing(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$this->assertTrue($this->refresh($this->output));
		$pages = $this->pages();
		$afterFirstRun = $this->snapshots($pages);

		$this->assertTrue($this->refresh($this->output), 'a second run over migrated pages must still report TRUE');

		$this->assertSame($afterFirstRun, $this->snapshots($pages), 'a second run must not rewrite any page');
	}

	public function testUnlistedNeighbouringPhpPagesAreNeverTouched(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$neighbours = [
			"{$this->output}/pfblockerng_dnsbl.php" => self::CONTINENT_OLD,
			"{$this->output}/pfblockerng_Unlisted.php" => self::REPUTATION_OLD,
		];
		foreach ($neighbours as $path => $rows) {
			$this->assertNotFalse(file_put_contents($path, "<?php\n{$rows}\n"));
			$this->pin($path);
		}
		$paths = array_keys($neighbours);
		$before = $this->snapshots($paths);

		$this->assertTrue($this->refresh($this->output));

		$this->assertSame($before, $this->snapshots($paths), 'pages outside the generated list must keep their bytes, inode and mtime');
		$this->assertStringContainsString(self::CONTINENT_NEW, $this->read("{$this->output}/pfblockerng_Africa.php"),
			'the generated pages in the same root are still migrated');
	}

	/** @return array<string, array{string, bool}> */
	public static function singleRowLayouts(): array
	{
		return [
			'pre-pfB-DNS continent' => ['Africa', FALSE],
			'pre-pfB-DNS Reputation' => ['reputation', FALSE],
			'stable 3.3.11 continent' => ['Africa', TRUE],
			'stable 3.3.11 Reputation' => ['reputation', TRUE],
		];
	}

	#[DataProvider('singleRowLayouts')]
	public function testSupportedSingleDnsblRowsKeepUpdateAndEveryOtherByte(string $slug, bool $lowercase): void
	{
		$this->generateCurrentPages();
		$page = "{$this->output}/pfblockerng_{$slug}.php";
		$current = $this->read($page);
		$old = explode("\n", $this->oldPair($page))[0];
		$tabs = $slug === 'reputation' ? "\t" : "\t\t";
		$update = "\$tab_array[]\t= array(gettext('Update'),{$tabs}FALSE,\t'/pfblockerng/pfblockerng_update.php');";
		$oldUpdate = $update;
		if ($lowercase) {
			$old = str_replace('FALSE', 'false', $old);
			$oldUpdate = str_replace('FALSE', 'false', $update);
		}
		$before = str_replace($this->currentRow($page) . "\n" . $update, $old . "\n" . $oldUpdate, $current, $matches);
		$this->assertSame(1, $matches, 'the fixture must replace the one generated DNS/Update row pair');
		$this->assertNotFalse(file_put_contents($page, $before));

		$this->assertTrue($this->refresh($this->output));

		$this->assertSame(str_replace($old, $this->currentRow($page), $before), $this->read($page),
			'the supported legacy DNSBL row alone changes; Update and populated options retain their bytes');
	}

	/** @return array<string, array{string, string}> */
	public static function nonNavigationPairs(): array
	{
		return [
			'commented continent' => ['Africa', 'comment'],
			'commented Reputation' => ['reputation', 'comment'],
			'suffixed continent' => ['Africa', 'suffix'],
			'suffixed Reputation' => ['reputation', 'suffix'],
			'embedded continent' => ['Africa', 'embedded'],
			'embedded Reputation' => ['reputation', 'embedded'],
		];
	}

	#[DataProvider('nonNavigationPairs')]
	public function testLegacyTextOutsideCompleteNavigationRowsIsNeverRewritten(string $slug, string $kind): void
	{
		$this->generateCurrentPages();
		$page = "{$this->output}/pfblockerng_{$slug}.php";
		$current = $this->read($page);
		$old = $this->oldPair($page);
		$before = match ($kind) {
			'comment' => str_replace($this->currentRow($page), '// ' . $old, $current),
			'suffix' => str_replace($this->currentRow($page), $old . ' // retained operator note', $current),
			'embedded' => $current . "\n<?php\n\$saved = <<<'PFB_NAV_DATA'\n{$old}\nPFB_NAV_DATA;\n",
		};
		$this->assertNotFalse(file_put_contents($page, $before));
		$this->pin($page);
		$snapshot = $this->snapshot($page);

		$this->assertTrue($this->refresh($this->output));

		$this->assertSame($snapshot, $this->snapshot($page),
			'commented/suffixed rows and literal page data are not the known generated navigation');
	}

	public function testMalformedNavigationPairsAreLeftAlone(): void
	{
		$cases = [
			'pfblockerng_Africa.php' => self::DNSBL_CONTINENT_ROW,
			'pfblockerng_Antarctica.php' => self::PFBDNS_CONTINENT_ROW . "\n" . self::DNSBL_CONTINENT_ROW,
			'pfblockerng_Asia.php' => self::DNSBL_CONTINENT_ROW . "\n" . self::IP_ROW . "\n" . self::PFBDNS_CONTINENT_ROW,
		];
		$paths = [];
		foreach ($cases as $name => $rows) {
			$path = "{$this->output}/{$name}";
			$this->assertNotFalse(file_put_contents($path, "<?php\n{$rows}\n"));
			$this->pin($path);
			$paths[] = $path;
		}
		$before = $this->snapshots($paths);

		$this->assertTrue($this->refresh($this->output), 'pages without a complete adjacent pair are no-match, not failure');

		$this->assertSame($before, $this->snapshots($paths),
			'a lone, reversed or separated DNSBL/pfB-DNS row must never be rewritten');
	}

	public function testReadOnlyStagingFailureReturnsFalseKeepsOriginalBytesAndLeavesNoTempFiles(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$pages = $this->pages();
		$before = $this->snapshots($pages);
		$names = $this->listing($this->output);
		$this->requireHelper();

		$this->assertTrue(chmod($this->output, 0555));
		try {
			$result = pfb_test_as_unprivileged(fn (): bool => pfb_geoip_refresh_navigation($this->output), [$this->output]);
		} finally {
			chmod($this->output, 0755);
		}

		$this->assertFalse($result, 'a page that cannot be published must make the helper report FALSE');
		$this->assertSame($before, $this->snapshots($pages), 'a refused publication must leave every original page byte-identical');
		$this->assertSame($names, $this->listing($this->output), 'a refused publication must leave no staging file behind');
	}

	public function testASymlinkedGeneratedPageIsNeverFollowedOrReplaced(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$africa = "{$this->output}/pfblockerng_Africa.php";
		$outside = "{$this->tmp}/outside/pfblockerng_Africa.php";
		$this->assertTrue(mkdir(dirname($outside), 0755, TRUE));
		$this->assertNotFalse(file_put_contents($outside, "<?php\n" . self::CONTINENT_OLD . "\n"));
		$this->pin($outside);
		$this->assertTrue(unlink($africa));
		$this->assertTrue(symlink($outside, $africa));
		$before = $this->snapshots([$outside]);

		$this->assertFalse($this->refresh($this->output), 'a symlinked generated page must be refused, not followed');

		$this->assertSame($before, $this->snapshots([$outside]), 'the symlink target must keep its bytes, inode and mtime');
		$this->assertTrue(is_link($africa), 'the generated path must remain the operator-placed symlink');
		$this->assertSame($outside, readlink($africa));
	}

	public function testAnEmptyOutputRootReportsSuccessAndCreatesNothing(): void
	{
		$this->assertSame([], $this->listing($this->output));

		$this->assertTrue($this->refresh($this->output), 'absent pages are not a failure');

		$this->assertSame([], $this->listing($this->output), 'absent pages must not be created');
	}

	public function testInstallerDispatchReportsDoneAfterAMigration(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$code = $this->installerDispatchCode();

		$statuses = $this->runInstallerDispatch($code, $this->output);

		$this->assertCount(1, $statuses, 'the installer dispatch must report exactly one outcome');
		$this->assertStringContainsString('done.', $statuses[0]);
		$this->assertStringNotContainsString('failed.', $statuses[0]);
		$this->assertStringContainsString(self::CONTINENT_NEW, $this->read("{$this->output}/pfblockerng_Africa.php"),
			'the installer dispatch must run the real helper over the output root');
	}

	public function testInstallerDispatchReportsFailedWhenAPublicationIsRefused(): void
	{
		$this->generateCurrentPages();
		$this->downgradeToPreCutoverNavigation();
		$pages = $this->pages();
		$before = $this->snapshots($pages);
		$code = $this->installerDispatchCode();
		$this->requireHelper();

		$this->assertTrue(chmod($this->output, 0555));
		try {
			$statuses = pfb_test_as_unprivileged(
				fn (): array => $this->runInstallerDispatch($code, $this->output),
				[$this->output]
			);
		} finally {
			chmod($this->output, 0755);
		}

		$this->assertCount(1, $statuses, 'the installer dispatch must report exactly one outcome');
		$this->assertStringContainsString('failed.', $statuses[0]);
		$this->assertStringNotContainsString('done.', $statuses[0]);
		$this->assertSame($before, $this->snapshots($pages), 'a refused publication must leave every page byte-identical');
	}

	private function requireHelper(): void
	{
		$this->assertTrue(function_exists('pfb_geoip_refresh_navigation'),
			'pfb_geoip_refresh_navigation(string $output_root): bool must exist in pfblockerng_geoip.inc (missing helper)');
	}

	private function refresh(string $root): bool
	{
		$this->requireHelper();
		return pfb_geoip_refresh_navigation($root);
	}

	/**
	 * Runs the installer's GeoIP dispatch with its helper root and status sink bound to this fixture.
	 *
	 * @return list<string>
	 */
	private function runInstallerDispatch(string $code, string $root): array
	{
		$this->requireHelper();
		$statuses = [];
		pfb_test_page_eval($code, [
			'pfb_nav_root' => $root,
			'pfb_nav_status' => static function (string $status) use (&$statuses): void {
				$statuses[] = $status;
			},
		]);
		return $statuses;
	}

	/** Run the shipped installer branch with its filesystem root and status sink bound to this fixture. */
	private function installerDispatchCode(): string
	{
		$this->requireHelper();
		$code = pfb_test_page_region(self::INSTALL, 'if (pfb_geoip_refresh_navigation())', '// MaxMind Database');
		return str_replace(
			['pfb_geoip_refresh_navigation()', 'update_status('],
			['pfb_geoip_refresh_navigation($pfb_nav_root)', '$pfb_nav_status('],
			$code
		);
	}

	/** Production generator output: current navigation rows and populated continent/Reputation options. */
	private function generateCurrentPages(): void
	{
		$continents = ['Africa', 'Antarctica', 'Asia', 'Europe', 'North America', 'Oceania', 'South America', 'Proxy and Satellite', 'Top Spammers'];
		foreach ($continents as $continent) {
			$slug = str_replace(' ', '_', $continent);
			foreach (['4', '6'] as $type) {
				$countries = $continent === 'Africa' && $type === '4'
					? [['Alpha', 'AA', ['1.1.1.1', '1.1.1.2']], ['Beta', 'BB', ['2.2.2.2']]]
					: [];
				$this->writeContinent($continent, $slug, $type, $countries);
			}
		}
		foreach (['AA', 'BB'] as $iso) {
			foreach (['4', '6'] as $type) {
				touch("{$this->ccdir}/{$iso}_v{$type}.txt");
			}
		}
		$this->assertTrue(pfblockerng_get_countries($this->output), 'the production generator must build the fixture pages');
	}

	/** @param list<array{0: string, 1: string, 2: list<string>}> $countries */
	private function writeContinent(string $continent, string $slug, string $type, array $countries): void
	{
		$filename = $continent === 'Top Spammers' ? "{$slug}_v{$type}.info" : "{$slug}_v{$type}.txt";
		$lines = ["# Continent IPv{$type}: {$continent}", "# Continent en: {$slug}"];
		foreach ($countries as [$country, $iso, $addresses]) {
			$lines[] = "# Country: {$country}";
			$lines[] = "# ISO Code: {$iso}";
			$lines[] = $addresses === [] ? '# Total Networks: NA' : '# Total Networks: ' . count($addresses);
			array_push($lines, ...$addresses);
		}
		$this->assertNotFalse(file_put_contents("{$this->ccdir}/{$filename}", implode("\n", $lines) . "\n"));
	}

	/** Turns each generated page's current DNS row into the literal pre-cutover pair. */
	private function downgradeToPreCutoverNavigation(): void
	{
		foreach ($this->pages() as $page) {
			$current = $this->read($page);
			$this->assertSame(1, substr_count($current, $this->currentRow($page)),
				basename($page) . ' must carry exactly one current DNS row to downgrade');
			$this->assertNotFalse(file_put_contents($page, str_replace($this->currentRow($page), $this->oldPair($page), $current)));
		}
	}

	/** @return list<string> */
	private function pages(): array
	{
		$pages = array_map(fn (string $name): string => "{$this->output}/pfblockerng_{$name}.php", self::CONTINENTS);
		$pages[] = "{$this->output}/pfblockerng_reputation.php";
		return $pages;
	}

	private function isReputation(string $page): bool
	{
		return str_ends_with($page, '/pfblockerng_reputation.php');
	}

	private function oldPair(string $page): string
	{
		return $this->isReputation($page) ? self::REPUTATION_OLD : self::CONTINENT_OLD;
	}

	private function currentRow(string $page): string
	{
		return $this->isReputation($page) ? self::REPUTATION_NEW : self::CONTINENT_NEW;
	}

	private function read(string $path): string
	{
		$bytes = file_get_contents($path);
		$this->assertIsString($bytes, "could not read {$path}");
		return $bytes;
	}

	/** @return array{ino: int, mtime: int, bytes: string} */
	private function snapshot(string $path): array
	{
		clearstatcache();
		$stat = stat($path);
		$this->assertIsArray($stat, "could not stat {$path}");
		return ['ino' => $stat['ino'], 'mtime' => $stat['mtime'], 'bytes' => $this->read($path)];
	}

	/**
	 * @param list<string> $paths
	 * @return array<string, array{ino: int, mtime: int, bytes: string}>
	 */
	private function snapshots(array $paths): array
	{
		$snapshots = [];
		foreach ($paths as $path) {
			$snapshots[$path] = $this->snapshot($path);
		}
		return $snapshots;
	}

	private function pin(string $path): void
	{
		$this->assertTrue(touch($path, self::PAST), "could not pin mtime of {$path}");
	}

	/** @return list<string> */
	private function listing(string $dir): array
	{
		return array_values(array_diff(scandir($dir) ?: [], ['.', '..']));
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path)) {
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$child = "{$path}/{$entry}";
			is_dir($child) ? $this->removeTree($child) : @unlink($child);
		}
		@rmdir($path);
	}
}
