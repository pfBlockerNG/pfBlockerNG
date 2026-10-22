<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyRcSandboxTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3566 -- the generated rc script's top-level `stop` leaves the DNS proxy running across a package upgrade.
 *
 * Intent pinned here: when an ancestor of the stop is pfSense's `rc.packages ... DEINSTALL` AND the nearest classifiable
 * pkg/pkg-static ancestor (classified as pfb_pkg_operation() does) is an install, upgrade or reinstall, the stop leaves both
 * processes running and logs that it did. Everything else stops as before: a delete, no pkg ancestor, no DEINSTALL ancestor,
 * an unreadable process table. The script's own `rc_stop` calls from start and restart never leave anything running.
 *
 * The real script runs under dash in the sandbox of DnsProxyRcSandboxTrait; its `ps` double answers the ancestry from a table.
 * The script runs in a directory holding entries a hostile argv glob would expand to.
 */
#[CoversFunction('pfb_dns_proxy_service')]
final class DnsProxyUpgradeStopTest extends TestCase
{
	use DnsProxyRcSandboxTrait;

	private const DEINSTALL = '/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG DEINSTALL';
	private const SHELL = '/bin/sh /tmp/x';
	private const FILLER = '/bin/sh /tmp/filler';
	private const KEPT_LOG = 'left running across the package upgrade';

	protected function setUp(): void
	{
		$this->sandboxUp();
	}

	protected function tearDown(): void
	{
		$this->sandboxDown();
	}

	/**
	 * Generate the script and seed a serving proxy and the stop's ancestry.
	 *
	 * @param list<string> $ancestors the stop's ancestors above its own `sh -c`, nearest first
	 */
	private function arrangeStop(array $ancestors, bool $psFails = FALSE, string $lastPpid = '1'): void
	{
		$this->moveResolver();
		pfb_dns_proxy_service();
		$this->arrange([], '2', '1', TRUE);
		$this->ancestry(array_merge([
			'/bin/sh /usr/local/etc/rc.d/pfb_dns_proxy.sh stop',
			'sh -c /usr/local/etc/rc.d/pfb_dns_proxy.sh stop',
		], $ancestors), $psFails, $lastPpid);
		// Run in a directory a glob in an argv would expand against: `upgrade`, `DEINSTALL` and `-o` are entries there
		$glob = "{$this->dir}/glob";
		mkdir($glob);
		foreach (['upgrade', 'DEINSTALL', '-o'] as $entry) {
			touch("{$glob}/{$entry}");
		}
		file_put_contents("{$this->dir}/run.sh", "cd '{$glob}' || exit 99\n" . file_get_contents("{$this->dir}/run.sh"));
	}

	private function assertGlobDirUntouched(): void
	{
		$entries = array_values(array_diff(scandir("{$this->dir}/glob") ?: [], ['.', '..']));
		$this->assertSame(['-o', 'DEINSTALL', 'upgrade'], $entries, 'an argv word was executed or written through');
	}

	private function assertLeftRunning(int $status, string $output): void
	{
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['log'], $this->events(TRUE), 'no signal, no wait, one log line');
		$this->assertSame(['1001', '1002'], $this->livePids(), 'the proxy was left running');
		$this->assertFileExists($this->pidfile('pfb_dns_proxy_daemon.pid'));
		$this->assertFileExists($this->pidfile('pfb_dns_proxy.pid'));
		$logged = (string) file_get_contents("{$this->dir}/state/logger");
		$this->assertStringContainsString(self::KEPT_LOG, $logged);
		$this->assertStringContainsString('[' . LOG_PREFIX_PKG_PFBLOCKERNG . ']', $logged, 'the house log prefix');
		$this->assertFileExists($this->keptFile(), 'the script keeps a copy of itself: pfSense unlinks it right after this stop');
		$this->assertSame((string) file_get_contents("{$this->dir}/run.sh"), (string) @file_get_contents($this->keptFile()), 'the copy is the script byte for byte');
		$this->assertGlobDirUntouched();
	}

	private function assertStopped(int $status, string $output): void
	{
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep'], $this->events(TRUE), 'TERM, then the wait for both to exit');
		$this->assertSame([], $this->livePids(), 'the proxy was stopped');
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy_daemon.pid'));
		$this->assertFileDoesNotExist($this->pidfile('pfb_dns_proxy.pid'));
		$this->assertStringNotContainsString(self::KEPT_LOG, (string) file_get_contents("{$this->dir}/state/logger"));
		$this->assertFileDoesNotExist($this->keptFile(), 'a stop that stopped the proxy keeps no copy');
		$this->assertGlobDirUntouched();
	}

	/** @return array<string,array{list<string>}> ancestors above the stop's `sh -c`, nearest first */
	public static function upgradeRows(): array
	{
		$d = self::DEINSTALL;
		$s = self::SHELL;
		return [
			'pkg upgrade'                      => [[$d, $s, 'pkg upgrade -y pfSense-pkg-pfBlockerNG']],
			'pkg-static install -f (reinstall)' => [[$d, $s, '/usr/local/sbin/pkg-static install -f pfSense-pkg-pfBlockerNG']],
			'bundled -fy (reinstall)'          => [[$d, $s, 'pkg install -fy x']],
			'--force (reinstall)'              => [[$d, $s, 'pkg install --force x']],
			'pkg install'                      => [[$d, $s, 'pkg install x']],
			'global options with values'       => [[$d, $s, 'pkg -o ABI=x -r /rootdir upgrade']],
			'attached long option, upper case' => [[$d, $s, 'pkg --rootdir=/x UPGRADE']],
			'glued short value'                => [[$d, $s, 'pkg -r/x upgrade']],
			'path-qualified pkg'               => [[$d, $s, '/usr/sbin/pkg upgrade']],
			'unclassifiable pkg below upgrade' => [[$d, $s, 'pkg -C cfg query x', 'pkg upgrade -y x']],
			'pkg right above rc.packages'      => [[$d, 'pkg upgrade']],
			'deinstall above the pkg'          => [['pkg upgrade', $s, $d]],
			'glob and tabs in the pkg argv'    => [[$d, $s, "pkg\t\tupgrade   -y\tx *"]],
			'glob that expands to a value-taking option' => [[$d, $s, 'pkg -* upgrade']],
			'metacharacters in the pkg argv'   => [[$d, $s, 'pkg upgrade -y $(touch PWNED); echo x; `touch PWNED2` "a b\' c']],
			'metacharacters in rc.packages'    => [['/usr/local/bin/php -f /etc/rc.packages $(touch PWNED3) `touch PWNED4`; DEINSTALL', $s, 'pkg upgrade']],
			'tabs in rc.packages'              => [["/usr/local/bin/php\t-f  /etc/rc.packages\tp\t\tDEINSTALL", $s, 'pkg upgrade']],
		];
	}

	/** @param list<string> $ancestors */
	#[DataProvider('upgradeRows')]
	public function testAStopUnderAPackageUpgradeLeavesTheProxyRunningAndSaysSo(array $ancestors): void
	{
		$this->arrangeStop($ancestors);

		[$status, $output] = $this->rc('stop');

		$this->assertLeftRunning($status, $output);
	}

	/** @return array<string,array{list<string>}> */
	public static function teardownRows(): array
	{
		$d = self::DEINSTALL;
		$s = self::SHELL;
		return [
			'pkg delete'                        => [[$d, $s, 'pkg delete -y x']],
			'pkg remove'                        => [[$d, $s, 'pkg remove x']],
			'pkg autoremove'                    => [[$d, $s, 'pkg autoremove']],
			'delete below an upgrade'           => [[$d, 'pkg delete -y x', $s, 'pkg upgrade']],
			'delete, pkg-static, upper case'    => [[$d, $s, '/usr/local/sbin/pkg-static DELETE x']],
			'deinstall, no pkg ancestor'        => [[$d, $s]],
			'only the stop itself, no ancestor' => [[]],
			'pkg upgrade, POST-INSTALL'         => [['/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG POST-INSTALL', $s, 'pkg upgrade']],
			'pkg upgrade, POST-DEINSTALL'       => [['/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG POST-DEINSTALL', $s, 'pkg upgrade']],
			'pkg upgrade, PRE-DEINSTALL'        => [['/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG PRE-DEINSTALL', $s, 'pkg upgrade']],
			'pkg upgrade, no rc.packages'       => [[$s, 'pkg upgrade -y x']],
			'DEINSTALL without rc.packages'     => [['/usr/local/bin/php -f /etc/rc.packages.bak x DEINSTALL', $s, 'pkg upgrade']],
			'DEINSTALL before rc.packages'      => [['/usr/local/bin/php -f DEINSTALL /etc/rc.packages x', $s, 'pkg upgrade']],
			'DEINSTALL in another ancestor'     => [['/usr/local/bin/php -f /etc/rc.packages x', 'DEINSTALL', 'pkg upgrade']],
			'pkg with only global options'      => [[$d, $s, 'pkg -o ABI=x -v']],
			'pkg with a trailing option value'  => [[$d, $s, 'pkg -o']],
			'bare pkg'                          => [[$d, $s, 'pkg']],
			'other command, not pkg'            => [[$d, $s, '/usr/local/bin/mypkg upgrade']],
			'unknown pkg subcommand'            => [[$d, $s, 'pkg query x']],
			'glob that would expand to rc.packages args' => [['/usr/local/bin/php -f /etc/rc.packages x DEINSTAL?', $s, 'pkg upgrade']],
			'glob that would expand to a subcommand' => [[$d, $s, 'pkg ?pgrade']],
		];
	}

	/** @param list<string> $ancestors */
	#[DataProvider('teardownRows')]
	public function testAStopThatIsNoPackageUpgradeStopsTheProxy(array $ancestors): void
	{
		$this->arrangeStop($ancestors);

		[$status, $output] = $this->rc('stop');

		$this->assertStopped($status, $output);
	}

	public function testAStopWhenPsFailsStopsTheProxy(): void
	{
		$this->arrangeStop([self::DEINSTALL, self::SHELL, 'pkg upgrade'], TRUE);

		[$status, $output] = $this->rc('stop');

		$this->assertStopped($status, $output);
		$this->assertGreaterThan(0, $this->ancestryQueries(), 'precondition: the probe asked ps');
	}

	public function testAStopWhoseAncestryBreaksBeforeThePkgIsFoundStopsTheProxy(): void
	{
		// Given rc.packages DEINSTALL seen, then a parent ps knows nothing about
		$this->arrangeStop([self::DEINSTALL], FALSE, '999');

		[$status, $output] = $this->rc('stop');

		$this->assertStopped($status, $output);
	}

	public function testACycleInTheAncestryEndsTheWalkAndStopsTheProxy(): void
	{
		// Given ancestors that are each other's parent and name neither rc.packages nor pkg
		$this->arrangeStop([self::FILLER], FALSE, '501');

		[$status, $output] = $this->rc('stop');

		$this->assertStopped($status, $output);
		$this->assertLessThanOrEqual(64, $this->ancestryQueries(), 'the walk is bounded');
	}

	/** @param list<string> $upper */
	private function longChain(int $depth, array $upper): array
	{
		// $depth fillers, then $upper: the stop itself and its `sh -c` are the first two processes of the walk
		return array_merge(array_fill(0, $depth, self::FILLER), $upper);
	}

	public function testTheWalkReachesTheSixtyFourthProcessAndNoFurther(): void
	{
		// Given pkg upgrade and rc.packages DEINSTALL as the 63rd and 64th processes from the stop (counting it as the first)
		$this->arrangeStop($this->longChain(60, ['pkg upgrade', self::DEINSTALL]));

		[$status, $output] = $this->rc('stop');

		$this->assertLeftRunning($status, $output);
		$this->assertSame(64, $this->ancestryQueries(), 'the walk stops at the 64th process');
	}

	public function testAChainLongerThanSixtyFourProcessesStopsTheProxyAfterSixtyFourQueries(): void
	{
		// Given the same pair one process further out
		$this->arrangeStop($this->longChain(61, ['pkg upgrade', self::DEINSTALL]));

		[$status, $output] = $this->rc('stop');

		$this->assertStopped($status, $output);
		$this->assertSame(64, $this->ancestryQueries(), 'the walk stops at the 64th process');
	}

	public function testARestartUnderAPackageUpgradeStillStopsAndStartsTheProxy(): void
	{
		// Given the upgrade's ancestry and a serving proxy
		$this->arrangeStop([self::DEINSTALL, self::SHELL, 'pkg upgrade -y pfSense-pkg-pfBlockerNG']);

		[$status, $output] = $this->rc('restart');

		// Then the restart's own stop ran, and the proxy was replaced
		$this->assertSame(0, $status, "rc restart failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events());
		$this->assertSame(['3001', '3002'], $this->livePids());
		$this->assertSame(0, $this->ancestryQueries(), 'the internal stop never asks about the ancestry');
		$this->assertStringNotContainsString(self::KEPT_LOG, (string) file_get_contents("{$this->dir}/state/logger"));
	}

	public function testAStartOverAnUnhealthyProxyUnderAPackageUpgradeStillStopsItFirst(): void
	{
		// Given the upgrade's ancestry and a supervisor whose child is gone
		$this->arrangeStop([self::DEINSTALL, self::SHELL, 'pkg upgrade -y pfSense-pkg-pfBlockerNG']);
		file_put_contents($this->pidfile('pfb_dns_proxy.pid'), "4242\n");
		file_put_contents("{$this->dir}/state/procs", "1001|{$this->dir}/run/pfb_dns_proxy_daemon.pid|||daemon: pfb_dns_proxy[4242] (daemon)\n");

		[$status, $output] = $this->rc('start');

		// Then the start's stop ran before the launch
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events());
		$this->assertSame(['3001', '3002'], $this->livePids());
		$this->assertSame(0, $this->ancestryQueries(), 'the internal stop never asks about the ancestry');
		$this->assertStringNotContainsString(self::KEPT_LOG, (string) file_get_contents("{$this->dir}/state/logger"));
	}
}
