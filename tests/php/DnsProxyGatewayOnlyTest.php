<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyRcSandboxTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3517 -- pfB-DNS runs only through the Go gateway.
 *
 * Function under test: pfb_dns_proxy_service() -- writes /usr/local/etc/rc.d/pfb_dns_proxy.sh. Intent pinned here:
 *   - the script has one launch line, through pfb_dns.sh, whatever the package ships: there is no Python listener to
 *     fall back to, and the Python proxy is only the gateway's decider (`--decision-fd 3`);
 *   - a package with no pfb-dns this machine can run (no payload at all, the other architecture's only, a binary that
 *     is not executable, a machine the package has no binary for) is not started by anything else: the launch line
 *     the daemon is given exits nonzero with the wrapper's reason on its stderr, which daemon(8) writes to the proxy
 *     log, and runs no binary. The supervisor starts it again, no ready marker is ever published, and the activation's
 *     readiness wait rolls back (DnsProxyActivationRollbackTest);
 *   - a package with a binary for this machine launches it through the wrapper, with the decider after `--`.
 *
 * The real script runs under dash in the sandbox of DnsProxyRcSandboxTrait, with the SHIPPED pfb_dns.sh beside the
 * pfb-dns stand-ins and a `uname` double that says which machine it is. The launch line the daemon double recorded is
 * then run for real.
 */
#[CoversFunction('pfb_dns_proxy_service')]
final class DnsProxyGatewayOnlyTest extends TestCase
{
	use DnsProxyRcSandboxTrait;

	protected function setUp(): void
	{
		$this->sandboxUp();
	}

	protected function tearDown(): void
	{
		$this->sandboxDown();
	}

	/**
	 * The package's dns_proxy directory: the shipped pfb_dns.sh and a pfb-dns stand-in under each bin/<target>, which
	 * leaves a marker file when it is run.
	 *
	 * @param list<string> $targets
	 */
	private function package(array $targets, int $mode = 0555): string
	{
		$dir = "{$this->dir}/dns_proxy";
		$this->assertTrue(is_dir($dir) || mkdir($dir, 0777, TRUE), 'package mkdir failed');
		$shipped = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns.sh';
		$this->assertTrue(copy($shipped, "{$dir}/pfb_dns.sh"), "cannot copy {$shipped}");
		foreach ($targets as $target) {
			$this->assertTrue(is_dir("{$dir}/bin/{$target}") || mkdir("{$dir}/bin/{$target}", 0777, TRUE), "payload mkdir failed: {$target}");
			file_put_contents("{$dir}/bin/{$target}/pfb-dns", "#!/bin/sh\necho \"{$target}\" > '{$this->dir}/ran'\n");
			chmod("{$dir}/bin/{$target}/pfb-dns", $mode);
		}
		return $dir;
	}

	/** @return list<string> the argv of the daemon launch the rc `start` of the script generated for $proxyDir made on a machine whose `uname -p` is $machine */
	private function startAndReadLaunch(string $proxyDir, string $machine): array
	{
		$this->moveResolver(FALSE, 'lan', ['lan' => '192.0.2.1']);
		pfb_dns_proxy_service($proxyDir);
		$this->arrange([], '2', '1', FALSE, $machine);
		[$status, $output] = $this->rc('start');
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events(), 'exactly one launch');
		return $this->daemonArgv();
	}

	/**
	 * Run the command daemon(8) was given, as daemon(8) would: its stdout and stderr, which daemon -o puts in the log.
	 *
	 * @param list<string> $launch the daemon double's argv
	 * @return array{0: int, 1: string}
	 */
	private function runWhatDaemonLaunched(array $launch): array
	{
		$command = array_slice($launch, (int) array_search('/bin/sh', $launch, TRUE));
		$run = pfb_test_run_process($command, 20.0, ['PATH' => "{$this->dir}/bin:" . (string) getenv('PATH')]);
		return [$run['exit'], $run['stdout'] . $run['stderr']];
	}

	/** @return array<string,array{list<string>,int,string,int,string}> payload targets, their mode, the machine, the wrapper's status, what its message names */
	public static function unusablePackages(): array
	{
		return [
			'no payload at all'            => [[], 0555, 'amd64', 3, 'no pfb-dns binary'],
			'the other architecture only'  => [['freebsd-arm64'], 0555, 'amd64', 1, 'freebsd-amd64'],
			'the amd64 binary on arm64'    => [['freebsd-amd64'], 0555, 'aarch64', 1, 'freebsd-arm64'],
			'no execute bit'               => [['freebsd-amd64', 'freebsd-arm64'], 0644, 'amd64', 1, 'freebsd-amd64'],
			'a machine with no binary'     => [['freebsd-amd64', 'freebsd-arm64'], 0555, 'riscv64', 1, 'riscv64'],
		];
	}

	/** @param list<string> $targets */
	#[DataProvider('unusablePackages')]
	public function testAPackageThisMachineCannotRunStillLaunchesTheWrapperWhichFailsLoudlyAndRunsNothing(array $targets, int $mode, string $machine, int $status, string $named): void
	{
		// Given a package with no pfb-dns this machine can run
		$proxyDir = $this->package($targets, $mode);

		// When the rc service starts
		$launch = $this->startAndReadLaunch($proxyDir, $machine);

		// Then the daemon is given the wrapper, never the Python proxy as a listener
		$this->assertContains('/bin/sh', $launch);
		$this->assertContains("{$proxyDir}/pfb_dns.sh", $launch, 'the daemon runs the wrapper');
		$this->assertNotContains('--decision-fd', array_slice($launch, 0, (int) array_search('--', $launch, TRUE)), 'the Python proxy is only ever the decider after `--`');

		// And what it launched fails with the wrapper's status and reason, and ran no binary
		[$exit, $output] = $this->runWhatDaemonLaunched($launch);
		$this->assertSame($status, $exit, "the wrapper's status: {$output}");
		$this->assertStringContainsString($named, $output, 'the wrapper says why on its stderr');
		$this->assertFileDoesNotExist("{$this->dir}/ran", 'no pfb-dns ran');
	}

	/** @return array<string,array{string,string}> the machine's `uname -p`, the bin/<target> that serves it */
	public static function machines(): array
	{
		return ['amd64' => ['amd64', 'freebsd-amd64'], 'aarch64' => ['aarch64', 'freebsd-arm64'], 'arm64' => ['arm64', 'freebsd-arm64']];
	}

	#[DataProvider('machines')]
	public function testAPackageWithABinaryForThisMachineLaunchesItThroughTheWrapperWithTheDeciderAfterTheSeparator(string $machine, string $target): void
	{
		// Given a package that ships a pfb-dns for this machine
		$proxyDir = $this->package(['freebsd-amd64', 'freebsd-arm64']);

		// When the rc service starts
		$launch = $this->startAndReadLaunch($proxyDir, $machine);

		// Then the daemon runs the wrapper, with the Python proxy as the decider after `--`
		$wrapper = (int) array_search("{$proxyDir}/pfb_dns.sh", $launch, TRUE);
		$this->assertGreaterThan(0, $wrapper, 'the daemon runs the wrapper');
		$this->assertSame('/bin/sh', $launch[$wrapper - 1]);
		$separator = (int) array_search('--', $launch, TRUE);
		$this->assertSame(
			['/usr/local/pkg/pfblockerng/pfb_python.sh', '-u', '/usr/local/pkg/pfblockerng/dns_proxy/pfb_dns_proxy.py', '--decision-fd', '3'],
			array_slice($launch, $separator + 1, 5),
			'the decider follows the separator'
		);

		// And the wrapper runs this machine's binary
		[$exit, $output] = $this->runWhatDaemonLaunched($launch);
		$this->assertSame(0, $exit, "the stand-in binary: {$output}");
		$this->assertSame("{$target}\n", file_get_contents("{$this->dir}/ran"), 'the binary of this machine ran');
	}

	public function testTheScriptHasOneLaunchLineThroughTheWrapperWhateverThePackageShips(): void
	{
		// Given the script generated for a package with no payload
		$proxyDir = $this->package([]);
		$this->moveResolver(TRUE, 'lan', ['lan' => '192.0.2.1']);
		pfb_dns_proxy_service($proxyDir);
		$withoutPayload = $this->rcText();

		// Then its one launch line is the wrapper's, with the Python proxy as the decider, and no Python listener
		$this->assertStringContainsString("/bin/sh '{$proxyDir}/pfb_dns.sh' ", $withoutPayload);
		$this->assertStringContainsString('--decision-fd 3', $withoutPayload);
		$this->assertSame(1, substr_count($withoutPayload, '/usr/sbin/daemon '), 'one launch line');
		$this->assertStringNotContainsString('pfb_dns_proxy.py --listen', $withoutPayload, 'there is no standalone Python listener');

		// When the package ships a payload and the script is generated again
		$this->package(['freebsd-amd64', 'freebsd-arm64']);
		pfb_dns_proxy_service($proxyDir);

		// Then it is the same script, byte for byte: the payload is the wrapper's business when the service starts
		$this->assertSame($withoutPayload, $this->rcText());
	}
}
