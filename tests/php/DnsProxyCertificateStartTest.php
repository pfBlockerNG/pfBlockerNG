<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyRcSandboxTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the generated rc script's start and the Resolver's certificate. On a /var that came up empty (RAM disks) the
 * proxy starts with no certificate file, and DoT, DoH and DoQ would be refused until the next apply or cron tick. The start
 * therefore has PHP write it first: `php -f pfblockerng.inc dns_cert` under timeout(1), once, only when the file is missing.
 * Intent pinned here, with the real generated script run under dash over command doubles:
 *   - a missing file at start runs the export exactly once, inside a 30 s limit (the start holds the start lock, which a second
 *     start waits for at most 10 s), and the proxy launches after it;
 *   - a file that is there is never rewritten by the start: PHP is not run;
 *   - an export that does not finish (the limit fires) or fails never stops the start: plain DNS must serve, so the script logs
 *     that DoT, DoH and DoQ are not served and launches the proxy;
 *   - the verb's exit status is what pfb_dns_proxy_certificate_refresh() returns: 0 once the file holds the Resolver's
 *     certificate, 1 with a notice when it cannot.
 */
#[CoversFunction('pfb_dns_proxy_service')]
#[CoversFunction('pfb_dns_proxy_certificate_refresh')]
final class DnsProxyCertificateStartTest extends TestCase
{
	use DnsProxyRcSandboxTrait;

	protected function setUp(): void
	{
		$this->sandboxUp();
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_file_notices']);
		$this->sandboxDown();
	}

	/** @return list<string> the lines a command double recorded */
	private function recorded(string $file): array
	{
		return array_values(array_filter(explode("\n", (string) file_get_contents("{$this->dir}/state/{$file}"))));
	}

	/** A box whose proxy was generated for DoT, with no certificate file at start. */
	private function startWithNoCertificateFile(array $gates = []): array
	{
		$this->moveResolver(TRUE);
		pfb_dns_proxy_service();
		unlink($this->certFile());
		$this->arrange($gates);
		return $this->rc('start');
	}

	public function testAMissingFileAtStartRunsTheExportOnceUnderALimitBeforeTheLaunch(): void
	{
		// Given DoT wanted and no certificate file, as after a boot with RAM disks
		// When the proxy starts
		[$status, $output] = $this->startWithNoCertificateFile();

		// Then PHP runs the dns_cert verb once, inside timeout -s TERM -k 5 30, and the proxy launches after it
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['export', 'launch'], $this->events());
		$this->assertSame(
			["-s TERM -k 5 30 {$this->dir}/bin/php -f /usr/local/pkg/pfblockerng/pfblockerng.inc dns_cert"],
			$this->recorded('timeout.args'),
			'one bounded run: 5 s from TERM to KILL, 30 s in all'
		);
		$this->assertSame(['-f /usr/local/pkg/pfblockerng/pfblockerng.inc dns_cert'], $this->recorded('php.args'));
		$this->assertFileExists($this->certFile());
	}

	public function testAFileThatIsThereIsNeverTouchedByTheStart(): void
	{
		$this->moveResolver(TRUE);
		pfb_dns_proxy_service();
		$this->assertFileExists($this->certFile(), 'the apply wrote it');
		$this->arrange();

		[$status, $output] = $this->rc('start');

		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertSame([], $this->recorded('timeout.args'), 'PHP is not even started');
	}

	public function testAStartForgetsWhatWasPushedToTheGatewayBeforeIt(): void
	{
		// Given a certificate pushed to the gateway that is now to be replaced by a new process
		$this->moveResolver(TRUE);
		pfb_dns_proxy_service();
		file_put_contents($this->pushedFile(), hash('sha256', (string) file_get_contents($this->certFile())));
		$this->arrange();

		// When the proxy starts
		[$status, $output] = $this->rc('start');

		// Then the record is gone, so the next apply or tick pushes to the new process whatever it read at start; the file stays
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['launch'], $this->events());
		$this->assertFileDoesNotExist($this->pushedFile());
		$this->assertFileExists($this->certFile());
	}

	public function testAStartThatKeepsTheRunningGatewayKeepsTheRecordOfWhatItWasPushed(): void
	{
		// Given a gateway that serves, and what was pushed to it on record
		$this->moveResolver(TRUE);
		pfb_dns_proxy_service();
		file_put_contents($this->pushedFile(), 'the digest of what the running gateway has');
		$this->arrange([], '2', '1', TRUE);

		// When a second start finds it serving
		[$status, $output] = $this->rc('start');

		// Then nothing is launched and the record still describes that gateway
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame([], $this->events());
		$this->assertSame('the digest of what the running gateway has', (string) file_get_contents($this->pushedFile()));
	}

	public function testAnExportThatTheLimitKillsLeavesPlainDnsServingAndSaysWhatIsNotServed(): void
	{
		// Given the same start, and a limit that fires before PHP did anything
		[$status, $output] = $this->startWithNoCertificateFile(['TIMEOUT_FIRES' => '1']);

		// Then the start goes on to the launch, after one warning, and PHP never ran
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['log', 'launch', 'log'], $this->events(TRUE), 'the warning, the launch, then the usual "started" line');
		$this->assertSame([], $this->recorded('php.args'));
		$this->assertStringContainsString('DoT, DoH and DoQ are not served until it is', implode("\n", $this->recorded('logger')));
		$this->assertFileDoesNotExist($this->certFile());
	}

	public function testTheVerbsExitStatusIsWhetherTheFileHoldsTheResolversCertificate(): void
	{
		// Given a Resolver with a usable certificate: the verb exits 0
		$this->moveResolver(TRUE);
		$this->assertTrue(pfb_dns_proxy_certificate_refresh(TRUE));
		$this->assertFileExists($this->certFile());
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);

		// When the certificate becomes unusable (no certificate chosen): the verb exits 1 and says why, and the file stays
		$served = (string) file_get_contents($this->certFile());
		$GLOBALS['config']['unbound']['sslcertref'] = '';
		$this->assertFalse(pfb_dns_proxy_certificate_refresh(TRUE));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertSame($served, (string) file_get_contents($this->certFile()));
	}
}
