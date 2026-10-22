<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3560 -- the upstream a serving proxy relies on is the one its running gateway was started with, read from the process table
 * (PFB_DNS_PROXY_PS), not from the rc script on disk. The rc script is the desired state an apply writes: an update that was not
 * applied, a package upgrade that unlinked it, and an orphaned Resolver whose rc refuses to start all leave it out of step with the
 * process that runs. Readiness asks the process what it forwards to, and that Unbound owns that endpoint over TCP and UDP.
 */
#[CoversFunction('pfb_dns_proxy_upstream_ready')]
#[CoversFunction('pfb_dns_proxy_serving_ready')]
#[CoversFunction('pfb_dns_status')]
final class DnsProxyRunningUpstreamTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const ORPHAN_RC = "#!/bin/sh\n# refused: the Resolver carries our block and its snapshot is gone\n";

	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'pfb_test_interface_ip', 'pfb_test_rcfile_dir'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_interface_ip'] = ['lo0' => '127.0.0.1'];
		$GLOBALS['pfb_test_rcfile_dir'] = dirname(PFB_DNS_PROXY_RCFILE);
		$this->clearProxyFiles();
		$this->setUpUpstreamFixture();
	}

	protected function tearDown(): void
	{
		$this->tearDownUpstreamFixture();
		$this->clearProxyFiles();
		@unlink(PFB_DNS_PROXY_RCFILE);
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	/** The rc script an apply writes: the desired state, whether or not the running gateway was started from it. */
	private function desiredRc(string $upstream): void
	{
		file_put_contents(PFB_DNS_PROXY_RCFILE, "#!/bin/sh\n/usr/sbin/daemon -p /var/run/pfb_dns_proxy.pid " . PFB_DNS_PROXY_DIR
			. "/pfb_dns.sh --listen 127.0.0.1 --port 53 --upstream {$upstream}\n");
	}

	/** A live gateway (child pid 4242, marker published) whose process table row is `$commandLine` (NULL: no row at all). */
	private function runningGateway(?string $upstream = '127.0.0.1:5353'): void
	{
		$this->proxyServes();
		$this->seedRunningGateway('4242', $upstream);
	}

	/** Our block in the Resolver with no snapshot to put back, and pfB-DNS on: the orphaned state the status reads as recovery. */
	private function orphanedResolver(): void
	{
		$GLOBALS['config']['unbound'] = [
			'active_interface' => 'lo0',
			'custom_options'   => base64_encode("server:\n# pfBlockerNG DNS proxy\nport: 5354\n# end pfBlockerNG DNS proxy"),
		];
		config_set_path(self::SAVED, '');
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;
	}

	/** The process table's row for the child: an arbitrary command line, written as ps would print it. */
	private function processTableRow(string $commandLine): void
	{
		file_put_contents($GLOBALS['pfb_test_ps_output'], "4242 {$commandLine}\n");
	}

	public function testTheRunningGatewayServesFromTheUpstreamItWasStartedWithNotTheDesiredRc(): void
	{
		// Given a gateway running with --upstream 127.0.0.1:5353, and an apply's rc asking for 5354 that was never applied
		$this->runningGateway('127.0.0.1:5353');
		$this->desiredRc('127.0.0.1:5354');
		// And Unbound owns the endpoint the running gateway forwards to
		$this->seedUnbound('127.0.0.1:5353');

		// Then the proxy serves: what it forwards to is what it runs with
		$this->assertTrue(pfb_dns_proxy_serving_ready());
	}

	public function testUnboundOwningOnlyTheDesiredEndpointDoesNotServeForTheRunningGateway(): void
	{
		// Given the same running gateway on 5353, and Unbound owning only 5354, which the unapplied rc asks for
		$this->runningGateway('127.0.0.1:5353');
		$this->desiredRc('127.0.0.1:5354');
		$this->seedUnbound('127.0.0.1:5354');

		// Then the proxy does not serve: nothing owns the endpoint the running gateway forwards to
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the running gateway forwards to 5353, which nothing owns');
	}

	public function testAnOrphanedRcThatNamesNoDaemonDoesNotStopAHealthyRunningGatewayFromServing(): void
	{
		// Given the refusal script on disk (no daemon line) and a running gateway on 5353 that Unbound backs
		$this->runningGateway('127.0.0.1:5353');
		file_put_contents(PFB_DNS_PROXY_RCFILE, self::ORPHAN_RC);
		$this->seedUnbound('127.0.0.1:5353');

		// Then the proxy serves: the rc on disk names no endpoint, the running process does
		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'the rc on disk names no endpoint, but the running gateway forwards to 5353');
	}

	public function testAnOrphanedResolverWithAHealthyRunningGatewayReadsRunningInRecoveryMode(): void
	{
		$this->orphanedResolver();
		$this->runningGateway('127.0.0.1:5353');
		file_put_contents(PFB_DNS_PROXY_RCFILE, self::ORPHAN_RC);
		$this->seedUnbound('127.0.0.1:5353');

		$status = pfb_dns_status();

		$this->assertSame('Running', $status['service'], 'the service is what the proxy really does');
		$this->assertStringStartsWith('Recovery required', $status['mode']);
	}

	public function testAnOrphanedResolverWithADeadBackendReadsStartingNotRunning(): void
	{
		$this->orphanedResolver();
		$this->runningGateway('127.0.0.1:5353');
		file_put_contents(PFB_DNS_PROXY_RCFILE, self::ORPHAN_RC);
		$this->seedUnbound('127.0.0.1:5353', '5151', FALSE);

		$this->assertSame('Starting', pfb_dns_status()['service']);
	}

	public function testAGatewayCommandWithNoUpstreamFailsClosedEvenWhenTheRcNamesAHealthyOne(): void
	{
		$this->runningGateway(NULL);
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the running command names no upstream, so there is no endpoint to confirm');
	}

	public function testAGatewayCommandWithTwoUpstreamsFailsClosed(): void
	{
		$this->proxyServes();
		$this->processTableRow(PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns --upstream 127.0.0.1:5353 --upstream 127.0.0.1:5353');
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'an ambiguous command line names no single endpoint');
	}

	public function testAnUnparsableRunningUpstreamFailsClosed(): void
	{
		$this->proxyServes();
		$this->processTableRow(PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns --upstream not-an-endpoint');
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the strict endpoint validation rejects it');
	}

	public function testAProcessThatIsNotTheInstalledGatewayFailsClosed(): void
	{
		$this->proxyServes();
		$this->processTableRow('/usr/bin/someone-else --upstream 127.0.0.1:5353');
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the child pidfile names a process that is not the installed gateway');
	}

	public function testAnotherBinaryUnderTheSameDirectoryFailsClosed(): void
	{
		$this->proxyServes();
		$this->processTableRow(PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns-debug --upstream 127.0.0.1:5353');
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'a binary that only shares the name prefix is not the gateway the wrapper execs');
	}

	public function testAGatewayPidTheProcessTableDoesNotShowFailsClosed(): void
	{
		$this->proxyServes();
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'no running command for the child pid: nothing to confirm the upstream against');
	}

	public function testTheBinaryOfTheOtherArchitectureTheWrapperExecsIsTheSameGateway(): void
	{
		$this->proxyServes();
		$this->processTableRow(PFB_DNS_PROXY_DIR . '/bin/freebsd-arm64/pfb-dns --listen 127.0.0.1 --port 53 --upstream 127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'pfb_dns.sh execs bin/<target>/pfb-dns for the machine it runs on');
	}
}
