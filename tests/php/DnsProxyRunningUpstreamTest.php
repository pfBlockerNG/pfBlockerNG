<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3560 -- readiness uses the applied upstream, never the desired rc script on disk. An unapplied update, a missing script
 * or an orphaned Resolver must not override the running gateway. Unbound must own that applied endpoint over both TCP and UDP.
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

	/** A live gateway (child pid 4242, marker published) with the applied upstream (NULL: malformed missing endpoint). */
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

	/** Applied identity supplied independently of the desired rc script. */
	private function appliedIdentity(array $fields): void
	{
		$this->gatewayStatus($fields);
		$this->standIn($GLOBALS['pfb']['dns_proxy_ctl']);
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

	public function testAGatewayStatusWithNoUpstreamFailsClosedEvenWhenTheRcNamesAHealthyOne(): void
	{
		$this->runningGateway(NULL);
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'applied status names no upstream, so there is no endpoint to confirm');
	}

	public function testAGatewayStatusWithTwoUpstreamsFailsClosed(): void
	{
		$this->proxyServes();
		$this->appliedIdentity(['upstream' => ['127.0.0.1:5353', '127.0.0.1:5353']]);
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'an ambiguous applied endpoint is not a single upstream');
	}

	public function testAnUnparsableRunningUpstreamFailsClosed(): void
	{
		$this->proxyServes();
		$this->appliedIdentity(['upstream' => 'not-an-endpoint']);
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the strict endpoint validation rejects it');
	}

	public function testAProcessThatIsNotTheInstalledGatewayFailsClosed(): void
	{
		$this->proxyServes();
		$this->appliedIdentity(['executable' => '/usr/bin/someone-else']);
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'the child pidfile names a process that is not the installed gateway');
	}

	public function testAnotherBinaryUnderTheSameDirectoryFailsClosed(): void
	{
		$this->proxyServes();
		$this->appliedIdentity(['executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns-debug']);
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

	public function testAGatewayStatusForAnotherPidFailsClosed(): void
	{
		$this->proxyServes();
		$this->appliedIdentity(['pid' => 4243]);
		$this->desiredRc('127.0.0.1:5353');
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'status names another PID, not the child in the pidfile');
	}

	public function testTheBinaryOfTheOtherArchitectureTheWrapperExecsIsTheSameGateway(): void
	{
		$this->proxyServes();
		$this->appliedIdentity(['executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-arm64/pfb-dns']);
		$this->seedUnbound('127.0.0.1:5353');

		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'pfb_dns.sh execs bin/<target>/pfb-dns for the machine it runs on');
	}

	public function testALiteralQuotedUpstreamFailsClosed(): void
	{
		// Literal quotes are not part of a canonical applied endpoint.
		$this->proxyServes();
		$this->appliedIdentity(['upstream' => "'127.0.0.1:5353'"]);
		$this->seedUnbound('127.0.0.1:5353');

		// Then nothing is confirmed: a quoted argv is not a command line the gateway was started with
		$this->assertFalse(pfb_dns_proxy_serving_ready(), 'a literal quote is not part of the endpoint the gateway forwards to');
	}

	public function testABracketedIPv4UpstreamIsJudgedByTheEndpointItNames(): void
	{
		// Given a gateway whose applied upstream is what the Go emitter writes for the config input [127.0.0.1]:5353 (canonical 127.0.0.1:5353),
		// and Unbound owning that endpoint. A noncanonical status wire is rejected elsewhere; this row pins the canonical endpoint's owner check.
		$this->proxyServes();
		$this->appliedIdentity(['upstream' => '127.0.0.1:5353']);
		$this->seedUnbound('127.0.0.1:5353');

		// Then the proxy serves: the applied endpoint is the one Unbound owns over TCP and UDP
		$this->assertTrue(pfb_dns_proxy_serving_ready(), 'the applied endpoint 127.0.0.1:5353 is owned by Unbound');
	}
}
