<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyRcSandboxTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #4259 -- on a RAM-disk box (use_mfs_tmpvar), a pfB-DNS stop writes the DNSBL archive (`pfblockerng.inc dnsbl_cache`,
 * which takes the publication lock and runs `pfblockerng.sh dnsbl_cache save`) once pfB-DNS has exited, whenever the Core
 * input's cache folder /var/unbound/pfb_dns exists: the archive then holds what pfB-DNS last fetched, and nothing writes to
 * the folder while it is archived. The save is bounded (timeout(1)) and its failure never fails the stop.
 *
 * Only the stop pfSense makes (no argument: Status > Services, a package stop, the shutdown) writes it: the stop that
 * starts and restarts make before a launch (`rc_stop internal`) does not, because pfB-DNS serves nothing until the launch.
 *
 * The real script runs under dash in the sandbox of DnsProxyRcSandboxTrait; the php double records the save and what is
 * still alive when it runs.
 */
#[CoversFunction('pfb_dns_proxy_service')]
final class DnsProxyStopArchiveTest extends TestCase
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

	/** A serving proxy on a box whose RAM-disk switch and Core input folder are as given; the stop has no pkg ancestor. */
	private function arrangeStop(bool $ramDisk = TRUE, bool $folder = TRUE, string $termAfter = '2', string $killAfter = '1', bool $saveFails = FALSE): void
	{
		$this->moveResolver();
		pfb_dns_proxy_service();
		$this->arrange(['GATE_MFS' => $ramDisk ? 'true' : 'false', 'SAVE_FAIL' => $saveFails ? '1' : ''], $termAfter, $killAfter, TRUE);
		$this->ancestry(['/bin/sh /usr/local/etc/rc.d/pfb_dns_proxy.sh stop', 'sh -c /usr/local/etc/rc.d/pfb_dns_proxy.sh stop']);
		if ($folder) {
			$this->assertTrue(mkdir($this->inputDir(), 0755, TRUE));
		}
	}

	/** @return list<string> the pids alive at each save, one entry per save ('' = none) */
	private function saves(): array
	{
		return array_map('trim', file("{$this->dir}/state/save.alive", FILE_IGNORE_NEW_LINES) ?: []);
	}

	public function testTheStopWritesTheArchiveOncePfbDnsHasExited(): void
	{
		$this->arrangeStop();

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'save'], $this->events(), 'the save comes after the wait for both processes to exit');
		$this->assertSame([''], $this->saves(), 'one save, with no proxy process alive');
		$this->assertSame(['-f /usr/local/pkg/pfblockerng/pfblockerng.inc dnsbl_cache'], $this->phpAsked(), 'the save takes the publication lock: pfb_dnsbl_cache(\'save\')');
		$this->assertMatchesRegularExpression('~^-s TERM -k 5 \d+ \S*php -f /usr/local/pkg/pfblockerng/pfblockerng\.inc dnsbl_cache$~m',
			(string) file_get_contents("{$this->dir}/state/timeout.args"), 'the save is bounded by timeout(1)');
	}

	public function testNoFolderNoSave(): void
	{
		$this->arrangeStop(folder: FALSE);

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep'], $this->events());
		$this->assertSame([], $this->saves(), 'before the cutover the folder does not exist: nothing changes');
	}

	public function testNoRamDiskNoSave(): void
	{
		$this->arrangeStop(ramDisk: FALSE);

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep'], $this->events());
		$this->assertSame([], $this->saves(), 'a disk /var keeps the folder across a reboot: no archive');
	}

	public function testAFailingSaveLeavesTheStopsStatusAloneAndSaysSo(): void
	{
		$this->arrangeStop(saveFails: TRUE);

		[$status, $output] = $this->rc('stop');

		$this->assertSame(0, $status, "a failed save failed the stop: {$output}");
		$this->assertSame([''], $this->saves());
		$this->assertSame([], $this->livePids());
		$this->assertStringContainsString('archive', (string) file_get_contents("{$this->dir}/state/logger"), 'the failure is logged');
	}

	public function testAStopThatCannotEndPfbDnsWritesNoArchive(): void
	{
		$this->arrangeStop(termAfter: 'never', killAfter: 'never');

		[$status, $output] = $this->rc('stop');

		$this->assertSame(1, $status, "a survivor must fail the stop: {$output}");
		$this->assertSame([], $this->saves(), 'pfB-DNS is still running: no archive while it may write the folder');
	}

	public function testTheRestartsOwnStopWritesNoArchive(): void
	{
		$this->arrangeStop();

		[$status, $output] = $this->rc('restart');

		$this->assertSame(0, $status, "rc restart failed: {$output}");
		$this->assertContains('launch', $this->events(), 'the restart launched pfB-DNS again');
		$this->assertSame([], $this->saves(), 'a restart serves nothing until the launch: it does not wait on an archive');
	}
}
