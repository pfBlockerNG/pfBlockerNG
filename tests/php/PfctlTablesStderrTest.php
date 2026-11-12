<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3902 -- the pf-table listings run `/sbin/pfctl -s Tables | grep '^pfB_'` with pfctl's stderr
 * unredirected. On a host without /sbin/pfctl (Linux CI) the shell's "No such file or directory" went
 * straight to the process's stderr: 35 lines per PHPUnit job (34 from the apply passes driven by
 * DnsblVipApplyLifecycleTest, one from the pre-deinstall teardown). Only grep's stdout is read; a
 * failed listing still reads as "no pfB_ tables".
 *
 * Neither site can be driven alone off-appliance (each sits inside a full sync_package_pfblockerng()
 * pass or the pre-deinstall teardown), so this pins the command shape, as MountCheckStderrTest does.
 */
#[CoversFunction('sync_package_pfblockerng')]
#[CoversFunction('pfblockerng_php_pre_deinstall_command')]
final class PfctlTablesStderrTest extends TestCase
{
	/**
	 * Given every `{$pfb['pfctl']} ... |` pipeline in the package sources,
	 * Then each discards pfctl's stderr before the pipe.
	 */
	public function testEveryPfctlPipelineDiscardsPfctlStderr(): void
	{
		$pkg = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng';
		$sites = 0;
		foreach (['pfblockerng.inc', 'pfblockerng_apply.inc'] as $file) {
			$src = (string) file_get_contents("{$pkg}/{$file}");
			$this->assertSame(1, preg_match_all('#\{\$pfb\[\'pfctl\'\]\}([^"|\n]*)\|#', $src, $m), "{$file}: one pfctl pipeline");
			foreach ($m[1] as $head) {
				$sites++;
				$this->assertStringEndsWith(' 2>/dev/null ', $head, "{$file}: a pfctl pipeline leaks pfctl's stderr");
			}
		}
		$this->assertSame(2, $sites, 'the two `pfctl -s Tables | grep` listings of issue #3902');
	}
}
