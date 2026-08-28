<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #697: pfb_parse_pkg_operation() classifies the current package-manager operation by walking
 * the process ancestry (synthetic `ps -o pid,ppid,command` lines) up to the pkg/pkg-static process
 * and reading its subcommand. It exists so an update hook can learn (via PFB_PKG_OP) whether the run
 * is a fresh install, an upgrade, a forced reinstall, or a delete.
 *
 * The parser must respect pkg's grammar `pkg [GLOBAL opts] <command> [command flags]`: the global
 * options -o/-j/-c/-r/-C/-R (and long forms) sit BEFORE the subcommand and consume the following
 * token, so they must be skipped WITH their value — pfSense passes -c/-r (chroot/rootdir) during an
 * OS upgrade, so a naive "first non-dash token" read would misclassify exactly then.
 */
#[CoversFunction('pfb_parse_pkg_operation')]
#[CoversFunction('pfb_pkg_argv_subcommand')]
#[CoversFunction('pfb_pkg_op_tears_down')]
final class PfbPkgOperationTest extends TestCase
{
	/**
	 * The teardown gate (#697): the pre-deinstall tears pfBlockerNG down ONLY on a genuine removal
	 * ('delete' — a real uninstall or a major OS upgrade's mass-removal), and keeps it live across a
	 * package upgrade/reinstall ('install'/'upgrade'/'reinstall'). An undetectable op ('') fails safe
	 * to teardown, since a real uninstall is always a detectable `pkg delete`.
	 */
	public function testDeleteTearsDown(): void
	{
		$this->assertTrue(pfb_pkg_op_tears_down('delete'));
	}

	public function testUndetectableOpFailsSafeToTeardown(): void
	{
		$this->assertTrue(pfb_pkg_op_tears_down(''), 'an unknown op must fail safe to teardown');
	}

	public function testPackageOperationsKeepPfblockerngLive(): void
	{
		$this->assertFalse(pfb_pkg_op_tears_down('install'), 'a fresh install must not tear down');
		$this->assertFalse(pfb_pkg_op_tears_down('reinstall'), 'a forced reinstall must not tear down');
		$this->assertFalse(pfb_pkg_op_tears_down('upgrade'), 'a package upgrade must not tear down');
	}

	/** Build a simple linear ancestry: pid 100 (self) -> 90 -> 80 (the pkg proc). */
	private function chain(string $pkg_cmd): array
	{
		return [
			'  PID  PPID COMMAND',            // header row, must be ignored
			'  100   90 /usr/local/bin/php -f /usr/local/pkg/pfblockerng/...',
			'   90   80 /bin/sh -c /etc/rc.packages pfSense-pkg-pfBlockerNG deinstall',
			"   80    1 {$pkg_cmd}",
		];
	}

	public function testPlainDeleteIsDelete(): void
	{
		$this->assertSame('delete', pfb_parse_pkg_operation($this->chain('pkg delete -y pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testBareInstallIsInstall(): void
	{
		$this->assertSame('install', pfb_parse_pkg_operation($this->chain('pkg install -y pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testForcedInstallIsReinstall(): void
	{
		$this->assertSame('reinstall', pfb_parse_pkg_operation($this->chain('pkg install -y -f pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testUpgradeViaPkgStaticIsUpgrade(): void
	{
		$this->assertSame('upgrade', pfb_parse_pkg_operation($this->chain('pkg-static upgrade'), 100));
	}

	public function testAutoremoveCountsAsDelete(): void
	{
		$this->assertSame('delete', pfb_parse_pkg_operation($this->chain('pkg autoremove -y'), 100));
	}

	/**
	 * The critical case your review flagged: a global option that consumes the next token (-r rootdir,
	 * -c chroot, -o var=val, -C conf) sits BEFORE the subcommand — pfSense uses these during an OS
	 * upgrade. A naive parser would read the option's VALUE as the subcommand and misclassify.
	 */
	public function testGlobalRootdirOptionIsSkippedWithItsValue(): void
	{
		$this->assertSame('delete', pfb_parse_pkg_operation($this->chain('pkg -r /new/root delete -y pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testGlobalChrootOptionIsSkippedWithItsValue(): void
	{
		$this->assertSame('install', pfb_parse_pkg_operation($this->chain('pkg -c /path install -y pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testGlobalOptionWithEqualsValueIsSkipped(): void
	{
		$this->assertSame('install', pfb_parse_pkg_operation($this->chain('pkg -o ASSUME_ALWAYS_YES=yes install pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testAttachedLongRootdirDoesNotConsumeNextToken(): void
	{
		// `--rootdir=/r` carries its value; the very next token is the subcommand.
		$this->assertSame('delete', pfb_parse_pkg_operation($this->chain('pkg --rootdir=/r delete pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testNoArgGlobalFlagsBeforeSubcommand(): void
	{
		// `-4` is a no-arg global; `-f` after `install` is a command flag => reinstall.
		$this->assertSame('reinstall', pfb_parse_pkg_operation($this->chain('pkg -4 -y install -f pfSense-pkg-pfBlockerNG'), 100));
	}

	public function testNoPkgAncestorYieldsEmpty(): void
	{
		// A normal cron/manual update: no pkg anywhere in the ancestry.
		$lines = [
			'  100   90 /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick',
			'   90    1 /usr/sbin/cron',
		];
		$this->assertSame('', pfb_parse_pkg_operation($lines, 100));
	}

	public function testPkgAncestorHigherUpTheChainIsFound(): void
	{
		// Intermediate non-pkg processes, with pkg two hops up.
		$lines = [
			'  100   90 /usr/local/bin/php -f install.inc',
			'   90   80 /bin/sh -c rc.packages ...',
			'   80    1 pkg upgrade pfSense-pkg-pfBlockerNG',
		];
		$this->assertSame('upgrade', pfb_parse_pkg_operation($lines, 100));
	}

	public function testUnrecognisedSubcommandYieldsEmpty(): void
	{
		$this->assertSame('', pfb_parse_pkg_operation($this->chain('pkg info -q pfSense-pkg-pfBlockerNG'), 100));
	}
}
