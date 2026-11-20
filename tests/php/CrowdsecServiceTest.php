<?php

declare(strict_types=1);

require_once __DIR__ . '/CoreRcSandboxTrait.php';
require_once __DIR__ . '/DnsProxyUpgradeStopTest.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4071 -- pfb_crowdsec_service() generates /usr/local/etc/rc.d/pfb_crowdsec.sh (docs/specs/crowdsec-integration.md, D4).
 *
 * Intent pinned here:
 *   - start runs this machine's pfb_crowdsec (bin/freebsd-amd64 or bin/freebsd-arm64 by `uname -p`) under daemon(8): restarted 5 s
 *     after it exits (-r -R 5), its output to syslog as daemon.* tagged pfb_crowdsec (-S -l daemon -T pfb_crowdsec), std fds detached,
 *     the supervisor's pid in its own file (-P) and the bouncer's in /var/run/pfb_crowdsec.pid (-p), the file the rule hook signals
 *     (#4069: SIGUSR1 to daemon(8)'s supervisor kills it);
 *   - it starts only while its config file exists (pfb_crowdsec_apply() writes it exactly while the bouncer should run), and only
 *     a config the binary accepts (`-t`); no binary for this machine starts nothing and is not a failure, an unknown
 *     machine is; a start over a running bouncer keeps it;
 *   - stop sends TERM to the supervisor and to the bouncer (which empties its tables; it keeps handling TERM until it exits), KILL
 *     to both at 5 s, and fails at 7 s keeping the pidfiles;
 *   - the script does nothing to PF itself (the bouncer creates its own tables);
 *   - start and stop each run under one lock, as Core's do (#4139; restart is stop then start): the script runs itself once more
 *     under `lockf -k -t 20`, and that run takes no second lock; a lock not had within 20 s does nothing and fails (lockf's 75). Two starts at once therefore
 *     run one after the other, and the second keeps the first one's bouncer: no start kills a running pair;
 *   - every signal goes to a pid a pidfile names and only while its command line is a bouncer's or a supervisor's (Core's rule);
 *   - the start records the sha256 of the binary it runs, which the apply compares with the installed one (#4139);
 *   - pfSense's own stop under a package upgrade or reinstall leaves the bouncer running (pfB-DNS's rule, the same ancestry rows).
 *
 * The script runs in Core's rc sandbox (CoreRcSandboxTrait), which also holds the lock, stop, survivor and start-confirmation rows
 * this service shares with Core's (#4145).
 */
#[CoversFunction('pfb_crowdsec_service')]
final class CrowdsecServiceTest extends TestCase
{
	use CoreRcSandboxTrait;

	private const BINARY_SHA = 'aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990';
	private const KEPT_LOG = 'left running across the package upgrade';

	/** The installed bouncer: `-t -c FILE` answers as the scenario says; anything else must not happen in the rc script itself. */
	private const BINARY = <<<'SH'
		#!/bin/sh
		S=@STATE@
		. "$S/scenario"
		[ "$1" = -t ] && [ "$2" = -c ] && [ "$#" -eq 3 ] || { printf 'bad-binary %s\n' "$*" >> "$S/events"; exit 2; }
		printf 'check %s\n' "$3" >> "$S/events"
		if [ "$CHECK_EXIT" = 0 ]; then echo "pfb_crowdsec: configuration OK"; exit 0; fi
		echo "pfb_crowdsec: config: api_url must be an http:// or https:// URL with a host" >&2
		exit "$CHECK_EXIT"
		SH;

	protected function setUp(): void
	{
		$this->sandboxUp(['daemon', 'logger', 'uname', 'pgrep', 'pkill', 'sleep', 'lockf', 'ps', 'sha256'],
			['conf', 'crowdsec/bin/freebsd-amd64', 'crowdsec/bin/freebsd-arm64'], [
				'crowdsec_config'         => 'conf/pfb_crowdsec.json',
				'crowdsec_pidfile'        => 'run/pfb_crowdsec.pid',
				'crowdsec_daemon_pidfile' => 'run/pfb_crowdsec_daemon.pid',
				'crowdsec_lockfile'       => 'run/pfb_crowdsec.lock',
				'crowdsec_binary_record'  => 'run/pfb_crowdsec.sha256',
			]);
	}

	protected function tearDown(): void
	{
		$this->sandboxDown();
	}

	private static function rcService(): array
	{
		return ['tag' => 'pfb_crowdsec', 'pidfile' => 'crowdsec_pidfile', 'daemon_pidfile' => 'crowdsec_daemon_pidfile',
			'lockfile' => 'crowdsec_lockfile', 'lock_var' => 'PFB_CROWDSEC_LOCKED', 'started' => 'CrowdSec bouncer started', 'lock_held' => 'held the lock'];
	}

	private function childArgs(string $binary): string
	{
		return "{$binary} -c {$GLOBALS['pfb']['crowdsec_config']}";
	}

	private function binary(string $target = 'freebsd-amd64'): string
	{
		return "{$this->dir}/crowdsec/bin/{$target}/pfb_crowdsec";
	}

	private function preLaunchEvents(): array
	{
		return ["check {$GLOBALS['pfb']['crowdsec_config']}"];
	}

	private function arrangeInstalled(bool $running = FALSE, array $scenario = [], ?string $child = NULL): void
	{
		$this->install();
		$this->arrange(running: $running, scenario: $scenario, child: $child);
	}

	private function install(string $target = 'freebsd-amd64'): void
	{
		file_put_contents($this->binary($target), str_replace('@STATE@', escapeshellarg("{$this->dir}/state"), self::BINARY) . "\n");
		chmod($this->binary($target), 0755);
	}

	/**
	 * Generate the script, point its commands at the doubles, and seed the scenario.
	 *
	 * @param array<string, string> $scenario overrides of the double's variables (sandboxArrange()), and CHECK_EXIT (the binary's `-t` status)
	 */
	private function arrange(string $machine = 'amd64', bool $configured = TRUE, bool $running = FALSE, array $scenario = [], ?string $child = NULL): void
	{
		pfb_crowdsec_service("{$this->dir}/crowdsec");
		$text = @file_get_contents("{$this->dir}/rc/pfb_crowdsec.sh");
		$this->assertIsString($text, 'pfb_crowdsec_service() wrote no rc script');
		$this->assertStringNotContainsString('pfctl', $text, 'the rc script does nothing to PF');
		// /etc/rc.packages is a word the package-upgrade check compares an ancestor's argv with, never a file the script opens
		$this->sandboxArrange($text, ['/etc/rc.packages'], $scenario + ['MACHINE' => $machine, 'CHECK_EXIT' => '0', 'BINARY_SHA' => self::BINARY_SHA],
			$running, $child);
		if ($configured) {
			file_put_contents($GLOBALS['pfb']['crowdsec_config'], "{}\n");
		}
	}

	private function launched(): bool
	{
		return in_array('launch', $this->lines('events'), TRUE);
	}

	// ---- start ----------------------------------------------------------------------------

	public function testStartRunsThisMachinesBouncerUnderDaemonWithRestartSyslogAndBothPidfiles(): void
	{
		$this->arrangeInstalled();

		[$status, $out] = $this->rc('start');

		$this->assertSame(0, $status, $out);
		$this->assertSame(['-r', '-R', '5', '-S', '-l', 'daemon', '-T', 'pfb_crowdsec', '-t', 'pfb_crowdsec',
			'-P', $GLOBALS['pfb']['crowdsec_daemon_pidfile'], '-p', $GLOBALS['pfb']['crowdsec_pidfile'],
			$this->binary(), '-c', $GLOBALS['pfb']['crowdsec_config']], $this->lines('daemon.argv'));
		$this->assertSame(['0 1 2 '], $this->lines('fds'), 'stdin, stdout and stderr are detached');
		$this->assertSame(["check {$GLOBALS['pfb']['crowdsec_config']}", 'launch'], $this->lines('events'), 'the config is checked first');
		$this->assertStringContainsString('started', implode("\n", $this->lines('logger')));
		$this->assertSame(self::BINARY_SHA . ' ' . $this->binary() . "\n", (string) @file_get_contents($GLOBALS['pfb']['crowdsec_binary_record']),
			'the start records the sha256 of the binary it runs');
	}

	public function testASecondStartKeepsTheBouncerTheFirstOneStartedAndKillsNothing(): void
	{
		// Given one start that launched the bouncer (two starts at once run one after the other under the lock)
		$this->arrangeInstalled();
		[$first] = $this->rc('start');
		$this->assertSame(0, $first);
		$this->assertSame(['check ' . $GLOBALS['pfb']['crowdsec_config'], 'launch'], $this->lines('events'), 'before-state: one launch');

		// When the second start runs
		[$second, $out] = $this->rc('start');

		// Then it launches nothing and signals nothing: one bouncer, the first one's
		$this->assertSame(0, $second, $out);
		$this->assertSame(['check ' . $GLOBALS['pfb']['crowdsec_config'], 'launch'], $this->lines('events'), 'no second launch, no signal');
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testStartOnAnArmMachineRunsTheArmBinary(): void
	{
		$this->install('freebsd-arm64');
		$this->arrange('aarch64');

		[$status] = $this->rc('start');

		$this->assertSame(0, $status);
		$this->assertContains($this->binary('freebsd-arm64'), $this->lines('daemon.argv'));
	}

	public function testStartWithoutAConfigFileStartsNothing(): void
	{
		$this->install();
		$this->arrange(configured: FALSE);

		[$status] = $this->rc('start');

		$this->assertSame(0, $status, 'a bouncer that should not run is not a failure');
		$this->assertFalse($this->launched());
		$this->assertStringContainsString('not started', implode("\n", $this->lines('logger')));
	}

	public function testStartWithNoBinaryForThisMachineStartsNothingAndIsNoFailure(): void
	{
		$this->install('freebsd-arm64');
		$this->arrange('amd64');

		[$status] = $this->rc('start');

		$this->assertSame(0, $status);
		$this->assertFalse($this->launched());
		$this->assertStringContainsString('freebsd-amd64', implode("\n", $this->lines('logger')));
	}

	public function testStartOnAnUnknownMachineFails(): void
	{
		$this->install();
		$this->arrange('mips64');

		[$status] = $this->rc('start');

		$this->assertSame(1, $status);
		$this->assertFalse($this->launched());
		$this->assertStringContainsString("'mips64'", implode("\n", $this->lines('logger')));
	}

	public function testStartWithAConfigTheBouncerRejectsFailsAndLogsWhy(): void
	{
		$this->arrangeInstalled(scenario: ['CHECK_EXIT' => '1']);

		[$status] = $this->rc('start');

		$this->assertSame(1, $status);
		$this->assertFalse($this->launched());
		$this->assertStringContainsString('api_url must be', implode("\n", $this->lines('logger')));
	}

	public function testStartOverAStalePidfileOfAnotherProcessLaunchesAndSignalsNothing(): void
	{
		$this->arrangeInstalled();
		file_put_contents($GLOBALS['pfb']['crowdsec_daemon_pidfile'], "77\n");
		file_put_contents($GLOBALS['pfb']['crowdsec_pidfile'], "78\n");
		file_put_contents("{$this->dir}/state/procs", "77|/usr/sbin/sshd|\n78|/usr/local/sbin/unbound|\n");

		[$status] = $this->rc('start');

		$this->assertSame(0, $status);
		$this->assertTrue($this->launched());
		$this->assertNotContains('TERM 77', $this->lines('events'));
		$this->assertContains('77', $this->livePids(), 'a reused pid is never signalled');
		$this->assertContains('78', $this->livePids());
	}

	// ---- stop -----------------------------------------------------------------------------

	public function testStopSendsTermToTheSupervisorAndTheBouncerAndRemovesThePidfiles(): void
	{
		$this->arrangeInstalled(running: TRUE);
		file_put_contents($GLOBALS['pfb']['crowdsec_binary_record'], self::BINARY_SHA . ' ' . $this->binary() . "\n");

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001', 'TERM 1002'], $this->lines('events'), 'TERM to both, as Core');
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['crowdsec_daemon_pidfile']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['crowdsec_pidfile']);
		$this->assertFileExists($GLOBALS['pfb']['crowdsec_binary_record'], 'the record outlives a stop: only a start rewrites it');
	}

	// ---- package upgrade: pfSense's own stop leaves the bouncer running (pfB-DNS's rule) ------------

	/** @param list<string> $ancestors the stop's ancestors above its own `sh -c`, nearest first (pfB-DNS's rows) */
	private function ancestry(array $ancestors): void
	{
		$argvs = array_merge(['/bin/sh /usr/local/etc/rc.d/pfb_crowdsec.sh stop', 'sh -c /usr/local/etc/rc.d/pfb_crowdsec.sh stop'], $ancestors);
		$rows = '';
		foreach ($argvs as $i => $args) {
			$pid = $i === 0 ? 'SELF' : (string) (500 + $i);
			$ppid = $i === count($argvs) - 1 ? '1' : (string) (501 + $i);
			$rows .= "{$pid}|{$ppid}|{$args}\n";
		}
		file_put_contents("{$this->dir}/state/ancestry", $rows);
	}

	/** @param list<string> $ancestors */
	#[DataProviderExternal(DnsProxyUpgradeStopTest::class, 'upgradeRows')]
	public function testAStopUnderAPackageUpgradeLeavesTheBouncerRunningAndSaysSo(array $ancestors): void
	{
		$this->arrangeInstalled(running: TRUE);
		$this->ancestry($ancestors);

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'nothing signalled');
		$this->assertSame(['1001', '1002'], $this->livePids(), 'the bouncer runs on, same pids');
		$this->assertFileExists($GLOBALS['pfb']['crowdsec_pidfile']);
		$this->assertStringContainsString(self::KEPT_LOG, implode("\n", $this->lines('logger')));
	}

	/** @param list<string> $ancestors */
	#[DataProviderExternal(DnsProxyUpgradeStopTest::class, 'teardownRows')]
	public function testAStopThatIsNoPackageUpgradeStopsTheBouncer(array $ancestors): void
	{
		$this->arrangeInstalled(running: TRUE);
		$this->ancestry($ancestors);

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->livePids(), 'an uninstall stops it');
	}

	public function testARestartUnderAPackageUpgradeStillStopsAndStartsTheBouncer(): void
	{
		$this->arrangeInstalled(running: TRUE);
		$this->ancestry(['/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG DEINSTALL', '/bin/sh /tmp/x', 'pkg upgrade -y x']);

		[$status, $out] = $this->rc('restart');

		$this->assertSame(0, $status, $out);
		$this->assertSame('TERM 1001', $this->lines('events')[0] ?? NULL);
		$this->assertTrue($this->launched());
	}

	public function testAPairNoPidfileNamesIsNeverSignalledByStopOrStart(): void
	{
		// Given a supervisor and a bouncer that no pidfile names (Core's rule: only what a pidfile names is signalled)
		$this->arrangeInstalled();
		file_put_contents("{$this->dir}/state/procs", "4001|daemon: pfb_crowdsec[4002] (daemon)|\n4002|{$this->childArgs($this->binary())}|\n");

		[$stop] = $this->rc('stop');
		[$start] = $this->rc('start');

		$this->assertSame(0, $stop);
		$this->assertSame(0, $start);
		$this->assertSame(['check ' . $GLOBALS['pfb']['crowdsec_config'], 'launch'], $this->lines('events'), 'no signal to the unnamed pair');
		$this->assertContains('4001', $this->livePids());
		$this->assertContains('4002', $this->livePids());
	}
}
