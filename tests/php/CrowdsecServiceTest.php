<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';
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
 *   - stop sends TERM to the supervisor (daemon(8) passes it on, and the bouncer empties its tables), or to the bouncer when no
 *     supervisor is left, KILL to both at 5 s, and fails at 7 s keeping the pidfiles;
 *   - the script does nothing to PF itself (the bouncer creates its own tables);
 *   - start, stop and restart run under one lock, as Core's do (#4139): the script runs itself once more under `lockf -k -t 20`, and
 *     that run takes no second lock; a lock not had within 20 s does nothing and fails (lockf's 75). Two starts at once therefore
 *     run one after the other, and the second keeps the first one's bouncer: no start kills a running pair;
 *   - every signal goes to a pid a pidfile names and only while its command line is a bouncer's or a supervisor's (Core's rule);
 *   - the start records the sha256 of the binary it runs, which the apply compares with the installed one (#4139);
 *   - pfSense's own stop under a package upgrade or reinstall leaves the bouncer running (pfB-DNS's rule, the same ancestry rows).
 *
 * The real generator's output is written through the write_rcfile() double and executed under dash. Every absolute command path
 * is redirected to a command double (a path with no double fails the test instead of running a host binary); `sleep 1` is one
 * tick of a controlled clock, so the 5 s and 7 s deadlines are counted in ticks, never measured.
 */
#[CoversFunction('pfb_crowdsec_service')]
final class CrowdsecServiceTest extends TestCase
{
	private const DOUBLES = ['daemon', 'logger', 'uname', 'pgrep', 'pkill', 'sleep', 'lockf', 'ps', 'sha256'];
	private const BINARY_SHA = 'aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899990';
	private const KEPT_LOG = 'left running across the package upgrade';
	private const SUPERVISOR = 2001;
	private const CHILD = 2002;

	/** One script under every command name the rc body uses; $0 picks the role. procs: pid|args|tick it dies at (empty: alive). */
	private const DOUBLE = <<<'SH'
		#!/bin/sh
		S=@STATE@
		. "$S/scenario"
		ev() { printf '%s\n' "$1" >> "$S/events"; }
		tick() { read -r t < "$S/ticks"; echo "$t"; }
		reap() {
			now="$(tick)"
			true > "$S/procs.new"
			while IFS='|' read -r pid args due; do
				[ -n "$pid" ] || continue
				if [ -n "$due" ] && [ "$now" -ge "$due" ]; then gone "$pid"; continue; fi
				printf '%s|%s|%s\n' "$pid" "$args" "$due" >> "$S/procs.new"
			done < "$S/procs"
			mv "$S/procs.new" "$S/procs"
		}
		# daemon(8)'s supervisor holds both pidfiles locked while it runs; ending, it removes them (a KILLed one cannot)
		gone() {
			if [ "$1" = "$SUPERVISOR" ] && [ -s "$S/locks" ]; then
				[ -n "$2" ] || rm -f "$DAEMONPID" "$CHILDPID"
				true > "$S/locks"
			fi
		}
		# all PATTERN: every process whose command line matches
		all() {
			while IFS='|' read -r pid args due; do
				if [ -n "$pid" ] && printf '%s\n' "$args" | grep -Eq -- "$1"; then echo "$pid"; fi
			done < "$S/procs"
		}
		match() {
			[ -r "$1" ] || return 1
			read -r want < "$1" || return 1
			while IFS='|' read -r pid args due; do
				if [ "$pid" = "$want" ] && printf '%s\n' "$args" | grep -Eq -- "$2"; then echo "$pid"; return 0; fi
			done < "$S/procs"
			return 1
		}
		# kill PID SIG: TERM ends it (and, for the supervisor, its child: daemon(8) passes TERM on) TERM_AFTER ticks later; KILL at once
		signal() {
			kid=
			while IFS='|' read -r p args due; do
				case "$p|$args" in "$1|daemon: pfb_crowdsec["*) kid="${args#*[}"; kid="${kid%%]*}" ;; esac
			done < "$S/procs"
			true > "$S/procs.new"
			while IFS='|' read -r p args due; do
				[ -n "$p" ] || continue
				hit=
				if [ "$p" = "$1" ]; then hit=1; fi
				if [ -n "$kid" ] && [ "$p" = "$kid" ] && [ "$2" = TERM ]; then hit=1; fi
				if [ -n "$hit" ]; then
					if [ "$2" = KILL ]; then
						case " $KILL_IGNORED " in *" $p "*) ;; *) gone "$p" killed; continue ;; esac
					elif [ "$TERM_AFTER" != never ]; then
						due=$(( $(tick) + TERM_AFTER ))
					fi
				fi
				printf '%s|%s|%s\n' "$p" "$args" "$due" >> "$S/procs.new"
			done < "$S/procs"
			mv "$S/procs.new" "$S/procs"
		}
		case "${0##*/}" in
		pgrep|pkill)
			sig=
			if [ "${0##*/}" = pkill ]; then
				case "$1" in -TERM|-KILL) sig="${1#-}"; shift ;; *) ev bad-pkill; exit 2 ;; esac
			fi
			if [ "$1" = -F ] && [ "$3" = -f ] && [ "$#" -eq 4 ]; then
				pids="$(match "$2" "$4")" || exit 1
			elif [ "$1" = -f ] && [ "$#" -eq 2 ]; then
				pids="$(all "$2")"; [ -n "$pids" ] || exit 1
			else
				ev "bad-${0##*/}"; exit 2
			fi
			[ -n "$sig" ] || exit 0
			for pid in $pids; do
				ev "$sig $pid @$(tick)"
				signal "$pid" "$sig"
			done
			;;
		lockf)
			# lockf(1) as the rc script must call it (Core's double): -k -t 20 FILE COMMAND...; the lock itself is not modelled,
			# LOCKF_EXIT stands for a wait that ran out (75) and runs nothing
			[ "$1" = -k ] && [ "$2" = -t ] && [ "$3" = 20 ] && [ "$#" -ge 5 ] || { ev bad-lockf; exit 2; }
			printf '%s\n' "$*" >> "$S/lockf.calls"
			[ -z "$LOCKF_EXIT" ] || exit "$LOCKF_EXIT"
			shift 4
			exec "$@"
			;;
		ps)
			# pfB-DNS's double: the ancestry probe of a top-level stop (-ww -o ppid= -o args= -p PID) from the `ancestry` table
			[ "$#" -eq 7 ] && [ "$1" = -ww ] && [ "$2" = -o ] && [ "$3" = 'ppid=' ] && [ "$4" = -o ] && [ "$5" = 'args=' ] && [ "$6" = -p ] || { ev bad-ps; exit 2; }
			[ -s "$S/ancestry.self" ] || echo "$7" > "$S/ancestry.self"
			read -r self < "$S/ancestry.self"
			key="$7"
			[ "$key" != "$self" ] || key=SELF
			while IFS='|' read -r pid ppid args; do
				if [ "$pid" = "$key" ]; then printf '%5s %s\n' "$ppid" "$args"; exit 0; fi
			done < "$S/ancestry"
			exit 1
			;;
		sha256)
			[ "$#" -eq 2 ] && [ "$1" = -r ] || { ev bad-sha256; exit 2; }
			printf '%s %s\n' "$BINARY_SHA" "$2"
			;;
		sleep)
			[ "$#" -eq 1 ] && [ "$1" = 1 ] || { ev bad-sleep; exit 2; }
			echo "$(( $(tick) + 1 ))" > "$S/ticks"
			reap
			if [ "$(tick)" = "$SUPERVISOR_AT" ] && [ -s "$S/launched" ]; then
				echo "$SUPERVISOR" > "$DAEMONPID"; echo "$CHILD" > "$CHILDPID"
			fi
			;;
		logger)
			printf '%s\n' "$*" >> "$S/logger"
			;;
		uname)
			[ "$1" = -p ] || { ev bad-uname; exit 2; }
			printf '%s\n' "$MACHINE"
			;;
		daemon)
			true > "$S/daemon.argv"
			for arg in "$@"; do printf '%s\n' "$arg" >> "$S/daemon.argv"; done
			attached=
			for fd in 0 1 2; do
				if [ "/dev/fd/$fd" -ef /dev/null ]; then attached="${attached:+$attached }$fd"; fi
			done
			echo "${attached:-none}" > "$S/fds"
			ev launch
			# 3: another start's daemon(8) took the pidfiles' lock first, and its pair is the one that runs
			case "$DAEMON_EXIT" in 0|3) ;; *) exit "$DAEMON_EXIT" ;; esac
			printf '%s\n%s\n' "$DAEMONPID" "$CHILDPID" > "$S/locks"
			true > "$DAEMONPID"; true > "$CHILDPID"
			shift 14
			printf '%s|daemon: pfb_crowdsec[%s] (daemon)|\n%s|%s|\n' "$SUPERVISOR" "$CHILD" "$CHILD" "$*" >> "$S/procs"
			echo 1 > "$S/launched"
			if [ "$SUPERVISOR_AT" = 0 ]; then
				echo "$SUPERVISOR" > "$DAEMONPID"; echo "$CHILD" > "$CHILDPID"
			fi
			exit "$DAEMON_EXIT"
			;;
		*)
			ev "unexpected ${0##*/}"
			exit 2
			;;
		esac
		SH;

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

	private string $dir = '';
	private string $shell = '';
	private array $savedPfb = [];
	private array $savedRcDir = [];

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? [];
		$this->savedRcDir = [array_key_exists('pfb_test_rcfile_dir', $GLOBALS), $GLOBALS['pfb_test_rcfile_dir'] ?? NULL];
		$this->dir = sys_get_temp_dir() . '/pfb_crowdsec_rc_' . bin2hex(random_bytes(6));
		foreach (['bin', 'state', 'run', 'conf', 'rc', 'crowdsec/bin/freebsd-amd64', 'crowdsec/bin/freebsd-arm64'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0777, TRUE), "sandbox mkdir failed: {$sub}");
		}
		$double = "{$this->dir}/double.sh";
		file_put_contents($double, str_replace('@STATE@', escapeshellarg("{$this->dir}/state"), self::DOUBLE) . "\n");
		chmod($double, 0755);
		foreach (self::DOUBLES as $name) {
			$this->assertTrue(symlink($double, "{$this->dir}/bin/{$name}"), "double link failed: {$name}");
		}
		$rm = trim((string) shell_exec('command -v rm'));
		$this->assertNotSame('', $rm, 'no rm on this host');
		$this->assertTrue(symlink($rm, "{$this->dir}/bin/rm"));
		$dash = trim((string) shell_exec('command -v dash 2>/dev/null'));
		$this->shell = $dash !== '' ? $dash : '/bin/sh';

		$GLOBALS['pfb'] = array_merge($this->savedPfb, [
			'crowdsec_config'         => "{$this->dir}/conf/pfb_crowdsec.json",
			'crowdsec_pidfile'        => "{$this->dir}/run/pfb_crowdsec.pid",
			'crowdsec_daemon_pidfile' => "{$this->dir}/run/pfb_crowdsec_daemon.pid",
			'crowdsec_lockfile'       => "{$this->dir}/run/pfb_crowdsec.lock",
			'crowdsec_binary_record'  => "{$this->dir}/run/pfb_crowdsec.sha256",
		]);
		$GLOBALS['pfb_test_rcfile_dir'] = "{$this->dir}/rc";
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		[$existed, $value] = $this->savedRcDir;
		if ($existed) {
			$GLOBALS['pfb_test_rcfile_dir'] = $value;
		} else {
			unset($GLOBALS['pfb_test_rcfile_dir']);
		}
		rmdir_recursive($this->dir);
	}

	private function binary(string $target = 'freebsd-amd64'): string
	{
		return "{$this->dir}/crowdsec/bin/{$target}/pfb_crowdsec";
	}

	private function install(string $target = 'freebsd-amd64'): void
	{
		file_put_contents($this->binary($target), str_replace('@STATE@', escapeshellarg("{$this->dir}/state"), self::BINARY) . "\n");
		chmod($this->binary($target), 0755);
	}

	/**
	 * Generate the script, point its commands at the doubles, and seed the scenario.
	 *
	 * @param array<string, string> $scenario overrides: SUPERVISOR_AT (tick the pidfiles are written at), DAEMON_EXIT, CHECK_EXIT (the
	 *   binary's `-t` status), TERM_AFTER (ticks a TERMed process takes to exit, or never), KILL_IGNORED (pids that survive KILL)
	 */
	private function arrange(string $machine = 'amd64', bool $configured = TRUE, bool $running = FALSE, array $scenario = []): void
	{
		pfb_crowdsec_service("{$this->dir}/crowdsec");
		$text = @file_get_contents("{$this->dir}/rc/pfb_crowdsec.sh");
		$this->assertIsString($text, 'pfb_crowdsec_service() wrote no rc script');
		$this->assertStringNotContainsString('pfctl', $text, 'the rc script does nothing to PF');
		$script = (string) preg_replace_callback(
			'~(?<![\w$.\-/])/(?:usr/sbin|usr/bin|sbin|bin)/([\w.\-]+)~',
			function (array $m): string {
				if ($m[0] === '/bin/sh') {
					return $m[0];
				}
				$this->assertFileExists("{$this->dir}/bin/{$m[1]}", "no command double for {$m[0]}; refusing to run a host binary");
				return "{$this->dir}/bin/{$m[1]}";
			},
			$text
		);
		// /etc/rc.packages is a word the package-upgrade check compares an ancestor's argv with, never a file the script opens
		$this->assertDoesNotMatchRegularExpression('~(?<![\w.\-])/(?:var|usr|etc)/~', str_replace([$this->dir, '/etc/rc.packages'], '', $script),
			"the rc script names a host path the test did not redirect:\n{$script}");
		file_put_contents("{$this->dir}/run.sh", $script);
		$state = "{$this->dir}/state";
		$vars = $scenario + ['MACHINE' => $machine, 'TERM_AFTER' => '1', 'SUPERVISOR_AT' => '0', 'DAEMON_EXIT' => '0', 'CHECK_EXIT' => '0',
			'KILL_IGNORED' => '', 'LOCKF_EXIT' => '', 'BINARY_SHA' => self::BINARY_SHA, 'SUPERVISOR' => (string) self::SUPERVISOR, 'CHILD' => (string) self::CHILD,
			'DAEMONPID' => $GLOBALS['pfb']['crowdsec_daemon_pidfile'], 'CHILDPID' => $GLOBALS['pfb']['crowdsec_pidfile']];
		file_put_contents("{$state}/scenario", implode('', array_map(
			static fn (string $k, string $v): string => "{$k}=" . escapeshellarg($v) . "\n",
			array_keys($vars),
			array_values($vars)
		)));
		file_put_contents("{$state}/ticks", "0\n");
		foreach (['events', 'procs', 'logger', 'daemon.argv', 'fds', 'launched', 'locks', 'lockf.calls', 'ancestry', 'ancestry.self'] as $file) {
			file_put_contents("{$state}/{$file}", '');
		}
		if ($configured) {
			file_put_contents($GLOBALS['pfb']['crowdsec_config'], "{}\n");
		}
		if ($running) {
			file_put_contents($GLOBALS['pfb']['crowdsec_daemon_pidfile'], self::SUPERVISOR . "\n");
			file_put_contents($GLOBALS['pfb']['crowdsec_pidfile'], self::CHILD . "\n");
			file_put_contents("{$state}/procs", self::SUPERVISOR . "|daemon: pfb_crowdsec[" . self::CHILD . "] (daemon)|\n"
				. self::CHILD . "|{$this->binary()} -c {$GLOBALS['pfb']['crowdsec_config']}|\n");
		}
	}

	/** @return array{0: int, 1: string} exit status, then stdout and stderr */
	private function rc(string $verb): array
	{
		$run = pfb_test_finish_process(
			pfb_test_start_process(['/usr/bin/timeout', '-k', '2', '20', $this->shell, "{$this->dir}/run.sh", $verb],
				['PATH' => "{$this->dir}/bin:" . (string) getenv('PATH')]),
			25.0
		);
		if ($run['exit'] === 124 || $run['exit'] === 137 || $run['termsig'] === 9) {
			throw new RuntimeException("STUCK/ENVIRONMENT: rc {$verb} was stopped by its time limit: {$run['stdout']}{$run['stderr']}");
		}
		return [$run['exit'], $run['stdout'] . $run['stderr']];
	}

	/** @return list<string> */
	private function lines(string $file): array
	{
		return file("{$this->dir}/state/{$file}", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	/** @return list<string> */
	private function livePids(): array
	{
		return array_map(static fn (string $line): string => explode('|', $line, 2)[0], $this->lines('procs'));
	}

	private function launched(): bool
	{
		return in_array('launch', $this->lines('events'), TRUE);
	}

	// ---- start ----------------------------------------------------------------------------

	public function testStartRunsThisMachinesBouncerUnderDaemonWithRestartSyslogAndBothPidfiles(): void
	{
		$this->install();
		$this->arrange();

		[$status, $out] = $this->rc('start');

		$this->assertSame(0, $status, $out);
		$this->assertSame(['-r', '-R', '5', '-S', '-l', 'daemon', '-T', 'pfb_crowdsec', '-t', 'pfb_crowdsec',
			'-P', $GLOBALS['pfb']['crowdsec_daemon_pidfile'], '-p', $GLOBALS['pfb']['crowdsec_pidfile'],
			$this->binary(), '-c', $GLOBALS['pfb']['crowdsec_config']], $this->lines('daemon.argv'));
		$this->assertSame(['0 1 2'], $this->lines('fds'), 'stdin, stdout and stderr are detached');
		$this->assertSame(["check {$GLOBALS['pfb']['crowdsec_config']}", 'launch'], $this->lines('events'), 'the config is checked first');
		$this->assertStringContainsString('started', implode("\n", $this->lines('logger')));
		$this->assertSame(self::BINARY_SHA . ' ' . $this->binary() . "\n", (string) @file_get_contents($GLOBALS['pfb']['crowdsec_binary_record']),
			'the start records the sha256 of the binary it runs');
	}

	public function testStartRunsItselfUnderTheLockAndTheLockedRunTakesNoSecondLock(): void
	{
		$this->install();
		$this->arrange();

		[$status, $out] = $this->rc('start');

		$this->assertSame(0, $status, $out);
		$this->assertSame(["-k -t 20 {$GLOBALS['pfb']['crowdsec_lockfile']} /bin/sh {$this->dir}/run.sh start"], $this->lines('lockf.calls'));
		$this->assertTrue($this->launched());
	}

	public function testStopRunsUnderTheSameLock(): void
	{
		$this->install();
		$this->arrange(running: TRUE);

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame(["-k -t 20 {$GLOBALS['pfb']['crowdsec_lockfile']} /bin/sh {$this->dir}/run.sh stop"], $this->lines('lockf.calls'));
	}

	public function testAStartThatCannotTakeTheLockInTimeLaunchesNothingAndSaysSo(): void
	{
		$this->install();
		$this->arrange(scenario: ['LOCKF_EXIT' => '75']);

		[$status] = $this->rc('start');

		$this->assertSame(75, $status);
		$this->assertFalse($this->launched());
		$this->assertStringContainsString('lock', implode("\n", $this->lines('logger')));
	}

	public function testAStopThatCannotTakeTheLockInTimeSignalsNothingAndFails(): void
	{
		$this->install();
		$this->arrange(running: TRUE, scenario: ['LOCKF_EXIT' => '75']);

		[$status] = $this->rc('stop');

		$this->assertSame(75, $status);
		$this->assertSame([], $this->lines('events'));
		$this->assertSame([(string) self::SUPERVISOR, (string) self::CHILD], $this->livePids());
	}

	public function testASecondStartKeepsTheBouncerTheFirstOneStartedAndKillsNothing(): void
	{
		// Given one start that launched the bouncer (two starts at once run one after the other under the lock)
		$this->install();
		$this->arrange();
		[$first] = $this->rc('start');
		$this->assertSame(0, $first);
		$this->assertSame(['check ' . $GLOBALS['pfb']['crowdsec_config'], 'launch'], $this->lines('events'), 'before-state: one launch');

		// When the second start runs
		[$second, $out] = $this->rc('start');

		// Then it launches nothing and signals nothing: one bouncer, the first one's
		$this->assertSame(0, $second, $out);
		$this->assertSame(['check ' . $GLOBALS['pfb']['crowdsec_config'], 'launch'], $this->lines('events'), 'no second launch, no signal');
		$this->assertSame([(string) self::SUPERVISOR, (string) self::CHILD], $this->livePids());
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
		$this->install();
		$this->arrange(scenario: ['CHECK_EXIT' => '1']);

		[$status] = $this->rc('start');

		$this->assertSame(1, $status);
		$this->assertFalse($this->launched());
		$this->assertStringContainsString('api_url must be', implode("\n", $this->lines('logger')));
	}

	public function testStartOverARunningBouncerKeepsIt(): void
	{
		$this->install();
		$this->arrange(running: TRUE);

		[$status] = $this->rc('start');

		$this->assertSame(0, $status);
		$this->assertSame([], $this->lines('events'), 'nothing signalled, nothing launched');
		$this->assertSame([(string) self::SUPERVISOR, (string) self::CHILD], $this->livePids());
	}

	public function testStartOverAStalePidfileOfAnotherProcessLaunchesAndSignalsNothing(): void
	{
		$this->install();
		$this->arrange();
		file_put_contents($GLOBALS['pfb']['crowdsec_daemon_pidfile'], "77\n");
		file_put_contents($GLOBALS['pfb']['crowdsec_pidfile'], "78\n");
		file_put_contents("{$this->dir}/state/procs", "77|/usr/sbin/sshd|\n78|/usr/local/sbin/unbound|\n");

		[$status] = $this->rc('start');

		$this->assertSame(0, $status);
		$this->assertTrue($this->launched());
		$this->assertNotContains('TERM 77 @0', $this->lines('events'));
		$this->assertContains('77', $this->livePids(), 'a reused pid is never signalled');
		$this->assertContains('78', $this->livePids());
	}

	public function testAFailingDaemonFailsTheStart(): void
	{
		$this->install();
		$this->arrange(scenario: ['DAEMON_EXIT' => '2']);

		[$status] = $this->rc('start');

		$this->assertSame(1, $status);
	}

	public function testASupervisorThatNeverWritesItsPidfileFailsTheStartAfterFiveTicks(): void
	{
		$this->install();
		$this->arrange(scenario: ['SUPERVISOR_AT' => 'never']);

		[$status] = $this->rc('start');

		$this->assertSame(1, $status);
		$this->assertSame(['5'], $this->lines('ticks'));
	}

	public function testASupervisorThatWritesItsPidfileLateIsWaitedFor(): void
	{
		$this->install();
		$this->arrange(scenario: ['SUPERVISOR_AT' => '2']);

		[$status] = $this->rc('start');

		$this->assertSame(0, $status);
	}

	// ---- stop -----------------------------------------------------------------------------

	public function testStopSendsTermToTheSupervisorOnlyAndRemovesThePidfiles(): void
	{
		$this->install();
		$this->arrange(running: TRUE);

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM ' . self::SUPERVISOR . ' @0'], $this->lines('events'), 'daemon(8) passes TERM on: the bouncer is not signalled twice');
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['crowdsec_daemon_pidfile']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['crowdsec_pidfile']);
	}

	public function testStopOfABouncerWhoseSupervisorIsGoneSignalsTheBouncer(): void
	{
		$this->install();
		$this->arrange(running: TRUE);
		file_put_contents("{$this->dir}/state/procs", self::CHILD . "|{$this->binary()} -c {$GLOBALS['pfb']['crowdsec_config']}|\n");

		[$status] = $this->rc('stop');

		$this->assertSame(0, $status);
		$this->assertSame(['TERM ' . self::CHILD . ' @0'], $this->lines('events'));
		$this->assertSame([], $this->livePids());
	}

	public function testStopSendsKillToBothAtFiveTicksWhenTermIsIgnored(): void
	{
		$this->install();
		$this->arrange(running: TRUE, scenario: ['TERM_AFTER' => 'never']);

		[$status] = $this->rc('stop');

		$this->assertSame(0, $status);
		$this->assertSame(['TERM ' . self::SUPERVISOR . ' @0', 'KILL ' . self::SUPERVISOR . ' @5', 'KILL ' . self::CHILD . ' @5'], $this->lines('events'));
		$this->assertSame([], $this->livePids());
	}

	public function testStopFailsAtSevenTicksAndKeepsThePidfilesWhenKillDoesNotEndIt(): void
	{
		$this->install();
		$this->arrange(running: TRUE, scenario: ['TERM_AFTER' => 'never', 'KILL_IGNORED' => (string) self::CHILD]);

		[$status] = $this->rc('stop');

		$this->assertSame(1, $status);
		$this->assertSame(['7'], $this->lines('ticks'));
		$this->assertFileExists($GLOBALS['pfb']['crowdsec_pidfile'], 'the pidfile still names the survivor');
	}

	public function testStopNeverSignalsAProcessThatReusedAPid(): void
	{
		$this->install();
		$this->arrange();
		file_put_contents($GLOBALS['pfb']['crowdsec_daemon_pidfile'], "77\n");
		file_put_contents($GLOBALS['pfb']['crowdsec_pidfile'], "78\n");
		file_put_contents("{$this->dir}/state/procs", "77|/usr/sbin/sshd|\n78|/usr/local/sbin/unbound|\n");

		[$status] = $this->rc('stop');

		$this->assertSame(0, $status);
		$this->assertSame([], $this->lines('events'));
		$this->assertSame(['77', '78'], $this->livePids());
	}

	public function testRestartStopsTheRunningBouncerThenStartsOne(): void
	{
		$this->install();
		$this->arrange(running: TRUE);

		[$status, $out] = $this->rc('restart');

		$this->assertSame(0, $status, $out);
		$events = $this->lines('events');
		$this->assertSame('TERM ' . self::SUPERVISOR . ' @0', $events[0] ?? NULL);
		$this->assertSame('launch', end($events));
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
		$this->install();
		$this->arrange(running: TRUE);
		$this->ancestry($ancestors);

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'nothing signalled');
		$this->assertSame([(string) self::SUPERVISOR, (string) self::CHILD], $this->livePids(), 'the bouncer runs on, same pids');
		$this->assertFileExists($GLOBALS['pfb']['crowdsec_pidfile']);
		$this->assertStringContainsString(self::KEPT_LOG, implode("\n", $this->lines('logger')));
	}

	/** @param list<string> $ancestors */
	#[DataProviderExternal(DnsProxyUpgradeStopTest::class, 'teardownRows')]
	public function testAStopThatIsNoPackageUpgradeStopsTheBouncer(array $ancestors): void
	{
		$this->install();
		$this->arrange(running: TRUE);
		$this->ancestry($ancestors);

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->livePids(), 'an uninstall stops it');
	}

	public function testARestartUnderAPackageUpgradeStillStopsAndStartsTheBouncer(): void
	{
		$this->install();
		$this->arrange(running: TRUE);
		$this->ancestry(['/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-pfBlockerNG DEINSTALL', '/bin/sh /tmp/x', 'pkg upgrade -y x']);

		[$status, $out] = $this->rc('restart');

		$this->assertSame(0, $status, $out);
		$this->assertSame('TERM ' . self::SUPERVISOR . ' @0', $this->lines('events')[0] ?? NULL);
		$this->assertTrue($this->launched());
	}

	public function testRestartOverASurvivorLaunchesNothing(): void
	{
		$this->install();
		$this->arrange(running: TRUE, scenario: ['TERM_AFTER' => 'never', 'KILL_IGNORED' => self::SUPERVISOR . ' ' . self::CHILD]);

		[$status] = $this->rc('restart');

		$this->assertSame(1, $status);
		$this->assertFalse($this->launched());
	}
}
