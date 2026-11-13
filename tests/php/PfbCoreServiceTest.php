<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3841 -- pfb-core, the Core API daemon (go/pfb_core), runs as the supervised rc service pfb_core.
 *
 * Function under test: pfb_core_service() -- writes /usr/local/etc/rc.d/pfb_core.sh. Intent pinned here:
 *   - start runs this machine's pfb-core (bin/freebsd-amd64 or bin/freebsd-arm64 under the package's core directory) under
 *     daemon(8): restarted when it exits, its output in the package log, its socket the one PHP calls, stdio detached;
 *   - a package that ships no pfb-core for this machine starts nothing and is not a failure; an unknown machine is;
 *   - a start over a Core that serves keeps it, also a supervisor that has not set its process title yet; a restart stops first;
 *   - starts are serialized by a lock (a start that cannot get it in 10 s launches nothing) and return once the supervisor is confirmed;
 *     a daemon(8) that fails is a failed start;
 *   - stop signals only the processes its own pidfiles name while their command line is pfb-core's, TERM first, KILL at 5 s; a Core
 *     still running 7 s after TERM fails the stop (pidfiles kept), and a start or restart over it launches nothing;
 *   - issue #3924: Core reads and writes its settings through the adapter script the daemon line names (--settings-backend-cmd),
 *     the start pushes nothing, and generating the service retires the settings store and push records of the earlier model.
 *
 * The real generator's output is written through the write_rcfile() double and executed under dash. Every absolute
 * command path is redirected to a command double (a path with no double fails the test instead of running a host
 * binary); `sleep 1` is one tick of a controlled clock, so the 5 s deadline is counted in ticks, never measured.
 */
#[CoversFunction('pfb_core_service')]
final class PfbCoreServiceTest extends TestCase
{
	private const DOUBLES = ['daemon', 'logger', 'lockf', 'uname', 'pgrep', 'pkill', 'sleep'];

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
				if [ -n "$due" ] && [ "$now" -ge "$due" ]; then continue; fi
				printf '%s|%s|%s\n' "$pid" "$args" "$due" >> "$S/procs.new"
			done < "$S/procs"
			mv "$S/procs.new" "$S/procs"
		}
		# A pidfile daemon(8) has opened but not yet written: pending is due|pidfile|pid, written once the clock reaches due
		settle() {
			[ -s "$S/pending" ] || return 0
			IFS='|' read -r due file pid < "$S/pending"
			[ "$(tick)" -ge "$due" ] || return 0
			echo "$pid" > "$file"
			true > "$S/pending"
		}
		# match PIDFILE PATTERN: the pid the pidfile names, when that process is alive and its args match PATTERN (ERE)
		match() {
			[ -r "$1" ] || return 1
			read -r want < "$1" || return 1
			while IFS='|' read -r pid args due; do
				if [ "$pid" = "$want" ] && printf '%s\n' "$args" | grep -Eq -- "$2"; then echo "$pid"; return 0; fi
			done < "$S/procs"
			return 1
		}
		case "${0##*/}" in
		pgrep|pkill)
			sig=
			if [ "${0##*/}" = pkill ]; then
				case "$1" in -TERM|-KILL) sig="${1#-}"; shift ;; *) ev bad-pkill; exit 2 ;; esac
			fi
			[ "$1" = -F ] && [ "$3" = -f ] && [ "$#" -eq 4 ] || { ev "bad-${0##*/}"; exit 2; }
			pid="$(match "$2" "$4")" || exit 1
			[ -n "$sig" ] || exit 0
			ev "$sig $pid"
			printf '%s %s @%s\n' "$sig" "$pid" "$(tick)" >> "$S/signal.ticks"
			true > "$S/procs.new"
			while IFS='|' read -r p args due; do
				[ -n "$p" ] || continue
				if [ "$p" = "$pid" ]; then
					if [ "$sig" = KILL ]; then
						case " $KILL_IGNORED " in *" $p "*) ;; *) continue ;; esac
					elif [ "$TERM_AFTER" != never ]; then
						due=$(( $(tick) + TERM_AFTER ))
					fi
				fi
				printf '%s|%s|%s\n' "$p" "$args" "$due" >> "$S/procs.new"
			done < "$S/procs"
			mv "$S/procs.new" "$S/procs"
			;;
		sleep)
			[ "$#" -eq 1 ] && [ "$1" = 1 ] || { ev bad-sleep; exit 2; }
			echo "$(( $(tick) + 1 ))" > "$S/ticks"
			reap
			settle
			;;
		logger)
			printf '%s\n' "$*" >> "$S/logger"
			;;
		uname)
			[ "$1" = -p ] || { ev bad-uname; exit 2; }
			printf '%s\n' "$MACHINE"
			;;
		lockf)
			# lockf(1) as the rc script must call it: -k (keep the lock file) -t 10 (wait at most 10 s) FILE COMMAND...; the lock itself
			# is not modelled, LOCKF_EXIT stands for a wait that ran out (75) and runs nothing
			[ "$1" = -k ] && [ "$2" = -t ] && [ "$3" = 10 ] && [ "$#" -ge 5 ] || { ev bad-lockf; exit 2; }
			printf '%s\n' "$*" >> "$S/lockf.calls"
			[ -z "$LOCKF_EXIT" ] || exit "$LOCKF_EXIT"
			shift 4
			exec "$@"
			;;
		daemon)
			orig="$0 $*"
			true > "$S/daemon.argv"
			for arg in "$@"; do printf '%s\n' "$arg" >> "$S/daemon.argv"; done
			attached=
			for fd in 0 1 2; do
				if [ "/dev/fd/$fd" -ef /dev/null ]; then attached="$attached$fd "; fi
			done
			echo "${attached:-none}" > "$S/fds"
			ev launch
			[ "$DAEMON_EXIT" = 0 ] || exit "$DAEMON_EXIT"
			supervisor=; child=
			while [ "$#" -gt 0 ]; do
				case "$1" in
				-P) supervisor="$2"; shift 2 ;;
				-p) child="$2"; shift 2 ;;
				-o|-R|-t) shift 2 ;;
				-r) shift ;;
				*) break ;;
				esac
			done
			# pidfile_open() creates the supervisor's pidfile before daemon(3); its pid is written later (SUPERVISOR_AT ticks on), and
			# until it sets its title the supervisor's command line is the one daemon(8) was started with
			true > "$supervisor"
			[ "$SUPERVISOR_AT" = never ] || echo "$(( $(tick) + SUPERVISOR_AT ))|$supervisor|3001" > "$S/pending"
			settle
			echo 3002 > "$child"
			printf '%s\n' "3001|$orig|" "3002|$*|" >> "$S/procs"
			;;
		*)
			exit 2
			;;
		esac
		SH;

	private string $dir = '';
	private string $shell = '';
	private array $savedPfb = [];
	private array $savedRcDir = [];

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? [];
		$this->savedRcDir = [array_key_exists('pfb_test_rcfile_dir', $GLOBALS), $GLOBALS['pfb_test_rcfile_dir'] ?? NULL];
		$this->dir = sys_get_temp_dir() . '/pfb_core_rc_' . bin2hex(random_bytes(6));
		foreach (['bin', 'state', 'run', 'log', 'rc', 'core/bin/freebsd-amd64', 'core/bin/freebsd-arm64'] as $sub) {
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
			'core_socket'         => "{$this->dir}/run/pfb_core/api.sock",
			'core_state'          => "{$this->dir}/db/pfb_core",
			'dbdir'               => "{$this->dir}/dbdir",
			'core_log'            => "{$this->dir}/log/core.log",
			'core_pidfile'        => "{$this->dir}/run/pfb_core.pid",
			'core_daemon_pidfile' => "{$this->dir}/run/pfb_core_daemon.pid",
			'core_lockfile'       => "{$this->dir}/run/pfb_core.lock",
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

	/** The installed pfb-core of one architecture: an executable file is all the start looks at. */
	private function install(string $target, int $mode = 0755): string
	{
		$binary = "{$this->dir}/core/bin/{$target}/pfb-core";
		file_put_contents($binary, "not run by the test\n");
		chmod($binary, $mode);
		return $binary;
	}

	/**
	 * Generate the script, point its commands at the doubles, and seed the scenario.
	 *
	 * @param array<string, string> $scenario overrides of the double's variables: SUPERVISOR_AT (tick the supervisor writes its pidfile at,
	 *   or never), DAEMON_EXIT (status of daemon(8)), LOCKF_EXIT (status of a lockf whose wait ran out), KILL_IGNORED (pids that survive KILL)
	 */
	private function arrange(string $machine = 'amd64', bool $running = FALSE, string $termAfter = '2', string $childArgs = '', array $scenario = []): void
	{
		pfb_core_service("{$this->dir}/core");
		$text = @file_get_contents("{$this->dir}/rc/pfb_core.sh");
		$this->assertIsString($text, 'pfb_core_service() wrote no rc script');
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
		// The settings adapter script, which Core runs, is the one host path an argument may name
		$this->assertDoesNotMatchRegularExpression('~(?<![\w.\-])/(?:var|usr|etc)/~', str_replace([$this->dir, '/usr/local/pkg/pfblockerng/pfb_core_settings.sh'], '', $script),
			"the rc script names a host path the test did not redirect:\n{$script}");
		file_put_contents("{$this->dir}/run.sh", $script);
		$state = "{$this->dir}/state";
		$vars = $scenario + ['MACHINE' => $machine, 'TERM_AFTER' => $termAfter, 'SUPERVISOR_AT' => '0', 'DAEMON_EXIT' => '0', 'LOCKF_EXIT' => '', 'KILL_IGNORED' => ''];
		file_put_contents("{$state}/scenario", implode('', array_map(
			static fn (string $k, string $v): string => "{$k}=" . escapeshellarg($v) . "\n",
			array_keys($vars),
			array_values($vars)
		)));
		file_put_contents("{$state}/ticks", "0\n");
		foreach (['events', 'procs', 'logger', 'daemon.argv', 'fds', 'lockf.calls', 'signal.ticks', 'pending'] as $file) {
			file_put_contents("{$state}/{$file}", '');
		}
		if ($running) {
			file_put_contents($GLOBALS['pfb']['core_daemon_pidfile'], "1001\n");
			file_put_contents($GLOBALS['pfb']['core_pidfile'], "1002\n");
			$child = $childArgs !== '' ? $childArgs : $this->coreArgs();
			file_put_contents("{$state}/procs", "1001|daemon: pfb_core[1002] (daemon)|\n1002|{$child}|\n");
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

	/** @return list<string> pids still alive in the sandbox process table */
	private function livePids(): array
	{
		return array_map(static fn (string $line): string => explode('|', $line, 2)[0], $this->lines('procs'));
	}

	/** The command line pfb-core runs under in the sandbox. */
	private function coreArgs(): string
	{
		return "{$this->dir}/core/bin/freebsd-amd64/pfb-core --socket {$GLOBALS['pfb']['core_socket']}";
	}

	/**
	 * A supervisor daemon(3) has forked and that has not set its process title yet: its pidfile names it, its command line is still the
	 * one daemon(8) was started with (the sandbox redirects /usr/sbin/daemon to its daemon double), and pfb-core has no pidfile yet.
	 */
	private function supervisorOnItsLaunchCommandLine(): void
	{
		$pfb = $GLOBALS['pfb'];
		file_put_contents($pfb['core_daemon_pidfile'], "1001\n");
		file_put_contents("{$this->dir}/state/procs",
			"1001|{$this->dir}/bin/daemon -r -R 5 -t pfb_core -P {$pfb['core_daemon_pidfile']} -p {$pfb['core_pidfile']} -o {$pfb['core_log']} {$this->coreArgs()}|\n");
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function machines(): array
	{
		return ['amd64' => ['amd64', 'freebsd-amd64'], 'aarch64' => ['aarch64', 'freebsd-arm64'], 'arm64' => ['arm64', 'freebsd-arm64']];
	}

	#[DataProvider('machines')]
	public function testStartRunsThisMachinesBinaryUnderDaemonWithTheSocketStateLogAndSettingsAdapter(string $machine, string $target): void
	{
		// Given both architectures' pfb-core are installed
		$this->install('freebsd-amd64');
		$this->install('freebsd-arm64');
		$this->arrange($machine);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then daemon(8) supervises this machine's binary, restarting it, with the package log, the API socket, Core's state directory and the settings adapter
		$this->assertSame(0, $status, $out);
		$this->assertSame([
			'-r', '-R', '5', '-t', 'pfb_core',
			'-P', $GLOBALS['pfb']['core_daemon_pidfile'], '-p', $GLOBALS['pfb']['core_pidfile'], '-o', $GLOBALS['pfb']['core_log'],
			"{$this->dir}/core/bin/{$target}/pfb-core", '--socket', $GLOBALS['pfb']['core_socket'],
			'--state-dir', $GLOBALS['pfb']['core_state'],
			'--settings-backend-cmd', '/usr/local/pkg/pfblockerng/pfb_core_settings.sh',
		], $this->lines('daemon.argv'));
		$this->assertSame(['0 1 2 '], $this->lines('fds'), 'the daemon inherited a descriptor of the caller (stdio must be /dev/null)');
	}

	public function testStartWithNoBinaryForThisMachineStartsNothingAndSaysSo(): void
	{
		// Given only the other architecture's pfb-core, or one that is not executable
		$this->install('freebsd-arm64');
		$this->install('freebsd-amd64', 0644);
		$this->arrange('amd64');

		[$status, $out] = $this->rc('start');

		$this->assertSame(0, $status, "a package without a usable pfb-core is not a failed start: {$out}");
		$this->assertSame([], $this->lines('events'), 'something was launched or signalled');
		$this->assertStringContainsString('not installed', implode("\n", $this->lines('logger')));
	}

	public function testStartOnAnUnknownMachineFails(): void
	{
		$this->install('freebsd-amd64');
		$this->install('freebsd-arm64');
		$this->arrange('riscv64');

		[$status, $out] = $this->rc('start');

		$this->assertSame(1, $status, $out);
		$this->assertSame([], $this->lines('events'));
		$this->assertStringContainsString('riscv64', implode("\n", $this->lines('logger')));
	}

	public function testStartOverACoreThatServesKeepsIt(): void
	{
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE);

		[$status, $out] = $this->rc('start');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'a serving Core was signalled or launched again');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	public function testRestartStopsTheRunningCoreThenLaunchesAgain(): void
	{
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE);

		[$status, $out] = $this->rc('restart');

		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001', 'TERM 1002', 'launch'], $this->lines('events'));
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testStopEscalatesToKillAfterFiveSeconds(): void
	{
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE, termAfter: 'never');

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001', 'TERM 1002', 'KILL 1001', 'KILL 1002'], $this->lines('events'));
		$this->assertSame('5', trim((string) file_get_contents("{$this->dir}/state/ticks")), 'KILL was not sent at the 5 s tick');
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['core_pidfile']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['core_daemon_pidfile']);
	}

	public function testStopNeverSignalsAProcessThatReusedAPidfilePid(): void
	{
		// Given pidfiles left behind whose pids now belong to unrelated processes
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE, childArgs: '/usr/sbin/sshd -D');
		file_put_contents("{$this->dir}/state/procs", "1001|/usr/sbin/cron|\n1002|/usr/sbin/sshd -D|\n");

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'an unrelated process was signalled');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	public function testStartRunsItselfUnderTheStartLockAndTheLockedRunTakesNoSecondLock(): void
	{
		// Given pfb-core is installed and nothing runs
		$this->install('freebsd-amd64');
		$this->arrange('amd64');

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then it ran itself once under lockf (lock file kept, 10 s wait), and that locked run launched without locking again
		$this->assertSame(0, $status, $out);
		$this->assertSame(["-k -t 10 {$this->dir}/run/pfb_core.lock /bin/sh {$this->dir}/run.sh start"], $this->lines('lockf.calls'));
		$this->assertSame(['launch'], $this->lines('events'));
	}

	public function testStartThatCannotTakeTheStartLockInTimeLaunchesNothingAndSaysSo(): void
	{
		// Given another start holds the start lock past lockf's wait (lockf then exits 75 without running the start)
		$this->install('freebsd-amd64');
		$this->arrange('amd64', scenario: ['LOCKF_EXIT' => '75']);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then it fails with lockf's status, launches and signals nothing, and logs one error naming the lock
		$this->assertSame(75, $status, $out);
		$this->assertSame([], $this->lines('events'), 'something was launched or signalled without the lock');
		$logged = $this->lines('logger');
		$this->assertCount(1, $logged, 'expected one log line, got: ' . implode(' | ', $logged));
		$this->assertStringContainsString('start lock', $logged[0]);
	}

	public function testStartKeepsASupervisorThatHasNotSetItsProcessTitleYet(): void
	{
		// Given a start A launched the supervisor a moment ago: its pidfile names it, but its command line is still daemon(8)'s own
		$this->install('freebsd-amd64');
		$this->arrange('amd64');
		$this->supervisorOnItsLaunchCommandLine();

		// When a start B runs
		[$status, $out] = $this->rc('start');

		// Then B sees a serving Core: it neither stops it (removing A's pidfile) nor launches a second supervisor
		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'the supervisor of the earlier start was signalled or launched again');
		$this->assertSame(['1001'], $this->livePids());
		$this->assertFileExists($GLOBALS['pfb']['core_daemon_pidfile']);
	}

	public function testStopSignalsASupervisorThatHasNotSetItsProcessTitleYet(): void
	{
		// Given the supervisor of a start that has just launched: its command line is still daemon(8)'s own
		$this->install('freebsd-amd64');
		$this->arrange('amd64');
		$this->supervisorOnItsLaunchCommandLine();

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then the supervisor is terminated, not left running behind a removed pidfile
		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001'], $this->lines('events'));
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['core_daemon_pidfile']);
	}

	/** @return array<string, array{0: string}> */
	public static function confirmedWithinFiveTicks(): array
	{
		return ['at once' => ['0'], 'after 2 ticks' => ['2'], 'at the last tick' => ['5']];
	}

	#[DataProvider('confirmedWithinFiveTicks')]
	public function testStartReturnsOnceThePidfileNamesTheSupervisor(string $at): void
	{
		// Given daemon(8) returns before the supervisor has written its pidfile, which it does $at ticks later
		$this->install('freebsd-amd64');
		$this->arrange('amd64', scenario: ['SUPERVISOR_AT' => $at]);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the start waited, one tick per poll, until the pidfile named the supervisor, and only then said started
		$this->assertSame(0, $status, $out);
		$this->assertSame($at, trim((string) file_get_contents("{$this->dir}/state/ticks")), 'the start did not wait for the supervisor pidfile');
		$this->assertSame('3001', trim((string) file_get_contents($GLOBALS['pfb']['core_daemon_pidfile'])));
		$this->assertStringContainsString('Core API started', implode("\n", $this->lines('logger')));
	}

	/** @return array<string, array{0: string}> */
	public static function neverConfirmed(): array
	{
		return ['one tick too late' => ['6'], 'never' => ['never']];
	}

	#[DataProvider('neverConfirmed')]
	public function testStartFailsWhenNoSupervisorAppearsWithinFiveTicks(string $at): void
	{
		// Given daemon(8) returns and the supervisor's pidfile stays empty beyond the fifth tick
		$this->install('freebsd-amd64');
		$this->arrange('amd64', scenario: ['SUPERVISOR_AT' => $at]);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then it gives up after five ticks with the error, and never claims the Core started
		$this->assertSame(1, $status, $out);
		$this->assertSame('5', trim((string) file_get_contents("{$this->dir}/state/ticks")), 'the start did not give up at the fifth tick');
		$logged = implode("\n", $this->lines('logger'));
		$this->assertStringContainsString('started no supervisor', $logged);
		$this->assertStringNotContainsString('Core API started', $logged);
	}

	public function testStartWhoseDaemonCommandFailsIsNotStartedAndSaysWhy(): void
	{
		// Given daemon(8) rejects its arguments (status 6) and writes nothing
		$this->install('freebsd-amd64');
		$this->arrange('amd64', scenario: ['DAEMON_EXIT' => '6']);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the start fails at once with daemon's status in the log, and never claims the Core started
		$this->assertSame(1, $status, $out);
		$this->assertSame('0', trim((string) file_get_contents("{$this->dir}/state/ticks")), 'the start waited for a supervisor of a daemon(8) that failed');
		$logged = implode("\n", $this->lines('logger'));
		$this->assertStringContainsString('failed with status 6', $logged);
		$this->assertStringNotContainsString('Core API started', $logged);
	}

	public function testStopOfACoreThatSurvivesKillFailsAtSevenSecondsAndKeepsItsPidfiles(): void
	{
		// Given a running Core whose pfb-core ignores TERM and survives KILL
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE, termAfter: 'never', scenario: ['KILL_IGNORED' => '1002']);

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then TERM went out at 0 s and KILL (once) at 5 s, the stop failed at 7 s naming the survivor, and both pidfiles are kept
		$this->assertSame(1, $status, $out);
		$this->assertSame(['TERM 1001 @0', 'TERM 1002 @0', 'KILL 1001 @5', 'KILL 1002 @5'], $this->lines('signal.ticks'));
		$this->assertSame('7', trim((string) file_get_contents("{$this->dir}/state/ticks")), 'the stop did not give up at the 7 s tick');
		$this->assertSame(['1002'], $this->livePids());
		$this->assertStringContainsString('still running after KILL', implode("\n", $this->lines('logger')));
		$this->assertFileExists($GLOBALS['pfb']['core_pidfile']);
		$this->assertFileExists($GLOBALS['pfb']['core_daemon_pidfile']);
	}

	public function testRestartOverACoreThatSurvivesKillFailsWithoutLaunching(): void
	{
		// Given a running Core whose pfb-core ignores TERM and survives KILL
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE, termAfter: 'never', scenario: ['KILL_IGNORED' => '1002']);

		// When the service restarts
		[$status, $out] = $this->rc('restart');

		// Then the restart fails after the failed stop: no second Core is launched over the survivor
		$this->assertSame(1, $status, $out);
		$this->assertSame(['TERM 1001', 'TERM 1002', 'KILL 1001', 'KILL 1002'], $this->lines('events'));
		$this->assertSame(['1002'], $this->livePids());
	}

	public function testStartOverAnOrphanedCoreThatSurvivesKillFailsWithoutLaunching(): void
	{
		// Given pfb-core alive under its pidfile, its supervisor gone, and pfb-core ignoring TERM and surviving KILL
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE, termAfter: 'never', scenario: ['KILL_IGNORED' => '1002']);
		unlink($GLOBALS['pfb']['core_daemon_pidfile']);
		file_put_contents("{$this->dir}/state/procs", "1002|{$this->coreArgs()}|\n");

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the start's stop fails and the start fails with it: nothing is launched
		$this->assertSame(1, $status, $out);
		$this->assertSame(['TERM 1002', 'KILL 1002'], $this->lines('events'));
		$this->assertSame(['1002'], $this->livePids());
	}

	public function testStartStopsAnOrphanedCoreBeforeLaunchingAgain(): void
	{
		// Given pfb-core alive under its pidfile while its supervisor is gone
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE);
		unlink($GLOBALS['pfb']['core_daemon_pidfile']);
		file_put_contents("{$this->dir}/state/procs", "1002|{$this->coreArgs()}|\n");

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the orphan is terminated before the new Core is launched, so two pfb-core never run side by side
		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1002', 'launch'], $this->lines('events'));
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testStopNeverSignalsAProcessWhoseNameOnlyStartsWithPfbCoresPath(): void
	{
		// Given the child's pidfile names a live process of a binary called pfb-core-old, next to the package's own supervisor
		$this->install('freebsd-amd64');
		$this->arrange('amd64', running: TRUE, childArgs: "{$this->dir}/core/bin/freebsd-amd64/pfb-core-old --x");

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then only the supervisor is terminated: pfb-core-old is not pfb-core
		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001'], $this->lines('events'));
		$this->assertSame(['1002'], $this->livePids());
	}

	public function testStartPushesNothingToCoreAndNamesNoPhpVerb(): void
	{
		// Given a Core whose socket exists, as soon as the service starts
		$this->install('freebsd-amd64');
		$this->arrange('amd64');
		$this->assertTrue(mkdir(dirname($GLOBALS['pfb']['core_socket']), 0700, TRUE));
		$server = stream_socket_server('unix://' . $GLOBALS['pfb']['core_socket'], $errno, $errstr);
		$this->assertNotFalse($server, "socket: {$errstr}");
		$text = (string) file_get_contents("{$this->dir}/rc/pfb_core.sh");

		try {
			// When the service starts
			[$status, $out] = $this->rc('start');
		} finally {
			fclose($server);
		}

		// Then it launched the daemon and nothing else: Core reads the settings itself, through the adapter
		$this->assertSame(0, $status, $out);
		$this->assertSame(['launch'], $this->lines('events'));
		$this->assertStringNotContainsString('core_push', $text);
		$this->assertStringNotContainsString('pfblockerng.inc', $text, 'the rc script runs no PHP verb');
	}

	public function testGeneratingTheServiceRetiresTheSettingsStoreAndPushRecordsOfTheEarlierModel(): void
	{
		// Given Core's state directory with the old store, and the old push records
		$state = $GLOBALS['pfb']['core_state'];
		$this->assertTrue(mkdir($state, 0700, TRUE));
		$this->assertTrue(mkdir($GLOBALS['pfb']['dbdir'], 0700, TRUE));
		$old = [
			"{$state}/settings.json", "{$state}/settings.json.tmp", "{$state}/settings.lock",
			"{$GLOBALS['pfb']['dbdir']}/core_pushed", "{$GLOBALS['pfb']['dbdir']}/core_push_failed",
		];
		$keep = ["{$state}/core.lock", "{$state}/other.dat", "{$GLOBALS['pfb']['dbdir']}/core_settings_failed"];
		foreach ([...$old, ...$keep] as $file) {
			$this->assertNotFalse(file_put_contents($file, 'x'), "fixture {$file}");
		}

		// When the service is generated (every install and upgrade does)
		pfb_core_service("{$this->dir}/core");

		// Then the old files are gone and nothing else is
		foreach ($old as $file) {
			$this->assertFileDoesNotExist($file);
		}
		foreach ($keep as $file) {
			$this->assertFileExists($file);
		}
	}

	public function testTheServiceIsRegisteredWithPfSense(): void
	{
		$xml = (string) file_get_contents(__DIR__ . '/../../src/usr/local/pkg/pfblockerng.xml');
		$this->assertMatchesRegularExpression(
			'~<service>\s*<name>pfb_core</name>\s*<rcfile>pfb_core\.sh</rcfile>\s*'
			. '<custom_php_service_status_command>isvalidpid\(\'/var/run/pfb_core\.pid\'\)</custom_php_service_status_command>\s*'
			. '<description>[^<]+</description>\s*</service>~',
			$xml
		);
	}
}
