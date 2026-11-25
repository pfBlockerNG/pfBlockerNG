<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The sandbox Core's rc script runs in, shared with every service generated in its shape (issue #4145): pfb_core.sh and
 * pfb_crowdsec.sh. The real generator's output is written through the write_rcfile() double and executed under dash. Every
 * absolute command path is redirected to a command double (a path with no double fails the test instead of running a host
 * binary); `sleep 1` is one tick of a controlled clock, so the 5 s and 7 s deadlines are counted in ticks, never measured.
 *
 * A test class calls sandboxUp() from setUp() and sandboxDown() from tearDown(), and its arrange() generates the script and
 * hands it to sandboxArrange(). The class names its service with rcService(), childArgs(), binary(), preLaunchEvents() and
 * arrangeInstalled(); the rows below, the lock, stop, survivor and start-confirmation contract both services share, then run
 * for each of them.
 *
 * Pids: a running pair is supervisor 1001 and child 1002 (the pidfiles name them), the pair a start launches 3001 and 3002.
 */
trait CoreRcSandboxTrait
{
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
			# lockf(1) as the rc script must call it: -k (keep the lock file) -t 20 (wait at most 20 s) FILE COMMAND...; the lock itself
			# is not modelled, LOCKF_EXIT stands for a wait that ran out (75) and runs nothing
			[ "$1" = -k ] && [ "$2" = -t ] && [ "$3" = 20 ] && [ "$#" -ge 5 ] || { ev bad-lockf; exit 2; }
			printf '%s\n' "$*" >> "$S/lockf.calls"
			# What the supervisor's pidfile was when the lock was asked for: absent, empty or its pid
			if [ ! -e "$DAEMON_PIDFILE" ]; then echo absent; elif [ -s "$DAEMON_PIDFILE" ]; then cat "$DAEMON_PIDFILE"; else echo empty; fi >> "$S/lockf.pidfile"
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
		id)
			# id(1) asked for unbound's uid (-u) or gid (-g); an empty UNBOUND_UID stands for a system without that user
			[ "$#" -eq 2 ] && [ "$2" = unbound ] || { ev bad-id; exit 2; }
			[ -n "$UNBOUND_UID" ] || exit 1
			case "$1" in -u) echo "$UNBOUND_UID" ;; -g) echo "$UNBOUND_GID" ;; *) ev bad-id; exit 2 ;; esac
			;;
		sha256)
			[ "$#" -eq 2 ] && [ "$1" = -r ] || { ev bad-sha256; exit 2; }
			printf '%s %s\n' "$BINARY_SHA" "$2"
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
			# The lock marker of the locked run, as the daemon inherits it (unset: anything the daemon runs takes the lock again)
			printenv "$LOCK_VAR" > "$S/daemon.env" || echo unset > "$S/daemon.env"
			[ "$DAEMON_EXIT" = 0 ] || exit "$DAEMON_EXIT"
			supervisor=; child=
			while [ "$#" -gt 0 ]; do
				case "$1" in
				-P) supervisor="$2"; shift 2 ;;
				-p) child="$2"; shift 2 ;;
				-o|-R|-t|-l|-s|-T) shift 2 ;;
				-r|-S) shift ;;
				-*) ev "bad-daemon $1"; exit 2 ;;
				*) break ;;
				esac
			done
			# pidfile_open() creates the supervisor's pidfile before daemon(3); its pid is written later (SUPERVISOR_AT ticks on), and
			# until it sets its title the supervisor's command line is the one daemon(8) was started with
			true > "$supervisor"
			[ "$SUPERVISOR_AT" = never ] || echo "$(( $(tick) + SUPERVISOR_AT ))|$supervisor|$SUPERVISOR_PID" > "$S/pending"
			settle
			echo 3002 > "$child"
			printf '%s\n' "3001|$orig|" "3002|$*|" >> "$S/procs"
			;;
		*)
			ev "unexpected ${0##*/}"
			exit 2
			;;
		esac
		SH;

	private string $dir = '';
	private string $shell = '';
	private array $savedPfb = [];
	private array $savedRcDir = [];

	/**
	 * @return array{tag: string, pidfile: string, daemon_pidfile: string, lockfile: string, lock_var: string, started: string, lock_held: string}
	 *   the daemon(8) tag; the $pfb keys of the child's pidfile, the supervisor's pidfile and the lock file; the variable that marks
	 *   the locked run; and the log text of a confirmed start and of a lock another start or stop held
	 */
	abstract private static function rcService(): array;

	/** The command line the child runs under when $binary is the executable. */
	abstract private function childArgs(string $binary): string;

	/** This machine's (amd64) installed child binary. */
	abstract private function binary(): string;

	/** The events a start records before it stops what is left and launches (the service's own checks). @return list<string> */
	abstract private function preLaunchEvents(): array;

	/**
	 * Install the amd64 binary, set the service up to start, and arrange the script.
	 *
	 * @param array<string, string> $scenario overrides of the double's variables (sandboxArrange())
	 * @param ?string $child the running child's command line (default: this machine's binary)
	 */
	abstract private function arrangeInstalled(bool $running = FALSE, array $scenario = [], ?string $child = NULL): void;

	/**
	 * @param list<string> $doubles the command names the rc body uses
	 * @param list<string> $dirs sandbox folders to create
	 * @param array<string, string> $pfb the $pfb entries pointed into the sandbox (relative to it)
	 */
	private function sandboxUp(array $doubles, array $dirs, array $pfb): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? [];
		$this->savedRcDir = [array_key_exists('pfb_test_rcfile_dir', $GLOBALS), $GLOBALS['pfb_test_rcfile_dir'] ?? NULL];
		$this->dir = sys_get_temp_dir() . '/' . static::rcService()['tag'] . '_rc_' . bin2hex(random_bytes(6));
		foreach (['bin', 'state', 'run', 'rc', ...$dirs] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0777, TRUE), "sandbox mkdir failed: {$sub}");
		}
		$double = "{$this->dir}/double.sh";
		file_put_contents($double, str_replace('@STATE@', escapeshellarg("{$this->dir}/state"), self::DOUBLE) . "\n");
		chmod($double, 0755);
		foreach ($doubles as $name) {
			$this->assertTrue(symlink($double, "{$this->dir}/bin/{$name}"), "double link failed: {$name}");
		}
		$rm = trim((string) shell_exec('command -v rm'));
		$this->assertNotSame('', $rm, 'no rm on this host');
		$this->assertTrue(symlink($rm, "{$this->dir}/bin/rm"));
		$dash = trim((string) shell_exec('command -v dash 2>/dev/null'));
		$this->shell = $dash !== '' ? $dash : '/bin/sh';

		$GLOBALS['pfb'] = array_merge($this->savedPfb, array_map(fn (string $path): string => "{$this->dir}/{$path}", $pfb));
		$GLOBALS['pfb_test_rcfile_dir'] = "{$this->dir}/rc";
	}

	private function sandboxDown(): void
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

	/**
	 * Point the generated script's commands at the doubles, refuse a host path it names that the test did not redirect, and seed the
	 * scenario.
	 *
	 * @param list<string> $hostWords host paths the script may name without opening them (or that its programs are told)
	 * @param array<string, string> $vars the double's variables: MACHINE, TERM_AFTER (ticks a TERMed process takes to exit, or never),
	 *   SUPERVISOR_AT (ticks after daemon(8) the supervisor writes its pidfile, or never), SUPERVISOR_PID (the pid it writes there),
	 *   DAEMON_EXIT (status of daemon(8)), LOCKF_EXIT (status of a lockf whose wait ran out), KILL_IGNORED (pids that survive KILL),
	 *   and the service's own
	 * @param ?string $child the running child's command line (default: this machine's binary)
	 */
	private function sandboxArrange(string $text, array $hostWords, array $vars, bool $running, ?string $child = NULL): void
	{
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
		$named = [$this->dir, ...$hostWords];
		usort($named, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));
		$this->assertDoesNotMatchRegularExpression('~(?<![\w.\-])/(?:var|usr|etc)/~', str_replace($named, '', $script),
			"the rc script names a host path the test did not redirect:\n{$script}");
		file_put_contents("{$this->dir}/run.sh", $script);
		$state = "{$this->dir}/state";
		$vars += ['MACHINE' => 'amd64', 'TERM_AFTER' => '1', 'SUPERVISOR_AT' => '0', 'DAEMON_EXIT' => '0', 'LOCKF_EXIT' => '', 'KILL_IGNORED' => '',
			'LOCK_VAR' => static::rcService()['lock_var'], 'DAEMON_PIDFILE' => $this->rcPath('daemon_pidfile'), 'SUPERVISOR_PID' => '3001',
			'UNBOUND_UID' => '59', 'UNBOUND_GID' => '60'];
		file_put_contents("{$state}/scenario", implode('', array_map(
			static fn (string $k, string $v): string => "{$k}=" . escapeshellarg($v) . "\n",
			array_keys($vars),
			array_values($vars)
		)));
		file_put_contents("{$state}/ticks", "0\n");
		foreach (['events', 'procs', 'logger', 'daemon.argv', 'daemon.env', 'fds', 'lockf.calls', 'lockf.pidfile', 'signal.ticks', 'pending', 'ancestry', 'ancestry.self'] as $file) {
			file_put_contents("{$state}/{$file}", '');
		}
		if ($running) {
			file_put_contents($this->rcPath('daemon_pidfile'), "1001\n");
			file_put_contents($this->rcPath('pidfile'), "1002\n");
			$tag = static::rcService()['tag'];
			file_put_contents("{$state}/procs", "1001|daemon: {$tag}[1002] (daemon)|\n1002|" . ($child ?? $this->childArgs($this->binary())) . "|\n");
		}
	}

	/** @param 'pidfile'|'daemon_pidfile'|'lockfile' $which */
	private function rcPath(string $which): string
	{
		return $GLOBALS['pfb'][static::rcService()[$which]];
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

	private function ticks(): string
	{
		return trim((string) file_get_contents("{$this->dir}/state/ticks"));
	}

	/** The child alive under its pidfile while its supervisor (and its pidfile) is gone. */
	private function orphanedChild(): void
	{
		unlink($this->rcPath('daemon_pidfile'));
		file_put_contents("{$this->dir}/state/procs", "1002|{$this->childArgs($this->binary())}|\n");
	}

	/**
	 * A supervisor daemon(3) has forked and that has not set its process title yet: its pidfile names it, its command line is still the
	 * one daemon(8) was started with (the sandbox redirects /usr/sbin/daemon to its daemon double), and the child has no pidfile yet.
	 */
	private function supervisorOnItsLaunchCommandLine(): void
	{
		$tag = static::rcService()['tag'];
		file_put_contents($this->rcPath('daemon_pidfile'), "1001\n");
		file_put_contents("{$this->dir}/state/procs", "1001|{$this->dir}/bin/daemon -r -R 5 -t {$tag} -P {$this->rcPath('daemon_pidfile')} "
			. "-p {$this->rcPath('pidfile')} {$this->childArgs($this->binary())}|\n");
	}

	// ---- the lock: starts and stops run one after the other ------------------------------------------------------------

	public function testStartRunsItselfUnderTheLockAndTheLockedRunTakesNoSecondLock(): void
	{
		// Given the binary is installed and nothing runs
		$this->arrangeInstalled();

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then it ran itself once under lockf (lock file kept, 20 s wait), and that locked run launched without locking again
		$this->assertSame(0, $status, $out);
		$this->assertSame(["-k -t 20 {$this->rcPath('lockfile')} /bin/sh {$this->dir}/run.sh start"], $this->lines('lockf.calls'));
		$this->assertSame([...$this->preLaunchEvents(), 'launch'], $this->lines('events'));
		// ...and the daemon does not inherit the locked run's marker: a start from anything it runs takes the lock again
		$this->assertSame(['unset'], $this->lines('daemon.env'));
	}

	public function testStopRunsUnderTheLockSoItNeverRemovesThePidfileOfAStartInFlight(): void
	{
		// Given a start in flight: daemon(8) has created the supervisor's pidfile but not yet written its pid into it
		$this->arrangeInstalled();
		$this->assertNotFalse(file_put_contents($this->rcPath('daemon_pidfile'), ''));

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then the stop ran itself under the same lock as the starts (so it waits for that start's confirmation), and only once
		$this->assertSame(0, $status, $out);
		$this->assertSame(["-k -t 20 {$this->rcPath('lockfile')} /bin/sh {$this->dir}/run.sh stop"], $this->lines('lockf.calls'));
		// ...before touching the start's pidfile, which was still there, empty, when the stop asked for the lock
		$this->assertSame(['empty'], $this->lines('lockf.pidfile'));
	}

	public function testStartThatCannotTakeTheLockInTimeLaunchesNothingAndSaysSo(): void
	{
		// Given an orphaned child a locked start would stop, and another start holding the lock past lockf's wait (lockf then exits 75
		// without running the start)
		$this->arrangeInstalled(running: TRUE, scenario: ['LOCKF_EXIT' => '75']);
		$this->orphanedChild();

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then it fails with lockf's status, launches and signals nothing, and logs one error naming the lock
		$this->assertSame(75, $status, $out);
		$this->assertSame([], $this->lines('events'), 'something was launched or signalled without the lock');
		$this->assertSame(['1002'], $this->livePids());
		$this->assertFileExists($this->rcPath('pidfile'));
		$logged = $this->lines('logger');
		$this->assertCount(1, $logged, 'expected one log line, got: ' . implode(' | ', $logged));
		$this->assertStringContainsString(static::rcService()['lock_held'] . ' for 20 s - not started', $logged[0]);
	}

	public function testStopThatCannotTakeTheLockInTimeSignalsNothingAndFails(): void
	{
		// Given a running pair, and a start holding the lock past lockf's wait
		$this->arrangeInstalled(running: TRUE, scenario: ['LOCKF_EXIT' => '75']);

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then the stop fails with lockf's status, signals nothing, keeps the pair and its pidfiles and logs one error naming the lock
		$this->assertSame(75, $status, $out);
		$this->assertSame([], $this->lines('events'), 'something was signalled without the lock');
		$this->assertSame(['1001', '1002'], $this->livePids());
		$this->assertFileExists($this->rcPath('daemon_pidfile'));
		$this->assertFileExists($this->rcPath('pidfile'));
		$logged = $this->lines('logger');
		$this->assertCount(1, $logged, 'expected one log line, got: ' . implode(' | ', $logged));
		$this->assertStringContainsString(static::rcService()['lock_held'] . ' for 20 s - not stopped', $logged[0]);
	}

	// ---- stop: only what a pidfile names, TERM then KILL ---------------------------------------------------------------

	public function testStartOverARunningServiceKeepsIt(): void
	{
		$this->arrangeInstalled(running: TRUE);

		[$status, $out] = $this->rc('start');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'a running pair was signalled or launched again');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	public function testRestartStopsTheRunningPairThenLaunchesAgain(): void
	{
		$this->arrangeInstalled(running: TRUE);

		[$status, $out] = $this->rc('restart');

		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001', 'TERM 1002', ...$this->preLaunchEvents(), 'launch'], $this->lines('events'));
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testStopEscalatesToKillAfterFiveSeconds(): void
	{
		// Given a running pair that ignores TERM
		$this->arrangeInstalled(running: TRUE, scenario: ['TERM_AFTER' => 'never']);

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then TERM went to both at 0 s and KILL to both at 5 s, which ended them, and both pidfiles are gone
		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001', 'TERM 1002', 'KILL 1001', 'KILL 1002'], $this->lines('events'));
		$this->assertSame(['TERM 1001 @0', 'TERM 1002 @0', 'KILL 1001 @5', 'KILL 1002 @5'], $this->lines('signal.ticks'));
		$this->assertSame('5', $this->ticks(), 'KILL was not sent at the 5 s tick');
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->rcPath('pidfile'));
		$this->assertFileDoesNotExist($this->rcPath('daemon_pidfile'));
	}

	public function testStopNeverSignalsAProcessThatReusedAPidfilePid(): void
	{
		// Given pidfiles left behind whose pids now belong to unrelated processes
		$this->arrangeInstalled(running: TRUE);
		file_put_contents("{$this->dir}/state/procs", "1001|/usr/sbin/cron|\n1002|/usr/sbin/sshd -D|\n");

		[$status, $out] = $this->rc('stop');

		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'an unrelated process was signalled');
		$this->assertSame(['1001', '1002'], $this->livePids());
	}

	/** @return array<string, array{0: string}> another service's supervisor whose tag begins with this one's, %s standing for its tag */
	public static function anotherDaemon(): array
	{
		return ['by its title' => ['daemon: %s_other[1002] (daemon)'], 'by its launch command line' => ['@BIN@/daemon -r -t %s_other -P /x /usr/sbin/other']];
	}

	#[DataProvider('anotherDaemon')]
	public function testStopNeverSignalsAnotherDaemonWhoseTagOnlyStartsWithThisOne(string $args): void
	{
		// Given the supervisor pidfile names a daemon(8) started for another service whose tag begins with this one's
		$this->arrangeInstalled();
		file_put_contents($this->rcPath('daemon_pidfile'), "1001\n");
		$args = str_replace('@BIN@', "{$this->dir}/bin", sprintf($args, static::rcService()['tag']));
		file_put_contents("{$this->dir}/state/procs", "1001|{$args}|\n");

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then that daemon is left alone
		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'another service\'s daemon was signalled');
		$this->assertSame(['1001'], $this->livePids());
	}

	public function testStopNeverSignalsAProcessWhoseNameOnlyStartsWithTheBinarysPath(): void
	{
		// Given the child's pidfile names a live process of a binary whose name only begins with the service's, beside its own supervisor
		$this->arrangeInstalled(running: TRUE, child: $this->childArgs("{$this->binary()}-old"));

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then only the supervisor is terminated
		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001'], $this->lines('events'));
		$this->assertSame(['1002'], $this->livePids());
	}

	public function testStartKeepsASupervisorThatHasNotSetItsProcessTitleYet(): void
	{
		// Given a start A launched the supervisor a moment ago: its pidfile names it, but its command line is still daemon(8)'s own
		$this->arrangeInstalled();
		$this->supervisorOnItsLaunchCommandLine();

		// When a start B runs
		[$status, $out] = $this->rc('start');

		// Then B sees a running service: it neither stops it (removing A's pidfile) nor launches a second supervisor
		$this->assertSame(0, $status, $out);
		$this->assertSame([], $this->lines('events'), 'the supervisor of the earlier start was signalled or launched again');
		$this->assertSame(['1001'], $this->livePids());
		$this->assertFileExists($this->rcPath('daemon_pidfile'));
	}

	public function testStopSignalsASupervisorThatHasNotSetItsProcessTitleYet(): void
	{
		// Given the supervisor of a start that has just launched: its command line is still daemon(8)'s own
		$this->arrangeInstalled();
		$this->supervisorOnItsLaunchCommandLine();

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then the supervisor is terminated, not left running behind a removed pidfile
		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1001'], $this->lines('events'));
		$this->assertSame([], $this->livePids());
		$this->assertFileDoesNotExist($this->rcPath('daemon_pidfile'));
	}

	public function testStartStopsAnOrphanedChildBeforeLaunchingAgain(): void
	{
		// Given the child alive under its pidfile while its supervisor is gone
		$this->arrangeInstalled(running: TRUE);
		$this->orphanedChild();

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the orphan is terminated before the new pair is launched, so two children never run side by side
		$this->assertSame(0, $status, $out);
		$this->assertSame([...$this->preLaunchEvents(), 'TERM 1002', 'launch'], $this->lines('events'));
		$this->assertSame(['3001', '3002'], $this->livePids());
	}

	public function testStopOfAnOrphanedChildSignalsTheChild(): void
	{
		// Given the child alive under its pidfile while its supervisor is gone
		$this->arrangeInstalled(running: TRUE);
		$this->orphanedChild();

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then the child alone is terminated
		$this->assertSame(0, $status, $out);
		$this->assertSame(['TERM 1002'], $this->lines('events'));
		$this->assertSame([], $this->livePids());
	}

	// ---- a child that survives KILL fails the stop, and every start or restart over it ---------------------------------

	public function testStopOfAChildThatSurvivesKillFailsAtSevenSecondsAndKeepsItsPidfiles(): void
	{
		// Given a running pair whose child ignores TERM and survives KILL
		$this->arrangeInstalled(running: TRUE, scenario: ['TERM_AFTER' => 'never', 'KILL_IGNORED' => '1002']);

		// When the service stops
		[$status, $out] = $this->rc('stop');

		// Then TERM went out at 0 s and KILL (once) at 5 s, the stop failed at 7 s naming the survivor, and both pidfiles are kept
		$this->assertSame(1, $status, $out);
		$this->assertSame(['TERM 1001 @0', 'TERM 1002 @0', 'KILL 1001 @5', 'KILL 1002 @5'], $this->lines('signal.ticks'));
		$this->assertSame('7', $this->ticks(), 'the stop did not give up at the 7 s tick');
		$this->assertSame(['1002'], $this->livePids());
		$this->assertStringContainsString('still running after KILL', implode("\n", $this->lines('logger')));
		$this->assertFileExists($this->rcPath('pidfile'));
		$this->assertFileExists($this->rcPath('daemon_pidfile'));
	}

	public function testRestartOverAChildThatSurvivesKillFailsWithoutLaunching(): void
	{
		$this->arrangeInstalled(running: TRUE, scenario: ['TERM_AFTER' => 'never', 'KILL_IGNORED' => '1002']);

		[$status, $out] = $this->rc('restart');

		// Then the restart fails after the failed stop: no second pair is launched over the survivor
		$this->assertSame(1, $status, $out);
		$this->assertSame(['TERM 1001', 'TERM 1002', 'KILL 1001', 'KILL 1002'], $this->lines('events'));
		$this->assertSame(['1002'], $this->livePids());
	}

	public function testStartOverAnOrphanedChildThatSurvivesKillFailsWithoutLaunching(): void
	{
		// Given the child alive under its pidfile, its supervisor gone, and the child ignoring TERM and surviving KILL
		$this->arrangeInstalled(running: TRUE, scenario: ['TERM_AFTER' => 'never', 'KILL_IGNORED' => '1002']);
		$this->orphanedChild();

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the start's stop fails and the start fails with it: nothing is launched
		$this->assertSame(1, $status, $out);
		$this->assertSame([...$this->preLaunchEvents(), 'TERM 1002', 'KILL 1002'], $this->lines('events'));
		$this->assertSame(['1002'], $this->livePids());
	}

	// ---- a start returns once the supervisor is confirmed --------------------------------------------------------------

	/** @return array<string, array{0: string}> */
	public static function confirmedWithinFiveTicks(): array
	{
		return ['at once' => ['0'], 'after 2 ticks' => ['2'], 'at the last tick' => ['5']];
	}

	#[DataProvider('confirmedWithinFiveTicks')]
	public function testStartReturnsOnceThePidfileNamesTheSupervisor(string $at): void
	{
		// Given daemon(8) returns before the supervisor has written its pidfile, which it does $at ticks later
		$this->arrangeInstalled(scenario: ['SUPERVISOR_AT' => $at]);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the start waited, one tick per poll, until the pidfile named the supervisor, and only then said started
		$this->assertSame(0, $status, $out);
		$this->assertSame($at, $this->ticks(), 'the start did not wait for the supervisor pidfile');
		$this->assertSame('3001', trim((string) file_get_contents($this->rcPath('daemon_pidfile'))));
		$this->assertStringContainsString(static::rcService()['started'], implode("\n", $this->lines('logger')));
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
		$this->arrangeInstalled(scenario: ['SUPERVISOR_AT' => $at]);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then it gives up after five ticks with the error, and never claims the service started
		$this->assertSame(1, $status, $out);
		$this->assertSame('5', $this->ticks(), 'the start did not give up at the fifth tick');
		$logged = implode("\n", $this->lines('logger'));
		$this->assertStringContainsString('started no supervisor', $logged);
		$this->assertStringNotContainsString(static::rcService()['started'], $logged);
	}

	public function testStartFailsWhenThePidfileNamesAnUnrelatedProcess(): void
	{
		// Given the supervisor's pidfile, once written, names a live process that is no supervisor of this service
		$this->arrangeInstalled(scenario: ['SUPERVISOR_PID' => '77']);
		file_put_contents("{$this->dir}/state/procs", "77|/usr/sbin/cron|\n");

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then it is not taken for the supervisor: the start gives up after five ticks and never claims the service started
		$this->assertSame(1, $status, $out);
		$this->assertSame('5', $this->ticks(), 'the start did not give up at the fifth tick');
		$this->assertSame('77', trim((string) file_get_contents($this->rcPath('daemon_pidfile'))), 'the pidfile did not name the unrelated pid');
		$logged = implode("\n", $this->lines('logger'));
		$this->assertStringContainsString('started no supervisor', $logged);
		$this->assertStringNotContainsString(static::rcService()['started'], $logged);
	}

	public function testStartWhoseDaemonCommandFailsIsNotStartedAndSaysWhy(): void
	{
		// Given daemon(8) rejects its arguments (status 6) and writes nothing
		$this->arrangeInstalled(scenario: ['DAEMON_EXIT' => '6']);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the start fails at once with daemon's status in the log, and never claims the service started
		$this->assertSame(1, $status, $out);
		$this->assertSame('0', $this->ticks(), 'the start waited for a supervisor of a daemon(8) that failed');
		$logged = implode("\n", $this->lines('logger'));
		$this->assertStringContainsString('failed with status 6', $logged);
		$this->assertStringNotContainsString(static::rcService()['started'], $logged);
	}
}
