<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * #3423 — restarting the DNSBL webserver must never launch a replacement lighttpd_pfb
 * while the previous one is still alive.
 *
 * Function under test: pfb_dnsbl_service() — generates /usr/local/etc/rc.d/pfb_dnsbl.sh.
 * Every package-owned restart (pfb_create_dnsbl(), pfb_update_unbound(), the dashboard
 * widget -> restart_service('pfb_dnsbl')) runs this one script, so its rc_stop / rc_start
 * pair is the single gate. Intent: after TERM the stop path waits (bounded) for the exact
 * lighttpd_pfb process to exit, escalates to KILL, and fails when the process still
 * survives; rc_start refuses to launch over a survivor.
 *
 * The generated start/stop bodies are captured through the write_rcfile() double, wrapped
 * exactly as pfSense's write_rcfile() wraps them, and executed under dash. Every absolute
 * executable path in the body is redirected to a sandbox command double (a path with no
 * double fails the test instead of running a host binary). The doubles model one process
 * table and a controlled clock: `sleep 1` is one tick, so the 5 s TERM deadline and the 2 s
 * KILL grace are counted in ticks, never measured in wall-clock time.
 */
#[CoversFunction('pfb_dnsbl_service')]
final class DnsblServiceRestartTest extends TestCase
{
	private const DOUBLES = ['pgrep', 'killall', 'sleep', 'logger', 'lighttpd_pfb', 'read_xml_tag.sh'];

	private const DOUBLE = <<<'SH'
		#!/bin/sh
		# One script, installed under every command name the rc body uses; $0 picks the role.
		S=@STATE@
		. "$S/scenario"
		ev() { printf '%s\n' "$1" >> "$S/events"; }
		# Remove every exact-name lighttpd_pfb once the clock reaches the scheduled death tick.
		reap() {
			[ -s "$S/death" ] || return 0
			read -r due < "$S/death"
			read -r now < "$S/ticks"
			[ "$now" -ge "$due" ] || return 0
			keep=
			while IFS= read -r name; do
				[ "$name" = lighttpd_pfb ] || keep="${keep}${name}
		"
			done < "$S/procs"
			printf '%s' "$keep" > "$S/procs"
			: > "$S/death"
		}
		# Schedule death $1 ticks from now unless the process ignores the signal.
		schedule() {
			[ "$1" != never ] || return 0
			read -r now < "$S/ticks"
			at=$((now + $1))
			if [ -s "$S/death" ]; then
				read -r cur < "$S/death"
				[ "$at" -lt "$cur" ] || return 0
			fi
			echo "$at" > "$S/death"
		}
		case "${0##*/}" in
		pgrep)
			exact=
			if [ "$1" = -x ]; then exact=1; shift; fi
			[ "$#" -eq 1 ] || exit 2
			status=1
			n=0
			while IFS= read -r name; do
				n=$((n + 1))
				if [ -n "$exact" ]; then
					[ "$name" = "$1" ] || continue
				else
					case "$name" in *"$1"*) ;; *) continue ;; esac
				fi
				echo "$((1000 + n))"
				status=0
			done < "$S/procs"
			exit "$status"
			;;
		killall)
			case "$1" in
			-KILL|-9) sig='kill'; shift ;;
			-*) exit 2 ;;
			*) sig='term' ;;
			esac
			[ "$#" -eq 1 ] || exit 2
			grep -qx -- "$1" "$S/procs" || exit 1
			ev "$sig"
			if [ "$sig" = kill ]; then schedule "$KILL_AFTER"; else schedule "$TERM_AFTER"; fi
			reap
			;;
		sleep)
			[ "$#" -eq 1 ] && [ "$1" = 1 ] || { ev bad-sleep; exit 2; }
			ev sleep
			read -r now < "$S/ticks"
			echo "$((now + 1))" > "$S/ticks"
			reap
			;;
		logger)
			ev log
			;;
		read_xml_tag.sh)
			echo on
			;;
		lighttpd_pfb)
			[ "$1" = -f ] && [ -e "$2" ] || { ev bad-launch; exit 2; }
			attached=
			for fd in 0 1 2; do
				if [ "/dev/fd/$fd" -ef /dev/null ]; then attached="$attached$fd "; fi
			done
			ev launch
			if grep -qx lighttpd_pfb "$S/procs"; then ev collision; fi
			echo "${attached:-none}" >> "$S/fds"
			echo lighttpd_pfb >> "$S/procs"
			;;
		*)
			exit 2
			;;
		esac
		SH;

	private string $dir = '';

	private string $shell = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_dnsbl_rc_' . bin2hex(random_bytes(6));
		foreach (['bin', 'state', 'var'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0777, TRUE), "sandbox mkdir failed: {$this->dir}/{$sub}");
		}
		$double = "{$this->dir}/double.sh";
		file_put_contents($double, str_replace('@STATE@', escapeshellarg("{$this->dir}/state"), self::DOUBLE) . "\n");
		chmod($double, 0755);
		foreach (self::DOUBLES as $name) {
			$this->assertTrue(symlink($double, "{$this->dir}/bin/{$name}"), "double link failed: {$name}");
		}
		touch("{$this->dir}/var/pfb_dnsbl_lighty.conf");
		touch("{$this->dir}/var/pfb_unbound.py");
		$dash = trim((string) shell_exec('command -v dash 2>/dev/null'));
		$this->shell = $dash !== '' ? $dash : '/bin/sh';
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/**
	 * Build the executable rc script from the real generator, with the process table and
	 * clock seeded: $procs are the live process names, $termAfter / $killAfter are the
	 * ticks the exact lighttpd_pfb takes to die after TERM / KILL ('never' = ignores it).
	 *
	 * @param list<string> $procs
	 */
	private function arrange(array $procs, string $termAfter = 'never', string $killAfter = 'never'): void
	{
		$state = "{$this->dir}/state";
		file_put_contents("{$state}/scenario", "TERM_AFTER={$termAfter}\nKILL_AFTER={$killAfter}\n");
		file_put_contents("{$state}/procs", implode('', array_map(static fn (string $p): string => "{$p}\n", $procs)));
		file_put_contents("{$state}/ticks", "0\n");
		foreach (['events', 'fds', 'death'] as $file) {
			file_put_contents("{$state}/{$file}", '');
		}

		$GLOBALS['pfb_test_rcfiles'] = [];
		pfb_dnsbl_service();
		$rc = $GLOBALS['pfb_test_rcfiles']['pfb_dnsbl.sh'] ?? null;
		$this->assertIsArray($rc, 'write_rcfile() never produced pfb_dnsbl.sh');

		$sandbox = fn (string $body): string => $this->sandboxPaths($body);
		$start = $sandbox((string) $rc['start']);
		$stop = $sandbox((string) $rc['stop']);
		$restart = isset($rc['restart']) ? $sandbox((string) $rc['restart']) : "\trc_stop\n\trc_start\n";
		// Same wrapper as pfSense service-utils.inc write_rcfile().
		$script = "#!/bin/sh\n\nrc_start() {\n\t{$start}\n}\n\nrc_stop() {\n\t{$stop}\n}\n\n"
			. "rc_restart() {\n{$restart}\n}\n\n"
			. "case \$1 in\n\tstart)\n\t\trc_start\n\t\t;;\n\tstop)\n\t\trc_stop\n\t\t;;\n\trestart)\n\t\trc_restart\n\t\t;;\nesac\n\n";
		file_put_contents("{$this->dir}/pfb_dnsbl.sh", $script);
	}

	/** Point every absolute path in a generated body at the sandbox; fail closed on any other. */
	private function sandboxPaths(string $body): string
	{
		return (string) preg_replace_callback(
			'~(?<![\w$.\-/])/(?:[\w.\-]+/)*[\w.\-]+~',
			function (array $m): string {
				$path = $m[0];
				if ($path === '/dev/null') {
					return $path;
				}
				if (preg_match('~^/(?:usr/local/sbin|usr/local/bin|usr/sbin|usr/bin|sbin|bin)/([\w.\-]+)$~', $path, $cmd) === 1) {
					$this->assertFileExists("{$this->dir}/bin/{$cmd[1]}", "no command double for {$path}; refusing to run a host binary");
					return "{$this->dir}/bin/{$cmd[1]}";
				}
				if (preg_match('~^/var/unbound/([\w.\-]+)$~', $path, $file) === 1) {
					return "{$this->dir}/var/{$file[1]}";
				}
				$this->fail("generated rc body references {$path} with no sandbox replacement; refusing to run it");
			},
			$body
		);
	}

	/**
	 * Run a command with pipes (never /dev/null) on fds 0/1/2 under a hard watchdog.
	 *
	 * @return array{0: int, 1: string} exit status and combined stdout/stderr
	 */
	private function runCommand(string ...$command): array
	{
		$proc = proc_open(
			[$GLOBALS['pfb']['timeout'], '-k', '2', '20', ...$command],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
			$pipes
		);
		$this->assertIsResource($proc, 'proc_open failed');
		fclose($pipes[0]);
		$output = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		return [proc_close($proc), $output];
	}

	/** @return array{0: int, 1: string} */
	private function rc(string $verb): array
	{
		return $this->runCommand($this->shell, "{$this->dir}/pfb_dnsbl.sh", $verb);
	}

	/**
	 * Recorded command events in order: term, kill, sleep, launch, collision, log.
	 *
	 * @return list<string>
	 */
	private function events(bool $withLogs = FALSE): array
	{
		$lines = file("{$this->dir}/state/events", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		return $withLogs ? $lines : array_values(array_filter($lines, static fn (string $e): bool => $e !== 'log'));
	}

	/** @return list<string> */
	private function liveProcesses(): array
	{
		return file("{$this->dir}/state/procs", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
	}

	/** One TERM wait that runs the full 5-tick deadline and escalates to KILL. */
	private static function termDeadlineThenKill(): array
	{
		return ['term', 'sleep', 'sleep', 'sleep', 'sleep', 'sleep', 'kill'];
	}

	public static function noProcessProvider(): array
	{
		return [
			'start launches exactly once' => ['start', ['launch']],
			'stop returns without signalling' => ['stop', []],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('noProcessProvider')]
	public function testNoRunningProcessNeverWaits(string $verb, array $expected): void
	{
		// Given no lighttpd_pfb is alive
		$this->arrange([]);

		// When the service is started / stopped
		[$status, $output] = $this->rc($verb);

		// Then it returns at once: no signal, no tick of waiting, one launch for start
		$this->assertSame(0, $status, "rc {$verb} failed: {$output}");
		$this->assertSame($expected, $this->events(), "rc {$verb} command events");
		$this->assertSame($verb === 'start' ? ['lighttpd_pfb'] : [], $this->liveProcesses());
	}

	public function testStopWaitsForProcessToExitAfterTerm(): void
	{
		// Given lighttpd_pfb that exits two ticks after TERM
		$this->arrange(['lighttpd_pfb'], '2');
		$this->assertSame(['lighttpd_pfb'], $this->liveProcesses(), 'precondition: process alive');

		// When the service is stopped
		[$status, $output] = $this->rc('stop');

		// Then stop returns only after observing the exit, with no KILL
		$this->assertSame(0, $status, "rc stop failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep'], $this->events());
		$this->assertSame([], $this->liveProcesses());
	}

	public function testStartWaitsForPreviousProcessThenLaunchesOnce(): void
	{
		// Given lighttpd_pfb that exits two ticks after TERM
		$this->arrange(['lighttpd_pfb'], '2');

		// When the service is started (rc_start stops the old process first)
		[$status, $output] = $this->rc('start');

		// Then the replacement launches only after the old one exited: no collision, no KILL
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['term', 'sleep', 'sleep', 'launch'], $this->events());
		$this->assertSame(['lighttpd_pfb'], $this->liveProcesses());
	}

	public function testProcessIgnoringTermIsKilledAfterFiveTicks(): void
	{
		// Given lighttpd_pfb that ignores TERM and dies one tick after KILL
		$this->arrange(['lighttpd_pfb'], 'never', '1');

		// When the service is started
		[$status, $output] = $this->rc('start');

		// Then TERM is waited on for exactly 5 ticks, the escalation is logged and KILLed,
		// the grace observes the exit, and only then does the replacement launch
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(
			[...self::termDeadlineThenKill(), 'sleep', 'launch'],
			$this->events(),
			'TERM wait / KILL / grace / launch order'
		);
		$all = $this->events(TRUE);
		$kill = array_search('kill', $all, TRUE);
		$this->assertSame('log', $all[$kill - 1] ?? null, 'the KILL escalation is logged before it is sent');
		$this->assertSame(['lighttpd_pfb'], $this->liveProcesses());
	}

	public static function survivorProvider(): array
	{
		$cycle = [...self::termDeadlineThenKill(), 'sleep', 'sleep'];
		return [
			'stop' => ['stop', $cycle],
			'start' => ['start', $cycle],
			// pfSense's default rc_restart is rc_stop then rc_start, and rc_start stops again.
			'restart' => ['restart', [...$cycle, ...$cycle]],
		];
	}

	/** @param list<string> $expected */
	#[DataProvider('survivorProvider')]
	public function testProcessSurvivingKillFailsAndNeverLaunchesReplacement(string $verb, array $expected): void
	{
		// Given lighttpd_pfb that survives both TERM and KILL
		$this->arrange(['lighttpd_pfb']);

		// When the service is stopped / started / restarted
		[$status, $output] = $this->rc($verb);

		// Then 5 TERM ticks and 2 grace ticks are spent, the command fails (not by harness
		// timeout), and no replacement is ever launched over the survivor
		$this->assertNotContains($status, [0, 124, 137], "rc {$verb} must fail on its own: {$output}");
		$this->assertSame($expected, $this->events(), "rc {$verb} command events");
		$this->assertSame(['lighttpd_pfb'], $this->liveProcesses(), 'the survivor is the only process');
	}

	public function testRapidRestartsNeverCollide(): void
	{
		// Given a fresh service whose webserver exits one tick after TERM
		$this->arrange([], '1');

		// When it is started and then restarted twice back to back
		foreach (['start', 'restart', 'restart'] as $verb) {
			[$status, $output] = $this->rc($verb);
			$this->assertSame(0, $status, "rc {$verb} failed: {$output}");
		}

		// Then every launch followed the previous process's exit: no collision, no KILL,
		// and exactly one process is alive at the end
		$restart = ['term', 'sleep', 'launch'];
		$this->assertSame(['launch', ...$restart, ...$restart], $this->events());
		$this->assertSame(['lighttpd_pfb'], $this->liveProcesses());
	}

	public function testLauncherStdFdsAreDetachedToDevNull(): void
	{
		// Given a launcher probe, first run bare under the harness pipes (control)
		$this->arrange([]);
		[$status, $output] = $this->runCommand("{$this->dir}/bin/lighttpd_pfb", '-f', "{$this->dir}/var/pfb_dnsbl_lighty.conf");
		$this->assertSame(0, $status, "control launch failed: {$output}");
		$this->assertSame(['none'], $this->fdReports(), 'the probe reports no /dev/null fd for pipe stdio');
		file_put_contents("{$this->dir}/state/procs", '');

		// When the service launches lighttpd_pfb
		[$status, $output] = $this->rc('start');

		// Then the launched webserver sees fds 0, 1 and 2 attached to /dev/null (#662)
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame(['none', '0 1 2'], $this->fdReports());
	}

	/** @return list<string> one entry per launch: the fds attached to /dev/null */
	private function fdReports(): array
	{
		$lines = file("{$this->dir}/state/fds", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		return array_map('trim', $lines);
	}

	public static function lookAlikeProvider(): array
	{
		return [
			'only look-alike names are alive' => [['lighttpd_pfb_old', 'xlighttpd_pfb'], 'never', ['launch']],
			'look-alikes next to an exact process that exits after TERM' => [
				['lighttpd_pfb_old', 'lighttpd_pfb', 'xlighttpd_pfb'],
				'1',
				['term', 'sleep', 'launch'],
			],
		];
	}

	/**
	 * @param list<string> $procs
	 * @param list<string> $expected
	 */
	#[DataProvider('lookAlikeProvider')]
	public function testLivenessMatchesExactProcessNameOnly(array $procs, string $termAfter, array $expected): void
	{
		// Given processes whose names merely contain lighttpd_pfb
		$this->arrange($procs, $termAfter);

		// When the service is started
		[$status, $output] = $this->rc('start');

		// Then they are neither waited on nor signalled: only the exact name counts
		$this->assertSame(0, $status, "rc start failed: {$output}");
		$this->assertSame($expected, $this->events());
		$this->assertSame(['lighttpd_pfb_old', 'xlighttpd_pfb', 'lighttpd_pfb'], $this->liveProcesses());
	}
}
