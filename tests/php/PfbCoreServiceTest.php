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
 *   - a start over a Core that serves keeps it; a restart stops first;
 *   - stop signals only the processes its own pidfiles name while their command line is pfb-core's, TERM first, KILL at 5 s.
 *
 * The real generator's output is written through the write_rcfile() double and executed under dash. Every absolute
 * command path is redirected to a command double (a path with no double fails the test instead of running a host
 * binary); `sleep 1` is one tick of a controlled clock, so the 5 s deadline is counted in ticks, never measured.
 */
#[CoversFunction('pfb_core_service')]
final class PfbCoreServiceTest extends TestCase
{
	private const DOUBLES = ['daemon', 'logger', 'uname', 'pgrep', 'pkill', 'sleep'];

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
			true > "$S/procs.new"
			while IFS='|' read -r p args due; do
				[ -n "$p" ] || continue
				if [ "$p" = "$pid" ]; then
					[ "$sig" = KILL ] && continue
					[ "$TERM_AFTER" = never ] || due=$(( $(tick) + TERM_AFTER ))
				fi
				printf '%s|%s|%s\n' "$p" "$args" "$due" >> "$S/procs.new"
			done < "$S/procs"
			mv "$S/procs.new" "$S/procs"
			;;
		sleep)
			[ "$#" -eq 1 ] && [ "$1" = 1 ] || { ev bad-sleep; exit 2; }
			echo "$(( $(tick) + 1 ))" > "$S/ticks"
			reap
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
				if [ "/dev/fd/$fd" -ef /dev/null ]; then attached="$attached$fd "; fi
			done
			echo "${attached:-none}" > "$S/fds"
			ev launch
			supervisor=; child=; title=
			while [ "$#" -gt 0 ]; do
				case "$1" in
				-P) supervisor="$2"; shift 2 ;;
				-p) child="$2"; shift 2 ;;
				-t) title="$2"; shift 2 ;;
				-o|-R) shift 2 ;;
				-r) shift ;;
				*) break ;;
				esac
			done
			echo 3001 > "$supervisor"
			echo 3002 > "$child"
			printf '%s\n' "3001|daemon: $title[3002] (daemon)|" "3002|$*|" >> "$S/procs"
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
			'core_log'            => "{$this->dir}/log/core.log",
			'core_pidfile'        => "{$this->dir}/run/pfb_core.pid",
			'core_daemon_pidfile' => "{$this->dir}/run/pfb_core_daemon.pid",
		]);
		$GLOBALS['pfb_test_rcfile_dir'] = "{$this->dir}/rc";
		// Every generated start names timeout(1) and the PHP binary of its settings push (issue #3913)
		$this->installPushDouble();
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

	/** Generate the script, point its commands at the doubles, and seed the scenario. */
	private function arrange(string $machine = 'amd64', bool $running = FALSE, string $termAfter = '2', string $childArgs = ''): void
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
		// pfblockerng.inc, which the start's settings push runs, is the one host path an argument may name
		$this->assertDoesNotMatchRegularExpression('~(?<![\w.\-])/(?:var|usr|etc)/~', str_replace([$this->dir, '/usr/local/pkg/pfblockerng/pfblockerng.inc'], '', $script),
			"the rc script names a host path the test did not redirect:\n{$script}");
		file_put_contents("{$this->dir}/run.sh", $script);
		$state = "{$this->dir}/state";
		file_put_contents("{$state}/scenario", 'MACHINE=' . escapeshellarg($machine) . "\nTERM_AFTER=" . escapeshellarg($termAfter) . "\n");
		file_put_contents("{$state}/ticks", "0\n");
		foreach (['events', 'procs', 'logger', 'daemon.argv', 'fds'] as $file) {
			file_put_contents("{$state}/{$file}", '');
		}
		if ($running) {
			file_put_contents($GLOBALS['pfb']['core_daemon_pidfile'], "1001\n");
			file_put_contents($GLOBALS['pfb']['core_pidfile'], "1002\n");
			$child = $childArgs !== '' ? $childArgs : "{$this->dir}/core/bin/freebsd-amd64/pfb-core --socket {$GLOBALS['pfb']['core_socket']}";
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

	/** @return array<string, array{0: string, 1: string}> */
	public static function machines(): array
	{
		return ['amd64' => ['amd64', 'freebsd-amd64'], 'aarch64' => ['aarch64', 'freebsd-arm64'], 'arm64' => ['arm64', 'freebsd-arm64']];
	}

	#[DataProvider('machines')]
	public function testStartRunsThisMachinesBinaryUnderDaemonWithTheSocketStateAndLog(string $machine, string $target): void
	{
		// Given both architectures' pfb-core are installed
		$this->install('freebsd-amd64');
		$this->install('freebsd-arm64');
		$this->arrange($machine);

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then daemon(8) supervises this machine's binary, restarting it, with the package log, the API socket and Core's state directory
		$this->assertSame(0, $status, $out);
		$this->assertSame([
			'-r', '-R', '5', '-t', 'pfb_core',
			'-P', $GLOBALS['pfb']['core_daemon_pidfile'], '-p', $GLOBALS['pfb']['core_pidfile'], '-o', $GLOBALS['pfb']['core_log'],
			"{$this->dir}/core/bin/{$target}/pfb-core", '--socket', $GLOBALS['pfb']['core_socket'],
			'--state-dir', $GLOBALS['pfb']['core_state'],
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

	/** The timeout(1) double of the settings push: records its argv, which descriptors are /dev/null, and an event, then holds until released. */
	private function installPushDouble(): void
	{
		$state = escapeshellarg("{$this->dir}/state");
		$double = <<<SH
			#!/bin/sh
			S={$state}
			printf '%s\\n' "\$@" > "\$S/push.argv"
			attached=
			for fd in 0 1 2; do
				if [ "/dev/fd/\$fd" -ef /dev/null ]; then attached="\$attached\$fd "; fi
			done
			echo "\${attached:-none}" > "\$S/push.fds"
			printf 'push\\n' >> "\$S/events"
			echo ready > "\$S/push.ready"
			n=0
			while [ ! -e "\$S/push.release" ] && [ "\$n" -lt 200 ]; do /bin/sleep 0.05; n=\$((n + 1)); done
			echo done > "\$S/push.done"

			SH;
		file_put_contents("{$this->dir}/bin/timeout", $double);
		chmod("{$this->dir}/bin/timeout", 0755);
		$GLOBALS['pfb']['php'] = "{$this->dir}/bin/php";
	}

	/** Wait (bounded) for a file the backgrounded push writes. */
	private function awaitState(string $file): bool
	{
		$deadline = hrtime(TRUE) + 10_000_000_000;
		while (!file_exists("{$this->dir}/state/{$file}")) {
			if (hrtime(TRUE) > $deadline) {
				return FALSE;
			}
			usleep(10_000);
		}
		return TRUE;
	}

	public function testStartPushesTheSettingsOnceCoreListens(): void
	{
		// Given Core's socket is up and the push's timeout(1) holds until released
		$this->install('freebsd-amd64');
		$this->installPushDouble();
		$this->arrange('amd64');
		$this->assertTrue(mkdir(dirname($GLOBALS['pfb']['core_socket']), 0700, TRUE));
		$server = stream_socket_server('unix://' . $GLOBALS['pfb']['core_socket'], $errno, $errstr);
		$this->assertNotFalse($server, "socket: {$errstr}");

		try {
			// When the service starts
			[$status, $out] = $this->rc('start');

			// Then the start returned while the push still runs, and the push is the core_push verb under timeout(1), after the daemon launch
			$this->assertSame(0, $status, $out);
			$this->assertTrue($this->awaitState('push.ready'), 'the start never ran the settings push');
			$this->assertSame([
				'-s', 'TERM', '-k', '5', '60', "{$this->dir}/bin/php", '-f', '/usr/local/pkg/pfblockerng/pfblockerng.inc', 'core_push',
			], $this->lines('push.argv'));
			$this->assertSame(['launch', 'push'], $this->lines('events'));
			$this->assertSame(['0 1 2 '], $this->lines('push.fds'), 'the push inherited a descriptor of the caller');
			$this->assertFileDoesNotExist("{$this->dir}/state/push.done", 'the start waited for the push');
		} finally {
			touch("{$this->dir}/state/push.release");
			$this->awaitState('push.done');
			fclose($server);
		}
	}

	public function testStartGivesUpWaitingForTheSocketAfterThirtySeconds(): void
	{
		// Given Core never listens
		$this->install('freebsd-amd64');
		$this->installPushDouble();
		$this->arrange('amd64');

		// When the service starts
		[$status, $out] = $this->rc('start');

		// Then the start returns, the backgrounded wait counts thirty 1 s steps and stops, and no push ran
		$this->assertSame(0, $status, $out);
		$deadline = hrtime(TRUE) + 10_000_000_000;
		while ((int) trim((string) @file_get_contents("{$this->dir}/state/ticks")) < 30 && hrtime(TRUE) < $deadline) {
			usleep(10_000);
		}
		usleep(300_000);
		$this->assertSame('30', trim((string) file_get_contents("{$this->dir}/state/ticks")), 'the wait is bounded at 30 one-second steps');
		$this->assertFileDoesNotExist("{$this->dir}/state/push.argv");
		$this->assertSame(['launch'], $this->lines('events'));
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
