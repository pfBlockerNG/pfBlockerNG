<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4260 (part of #3977, the coverage matrix): the CLI verbs that ran a PHP pass in-process, `cron`, `update`,
 * `updateip`, `updatednsbl`, `pfb_trigger` and `forcecheck`, start an Update through the Core API's StartUpdate instead and
 * follow it to its end: the Update's log goes to stdout as Core holds it, and the exit status is the Update's result. Before
 * the cutover Core runs that Update through `--update-cmd` (the PHP update program), so what it does is unchanged.
 *   - No silent PHP fallback: a Core API that is down, or that refuses the caller (a user who is not root), gets a clear message
 *     and a non-zero exit.
 *   - An Update started while one runs is Core's `conflict`: reported, nothing queued, and the exit status of a held lock
 *     (PFB_EXIT_LOCKED), as a deferred pass exited.
 *   - `cron` (verb or trigger) is a `manual` Update, as the owner decided for the bypass entries ("manual or apply, as
 *     fits"): Core's `retry` runs the due Extras first, which the verb never did.
 */
#[CoversFunction('pfb_cli_update_request')]
#[CoversFunction('pfb_cli_update_run')]
#[CoversFunction('pfb_cli_deprecation_warning')]
#[CoversFunction('pfb_cli_deprecate')]
final class CliUpdateVerbsTest extends TestCase
{
	/** @var list<array{0: string, 1: array}> every call the fake Core got: method, params */
	private array $calls = [];
	private string $out = '';
	private string $err = '';

	/** The request the verbs make, and the one the fake Core's Updates report (update()). */
	private const MANUAL = ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none'];

	/** @return array<string, array{0: list<string>, 1: ?array}> */
	public static function verbs(): array
	{
		return [
			'cron (deprecated)'           => [['cron'], ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']],
			'update'                      => [['update'], ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']],
			'updateip'                    => [['updateip'], ['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse']],
			'updatednsbl'                 => [['updatednsbl'], ['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'parse']],
			'pfb_trigger defaults'        => [['pfb_trigger'], ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']],
			'pfb_trigger forced reload'   => [['pfb_trigger', 'scope=ip', 'force=true', 'trigger=force'],
				['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse']],
			'pfb_trigger manual dnsbl'    => [['pfb_trigger', 'scope=dnsbl', 'force=false', 'trigger=manual'],
				['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'none']],
			'pfb_trigger cron'            => [['pfb_trigger', 'scope=dnsbl', 'force=false', 'trigger=cron'],
				['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'none']],
			'pfb_trigger unknown values'  => [['pfb_trigger', 'scope=all', 'trigger=later'],
				['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']],
			'forcecheck'                  => [['forcecheck', 'scope=ip'], ['trigger' => 'manual', 'scope' => 'ip', 'force' => 'download']],
			'forcecheck with the hashes'  => [['forcecheck', 'scope=dnsbl', 'hashes=true'],
				['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'both']],
			'forcecheck unknown scope'    => [['forcecheck', 'scope=x'], ['trigger' => 'manual', 'scope' => 'both', 'force' => 'download']],
			'the last scope given'        => [['pfb_trigger', 'scope=ip', 'scope=dnsbl'],
				['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'none']],
			'an Extra verb is none'       => [['dcc'], NULL],
			'the tick is none'            => [['tick'], NULL],
		];
	}

	/** @param list<string> $args */
	#[DataProvider('verbs')]
	public function testEachVerbAsksCoreForItsUpdate(array $args, ?array $want): void
	{
		$this->assertSame($want, pfb_cli_update_request(array_merge(['pfblockerng.php'], $args)));
	}

	/** A Core that answers each call with the next of $replies (the last one again once they run out), recording the call. */
	private function core(array ...$replies): callable
	{
		return function (string $method, array $params, ?string $socket, int $timeout) use (&$replies): array {
			$this->calls[] = [$method, $params];
			return count($replies) > 1 ? array_shift($replies) : $replies[0];
		};
	}

	private static function ok(array $body): array
	{
		return ['status' => 200, 'body' => $body, 'error' => NULL];
	}

	private static function update(bool $running, string $log, string $next, ?string $result = NULL, int $started = 100): array
	{
		$update = ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none', 'startedAt' => $started];
		if ($result !== NULL) {
			$update += ['finishedAt' => $started + 5, 'result' => $result];
		}
		return self::ok(['running' => $running, 'update' => $update, 'log' => $log, 'next' => $next]);
	}

	/** The verb asks for its Update at second 100 of the fake clock. */
	private function follow(array $request, callable $core, int $polls = 10): int
	{
		return pfb_cli_update_run($request, $core,
			function (string $s): void { $this->out .= $s; },
			function (string $s): void { $this->err .= $s; },
			static function (): void {}, $polls, static fn (): int => 100);
	}

	/**
	 * Right after StartUpdate, GetUpdate can still report the Update before ours (seen on a box): one that started before the
	 * verb asked is not ours, so the verb waits for its own instead of taking that one's result or calling ours another.
	 */
	public function testAnUpdateThatStartedBeforeTheRequestIsNotOurs(): void
	{
		$code = $this->follow(['trigger' => 'manual', 'scope' => 'both', 'force' => 'none'], $this->core(self::ok([]),
			self::update(FALSE, "old\n", '9', 'failed', 50), self::update(TRUE, "ours\n", '5', NULL, 100),
			self::update(FALSE, '', '5', 'success', 100)));

		$this->assertSame(0, $code, $this->err);
		$this->assertSame('', $this->err);
		$this->assertSame("ours\n", $this->out, 'the earlier Update\'s log is none of ours');
	}

	public function testTheUpdateIsStartedThenFollowedToItsEndWithItsLog(): void
	{
		$ours = static function (array $answer): array {
			$answer['body']['update'] = ['scope' => 'ip', 'force' => 'parse'] + $answer['body']['update'];
			return $answer;
		};
		$code = $this->follow(['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse'], $this->core(self::ok([]),
			$ours(self::update(TRUE, "first\n", '6')), $ours(self::update(TRUE, '', '6')),
			$ours(self::update(FALSE, "last\n", '11', 'success'))));

		$this->assertSame(0, $code);
		$this->assertSame("first\nlast\n", $this->out, 'the Update log goes to stdout, each chunk once');
		[$method, $params] = $this->calls[0];
		$this->assertSame('StartUpdate', $method);
		$this->assertSame(['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse'], array_diff_key($params, ['requestId' => 1]));
		$this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $params['requestId']);
		$this->assertSame([['GetUpdate', []], ['GetUpdate', ['after' => '6']], ['GetUpdate', ['after' => '6']]],
			array_slice($this->calls, 1), 'the log is read from the cursor Core gave');
	}

	/**
	 * The Update log goes to stdout only when stdout is a terminal ($out NULL otherwise), as the pass in-process mirrored itself:
	 * the Update program writes the main log itself, so a verb whose stdout is appended to that log adds no second copy.
	 */
	public function testWithoutATerminalTheLogIsNotEchoedAndTheResultStands(): void
	{
		$code = pfb_cli_update_run(['trigger' => 'manual', 'scope' => 'both', 'force' => 'none'],
			$this->core(self::ok([]), self::update(FALSE, "hook output\n", '12', 'success')),
			NULL, function (string $s): void { $this->err .= $s; }, static function (): void {}, 10, static fn (): int => 100);

		$this->assertSame(0, $code);
		$this->assertSame('', $this->err);
	}

	/** The page echoes the Update log only to a terminal. */
	public function testThePageEchoesTheLogOnlyToATerminal(): void
	{
		$page = (string) file_get_contents(__DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertStringContainsString("pfb_stdout_is_terminal() ? static function (string \$text): void { echo \$text; } : NULL", $page);
	}

	/** @return array<string, array{0: string, 1: int}> */
	public static function results(): array
	{
		return ['failed' => ['failed', 1], 'skipped (the pass was deferred)' => ['skipped', PFB_EXIT_LOCKED]];
	}

	#[DataProvider('results')]
	public function testTheExitStatusIsTheUpdatesResult(string $result, int $code): void
	{
		$this->assertSame($code, $this->follow(self::MANUAL, $this->core(self::ok([]), self::update(FALSE, '', '0', $result))));
	}

	/** A deferred pass, which once said so on the CLI's stderr, still does: Core reports it as the Update's result `skipped`. */
	public function testASkippedUpdateSaysThePassWasDeferred(): void
	{
		$this->follow(self::MANUAL, $this->core(self::ok([]), self::update(FALSE, '', '0', 'skipped')));

		$this->assertSame("pfBlockerNG feed pass deferred: the Update was skipped while another pass holds its lock\n", $this->err);
	}

	public function testAnUpdateThatRunsAlreadyIsAConflictReportedAndNothingQueued(): void
	{
		$code = $this->follow(self::MANUAL, $this->core(['status' => 409, 'body' => ['error' => ['code' => 'conflict',
			'message' => 'an Update is running']], 'error' => NULL]));

		$this->assertSame(PFB_EXIT_LOCKED, $code);
		$this->assertStringContainsString('conflict: an Update is running', $this->err);
		$this->assertCount(1, $this->calls, 'nothing is queued or retried');
	}

	/** @return array<string, array{0: array}> */
	public static function refusals(): array
	{
		return [
			'the Core API is down'         => [['status' => 0, 'body' => NULL, 'error' => 'the Core API cannot be reached: No such file or directory']],
			'a caller that is not root'    => [['status' => 0, 'body' => NULL, 'error' => 'the Core API cannot be reached: Permission denied']],
			'a method a client may not call' => [['status' => 401, 'body' => ['error' => ['code' => 'unauthenticated',
				'message' => 'the method is for root alone']], 'error' => NULL]],
		];
	}

	#[DataProvider('refusals')]
	public function testACoreThatDoesNotStartTheUpdateIsAClearFailureWithoutAFallback(array $answer): void
	{
		$this->assertSame(1, $this->follow(self::MANUAL, $this->core($answer)));
		$this->assertStringStartsWith('pfBlockerNG Core did not start the Update: ', $this->err);
		$this->assertCount(1, $this->calls);
	}

	/**
	 * Core answers `unavailable` while the result of an Update that just ended waits to be recorded (the worker published its
	 * completion before its lock holder exited): the Update is not lost, so the verb asks again, within its wait.
	 */
	public function testAnUnavailableCoreIsAskedAgainUntilTheResultIsRecorded(): void
	{
		$code = $this->follow(self::MANUAL, $this->core(self::ok([]), self::update(TRUE, "x\n", '2'),
			['status' => 503, 'body' => ['error' => ['code' => 'unavailable', 'message' => 'an Update result is waiting to be recorded']],
				'error' => NULL],
			self::update(FALSE, "y\n", '4', 'success')));

		$this->assertSame(0, $code);
		$this->assertSame("x\ny\n", $this->out);
		$this->assertSame('', $this->err);
		$this->assertSame(['after' => '2'], $this->calls[3][1], 'the cursor stands across the unavailable answer');
	}

	/**
	 * An Update that started in the very second the verb asked, but is not the one it asked for (a tick's Update that was
	 * skipped at once), is not ours: ours is the one with the trigger, scope and force the verb asked for.
	 */
	public function testAnUpdateOfTheSameSecondThatIsNotTheOneAskedForIsNotOurs(): void
	{
		$tick = self::update(FALSE, "tick\n", '3', 'skipped', 100);
		$tick['body']['update']['trigger'] = 'scheduled';
		$code = $this->follow(self::MANUAL, $this->core(self::ok([]), $tick, self::update(TRUE, "ours\n", '5', NULL, 100),
			self::update(FALSE, '', '5', 'success', 100)));

		$this->assertSame(0, $code, $this->err);
		$this->assertSame("ours\n", $this->out);
	}

	/**
	 * Core answers `unavailable` for faults that last too (a receipt Recover cannot read): past a bound of answers in a row the
	 * verb stops, with Core's message, instead of waiting out the whole wait in silence.
	 */
	public function testACoreThatStaysUnavailableEndsTheVerbWithItsMessage(): void
	{
		$code = $this->follow(self::MANUAL, $this->core(self::ok([]), ['status' => 503, 'body' => ['error' => [
			'code' => 'unavailable', 'message' => 'the worker status cannot be read']], 'error' => NULL]), 1000);

		$this->assertSame(1, $code);
		$this->assertStringContainsString('unavailable: the worker status cannot be read', $this->err);
		$this->assertSame(1 + PFB_CLI_UNAVAILABLE_POLLS, count($this->calls), 'the start and the bounded run of unavailable answers');
	}

	/**
	 * Core stamps an Update's start twice: when it admits it, which GetUpdate reports until the worker publishes, and in the
	 * worker's own status. A second can fall between the two: the same Update a second later is still ours.
	 */
	public function testTheSameUpdateStampedASecondLaterIsStillOurs(): void
	{
		$code = $this->follow(self::MANUAL, $this->core(self::ok([]), self::update(TRUE, "a\n", '2', NULL, 100),
			self::update(FALSE, "b\n", '4', 'success', 101)));

		$this->assertSame(0, $code, $this->err);
		$this->assertSame("a\nb\n", $this->out);
	}

	/**
	 * A deprecated verb says so on stderr and in the main log, as the verbs did when their pass logged it: a crontab that
	 * discards the CLI's output still leaves the line in pfblockerng.log. `cron` names the request it is now.
	 */
	public function testADeprecatedVerbSaysSoOnStderrAndInTheMainLog(): void
	{
		$saved = $GLOBALS['pfb']['log'] ?? NULL;
		$GLOBALS['pfb']['log'] = tempnam(sys_get_temp_dir(), 'pfb_cli_log_');
		try {
			pfb_cli_deprecate('cron', function (string $s): void { $this->err .= $s; });
			$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		} finally {
			@unlink($GLOBALS['pfb']['log']);
			$GLOBALS['pfb']['log'] = $saved;
		}

		$this->assertStringContainsString("DEPRECATED: pfblockerng verb 'cron'", $this->err);
		$this->assertStringContainsString('scope=both force=false trigger=manual', $this->err, 'the request cron is now');
		$this->assertStringContainsString("DEPRECATED: pfblockerng verb 'cron'", $log);
	}

	public function testAVerbThatIsNotDeprecatedSaysNothing(): void
	{
		pfb_cli_deprecate('pfb_trigger', function (string $s): void { $this->err .= $s; });

		$this->assertSame('', $this->err);
	}

	public function testACoreLostWhileTheUpdateRunsIsAFailure(): void
	{
		$code = $this->follow(self::MANUAL, $this->core(self::ok([]), self::update(TRUE, '', '0'),
			['status' => 0, 'body' => NULL, 'error' => 'the Core API cannot be reached: Connection refused']));

		$this->assertSame(1, $code);
		$this->assertStringContainsString('Connection refused', $this->err);
	}

	public function testAnUpdateThatOutlivesTheWaitIsAFailureAndKeepsRunning(): void
	{
		$code = $this->follow(self::MANUAL, $this->core(self::ok([]), self::update(TRUE, '', '0')), 3);

		$this->assertSame(1, $code);
		$this->assertStringContainsString('still runs', $this->err);
		$this->assertSame(4, count($this->calls), 'the start and the polls the wait allows, then no more');
	}

	public function testALaterUpdateInPlaceOfOursIsNoResultOfOurs(): void
	{
		$code = $this->follow(self::MANUAL, $this->core(self::ok([]), self::update(TRUE, '', '0', NULL, 100),
			self::update(TRUE, '', '0', NULL, 200)));

		$this->assertSame(1, $code);
		$this->assertStringContainsString('another Update started', $this->err);
	}

	/**
	 * `cron` is deprecated as a CLI verb only (the matrix keeps it): the pass's own `cron` string never warns
	 * (pfb_verb_deprecation_warning(), TriggerAdaptersTest), so the CLI says it for itself.
	 */
	public function testTheDeprecatedCliVerbsSaySo(): void
	{
		$this->assertStringContainsString("DEPRECATED: pfblockerng verb 'cron'", pfb_cli_deprecation_warning('cron'));
		$this->assertSame(pfb_verb_deprecation_warning('update'), pfb_cli_deprecation_warning('update'));
		$this->assertSame('', pfb_cli_deprecation_warning('pfb_trigger'));
		$this->assertSame('', pfb_verb_deprecation_warning('cron'), "the pass's own cron string still never warns");
	}

	/**
	 * The page's block for these verbs is the dispatch and nothing else: no PHP pass (sync_package_pfblockerng(),
	 * pfblockerng_sync_cron()) is reachable from them in-process.
	 */
	public function testThePageDispatchesTheVerbsToCoreAlone(): void
	{
		$page = (string) file_get_contents(__DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertStringContainsString('if (($pfb_update_request = pfb_cli_update_request($argv)) !== NULL) {', $page);
		$this->assertDoesNotMatchRegularExpression('/pfblockerng_sync_cron\(|sync_package_pfblockerng\(/', $page,
			'no verb of the page runs a PHP pass in-process');
	}
}
