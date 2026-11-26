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
 */
#[CoversFunction('pfb_cli_update_request')]
#[CoversFunction('pfb_cli_update_run')]
#[CoversFunction('pfb_cli_deprecation_warning')]
final class CliUpdateVerbsTest extends TestCase
{
	/** @var list<array{0: string, 1: array}> every call the fake Core got: method, params */
	private array $calls = [];
	private string $out = '';
	private string $err = '';

	/** @return array<string, array{0: list<string>, 1: ?array}> */
	public static function verbs(): array
	{
		return [
			'cron (deprecated)'           => [['cron'], ['trigger' => 'retry']],
			'update'                      => [['update'], ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']],
			'updateip'                    => [['updateip'], ['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse']],
			'updatednsbl'                 => [['updatednsbl'], ['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'parse']],
			'pfb_trigger defaults'        => [['pfb_trigger'], ['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']],
			'pfb_trigger forced reload'   => [['pfb_trigger', 'scope=ip', 'force=true', 'trigger=force'],
				['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse']],
			'pfb_trigger manual dnsbl'    => [['pfb_trigger', 'scope=dnsbl', 'force=false', 'trigger=manual'],
				['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'none']],
			'pfb_trigger cron'            => [['pfb_trigger', 'scope=dnsbl', 'force=false', 'trigger=cron'], ['trigger' => 'retry']],
			'pfb_trigger unknown values'  => [['pfb_trigger', 'scope=all', 'trigger=later'],
				['trigger' => 'manual', 'scope' => 'both', 'force' => 'none']],
			'forcecheck'                  => [['forcecheck', 'scope=ip'], ['trigger' => 'manual', 'scope' => 'ip', 'force' => 'download']],
			'forcecheck with the hashes'  => [['forcecheck', 'scope=dnsbl', 'hashes=true'],
				['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'both']],
			'forcecheck unknown scope'    => [['forcecheck', 'scope=x'], ['trigger' => 'manual', 'scope' => 'both', 'force' => 'download']],
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

	private function follow(array $request, callable $core, int $polls = 10): int
	{
		return pfb_cli_update_run($request, $core,
			function (string $s): void { $this->out .= $s; },
			function (string $s): void { $this->err .= $s; },
			static function (): void {}, $polls);
	}

	public function testTheUpdateIsStartedThenFollowedToItsEndWithItsLog(): void
	{
		$code = $this->follow(['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse'], $this->core(self::ok([]),
			self::update(TRUE, "first\n", '6'), self::update(TRUE, '', '6'), self::update(FALSE, "last\n", '11', 'success')));

		$this->assertSame(0, $code);
		$this->assertSame("first\nlast\n", $this->out, 'the Update log goes to stdout, each chunk once');
		[$method, $params] = $this->calls[0];
		$this->assertSame('StartUpdate', $method);
		$this->assertSame(['trigger' => 'manual', 'scope' => 'ip', 'force' => 'parse'], array_diff_key($params, ['requestId' => 1]));
		$this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $params['requestId']);
		$this->assertSame([['GetUpdate', []], ['GetUpdate', ['after' => '6']], ['GetUpdate', ['after' => '6']]],
			array_slice($this->calls, 1), 'the log is read from the cursor Core gave');
	}

	/** @return array<string, array{0: string, 1: int}> */
	public static function results(): array
	{
		return ['failed' => ['failed', 1], 'skipped (the pass was deferred)' => ['skipped', PFB_EXIT_LOCKED]];
	}

	#[DataProvider('results')]
	public function testTheExitStatusIsTheUpdatesResult(string $result, int $code): void
	{
		$this->assertSame($code, $this->follow(['trigger' => 'retry'], $this->core(self::ok([]), self::update(FALSE, '', '0', $result))));
	}

	public function testAnUpdateThatRunsAlreadyIsAConflictReportedAndNothingQueued(): void
	{
		$code = $this->follow(['trigger' => 'retry'], $this->core(['status' => 409, 'body' => ['error' => ['code' => 'conflict',
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
		$this->assertSame(1, $this->follow(['trigger' => 'retry'], $this->core($answer)));
		$this->assertStringStartsWith('pfBlockerNG Core did not start the Update: ', $this->err);
		$this->assertCount(1, $this->calls);
	}

	public function testACoreLostWhileTheUpdateRunsIsAFailure(): void
	{
		$code = $this->follow(['trigger' => 'retry'], $this->core(self::ok([]), self::update(TRUE, '', '0'),
			['status' => 0, 'body' => NULL, 'error' => 'the Core API cannot be reached: Connection refused']));

		$this->assertSame(1, $code);
		$this->assertStringContainsString('Connection refused', $this->err);
	}

	public function testAnUpdateThatOutlivesTheWaitIsAFailureAndKeepsRunning(): void
	{
		$code = $this->follow(['trigger' => 'retry'], $this->core(self::ok([]), self::update(TRUE, '', '0')), 3);

		$this->assertSame(1, $code);
		$this->assertStringContainsString('still runs', $this->err);
		$this->assertSame(4, count($this->calls), 'the start and the polls the wait allows, then no more');
	}

	public function testALaterUpdateInPlaceOfOursIsNoResultOfOurs(): void
	{
		$code = $this->follow(['trigger' => 'retry'], $this->core(self::ok([]), self::update(TRUE, '', '0', NULL, 100),
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
