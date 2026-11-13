<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3922: Core's dry run (ValidateSettings) runs under the DNS config lock, which the other settings saves wait for
 * (PFB_DNS_CONFIG_LOCK_WAIT). A Core that takes the connection and does not answer must not hold the lock for the 30 s every other
 * call to Core is given: the dry run gets a budget of its own and, past it, is "Core could not judge" -- no messages, so the page's
 * own checks decide.
 *
 * The stalled Core is the settings stand-in with a delay (support/CoreSettingsStandIn.php): it holds the request unanswered until
 * the client hangs up or the delay passes, then refuses. The tests assert outcomes only, never how long a call took.
 */
#[CoversFunction('pfb_core_settings_validate')]
#[CoversFunction('pfb_core_call')]
final class CoreSettingsValidateTimeoutTest extends TestCase
{
	/** Seconds the stalled stand-in holds a request: longer than any budget under test, shorter than pfb_core_call()'s 30 s default. */
	private const STALL = 15;

	private string $dir;
	/** @var ?array{0: resource, 1: array<int, resource>, 2: string} the running stand-in */
	private ?array $standIn = NULL;
	private array $priorConfig;
	private array $priorPfb;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_timeout_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['core_socket'] = "{$this->dir}/api.sock";
		$GLOBALS['pfb']['core_settings_failed'] = "{$this->dir}/core_settings_failed";
	}

	protected function tearDown(): void
	{
		if ($this->standIn !== NULL) {
			[$process, $pipes] = $this->standIn;
			proc_terminate($process);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->dir);
	}

	/** Start the stand-in with $script, holding each request for $delay seconds; returns once it listens. */
	private function core(array $script, int $delay): string
	{
		$socket = "{$this->dir}/api.sock";
		$this->standIn = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreSettingsStandIn.php', $socket, "{$this->dir}/requests",
			json_encode($script, JSON_THROW_ON_ERROR), (string) $delay]);
		$deadline = hrtime(TRUE) + 10_000_000_000;
		for ($out = ''; !str_contains($out, 'ready'); usleep(1000)) {
			$out .= (string) stream_get_contents($this->standIn[1][1]);
			if (hrtime(TRUE) > $deadline) {
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
		}
		return $socket;
	}

	/** @return list<string> the methods the stand-in got, in order */
	private function methods(): array
	{
		$lines = @file("{$this->dir}/requests", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		return array_column(array_map(static fn (string $line): array => json_decode($line, TRUE, 512, JSON_THROW_ON_ERROR), $lines), 'method');
	}

	private static function refusal(): array
	{
		return ['ValidateSettings' => [400, ['error' => ['code' => 'invalid_argument', 'message' => 'the settings are invalid',
			'fieldErrors' => [['field' => 'changes.dns.replyLogging', 'message' => 'refused by the stand-in']]]]]];
	}

	public function testTheDryRunBudgetPlusTheSavesOwnReadAndWriteStaysBelowTheLockWait(): void
	{
		// Given the dry run's budget, which a save spends while it holds the DNS config lock
		$this->assertTrue(defined('PFB_CORE_VALIDATE_TIMEOUT'), 'the dry run has no budget of its own');

		// Then a settings save queued behind it still takes the lock inside its own bounded wait: the budget, plus a second for the
		// holder's fresh read and write
		$this->assertLessThan(PFB_DNS_CONFIG_LOCK_WAIT, constant('PFB_CORE_VALIDATE_TIMEOUT') + 1,
			'the lock wait must outlast a dry run that Core never answers');
	}

	public function testACoreThatStallsLeavesTheDryRunWithoutAVerdict(): void
	{
		// Given a Core that takes the request and answers it, with a refusal, long after the dry run's budget
		$this->core(self::refusal(), self::STALL);

		// When the dry run asks it
		$messages = pfb_core_settings_validate();

		// Then Core could not judge in time: no messages, the page's own checks decide
		$this->assertSame(['ValidateSettings'], $this->methods(), 'positive control: the request reached Core');
		$this->assertSame([], $messages);
	}

	public function testACoreThatAnswersPromptlyStillRefusesTheDryRun(): void
	{
		$this->core(self::refusal(), 0);

		$this->assertSame(['pfBlockerNG Core refused the DNS settings: dns.replyLogging: refused by the stand-in'], pfb_core_settings_validate());
	}

	public function testTheDryRunAsksTheCallerForItsBudgetAndATwoArgumentCallerStillWorks(): void
	{
		$this->assertTrue(defined('PFB_CORE_VALIDATE_TIMEOUT'), 'the dry run has no budget of its own');
		$reply = ['status' => 200, 'body' => [], 'error' => NULL];

		$asked = NULL;
		pfb_core_settings_validate(static function (string $method, array $params, ?string $socket = NULL, int $timeout = 30) use (&$asked, $reply): array {
			$asked = [$method, $timeout];
			return $reply;
		});
		$seen = NULL;
		$messages = pfb_core_settings_validate(static function (string $method, array $params) use (&$seen): array {
			$seen = $method;
			return ['status' => 400, 'body' => ['error' => ['code' => 'invalid_argument', 'message' => 'two arguments']], 'error' => NULL];
		});

		$this->assertSame(['ValidateSettings', constant('PFB_CORE_VALIDATE_TIMEOUT')], $asked);
		$this->assertSame('ValidateSettings', $seen);
		$this->assertSame(['pfBlockerNG Core refused the DNS settings: two arguments'], $messages);
	}

	public function testACallWithATimeoutGivesUpOnAStalledCoreWithStatusZero(): void
	{
		$socket = $this->core([], self::STALL);

		$result = pfb_core_call('GetVersion', [], $socket, 1);

		$this->assertSame(['GetVersion'], $this->methods(), 'positive control: the request reached Core');
		$this->assertSame(0, $result['status']);
		$this->assertNull($result['body']);
		$this->assertStringContainsString('did not answer', (string) $result['error']);
	}

	public function testEveryOtherCallerKeepsTheDefaultOfThirtySeconds(): void
	{
		// pfb_core_call()'s timeout is its last parameter, 30 s unless a caller says otherwise ...
		$timeout = array_values(array_filter((new ReflectionFunction('pfb_core_call'))->getParameters(), static fn (ReflectionParameter $p): bool => $p->getName() === 'timeout'));
		$this->assertCount(1, $timeout, 'pfb_core_call() has no timeout parameter');
		$this->assertSame(30, $timeout[0]->getDefaultValue());

		// ... and the notice to Core (the tick's and the saves') is one of the callers that never says
		$calls = [];
		pfb_core_settings_changed(static function (string $method, array $params = []) use (&$calls): array {
			$calls[] = func_get_args();
			return ['status' => 200, 'body' => [], 'error' => NULL];
		}, TRUE);
		$this->assertSame([['SettingsChanged', []]], $calls);
	}
}
