<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3977 (owner, 2026-11-27): Core's set of temporary DNSBL unlocks is the Alerts page's source of truth. The page reads it
 * (GetTemporaryUnlocks) to show the unlocked domains, and each Lock and Unlock sends Core the whole set with the one domain
 * added or removed (SetTemporaryUnlocks). PHP keeps no store of its own (/tmp/dnsbl_unlock is gone), and a Core that does
 * not take the change, an Update's `conflict` included, is said to the person.
 */
#[CoversFunction('pfb_dnsbl_unlocks')]
#[CoversFunction('pfb_dnsbl_unlocks_set')]
#[CoversFunction('pfb_dnsbl_unlock_toggle')]
final class DnsblCoreUnlocksTest extends TestCase
{
	/**
	 * A fake pfb_core_call(): answers each method from $answers and records the calls.
	 *
	 * @param array<string, array{status: int, body: ?array, error: ?string}> $answers
	 * @return array{0: callable, 1: ArrayObject<int, array{string, array}>}
	 */
	private static function core(array $answers): array
	{
		$calls = new ArrayObject();
		$call = function (string $method, array $params) use ($answers, $calls): array {
			$calls[] = [$method, $params];
			return $answers[$method] ?? ['status' => 200, 'body' => [], 'error' => NULL];
		};
		return [$call, $calls];
	}

	private static function ok(array $body): array
	{
		return ['status' => 200, 'body' => $body, 'error' => NULL];
	}

	public function testTheSetIsReadFromCoreAsDomainToType(): void
	{
		[$call] = self::core(['GetTemporaryUnlocks' => self::ok(['unlocks' => [
			['domain' => 'a.example', 'type' => 'DNSBL'], ['domain' => 'b.example', 'type' => 'Python']]])]);
		$error = 'unset';
		$this->assertSame(['a.example' => 'DNSBL', 'b.example' => 'Python'], pfb_dnsbl_unlocks($call, $error));
		$this->assertNull($error);
	}

	public function testACoreThatDoesNotAnswerGivesNoUnlocksAndSaysWhy(): void
	{
		[$call] = self::core(['GetTemporaryUnlocks' => ['status' => 0, 'body' => NULL, 'error' => 'the Core API is not running']]);
		$error = NULL;
		$this->assertSame([], pfb_dnsbl_unlocks($call, $error));
		$this->assertSame('the Core API is not running', $error);
	}

	public function testAnEntryThatIsNoDomainOrNoWordIsLeftOut(): void
	{
		[$call] = self::core(['GetTemporaryUnlocks' => self::ok(['unlocks' => [
			['domain' => 'a.example', 'type' => 'DNSBL'], ['domain' => '<b>', 'type' => 'DNSBL'], ['domain' => 'c.example', 'type' => 'x y'],
			'junk']])]);
		$error = NULL;
		$this->assertSame(['a.example' => 'DNSBL'], pfb_dnsbl_unlocks($call, $error));
	}

	public function testTheWholeSetIsSentWithItsTypes(): void
	{
		[$call, $calls] = self::core([]);
		$this->assertNull(pfb_dnsbl_unlocks_set($call, ['a.example' => 'DNSBL', 'b.example' => 'Python']));
		$this->assertSame('SetTemporaryUnlocks', $calls[0][0]);
		$this->assertSame([['domain' => 'a.example', 'type' => 'DNSBL'], ['domain' => 'b.example', 'type' => 'Python']],
			$calls[0][1]['unlocks']);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $calls[0][1]['requestId']);
	}

	public function testAnUnlockAddsTheDomainToCoresSet(): void
	{
		[$call, $calls] = self::core(['GetTemporaryUnlocks' => self::ok(['unlocks' => [['domain' => 'a.example', 'type' => 'DNSBL']]])]);
		$this->assertNull(pfb_dnsbl_unlock_toggle($call, 'unlock', 'b.example', 'Python'));
		$this->assertSame([['domain' => 'a.example', 'type' => 'DNSBL'], ['domain' => 'b.example', 'type' => 'Python']],
			$calls[1][1]['unlocks']);
	}

	public function testALockRemovesTheDomainFromCoresSet(): void
	{
		[$call, $calls] = self::core(['GetTemporaryUnlocks' => self::ok(['unlocks' => [
			['domain' => 'a.example', 'type' => 'DNSBL'], ['domain' => 'b.example', 'type' => 'Python']]])]);
		$this->assertNull(pfb_dnsbl_unlock_toggle($call, 'lock', 'a.example', 'DNSBL'));
		$this->assertSame([['domain' => 'b.example', 'type' => 'Python']], $calls[1][1]['unlocks']);
	}

	public function testAConflictIsSaidToThePersonAndNothingElseIsWritten(): void
	{
		[$call, $calls] = self::core([
			'GetTemporaryUnlocks' => self::ok(['unlocks' => []]),
			'SetTemporaryUnlocks' => ['status' => 409, 'body' => ['error' => ['code' => 'conflict',
				'message' => 'an Update is running, and its end re-locks every temporary unlock; ask again after it']], 'error' => NULL],
		]);
		$error = pfb_dnsbl_unlock_toggle($call, 'unlock', 'a.example', 'DNSBL');
		$this->assertStringContainsString('an Update is running', (string) $error);
		$this->assertCount(2, $calls);
	}

	public function testATogglePerformedOnASetCoreCouldNotGiveSendsNothing(): void
	{
		[$call, $calls] = self::core(['GetTemporaryUnlocks' => ['status' => 0, 'body' => NULL, 'error' => 'the Core API is not running']]);
		$this->assertSame('the Core API is not running', pfb_dnsbl_unlock_toggle($call, 'unlock', 'a.example', 'DNSBL'));
		$this->assertCount(1, $calls, 'a set sent without the current one would drop every other unlock');
	}

	public function testATogglePerformedTwiceChangesNothingMore(): void
	{
		[$call, $calls] = self::core(['GetTemporaryUnlocks' => self::ok(['unlocks' => [['domain' => 'a.example', 'type' => 'DNSBL']]])]);
		$this->assertNull(pfb_dnsbl_unlock_toggle($call, 'unlock', 'a.example', 'DNSBL'));
		$this->assertCount(1, $calls, 'an unlock of an unlocked domain sends nothing');
		$this->assertNull(pfb_dnsbl_unlock_toggle($call, 'lock', 'z.example', 'DNSBL'));
		$this->assertCount(2, $calls, 'a lock of a locked domain sends nothing');
	}
}
