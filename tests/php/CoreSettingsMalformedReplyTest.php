<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3913: a Core reply of the wrong shape (a version-skewed or broken Core) is a failed notice or a Core that cannot judge,
 * never a PHP error: the tick notifies Core first and every page save after its write, so a throw there would abort the tick or
 * turn the save into an HTTP 500.
 */
#[CoversFunction('pfb_core_settings_changed')]
#[CoversFunction('pfb_core_settings_validate')]
final class CoreSettingsMalformedReplyTest extends TestCase
{
	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_malformed_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['core_settings_failed'] = "{$this->dir}/core_settings_failed";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		// A pending failure exists, so the file the notice removes is there: any warning or notice left is the reply handling's
		file_put_contents("{$this->dir}/core_settings_failed", 'earlier');
		set_error_handler(static function (int $errno, string $errstr): never {
			throw new ErrorException($errstr, 0, $errno);
		});
	}

	protected function tearDown(): void
	{
		restore_error_handler();
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->dir);
	}

	/** @return array<string, array{0: array<string, mixed>}> GetSettings bodies a broken Core could send */
	public static function brokenSettingsBodies(): array
	{
		return [
			'no revision'         => [[]],
			'revision as text'    => [['revision' => 'x']],
			'revision a list'     => [['revision' => [1]]],
			'revision null'       => [['revision' => NULL]],
			'revision a float'    => [['revision' => 1.5]],
		];
	}

	/** @param array<string, mixed> $body */
	#[DataProvider('brokenSettingsBodies')]
	public function testABrokenGetSettingsReplyIsACoreThatDiffersNeverAnError(array $body): void
	{
		$told = [];
		$call = static function (string $method, array $params = []) use ($body, &$told): array {
			if ($method === 'GetSettings') {
				return ['status' => 200, 'body' => $body, 'error' => NULL];
			}
			$told[] = $method;
			return ['status' => 200, 'body' => [], 'error' => NULL];
		};

		$reason = pfb_core_settings_changed($call);

		$this->assertSame(['SettingsChanged'], $told, 'a reply without a usable revision is a Core that differs: it is told');
		$this->assertNull($reason);
	}

	/** @return array<string, array{0: mixed}> ValidateSettings `fieldErrors` values a broken Core could send */
	public static function brokenFieldErrors(): array
	{
		return [
			'fieldErrors not a list' => ['nope'],
			'a fault not a map'      => [['x']],
			'field not text'         => [[['field' => ['a'], 'message' => ['b']]]],
		];
	}

	#[DataProvider('brokenFieldErrors')]
	public function testABrokenRefusalStillRefusesWithAMessageNeverAnError(mixed $fieldErrors): void
	{
		$call = static fn(string $method, array $params = []): array => ['status' => 400, 'body' => ['error' => ['code' => 'invalid_argument', 'message' => 'bad', 'fieldErrors' => $fieldErrors]], 'error' => NULL];

		$messages = pfb_core_settings_validate($call);

		$this->assertNotSame([], $messages, 'Core refused: the save is blocked');
		foreach ($messages as $message) {
			$this->assertStringStartsWith('pfBlockerNG Core refused the DNS settings: ', $message);
		}
	}
}
