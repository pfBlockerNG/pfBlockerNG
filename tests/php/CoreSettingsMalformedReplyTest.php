<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3913: a Core reply of the wrong shape (a version-skewed or broken Core) is a failed push or a Core that cannot judge,
 * never a PHP error: the push runs first in every tick and after every page save, so a throw there would abort the tick or
 * turn the save into an HTTP 500.
 */
#[CoversFunction('pfb_core_settings_push')]
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
		$GLOBALS['pfb']['core_push_failed'] = "{$this->dir}/core_push_failed";
		$GLOBALS['pfb']['core_pushed'] = "{$this->dir}/core_pushed";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		// The record and a pending failure exist, so the files the push reads and removes are there: any warning or notice
		// left is the reply handling's, and fails the test
		file_put_contents("{$this->dir}/core_pushed", '{}');
		file_put_contents("{$this->dir}/core_push_failed", 'earlier');
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

	/** @return array<string, array{0: mixed}> GetSettings `projections` values a broken Core could send */
	public static function brokenProjections(): array
	{
		return [
			'projections not a list'   => ['nope'],
			'a projection not a map'   => [['x']],
			'value not a map'          => [[['resourceId' => 'settings/dns', 'generation' => 1, 'value' => 'x']]],
		];
	}

	#[DataProvider('brokenProjections')]
	public function testABrokenSettingsReplyIsAFailedPushNeverAnError(mixed $projections): void
	{
		$saved = [];
		$call = static function (string $method, array $params = []) use ($projections, &$saved): array {
			if ($method === 'GetSettings') {
				return ['status' => 200, 'body' => ['initialized' => TRUE, 'revision' => 3, 'projections' => $projections], 'error' => NULL];
			}
			$saved[] = $method;
			return ['status' => 200, 'body' => ['revision' => 4, 'projections' => []], 'error' => NULL];
		};

		$reason = pfb_core_settings_push($call, TRUE);

		// Nothing Core holds could be read, so the values are sent again: Core ends up holding config.xml's values
		$this->assertSame(['SaveSettings'], $saved, 'a reply with no readable settings/dns value is a Core that differs');
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
