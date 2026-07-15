<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1285 — blacklist enable/lang autosubmit handlers must tolerate arrays.
 *
 * The page cannot be required off-appliance, so both standalone handlers are
 * eval-extracted verbatim from the real source using anchors stable across the
 * guard change.
 */
final class BlacklistPostGuardTest extends TestCase
{
	private array $savedPost = [];
	private mixed $savedPfb = null;
	private mixed $savedConfig = null;
	private bool $hadConfig = FALSE;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_blacklist.php'
		);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_blacklist.php');
		}

		if (!function_exists('pfb_blacklist_oracle_enable')) {
			if (!preg_match(
				'/\n\t(if \(isset\(\$_POST\[\'blacklist_enable\'\]\)\) \{.*?\n\t\})'
				. '\n\n\tif \(isset\(\$_POST\[\'blacklist_lang\'\]\)\)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: blacklist_enable handler not found');
			}
			eval(
				'function pfb_blacklist_oracle_enable(): array {'
				. ' global $pfb; $config_mod = FALSE;'
				. ' $options_blacklist_enable = [\'Disable\' => \'Disable\', \'Enable\' => \'Enable\'];'
				. $m[1]
				. ' return [\'config_mod\' => $config_mod, \'bconfig\' => $pfb[\'bconfig\'], \'post\' => $_POST]; }'
			);
		}

		if (!function_exists('pfb_blacklist_oracle_lang')) {
			if (!preg_match(
				'/\n\t(if \(isset\(\$_POST\[\'blacklist_lang\'\]\)\) \{.*?\n\t\})'
				. '\n\n\tif \(isset\(\$_POST\[\'save\'\]\)\)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: blacklist_lang handler not found');
			}
			eval(
				'function pfb_blacklist_oracle_lang(): array {'
				. ' global $pfb; $config_mod = FALSE;'
				. ' $options_blacklist_lang = [\'EN\' => \'English\', \'DE\' => \'German\', \'FR\' => \'French\','
				. ' \'IT\' => \'Italian\', \'NL\' => \'Dutch\', \'PT\' => \'Portuguese\','
				. ' \'ES\' => \'Spanish\', \'RU\' => \'Russian\'];'
				. $m[1]
				. ' return [\'config_mod\' => $config_mod, \'bconfig\' => $pfb[\'bconfig\'], \'post\' => $_POST]; }'
			);
		}
	}

	protected function setUp(): void
	{
		global $pfb;
		$this->savedPost  = $_POST;
		$this->savedPfb   = $pfb ?? null;
		$this->hadConfig  = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? null;

		$_POST = [];
		$pfb = ['bconfig' => [
			'blacklist_enable' => 'enable-sentinel',
			'blacklist_lang'   => 'lang-sentinel',
		]];
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		global $pfb;
		$_POST = $this->savedPost;
		$pfb   = $this->savedPfb;
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
	}

	public static function fieldProvider(): array
	{
		return [
			'blacklist_enable' => [
				'blacklist_enable',
				'pfb_blacklist_oracle_enable',
				'Disable',
				'Enable',
				'enable-sentinel',
			],
			'blacklist_lang' => [
				'blacklist_lang',
				'pfb_blacklist_oracle_lang',
				'EN',
				'DE',
				'lang-sentinel',
			],
		];
	}

	public static function arrayValueProvider(): array
	{
		$rows = [];
		foreach (self::fieldProvider() as $name => $field) {
			foreach ([
				'flat'   => ['crafted'],
				'empty'  => [],
				'nested' => ['outer' => ['inner' => 'crafted']],
			] as $shape => $value) {
				$rows["{$name}-{$shape}"] = [...$field, $value];
			}
		}
		return $rows;
	}

	private function runOracle(string $oracle, string $field): array
	{
		try {
			return $oracle();
		} catch (\TypeError $e) {
			$this->fail("an array {$field} value must not TypeError: " . $e->getMessage());
		}
	}

	private function configPath(string $field): string
	{
		return "installedpackages/pfblockerngblacklist/{$field}";
	}

	#[DataProvider('arrayValueProvider')]
	public function testArrayValuesNormalizeToExistingDefaultWithoutThrowing(
		string $field,
		string $oracle,
		string $default,
		string $valid,
		string $sentinel,
		array $value
	): void {
		$_POST[$field] = $value;
		$result = $this->runOracle($oracle, $field);

		$this->assertTrue($result['config_mod'], "array {$field} must ride the existing autosubmit write path");
		$this->assertSame($default, $_POST[$field], "array {$field} must normalize to its existing default");
		$this->assertSame($default, $result['bconfig'][$field]);
		$this->assertSame($default, config_get_path($this->configPath($field)));
	}

	#[DataProvider('fieldProvider')]
	public function testValidScalarIsPersistedUnchanged(
		string $field,
		string $oracle,
		string $default,
		string $valid,
		string $sentinel
	): void {
		$_POST[$field] = $valid;
		$result = $this->runOracle($oracle, $field);

		$this->assertSame($valid, $_POST[$field]);
		$this->assertSame($valid, $result['bconfig'][$field]);
		$this->assertSame($valid, config_get_path($this->configPath($field)));
	}

	#[DataProvider('fieldProvider')]
	public function testUnknownScalarNormalizesToExistingDefault(
		string $field,
		string $oracle,
		string $default,
		string $valid,
		string $sentinel
	): void {
		$_POST[$field] = 'unknown-value';
		$result = $this->runOracle($oracle, $field);

		$this->assertSame($default, $_POST[$field]);
		$this->assertSame($default, $result['bconfig'][$field]);
		$this->assertSame($default, config_get_path($this->configPath($field)));
	}

	#[DataProvider('fieldProvider')]
	public function testMissingFieldIsUntouchedAndNotWritten(
		string $field,
		string $oracle,
		string $default,
		string $valid,
		string $sentinel
	): void {
		unset($_POST[$field]);
		$result = $this->runOracle($oracle, $field);

		$this->assertFalse($result['config_mod'], "missing {$field} must not mark config modified");
		$this->assertArrayNotHasKey($field, $_POST);
		$this->assertSame($sentinel, $result['bconfig'][$field], "missing {$field} must leave bconfig untouched");
		$this->assertNull(config_get_path($this->configPath($field)), "missing {$field} must not write config");
	}
}
