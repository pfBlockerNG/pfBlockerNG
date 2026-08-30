<?php

declare(strict_types=1);

namespace PfbRuntimeToggleOwnershipSpy;

use PHPUnit\Framework\Attributes\Depends;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class SpyState
{
	/** @var array<string,mixed> */
	public static array $paths = [];
	/** @var array<string,bool> */
	public static array $registered = [];
	/** @var list<string> */
	public static array $gatewayKeys = [];
	/** @var list<string> */
	public static array $dynamicKeys = [];
}

enum PfbToggle
{
	case On;
	case Off;
}

final class PfbConfig
{
	public static function read(string $key): PfbToggle
	{
		SpyState::$gatewayKeys[] = $key;
		$field = substr($key, strpos($key, '/') + 1);
		return (SpyState::$registered[$field] ?? FALSE) ? PfbToggle::On : PfbToggle::Off;
	}
}

function config_get_path(string $path, mixed $default = NULL): mixed
{
	return SpyState::$paths[$path] ?? $default;
}

function pfb_dnsbl_toggle_enabled(mixed $stored): bool
{
	if (!is_array($stored) || !is_string($stored['field'] ?? NULL) || !is_bool($stored['enabled'] ?? NULL)) {
		throw new RuntimeException('dynamic toggle spy received an unlabelled value');
	}
	SpyState::$dynamicKeys[] = $stored['field'];
	return $stored['enabled'];
}

final class RuntimeToggleOwnershipExecutionTest extends TestCase
{
	private const EXPECTED_FIELDS = [
		'autonot_out', 'autoaddrnot_out', 'autoports_out', 'autoaddr_out',
		'autonot_in', 'autoaddrnot_in', 'autoports_in', 'autoaddr_in',
	];
	/** @var array<string,array{bool,mixed}> */
	private static array $originalGlobals = [];
	/** @var array<string,array{bool,mixed}> */
	private array $savedGlobals = [];


	public static function setUpBeforeClass(): void
	{
		foreach (['pfb', 'pfbarr'] as $name) {
			self::$originalGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}

		$reflection = new \ReflectionFunction('pfb_determine_list_detail');
		$lines = file($reflection->getFileName());
		if (!is_array($lines)) {
			throw new RuntimeException('test bootstrap: failed to read pfb_determine_list_detail source');
		}
		$source = implode('', array_slice(
			$lines,
			$reflection->getStartLine() - 1,
			$reflection->getEndLine() - $reflection->getStartLine() + 1
		));
		eval('namespace ' . __NAMESPACE__ . '; ' . $source);
	}
	protected function setUp(): void
	{
		foreach (['pfb', 'pfbarr'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}


	public function testStaticAndDynamicHomesInvokeOnlyTheirOwner(): void
	{
		$homes = [
			'static settings singleton' => ['pfblockerngdnsblsettings', '0', TRUE],
			'dynamic feed row' => ['pfblockernglistsv4', '3', FALSE],
			'dynamic continent' => ['pfblockerngafrica', '0', FALSE],
		];
		foreach ($homes as $label => [$section, $key, $registered]) {
			$this->seed($section, $key);

			$result = pfb_determine_list_detail('Deny_Both', 'ownership-spy', $section, $key);

			$this->assertSame('/native', $result['folder'], "{$label}: enabled invert must force Native");
			$this->assertSame('on', $result['aaddrnot_in'], "{$label}: enabled invert verdict");
			if ($registered) {
				$this->assertSame(
					array_map(static fn (string $field): string => "dnsbl/{$field}", self::EXPECTED_FIELDS),
					SpyState::$gatewayKeys,
					"{$label}: exact registered gateway keys"
				);
				$this->assertSame([], SpyState::$dynamicKeys, "{$label}: foreign-key adapter must not run");
			} else {
				$this->assertSame([], SpyState::$gatewayKeys, "{$label}: singleton gateway must not run");
				$this->assertSame(self::EXPECTED_FIELDS, SpyState::$dynamicKeys,
					"{$label}: exact dynamic foreign-key adapter fields");
			}
		}
	}
	#[Depends('testStaticAndDynamicHomesInvokeOnlyTheirOwner')]
	public function testGlobalStateIsRestoredForDependentTests(): void
	{
		foreach (self::$originalGlobals as $name => [$existed, $value]) {
			$this->assertSame($existed, array_key_exists($name, $GLOBALS), "{$name}: existence must be restored");
			if ($existed) {
				$this->assertSame($value, $GLOBALS[$name], "{$name}: value must be restored");
			}
		}
	}


	private function seed(string $section, string $key): void
	{
		SpyState::$paths = [];
		SpyState::$registered = [];
		SpyState::$gatewayKeys = [];
		SpyState::$dynamicKeys = [];
		$row = [];
		foreach (['_out', '_in'] as $direction) {
			$row['autoproto' . $direction] = '';
			$row['agateway' . $direction] = 'default';
			$row['aliasports' . $direction] = '';
			$row['aliasaddr' . $direction] = '';
			foreach (['autonot', 'autoaddrnot', 'autoports', 'autoaddr'] as $prefix) {
				$field = $prefix . $direction;
				$enabled = $field === 'autoaddrnot_in';
				$row[$field] = ['field' => $field, 'enabled' => $enabled];
				SpyState::$registered[$field] = $enabled;
			}
		}
		SpyState::$paths["installedpackages/{$section}/config/{$key}"] = $row;
		SpyState::$paths['aliases/alias'] = [];

		$GLOBALS['pfb'] = [
			'denydir' => '/deny',
			'nativedir' => '/native',
			'origdir' => '/orig',
			'reuse' => '',
		];
		$GLOBALS['pfbarr'] = [];
	}
}
