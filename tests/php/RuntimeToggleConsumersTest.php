<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_determine_list_detail')]
final class RuntimeToggleConsumersTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	/** @var array<string,array{bool,mixed}> */
	private array $saved = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb', 'pfbarr'] as $name) {
			$this->saved[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb'] = [
			'denydir' => '/tmp/pfb_deny',
			'nativedir' => '/tmp/pfb_native',
			'origdir' => '/tmp/pfb_orig',
			'reuse' => '',
		];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
	}

	public static function rawToggleStates(): iterable
	{
		yield 'mixed-case On' => ['On', TRUE];
		yield 'mixed-case OFF' => ['OFF', FALSE];
		yield 'legacy off' => ['off', FALSE];
		yield 'absent' => [NULL, FALSE];
	}

	#[DataProvider('rawToggleStates')]
	public function testApplyIpMirrorsUseRegisteredToggleVocabulary(mixed $raw, bool $enabled): void
	{
		$fields = [
			'enable_float' => 'float',
			'enable_dup' => 'dup',
			'enable_agg' => 'agg',
			'enable_log' => 'global_log',
			'killstates' => 'kstates',
		];
		$ipconfig = ['pass_order' => 'order_0', 'autorule_suffix' => ''];
		if ($raw !== NULL) {
			foreach (array_keys($fields) as $field) {
				$ipconfig[$field] = $raw;
			}
		}
		config_set_path('installedpackages/pfblockerngipsettings/config/0', $ipconfig);

		$pfb = ['ipconfig' => $ipconfig];
		$source = self::readSource(self::APPLY);
		$block = self::sourceRange($source, "\$pfb['float']", "\$pfb['kstates']");
		set_error_handler(static function (int $severity, string $message): never {
			throw new ErrorException($message, 0, $severity);
		});
		try {
			eval($block);
		} finally {
			restore_error_handler();
		}

		$expected = $enabled ? PfbToggle::On : PfbToggle::Off;
		foreach ($fields as $field => $mirror) {
			$this->assertSame($expected, $pfb[$mirror], "{$field}: runtime mirror");
		}
	}

	public function testKillstatesBranchRequiresTheOnEnum(): void
	{
		$source = self::readSource(self::APPLY);
		$this->assertSame(1, preg_match(
			'/if \((?<condition>[^\r\n]*\$pfb\[\'kstates\'\][^\r\n]*)\) \{/',
			$source,
			$match
		), 'the live killstates condition must be extractable');

		foreach ([[PfbToggle::On, TRUE], [PfbToggle::Off, FALSE]] as [$toggle, $expected]) {
			$pfb = ['save' => FALSE, 'filter_configure' => FALSE, 'kstates' => $toggle];
			$actual = eval('return ' . $match['condition'] . ';');
			$this->assertSame($expected, $actual, "killstates {$toggle->value} verdict");
		}
	}

	#[DataProvider('rawToggleStates')]
	public function testDatabaseCountryConsumerUsesGatewayVerdict(mixed $raw, bool $enabled): void
	{
		$ipconfig = [];
		if ($raw !== NULL) {
			$ipconfig['database_cc'] = $raw;
		}
		config_set_path('installedpackages/pfblockerngipsettings/config/0', $ipconfig);

		$pfb = ['ipconfig' => $ipconfig];
		$source = self::readSource(self::INC);
		eval(self::sourceRange($source, "\$pfb['cc']", "\$pfb['cc']"));

		$this->assertSame($enabled, $pfb['cc'], 'database_cc runtime verdict');
	}

	public static function advancedToggleMatrix(): iterable
	{
		$homes = [
			'static registered settings' => ['pfblockerngdnsblsettings', '0'],
			'dynamic per-row IPv4 list' => ['pfblockernglistsv4', '3'],
			'dynamic per-continent list' => ['pfblockerngafrica', '0'],
		];
		$fields = [
			'autoaddrnot_in', 'autoports_in', 'autoaddr_in', 'autonot_in',
			'autoaddrnot_out', 'autoports_out', 'autoaddr_out', 'autonot_out',
		];
		foreach ($homes as $home => [$section, $key]) {
			foreach ($fields as $field) {
				foreach (self::rawToggleStates() as $state => [$raw, $enabled]) {
					yield "{$home}: {$field} [{$state}]" => [$section, $key, $field, $raw, $enabled];
				}
			}
		}
	}

	#[DataProvider('advancedToggleMatrix')]
	public function testAdvancedRuleTogglesShareVocabularyAcrossStaticAndDynamicHomes(
		string $section,
		string $key,
		string $field,
		mixed $raw,
		bool $enabled
	): void {
		$row = self::advancedRow();
		if ($raw === NULL) {
			unset($row[$field]);
		} else {
			$row[$field] = $raw;
		}
		config_set_path("installedpackages/{$section}/config/{$key}", $row);
		config_set_path('aliases/alias', self::aliases());

		$result = pfb_determine_list_detail('Deny_Both', 'runtime-toggle', $section, $key);
		$direction = str_ends_with($field, '_in') ? '_in' : '_out';

		if (str_starts_with($field, 'autoaddrnot')) {
			$this->assertSame($enabled ? 'on' : '', $result['aaddrnot' . $direction]);
			$this->assertSame(
				$enabled ? $GLOBALS['pfb']['nativedir'] : $GLOBALS['pfb']['denydir'],
				$result['folder'],
				'Invert source/destination must control the Native override'
			);
		} elseif (str_starts_with($field, 'autonot')) {
			$this->assertSame($enabled ? 'on' : '', $result['anot' . $direction]);
		} elseif (str_starts_with($field, 'autoports')) {
			$this->assertSame($enabled ? 'ports' . $direction : NULL, $result['aports' . $direction] ?? NULL);
		} else {
			$this->assertSame($enabled ? 'address' . $direction : NULL, $result['aaddr' . $direction] ?? NULL);
		}
	}

	/** @return array<string,mixed> */
	private static function advancedRow(): array
	{
		$row = [];
		foreach (['_in', '_out'] as $direction) {
			$row['autoproto' . $direction] = '';
			$row['autonot' . $direction] = '';
			$row['autoaddrnot' . $direction] = '';
			$row['agateway' . $direction] = 'default';
			$row['autoports' . $direction] = '';
			$row['autoaddr' . $direction] = '';
			$row['aliasports' . $direction] = 'ports' . $direction;
			$row['aliasaddr' . $direction] = 'address' . $direction;
		}
		return $row;
	}

	/** @return list<array{name:string,address:string}> */
	private static function aliases(): array
	{
		return [
			['name' => 'ports_in', 'address' => '443'],
			['name' => 'ports_out', 'address' => '443'],
			['name' => 'address_in', 'address' => '192.0.2.1'],
			['name' => 'address_out', 'address' => '192.0.2.2'],
		];
	}

	private static function readSource(string $path): string
	{
		$source = file_get_contents($path);
		if (!is_string($source)) {
			throw new RuntimeException("test bootstrap: failed to read {$path}");
		}
		return $source;
	}

	private static function sourceRange(string $source, string $first, string $last): string
	{
		$start = strpos($source, $first);
		$lastStart = strpos($source, $last, $start === FALSE ? 0 : $start);
		$end = $lastStart === FALSE ? FALSE : strpos($source, "\n", $lastStart);
		if ($start === FALSE || $lastStart === FALSE || $end === FALSE) {
			throw new RuntimeException("test bootstrap: failed to extract {$first} through {$last}");
		}
		return substr($source, $start, $end - $start + 1);
	}
}
