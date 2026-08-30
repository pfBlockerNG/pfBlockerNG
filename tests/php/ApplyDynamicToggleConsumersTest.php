<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ApplyDynamicToggleConsumersTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	public static function invertStates(): iterable
	{
		yield 'inbound mixed-case On' => ['On', '', TRUE];
		yield 'outbound mixed-case On' => ['', 'On', TRUE];
		yield 'mixed-case OFF' => ['OFF', 'OFF', FALSE];
		yield 'legacy off' => ['off', 'off', FALSE];
		yield 'absent' => [NULL, NULL, FALSE];
	}

	#[DataProvider('invertStates')]
	public function testContinentAndPerRowBranchesUseTheSharedToggleVocabulary(
		mixed $inbound,
		mixed $outbound,
		bool $expected
	): void {
		$source = file_get_contents(self::APPLY);
		if (!is_string($source)) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		[$continentCondition, $rowCondition] = self::nativeOverrideConditions($source);

		$continent_config = [];
		$list = ['action' => 'Deny_Both'];
		if ($inbound !== NULL) {
			$continent_config['autoaddrnot_in'] = $inbound;
			$list['autoaddrnot_in'] = $inbound;
		}
		if ($outbound !== NULL) {
			$continent_config['autoaddrnot_out'] = $outbound;
			$list['autoaddrnot_out'] = $outbound;
		}

		set_error_handler(static function (int $severity, string $message): never {
			throw new ErrorException($message, 0, $severity);
		});
		try {
			$continent = eval('return ' . $continentCondition . ';');
			$row = eval('return ' . $rowCondition . ';');
		} finally {
			restore_error_handler();
		}

		$this->assertSame($expected, $continent, 'per-continent Native override verdict');
		$this->assertSame($expected, $row, 'per-row Native override verdict');
	}

	/** @return array{string,string} */
	private static function nativeOverrideConditions(string $source): array
	{
		$marker = "// Force 'Alias Native' setting to any Alias with 'Advanced Inbound/Outbound -Invert src/dst' settings.";
		$conditions = [];
		$offset = 0;
		for ($occurrence = 0; $occurrence < 2; $occurrence++) {
			$markerStart = strpos($source, $marker, $offset);
			$ifStart = $markerStart === FALSE ? FALSE : strpos($source, 'if (', $markerStart);
			if ($markerStart === FALSE || $ifStart === FALSE) {
				throw new RuntimeException('test bootstrap: failed to find dynamic Native override');
			}
			$conditionStart = $ifStart + strlen('if (');
			$depth = 1;
			$length = strlen($source);
			for ($cursor = $conditionStart; $cursor < $length; $cursor++) {
				if ($source[$cursor] === '(') {
					$depth++;
				} elseif ($source[$cursor] === ')') {
					$depth--;
					if ($depth === 0) {
						$conditions[] = substr($source, $conditionStart, $cursor - $conditionStart);
						$offset = $cursor + 1;
						break;
					}
				}
			}
		}
		if (count($conditions) !== 2) {
			throw new RuntimeException('test bootstrap: failed to extract both dynamic Native overrides');
		}
		return $conditions;
	}
}
