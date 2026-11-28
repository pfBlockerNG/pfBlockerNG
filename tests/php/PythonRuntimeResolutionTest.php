<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Pins the appliance Python runtime boundary used by DNSBL validation.
 * The package dependency is authoritative: py311/python311 selects the matching versioned interpreter through the shared wrapper, while
 * module dependencies and malformed or ambiguous versions must never be treated as it.
 */
#[CoversFunction('pfb_python_interpreter')]
final class PythonRuntimeResolutionTest extends TestCase
{
	/** @return array<string, array{array<int, string|int>}> */
	public static function supportedDependencyProvider(): array
	{
		return [
			'py311' => [['py311']],
			'python311' => [['python311']],
			'whitespace is trimmed' => [['  py311  ']],
			'duplicate aliases collapse' => [['py311', 'python311', 'py311-sqlite3']],
			'non-string array member is ignored' => [[123, 'py311']],
			'module dependency is not interpreter' => [['py311-sqlite3']],
		];
	}

	#[DataProvider('supportedDependencyProvider')]
	public function testInterpreterDerivesFromExactDependency(array $dependencies): void
	{
		$expected = $dependencies === ['py311-sqlite3'] ? '' : '/usr/local/bin/' . 'python3.11';
		$this->assertSame($expected, pfb_python_interpreter($dependencies), json_encode($dependencies));
	}

	/** @return array<string, array{array<int, string>}> */
	public static function unsupportedDependencyProvider(): array
	{
		return [
			'absent' => [[]],
			'ambiguous versions' => [['py311', 'python312']],
			'malformed nonnumeric version' => [['python3x']],
			'python dotted name is not package dependency' => [['python3.11']],
			'one digit version is rejected' => [['py3']],
			'whitespace-only dependency is ignored' => [['   ']],
		];
	}

	#[DataProvider('unsupportedDependencyProvider')]
	public function testInterpreterRejectsAbsentAmbiguousAndMalformedDependencies(array $dependencies): void
	{
		$this->assertSame('', pfb_python_interpreter($dependencies), json_encode($dependencies));
	}
}
