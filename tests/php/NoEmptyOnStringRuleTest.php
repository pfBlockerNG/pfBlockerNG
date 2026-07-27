<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1787 — the custom PHPStan rule (PfBlockerNG\PHPStan\NoEmptyOnStringRule)
 * that mechanically bans empty() on statically-string-typed operands, because
 * empty('0') is TRUE and a valid "0" value reads as absent (issue #1707 class).
 *
 * A linter that never fires is worthless, so this suite pins BOTH sides of the
 * rule's decision, driving the real `phpstan` binary (the repo config, so the
 * exact CI wiring) over fixture files under tests/phpstan/fixtures/:
 *
 *   - it FLAGS empty() on string, ?string, and string|false operands (the
 *     null/false wrappers still lie about '0');
 *   - it STAYS SILENT for empty() on arrays and untyped/mixed operands (the
 *     legacy config-read idiom), and for the honest `$value === ''` check.
 *
 * The rule is dev-only tooling; if phpstan is not installed the suite SKIPs
 * (CI's phpstan job is the hard gate), it never falsely fails.
 */
final class NoEmptyOnStringRuleTest extends TestCase
{
	private const IDENTIFIER = 'pfBlockerNG.emptyOnString';

	/** @var array<string, list<array{line: int, identifier: string}>>|null keyed by fixture basename */
	private static ?array $findings = null;

	private static function repoRoot(): string
	{
		return dirname(__DIR__, 2);
	}

	protected function setUp(): void
	{
		if (!is_file(self::repoRoot() . '/vendor/bin/phpstan')) {
			$this->markTestSkipped('phpstan not installed (composer install) — CI phpstan job is the gate.');
		}
	}

	/**
	 * One shared phpstan run over both fixtures (analysis is the slow part),
	 * returning per-file emptyOnString findings.
	 *
	 * @return array<string, list<array{line: int, identifier: string}>>
	 */
	private function findings(): array
	{
		if (self::$findings !== null) {
			return self::$findings;
		}
		$root = self::repoRoot();
		$cmd = escapeshellarg($root . '/vendor/bin/phpstan')
			. ' analyse --no-progress --memory-limit=1G --error-format=json'
			. ' -c ' . escapeshellarg($root . '/phpstan.neon')
			. ' ' . escapeshellarg($root . '/tests/phpstan/fixtures')
			. ' 2>/dev/null';
		exec($cmd, $output, $status);
		$report = json_decode(implode("\n", $output), true);
		$this->assertIsArray($report, 'phpstan produced no parseable JSON report');

		$byFile = [];
		foreach (($report['files'] ?? []) as $path => $file) {
			foreach (($file['messages'] ?? []) as $message) {
				if (($message['identifier'] ?? '') !== self::IDENTIFIER) {
					continue;
				}
				$byFile[basename((string) $path)][] = [
					'line'       => (int) $message['line'],
					'identifier' => (string) $message['identifier'],
				];
			}
		}
		return self::$findings = $byFile;
	}

	public function testFlagsEmptyOnStringTypedOperands(): void
	{
		$flagged = array_column($this->findings()['empty_on_string_violation.php'] ?? [], 'line');
		sort($flagged);
		// string / ?string / string|false, plus (issue #1792 N1) string|int and
		// a literal-string union — one finding per fixture function.
		$this->assertSame([8, 12, 17, 22, 27], $flagged);
	}

	public function testStaysSilentOnArraysUntypedAndExactComparison(): void
	{
		$this->assertArrayNotHasKey(
			'empty_on_string_compliant.php',
			$this->findings(),
			'rule must not fire on array/untyped operands or exact comparisons'
		);
	}
}
