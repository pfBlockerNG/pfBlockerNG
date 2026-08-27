<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-28 item 5 — the PfBlockerNG.CodeStyle.UppercaseBooleanLiteral sniff.
 *
 * Pins both sides of every decision the sniff makes, driving the real `phpcs`
 * binary over fixture files under tests/phpcs/fixtures/:
 *
 *   - COMPLIANT (bool_compliant.php): uppercase TRUE/FALSE values, a
 *     "string|false" return type, and a 'true' string literal — sniff MUST
 *     stay silent for all of them (proves the type-decl exclusion, proves
 *     strings are not touched, proves correct literals pass).
 *
 *   - VIOLATING (bool_violation.php): lowercase "true", "false", and
 *     PascalCase "False" value literals — sniff MUST flag exactly those three
 *     lines; the "string|false" return type on a different line MUST NOT be
 *     flagged (the before/after proof: if the type-decl exclusion were broken,
 *     that line would appear in the findings and the assertion would fail).
 *
 * Covers every branch: uppercase (ok), lowercase (flagged), PascalCase
 * (flagged), type-declaration position (excluded), string literal (excluded).
 *
 * If phpcs is not installed the suite SKIPs — CI's php-codesniffer job is the
 * hard gate; never falsely fails in a vendor-less environment.
 */
final class UppercaseBooleanLiteralSniffTest extends TestCase
{
	private const SOURCE = 'PfBlockerNG.CodeStyle.UppercaseBooleanLiteral.Found';

	private static function repoRoot(): string
	{
		return dirname(__DIR__, 2);
	}

	private static function phpcsBin(): string
	{
		return self::repoRoot() . '/vendor/bin/phpcs';
	}

	protected function setUp(): void
	{
		if (!is_file(self::phpcsBin())) {
			$this->markTestSkipped('phpcs not installed (composer install) — CI php-codesniffer job is the gate.');
		}
	}

	/**
	 * Run the custom standard over one fixture and return only the
	 * UppercaseBooleanLiteral findings (source = self::SOURCE).
	 *
	 * @return list<array<string, mixed>>
	 */
	private function findingsFor(string $fixture): array
	{
		$root = self::repoRoot();
		$path = $root . '/tests/phpcs/fixtures/' . $fixture;
		$this->assertFileExists($path, "fixture {$fixture} must exist");

		$cmd = escapeshellarg(self::phpcsBin())
			. ' --standard=' . escapeshellarg($root . '/tests/phpcs/PfBlockerNG/ruleset.xml')
			. ' --report=json'
			. ' ' . escapeshellarg($path)
			. ' 2>/dev/null';

		$json = shell_exec($cmd);
		$this->assertIsString($json, 'phpcs must produce JSON output');

		$report = json_decode((string) $json, true);
		$this->assertIsArray($report, 'phpcs JSON report must decode');

		$messages = $report['files'][$path]['messages'] ?? [];
		return array_values(array_filter(
			$messages,
			static fn (array $m): bool => ($m['source'] ?? '') === self::SOURCE
		));
	}

	/**
	 * Compliant fixture: uppercase value literals + type-decl "string|false"
	 * + string literal 'true' — the sniff MUST stay silent for all of them.
	 *
	 * The type-decl line is the critical branch: if the sniff incorrectly
	 * flagged "false" in "string|false" it would show up here and the
	 * empty-findings assertion would fail.
	 */
	public function testCompliantFileIsClean(): void
	{
		$findings = $this->findingsFor('bool_compliant.php');
		$this->assertSame(
			[],
			$findings,
			'uppercase value literals, type-decl "string|false", and string literals must produce no findings'
		);
	}

	/**
	 * Violating fixture: lowercase "true" / "false" / PascalCase "False" as
	 * VALUE literals MUST each be flagged; the "string|false" TYPE declaration
	 * on a different line MUST NOT appear in the findings.
	 *
	 * Before/after proof: the fixture has a clean "string|false" line; if it
	 * appeared in the findings the line-set assertion would fail, proving the
	 * type-decl exclusion is working.
	 */
	public function testViolatingFileFindings(): void
	{
		$findings = $this->findingsFor('bool_violation.php');

		$lines = array_column($findings, 'line');
		sort($lines);

		// Exactly lines 17 (true), 18 (false), 19 (False) flagged; line 24
		// ("string|false" return type) must NOT appear.
		$this->assertSame(
			[17, 18, 19],
			$lines,
			'exactly the three lowercase/PascalCase value literals must be flagged; '
			. 'the "string|false" type declaration must not appear in the findings'
		);

		// Each finding carries the correct sniff source.
		foreach ($findings as $finding) {
			$this->assertSame(self::SOURCE, $finding['source']);
		}
	}

	/**
	 * Verify the sniff does NOT flag the existing PFBL-01 violation fixtures
	 * (they contain uppercase TRUE/FALSE and no boolean-literal violations) so
	 * the two sniffs don't interfere.
	 */
	public function testDoesNotInterfereWithPfbl01Fixtures(): void
	{
		// Out-of-scope fixture uses exec() without a validator: no bool literals.
		$findings = $this->findingsFor('out_of_scope.php');
		$this->assertSame([], $findings, 'PFBL-01 out_of_scope fixture must produce no UppercaseBooleanLiteral findings');

		// Compliant PFBL-01 fixture uses uppercase TRUE/FALSE: must be clean.
		$findings = $this->findingsFor('compliant_filtered.php');
		$this->assertSame([], $findings, 'PFBL-01 compliant_filtered fixture must produce no UppercaseBooleanLiteral findings');
	}
}
