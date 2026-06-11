<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * PFBL-01 Requirement 4 — the custom PHP_CodeSniffer rule (PfBlockerNG.Validation.
 * RequirePfbFilter) that mechanically enforces the input-validation contract.
 *
 * A linter that never fires is worthless, so this suite pins BOTH sides of every
 * decision the sniff makes, driving the real `phpcs` binary over fixture files
 * under tests/phpcs/fixtures/:
 *
 *   - it FLAGS an unfiltered exec / json_encode / path sink inside an in-scope
 *     (allow-listed) function — one test per sink class;
 *   - it STAYS SILENT when a semantic-validation call precedes the sink (the
 *     before/after partner of the exec case — same sink, the lone difference is the
 *     leading pfb_filter(), so green proves the validator is what suppresses it);
 *   - it STAYS SILENT for a function NOT on the allow-list (the ADR's legacy
 *     carve-out: scope is an explicit list, never a blanket scan).
 *
 * The sniff is dev-only tooling; if phpcs is not installed the suite SKIPs (CI's
 * php-codesniffer job is the hard gate), it never falsely fails.
 */
final class RequirePfbFilterSniffTest extends TestCase
{
	private const SOURCE = 'PfBlockerNG.Validation.RequirePfbFilter.MissingFilter';

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
	 * Run the custom standard over one fixture and return the MissingFilter findings.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function findingsFor(string $fixture): array
	{
		$root    = self::repoRoot();
		$path    = $root . '/tests/phpcs/fixtures/' . $fixture;
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

	public function testFlagsExecSinkWithoutValidator(): void
	{
		// When: an in-scope function reaches exec() with no preceding validator.
		// Then: the sniff reports at least one MissingFilter error.
		$findings = $this->findingsFor('violation_exec.php');
		$this->assertNotEmpty($findings, 'an unfiltered exec sink in an in-scope function must be flagged');
	}

	public function testFlagsManifestSinkWithoutValidator(): void
	{
		$findings = $this->findingsFor('violation_json.php');
		$this->assertNotEmpty($findings, 'an unfiltered json_encode manifest sink must be flagged');
	}

	public function testFlagsNamespaceQualifiedExecSink(): void
	{
		// Regression: a fully-qualified \exec() (one T_NAME_FULLY_QUALIFIED token)
		// bypassed the T_STRING-only match. The bare name must be resolved so a
		// namespace-qualified sink is still flagged.
		$findings = $this->findingsFor('violation_namespaced.php');
		$this->assertNotEmpty($findings, 'a namespace-qualified exec sink must still be flagged');
	}

	public function testFlagsPathBuildWithoutValidator(): void
	{
		$findings = $this->findingsFor('violation_path.php');
		$this->assertNotEmpty($findings, 'an unfiltered interpolated path build must be flagged');
	}

	public function testValidatorBeforeSinkPasses(): void
	{
		// Before/after partner of testFlagsExecSinkWithoutValidator: identical exec
		// sink, the only added code is the leading pfb_filter() — so zero findings
		// proves the validator presence (not some unrelated detail) clears it.
		$findings = $this->findingsFor('compliant_filtered.php');
		$this->assertSame([], $findings, 'a validator preceding the sink must clear the finding');
	}

	public function testOutOfScopeFunctionIsNotFlagged(): void
	{
		// A raw exec in a non-allow-listed function must NOT be flagged — encodes the
		// ADR's "legacy code paths are out of scope" carve-out.
		$findings = $this->findingsFor('out_of_scope.php');
		$this->assertSame([], $findings, 'a function outside the in-scope allow-list must never be flagged');
	}
}
