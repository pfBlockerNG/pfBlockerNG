<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 enforcement — the PfBlockerNG.Config.RequireConfigGateway sniff.
 *
 * Pins both sides of every decision the sniff makes, driving the real `phpcs`
 * binary over fixture files under tests/phpcs/fixtures/:
 *
 *   VIOLATING (gateway_violation.php): raw config_*_path calls each targeting
 *   a REGISTERED installedpackages/pfblockerng* key — the sniff MUST flag
 *   every one (one config_get_path, one config_set_path, one config_del_path,
 *   one comment-evasion attempt, and the ADR-53 v4suppression key).  Every
 *   branch of the gated-function set is exercised.
 *
 *   COMPLIANT (gateway_compliant.php): foreign/unregistered keys, dynamic
 *   paths, pfSense-core sections, and section-level (not scalar-key) accesses
 *   — the sniff MUST stay entirely silent.  This is the critical before/after
 *   proof: the compliant fixture has the same function shapes as the violating
 *   one; zero findings here proves that the KEY (not the function name or call
 *   pattern) is what triggers the sniff.
 *
 * Covers all decision branches:
 *   - registered gen-section key flagged (config_get_path)
 *   - registered DNSBL-settings key flagged (config_set_path)
 *   - registered SafeSearch key flagged (config_del_path)
 *   - registered v4suppression key flagged (ADR-53, config_get_path)
 *   - foreign section (pfblockerngipsettings/enable_dup) — silent
 *   - v4suppression accessed via PfbConfig (not raw config_*_path) — silent
 *   - dynamic per-row path ($row interpolation) — silent
 *   - pfSense-core section (aliases/alias) — silent
 *   - section-level read (path ends at /config/0, no key) — silent
 *   - dynamic path via concatenation (feed_.$key) — silent
 *   - foreign write (pfblockerngblacklist key) — silent
 *   - widget-* foreign key — silent
 *   - wizard temp section delete — silent
 *
 * If phpcs is not installed the suite SKIPs — CI's php-codesniffer job is the
 * hard gate; never falsely fails in a vendor-less environment.
 */
final class RequireConfigGatewaySniffTest extends TestCase
{
	private const SOURCE = 'PfBlockerNG.Config.RequireConfigGateway.RawRegisteredKeyAccess';

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
	 * Run the custom PfBlockerNG standard over one fixture and return only the
	 * RequireConfigGateway findings (source = self::SOURCE).
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

		$report = json_decode((string) $json, TRUE);
		$this->assertIsArray($report, 'phpcs JSON report must decode');

		$messages = $report['files'][$path]['messages'] ?? [];
		return array_values(array_filter(
			$messages,
			static fn (array $m): bool => ($m['source'] ?? '') === self::SOURCE
		));
	}

	/**
	 * Violating fixture: five raw config_*_path calls on registered keys MUST
	 * each be flagged — one per gated function (get / set / del), one where
	 * an inline comment appears between '(' and the key (comment-evasion guard),
	 * and one on the ADR-53 v4suppression key (proving the sniff picks up a
	 * newly-registered key with no other change).
	 *
	 * Before/after proof: the exact same call patterns appear in the compliant
	 * fixture but on FOREIGN keys — zero findings there proves the registered
	 * key path (not the function name) is what triggers the violation.
	 */
	public function testFlagsRawRegisteredKeyAccess(): void
	{
		$findings = $this->findingsFor('gateway_violation.php');

		$this->assertCount(
			5,
			$findings,
			'exactly five raw registered-key calls must be flagged (get / set / del / comment-evasion / v4suppression)'
		);

		$lines = array_column($findings, 'line');
		sort($lines);

		// Line 21: config_get_path on pfb_keep (gen section)
		// Line 24: config_set_path on pfb_dnsbl (DNSBL settings section)
		// Line 27: config_del_path on safesearch_enable (SafeSearch section)
		// Line 30: config_get_path with inline comment before the key (comment-evasion)
		// Line 38: config_get_path on v4suppression (ADR-53 -- IP settings section)
		$this->assertSame(
			[21, 24, 27, 30, 38],
			$lines,
			'findings must land on the five raw registered-key call lines'
		);

		foreach ($findings as $finding) {
			$this->assertSame(
				self::SOURCE,
				$finding['source'],
				'every finding must carry the RequireConfigGateway source'
			);
		}
	}

	/**
	 * Compliant fixture: foreign/unregistered keys, dynamic paths, section-level
	 * reads, and pfSense-core sections — the sniff MUST produce zero findings.
	 *
	 * This is the critical before/after partner: if the sniff incorrectly flagged
	 * a non-registered key or a dynamic path, a finding would appear here and the
	 * assertion would fail — proving that precision, not mere presence, is tested.
	 */
	public function testCompliantCasesAreClean(): void
	{
		$findings = $this->findingsFor('gateway_compliant.php');
		$this->assertSame(
			[],
			$findings,
			'foreign keys, dynamic paths, section-level reads, and pfSense-core '
			. 'sections must produce no RequireConfigGateway findings'
		);
	}

	/**
	 * Verify the new sniff does NOT interfere with the PFBL-01 fixtures (they
	 * contain config_*_path calls on foreign keys / pfSense-core sections, which
	 * must not be flagged by RequireConfigGateway).
	 */
	public function testDoesNotInterfereWithOtherFixtures(): void
	{
		// PFBL-01 exec violation fixture uses pfSense-core paths; must stay clean.
		$findings = $this->findingsFor('out_of_scope.php');
		$this->assertSame(
			[],
			$findings,
			'PFBL-01 out_of_scope fixture must produce no RequireConfigGateway findings'
		);

		// ADR-28 compliant fixture has no config_*_path calls; must stay clean.
		$findings = $this->findingsFor('bool_compliant.php');
		$this->assertSame(
			[],
			$findings,
			'ADR-28 bool_compliant fixture must produce no RequireConfigGateway findings'
		);
	}
}
