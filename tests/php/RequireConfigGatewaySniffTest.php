<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 / issue #1895 enforcement — the PfBlockerNG.Config.RequireConfigGateway
 * sniff. It carries two independent checks; this suite pins both.
 *
 * CHECK 1 — RawRegisteredKeyAccess (ADR-29). Pins both sides of every decision
 * the check makes, driving the real `phpcs` binary over fixture files under
 * tests/phpcs/fixtures/:
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
 * CHECK 2 — SystemWriteInWww (issue #1895). Fixtures live at path-dependent
 * locations under tests/phpcs/fixtures/usr/local/... so the sniff's
 * "/usr/local/www/" file-path substring check has real substrings to match
 * against, mirroring the real src/usr/local/www/ tree layout:
 *
 *   tests/phpcs/fixtures/usr/local/www/system_write_violation.php — a www/
 *   path calling PfbConfig::writeSystem() / writeSectionSystem() /
 *   writeSectionRawSystem() (issue #1921), a case-varied
 *   (pfbconfig::WRITESYSTEM()) call, and three comment-interleaved shapes (a
 *   comment between the class name and '::', one between '::' and the method
 *   name, and one between the method name and '(') — all seven MUST be flagged.
 *
 *   tests/phpcs/fixtures/usr/local/www/system_write_compliant.php — the same
 *   www/ path, but PfbConfig::write()/writeSection() (different method),
 *   SomethingElse::writeSystem() (different class), and a comment/string
 *   mentioning "PfbConfig::writeSystem" — all MUST stay silent.
 *
 *   tests/phpcs/fixtures/usr/local/pkg/pfblockerng/system_write_compliant.php
 *   — a non-www path with the identical writeSystem()/writeSectionSystem()
 *   call shapes as the violating fixture — MUST stay silent (the legitimate
 *   system-caller use case the methods exist for).
 *
 * A final real-tree assertion runs the sniff over the actual
 * src/usr/local/www/ directory and asserts zero SystemWriteInWww findings —
 * the confinement this check exists to enforce holds today.
 *
 * If phpcs is not installed the suite SKIPs — CI's php-codesniffer job is the
 * hard gate; never falsely fails in a vendor-less environment.
 */
final class RequireConfigGatewaySniffTest extends TestCase
{
	private const SOURCE = 'PfBlockerNG.Config.RequireConfigGateway.RawRegisteredKeyAccess';
	private const SOURCE_SYSTEM_WRITE = 'PfBlockerNG.Config.RequireConfigGateway.SystemWriteInWww';

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
	 * RequireConfigGateway findings matching $source (default: self::SOURCE,
	 * the CHECK 1 RawRegisteredKeyAccess code).
	 *
	 * @return list<array<string, mixed>>
	 */
	private function findingsFor(string $fixture, string $source = self::SOURCE): array
	{
		$path = self::repoRoot() . '/tests/phpcs/fixtures/' . $fixture;
		$this->assertFileExists($path, "fixture {$fixture} must exist");

		return $this->findingsForPath($path, $source);
	}

	/**
	 * Run the custom PfBlockerNG standard over an arbitrary file or directory
	 * (absolute path) and return the decoded phpcs JSON report, unfiltered.
	 *
	 * Split out of findingsForPath() so the real-tree assertion (below) can
	 * additionally check how many files phpcs actually processed -- a
	 * zero-file report would make a zero-findings assertion vacuously true.
	 *
	 * @return array<string, mixed>
	 */
	private function runPhpcsJson(string $path): array
	{
		$root = self::repoRoot();
		$this->assertFileExists($path, "{$path} must exist");

		$cmd = escapeshellarg(self::phpcsBin())
			. ' --standard=' . escapeshellarg($root . '/tests/phpcs/PfBlockerNG/ruleset.xml')
			. ' --extensions=php,inc'
			. ' --report=json'
			. ' ' . escapeshellarg($path)
			. ' 2>/dev/null';

		$json = shell_exec($cmd);
		$this->assertIsString($json, 'phpcs must produce JSON output');

		$report = json_decode((string) $json, TRUE);
		$this->assertIsArray($report, 'phpcs JSON report must decode');

		return $report;
	}

	/**
	 * Filter a decoded phpcs JSON report (see runPhpcsJson()) down to the
	 * findings matching $source, across every file phpcs reports on.
	 *
	 * @param  array<string, mixed> $report
	 * @return list<array<string, mixed>>
	 */
	private function extractFindings(array $report, string $source): array
	{
		$findings = [];
		foreach (($report['files'] ?? []) as $file => $data) {
			$messages = $data['messages'] ?? [];
			foreach ($messages as $message) {
				if (($message['source'] ?? '') === $source) {
					$findings[] = $message + ['file' => $file];
				}
			}
		}

		return $findings;
	}

	/**
	 * Run the custom PfBlockerNG standard over an arbitrary file or directory
	 * (absolute path) and return only the findings matching $source, across
	 * every file phpcs reports on. Used for CHECK 2's real-tree assertion,
	 * where the fixture-path convention of findingsFor() does not apply.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function findingsForPath(string $path, string $source): array
	{
		return $this->extractFindings($this->runPhpcsJson($path), $source);
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

	/**
	 * CHECK 2 — issue #1895 SystemWriteInWww, violating fixture.
	 *
	 * tests/phpcs/fixtures/usr/local/www/system_write_violation.php lives at a
	 * path containing "/usr/local/www/" and calls PfbConfig::writeSystem() /
	 * PfbConfig::writeSectionSystem() / PfbConfig::writeSectionRawSystem()
	 * (issue #1921), plus a case-varied pfbconfig::WRITESYSTEM() call — every
	 * one MUST be flagged.
	 */
	public function testFlagsSystemWriteInWww(): void
	{
		$findings = $this->findingsFor(
			'usr/local/www/system_write_violation.php',
			self::SOURCE_SYSTEM_WRITE
		);

		$this->assertCount(
			7,
			$findings,
			'writeSystem(), writeSectionSystem(), writeSectionRawSystem(), the case-varied '
			. 'call, and all three comment-interleaved shapes must all be flagged'
		);

		$lines = array_column($findings, 'line');
		sort($lines);

		// Line 20: PfbConfig::writeSystem(...)
		// Line 26: PfbConfig::writeSectionSystem(...)
		// Line 32: PfbConfig::writeSectionRawSystem(...) (issue #1921)
		// Line 39: pfbconfig::WRITESYSTEM(...) (case variance)
		// Line 46: PfbConfig/*x*/::writeSystem(...) (comment before '::')
		// Line 53: PfbConfig::/*x*/writeSystem(...) (comment after '::')
		// Line 60: PfbConfig::writeSystem/*x*/(...) (comment before '(')
		$this->assertSame(
			[20, 26, 32, 39, 46, 53, 60],
			$lines,
			'findings must land on all seven static system-write call lines'
		);

		foreach ($findings as $finding) {
			$this->assertSame(
				self::SOURCE_SYSTEM_WRITE,
				$finding['source'],
				'every finding must carry the SystemWriteInWww source'
			);
		}
	}

	/**
	 * CHECK 2 — compliant counterpart, same "/usr/local/www/" path.
	 *
	 * tests/phpcs/fixtures/usr/local/www/system_write_compliant.php calls
	 * PfbConfig::write()/writeSection() (different method), SomethingElse::
	 * writeSystem() (different class), and merely mentions
	 * "PfbConfig::writeSystem" in a comment/string — none of that is the
	 * gated static PfbConfig::writeSystem()/writeSectionSystem() call, so the
	 * sniff MUST stay entirely silent despite sharing the www/ path with the
	 * violating fixture above.
	 */
	public function testSystemWriteCompliantCasesAreClean(): void
	{
		$findings = $this->findingsFor(
			'usr/local/www/system_write_compliant.php',
			self::SOURCE_SYSTEM_WRITE
		);

		$this->assertSame(
			[],
			$findings,
			'write()/writeSection(), a foreign class, and a comment/string mention '
			. 'must produce no SystemWriteInWww findings'
		);
	}

	/**
	 * CHECK 2 — the legitimate system-caller use case, outside www/.
	 *
	 * tests/phpcs/fixtures/usr/local/pkg/pfblockerng/system_write_compliant.php
	 * calls the identical PfbConfig::writeSystem()/writeSectionSystem() shapes
	 * as the violating www/ fixture, but its path contains no "/usr/local/www/"
	 * substring — the sniff MUST stay silent. This is the before/after proof
	 * that the file path, not the call shape, gates this check.
	 */
	public function testSystemWriteOutsideWwwIsClean(): void
	{
		$findings = $this->findingsFor(
			'usr/local/pkg/pfblockerng/system_write_compliant.php',
			self::SOURCE_SYSTEM_WRITE
		);

		$this->assertSame(
			[],
			$findings,
			'identical writeSystem()/writeSectionSystem() calls outside /usr/local/www/ '
			. 'must produce no SystemWriteInWww findings'
		);
	}

	/**
	 * CHECK 2 — real-tree assertion. The confinement issue #1895's docblocks
	 * promise (writeSystem()/writeSectionSystem() are system-caller-only) MUST
	 * hold mechanically across the actual shipped web UI today: zero
	 * SystemWriteInWww findings over src/usr/local/www/.
	 */
	public function testRealWwwTreeHasNoSystemWriteCalls(): void
	{
		$report = $this->runPhpcsJson(self::repoRoot() . '/src/usr/local/www');

		// Processed-file floor: guards against a vacuous pass (e.g. a wrong path, a
		// misconfigured --extensions, or phpcs silently skipping everything) where
		// zero files scanned would trivially satisfy the zero-findings assertion below.
		$this->assertGreaterThan(
			0,
			count($report['files'] ?? []),
			'phpcs must actually have processed files under src/usr/local/www/ -- a '
			. 'zero-file report would make the zero-findings assertion below vacuous'
		);

		$findings = $this->extractFindings($report, self::SOURCE_SYSTEM_WRITE);

		$this->assertSame(
			[],
			$findings,
			'src/usr/local/www/ must contain zero PfbConfig::writeSystem()/'
			. 'writeSectionSystem() calls (issue #1895 confinement)'
		);
	}
}
