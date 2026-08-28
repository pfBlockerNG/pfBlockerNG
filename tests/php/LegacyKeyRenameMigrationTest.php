<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1898 — retire the compatibility-only stored per-row config-key name.
 *
 * issue #1921 (S2): the scalar-section half of #1898 (the dead-Alexa TOP1M cluster,
 * ADR-66 §2.1/§2.2's TLD Allow and TLD Wildcard families) moved to registry 'old_name'
 * slots consumed by pfb_registry_pass() (pfblockerng.inc) -- RegistryPassTest rows
 * 11-16 cover that, including its per-key (not all-or-nothing) conflict/notice
 * contract. What remains here is the dynamic PER-ROW rename PFB_LEGACY_KEY_RENAMES
 * still owns (filter_alexa -> filter_top1m inside every DNSBL feed row), which
 * pfb_registry_pass() cannot reach -- a section-level array of rows, not a flat
 * key => value node.
 *
 * What this pins:
 *   - the row map is exactly the one audited pair, no style renames;
 *   - each preflight disposition (absent/absent, present/absent, absent/present,
 *     both-equal, both-different) behaves as specified, applied independently per row;
 *   - a conflicting row fails CLOSED — the WHOLE section is left unchanged, across
 *     every row, and an actionable notice fires that never echoes a value;
 *   - the migration is pure before commit, persisted by ONE write_config(), and a
 *     second run mutates nothing;
 *   - a fresh install (no rows) is untouched.
 */
#[CoversFunction('pfb_legacy_key_rename_migrate')]
#[CoversFunction('pfb_run_migrations')]
final class LegacyKeyRenameMigrationTest extends TestCase
{
	private const ROWS_SECTION = 'installedpackages/pfblockerngdnsbl/config';

	protected function setUp(): void
	{
		$GLOBALS['config']                      = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices']       = [];
	}

	// -----------------------------------------------------------------------
	// Fixtures
	// -----------------------------------------------------------------------

	/** Two DNSBL feed rows, the dynamic per-row section the row rename targets. */
	private function legacyRowsSection(): array
	{
		return [
			['aliasname' => 'ADs',     'filter_alexa' => 'on', 'state' => 'Enabled'],
			['aliasname' => 'Malware', 'filter_alexa' => '',   'state' => 'Enabled'],
		];
	}

	private function seed(string $section, array $data): void
	{
		config_set_path($section, $data);
	}

	private function get(string $section): array
	{
		$raw = config_get_path($section, []);
		return is_array($raw) ? $raw : [];
	}

	private function noticeText(): string
	{
		$out = '';
		foreach ($GLOBALS['pfb_test_file_notices'] ?? [] as $notice) {
			$out .= (string) ($notice['notice'] ?? '') . "\n";
		}
		return $out;
	}

	/** Run the rename migration over the section it owns, as the driver does. */
	private function applyRename(): ?array
	{
		return pfb_legacy_key_rename_migrate([
			self::ROWS_SECTION => $this->get(self::ROWS_SECTION),
		]);
	}

	// -----------------------------------------------------------------------
	// A — the mapping is exactly the audited row
	// -----------------------------------------------------------------------

	/**
	 * The map declares exactly one spec (the per-row feed section) and exactly the one
	 * audited pair. issue #1921 removed the scalar-section spec entirely -- its rows now
	 * live as registry 'old_name' slots instead.
	 */
	public function testRenameMapIsExactlyTheAuditedRow(): void
	{
		$this->assertCount(1, PFB_LEGACY_KEY_RENAMES,
			'the per-row rename must be the ONLY spec left in the map (issue #1921)');

		$spec = PFB_LEGACY_KEY_RENAMES[0];
		$this->assertSame(self::ROWS_SECTION, $spec['section']);
		$this->assertTrue($spec['rows'], 'the feed section is a list of per-feed rows');
		$this->assertSame(['filter_alexa' => 'filter_top1m'], $spec['keys']);
	}

	// -----------------------------------------------------------------------
	// B — the five preflight dispositions, applied independently per row
	// -----------------------------------------------------------------------

	/** old absent, new absent: nothing to do. */
	public function testPreflightBothAbsentIsANoOp(): void
	{
		$this->seed(self::ROWS_SECTION, [['aliasname' => 'ADs', 'state' => 'Enabled']]);

		$this->assertNull($this->applyRename(), 'a row with no retired key must not be rewritten');
	}

	/** old present, new absent: the value moves, byte-identically, independently per row. */
	public function testPreflightOldOnlyMovesEachRowIndependently(): void
	{
		$this->seed(self::ROWS_SECTION, $this->legacyRowsSection());

		$result = $this->applyRename();

		$this->assertIsArray($result);
		$rows = $result[self::ROWS_SECTION];
		$this->assertSame('on', $rows[0]['filter_top1m']);
		$this->assertSame('', $rows[1]['filter_top1m']);
		$this->assertArrayNotHasKey('filter_alexa', $rows[0]);
		$this->assertArrayNotHasKey('filter_alexa', $rows[1]);
		$this->assertSame('ADs', $rows[0]['aliasname'], 'unrelated per-row keys must pass through untouched');
	}

	/** old absent, new present: already migrated -- no rewrite. */
	public function testPreflightNewOnlyIsAlreadyMigrated(): void
	{
		$this->seed(self::ROWS_SECTION, [['aliasname' => 'ADs', 'filter_top1m' => 'on', 'state' => 'Enabled']]);

		$this->assertNull($this->applyRename(), 'an already-migrated row must not be rewritten');
	}

	/** both present, same value: converge on the new key, drop the old one. */
	public function testPreflightBothPresentAndEqualConvergesOnTheNewKey(): void
	{
		$this->seed(self::ROWS_SECTION, [
			['aliasname' => 'ADs', 'filter_alexa' => 'on', 'filter_top1m' => 'on', 'state' => 'Enabled'],
		]);

		$result = $this->applyRename();

		$this->assertIsArray($result);
		$this->assertSame('on', $result[self::ROWS_SECTION][0]['filter_top1m']);
		$this->assertArrayNotHasKey('filter_alexa', $result[self::ROWS_SECTION][0]);
	}

	/**
	 * both present, different values in ONE row: fail CLOSED across every row, and the
	 * notice names the keys but never their values (these are on/off tokens, but the
	 * rule is universal across every field this migration could ever carry).
	 */
	public function testPreflightConflictInOneRowFailsClosedAcrossAllRowsWithASecretSafeNotice(): void
	{
		$this->seed(self::ROWS_SECTION, [
			['aliasname' => 'ADs',     'filter_alexa' => 'on', 'filter_top1m' => 'off', 'state' => 'Enabled'], // conflict
			['aliasname' => 'Malware', 'filter_alexa' => 'on', 'state' => 'Enabled'],                          // otherwise migratable
		]);

		$this->assertNull($this->applyRename(), 'a conflicting row must abandon the whole migration');

		$rows = $this->get(self::ROWS_SECTION);
		$this->assertArrayHasKey('filter_alexa', $rows[1] ?? [],
			'a non-conflicting sibling row must NOT be migrated when another row conflicts -- all-or-nothing');

		$text = $this->noticeText();
		$this->assertStringContainsString('filter_alexa', $text, 'notice must name the retired key');
		$this->assertStringContainsString('filter_top1m', $text, 'notice must name the current key');
		$this->assertStringNotContainsString("'on'", $text, 'notice must not echo stored values');
		$this->assertStringNotContainsString("'off'", $text, 'notice must not echo stored values');
	}

	// -----------------------------------------------------------------------
	// C — the driver: atomic, one write, idempotent
	// -----------------------------------------------------------------------

	/**
	 * Scenario: a genuine pre-#1898 install upgrades.
	 *
	 * Given two feed rows carrying the retired per-row key across both truthy and
	 *   falsy stored values,
	 * When the post-install migration driver runs once,
	 * Then every row holds only the current name, values survive byte-identically,
	 *   and exactly one write_config() records the rename.
	 */
	public function testDriverMigratesEveryRowAndPersistsOnce(): void
	{
		$this->seed(self::ROWS_SECTION, $this->legacyRowsSection());
		$this->assertArrayHasKey('filter_alexa', $this->get(self::ROWS_SECTION)[0]);

		pfb_run_migrations();

		$rows = $this->get(self::ROWS_SECTION);
		$this->assertSame('on', $rows[0]['filter_top1m']);
		$this->assertSame('', $rows[1]['filter_top1m']);
		$this->assertArrayNotHasKey('filter_alexa', $rows[0]);
		$this->assertArrayNotHasKey('filter_alexa', $rows[1]);
		$this->assertSame('ADs', $rows[0]['aliasname'], 'unrelated per-row keys must pass through untouched');

		$rename_writes = array_filter(
			$GLOBALS['pfb_test_write_config_calls'],
			static fn (string $msg): bool => str_contains($msg, '1898')
		);
		$this->assertCount(1, $rename_writes, 'the rename must persist with exactly one write_config() event');
	}

	/**
	 * Idempotence: a second driver run over the migrated result mutates nothing and
	 * records no further rename write.
	 */
	public function testSecondRunIsAByteIdenticalNoOp(): void
	{
		$this->seed(self::ROWS_SECTION, $this->legacyRowsSection());
		pfb_run_migrations();

		$rows_after_first                        = $this->get(self::ROWS_SECTION);
		$GLOBALS['pfb_test_write_config_calls'] = [];

		pfb_run_migrations();

		$this->assertSame($rows_after_first, $this->get(self::ROWS_SECTION));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'],
			'a re-run on an already-migrated config must not call write_config() at all');
	}

	/** A fresh install has no rows anywhere, so the migration is inert. */
	public function testFreshInstallIsUntouchedByTheRename(): void
	{
		pfb_run_migrations();

		$this->assertSame([], $this->get(self::ROWS_SECTION));
	}
}
