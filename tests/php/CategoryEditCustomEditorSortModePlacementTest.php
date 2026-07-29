<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1875 step 2b fix -- the CM6 mount for the 'custom' field must render in EVERY
 * page mode, not only when the row-reorder block does.
 *
 * The first wiring pass placed the gated mountLists init inside the pre-existing
 * ADR-63 events.push, which is itself wrapped in the
 * `($rowdata[$rowid]['sort'] ?? '') == 'no-sort'` PHP conditional: auto-sort groups AND
 * brand-new groups (no rowid, so 'sort' resolves to '') rendered no editor at all,
 * while the 'custom' Form_Textarea itself renders unconditionally.
 * CategoryEditCustomEditorWiringTest cannot see this: its gate regex matches the
 * events.push/gate/mountLists chain wherever it sits, including inside an unrelated
 * outer conditional. This test pins the placement: the mountLists init must appear
 * BEFORE the no-sort conditional opens, i.e. outside it (same source-pin rationale as
 * the sibling wiring tests -- the page carries top-level render execution and cannot be
 * require()d off-appliance).
 */
final class CategoryEditCustomEditorSortModePlacementTest extends TestCase
{
	public function testMountListsInitSitsOutsideTheNoSortRowReorderConditional(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_category_edit.php');
		}

		// The full open-tag form is unique to the script-section conditional; the bare
		// `['sort'] ?? '') == 'no-sort'` literal also matches the earlier gutter-render
		// if() (~line 1140), which is not the block that swallowed the mount.
		$mountPos = strpos($src, 'pfbCM.mountLists(');
		$sortPos  = strpos($src, "<?php if ((\$rowdata[\$rowid]['sort'] ?? '') == 'no-sort') { ?>");

		$this->assertNotFalse($mountPos, 'expected a pfbCM.mountLists( call in the file');
		$this->assertNotFalse($sortPos, 'expected the ADR-63 no-sort row-reorder conditional in the file');
		$this->assertLessThan(
			$sortPos,
			$mountPos,
			'expected the pfbCM.mountLists( init to appear BEFORE (outside) the no-sort row-reorder '
			. 'conditional -- inside it, auto-sort groups and new groups render no editor at all'
		);
	}
}
