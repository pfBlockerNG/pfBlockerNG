<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1921 (S2 fix round) -- source-order guard, mechanical, over pfblockerng_install.inc.
 *
 * PfbConfig::writeSectionSystem() round-trips every adapter-bearing registered field
 * present in its $data through write_adapter(read_adapter(...)) (writeSectionRaw(),
 * pfblockerng_extra.inc). A pre-pass legacy-upgrade block in this file calling it would
 * canonicalise a bystander raw '' at a registered key to its registered default BEFORE
 * pfb_registry_pass() (the driver loop at the bottom of this file) gets a chance to see and
 * grandfather it. Before this step, migration-registry entry
 * issue1887-toggle-empty-preserve-gen closed this window; S2 deleted it, so every pre-pass
 * section write in this file must now be raw -- PfbConfig::writeSectionRawSystem(), which
 * persists byte-for-byte with no adapter round-trip.
 *
 * This test polices that mechanically: no 'writeSectionSystem(' byte offset may occur
 * before the pfb_registry_pass() call site. Every occurrence at/after that site is legal --
 * it is the pass's own write-back of its already-canonical output.
 *
 * Anchor gotcha: the short literal 'pfb_registry_pass(' also matches an unrelated comment
 * mention of the function's name earlier in the file (the VIP-migration raw-write-back
 * comment, "...ahead of pfb_registry_pass(), would destroy..."), which sits BEFORE every
 * writeSectionSystem() call site this test polices -- anchoring on that would make the
 * assertion vacuously pass no matter how many pre-pass call sites regress. The anchor below
 * is the longer, call-site-unique substring 'pfb_registry_pass($pfb_registry_sections)'.
 */
final class InstallPrePassWriteOrderTest extends TestCase
{
	public function testNoWriteSectionSystemCallBeforeTheRegistryPassCallSite(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
		$source = file_get_contents($path);
		$this->assertNotFalse($source, "could not read {$path}");

		$anchor = 'pfb_registry_pass($pfb_registry_sections)';
		$anchorOffset = strpos($source, $anchor);
		$this->assertNotFalse(
			$anchorOffset,
			"anchor '{$anchor}' not found in pfblockerng_install.inc -- the registry pass "
			. 'call site moved or was renamed; update this test\'s anchor'
		);

		$before = substr($source, 0, $anchorOffset);
		preg_match_all('/writeSectionSystem\s*\(/', $before, $matches, PREG_OFFSET_CAPTURE);
		$offenders = array_map(static fn(array $m): int => $m[1], $matches[0]);

		$this->assertSame(
			[],
			$offenders,
			'PfbConfig::writeSectionSystem() must not be called before the pfb_registry_pass() '
			. 'call site in pfblockerng_install.inc (it round-trips adapters, canonicalising a '
			. 'bystander raw value before the pass can grandfather it) -- convert the call at '
			. 'these byte offsets to PfbConfig::writeSectionRawSystem(): ' . implode(', ', $offenders)
		);
	}
}
