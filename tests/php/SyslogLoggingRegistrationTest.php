<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 — the installedpackages/package <logging> block pfBlockerNG self-registers for its
 * dedicated syslog on the pkg-add path (which does not copy the package XML's <logging>).
 *
 * Pins the two pure helpers in pfblockerng.inc:
 *   pfb_syslog_logging_want(): array            — the canonical block.
 *   pfb_syslog_logging_needs_update($cur,$want) — TRUE when the stored block must be rewritten.
 *
 * The intent: the block carries 'logtab' => 'pfBlockerNG' so the Status > System Logs > Packages
 * subtab reads "pfBlockerNG" on BOTH channels (commit 241302e added <logtab> only to the package
 * XML, which the pkg-add path ignores — so without 'logtab' here the devel package's tab falls
 * back to "pfBlockerNG-devel"). A pre-241302e config row (facilityname + logfilename, NO logtab)
 * MUST therefore be detected as needing a rewrite so existing installs self-heal on the next sync.
 */
final class SyslogLoggingRegistrationTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_syslog_logging_want() — the canonical block
	// -----------------------------------------------------------------------

	public function testWantBlockCarriesLogtabFacilityAndFilename(): void
	{
		$want = pfb_syslog_logging_want();

		// 'logtab' is the fix: it pins the Packages subtab label to "pfBlockerNG".
		$this->assertSame('pfBlockerNG', $want['logtab'] ?? null,
			"the canonical <logging> block must carry logtab='pfBlockerNG' to pin the subtab label");
		$this->assertSame('pfblockerng', $want['facilityname'] ?? null);
		$this->assertSame('pfblockerng_syslog.log', $want['logfilename'] ?? null);
		// No stale <logsocket> in the canonical block (the in-chroot socket was removed).
		$this->assertArrayNotHasKey('logsocket', $want);
	}

	// -----------------------------------------------------------------------
	// pfb_syslog_logging_needs_update() — branch coverage on every condition
	// -----------------------------------------------------------------------

	public function testCanonicalBlockNeedsNoUpdate(): void
	{
		// Given a stored block already equal to the canonical one, no rewrite is needed.
		$want = pfb_syslog_logging_want();
		$this->assertFalse(pfb_syslog_logging_needs_update($want, $want),
			"an already-canonical block must be left untouched (no needless write_config)");
	}

	public function testPre241302eBlockWithoutLogtabNeedsUpdate(): void
	{
		// This is the live state on every pkg-add install (e.g. Prod) before this fix: the block
		// has facilityname + logfilename but NO logtab. It MUST be rewritten so the subtab label
		// stops falling back to the package short name ("pfBlockerNG-devel").
		// Fail-before/pass-after: the old inline check only compared facilityname/logfilename, so
		// it returned FALSE here (no rewrite) and the label stayed wrong.
		$want = pfb_syslog_logging_want();
		$legacy = array(
			'facilityname' => 'pfblockerng',
			'logfilename' => 'pfblockerng_syslog.log',
		);
		$this->assertTrue(pfb_syslog_logging_needs_update($legacy, $want),
			"a block missing 'logtab' must be detected as needing a rewrite (self-heal the label)");
	}

	public function testWrongLogtabNeedsUpdate(): void
	{
		$want = pfb_syslog_logging_want();
		$cur = $want;
		$cur['logtab'] = 'pfBlockerNG-devel';
		$this->assertTrue(pfb_syslog_logging_needs_update($cur, $want),
			"a stale logtab label must trigger a rewrite");
	}

	public function testFacilityMismatchNeedsUpdate(): void
	{
		$want = pfb_syslog_logging_want();
		$cur = $want;
		$cur['facilityname'] = 'wrongfacility';
		$this->assertTrue(pfb_syslog_logging_needs_update($cur, $want));
	}

	public function testFilenameMismatchNeedsUpdate(): void
	{
		$want = pfb_syslog_logging_want();
		$cur = $want;
		$cur['logfilename'] = 'old.log';
		$this->assertTrue(pfb_syslog_logging_needs_update($cur, $want));
	}

	public function testStaleLogsocketNeedsUpdate(): void
	{
		// Even an otherwise-canonical block must be rewritten if it carries the removed
		// in-chroot <logsocket> (core would else regenerate the socket).
		$want = pfb_syslog_logging_want();
		$cur = $want;
		$cur['logsocket'] = '/var/unbound/pfb_syslog.sock';
		$this->assertTrue(pfb_syslog_logging_needs_update($cur, $want));
	}

	public function testMissingOrNonArrayCurrentNeedsUpdate(): void
	{
		// A fresh pkg-add has no <logging> block at all (empty / non-array) — must register it.
		$want = pfb_syslog_logging_want();
		$this->assertTrue(pfb_syslog_logging_needs_update(array(), $want),
			"an absent block must be registered");
		$this->assertTrue(pfb_syslog_logging_needs_update('', $want),
			"a non-array stored value must be treated as absent and registered");
	}
}
