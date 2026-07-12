<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Fresh add/addgroup-row $pconfig assembly guard (issue #1211).
 *
 * A fresh add/addgroup row (:190-322) populates only a handful of
 * $rowdata[$rowid] keys (aliasname/description/cron[/action][/custom]) --
 * every OTHER key the :868-914 $pconfig block reads is absent, so each
 * unguarded read emits an "Undefined array key" warning (and the unguarded
 * 'custom' read feeds base64_decode(null), a Deprecated notice). The fix
 * guards all 33 reads with a `??` default taken from that field's own
 * save-path fallback (:743-790); :904's suppression_cidr_v6 was already
 * guarded and is left untouched.
 *
 * The page carries top-level execution and cannot be require()d
 * off-appliance, so the $pconfig block is eval-extracted verbatim from the
 * REAL source (CategoryEditAutoSortTest's pattern), anchored on the unique
 * `$pconfig  = array();` line through the trailing `custom` assignment, and
 * run as a pure function of ($rowdata, $rowid, $gtype) -- the block itself
 * branches on $gtype at :881.
 */
final class CategoryEditFreshRowPconfigTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('pfb_category_oracle_fresh_pconfig')) {
			// Non-greedy up through the FULL 'custom' assignment line, whatever its
			// RHS is (pre-fix bare read or post-fix `?? ''`-guarded) -- survives the fix.
			if (!preg_match(
				'/\$pconfig\s*= array\(\);\n'
				. '(.*?\n\s*\$pconfig\[\'custom\'\][^\n]*\n)\}/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: fresh-row pconfig block not found');
			}
			eval(
				'function pfb_category_oracle_fresh_pconfig(array $rowdata, $rowid, string $gtype): array {'
				. ' $pconfig = array();'
				. $m[1]
				. ' return $pconfig; }'
			);
		}
	}

	/**
	 * Runs the extracted block capturing every diagnostic level; fails
	 * loudly (not just risky) so the assertion message names the exact
	 * undefined-key/deprecation the fix must silence.
	 */
	private function runExpectingNoDiagnostics(array $rowdata, $rowid, string $gtype): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$pconfig = pfb_category_oracle_fresh_pconfig($rowdata, $rowid, $gtype);
		} finally {
			restore_error_handler();
		}
		$this->assertSame(
			[],
			$diagnostics,
			"fresh-row \$pconfig assembly must emit zero diagnostics, got:\n" . implode("\n", $diagnostics)
		);
		return $pconfig;
	}

	// --- Axis 1: absent-key, gtype=ipv4 (mirrors the addgroup-Whitelist real
	// state at :291-294/:314 -- aliasname/description/cron/action/custom set,
	// every ipv4/ipv6-branch + common field absent) ---------------------------

	public function testFreshWhitelistRowIpv4LeavesEveryUnguardedFieldAtItsSaveDefault(): void
	{
		$rowdata = [3 => [
			'aliasname'   => 'Whitelist',
			'description' => 'pfBlockerNG Whitelist',
			'cron'        => 'EveryDay',
			'action'      => 'Permit_Outbound',
			'custom'      => base64_encode('192.0.2.55 # smoke-1211'),
		]];

		$pconfig = $this->runExpectingNoDiagnostics($rowdata, 3, 'ipv4');

		// Populated keys pass through untouched (not the point of THIS axis,
		// but proves the guard didn't clobber what the fresh-row path did set).
		$this->assertSame('Whitelist', $pconfig['aliasname']);
		$this->assertSame('pfBlockerNG Whitelist', $pconfig['description']);
		$this->assertSame('EveryDay', $pconfig['cron']);
		$this->assertSame('Permit_Outbound', $pconfig['action']);

		// Every absent key falls back to its save-path default (:743-790).
		$this->assertSame('', $pconfig['dow']);
		$this->assertSame('sort', $pconfig['sort']);
		$this->assertSame('', $pconfig['srcint']);
		$this->assertSame('', $pconfig['script_pre']);
		$this->assertSame('', $pconfig['script_post']);
		$this->assertSame('enabled', $pconfig['aliaslog']);
		$this->assertSame('enabled', $pconfig['stateremoval']);
		$this->assertSame('', $pconfig['autoaddrnot_in']);
		$this->assertSame('', $pconfig['autoports_in']);
		$this->assertSame('', $pconfig['aliasports_in']);
		$this->assertSame('', $pconfig['autoaddr_in']);
		$this->assertSame('', $pconfig['autonot_in']);
		$this->assertSame('', $pconfig['aliasaddr_in']);
		$this->assertSame('any', $pconfig['autoproto_in']);
		$this->assertSame('default', $pconfig['agateway_in']);
		$this->assertSame('', $pconfig['autoaddrnot_out']);
		$this->assertSame('', $pconfig['autoports_out']);
		$this->assertSame('', $pconfig['aliasports_out']);
		$this->assertSame('', $pconfig['autoaddr_out']);
		$this->assertSame('', $pconfig['autonot_out']);
		$this->assertSame('', $pconfig['aliasaddr_out']);
		$this->assertSame('any', $pconfig['autoproto_out']);
		$this->assertSame('default', $pconfig['agateway_out']);
		$this->assertSame('Disabled', $pconfig['suppression_cidr']);
		$this->assertSame('Disabled', $pconfig['suppression_cidr_v6']);
		$this->assertSame('', $pconfig['whois_convert']);
	}

	// --- Axis 1: absent-key, gtype=dnsbl (mirrors the addgroup-feed real
	// state at :319-322 -- only aliasname/description/cron set; no 'action',
	// no 'custom', no dnsbl-branch fields) -------------------------------------

	public function testFreshFeedRowDnsblLeavesEveryUnguardedFieldAtItsSaveDefault(): void
	{
		$rowdata = [5 => [
			'aliasname'   => 'smoke-1211-feed',
			'description' => 'smoke desc',
			'cron'        => 'EveryDay',
		]];

		$pconfig = $this->runExpectingNoDiagnostics($rowdata, 5, 'dnsbl');

		$this->assertSame('smoke-1211-feed', $pconfig['aliasname']);
		$this->assertSame('smoke desc', $pconfig['description']);
		$this->assertSame('EveryDay', $pconfig['cron']);

		// 'action' is absent on this branch -- proves the common (pre-$gtype-if)
		// guard fires regardless of which branch below it runs.
		$this->assertSame('Disabled', $pconfig['action']);
		$this->assertSame('', $pconfig['dow']);
		$this->assertSame('sort', $pconfig['sort']);
		$this->assertSame('', $pconfig['srcint']);
		$this->assertSame('', $pconfig['script_pre']);
		$this->assertSame('', $pconfig['script_post']);

		// dnsbl-branch-only fields.
		$this->assertSame('Enabled', $pconfig['logging']);
		$this->assertSame('default', $pconfig['order']);
		$this->assertSame('', $pconfig['filter_alexa']);

		// 'custom' absent -> base64_decode(null) would Deprecated-warn without
		// the guard; runExpectingNoDiagnostics already proved zero diagnostics.
		$this->assertSame('', $pconfig['custom']);
	}

	// --- Axis 2: populated-key, gtype=ipv4 -- guards are no-ops ---------------

	public function testExistingIpv4RowWithEveryKeyPresentPassesValuesThroughUnchanged(): void
	{
		$rowdata = [7 => [
			'aliasname'            => 'ExistingAlias',
			'description'          => 'Existing desc',
			'action'               => 'Deny_Both',
			'cron'                 => 'Weekly',
			'dow'                  => '3',
			'sort'                 => 'no-sort',
			'srcint'               => 'igb0',
			'script_pre'           => 'ip_pre_x.sh',
			'script_post'          => 'ip_post_x.sh',
			'aliaslog'             => 'disabled',
			'stateremoval'         => 'disabled',
			'autoaddrnot_in'       => 'on',
			'autoports_in'         => 'on',
			'aliasports_in'        => 'HTTP',
			'autoaddr_in'          => 'on',
			'autonot_in'           => 'on',
			'aliasaddr_in'         => 'LAN net',
			'autoproto_in'         => 'tcp',
			'agateway_in'          => 'WAN_GW',
			'autoaddrnot_out'      => 'on',
			'autoports_out'        => 'on',
			'aliasports_out'       => 'HTTPS',
			'autoaddr_out'         => 'on',
			'autonot_out'          => 'on',
			'aliasaddr_out'        => 'LAN net',
			'autoproto_out'        => 'udp',
			'agateway_out'         => 'WAN_GW',
			'suppression_cidr'     => '24',
			'suppression_cidr_v6'  => '64',
			'whois_convert'        => 'on',
			'custom'               => base64_encode('192.0.2.99 # existing'),
		]];

		$pconfig = $this->runExpectingNoDiagnostics($rowdata, 7, 'ipv4');

		// Every present value survives verbatim -- a guard that clobbered a
		// present key (e.g. a bare `?? default` typo'd over the real value)
		// would fail this, even though the absent-key axis above still passes.
		// 'custom' is base64_decode()d by the block, so it is asserted separately below.
		foreach ($rowdata[7] as $key => $value) {
			if ($key === 'custom') {
				continue;
			}
			$this->assertSame($value, $pconfig[$key], "populated key '{$key}' must pass through unchanged");
		}
		$this->assertSame('192.0.2.99 # existing', $pconfig['custom']);
	}

	// --- Axis 2: populated-key, gtype=dnsbl -- guards are no-ops --------------

	public function testExistingDnsblRowWithEveryKeyPresentPassesValuesThroughUnchanged(): void
	{
		$rowdata = [9 => [
			'aliasname'    => 'ExistingDnsblAlias',
			'description'  => 'Existing dnsbl desc',
			'action'       => 'unbound',
			'cron'         => '01hour',
			'dow'          => '5',
			'sort'         => 'sort',
			'srcint'       => 'wan',
			'script_pre'   => 'dnsbl_pre_x.py',
			'script_post'  => 'dnsbl_post_x.py',
			'logging'      => 'Disabled',
			'order'        => 'reverse',
			'filter_alexa' => 'on',
			'custom'       => base64_encode('example.invalid # existing dnsbl'),
		]];

		$pconfig = $this->runExpectingNoDiagnostics($rowdata, 9, 'dnsbl');

		// 'custom' is base64_decode()d by the block, so it is asserted separately below.
		foreach ($rowdata[9] as $key => $value) {
			if ($key === 'custom') {
				continue;
			}
			$this->assertSame($value, $pconfig[$key], "populated key '{$key}' must pass through unchanged");
		}
		$this->assertSame('example.invalid # existing dnsbl', $pconfig['custom']);
	}
}
