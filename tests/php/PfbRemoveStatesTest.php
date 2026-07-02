<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_remove_states() — the kill-states validation walk (issues #702 / #705).
 *
 * The function reaches pfctl exclusively through $pfb['pfctl'], reads the state
 * dump from $pfb['states_tmp'], and takes every policy input from config — so
 * the REAL function runs off-appliance against the committed
 * fixtures/fake_pfctl.sh stub (canned rules/states in, issued kills recorded to
 * a log the tests assert on). The live end-to-end legs (a real pf state killed /
 * preserved across an Update) are tests/smoke/test_smoke_killstates.py.
 *
 * Feature: kill-states state validation and suppression
 *   Background:
 *     Given a pfB block rule on interface em0 referencing the urltable aliases
 *           pfB_pfbunit_v4 / pfB_pfbunit_v6 (so both tables are kill candidates
 *           and em0 is a pfB interface)
 *     And   the fake pfctl reports which IPs "match" a table and records kills
 *
 * Pinned behaviour (every branch, both sides):
 *   * #702 — regression pinning for a behaviour-PRESERVING cleanup. Contrary to
 *     the issue's crash claim, the removed fourth filter_var() term never
 *     fataled: 'FILTER_FLAG_NO_LOOPBACK_RANGE' names a REAL function defined in
 *     pfblockerng.inc (:7826, the legacy "fake filter flag" idiom), so
 *     FILTER_CALLBACK had a valid callable — and for any IPv6 input that
 *     callback returns the value (truthy), making the term a NO-OP on the v6
 *     branch (its 127/8 check is IPv4-only). These tests pin the v6 walk across
 *     the removal (green before AND after, per the mandate's refactor rule): a
 *     table-matched public IPv6 state is killed, and loopback/link-local stay
 *     excluded via FILTER_FLAG_NO_RES_RANGE in the surviving term.
 *   * #705 — red→green: a state whose IP sits on a 'Permit_*' custom list is
 *     EXCLUDED from clearing (pre-fix two independent bugs each broke this: the
 *     config path 'installedpackages{type}' missed its '/' so the suppression
 *     set was always empty, and the inner-loop 'continue' was a no-op —
 *     'continue 2' is required to skip the state). Covered for bare-IP
 *     (/32-append branch) and explicit-CIDR entries, v4 and v6 list types, and
 *     the negative side (a 'Deny_*' custom list does NOT suppress).
 */
#[CoversFunction('pfb_remove_states')]
final class PfbRemoveStatesTest extends TestCase
{
	/** @var string Per-test sandbox root; one fresh dir tree per test. */
	private string $root;

	/** @var array Snapshot of $GLOBALS['config'] to restore in tearDown. */
	private array $savedConfig;

	/** @var array Snapshot of $GLOBALS['pfb'] to restore in tearDown. */
	private array $savedPfb;

	// The pfB interface every fixture state line sits on (must match the rules
	// fixture: pfb_remove_states skips states on non-pfB interfaces).
	private const IFACE = 'em0';

	// Inert victims: RFC 5737 TEST-NET-2 (v4) and the RFC 9637 documentation
	// block 3fff::/20 (v6). 3fff:: is deliberate: FILTER_FLAG_NO_RES_RANGE may
	// treat other doc ranges (2001:db8::/32) as reserved depending on the PHP
	// version, which would short-circuit the branch under test — a precondition
	// assert below pins that 3fff:: stays public on the running PHP.
	private const V4_VICTIM = '198.51.100.9';
	private const V4_PERMIT = '198.51.100.7';
	private const V6_VICTIM = '3fff::9';
	private const V6_PERMIT = '3fff::7';

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_killstates_' . getmypid() . '_' . uniqid();
		if (!mkdir($this->root, 0777, true)) {
			$this->fail("could not create sandbox {$this->root}");
		}
		$this->savedConfig = $GLOBALS['config'] ?? [];
		$this->savedPfb    = $GLOBALS['pfb'] ?? [];

		// Route every pfctl call through the committed stub; logs land in the sandbox.
		$GLOBALS['pfb']['pfctl']      = __DIR__ . '/fixtures/fake_pfctl.sh';
		$GLOBALS['pfb']['states_tmp'] = "{$this->root}/states_tmp";
		$GLOBALS['pfb']['log']        = "{$this->root}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']     = "{$this->root}/error.log";
		$GLOBALS['pfb']['ipconfig']['v4suppression'] = '';
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb_test_dns_servers'] = [];

		// One pfB block rule on IFACE — enough for pfb_filterrules() to list the
		// interface (only rule_list['int'] is consumed by pfb_remove_states).
		$rules = '@1(0) block return in log quick on ' . self::IFACE
			. ' inet from any to <pfB_pfbunit_v4:1> label "USER_RULE" ridentifier 1770000001' . "\n";
		file_put_contents("{$this->root}/rules.txt", $rules);
		putenv("PFB_FAKE_RULES={$this->root}/rules.txt");
		putenv("PFB_FAKE_KILL_LOG={$this->root}/kill.log");
		putenv('PFB_FAKE_MATCH=');
		putenv('PFB_FAKE_STATES=');
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb']    = $this->savedPfb;
		unset($GLOBALS['pfb_test_dns_servers']);
		foreach (['PFB_FAKE_RULES', 'PFB_FAKE_STATES', 'PFB_FAKE_MATCH', 'PFB_FAKE_KILL_LOG'] as $env) {
			putenv($env);
		}
		// Best-effort recursive cleanup of the sandbox.
		if (is_dir($this->root)) {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator($this->root, FilesystemIterator::SKIP_DOTS),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ($it as $file) {
				$file->isDir() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
			}
			@rmdir($this->root);
		}
	}

	/**
	 * Seed $GLOBALS['config']: both pfB urltable aliases wired to block rules
	 * (so pfB_pfbunit_v4/_v6 are kill-candidate tables) plus the given
	 * pfblockernglists rows (the Permit-customlist suppression source).
	 */
	private function seedConfig(array $lists_v4 = [], array $lists_v6 = []): void
	{
		$GLOBALS['config'] = [
			'aliases' => ['alias' => [
				['type' => 'urltable', 'name' => 'pfB_pfbunit_v4', 'descr' => 'pfBlockerNG unit'],
				['type' => 'urltable', 'name' => 'pfB_pfbunit_v6', 'descr' => 'pfBlockerNG unit'],
			]],
			'filter' => ['rule' => [
				['type' => 'block', 'source' => ['address' => 'pfB_pfbunit_v4'], 'descr' => ''],
				['type' => 'block', 'source' => ['address' => 'pfB_pfbunit_v6'], 'descr' => ''],
			]],
			'installedpackages' => [
				'pfblockernglistsv4' => ['config' => $lists_v4],
				'pfblockernglistsv6' => ['config' => $lists_v6],
			],
		];
	}

	/** Write the canned `pfctl -s state` dump the walk will parse. */
	private function seedStates(string ...$lines): void
	{
		file_put_contents("{$this->root}/states.txt", implode("\n", $lines) . "\n");
		putenv("PFB_FAKE_STATES={$this->root}/states.txt");
	}

	/** Declare which IPs the fake pfctl reports as members of ANY pfB table. */
	private function seedTableMatches(string ...$ips): void
	{
		putenv('PFB_FAKE_MATCH=' . implode(' ', $ips));
	}

	/** A NAT-shaped (7-token) v4 state line whose kill-candidate IP is the DESTINATION. */
	private function v4State(string $dst, int $port = 54321): string
	{
		return self::IFACE . " tcp 10.0.2.15:{$port} (192.168.1.10:{$port}) -> {$dst}:80 SYN_SENT:CLOSED";
	}

	/** A 6-token v6 state line whose kill-candidate IP is the LEFT endpoint. */
	private function v6State(string $left): string
	{
		return self::IFACE . " tcp {$left}[443] -> 3fff:ffff::1[80] ESTABLISHED:ESTABLISHED";
	}

	/**
	 * Run the REAL pfb_remove_states() and return the recorded kill log.
	 *
	 * The walk reads first-seen state-array keys before creating them (an
	 * appliance-tolerated E_WARNING under PHP 8) — swallow warnings/deprecations
	 * around the call with a scoped handler (PHPUnit's own handler records them
	 * regardless of error_reporting masking), so the suite output stays
	 * signal-only. Real Errors (the pre-fix #702 crash) still surface.
	 */
	private function runRemoveStates(): string
	{
		set_error_handler(static fn (): bool => true, E_WARNING | E_DEPRECATED);
		try {
			pfb_remove_states();
		} finally {
			restore_error_handler();
		}
		$kill_log = "{$this->root}/kill.log";
		return is_file($kill_log) ? (string) file_get_contents($kill_log) : '';
	}

	/**
	 * Scenario (#702) — a table-matched PUBLIC IPv6 state is killed.
	 *
	 * Given: a state on a pfB interface whose examined endpoint is the public
	 *        3fff::9 (asserted public under THIS PHP's NO_PRIV/NO_RES flags), and
	 *        the fake pfctl reporting 3fff::9 as a member of the v6 block table.
	 * When:  pfb_remove_states() runs.
	 * Then:  the state's kill is issued. Behaviour-preserving pin: the removed
	 *        FILTER_CALLBACK term was a no-op for IPv6 (its named callback
	 *        returns any v6 input truthily), so this must hold before AND after
	 *        the cleanup — it guards the removal, it does not chase a crash.
	 */
	public function test_public_ipv6_state_completes_and_kills_when_table_matched(): void
	{
		// Precondition (not theater): the chosen doc-range v6 must be PUBLIC to
		// this PHP's filter, or the branch under test is never reached.
		$this->assertNotFalse(
			filter_var(self::V6_VICTIM, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE),
			self::V6_VICTIM . ' must validate as public IPv6 under NO_PRIV|NO_RES on this PHP — pick a different fixture address'
		);

		$this->seedConfig();
		$this->seedStates($this->v6State(self::V6_VICTIM));
		$this->seedTableMatches(self::V6_VICTIM);

		$kills = $this->runRemoveStates();

		$this->assertStringContainsString(
			self::V6_VICTIM,
			$kills,
			'expected a kill for the table-matched public IPv6 state ' . self::V6_VICTIM
			. " — kill log was:\n{$kills}"
		);
	}

	/**
	 * Scenario (#702 rationale) — loopback / link-local IPv6 states stay excluded.
	 *
	 * Given: states for ::1 and fe80::1 on a pfB interface, with the fake pfctl
	 *        willing to report BOTH as table members.
	 * When:  pfb_remove_states() runs.
	 * Then:  neither is killed — FILTER_FLAG_NO_RES_RANGE excludes them in the
	 *        surviving term, which is why dropping the no-op FILTER_CALLBACK
	 *        "loopback" term loses no coverage (the cleanup's safety argument).
	 */
	public function test_reserved_ipv6_states_are_not_killed(): void
	{
		$this->seedConfig();
		$this->seedStates($this->v6State('::1'), $this->v6State('fe80::1'));
		$this->seedTableMatches('::1', 'fe80::1');

		$kills = $this->runRemoveStates();

		$this->assertSame(
			'',
			$kills,
			"reserved IPv6 endpoints (::1, fe80::1) must never be killed — kill log was:\n{$kills}"
		);
	}

	/**
	 * Scenario (#705) — a bare-IP 'Permit_*' custom entry spares its state.
	 *
	 * Given: a v4 Permit custom list holding the bare IP 198.51.100.7 (exercises
	 *        the '/32'-append branch), and BOTH 198.51.100.7 and 198.51.100.9 as
	 *        members of the v4 block table with a live state each (the genuine
	 *        permit-vs-deny conflict).
	 * When:  pfb_remove_states() runs.
	 * Then:  the unlisted 198.51.100.9 is killed (kill-states did run) and the
	 *        permitted 198.51.100.7 is NOT (pre-fix either bug killed it: the
	 *        misspelt config path made the suppression set empty, and the inner
	 *        'continue' skipped nothing — 'continue 2' skips the state).
	 */
	public function test_permit_customlist_bare_ip_spares_state_others_still_killed(): void
	{
		$this->seedConfig(lists_v4: [[
			'aliasname' => 'pfbpermit',
			'action'    => 'Permit_Outbound',
			'custom'    => base64_encode(self::V4_PERMIT),
		]]);
		$this->seedStates($this->v4State(self::V4_PERMIT), $this->v4State(self::V4_VICTIM, 54322));
		$this->seedTableMatches(self::V4_PERMIT, self::V4_VICTIM);

		$kills = $this->runRemoveStates();

		$this->assertStringContainsString(
			self::V4_VICTIM,
			$kills,
			'the non-permitted ' . self::V4_VICTIM . " must be killed (proves the pass ran) — kill log was:\n{$kills}"
		);
		$this->assertStringNotContainsString(
			self::V4_PERMIT,
			$kills,
			'the Permit-customlist IP ' . self::V4_PERMIT . " must be excluded from clearing — kill log was:\n{$kills}"
		);
	}

	/**
	 * Scenario (#705) — an explicit-CIDR 'Permit_*' entry spares only members.
	 *
	 * Given: a v4 Permit custom list holding 198.51.100.0/29 (no '/32' append),
	 *        one state inside the CIDR (198.51.100.5) and one outside
	 *        (198.51.100.99), both v4-table members.
	 * When:  pfb_remove_states() runs.
	 * Then:  the inside IP survives, the outside IP is killed — the exclusion is
	 *        real subnet membership, not list-presence.
	 */
	public function test_permit_customlist_cidr_spares_members_only(): void
	{
		$this->seedConfig(lists_v4: [[
			'aliasname' => 'pfbpermitcidr',
			'action'    => 'Permit_Both',
			'custom'    => base64_encode('198.51.100.0/29'),
		]]);
		$this->seedStates($this->v4State('198.51.100.5'), $this->v4State('198.51.100.99', 54322));
		$this->seedTableMatches('198.51.100.5', '198.51.100.99');

		$kills = $this->runRemoveStates();

		$this->assertStringContainsString(
			'198.51.100.99',
			$kills,
			"198.51.100.99 lies outside the permitted /29 and must be killed — kill log was:\n{$kills}"
		);
		$this->assertStringNotContainsString(
			'198.51.100.5',
			$kills,
			"198.51.100.5 lies inside the permitted 198.51.100.0/29 and must survive — kill log was:\n{$kills}"
		);
	}

	/**
	 * Scenario (#705) — the v6 list type feeds the suppression set too.
	 *
	 * Given: a pfblockernglistsv6 Permit custom list holding 3fff::7/128 (an
	 *        explicit host CIDR: the bare-IP branch appends '/32', which for
	 *        IPv6 would be a 32-BIT prefix — pre-existing quirk, out of scope),
	 *        and v6-table-matched states for 3fff::7 and 3fff::9.
	 * When:  pfb_remove_states() runs.
	 * Then:  3fff::7 survives, 3fff::9 is killed — the config walk reads BOTH
	 *        pfblockernglistsv4 and pfblockernglistsv6 (the misspelt pre-fix
	 *        path broke both identically).
	 */
	public function test_permit_customlist_v6_row_spares_v6_state(): void
	{
		$this->seedConfig(lists_v6: [[
			'aliasname' => 'pfbpermitv6',
			'action'    => 'Permit_Outbound',
			'custom'    => base64_encode(self::V6_PERMIT . '/128'),
		]]);
		$this->seedStates($this->v6State(self::V6_PERMIT), $this->v6State(self::V6_VICTIM));
		$this->seedTableMatches(self::V6_PERMIT, self::V6_VICTIM);

		$kills = $this->runRemoveStates();

		$this->assertStringContainsString(
			self::V6_VICTIM,
			$kills,
			'the non-permitted ' . self::V6_VICTIM . " must be killed — kill log was:\n{$kills}"
		);
		$this->assertStringNotContainsString(
			self::V6_PERMIT,
			$kills,
			'the v6 Permit-customlist IP ' . self::V6_PERMIT . " must survive — kill log was:\n{$kills}"
		);
	}

	/**
	 * Scenario (#705, negative branch) — a 'Deny_*' custom list does NOT suppress.
	 *
	 * Given: the SAME custom entry as the bare-IP scenario but on a Deny-action
	 *        list, with a table-matched state for it.
	 * When:  pfb_remove_states() runs.
	 * Then:  the IP is killed — only 'Permit_*' actions feed the suppression set
	 *        (pins the strpos($list['action'], 'Permit_') filter as a real branch).
	 */
	public function test_deny_customlist_does_not_suppress(): void
	{
		$this->seedConfig(lists_v4: [[
			'aliasname' => 'pfbdenycustom',
			'action'    => 'Deny_Outbound',
			'custom'    => base64_encode(self::V4_PERMIT),
		]]);
		$this->seedStates($this->v4State(self::V4_PERMIT));
		$this->seedTableMatches(self::V4_PERMIT);

		$kills = $this->runRemoveStates();

		$this->assertStringContainsString(
			self::V4_PERMIT,
			$kills,
			'a Deny-action custom list must NOT spare ' . self::V4_PERMIT . " — kill log was:\n{$kills}"
		);
	}
}
