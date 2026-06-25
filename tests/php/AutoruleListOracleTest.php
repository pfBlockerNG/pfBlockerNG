<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Oracle tests for pfb_build_autorule_list() — ADR-41 Phase 1.
 *
 * These are CHARACTERISATION (oracle) tests: they pin EXACTLY what the helper
 * returns today, INCLUDING the known-bad cases (order_1/order_2 duplication,
 * order_4 reorder). They stay GREEN across Phase 1 (extraction is
 * behaviour-preserving) and flip to the CORRECTED expected output in Phase 3.
 *
 * Fixture matrix covered (each pass_order × float on/off unless noted):
 *   A. order_0,  float=off, inbound==outbound ('lan'), Deny_* only
 *   B. order_0,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   C. order_1,  float=off, inbound==outbound ('lan'), Deny_* only  [KNOWN-BAD: dup]
 *   D. order_1,  float=off, inbound!=outbound ('lan'+'opt1'), Deny_* only
 *   E. order_1,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   F. order_2,  float=off, inbound==outbound ('lan'), Deny_* only  [KNOWN-BAD: dup]
 *   G. order_2,  float=off, inbound!=outbound ('lan'+'opt1'), Deny_* only
 *   H. order_2,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   I. order_3,  float=off, inbound==outbound ('lan'), Deny_* only
 *   J. order_3,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   K. order_4,  float=off, inbound==outbound ('lan'), Deny_* only  [KNOWN-BAD: reorder]
 *   L. order_4,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   M. absent/empty pass_order, float=off, treated as order_0 by the helper
 *   N. Permit_* (permit_inbound + permit_outbound) present, order_1, float=off
 *   O. DNS-redirect bypass rule present (pfB_ descr but NOT stripped), order_0, float=off
 *   P. DoT-block bypass rule present, order_0, float=off
 *
 * Each test asserts the FULL ordered descr|type|interface|floating list — not just
 * a count — so any reordering shows up as a test failure.
 *
 * KNOWN-BAD cases (pinned as "what it does today" — Phase 3 flips them):
 *   C (order_1, inbound==outbound, float=off): user LAN pass rule duplicated
 *   F (order_2, inbound==outbound, float=off): user LAN pass rule duplicated
 *   K (order_4, float=off):                   user rules reordered (opt1 before lan)
 *
 * No live pfSense state involved — pfb_tracker() is called via the existing
 * doubles (get_real_interface/get_interface_ip/etc. all seeded to deterministic
 * no-op values by default).
 */
#[CoversFunction('pfb_build_autorule_list')]
final class AutoruleListOracleTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixtures
	// -----------------------------------------------------------------------

	/** A minimal user 'pass' rule on 'lan'. */
	private function userPassLan(string $descr = 'Default allow LAN to any'): array
	{
		return [
			'descr'       => $descr,
			'type'        => 'pass',
			'interface'   => 'lan',
			'ipprotocol'  => 'inet',
			'floating'    => '',
			'source'      => ['any' => ''],
			'destination' => ['any' => ''],
		];
	}

	/** A minimal user 'pass' rule on 'opt1'. */
	private function userPassOpt1(string $descr = 'Default allow OPT1 to any'): array
	{
		return [
			'descr'       => $descr,
			'type'        => 'pass',
			'interface'   => 'opt1',
			'ipprotocol'  => 'inet',
			'floating'    => '',
			'source'      => ['any' => ''],
			'destination' => ['any' => ''],
		];
	}

	/** A minimal user floating 'pass' rule. */
	private function userFloatPass(string $descr = 'User Float Pass'): array
	{
		return [
			'descr'       => $descr,
			'type'        => 'pass',
			'interface'   => '',
			'ipprotocol'  => 'inet',
			'floating'    => 'yes',
			'direction'   => 'any',
			'source'      => ['any' => ''],
			'destination' => ['any' => ''],
		];
	}

	/** A pfB_ deny rule — should be STRIPPED by the helper (it rebuilds these). */
	private function pfbDenyRule(string $iface = 'lan'): array
	{
		return [
			'descr'       => 'pfB_DenyAlias_v4 Auto Rule',
			'type'        => 'block',
			'interface'   => $iface,
			'ipprotocol'  => 'inet',
			'floating'    => '',
			'source'      => ['address' => 'pfB_DenyAlias_v4'],
			'destination' => ['any' => ''],
		];
	}

	/** A DNS-redirect bypass rule — pfB_ descr but must NOT be stripped. */
	private function dnsRedirectBypassRule(): array
	{
		return [
			'descr'       => 'pfB_DNS_Redirect_lan_v4',  // starts with PFB_DNS_REDIR_DESCR_V4_PFX
			'type'        => 'pass',
			'interface'   => 'lan',
			'ipprotocol'  => 'inet',
			'floating'    => '',
			'source'      => ['any' => ''],
			'destination' => ['any' => ''],
		];
	}

	/** A DoT-block bypass rule — pfB_ descr but must NOT be stripped. */
	private function dotBlockBypassRule(): array
	{
		return [
			'descr'       => 'pfB_DoT_Block_lan',  // starts with PFB_DOT_BLOCK_DESCR_PFX
			'type'        => 'block',
			'interface'   => 'lan',
			'ipprotocol'  => 'inet',
			'floating'    => '',
			'source'      => ['any' => ''],
			'destination' => ['any' => ''],
		];
	}

	/**
	 * A minimal $pfb_generated with one deny_inbound rule (deny 'lan' inbound).
	 * The deny template has no interface/tracker yet — those are set per-interface in the helper.
	 */
	private function pfbGeneratedDenyOnly(): array
	{
		return [
			'permit_inbound'    => [],
			'permit_outbound'   => [],
			'deny_inbound'      => [
				[
					'descr'       => 'pfB_DenyList_v4 Auto Rule',
					'type'        => 'block',
					'interface'   => '',  // set by helper
					'ipprotocol'  => 'inet',
					'floating'    => '',
					'source'      => ['address' => 'pfB_DenyList_v4'],
					'destination' => ['any' => ''],
					'created'     => ['time' => 0, 'username' => 'Auto'],
				],
			],
			'deny_outbound'     => [
				[
					'descr'       => 'pfB_DenyList_v4 Auto Rule',
					'type'        => 'reject',
					'interface'   => '',  // set by helper
					'ipprotocol'  => 'inet',
					'floating'    => '',
					'source'      => ['any' => ''],
					'destination' => ['address' => 'pfB_DenyList_v4'],
					'created'     => ['time' => 0, 'username' => 'Auto'],
				],
			],
			'match_inbound'     => [],
			'match_outbound'    => [],
			'inbound_floating'  => '',
			'outbound_floating' => '',
			'dnsbl_float'       => [],
		];
	}

	/**
	 * $pfb_generated with permit_inbound + deny_inbound (Permit_* action present).
	 */
	private function pfbGeneratedPermitAndDeny(): array
	{
		return [
			'permit_inbound'    => [
				[
					'descr'       => 'pfB_PermitList_v4 Auto Rule',
					'type'        => 'pass',
					'interface'   => '',
					'ipprotocol'  => 'inet',
					'floating'    => '',
					'source'      => ['address' => 'pfB_PermitList_v4'],
					'destination' => ['any' => ''],
					'created'     => ['time' => 0, 'username' => 'Auto'],
				],
			],
			'permit_outbound'   => [
				[
					'descr'       => 'pfB_PermitList_v4 Auto Rule',
					'type'        => 'pass',
					'interface'   => '',
					'ipprotocol'  => 'inet',
					'floating'    => '',
					'source'      => ['any' => ''],
					'destination' => ['address' => 'pfB_PermitList_v4'],
					'created'     => ['time' => 0, 'username' => 'Auto'],
				],
			],
			'deny_inbound'      => [
				[
					'descr'       => 'pfB_DenyList_v4 Auto Rule',
					'type'        => 'block',
					'interface'   => '',
					'ipprotocol'  => 'inet',
					'floating'    => '',
					'source'      => ['address' => 'pfB_DenyList_v4'],
					'destination' => ['any' => ''],
					'created'     => ['time' => 0, 'username' => 'Auto'],
				],
			],
			'deny_outbound'     => [
				[
					'descr'       => 'pfB_DenyList_v4 Auto Rule',
					'type'        => 'reject',
					'interface'   => '',
					'ipprotocol'  => 'inet',
					'floating'    => '',
					'source'      => ['any' => ''],
					'destination' => ['address' => 'pfB_DenyList_v4'],
					'created'     => ['time' => 0, 'username' => 'Auto'],
				],
			],
			'match_inbound'     => [],
			'match_outbound'    => [],
			'inbound_floating'  => '',
			'outbound_floating' => '',
			'dnsbl_float'       => [],
		];
	}

	// -----------------------------------------------------------------------
	// $GLOBALS['pfb'] sandbox helpers
	// -----------------------------------------------------------------------

	private array $origPfb    = [];
	private bool  $hadPfb     = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb   = array_key_exists('pfb', $GLOBALS);
		$this->origPfb  = $GLOBALS['pfb'] ?? [];

		// Minimal pfb globals needed by pfb_tracker() (trackerids collision check).
		$GLOBALS['pfb'] = [
			'trackerids'         => [],
			'foreign_trackerids' => [],
			'last_trackerid'     => 1700000010,
		];
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->origPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	// -----------------------------------------------------------------------
	// Assertion helpers
	// -----------------------------------------------------------------------

	/**
	 * Extract [descr, type, interface, floating] from each rule in $result.
	 * This is the "shape" used for oracle assertions — enough to pin ORDER and
	 * presence without being brittle about tracker/created timestamps.
	 *
	 * @param array<int, array<string, mixed>> $result
	 * @return list<array{descr: string, type: string, interface: string, floating: string}>
	 */
	private function shapes(array $result): array
	{
		return array_map(static function (array $rule): array {
			return [
				'descr'     => $rule['descr']     ?? '',
				'type'      => $rule['type']       ?? '',
				'interface' => $rule['interface']  ?? '',
				'floating'  => $rule['floating']   ?? '',
			];
		}, array_values($result));
	}

	/**
	 * Assert the full ordered shape list equals $expected.
	 * On failure, print expected vs actual for diagnosis.
	 *
	 * @param list<array{descr: string, type: string, interface: string, floating: string}> $expected
	 * @param array<int, array<string, mixed>> $result
	 */
	private function assertShapes(array $expected, array $result, string $context = ''): void
	{
		$actual = $this->shapes($result);
		$label  = $context !== '' ? " [{$context}]" : '';
		$this->assertSame(
			$expected,
			$actual,
			"Rule shape mismatch{$label}."
				. "\n\nExpected:\n" . json_encode($expected, JSON_PRETTY_PRINT)
				. "\n\nActual:\n"   . json_encode($actual,   JSON_PRETTY_PRINT)
		);
	}

	/** Assert each rule in $result has a 'tracker' key (set by pfb_tracker). */
	private function assertTrackersSet(array $result, string $context = ''): void
	{
		foreach ($result as $i => $rule) {
			$descr = $rule['descr'] ?? "(rule {$i})";
			// Only pfB-generated rules (those from $pfb_generated) get trackers assigned;
			// user rules pass through without tracker. Skip user rules.
			if (!str_starts_with($descr, 'pfB_') || str_starts_with($descr, 'pfB_DNS_Redirect_')
			    || str_starts_with($descr, 'pfB_DoT_Block_')) {
				continue;
			}
			$this->assertArrayHasKey('tracker', $rule,
				"pfB rule [{$i}] '{$descr}' must have 'tracker' key set by pfb_tracker()");
		}
	}

	// -----------------------------------------------------------------------
	// A. order_0, float=off, inbound==outbound='lan', Deny_* only
	// -----------------------------------------------------------------------

	public function testOrder0FloatOffSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 0, float off, single managed iface (lan), Deny_* pfB rules.
		 *
		 * Given: existing rules = [pfB deny (stripped), user pass LAN].
		 *        pfB generated = deny_inbound + deny_outbound templates.
		 *        order=order_0, float=off, in+out ifaces = ['lan'].
		 *
		 * ORDER 0: pfB (p/m/b/r) | All other
		 * Expected order: pfB deny_in(lan), pfB deny_out(lan), user_pass(lan)
		 *
		 * user pass goes to $other_rules (order_0 -> order_0 pass -> other_rules).
		 * Tail: order!=order_4 -> other_rules emitted last.
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_0 float=off single iface');
		$this->assertTrackersSet($result, 'order_0 float=off');
	}

	// -----------------------------------------------------------------------
	// B. order_0, float=on, single iface, Deny_* only
	// -----------------------------------------------------------------------

	public function testOrder0FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 0, float=on. user floating pass goes to $fother_rules
		 * (order_0 + floating='yes' -> fother_rules).
		 *
		 * ORDER 0 float on:
		 *   - No pre-loop float emit (order_1 only).
		 *   - pfB deny_in(lan), pfB deny_out(lan).
		 *   - Tail: float=on + order_0/3/4 -> fother/fpermit/fmatch (fother_rules only here).
		 *   - order!=order_4 -> other_rules (none here).
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user float pass.
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->userFloatPass(),
			$this->userPassLan(),      // non-floating: goes to $other_rules (float=on branch)
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', 'on', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'User Float Pass',            'type' => 'pass',   'interface' => '',    'floating' => 'yes'],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_0 float=on');
		$this->assertTrackersSet($result, 'order_0 float=on');
	}

	// -----------------------------------------------------------------------
	// C. order_1, float=off, inbound==outbound='lan'  [KNOWN-BAD: duplication]
	// -----------------------------------------------------------------------

	public function testOrder1FloatOffSingleIfaceDenyOnlyKnownBadDuplicate(): void
	{
		/**
		 * Scenario: ORDER 1, float=off, SAME interface for inbound AND outbound.
		 *
		 * KNOWN-BAD: The user LAN pass rule goes into $permit_rules.
		 * It is emitted once in the inbound loop (order_1 permit_rules for 'lan')
		 * AND once in the outbound loop (order_1 permit_rules for 'lan').
		 * Result: user rule appears TWICE. This is the duplication bug.
		 * Phase 3 fixes this — Phase 1 pins it as "what it does today".
		 *
		 * ORDER 1: pfSense(p/m) | pfB(p/m) | pfB(b/r) | pfSense(b/r)
		 * Expected: user_pass(lan) [inbound], pfB deny_in(lan),
		 *           user_pass(lan) [outbound — DUPLICATE], pfB deny_out(lan)
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_1', '', ['lan'], ['lan']);

		// KNOWN-BAD: user rule appears twice (once per loop iteration).
		$this->assertShapes([
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'order_1 float=off single iface [KNOWN-BAD: duplicate]');
	}

	// -----------------------------------------------------------------------
	// D. order_1, float=off, inbound!=outbound ('lan' in, 'opt1' out)
	// -----------------------------------------------------------------------

	public function testOrder1FloatOffSeparateIfacesDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 1, float=off, separate inbound (lan) and outbound (opt1).
		 *
		 * User pass rules on both interfaces go to $permit_rules.
		 * In the inbound loop: user pass LAN emitted for 'lan' iface.
		 * In the outbound loop: user pass OPT1 emitted for 'opt1' iface.
		 * No duplication because interfaces differ.
		 *
		 * Expected: user_pass(lan), pfB deny_in(lan), user_pass(opt1), pfB deny_out(opt1)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->pfbDenyRule('opt1'),
			$this->userPassLan(),
			$this->userPassOpt1(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_1', '', ['lan'], ['opt1']);

		$this->assertShapes([
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow OPT1 to any', 'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_1 float=off separate ifaces');
		$this->assertTrackersSet($result, 'order_1 float=off separate');
	}

	// -----------------------------------------------------------------------
	// E. order_1, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder1FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 1, float=on. User float pass goes to $fpermit_rules.
		 * Non-floating user pass goes to $other_rules (float=on, non-floating).
		 *
		 * ORDER 1 float=on:
		 *   Pre-loop: fpermit_rules + fmatch_rules emitted.
		 *   Inbound loop: pfB deny_in(lan).
		 *   Outbound loop: pfB deny_out(lan).
		 *   Tail: float=on + order_1/2 -> fother_rules (none here).
		 *   order!=order_4 -> other_rules (non-floating user pass).
		 * Expected: user_float_pass, pfB deny_in(lan), pfB deny_out(lan), user_pass(lan)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->userFloatPass(),
			$this->userPassLan(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_1', 'on', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'User Float Pass',            'type' => 'pass',   'interface' => '',    'floating' => 'yes'],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_1 float=on single iface');
		$this->assertTrackersSet($result, 'order_1 float=on');
	}

	// -----------------------------------------------------------------------
	// F. order_2, float=off, inbound==outbound='lan'  [KNOWN-BAD: duplication]
	// -----------------------------------------------------------------------

	public function testOrder2FloatOffSingleIfaceDenyOnlyKnownBadDuplicate(): void
	{
		/**
		 * Scenario: ORDER 2, float=off, SAME interface for inbound AND outbound.
		 *
		 * KNOWN-BAD: The user LAN pass rule goes into $permit_rules.
		 * ORDER 2 emits permit_rules in the inbound loop (matching iface) AND
		 * in the outbound loop (matching iface). Same duplication as order_1.
		 *
		 * ORDER 2: pfB(p/m) | pfSense(p/m) | pfB(b/r) | pfSense(b/r)
		 * Expected: pfB deny_in(lan), user_pass(lan) [inbound],
		 *           pfB deny_out(lan) [outbound], user_pass(lan) [outbound — DUPLICATE]
		 *
		 * Wait — order_2 emits: (inbound loop) pfB permit_in, [order_2: fpermit+fmatch+permit],
		 * pfB deny_in. Then (outbound loop) pfB permit_out, [order_2: permit], pfB deny_out.
		 * Here no pfB permit rules, so:
		 *   inbound:  [order_2: permit_rules matching lan] = user_pass(lan), pfB deny_in(lan)
		 *   outbound: [order_2: permit_rules matching lan] = user_pass(lan), pfB deny_out(lan)
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_2', '', ['lan'], ['lan']);

		// KNOWN-BAD: user rule appears twice.
		$this->assertShapes([
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'order_2 float=off single iface [KNOWN-BAD: duplicate]');
	}

	// -----------------------------------------------------------------------
	// G. order_2, float=off, inbound!=outbound
	// -----------------------------------------------------------------------

	public function testOrder2FloatOffSeparateIfacesDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 2, float=off, separate ifaces (lan in, opt1 out).
		 * No duplication because inbound and outbound filters by iface.
		 *
		 * Inbound: [order_2 permit(lan)], pfB deny_in(lan)
		 * Outbound: [order_2 permit(opt1)], pfB deny_out(opt1)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->pfbDenyRule('opt1'),
			$this->userPassLan(),
			$this->userPassOpt1(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_2', '', ['lan'], ['opt1']);

		$this->assertShapes([
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow OPT1 to any', 'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_2 float=off separate ifaces');
		$this->assertTrackersSet($result, 'order_2 float=off separate');
	}

	// -----------------------------------------------------------------------
	// H. order_2, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder2FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 2, float=on. User float pass -> fpermit_rules.
		 * Non-floating user pass -> other_rules.
		 *
		 * float=on order_2: fpermit+fmatch emitted inside the first inbound loop iter
		 * (order_2 block).  No pfB permit_in templates.
		 * Outbound loop: order_2 block skipped (no permit_rules when float=on).
		 * Tail: float=on, order_2 -> fother_rules (none).
		 * order!=order_4 -> other_rules.
		 * Expected: fpermit(first inbound iter), pfB deny_in, pfB deny_out, user_pass(lan)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->userFloatPass(),
			$this->userPassLan(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_2', 'on', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'User Float Pass',            'type' => 'pass',   'interface' => '',    'floating' => 'yes'],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_2 float=on single iface');
		$this->assertTrackersSet($result, 'order_2 float=on');
	}

	// -----------------------------------------------------------------------
	// I. order_3, float=off, single iface
	// -----------------------------------------------------------------------

	public function testOrder3FloatOffSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 3, float=off.
		 * ORDER 3: pfB(p/m) | pfB(b/r) | pfSense(p/m) | pfSense(b/r)
		 *
		 * permit_rules used in the tail (order_3 -> emit permit_rules after interface loops).
		 * user pass LAN -> $permit_rules (order_3, not order_0).
		 *
		 * Inbound: pfB deny_in(lan)  [no permit_rules in inbound loop for order_3]
		 * Outbound: pfB deny_out(lan) [same]
		 * Tail: order_3 -> permit_rules (user pass), other_rules (none)
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_pass(lan)
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_3', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_3 float=off single iface');
		$this->assertTrackersSet($result, 'order_3 float=off');
	}

	// -----------------------------------------------------------------------
	// J. order_3, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder3FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 3, float=on. User float pass -> $fpermit_rules.
		 * Non-floating user pass -> other_rules.
		 *
		 * float=on order_3: tail emits fpermit+fmatch+fother (order_3 rule_order).
		 * Expected: pfB deny_in(lan), pfB deny_out(lan),
		 *           user_float_pass (in fpermit tail), user_pass(lan) (other_rules tail)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->userFloatPass(),
			$this->userPassLan(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_3', 'on', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'User Float Pass',            'type' => 'pass',   'interface' => '',    'floating' => 'yes'],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_3 float=on single iface');
		$this->assertTrackersSet($result, 'order_3 float=on');
	}

	// -----------------------------------------------------------------------
	// K. order_4, float=off, inbound==outbound='lan'  [KNOWN-BAD: reorder]
	// -----------------------------------------------------------------------

	public function testOrder4FloatOffSingleIfaceDenyOnlyKnownBadReorder(): void
	{
		/**
		 * Scenario: ORDER 4, float=off.
		 * ORDER 4: pfB(p/m) | pfB(b/r) | pfSense(b/r) | pfSense(p/m)
		 *
		 * user pass LAN -> $permit_rules.
		 * Inbound: pfB deny_in(lan).
		 * Outbound: pfB deny_out(lan).
		 * Tail: order_4 -> other_rules (none here), then permit_rules.
		 *       order_4: NOT emitting other_rules at the end.
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_pass(lan)
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_4', '', ['lan'], ['lan']);

		// order_4 tail: other_rules first (empty), then permit_rules.
		// No duplication because neither inbound nor outbound loops emit permit_rules for order_4.
		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_4 float=off single iface');
		$this->assertTrackersSet($result, 'order_4 float=off');
	}

	public function testOrder4FloatOffTwoIfacesKnownBadReorder(): void
	{
		/**
		 * Scenario: ORDER 4, float=off, two managed ifaces (opt1 inbound, lan outbound).
		 *
		 * KNOWN-BAD: The original code has TWO managed ifaces but the opt1 rule
		 * comes from the inbound loop and the lan rule from the outbound loop.
		 * Both go to $permit_rules, emitted in the tail in config.xml ORDER (opt1 first,
		 * lan second) — which inverts their original position relative to each other
		 * if the factory config had lan before opt1.
		 *
		 * This test pins the existing reorder behaviour as-is.
		 */

		$existing = [
			$this->pfbDenyRule('opt1'),
			$this->pfbDenyRule('lan'),
			$this->userPassLan(),
			$this->userPassOpt1(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		// inbound='opt1', outbound='lan' — mimics a config where opt1 is the inbound iface.
		$result = pfb_build_autorule_list($existing, $gen, 'order_4', '', ['opt1'], ['lan']);

		// ORDER 4 tail: other_rules (none), permit_rules (lan then opt1 — in $permit_rules order),
		// NOT order_4 "other_rules at end" — the condition is order!=order_4.
		// permit_rules order: userPassLan first (appears before userPassOpt1 in existing_rules
		// and both match managed ifaces), so lan first then opt1.
		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow OPT1 to any', 'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_4 float=off two ifaces [KNOWN-BAD: reorder]');
	}

	// -----------------------------------------------------------------------
	// L. order_4, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder4FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 4, float=on. User float pass -> fpermit_rules.
		 * Non-floating user pass -> other_rules.
		 *
		 * float=on order_4: tail emits fother+fpermit+fmatch (order_4 rule_order).
		 * order_4: other_rules tail (before permit_rules). No permit_rules.
		 * Expected: pfB deny_in, pfB deny_out, user_float_pass (fpermit), user_pass(other_rules tail)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->userFloatPass(),
			$this->userPassLan(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_4', 'on', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'User Float Pass',            'type' => 'pass',   'interface' => '',    'floating' => 'yes'],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_4 float=on single iface');
		$this->assertTrackersSet($result, 'order_4 float=on');
	}

	// -----------------------------------------------------------------------
	// M. absent/empty pass_order -> treated as order_0 (the #532 default fix)
	// -----------------------------------------------------------------------

	public function testAbsentOrderTreatedAsOrder0(): void
	{
		/**
		 * Scenario: empty pass_order string (absent). Should behave identically to
		 * order_0 — user pass rule goes to other_rules, never to permit_rules.
		 *
		 * (The order_0 default is applied by the caller before pfb_build_autorule_list();
		 *  this test passes an empty string to verify the helper doesn't mis-handle it.)
		 *
		 * With empty order: no branch matches order_1/2/3/4, so:
		 *   - bucket: pass rule on managed iface, empty string != 'order_0', so
		 *     the helper uses else -> permit_rules.
		 * Wait — the helper checks: if ($order == 'order_0') -> other_rules, else -> permit_rules.
		 * So empty order -> permit_rules, NOT other_rules. The rule is then emitted only in
		 * the tail if order_3/order_4... neither matches, so it is NEVER emitted.
		 *
		 * This is the DROP bug (#532). The caller defaults empty to 'order_0' before calling
		 * the helper. This test verifies the helper with a raw empty string to pin what
		 * IT does (the drop) — the protection lives in the caller's defaulting.
		 *
		 * With empty order string: permit_rules populated but no order_1/2/3/4 tail emits them.
		 * Result: pfB rules emitted, user pass rule DROPPED.
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		// Empty order: user pass goes to permit_rules but no tail emits permit_rules for ''.
		$result = pfb_build_autorule_list($existing, $gen, '', '', ['lan'], ['lan']);

		// User pass is dropped (no tail for unknown order); pfB rules still emitted.
		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'empty order -> user rule dropped (caller must default to order_0)');
	}

	// -----------------------------------------------------------------------
	// N. Permit_* config present (order_1, float=off, separate ifaces)
	// -----------------------------------------------------------------------

	public function testOrder1FloatOffPermitAndDenyRulesPresent(): void
	{
		/**
		 * Scenario: pfB has BOTH permit_inbound and deny_inbound (Permit_* list present).
		 * order_1, float=off, separate ifaces (lan in, opt1 out).
		 *
		 * ORDER 1: pfSense(p/m) first, then pfB(p/m), then pfB(b/r), then pfSense(b/r).
		 * Inbound: user_pass(lan) [permit_rules, order_1], pfB permit_in(lan), pfB deny_in(lan)
		 * Outbound: user_pass(opt1) [permit_rules, order_1], pfB permit_out(opt1), pfB deny_out(opt1)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->pfbDenyRule('opt1'),
			$this->userPassLan(),
			$this->userPassOpt1(),
		];
		$gen = $this->pfbGeneratedPermitAndDeny();

		$result = pfb_build_autorule_list($existing, $gen, 'order_1', '', ['lan'], ['opt1']);

		$this->assertShapes([
			['descr' => 'Default allow LAN to any',      'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_PermitList_v4 Auto Rule',   'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule',     'type' => 'block',  'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow OPT1 to any',     'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_PermitList_v4 Auto Rule',   'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule',     'type' => 'reject', 'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_1 float=off Permit_* + Deny_* separate ifaces');
		$this->assertTrackersSet($result, 'order_1 permit+deny');
	}

	// -----------------------------------------------------------------------
	// O. DNS-redirect bypass rule present — must survive (not stripped)
	// -----------------------------------------------------------------------

	public function testDnsRedirectBypassRulePreserved(): void
	{
		/**
		 * Scenario: existing rules include a DNS-redirect bypass rule.
		 * Its descr starts with PFB_DNS_REDIR_DESCR_V4_PFX ('pfB_DNS_Redirect_').
		 * The helper must treat it like a user rule — NOT strip it.
		 *
		 * order_0, float=off. Bypass rule is on 'lan', treated as other_rules (non-pass? no —
		 * it's type='pass', so order_0 -> other_rules because order_0 pass -> other_rules).
		 *
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), bypass_rule(lan), user_pass(lan)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->dnsRedirectBypassRule(),
			$this->userPassLan(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DNS_Redirect_lan_v4',   'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'DNS-redirect bypass rule preserved (not stripped)');
	}

	// -----------------------------------------------------------------------
	// P. DoT-block bypass rule present — must survive (not stripped)
	// -----------------------------------------------------------------------

	public function testDotBlockBypassRulePreserved(): void
	{
		/**
		 * Scenario: existing rules include a DoT-block bypass rule.
		 * Its descr starts with PFB_DOT_BLOCK_DESCR_PFX ('pfB_DoT_Block_').
		 * Must be preserved like a user rule.
		 *
		 * order_0, float=off. DoT rule type='block' -> not a pass rule -> other_rules.
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), dot_block_rule(lan), user_pass(lan)
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->dotBlockBypassRule(),
			$this->userPassLan(),
		];
		$gen = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DoT_Block_lan',         'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'DoT-block bypass rule preserved (not stripped)');
	}

	// -----------------------------------------------------------------------
	// Q. pfB_ rules stripped (sanity check)
	// -----------------------------------------------------------------------

	public function testPfbRulesAreStripped(): void
	{
		/**
		 * Scenario: existing rules contain only a pfB_ deny rule (no bypass prefix).
		 * It must be stripped and rebuilt from the template.
		 * Result: exactly the rebuilt pfB rules, no user rules.
		 */

		$existing = [$this->pfbDenyRule('lan')];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'pfB_ rules stripped and rebuilt');
		$this->assertTrackersSet($result, 'pfB stripped');
	}

	// -----------------------------------------------------------------------
	// R. DNSBL float rules emitted when present
	// -----------------------------------------------------------------------

	public function testDnsblFloatRulesEmittedBeforeIfaceLoop(): void
	{
		/**
		 * Scenario: pfb_generated['dnsbl_float'] contains the pre-built ping+permit pair.
		 * They must appear BEFORE the inbound/outbound interface rules.
		 *
		 * order_0, float=off.
		 * Expected: dnsbl_ping, dnsbl_permit, pfB deny_in(lan), pfB deny_out(lan), user_pass(lan)
		 */

		$existing = [$this->userPassLan()];

		$gen                 = $this->pfbGeneratedDenyOnly();
		$gen['dnsbl_float']  = [
			['descr' => 'pfB_DNSBL_Ping Auto Rule',   'type' => 'pass', 'interface' => 'opt2', 'floating' => 'yes',
			 'direction' => 'any', 'ipprotocol' => 'inet', 'source' => ['any' => ''],
			 'destination' => ['address' => '10.0.0.1'], 'created' => ['time' => 0, 'username' => 'Auto']],
			['descr' => 'pfB_DNSBL_Permit Auto Rule', 'type' => 'pass', 'interface' => 'opt2', 'floating' => 'yes',
			 'direction' => 'any', 'ipprotocol' => 'inet', 'source' => ['any' => ''],
			 'destination' => ['address' => '10.0.0.1', 'port' => 'pfB_DNSBL_Ports'],
			 'created' => ['time' => 0, 'username' => 'Auto']],
		];

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DNSBL_Ping Auto Rule',   'type' => 'pass',   'interface' => 'opt2', 'floating' => 'yes'],
			['descr' => 'pfB_DNSBL_Permit Auto Rule', 'type' => 'pass',   'interface' => 'opt2', 'floating' => 'yes'],
			['descr' => 'pfB_DenyList_v4 Auto Rule',  'type' => 'block',  'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule',  'type' => 'reject', 'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow LAN to any',   'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
		], $result, 'DNSBL float rules emitted before iface loop');
	}

	// -----------------------------------------------------------------------
	// S. Empty existing rules — no user rules, no pfB old rules
	// -----------------------------------------------------------------------

	public function testEmptyExistingRulesProducesOnlyPfbRules(): void
	{
		/**
		 * Scenario: no existing rules at all. Only pfB templates.
		 */

		$result = pfb_build_autorule_list([], $this->pfbGeneratedDenyOnly(), 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'empty existing rules');
		$this->assertTrackersSet($result, 'empty existing');
	}

	// -----------------------------------------------------------------------
	// T. Non-managed iface user rule goes to other_rules (float=off)
	// -----------------------------------------------------------------------

	public function testNonManagedIfaceRuleGoesToOtherRules(): void
	{
		/**
		 * Scenario: user rule on 'wan' — NOT in the managed inbound/outbound iface list.
		 * float=off. Should go to $other_rules, emitted at the end.
		 * order_0, managed=['lan'].
		 */

		$nonManagedRule = [
			'descr'       => 'WAN rule',
			'type'        => 'pass',
			'interface'   => 'wan',
			'ipprotocol'  => 'inet',
			'floating'    => '',
			'source'      => ['any' => ''],
			'destination' => ['any' => ''],
		];

		$existing = [$nonManagedRule, $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', '', ['lan'], ['lan']);

		// Non-managed rules go to other_rules (with order_0 managed rules too).
		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'WAN rule',                  'type' => 'pass',   'interface' => 'wan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'non-managed iface rule goes to other_rules (after managed)');
	}

	/**
	 * Regression: a null $float / $order must be tolerated exactly as ''.
	 *
	 * The call site passes $pfb['float'] / $pfb['order'] straight through, and those are
	 * unset (null) until configured (e.g. enable_float not set). The original inline code
	 * used the raw null in loose comparisons, so null is behaviour-equivalent to ''. The
	 * Phase-1 extraction's strict `string` typehint instead TypeError'd on the null the call
	 * site legitimately passes -- which on a live VM aborted `pfblockerng.php update` with a
	 * fatal ("Argument #4 ($float) must be of type string, null given"), so no pfB rule was
	 * built. This pins that the null path produces the SAME output as the empty-string path.
	 */
	public function testNullOrderAndFloatTreatedAsEmptyString(): void
	{
		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$withEmpty = pfb_build_autorule_list($existing, $gen, '', '', ['lan'], ['lan']);
		$withNull  = pfb_build_autorule_list($existing, $gen, null, null, ['lan'], ['lan']);

		$this->assertSame(
			$this->shapes($withEmpty),
			$this->shapes($withNull),
			'null $order/$float must behave identically to empty-string (regression for the live '
				. 'TypeError that aborted the update verb when enable_float was unset)'
		);
	}
}
