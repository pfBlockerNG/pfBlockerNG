<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Contract tests for pfb_build_autorule_list() — ADR-41 Phase 3.
 *
 * Three invariants hold for every fixture (ADR-41 §2 Decision table):
 *   (a) USER-RULE FIDELITY: every non-pfB rule in $existing_rules appears in the output
 *       in the SAME relative order and with the SAME count (no drop, no dup, no reorder).
 *   (b) PFB-SET IDENTICAL: the pfB rules emitted are the same set (descr/type/interface/
 *       floating) as would have been generated from the same $pfb_generated inputs.
 *   (c) IDEMPOTENCE: running the helper on its own output is a no-op (second pass
 *       produces the same result as the first).
 *
 * Anchor mapping (per-interface first-match — live-confirmed, ADR-41 Phase 2):
 *   order_1 / order_2           → pfB block AFTER  kept user rules (user pass wins)
 *   order_0 / order_3 / order_4 → pfB block BEFORE kept user rules (pfB wins)
 *   absent / unknown            → BEFORE (subsumes #539 drop bug)
 *
 * Fixture matrix covered (each pass_order × float on/off unless noted):
 *   A. order_0,  float=off, inbound==outbound ('lan'), Deny_* only
 *   B. order_0,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   C. order_1,  float=off, inbound==outbound ('lan'), Deny_* only
 *   D. order_1,  float=off, inbound!=outbound ('lan'+'opt1'), Deny_* only
 *   E. order_1,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   F. order_2,  float=off, inbound==outbound ('lan'), Deny_* only
 *   G. order_2,  float=off, inbound!=outbound ('lan'+'opt1'), Deny_* only
 *   H. order_2,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   I. order_3,  float=off, inbound==outbound ('lan'), Deny_* only
 *   J. order_3,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   K. order_4,  float=off, inbound==outbound ('lan'), Deny_* only
 *   L. order_4,  float=off, two ifaces (opt1 in, lan out)
 *   M. order_4,  float=on,  inbound==outbound ('lan'), Deny_* only
 *   N. absent/empty pass_order, float=off — treated as BEFORE (same as order_0)
 *   O. Permit_* (permit_inbound + permit_outbound) present, order_1, float=off
 *   P. DNS-redirect bypass rule present (pfB_ descr but NOT stripped), order_0, float=off
 *   Q. DoT-block bypass rule present, order_0, float=off
 *   R. pfB_ rules stripped and rebuilt (sanity)
 *   S. DNSBL float rules emitted before iface loop
 *   T. Empty existing rules → only pfB rules
 *   U. Non-managed iface user rule preserved in output
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

	/**
	 * CONTRACT (a): every non-pfB rule from $input appears in $output in the same
	 * relative order with the same count. A rule is pfB-owned iff its descr starts
	 * with 'pfB_' AND it is NOT a bypass rule (DNS-redirect / DoT-block).
	 *
	 * Fails on: user-rule drop (count < input), duplication (count > input), or reorder.
	 *
	 * @param array<int, array<string, mixed>> $input
	 * @param array<int, array<string, mixed>> $output
	 */
	private function assertUserRulesPreserved(array $input, array $output, string $context = ''): void
	{
		$is_user = static function (array $rule): bool {
			$descr = $rule['descr'] ?? '';
			if (!str_starts_with($descr, 'pfB_')) {
				return TRUE;
			}
			return str_starts_with($descr, 'pfB_DNS_Redirect_') ||
			       str_starts_with($descr, 'pfB_DoT_Block_');
		};

		$user_in  = array_values(array_filter($input,  $is_user));
		$user_out = array_values(array_filter($output, $is_user));

		$label = $context !== '' ? " [{$context}]" : '';
		$this->assertSame(
			$this->shapes($user_in),
			$this->shapes($user_out),
			"User-rule fidelity failure{$label}: non-pfB rules must be preserved exactly "
				. "(same set, count, and original relative order — no drop, dup, or reorder)."
				. "\n\nExpected (input user rules):\n"  . json_encode($this->shapes($user_in),  JSON_PRETTY_PRINT)
				. "\n\nActual (output user rules):\n"   . json_encode($this->shapes($user_out), JSON_PRETTY_PRINT)
		);
	}

	/**
	 * CONTRACT (c): running the helper on its own output is a no-op.
	 *
	 * Second-pass $existing_rules = first-pass $output. Same $pfb_generated / $order / $float /
	 * $in_ifaces / $out_ifaces. Result must be shape-identical to the first pass.
	 *
	 * @param array<int, array<string, mixed>> $output
	 * @param array<int, string>               $in_ifaces
	 * @param array<int, string>               $out_ifaces
	 */
	private function assertIdempotent(
		array  $output,
		array  $gen,
		string $order,
		string $float,
		array  $in_ifaces,
		array  $out_ifaces,
		string $context = ''
	): void {
		$second = pfb_build_autorule_list($output, $gen, $order, $float, $in_ifaces, $out_ifaces);
		$label  = $context !== '' ? " [{$context}]" : '';
		$this->assertSame(
			$this->shapes($output),
			$this->shapes($second),
			"Idempotence failure{$label}: running the helper on its own output must be a no-op."
				. "\n\nFirst pass:\n"  . json_encode($this->shapes($output), JSON_PRETTY_PRINT)
				. "\n\nSecond pass:\n" . json_encode($this->shapes($second), JSON_PRETTY_PRINT)
		);
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
		 * ORDER 0 anchor = BEFORE: pfB block first, then kept user rules.
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_pass(lan)
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
		$this->assertUserRulesPreserved($existing, $result, 'order_0 float=off');
		$this->assertIdempotent($result, $gen, 'order_0', '', ['lan'], ['lan'], 'order_0 float=off');
	}

	// -----------------------------------------------------------------------
	// B. order_0, float=on, single iface, Deny_* only
	// -----------------------------------------------------------------------

	public function testOrder0FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 0, float=on.
		 *
		 * ORDER 0 anchor = BEFORE: pfB block first, then kept user rules verbatim.
		 * keep = [user_float_pass, user_pass(lan)] (original order; pfB deny stripped).
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_float_pass, user_pass(lan).
		 *
		 * pf evaluates floating rules in a separate group regardless of config.xml
		 * interleaving, so the relative position of user_float_pass vs interface rules
		 * in config.xml does not affect pf precedence.
		 */

		$existing = [
			$this->pfbDenyRule('lan'),
			$this->userFloatPass(),
			$this->userPassLan(),
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
		$this->assertUserRulesPreserved($existing, $result, 'order_0 float=on');
		$this->assertIdempotent($result, $gen, 'order_0', 'on', ['lan'], ['lan'], 'order_0 float=on');
	}

	// -----------------------------------------------------------------------
	// C. order_1, float=off, inbound==outbound='lan'  [KNOWN-BAD: duplication]
	// -----------------------------------------------------------------------

	public function testOrder1FloatOffSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 1, float=off, SAME interface for inbound AND outbound ('lan').
		 *
		 * ORDER 1 anchor = AFTER: kept user rules first, then pfB block.
		 * keep = [user_pass(lan)] (pfB deny stripped; no dup — verbatim keep).
		 * pfB block = [deny_in(lan), deny_out(lan)].
		 * Expected: user_pass(lan), pfB deny_in(lan), pfB deny_out(lan).
		 *
		 * Fail-before: old bucket-per-iface code emitted user_pass TWICE (once per loop
		 * over the shared 'lan' interface). The immutable-splice model strips pfB rules
		 * and keeps the verbatim user list exactly once — no dup possible.
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_1', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'order_1 float=off single iface');
		$this->assertTrackersSet($result, 'order_1 float=off single');
		$this->assertUserRulesPreserved($existing, $result, 'order_1 float=off single');
		$this->assertIdempotent($result, $gen, 'order_1', '', ['lan'], ['lan'], 'order_1 float=off single');
	}

	// -----------------------------------------------------------------------
	// D. order_1, float=off, inbound!=outbound ('lan' in, 'opt1' out)
	// -----------------------------------------------------------------------

	public function testOrder1FloatOffSeparateIfacesDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 1, float=off, separate inbound (lan) and outbound (opt1).
		 *
		 * ORDER 1 anchor = AFTER: all kept user rules first (verbatim), then pfB block.
		 * keep = [user_pass(lan), user_pass(opt1)] (original order).
		 * pfB block = [deny_in(lan), deny_out(opt1)].
		 * Expected: user_pass(lan), user_pass(opt1), pfB deny_in(lan), pfB deny_out(opt1).
		 *
		 * Under per-interface first-match pf semantics the pfB-block-vs-user-BLOCK ordering
		 * is moot; only pfB-block-vs-user-PASS matters, and both user pass rules precede
		 * both pfB deny rules — user wins on both interfaces.
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
			['descr' => 'Default allow OPT1 to any', 'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_1 float=off separate ifaces');
		$this->assertTrackersSet($result, 'order_1 float=off separate');
		$this->assertUserRulesPreserved($existing, $result, 'order_1 float=off separate');
		$this->assertIdempotent($result, $gen, 'order_1', '', ['lan'], ['opt1'], 'order_1 float=off separate');
	}

	// -----------------------------------------------------------------------
	// E. order_1, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder1FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 1, float=on.
		 *
		 * ORDER 1 anchor = AFTER: all kept user rules first (verbatim), then pfB block.
		 * keep = [user_float_pass, user_pass(lan)] (original order; pfB deny stripped).
		 * pfB block = [deny_in(lan), deny_out(lan)].
		 * Expected: user_float_pass, user_pass(lan), pfB deny_in(lan), pfB deny_out(lan).
		 *
		 * pf evaluates floating rules in a separate group regardless of config.xml
		 * interleaving, so the relative position of user_float_pass vs interface rules
		 * in config.xml does not affect pf precedence.
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
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'order_1 float=on single iface');
		$this->assertTrackersSet($result, 'order_1 float=on');
		$this->assertUserRulesPreserved($existing, $result, 'order_1 float=on');
		$this->assertIdempotent($result, $gen, 'order_1', 'on', ['lan'], ['lan'], 'order_1 float=on');
	}

	// -----------------------------------------------------------------------
	// F. order_2, float=off, inbound==outbound='lan'  [KNOWN-BAD: duplication]
	// -----------------------------------------------------------------------

	public function testOrder2FloatOffSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 2, float=off, SAME interface for inbound AND outbound ('lan').
		 *
		 * ORDER 2 anchor = AFTER: kept user rules first (verbatim), then pfB block.
		 * keep = [user_pass(lan)] (pfB deny stripped; no dup).
		 * pfB block = [deny_in(lan), deny_out(lan)].
		 * Expected: user_pass(lan), pfB deny_in(lan), pfB deny_out(lan).
		 *
		 * Fail-before: old bucket-based code emitted user_pass TWICE (once per iface loop
		 * iteration). The immutable-splice model keeps the verbatim list exactly once.
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_2', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'order_2 float=off single iface');
		$this->assertTrackersSet($result, 'order_2 float=off single');
		$this->assertUserRulesPreserved($existing, $result, 'order_2 float=off single');
		$this->assertIdempotent($result, $gen, 'order_2', '', ['lan'], ['lan'], 'order_2 float=off single');
	}

	// -----------------------------------------------------------------------
	// G. order_2, float=off, inbound!=outbound
	// -----------------------------------------------------------------------

	public function testOrder2FloatOffSeparateIfacesDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 2, float=off, separate ifaces (lan in, opt1 out).
		 *
		 * ORDER 2 anchor = AFTER: all kept user rules first (verbatim), then pfB block.
		 * keep = [user_pass(lan), user_pass(opt1)] (original order).
		 * pfB block = [deny_in(lan), deny_out(opt1)].
		 * Expected: user_pass(lan), user_pass(opt1), pfB deny_in(lan), pfB deny_out(opt1).
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
			['descr' => 'Default allow OPT1 to any', 'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_2 float=off separate ifaces');
		$this->assertTrackersSet($result, 'order_2 float=off separate');
		$this->assertUserRulesPreserved($existing, $result, 'order_2 float=off separate');
		$this->assertIdempotent($result, $gen, 'order_2', '', ['lan'], ['opt1'], 'order_2 float=off separate');
	}

	// -----------------------------------------------------------------------
	// H. order_2, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder2FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 2, float=on.
		 *
		 * ORDER 2 anchor = AFTER: all kept user rules first (verbatim), then pfB block.
		 * keep = [user_float_pass, user_pass(lan)] (original order; pfB deny stripped).
		 * pfB block = [deny_in(lan), deny_out(lan)].
		 * Expected: user_float_pass, user_pass(lan), pfB deny_in(lan), pfB deny_out(lan).
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
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'order_2 float=on single iface');
		$this->assertTrackersSet($result, 'order_2 float=on');
		$this->assertUserRulesPreserved($existing, $result, 'order_2 float=on');
		$this->assertIdempotent($result, $gen, 'order_2', 'on', ['lan'], ['lan'], 'order_2 float=on');
	}

	// -----------------------------------------------------------------------
	// I. order_3, float=off, single iface
	// -----------------------------------------------------------------------

	public function testOrder3FloatOffSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 3, float=off.
		 *
		 * ORDER 3 anchor = BEFORE: pfB block first, then kept user rules.
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_pass(lan).
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
		$this->assertUserRulesPreserved($existing, $result, 'order_3 float=off');
		$this->assertIdempotent($result, $gen, 'order_3', '', ['lan'], ['lan'], 'order_3 float=off');
	}

	// -----------------------------------------------------------------------
	// J. order_3, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder3FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 3, float=on.
		 *
		 * ORDER 3 anchor = BEFORE: pfB block first, then kept user rules verbatim.
		 * keep = [user_float_pass, user_pass(lan)] (original order).
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_float_pass, user_pass(lan).
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
		$this->assertUserRulesPreserved($existing, $result, 'order_3 float=on');
		$this->assertIdempotent($result, $gen, 'order_3', 'on', ['lan'], ['lan'], 'order_3 float=on');
	}

	// -----------------------------------------------------------------------
	// K. order_4, float=off, inbound==outbound='lan'  [KNOWN-BAD: reorder]
	// -----------------------------------------------------------------------

	public function testOrder4FloatOffSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 4, float=off, single managed iface (lan).
		 *
		 * ORDER 4 anchor = BEFORE: pfB block first, then kept user rules verbatim.
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_pass(lan).
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_4', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'order_4 float=off single iface');
		$this->assertTrackersSet($result, 'order_4 float=off');
		$this->assertUserRulesPreserved($existing, $result, 'order_4 float=off');
		$this->assertIdempotent($result, $gen, 'order_4', '', ['lan'], ['lan'], 'order_4 float=off');
	}

	public function testOrder4FloatOffTwoIfacesDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 4, float=off, two managed ifaces (opt1 inbound, lan outbound).
		 *
		 * ORDER 4 anchor = BEFORE: pfB block first, then kept user rules verbatim.
		 * keep = [user_pass(lan), user_pass(opt1)] (original order in existing_rules).
		 * pfB block = [deny_in(opt1), deny_out(lan)].
		 * Expected: pfB deny_in(opt1), pfB deny_out(lan), user_pass(lan), user_pass(opt1).
		 *
		 * The deliberate behaviour change from Phase 1's KNOWN-BAD oracle: the old bucket-based
		 * code emitted user rules in accumulated-bucket order (also lan then opt1 for this
		 * fixture, but would diverge for a different existing_rules order). The immutable-splice
		 * always preserves the original config.xml order verbatim.
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

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
			['descr' => 'Default allow OPT1 to any', 'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_4 float=off two ifaces');
		$this->assertTrackersSet($result, 'order_4 float=off two ifaces');
		$this->assertUserRulesPreserved($existing, $result, 'order_4 float=off two ifaces');
		$this->assertIdempotent($result, $gen, 'order_4', '', ['opt1'], ['lan'], 'order_4 float=off two ifaces');
	}

	// -----------------------------------------------------------------------
	// L. order_4, float=on, single iface
	// -----------------------------------------------------------------------

	public function testOrder4FloatOnSingleIfaceDenyOnly(): void
	{
		/**
		 * Scenario: ORDER 4, float=on.
		 *
		 * ORDER 4 anchor = BEFORE: pfB block first, then kept user rules verbatim.
		 * keep = [user_float_pass, user_pass(lan)] (original order).
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_float_pass, user_pass(lan).
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
		$this->assertUserRulesPreserved($existing, $result, 'order_4 float=on');
		$this->assertIdempotent($result, $gen, 'order_4', 'on', ['lan'], ['lan'], 'order_4 float=on');
	}

	// -----------------------------------------------------------------------
	// M. absent/empty pass_order -> treated as order_0 (the #532 default fix)
	// -----------------------------------------------------------------------

	public function testAbsentOrderTreatedAsBefore(): void
	{
		/**
		 * Scenario: empty pass_order string (absent / unknown).
		 *
		 * The immutable-splice model maps any unknown order to the BEFORE anchor (pfB
		 * block first, then kept user rules). This makes the drop bug (#532) impossible
		 * by construction — user rules are never bucketed and cannot be omitted.
		 *
		 * Fail-before: the old bucket-based code sent user pass rules to $permit_rules
		 * for unrecognised orders, which had no tail emission → user rule DROPPED.
		 * The caller's order_0 default (#539) defended against that; the immutable-splice
		 * makes the helper itself safe regardless of what the caller passes.
		 *
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), user_pass(lan)  (same as order_0).
		 */

		$existing = [$this->pfbDenyRule('lan'), $this->userPassLan()];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, '', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'empty order -> BEFORE anchor (user rule preserved, same as order_0)');
		$this->assertTrackersSet($result, 'absent order');
		$this->assertUserRulesPreserved($existing, $result, 'absent order');
		$this->assertIdempotent($result, $gen, '', '', ['lan'], ['lan'], 'absent order');
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
		 * ORDER 1 anchor = AFTER: all kept user rules first (verbatim), then pfB block.
		 * keep = [user_pass(lan), user_pass(opt1)] (original order; pfB deny rules stripped).
		 * pfB block = [permit_in(lan), deny_in(lan), permit_out(opt1), deny_out(opt1)].
		 * Expected: user_pass(lan), user_pass(opt1), pfB permit_in(lan), pfB deny_in(lan),
		 *           pfB permit_out(opt1), pfB deny_out(opt1).
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
			['descr' => 'Default allow OPT1 to any',     'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_PermitList_v4 Auto Rule',   'type' => 'pass',   'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule',     'type' => 'block',  'interface' => 'lan',  'floating' => ''],
			['descr' => 'pfB_PermitList_v4 Auto Rule',   'type' => 'pass',   'interface' => 'opt1', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule',     'type' => 'reject', 'interface' => 'opt1', 'floating' => ''],
		], $result, 'order_1 float=off Permit_* + Deny_* separate ifaces');
		$this->assertTrackersSet($result, 'order_1 permit+deny');
		$this->assertUserRulesPreserved($existing, $result, 'order_1 permit+deny');
		$this->assertIdempotent($result, $gen, 'order_1', '', ['lan'], ['opt1'], 'order_1 permit+deny');
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
		 * order_0 anchor = BEFORE: pfB block first, then kept user rules verbatim.
		 * keep = [bypass_rule(lan), user_pass(lan)] (original order; pfB deny stripped).
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), bypass_rule(lan), user_pass(lan).
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
		$this->assertUserRulesPreserved($existing, $result, 'dns-redirect bypass');
		$this->assertIdempotent($result, $gen, 'order_0', '', ['lan'], ['lan'], 'dns-redirect bypass');
	}

	// -----------------------------------------------------------------------
	// P. DoT-block bypass rule present — must survive (not stripped)
	// -----------------------------------------------------------------------

	public function testDotBlockBypassRulePreserved(): void
	{
		/**
		 * Scenario: existing rules include a DoT-block bypass rule.
		 * Its descr starts with PFB_DOT_BLOCK_DESCR_PFX ('pfB_DoT_Block_').
		 * Must be preserved like a user rule — NOT stripped.
		 *
		 * order_0 anchor = BEFORE. keep = [dot_block_rule(lan), user_pass(lan)].
		 * Expected: pfB deny_in(lan), pfB deny_out(lan), dot_block_rule(lan), user_pass(lan).
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
		$this->assertUserRulesPreserved($existing, $result, 'dot-block bypass');
		$this->assertIdempotent($result, $gen, 'order_0', '', ['lan'], ['lan'], 'dot-block bypass');
	}

	// -----------------------------------------------------------------------
	// Q. pfB_ rules stripped (sanity check)
	// -----------------------------------------------------------------------

	public function testPfbRulesAreStripped(): void
	{
		/**
		 * Scenario: existing rules contain only a pfB_ deny rule (no bypass prefix).
		 * It must be stripped and rebuilt from the template.
		 * Result: exactly the rebuilt pfB rules, no user rules (keep = []).
		 */

		$existing = [$this->pfbDenyRule('lan')];
		$gen      = $this->pfbGeneratedDenyOnly();

		$result = pfb_build_autorule_list($existing, $gen, 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'pfB_ rules stripped and rebuilt');
		$this->assertTrackersSet($result, 'pfB stripped');
		$this->assertUserRulesPreserved($existing, $result, 'pfB stripped');
		$this->assertIdempotent($result, $gen, 'order_0', '', ['lan'], ['lan'], 'pfB stripped');
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
		$this->assertUserRulesPreserved($existing, $result, 'dnsbl float');
		$this->assertIdempotent($result, $gen, 'order_0', '', ['lan'], ['lan'], 'dnsbl float');
	}

	// -----------------------------------------------------------------------
	// S. Empty existing rules — no user rules, no pfB old rules
	// -----------------------------------------------------------------------

	public function testEmptyExistingRulesProducesOnlyPfbRules(): void
	{
		/**
		 * Scenario: no existing rules at all. Only pfB templates.
		 */

		$gen    = $this->pfbGeneratedDenyOnly();
		$result = pfb_build_autorule_list([], $gen, 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
		], $result, 'empty existing rules');
		$this->assertTrackersSet($result, 'empty existing');
		$this->assertUserRulesPreserved([], $result, 'empty existing');
		$this->assertIdempotent($result, $gen, 'order_0', '', ['lan'], ['lan'], 'empty existing');
	}

	// -----------------------------------------------------------------------
	// T. Non-managed iface user rule goes to other_rules (float=off)
	// -----------------------------------------------------------------------

	public function testNonManagedIfaceRulePreservedVerbatim(): void
	{
		/**
		 * Scenario: user rule on 'wan' — NOT in the managed inbound/outbound iface list.
		 * order_0, float=off, managed=['lan'].
		 *
		 * The immutable splice keeps ALL non-pfB-owned rules verbatim, regardless of
		 * interface. Non-managed rules are not singled out — they stay in their original
		 * position relative to other user rules in $keep.
		 * Expected: pfB BEFORE, then keep = [wan_rule, user_pass(lan)] (original order).
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

		$this->assertShapes([
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block',  'interface' => 'lan', 'floating' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => 'lan', 'floating' => ''],
			['descr' => 'WAN rule',                  'type' => 'pass',   'interface' => 'wan', 'floating' => ''],
			['descr' => 'Default allow LAN to any',  'type' => 'pass',   'interface' => 'lan', 'floating' => ''],
		], $result, 'non-managed iface rule preserved verbatim in original position');
		$this->assertUserRulesPreserved($existing, $result, 'non-managed iface');
		$this->assertIdempotent($result, $gen, 'order_0', '', ['lan'], ['lan'], 'non-managed iface');
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
