<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Oracle for pfb_build_autorule_list() — the IP auto-rule reconciler (ADR-41).
 *
 * pfBlockerNG regenerates its own firewall rules on every sync and must splice them around the
 * user's rules. The helper does a STABLE bucket reorder: each surviving rule is sorted into one
 * of four buckets — pfB pass/match, pfB block/reject, user pass/match, user block/reject — and
 * the buckets are concatenated in the sequence the `pass_order` setting dictates. The reorder is
 * applied independently to the two pf rule groups (FLOATING and INTERFACE), because pf evaluates
 * them separately. The ORDER table (GUI: pfblockerng_ip.php):
 *
 *   order_0 | pfB p/m | pfB b/r | user (not split)               (default)
 *   order_1 | user p/m | pfB p/m | pfB b/r | user b/r
 *   order_2 | pfB p/m | user p/m | pfB b/r | user b/r
 *   order_3 | pfB p/m | pfB b/r | user p/m | user b/r
 *   order_4 | pfB p/m | pfB b/r | user b/r | user p/m
 *   absent / unknown → order_0
 *
 * Contract pinned here:
 *   (a) every non-pfB (user) rule survives exactly once, with its content untouched (bar the
 *       legacy `_v4` alias-suffix upgrade) — no DROP (#532), no DUP, no mutation. Cross-bucket
 *       reorder IS allowed (it is what pass_order means); within-bucket order is preserved.
 *   (b) the pfB rules are regenerated and ordered per the ORDER table — in particular a pfB
 *       Permit list (pass) precedes a user Block for order_1..4 (the precedence a single binary
 *       anchor broke), and order_4 places the user's own Block before its Pass (intended).
 *   (c) running the helper on its own output is a no-op (idempotent).
 *
 * The headline regression guard is testBehaviourEqualsProvenReferenceOnDupFreeMatrix(): the helper
 * is asserted BEHAVIOURALLY identical to the years-proven pre-ADR-41 emission
 * (pfb_autorule_reference_8c4c482, frozen below) across a matrix of configs — same
 * per-(interface, direction) evaluation sequence AND the same full rule set (field-level, tracker
 * aside). The reference mishandles three config classes — exactly what this change fixes — which
 * are therefore SKIPPED from the differential and pinned to the corrected ORDER table by the
 * explicit per-order fixtures instead: (1) the user-pass DUP when an interface is both in and out
 * (order_1/order_2); (2) the order_2+float-on floating mis-order (it wedges the floating user
 * pass/match into the inbound loop). The empty/unknown-order DROP (3) is NOT skipped — the
 * differential feeds the reference the same `?: 'order_0'` normalization the production call site
 * applies, so that case is compared, not excluded.
 *
 * Loads the real pfblockerng.inc off-appliance via tests/php/bootstrap.php (shims + doubles).
 */

/**
 * FROZEN reference — pfb_build_autorule_list() exactly as it stood at commit 8c4c482 (ADR-41 P1,
 * a behaviour-preserving extraction of the inline auto-rule emission that shipped for years). It
 * carries the historical DUP/DROP defects on purpose: it is the behavioural oracle for every
 * dup-free config. DO NOT "fix" or refactor it — its value is being an independent, unchanging
 * witness of the proven pre-change behaviour. Calls the real pfb_tracker()/constants/
 * pfb_rule_alias_needs_v4_suffix() from the loaded pfblockerng.inc.
 */
function pfb_autorule_reference_8c4c482(
	array   $existing_rules,
	array   $pfb_generated,
	?string $order,
	?string $float,
	array   $in_ifaces,
	array   $out_ifaces
): array {
	$order = $order ?? '';
	$float = $float ?? '';
	$new_rules     = [];
	$permit_rules  = [];
	$match_rules   = [];
	$other_rules   = [];
	$fpermit_rules = [];
	$fmatch_rules  = [];
	$fother_rules  = [];

	foreach ($existing_rules as $rule) {
		$descr              = $rule['descr'] ?? '';
		$is_dns_bypass_rule =
		    str_starts_with($descr, PFB_DNS_REDIR_DESCR_V4_PFX) ||
		    str_starts_with($descr, PFB_DOT_BLOCK_DESCR_PFX);

		if (!str_starts_with($rule['descr'], 'pfB_') || $is_dns_bypass_rule) {
			foreach (array('source', 'destination') as $rtype) {
				if (pfb_rule_alias_needs_v4_suffix($rule[$rtype]['address'] ?? '', $rule['ipprotocol'] ?? '')) {
					$rule[$rtype]['address'] = "{$rule[$rtype]['address']}_v4";
				}
			}

			if ($float == 'on') {
				if ($order == 'order_0' && $rule['floating'] == 'yes') {
					$fother_rules[] = $rule;
				}
				else {
					if ($rule['type'] == 'pass' && $rule['floating'] == 'yes') {
						$fpermit_rules[] = $rule;
					} elseif ($rule['type'] == 'match' && $rule['floating'] == 'yes') {
						$fmatch_rules[] = $rule;
					} elseif ($rule['floating'] == 'yes') {
						$fother_rules[] = $rule;
					} else {
						$other_rules[] = $rule;
					}
				}
			} else {
				if (in_array($rule['interface'], $in_ifaces) ||
				    in_array($rule['interface'], $out_ifaces)) {
					if ($rule['floating'] == 'yes') {
						$fother_rules[] = $rule;
					} elseif ($rule['type'] == 'pass' || isset($rule['associated-rule-id'])) {
						if ($order == 'order_0') {
							$other_rules[] = $rule;
						} else {
							$permit_rules[] = $rule;
						}
					} else {
						$other_rules[] = $rule;
					}
				} else {
					if ($rule['floating'] == 'yes') {
						$fother_rules[] = $rule;
					} else {
						$other_rules[] = $rule;
					}
				}
			}
		}
	}

	if ($float == '' && $order == 'order_1' && !empty($fother_rules)) {
		foreach ($fother_rules as $cb_rules) {
			$new_rules[] = $cb_rules;
		}
	}
	if ($float == 'on' && $order == 'order_1') {
		foreach (array($fpermit_rules, $fmatch_rules) as $rtype) {
			if (!empty($rtype)) {
				foreach ($rtype as $cb_rules) {
					$new_rules[] = $cb_rules;
				}
			}
		}
	}

	foreach ($pfb_generated['dnsbl_float'] as $cb_rules) {
		$new_rules[] = $cb_rules;
	}

	if (!empty($in_ifaces)) {
		$pfbrunonce = TRUE;
		foreach ($in_ifaces as $inbound_interface) {
			if ($order == 'order_1' && !empty($permit_rules)) {
				foreach ($permit_rules as $cb_rules) {
					if ($cb_rules['interface'] == $inbound_interface) {
						$new_rules[] = $cb_rules;
					}
				}
			}
			if (!empty($pfb_generated['permit_inbound'])) {
				foreach ($pfb_generated['permit_inbound'] as $cb_rules) {
					$cb_rules['interface'] = $inbound_interface;
					$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'permit_in');
					$new_rules[]           = $cb_rules;
				}
			}
			if ($pfbrunonce && !empty($pfb_generated['match_inbound'])) {
				foreach ($pfb_generated['match_inbound'] as $cb_rules) {
					$cb_rules['interface'] = $pfb_generated['inbound_floating'];
					$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'match_in');
					$new_rules[]           = $cb_rules;
					$pfbrunonce            = FALSE;
				}
			}
			if ($order == 'order_2') {
				foreach (array($fpermit_rules, $fmatch_rules) as $rtype) {
					if (!empty($rtype)) {
						foreach ($rtype as $cb_rules) {
							$new_rules[] = $cb_rules;
						}
					}
				}
				if (!empty($permit_rules)) {
					foreach ($permit_rules as $cb_rules) {
						if ($cb_rules['interface'] == $inbound_interface) {
							$new_rules[] = $cb_rules;
						}
					}
				}
			}
			if (!empty($pfb_generated['deny_inbound'])) {
				foreach ($pfb_generated['deny_inbound'] as $cb_rules) {
					$cb_rules['interface'] = $inbound_interface;
					$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $inbound_interface, 'deny_in');
					$new_rules[]           = $cb_rules;
				}
			}
		}
	}

	if (!empty($out_ifaces)) {
		$pfbrunonce = TRUE;
		foreach ($out_ifaces as $outbound_interface) {
			if ($order == 'order_1' && !empty($permit_rules)) {
				foreach ($permit_rules as $cb_rules) {
					if ($cb_rules['interface'] == $outbound_interface) {
						$new_rules[] = $cb_rules;
					}
				}
			}
			if (!empty($pfb_generated['permit_outbound'])) {
				foreach ($pfb_generated['permit_outbound'] as $cb_rules) {
					$cb_rules['interface'] = $outbound_interface;
					$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'permit_out');
					$new_rules[]           = $cb_rules;
				}
			}
			if ($pfbrunonce && !empty($pfb_generated['match_outbound'])) {
				foreach ($pfb_generated['match_outbound'] as $cb_rules) {
					$cb_rules['interface'] = $pfb_generated['outbound_floating'];
					$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'match_out');
					$new_rules[]           = $cb_rules;
					$pfbrunonce            = FALSE;
				}
			}
			if ($order == 'order_2' && !empty($permit_rules)) {
				foreach ($permit_rules as $cb_rules) {
					if ($cb_rules['interface'] == $outbound_interface) {
						$new_rules[] = $cb_rules;
					}
				}
			}
			if (!empty($pfb_generated['deny_outbound'])) {
				foreach ($pfb_generated['deny_outbound'] as $cb_rules) {
					$cb_rules['interface'] = $outbound_interface;
					$cb_rules['tracker']   = pfb_tracker($cb_rules['descr'], $outbound_interface, 'deny_out');
					$new_rules[]           = $cb_rules;
				}
			}
		}
	}

	if ($float == 'on' && in_array($order, array('order_0', 'order_3', 'order_4'))) {
		if ($order != 'order_3') {
			$rule_order = array($fother_rules, $fpermit_rules, $fmatch_rules);
		} else {
			$rule_order = array($fpermit_rules, $fmatch_rules, $fother_rules);
		}
		foreach ($rule_order as $rtype) {
			if (!empty($rtype)) {
				foreach ($rtype as $cb_rules) {
					$new_rules[] = $cb_rules;
				}
			}
		}
	}
	if ($float == 'on' && in_array($order, array('order_1', 'order_2')) && !empty($fother_rules)) {
		foreach ($fother_rules as $cb_rules) {
			$new_rules[] = $cb_rules;
		}
	}
	if ($float == '' && $order != 'order_1' && !empty($fother_rules)) {
		foreach ($fother_rules as $cb_rules) {
			$new_rules[] = $cb_rules;
		}
	}
	if ($order == 'order_4' && !empty($other_rules)) {
		foreach ($other_rules as $cb_rules) {
			$new_rules[] = $cb_rules;
		}
	}
	if ($order == 'order_4' && !empty($permit_rules)) {
		foreach ($permit_rules as $cb_rules) {
			$new_rules[] = $cb_rules;
		}
	}
	if ($order == 'order_3' && !empty($permit_rules)) {
		foreach ($permit_rules as $cb_rules) {
			$new_rules[] = $cb_rules;
		}
	}
	if ($order != 'order_4' && !empty($other_rules)) {
		foreach ($other_rules as $cb_rules) {
			$new_rules[] = $cb_rules;
		}
	}

	return $new_rules;
}

#[CoversFunction('pfb_build_autorule_list')]
final class AutoruleListOracleTest extends TestCase
{
	// -----------------------------------------------------------------------
	// $GLOBALS['pfb'] sandbox (pfb_tracker() reads trackerids off it)
	// -----------------------------------------------------------------------

	private array $origPfb = [];
	private bool  $hadPfb  = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb  = array_key_exists('pfb', $GLOBALS);
		$this->origPfb = $GLOBALS['pfb'] ?? [];
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
	// Rule fixtures
	// -----------------------------------------------------------------------

	private function userPass(string $descr, string $iface = 'lan', string $floating = ''): array
	{
		return ['descr' => $descr, 'type' => 'pass', 'interface' => $iface, 'ipprotocol' => 'inet',
		        'floating' => $floating, 'source' => ['any' => ''], 'destination' => ['any' => '']];
	}

	private function userBlock(string $descr, string $iface = 'lan', string $floating = ''): array
	{
		return ['descr' => $descr, 'type' => 'block', 'interface' => $iface, 'ipprotocol' => 'inet',
		        'floating' => $floating, 'source' => ['address' => 'EvilHosts'], 'destination' => ['any' => '']];
	}

	private function userMatch(string $descr, string $iface = 'lan', string $floating = 'yes'): array
	{
		return ['descr' => $descr, 'type' => 'match', 'interface' => $iface, 'ipprotocol' => 'inet',
		        'floating' => $floating, 'source' => ['any' => ''], 'destination' => ['any' => '']];
	}

	/** A pfB-owned auto rule — the helper must STRIP and regenerate these (not keep them). */
	private function pfbOwnedDeny(string $iface = 'lan'): array
	{
		return ['descr' => 'pfB_DenyAlias_v4 Auto Rule', 'type' => 'block', 'interface' => $iface,
		        'ipprotocol' => 'inet', 'floating' => '', 'direction' => 'in',
		        'source' => ['address' => 'pfB_DenyAlias_v4'], 'destination' => ['any' => '']];
	}

	/** DNS-redirect bypass rule — pfB_ descr but must NOT be stripped (stays user-managed). */
	private function dnsRedirectBypass(): array
	{
		return ['descr' => 'pfB_DNS_Redirect_lan_v4', 'type' => 'pass', 'interface' => 'lan',
		        'ipprotocol' => 'inet', 'floating' => '', 'source' => ['any' => ''], 'destination' => ['any' => '']];
	}

	/** DoT-block bypass rule — pfB_ descr but must NOT be stripped. */
	private function dotBlockBypass(): array
	{
		return ['descr' => 'pfB_DoT_Block_lan', 'type' => 'block', 'interface' => 'lan',
		        'ipprotocol' => 'inet', 'floating' => '', 'source' => ['any' => ''], 'destination' => ['any' => '']];
	}

	// -----------------------------------------------------------------------
	// pfB-generated templates (direction-faithful: inbound rules carry
	// direction='in', outbound direction='out' — as filter.inc emits them)
	// -----------------------------------------------------------------------

	/** @param string $float 'on' makes the per-interface permit/deny floating (base_rule_float). */
	private function genPermitDeny(string $float = ''): array
	{
		$flo = $float === 'on' ? 'yes' : '';
		return [
			'permit_inbound'  => [['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass', 'interface' => '',
			    'direction' => 'in', 'ipprotocol' => 'inet', 'floating' => $flo,
			    'source' => ['address' => 'pfB_PermitList_v4'], 'destination' => ['any' => '']]],
			'permit_outbound' => [['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass', 'interface' => '',
			    'direction' => 'out', 'ipprotocol' => 'inet', 'floating' => $flo,
			    'source' => ['any' => ''], 'destination' => ['address' => 'pfB_PermitList_v4']]],
			'deny_inbound'    => [['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block', 'interface' => '',
			    'direction' => 'in', 'ipprotocol' => 'inet', 'floating' => $flo,
			    'source' => ['address' => 'pfB_DenyList_v4'], 'destination' => ['any' => '']]],
			'deny_outbound'   => [['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'reject', 'interface' => '',
			    'direction' => 'out', 'ipprotocol' => 'inet', 'floating' => $flo,
			    'source' => ['any' => ''], 'destination' => ['address' => 'pfB_DenyList_v4']]],
			'match_inbound'   => [], 'match_outbound' => [],
			'inbound_floating' => '', 'outbound_floating' => '', 'dnsbl_float' => [],
		];
	}

	/** Permit-list inbound only (the common case used by the precedence-trap fixtures). */
	private function genPermitDenyInbound(): array
	{
		$g = $this->genPermitDeny('');
		$g['permit_outbound'] = [];
		$g['deny_outbound']   = [];
		return $g;
	}

	private function genDenyOnly(): array
	{
		$g = $this->genPermitDeny('');
		$g['permit_inbound']  = [];
		$g['permit_outbound'] = [];
		$g['deny_outbound']   = [];
		return $g;
	}

	/** Deny + a floating Match rule (inbound + outbound); inbound_floating='lan'. */
	private function genWithMatch(): array
	{
		$g = $this->genDenyOnly();
		$g['match_inbound']  = [['descr' => 'pfB_MatchList_v4 Auto Rule', 'type' => 'match', 'interface' => '',
		    'direction' => 'in', 'ipprotocol' => 'inet', 'floating' => 'yes',
		    'source' => ['address' => 'pfB_MatchList_v4'], 'destination' => ['any' => '']]];
		$g['match_outbound'] = [['descr' => 'pfB_MatchList_v4 Auto Rule', 'type' => 'match', 'interface' => '',
		    'direction' => 'out', 'ipprotocol' => 'inet', 'floating' => 'yes',
		    'source' => ['any' => ''], 'destination' => ['address' => 'pfB_MatchList_v4']]];
		$g['inbound_floating']  = 'lan';
		$g['outbound_floating'] = 'lan';
		return $g;
	}

	/** Deny + the DNSBL floating pass pair (always floating). */
	private function genWithDnsbl(): array
	{
		$g = $this->genDenyOnly();
		$g['dnsbl_float'] = [
			['descr' => 'pfB_DNSBL_Permit', 'type' => 'pass', 'interface' => 'lan', 'direction' => '',
			 'ipprotocol' => 'inet', 'floating' => 'yes', 'source' => ['any' => ''], 'destination' => ['address' => 'pfB_DNSBL_VIPs']],
		];
		return $g;
	}

	// -----------------------------------------------------------------------
	// Assertion helpers
	// -----------------------------------------------------------------------

	/** [descr, type, interface, floating, direction] per rule — enough to pin ORDER + presence. */
	private function shapes(array $rules): array
	{
		return array_map(static fn (array $r): array => [
			'descr'     => $r['descr']     ?? '',
			'type'      => $r['type']      ?? '',
			'interface' => $r['interface'] ?? '',
			'floating'  => $r['floating']  ?? '',
			'direction' => $r['direction'] ?? '',
		], array_values($rules));
	}

	private function assertShapes(array $expected, array $result, string $ctx): void
	{
		$this->assertSame(
			$expected,
			$this->shapes($result),
			"Rule shape mismatch [{$ctx}].\n\nExpected:\n" . json_encode($expected, JSON_PRETTY_PRINT)
				. "\n\nActual:\n" . json_encode($this->shapes($result), JSON_PRETTY_PRINT)
		);
	}

	/** Every pfB-generated rule must carry a 'tracker' (user/bypass rules pass through without). */
	private function assertTrackersSet(array $result, string $ctx): void
	{
		foreach ($result as $i => $rule) {
			$descr = $rule['descr'] ?? "(rule {$i})";
			if (!$this->isPfbOwned($rule)) {
				continue;
			}
			$this->assertArrayHasKey('tracker', $rule,
				"pfB rule [{$i}] '{$descr}' must carry a tracker [{$ctx}]");
		}
	}

	private function isUserRule(array $rule): bool
	{
		$descr = $rule['descr'] ?? '';
		if (!str_starts_with($descr, 'pfB_')) {
			return TRUE;
		}
		return str_starts_with($descr, PFB_DNS_REDIR_DESCR_V4_PFX) ||
		       str_starts_with($descr, PFB_DOT_BLOCK_DESCR_PFX);
	}

	private function isPfbOwned(array $rule): bool
	{
		return !$this->isUserRule($rule);
	}

	/**
	 * Fidelity contract (a): user rules survive as a multiset — no DROP, no DUP, and the FULL
	 * content untouched (every field: source, destination, ipprotocol, associated-rule-id, …, not
	 * just the descr/type/interface/floating/direction shape). Uses canonical (order-insensitive)
	 * equality so cross-bucket reorder — exactly what pass_order does — is allowed while any
	 * content mutation goes red. Within-bucket order is pinned by the explicit per-order fixtures.
	 * (Callers that legitimately mutate content — the _v4 upgrade — assert that transform directly
	 * instead of via this helper.)
	 */
	private function assertUserRulesIntact(array $input, array $output, string $ctx): void
	{
		$inUser  = array_values(array_filter($input,  fn ($r) => $this->isUserRule($r)));
		$outUser = array_values(array_filter($output, fn ($r) => $this->isUserRule($r)));
		$this->assertEqualsCanonicalizing(
			$inUser,
			$outUser,
			"User-rule fidelity failure [{$ctx}]: every user rule must survive exactly once with its "
				. "FULL content intact (no drop, no dup, no source/destination/ipprotocol mutation).\n\n"
				. "Input user rules:\n" . json_encode($inUser, JSON_PRETTY_PRINT)
				. "\n\nOutput user rules:\n" . json_encode($outUser, JSON_PRETTY_PRINT)
		);
	}

	/** Contract (c): running the helper on its own output is a no-op. */
	private function assertIdempotent(array $output, array $gen, ?string $order, ?string $float,
	                                  array $in, array $out, string $ctx): void
	{
		$second = pfb_build_autorule_list($output, $gen, $order, $float, $in, $out);
		$this->assertSame(
			$this->shapes($output),
			$this->shapes($second),
			"Idempotence failure [{$ctx}]: a second pass must be a no-op.\n\nFirst:\n"
				. json_encode($this->shapes($output), JSON_PRETTY_PRINT) . "\n\nSecond:\n"
				. json_encode($this->shapes($second), JSON_PRETTY_PRINT)
		);
	}

	// =======================================================================
	// THE PRECEDENCE TRAP — pfB Permit + pfB Deny + user Pass + user Block on
	// one interface. This is the case a single binary anchor got wrong: it put
	// the whole block of user rules (incl. the user Block) before the pfB block,
	// so a pfB Permit could not override a user Block for order_1/order_2, and
	// order_4 stopped reordering the user's own Pass/Block. RED on that helper.
	// =======================================================================

	public function testTrapOrder0KeepsUserRulesTogetherAfterPfb(): void
	{
		// order_0: pfB pass, pfB block, then ALL user rules (not split), original order.
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDenyInbound(), 'order_0', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'User allow LAN',              'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => ''],
			['descr' => 'User block evil',             'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => ''],
		], $result, 'trap order_0');
		$this->assertUserRulesIntact($existing, $result, 'trap order_0');
	}

	public function testTrapOrder1PfbPermitBeatsUserBlock(): void
	{
		// order_1: user p/m, pfB p/m, pfB b/r, user b/r. The pfB Permit MUST precede the user
		// Block (the binary anchor put the user Block first -> pfB Permit lost).
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDenyInbound(), 'order_1', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'User allow LAN',              'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => ''],
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'User block evil',             'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => ''],
		], $result, 'trap order_1');
		$this->assertUserRulesIntact($existing, $result, 'trap order_1');
	}

	public function testTrapOrder2PfbPermitBeatsUserBlock(): void
	{
		// order_2: pfB p/m, user p/m, pfB b/r, user b/r. pfB Permit still precedes the user Block.
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDenyInbound(), 'order_2', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'User allow LAN',              'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'User block evil',             'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => ''],
		], $result, 'trap order_2');
		$this->assertUserRulesIntact($existing, $result, 'trap order_2');
	}

	public function testTrapOrder3PfbBlockBeforeUserRules(): void
	{
		// order_3: pfB p/m, pfB b/r, user p/m, user b/r.
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDenyInbound(), 'order_3', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'User allow LAN',              'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => ''],
			['descr' => 'User block evil',             'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => ''],
		], $result, 'trap order_3');
		$this->assertUserRulesIntact($existing, $result, 'trap order_3');
	}

	public function testTrapOrder4ReordersUserBlockBeforeUserPass(): void
	{
		// order_4: pfB p/m, pfB b/r, user b/r, user p/m. The user's OWN Block precedes its Pass —
		// an intended pass_order reorder the binary anchor wrongly dropped.
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDenyInbound(), 'order_4', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'User block evil',             'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => ''],
			['descr' => 'User allow LAN',              'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => ''],
		], $result, 'trap order_4');
		$this->assertUserRulesIntact($existing, $result, 'trap order_4');
	}

	// =======================================================================
	// Float mode ON — the per-interface pfB rules become floating, so pass_order
	// orders the FLOATING group (same ORDER table applied symmetrically).
	// =======================================================================

	public function testFloatOnAppliesOrderTableToFloatingGroup(): void
	{
		$existing = [$this->userPass('User float allow', 'lan', 'yes'), $this->userBlock('User float block', 'lan', 'yes')];
		$gen      = $this->genPermitDeny('on');
		$gen['permit_outbound'] = [];
		$gen['deny_outbound']   = [];

		$expected = [
			'order_1' => [
				['descr' => 'User float allow',            'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
				['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'User float block',            'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
			],
			'order_2' => [
				['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'User float allow',            'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
				['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'User float block',            'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
			],
			'order_3' => [
				['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'User float allow',            'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
				['descr' => 'User float block',            'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
			],
			'order_4' => [
				['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
				['descr' => 'User float block',            'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
				['descr' => 'User float allow',            'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
			],
		];
		foreach ($expected as $order => $shape) {
			$result = pfb_build_autorule_list($existing, $gen, $order, 'on', ['lan'], []);
			$this->assertShapes($shape, $result, "float-on {$order}");
			$this->assertUserRulesIntact($existing, $result, "float-on {$order}");
		}
	}

	public function testOrder2FloatOnMatchPlacement(): void
	{
		// order_2 + float-on is the one case the proven-reference differential cannot oracle (the
		// reference mis-orders it), so the floating MATCH placement must be pinned by a fixture:
		// the pfB Match rides in the pfB pass/match bucket and the user float Match in the user
		// pass/match bucket — both BEFORE the pfB Deny (order_2 = pfB p/m | user p/m | pfB b/r | …).
		$gen = $this->genWithMatch();
		$gen['permit_inbound'] = [
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass', 'interface' => '', 'direction' => 'in',
			 'ipprotocol' => 'inet', 'floating' => 'yes', 'source' => ['address' => 'pfB_PermitList_v4'], 'destination' => ['any' => '']],
		];
		$gen['deny_inbound'][0]['floating'] = 'yes';
		$gen['match_inbound'][0]['floating'] = 'yes';
		$existing = [
			$this->userPass('User float allow', 'lan', 'yes'),
			$this->userMatch('User float match', 'lan'),
			$this->userBlock('User float block', 'lan', 'yes'),
		];
		$result = pfb_build_autorule_list($existing, $gen, 'order_2', 'on', ['lan'], []);

		$this->assertShapes([
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
			['descr' => 'pfB_MatchList_v4 Auto Rule',  'type' => 'match', 'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
			['descr' => 'User float allow',            'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
			['descr' => 'User float match',            'type' => 'match', 'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => 'in'],
			['descr' => 'User float block',            'type' => 'block', 'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
		], $result, 'order_2 float-on with match');
		$this->assertUserRulesIntact($existing, $result, 'order_2 float-on with match');
	}

	// =======================================================================
	// pfB rule generation invariants
	// =======================================================================

	public function testMatchRuleEmittedOnceAcrossInterfaces(): void
	{
		// Match rules are floating-only and must be emitted ONCE even with multiple inbound ifaces.
		$result = pfb_build_autorule_list([$this->userPass('User allow LAN')], $this->genWithMatch(),
		                                  'order_0', '', ['lan', 'opt1'], []);
		$matches = array_filter($result, static fn ($r) => ($r['descr'] ?? '') === 'pfB_MatchList_v4 Auto Rule');
		$this->assertCount(1, $matches,
			"Floating Match rule must be emitted exactly once across interfaces.\n\nActual:\n"
				. json_encode($this->shapes($result), JSON_PRETTY_PRINT));
		// The single Match carries the inbound_floating interface, not a per-iface value.
		$this->assertSame('lan', array_values($matches)[0]['interface'], 'match interface = inbound_floating');
		$this->assertTrackersSet($result, 'match-once');
	}

	public function testDnsblFloatPairLeadsThePfbPassBucket(): void
	{
		$result = pfb_build_autorule_list([$this->userPass('User allow LAN')], $this->genWithDnsbl(),
		                                  'order_0', '', ['lan'], []);
		$this->assertShapes([
			['descr' => 'pfB_DNSBL_Permit',          'type' => 'pass',  'interface' => 'lan', 'floating' => 'yes', 'direction' => ''],
			['descr' => 'pfB_DenyList_v4 Auto Rule', 'type' => 'block', 'interface' => 'lan', 'floating' => '',    'direction' => 'in'],
			['descr' => 'User allow LAN',            'type' => 'pass',  'interface' => 'lan', 'floating' => '',    'direction' => ''],
		], $result, 'dnsbl lead');
	}

	public function testPfbOwnedRulesStrippedAndRegenerated(): void
	{
		// A stale pfB_DenyAlias auto rule in the input must be removed; the fresh pfB Deny appears.
		$existing = [$this->pfbOwnedDeny('lan'), $this->userPass('User allow LAN')];
		$result   = pfb_build_autorule_list($existing, $this->genDenyOnly(), 'order_0', '', ['lan'], []);

		$descrs = array_column($result, 'descr');
		$this->assertNotContains('pfB_DenyAlias_v4 Auto Rule', $descrs,
			"Stale pfB-owned rule must be stripped.\n\nActual:\n" . json_encode($descrs, JSON_PRETTY_PRINT));
		$this->assertContains('pfB_DenyList_v4 Auto Rule', $descrs, 'fresh pfB Deny regenerated');
		$this->assertContains('User allow LAN', $descrs, 'user rule kept');
	}

	public function testBypassRulesAreKeptNotStripped(): void
	{
		// DNS-redirect / DoT-block bypass rules keep their pfB_ prefix but are user-managed.
		$existing = [$this->dnsRedirectBypass(), $this->dotBlockBypass(), $this->userPass('User allow LAN')];
		$result   = pfb_build_autorule_list($existing, $this->genDenyOnly(), 'order_0', '', ['lan'], []);

		$descrs = array_column($result, 'descr');
		$this->assertContains('pfB_DNS_Redirect_lan_v4', $descrs, 'DNS-redirect bypass kept');
		$this->assertContains('pfB_DoT_Block_lan', $descrs, 'DoT-block bypass kept');
		$this->assertUserRulesIntact($existing, $result, 'bypass kept');
	}

	public function testV4AliasSuffixUpgradeAppliedToUserRuleAddress(): void
	{
		// The ONE sanctioned content mutation: a user rule referencing a bare pfB_ alias on an
		// inet rule has its source/destination address upgraded to the '_v4' form. A '_v6' alias
		// on an inet6 rule is left untouched (the issue #360 guard — appending '_v4' would point
		// at the nonexistent pfB_*_v6_v4). This is the only field-level change the helper may make
		// to a user rule; assertUserRulesIntact would (correctly) reject it, so assert it directly.
		$inetRule = ['descr' => 'User via pfB alias v4', 'type' => 'pass', 'interface' => 'lan',
		             'ipprotocol' => 'inet', 'floating' => '', 'source' => ['address' => 'pfB_CustomList'],
		             'destination' => ['any' => '']];
		$inet6Rule = ['descr' => 'User via pfB alias v6', 'type' => 'pass', 'interface' => 'lan',
		              'ipprotocol' => 'inet6', 'floating' => '', 'source' => ['address' => 'pfB_CustomList_v6'],
		              'destination' => ['any' => '']];
		$result = pfb_build_autorule_list([$inetRule, $inet6Rule], $this->genDenyOnly(), 'order_0', '', ['lan'], []);

		$byDescr = [];
		foreach ($result as $r) {
			$byDescr[$r['descr'] ?? ''] = $r;
		}
		$this->assertSame('pfB_CustomList_v4', $byDescr['User via pfB alias v4']['source']['address'] ?? null,
			"bare pfB_ alias on an inet rule must be upgraded to '_v4'.\nActual: "
				. json_encode($byDescr['User via pfB alias v4'] ?? null, JSON_PRETTY_PRINT));
		$this->assertSame('pfB_CustomList_v6', $byDescr['User via pfB alias v6']['source']['address'] ?? null,
			"a '_v6' alias on an inet6 rule must be left untouched (#360 guard).\nActual: "
				. json_encode($byDescr['User via pfB alias v6'] ?? null, JSON_PRETTY_PRINT));
	}

	// =======================================================================
	// Immutability contract (no drop / no dup / no mutation) + within-bucket order
	// =======================================================================

	public function testNoUserRuleDuplicationWhenInterfaceIsBothInAndOut(): void
	{
		// The #532 dup: a Permit list whose interface is BOTH inbound and outbound previously
		// emitted the user pass rule twice (once per loop). It must now appear exactly once.
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDeny(''), 'order_2', '', ['lan'], ['lan']);

		foreach (['User allow LAN', 'User block evil'] as $descr) {
			$count = count(array_filter($result, static fn ($r) => ($r['descr'] ?? '') === $descr));
			$this->assertSame(1, $count,
				"User rule '{$descr}' must appear exactly once (in==out dup guard).\n\nActual:\n"
					. json_encode($this->shapes($result), JSON_PRETTY_PRINT));
		}
		$this->assertUserRulesIntact($existing, $result, 'in==out no-dup');
	}

	public function testFloatingUserRulesNotDroppedWhenNoInboundInterface(): void
	{
		// Reference DROP bug: order_2 + float-on emitted floating user pass/match only inside the
		// inbound loop, so with NO inbound interface (outbound-only list) they vanished. They must
		// survive — a user rule is never dropped, whatever the iface/order/float combination.
		$existing = [$this->userPass('User float allow', 'lan', 'yes'), $this->userMatch('User float match', 'lan')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDeny('on'), 'order_2', 'on', [], ['lan']);

		$descrs = array_column($result, 'descr');
		$this->assertContains('User float allow', $descrs,
			"Floating user pass must survive with no inbound iface.\n\nActual:\n" . json_encode($descrs, JSON_PRETTY_PRINT));
		$this->assertContains('User float match', $descrs, 'floating user match must survive');
		$this->assertUserRulesIntact($existing, $result, 'order_2 float-on outbound-only no-drop');
	}

	public function testWithinBucketOrderPreserved(): void
	{
		// Two user pass rules on the same managed iface land in the same bucket; order_1 must keep
		// their RELATIVE order (only whole buckets move, never the rules inside one).
		$existing = [$this->userPass('User allow LAN'), $this->userPass('User allow LAN 2')];
		$result   = pfb_build_autorule_list($existing, $this->genPermitDenyInbound(), 'order_1', '', ['lan'], ['lan']);

		$this->assertShapes([
			['descr' => 'User allow LAN',              'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => ''],
			['descr' => 'User allow LAN 2',            'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => ''],
			['descr' => 'pfB_PermitList_v4 Auto Rule', 'type' => 'pass',  'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
			['descr' => 'pfB_DenyList_v4 Auto Rule',   'type' => 'block', 'interface' => 'lan', 'floating' => '', 'direction' => 'in'],
		], $result, 'within-bucket order');
	}

	public function testEmptyAndUnknownOrderBehaveAsOrder0(): void
	{
		// An empty/unknown pass_order must NOT drop a user rule (#532/#539) — it acts as order_0.
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil')];
		$order0   = $this->shapes(pfb_build_autorule_list($existing, $this->genDenyOnly(), 'order_0', '', ['lan'], ['lan']));

		foreach (['', 'totally_bogus', null] as $order) {
			$result = pfb_build_autorule_list($existing, $this->genDenyOnly(), $order, '', ['lan'], ['lan']);
			$this->assertSame($order0, $this->shapes($result),
				'order ' . var_export($order, TRUE) . ' must match order_0');
			$this->assertUserRulesIntact($existing, $result, 'empty/unknown order');
		}
	}

	public function testNullFloatTolerated(): void
	{
		// $pfb['float'] is null until configured; the helper coerces it to off, never TypeErrors.
		$existing = [$this->userPass('User allow LAN')];
		$result   = pfb_build_autorule_list($existing, $this->genDenyOnly(), 'order_0', null, ['lan'], []);
		$this->assertSame(
			$this->shapes(pfb_build_autorule_list($existing, $this->genDenyOnly(), 'order_0', '', ['lan'], [])),
			$this->shapes($result),
			'null float == off'
		);
	}

	public function testIdempotentAcrossOrdersAndFloat(): void
	{
		$existing = [$this->userPass('User allow LAN'), $this->userBlock('User block evil'),
		             $this->userPass('User allow OPT1', 'opt1')];
		foreach (['order_0', 'order_1', 'order_2', 'order_3', 'order_4'] as $order) {
			foreach (['', 'on'] as $float) {
				$gen   = $this->genPermitDeny($float);
				$first = pfb_build_autorule_list($existing, $gen, $order, $float, ['lan'], ['opt1']);
				$this->assertIdempotent($first, $gen, $order, $float, ['lan'], ['opt1'], "{$order} float='{$float}'");
			}
		}
	}

	// =======================================================================
	// HEADLINE GUARD — behavioural equivalence to the proven 8c4c482 reference
	// on every dup-free config (the dup-trigger configs are the bug we fix and
	// are pinned to the corrected ORDER table by the fixtures above).
	// =======================================================================

	public function testBehaviourEqualsProvenReferenceOnDupFreeMatrix(): void
	{
		$compared = 0;

		foreach ($this->differentialMatrix() as $label => $c) {
			[$existing, $gen, $order, $float, $in, $out] = $c;

			$new = pfb_build_autorule_list($existing, $gen, $order, $float, $in, $out);

			// (1) the dup fix holds for EVERY config: no user rule appears more than once.
			$userShapes = $this->shapes(array_values(array_filter($new, fn ($r) => $this->isUserRule($r))));
			$dups = array_filter(array_count_values(array_map('json_encode', $userShapes)), fn ($n) => $n > 1);
			$this->assertSame([], $dups,
				"[{$label}] user rule duplicated:\n" . json_encode(array_keys($dups), JSON_PRETTY_PRINT));

			// (2) behavioural equivalence to the proven reference — asserted ONLY where the
			//     reference is itself defect-free; the configs skipped here are exactly the bugs
			//     this change fixes, pinned to the corrected behaviour by the fixtures above:
			//       * an interface in BOTH in+out dups the user-pass rule (order_1/order_2);
			//       * order_2 + float-on wedges the floating user pass/match into the inbound loop
			//         (dropping them with no inbound iface, dup'ing them with >1) and emits the
			//         pfB match_outbound only later in the outbound loop — so the reference
			//         mis-orders that whole case. Our helper applies the ORDER table cleanly to
			//         the floating group (pinned by testFloatOnAppliesOrderTableToFloatingGroup).
			$overlap        = array_intersect($in, $out) !== [];
			$userDup        = ($order === 'order_1' || $order === 'order_2') && $overlap;
			$order2FloatBug = ($order === 'order_2' && $float === 'on');
			if ($userDup || $order2FloatBug) {
				continue;
			}

			// The production call site feeds the helper `pass_order ?: 'order_0'`, so the proven
			// reference only ever saw order_0..4 — never '' / unknown (its empty-order path is the
			// #532 drop we fix). Feed it the normalised order, exactly as the call site would.
			$refOrder = in_array($order, ['order_1', 'order_2', 'order_3', 'order_4'], TRUE) ? $order : 'order_0';
			$refClean = $this->dedup(pfb_autorule_reference_8c4c482($existing, $gen,
			    $refOrder, $float, $in, $out));

			foreach ($this->allIfaces($existing, $in, $out) as $iface) {
				foreach (['in', 'out'] as $dir) {
					$this->assertSame(
						$this->evalSeq($refClean, $iface, $dir),
						$this->evalSeq($new, $iface, $dir),
						"[{$label}] iface '{$iface}' dir '{$dir}' eval-sequence diverges from the proven reference"
					);
				}
			}
			// Field-level fidelity (order-insensitive): the full rule set — source / destination /
			// ipprotocol / every field EXCEPT the tracker — must match the proven reference, not
			// just the descr/type/interface/floating/direction shape the eval-sequence compares.
			// The tracker is stripped: pfb_tracker() is stateful (a per-call counter), so new and
			// the reference legitimately mint different tracker ids; tracker PRESENCE is checked by
			// assertTrackersSet, and tracker order/position by the eval-sequence above.
			$strip = static fn (array $rules): array => array_map(
				static function (array $r): array { unset($r['tracker']); return $r; }, $rules);
			$this->assertEqualsCanonicalizing($strip($refClean), $strip($new),
				"[{$label}] full rule set (field-level, tracker aside) diverges from the proven reference");
			$compared++;
		}

		// Guard against an accidentally-empty matrix silently passing.
		$this->assertGreaterThan(60, $compared, 'differential must compare a meaningful number of dup-free configs');
	}

	/**
	 * Deterministic enumerated config matrix: orders × float × iface layouts × user-rule sets ×
	 * pfB generators. Disjoint iface layouts keep most configs dup-free; the few dup-trigger ones
	 * are filtered inside the test. No RNG — fully reproducible.
	 *
	 * @return array<string, array{0: array, 1: array, 2: ?string, 3: ?string, 4: array, 5: array}>
	 */
	private function differentialMatrix(): array
	{
		$ifaceLayouts = [
			'in-lan'              => [['lan'], []],
			'out-lan'             => [[], ['lan']],
			'in-lan/out-opt1'     => [['lan'], ['opt1']],
			'in-lanopt1/out-opt2' => [['lan', 'opt1'], ['opt2']],
			'in-lanopt1'          => [['lan', 'opt1'], []],
			'in-lan/out-lan'      => [['lan'], ['lan']],     // overlap (dup-trigger, filtered)
		];
		$userSets = [
			'empty'        => [],
			'pass+block'   => [$this->userPass('U-pass', 'lan'), $this->userBlock('U-block', 'lan')],
			'mixed-ifaces' => [$this->userPass('U-pass-lan', 'lan'), $this->userBlock('U-block-opt1', 'opt1'),
			                   $this->userBlock('U-float', 'lan', 'yes')],
			'floatpass+match+unmanaged' => [$this->userPass('U-float-pass', 'lan', 'yes'),
			                   $this->userMatch('U-float-match', 'lan'), $this->userPass('U-wan', 'wan')],
			'bypass+stale' => [$this->dnsRedirectBypass(), $this->pfbOwnedDeny('lan'), $this->userPass('U-keep', 'lan')],
		];
		$orders = ['order_0', 'order_1', 'order_2', 'order_3', 'order_4', '', 'bogus'];

		$cases = [];
		foreach ($orders as $order) {
			foreach (['', 'on'] as $float) {
				foreach ($ifaceLayouts as $ilabel => [$in, $out]) {
					foreach ($userSets as $ulabel => $users) {
						foreach (['permit+deny', 'deny-only', 'with-match', 'with-dnsbl'] as $glabel) {
							$gen = match ($glabel) {
								'permit+deny' => $this->genPermitDeny($float),
								'deny-only'   => $this->genDenyOnly(),
								'with-match'  => $this->genWithMatch(),
								'with-dnsbl'  => $this->genWithDnsbl(),
							};
							$cases["o={$order};f={$float};if={$ilabel};u={$ulabel};g={$glabel}"]
								= [$users, $gen, $order, $float, $in, $out];
						}
					}
				}
			}
		}
		return $cases;
	}

	// --- differential projection primitives (mirror the pf evaluation model) ---------------

	/** Remove genuinely-identical duplicate rules, keeping first occurrence. */
	private function dedup(array $arr): array
	{
		$seen = []; $out = [];
		foreach ($arr as $r) {
			$k = json_encode($r);
			if (isset($seen[$k])) {
				continue;
			}
			$seen[$k] = TRUE;
			$out[]    = $r;
		}
		return $out;
	}

	private function dirOk(array $r, string $dir): bool
	{
		$d = $r['direction'] ?? '';
		return $d === '' || $d === 'any' || $d === $dir;
	}

	/**
	 * Rules a packet on ($iface,$dir) actually sees, in evaluation order: the floating rules that
	 * apply to it (in $dir, and either unscoped or scoped to $iface), then this interface's own
	 * non-floating rules. A floating rule scoped to another interface is NOT seen — so a reorder
	 * of two different-interface floating rules is inert, and this projection treats it as such.
	 */
	private function evalSeq(array $arr, string $iface, string $dir): array
	{
		$float = []; $ifc = [];
		foreach ($arr as $r) {
			if (!$this->dirOk($r, $dir)) {
				continue;
			}
			$ri = $r['interface'] ?? '';
			if (($r['floating'] ?? '') === 'yes') {
				if ($ri === '' || $ri === 'any' || $ri === $iface) {
					$float[] = $r;
				}
			} elseif ($ri === $iface) {
				$ifc[] = $r;
			}
		}
		return $this->shapes(array_merge($float, $ifc));
	}

	private function allIfaces(array $existing, array $in, array $out): array
	{
		$s = array_merge($in, $out);
		foreach ($existing as $r) {
			$s[] = $r['interface'] ?? '';
		}
		return array_values(array_unique($s));
	}
}
