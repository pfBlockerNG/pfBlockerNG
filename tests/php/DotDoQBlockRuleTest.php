<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-37 Phase 1 — Golden oracle tests for pfb_build_dot_block_rule().
 *
 * These tests pin the EXACT rule shape specified in ADR-37 §2.2.  They are
 * written BEFORE the builder implementation (oracle-first discipline) and
 * MUST FAIL against the Phase 1 skeleton (which throws LogicException).
 *
 * A correct Phase 2 implementation must make all tests pass without relaxing
 * any assertion.
 *
 * Ground-truth rule shape (ADR-37 §2.2):
 *
 *   <rule>
 *     <type>block</type>
 *     <interface>{iface}</interface>
 *     <ipprotocol>inet46</ipprotocol>
 *     <protocol>tcp/udp</protocol>
 *     <source><any></any></source>
 *     <!-- or, when exception alias set: -->
 *     <!-- <source><address>ALIAS</address><not></not></source> -->
 *     <destination>
 *       <network>(self)</network><not></not>
 *       <port>853</port>
 *     </destination>
 *     <statetype><![CDATA[keep state]]></statetype>
 *     <descr><![CDATA[pfB_DoT_Block_{iface}]]></descr>
 *   </rule>
 *
 * Invariants asserted (every branch, every field):
 *   (a) source is <any/> when no exception alias                [skeleton: FAIL - RED]
 *   (b) source is negated-alias when exception alias set        [skeleton: FAIL - RED]
 *   (c) type is 'block'                                         [skeleton: FAIL - RED]
 *   (d) ipprotocol is 'inet46'                                  [skeleton: FAIL - RED]
 *   (e) protocol is 'tcp/udp'                                   [skeleton: FAIL - RED]
 *   (f) destination has (self)+not+port 853 (both alias states) [skeleton: FAIL - RED]
 *   (g) statetype is 'keep state'                               [skeleton: FAIL - RED]
 *   (h) descr marker contains interface name                    [skeleton: FAIL - RED]
 *   (i) multiple interfaces produce independent rules            [skeleton: FAIL - RED]
 */
final class DotDoQBlockRuleTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Fixture helpers
	// -----------------------------------------------------------------------

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/**
	 * Call the builder and return the rule array.
	 *
	 * Phase 1: returns [] (skeleton) — assertions FAIL (RED) as expected.
	 * Phase 2: must return a well-formed array satisfying all assertions.
	 *
	 * @return array<string,mixed>
	 */
	private function buildRule(string $iface, string $exclude_alias = ''): array
	{
		return pfb_build_dot_block_rule($iface, $exclude_alias);
	}

	// -----------------------------------------------------------------------
	// (a) Source is <any> when no exception alias
	// -----------------------------------------------------------------------

	/**
	 * Source element is <any/> when the exception alias is empty.
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('lan', '') called (empty alias).
	 *   When the rule array is inspected.
	 *   Then rule['source'] contains an 'any' key (maps to <any/>).
	 *   And rule['source'] does NOT contain 'address' or 'not' keys.
	 */
	public function test_source_is_any_when_no_exception_alias(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', '');

		// Then: source is <any/> (the PHP representation is ['any' => ''] or
		// ['any' => NULL]; either is valid — check key presence, not exact value).
		$this->assertIsArray($rule, 'rule must be an array');
		$this->assertArrayHasKey('source', $rule, "rule must have 'source' key");

		$source = $rule['source'];
		$this->assertIsArray($source, 'source must be an array');

		// <any/> is present.
		$this->assertArrayHasKey('any', $source,
			"source must contain 'any' key when alias is empty (source = <any/>)"
		);

		// No address or not — those belong to the negated-alias branch.
		$this->assertArrayNotHasKey('address', $source,
			"source must NOT contain 'address' key when alias is empty"
		);
		$this->assertArrayNotHasKey('not', $source,
			"source must NOT contain 'not' key when alias is empty"
		);
	}

	// -----------------------------------------------------------------------
	// (b) Source is negated-alias when exception alias is set
	// -----------------------------------------------------------------------

	/**
	 * Source element is a negated alias when an exception alias is provided.
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('lan', 'DoT_Exceptions') called.
	 *   When the rule array is inspected.
	 *   Then rule['source']['address'] === 'DoT_Exceptions'.
	 *   And rule['source'] contains a 'not' key (maps to <not/>).
	 *   And rule['source'] does NOT contain 'any'.
	 */
	public function test_source_is_negated_alias_when_exception_alias_set(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', 'DoT_Exceptions');

		// Then.
		$this->assertIsArray($rule, 'rule must be an array');
		$this->assertArrayHasKey('source', $rule, "rule must have 'source' key");

		$source = $rule['source'];
		$this->assertIsArray($source, 'source must be an array');

		// address contains the alias name.
		$this->assertArrayHasKey('address', $source,
			"source must contain 'address' key when alias is set"
		);
		$this->assertSame('DoT_Exceptions', $source['address'],
			"source['address'] must equal the alias name 'DoT_Exceptions'"
		);

		// <not/> is present (negation — exception hosts bypass the block).
		$this->assertArrayHasKey('not', $source,
			"source must contain 'not' key (negated source) when alias is set"
		);

		// No <any/> — that belongs to the empty-alias branch.
		$this->assertArrayNotHasKey('any', $source,
			"source must NOT contain 'any' key when alias is set"
		);
	}

	// -----------------------------------------------------------------------
	// (c) Type is 'block'
	// -----------------------------------------------------------------------

	/**
	 * Rule type is 'block'.
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('lan', '') called.
	 *   When rule['type'] is inspected.
	 *   Then it equals 'block' (no other type is acceptable).
	 */
	public function test_type_is_block(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', '');

		// Then.
		$this->assertArrayHasKey('type', $rule, "rule must have 'type' key");
		$this->assertSame('block', $rule['type'],
			"rule['type'] must be exactly 'block'"
		);
	}

	// -----------------------------------------------------------------------
	// (d) ipprotocol is 'inet46'
	// -----------------------------------------------------------------------

	/**
	 * Rule ipprotocol is 'inet46' (covers both IPv4 and IPv6 in one rule).
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('lan', '') called.
	 *   When rule['ipprotocol'] is inspected.
	 *   Then it equals 'inet46' (NOT 'inet' or 'inet6' — no per-family split).
	 */
	public function test_ipprotocol_is_inet46(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', '');

		// Then.
		$this->assertArrayHasKey('ipprotocol', $rule, "rule must have 'ipprotocol' key");
		$this->assertSame('inet46', $rule['ipprotocol'],
			"rule['ipprotocol'] must be 'inet46' (single rule for both families)"
		);
	}

	// -----------------------------------------------------------------------
	// (e) Protocol is 'tcp/udp'
	// -----------------------------------------------------------------------

	/**
	 * Rule protocol is 'tcp/udp' (covers DoT on TCP 853 and DoQ on UDP 853).
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('lan', '') called.
	 *   When rule['protocol'] is inspected.
	 *   Then it equals 'tcp/udp'.
	 */
	public function test_protocol_is_tcp_udp(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', '');

		// Then.
		$this->assertArrayHasKey('protocol', $rule, "rule must have 'protocol' key");
		$this->assertSame('tcp/udp', $rule['protocol'],
			"rule['protocol'] must be 'tcp/udp' (covers DoT TCP + DoQ UDP)"
		);
	}

	// -----------------------------------------------------------------------
	// (f) Destination has (self)+not+port 853 regardless of alias state
	// -----------------------------------------------------------------------

	/**
	 * Destination is negated (self) with port 853 when no alias set.
	 *
	 * The firewall-self exemption is structural and cannot be disabled — the
	 * firewall's own outbound port-853 traffic is always excluded from the block.
	 *
	 * Scenario (alias empty):
	 *   Given pfb_build_dot_block_rule('lan', '') called.
	 *   When rule['destination'] is inspected.
	 *   Then destination['network'] === '(self)'.
	 *   And destination contains a 'not' key (negation — self is excluded).
	 *   And destination['port'] === '853'.
	 */
	public function test_destination_has_self_not_and_port_853_alias_empty(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', '');

		// Then.
		$this->assertArrayHasKey('destination', $rule, "rule must have 'destination' key");
		$destination = $rule['destination'];
		$this->assertIsArray($destination, 'destination must be an array');

		$this->assertArrayHasKey('network', $destination,
			"destination must have 'network' key"
		);
		$this->assertSame('(self)', $destination['network'],
			"destination['network'] must be '(self)' (firewall self-exempt)"
		);

		$this->assertArrayHasKey('not', $destination,
			"destination must have 'not' key (negated — self is excluded from block)"
		);

		$this->assertArrayHasKey('port', $destination,
			"destination must have 'port' key"
		);
		$this->assertSame('853', $destination['port'],
			"destination['port'] must be '853'"
		);
	}

	/**
	 * Destination is negated (self) with port 853 when alias is set.
	 *
	 * The destination shape is identical regardless of the alias state — the
	 * alias only affects the source.
	 *
	 * Scenario (alias set):
	 *   Given pfb_build_dot_block_rule('lan', 'DoT_Exceptions') called.
	 *   When rule['destination'] is inspected.
	 *   Then destination is identical: network '(self)', not present, port '853'.
	 */
	public function test_destination_has_self_not_and_port_853_alias_set(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', 'DoT_Exceptions');

		// Then.
		$this->assertArrayHasKey('destination', $rule, "rule must have 'destination' key");
		$destination = $rule['destination'];
		$this->assertIsArray($destination, 'destination must be an array');

		$this->assertArrayHasKey('network', $destination,
			"destination must have 'network' key (alias-set variant)"
		);
		$this->assertSame('(self)', $destination['network'],
			"destination['network'] must be '(self)' when alias is set"
		);

		$this->assertArrayHasKey('not', $destination,
			"destination must have 'not' key (alias-set variant)"
		);

		$this->assertArrayHasKey('port', $destination,
			"destination must have 'port' key (alias-set variant)"
		);
		$this->assertSame('853', $destination['port'],
			"destination['port'] must be '853' (alias-set variant)"
		);
	}

	// -----------------------------------------------------------------------
	// (g) Statetype is 'keep state'
	// -----------------------------------------------------------------------

	/**
	 * Rule statetype is 'keep state'.
	 *
	 * Matches the maintainer's ground-truth rule (ADR-37 §2.2).
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('lan', '') called.
	 *   When rule['statetype'] is inspected.
	 *   Then it equals 'keep state'.
	 */
	public function test_statetype_is_keep_state(): void
	{
		// Given / When.
		$rule = $this->buildRule('lan', '');

		// Then.
		$this->assertArrayHasKey('statetype', $rule, "rule must have 'statetype' key");
		$this->assertSame('keep state', $rule['statetype'],
			"rule['statetype'] must be 'keep state'"
		);
	}

	// -----------------------------------------------------------------------
	// (h) Descr marker contains interface name
	// -----------------------------------------------------------------------

	/**
	 * Rule descr starts with 'pfB_DoT_Block_' and contains the interface name.
	 *
	 * This is the ADR-35 ownership marker — the sole ownership signal used by
	 * the sweep/reconcile logic.
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('opt2', '') called.
	 *   When rule['descr'] is inspected.
	 *   Then it starts with 'pfB_DoT_Block_' and contains 'opt2'.
	 *   And the exact value is 'pfB_DoT_Block_opt2'.
	 */
	public function test_descr_marker_contains_iface(): void
	{
		// Given / When.
		$rule = $this->buildRule('opt2', '');

		// Then.
		$this->assertArrayHasKey('descr', $rule, "rule must have 'descr' key");
		$descr = $rule['descr'];

		$this->assertIsString($descr, "rule['descr'] must be a string");
		$this->assertStringStartsWith('pfB_DoT_Block_', $descr,
			"rule['descr'] must start with 'pfB_DoT_Block_'"
		);
		$this->assertStringContainsString('opt2', $descr,
			"rule['descr'] must contain the interface name 'opt2'"
		);
		$this->assertSame('pfB_DoT_Block_opt2', $descr,
			"rule['descr'] must be exactly 'pfB_DoT_Block_opt2'"
		);
	}

	// -----------------------------------------------------------------------
	// (i) Multiple interfaces produce independent rules
	// -----------------------------------------------------------------------

	/**
	 * Rules for different interfaces are independent and carry distinct markers.
	 *
	 * Scenario:
	 *   Given pfb_build_dot_block_rule('lan', '') and pfb_build_dot_block_rule('opt1', '')
	 *     called independently.
	 *   When both rule arrays are inspected.
	 *   Then rule_lan['interface'] === 'lan' and its descr contains 'lan'.
	 *   And rule_opt1['interface'] === 'opt1' and its descr contains 'opt1'.
	 *   And the two descr values are distinct (no shared state).
	 *   And all structural fields (type, ipprotocol, protocol, destination, statetype)
	 *     are identical between the two rules (same config, different interface).
	 */
	public function test_multiple_interfaces_produce_independent_rules(): void
	{
		// Given / When.
		$rule_lan  = $this->buildRule('lan',  '');
		$rule_opt1 = $this->buildRule('opt1', '');

		// Then: each rule carries its own interface name.
		$this->assertArrayHasKey('interface', $rule_lan,  "lan rule must have 'interface' key");
		$this->assertArrayHasKey('interface', $rule_opt1, "opt1 rule must have 'interface' key");

		$this->assertSame('lan',  $rule_lan['interface'],
			"lan rule['interface'] must be 'lan'"
		);
		$this->assertSame('opt1', $rule_opt1['interface'],
			"opt1 rule['interface'] must be 'opt1'"
		);

		// Distinct markers.
		$this->assertSame('pfB_DoT_Block_lan',  $rule_lan['descr'],
			"lan rule descr must be 'pfB_DoT_Block_lan'"
		);
		$this->assertSame('pfB_DoT_Block_opt1', $rule_opt1['descr'],
			"opt1 rule descr must be 'pfB_DoT_Block_opt1'"
		);

		// Markers are distinct.
		$this->assertNotSame($rule_lan['descr'], $rule_opt1['descr'],
			'lan and opt1 rules must have distinct descr markers'
		);

		// Structural fields are identical (same rule shape, different interface).
		$this->assertSame($rule_lan['type'],        $rule_opt1['type'],        'type must match');
		$this->assertSame($rule_lan['ipprotocol'],  $rule_opt1['ipprotocol'],  'ipprotocol must match');
		$this->assertSame($rule_lan['protocol'],    $rule_opt1['protocol'],    'protocol must match');
		$this->assertSame($rule_lan['statetype'],   $rule_opt1['statetype'],   'statetype must match');
		$this->assertSame($rule_lan['destination'], $rule_opt1['destination'], 'destination must match');
	}
}
