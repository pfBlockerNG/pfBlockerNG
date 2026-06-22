<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-36 Phase 1 — Golden rule-builder tests (oracle-first).
 *
 * Pins the EXACT §2.2 rule shape returned by pfb_build_dns_redirect_rules()
 * BEFORE the builder implementation is complete. These tests are written against
 * the spec, not the implementation. They will FAIL against the Phase-1 skeleton
 * (which returns the correct shape) but verify field-by-field correctness.
 *
 * Ground-truth rule shape (from maintainer's working config.xml, ADR-36 §2.2):
 *
 *   <rule>                                <!-- nat/rule -->
 *     <source><address>ALIAS</address><not/></source>  <!-- or <any/> when empty -->
 *     <destination>
 *       <network>(self)</network><not/><port>53</port>
 *     </destination>
 *     <ipprotocol>inet</ipprotocol>        <!-- inet | inet6 -->
 *     <protocol>tcp/udp</protocol>
 *     <target>127.0.0.1</target>           <!-- inet; inet6 => ::1 -->
 *     <local-port>53</local-port>
 *     <interface>lan</interface>
 *     <descr><![CDATA[pfB_DNS_Redirect_lan_v4]]></descr>
 *     <natreflection>disable</natreflection>
 *   </rule>
 *
 * The builder returns [0 => NAT rule array, 1 => associated filter PASS rule array].
 *
 * Test inventory (branch coverage — all mandatory per ADR-36 §2.2 + CLAUDE.md):
 *   a — inet family, no exception: target=127.0.0.1, source=any, self-exempt, fixed fields
 *   b — inet6 family, no exception: target=::1, source=any, same fixed fields
 *   c — inet family, exception alias set: source=negated-alias, same fixed fields
 *   d — inet6 family, exception alias set: source=negated-alias, target=::1
 *   e — multiple interfaces: independent per-interface rule sets with distinct markers
 *   f — marker in both NAT entry [0] and filter entry [1] (pfB_-prefixed)
 *
 * Phase-1 pass status (skeleton returns correct shape):
 *   ALL tests EXPECTED PASS against the skeleton — the skeleton returns the exact
 *   §2.2 structure. Tests are oracle-first: written against the spec, exercised against
 *   the implementation in Phase 2 for final verification.
 */
final class DnsRedirectBuilderTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/**
	 * Assert the destination element matches the §2.2 invariant:
	 * negated (self) network + port 53.
	 *
	 * @param  array<string,mixed> $rule  NAT rule array.
	 * @param  string              $label Test label for context.
	 */
	private function assertDestinationSelfExempt(array $rule, string $label): void
	{
		$this->assertArrayHasKey('destination', $rule, "{$label}: destination key present");
		$dest = $rule['destination'];
		$this->assertIsArray($dest, "{$label}: destination is array");
		$this->assertArrayHasKey('network', $dest, "{$label}: destination.network present");
		$this->assertSame('(self)', $dest['network'], "{$label}: destination.network=(self)");
		$this->assertArrayHasKey('not', $dest, "{$label}: destination.not present (negated)");
		$this->assertArrayHasKey('port', $dest, "{$label}: destination.port present");
		$this->assertSame('53', $dest['port'], "{$label}: destination.port=53");
	}

	/**
	 * Assert the fixed protocol/port/reflection fields match §2.2.
	 *
	 * @param  array<string,mixed> $rule  NAT rule array (entry [0]).
	 * @param  string              $label Test label.
	 */
	private function assertFixedNatFields(array $rule, string $label): void
	{
		$this->assertArrayHasKey('protocol', $rule, "{$label}: protocol key present");
		$this->assertSame('tcp/udp', $rule['protocol'], "{$label}: protocol=tcp/udp");

		$this->assertArrayHasKey('local-port', $rule, "{$label}: local-port key present");
		$this->assertSame('53', $rule['local-port'], "{$label}: local-port=53");

		$this->assertArrayHasKey('natreflection', $rule, "{$label}: natreflection key present");
		$this->assertSame('disable', $rule['natreflection'], "{$label}: natreflection=disable");
	}

	// -----------------------------------------------------------------------
	// Case (a): inet family, no exception alias
	//   ipprotocol=inet, target=127.0.0.1, source=<any>
	//   destination=negated (self) + port 53, natreflection=disable,
	//   protocol=tcp/udp, local-port=53
	// -----------------------------------------------------------------------

	/**
	 * Scenario: inet redirect, no exception.
	 *   Background: pfb_build_dns_redirect_rules() for inet with empty exception.
	 *     Given iface='lan', ipprotocol='inet', exception=''.
	 *     When the function is called.
	 *     Then [0] is the NAT rdr rule with target=127.0.0.1, source=<any>.
	 *     And destination is negated (self) + port 53 (firewall-self-exempt).
	 *     And natreflection=disable, protocol=tcp/udp, local-port=53.
	 *     And [1] is the associated filter PASS rule.
	 */
	public function testInetNoExceptionTargetIs127AndSourceIsAny(): void
	{
		// Given.
		$result = pfb_build_dns_redirect_rules('lan', 'inet', '');

		// Then: two entries returned.
		$this->assertIsArray($result, 'return value must be array');
		$this->assertCount(2, $result, 'result must have exactly 2 entries [NAT, filter]');

		$nat = $result[0];
		$this->assertIsArray($nat, '[0] (NAT rule) must be array');

		// ipprotocol.
		$this->assertArrayHasKey('ipprotocol', $nat, '[0]: ipprotocol key present');
		$this->assertSame('inet', $nat['ipprotocol'], '[0]: ipprotocol=inet');

		// target = 127.0.0.1 for inet.
		$this->assertArrayHasKey('target', $nat, '[0]: target key present');
		$this->assertSame('127.0.0.1', $nat['target'], '[0]: target=127.0.0.1 for inet');

		// source = <any> (no exception).
		$this->assertArrayHasKey('source', $nat, '[0]: source key present');
		$source = $nat['source'];
		$this->assertIsArray($source, '[0]: source is array');
		$this->assertArrayHasKey('any', $source, '[0]: source must contain any key when exception empty');
		$this->assertArrayNotHasKey('address', $source, '[0]: source must NOT have address key when exception empty');
		$this->assertArrayNotHasKey('not', $source, '[0]: source must NOT have not key when exception empty');

		// destination: negated (self) + port 53.
		$this->assertDestinationSelfExempt($nat, '[0] inet no-exception');

		// Fixed fields.
		$this->assertFixedNatFields($nat, '[0] inet no-exception');

		// interface.
		$this->assertArrayHasKey('interface', $nat, '[0]: interface key present');
		$this->assertSame('lan', $nat['interface'], '[0]: interface=lan');
	}

	// -----------------------------------------------------------------------
	// Case (b): inet6 family, no exception alias
	//   ipprotocol=inet6, target=::1, source=<any>
	// -----------------------------------------------------------------------

	/**
	 * Scenario: inet6 redirect, no exception.
	 *   Background: pfb_build_dns_redirect_rules() for inet6 with empty exception.
	 *     Given iface='lan', ipprotocol='inet6', exception=''.
	 *     When the function is called.
	 *     Then [0] target=::1 (NOT 127.0.0.1).
	 *     And [0] ipprotocol=inet6.
	 *     And destination is negated (self) + port 53.
	 *     And natreflection=disable, protocol=tcp/udp, local-port=53.
	 */
	public function testInet6NoExceptionTargetIsLoopback6AndSourceIsAny(): void
	{
		// Given.
		$result = pfb_build_dns_redirect_rules('lan', 'inet6', '');

		$this->assertCount(2, $result, 'result must have exactly 2 entries');
		$nat = $result[0];

		// ipprotocol = inet6.
		$this->assertArrayHasKey('ipprotocol', $nat, '[0]: ipprotocol key present');
		$this->assertSame('inet6', $nat['ipprotocol'], '[0]: ipprotocol=inet6');

		// target = ::1 for inet6 (NOT 127.0.0.1).
		$this->assertArrayHasKey('target', $nat, '[0]: target key present');
		$this->assertSame('::1', $nat['target'], '[0]: target=::1 for inet6');
		$this->assertNotSame('127.0.0.1', $nat['target'], '[0]: inet6 target must not be 127.0.0.1');

		// source = <any>.
		$source = $nat['source'];
		$this->assertArrayHasKey('any', $source, '[0]: source=any when exception empty (inet6)');
		$this->assertArrayNotHasKey('address', $source, '[0]: source must NOT have address key (inet6 no-exception)');

		// destination: negated (self) + port 53.
		$this->assertDestinationSelfExempt($nat, '[0] inet6 no-exception');

		// Fixed fields.
		$this->assertFixedNatFields($nat, '[0] inet6 no-exception');
	}

	// -----------------------------------------------------------------------
	// Case (c): inet family, exception alias set
	//   source = negated alias (<address>$alias</address><not/>)
	// -----------------------------------------------------------------------

	/**
	 * Scenario: inet redirect, exception alias set.
	 *   Background: pfb_build_dns_redirect_rules() with a non-empty exception.
	 *     Given iface='lan', ipprotocol='inet', exception='DNS_Whitelist'.
	 *     When the function is called.
	 *     Then [0] source has address='DNS_Whitelist' AND not key present (negated).
	 *     And destination is negated (self) + port 53.
	 *     And target=127.0.0.1 (inet), natreflection=disable, protocol=tcp/udp.
	 */
	public function testInetWithExceptionSourceIsNegatedAlias(): void
	{
		// Given.
		$result = pfb_build_dns_redirect_rules('lan', 'inet', 'DNS_Whitelist');

		$this->assertCount(2, $result, 'result must have exactly 2 entries');
		$nat = $result[0];

		// source: negated alias.
		$this->assertArrayHasKey('source', $nat, '[0]: source key present');
		$source = $nat['source'];
		$this->assertIsArray($source, '[0]: source is array');
		$this->assertArrayHasKey('address', $source, '[0]: source.address present when exception set');
		$this->assertSame('DNS_Whitelist', $source['address'], '[0]: source.address=DNS_Whitelist');
		$this->assertArrayHasKey('not', $source, '[0]: source.not present (negated exception)');
		$this->assertArrayNotHasKey('any', $source, '[0]: source must NOT have any key when exception set');

		// target still inet.
		$this->assertSame('127.0.0.1', $nat['target'], '[0]: target=127.0.0.1 for inet with exception');

		// destination: negated (self) + port 53.
		$this->assertDestinationSelfExempt($nat, '[0] inet with-exception');

		// Fixed fields.
		$this->assertFixedNatFields($nat, '[0] inet with-exception');
	}

	/**
	 * Transition test: before (empty exception → any) vs after (non-empty → negated alias).
	 *
	 * Asserts the BEFORE state (empty) then the AFTER state (set), proving the branch
	 * flip caused the change (ADR-29 / CLAUDE.md test coverage mandate).
	 */
	public function testExceptionTransitionFromEmptyToSetChangesSourceBranch(): void
	{
		// Before: empty exception → source is <any>.
		$before = pfb_build_dns_redirect_rules('lan', 'inet', '');
		$this->assertArrayHasKey('any', $before[0]['source'],
			'before: source=any when exception empty'
		);
		$this->assertArrayNotHasKey('address', $before[0]['source'],
			'before: no address key when exception empty'
		);

		// After: non-empty exception → source is negated alias.
		$after = pfb_build_dns_redirect_rules('lan', 'inet', 'DNS_Whitelist');
		$this->assertArrayHasKey('address', $after[0]['source'],
			'after: source.address present when exception set'
		);
		$this->assertArrayHasKey('not', $after[0]['source'],
			'after: source.not present (negated) when exception set'
		);
		$this->assertArrayNotHasKey('any', $after[0]['source'],
			'after: no any key when exception set'
		);
	}

	// -----------------------------------------------------------------------
	// Case (d): inet6 family, exception alias set
	//   source=negated-alias, target=::1, ipprotocol=inet6
	// -----------------------------------------------------------------------

	/**
	 * Scenario: inet6 redirect, exception alias set.
	 *   Background: pfb_build_dns_redirect_rules() for inet6 with non-empty exception.
	 *     Given iface='lan', ipprotocol='inet6', exception='DNS_Whitelist'.
	 *     When the function is called.
	 *     Then [0] source has address='DNS_Whitelist' AND not key (negated).
	 *     And [0] target=::1 (inet6).
	 *     And destination is negated (self) + port 53.
	 */
	public function testInet6WithExceptionSourceIsNegatedAliasAndTargetIsLoopback6(): void
	{
		// Given.
		$result = pfb_build_dns_redirect_rules('lan', 'inet6', 'DNS_Whitelist');

		$this->assertCount(2, $result, 'result must have exactly 2 entries');
		$nat = $result[0];

		// source: negated alias.
		$source = $nat['source'];
		$this->assertArrayHasKey('address', $source, '[0]: source.address present (inet6 + exception)');
		$this->assertSame('DNS_Whitelist', $source['address'], '[0]: source.address=DNS_Whitelist (inet6)');
		$this->assertArrayHasKey('not', $source, '[0]: source.not present (inet6 + exception)');
		$this->assertArrayNotHasKey('any', $source, '[0]: no any key (inet6 + exception)');

		// target = ::1 (inet6).
		$this->assertSame('::1', $nat['target'], '[0]: target=::1 for inet6 with exception');
		$this->assertNotSame('127.0.0.1', $nat['target'], '[0]: inet6 must not target 127.0.0.1');

		// ipprotocol = inet6.
		$this->assertSame('inet6', $nat['ipprotocol'], '[0]: ipprotocol=inet6 with exception');

		// destination: negated (self) + port 53.
		$this->assertDestinationSelfExempt($nat, '[0] inet6 with-exception');
	}

	// -----------------------------------------------------------------------
	// Case (e): Multiple interfaces — independent rule sets, distinct markers
	// -----------------------------------------------------------------------

	/**
	 * Scenario: multiple interfaces produce independent rule sets.
	 *   Background: pfb_build_dns_redirect_rules() called for each interface.
	 *     Given two calls: iface='lan' and iface='opt1', both inet, no exception.
	 *     When each call returns [NAT, filter].
	 *     Then each set is independent — different interface fields, different markers.
	 *     And the markers differ by interface name.
	 */
	public function testMultipleInterfacesProduceIndependentRuleSets(): void
	{
		// Given.
		$lan  = pfb_build_dns_redirect_rules('lan', 'inet', '');
		$opt1 = pfb_build_dns_redirect_rules('opt1', 'inet', '');

		// Each returns 2 entries.
		$this->assertCount(2, $lan, 'lan result must have 2 entries');
		$this->assertCount(2, $opt1, 'opt1 result must have 2 entries');

		// Interface fields differ.
		$this->assertSame('lan', $lan[0]['interface'], 'lan[0].interface=lan');
		$this->assertSame('opt1', $opt1[0]['interface'], 'opt1[0].interface=opt1');

		// Markers differ (contain the interface name).
		$lan_descr  = $lan[0]['descr'];
		$opt1_descr = $opt1[0]['descr'];

		$this->assertStringContainsString('lan', $lan_descr, 'lan NAT marker must contain interface name');
		$this->assertStringContainsString('opt1', $opt1_descr, 'opt1 NAT marker must contain interface name');
		$this->assertNotSame($lan_descr, $opt1_descr, 'markers for different interfaces must differ');

		// Each set has correct target (both inet).
		$this->assertSame('127.0.0.1', $lan[0]['target'], 'lan target=127.0.0.1');
		$this->assertSame('127.0.0.1', $opt1[0]['target'], 'opt1 target=127.0.0.1');

		// Destination invariant holds for both.
		$this->assertDestinationSelfExempt($lan[0], 'lan[0]');
		$this->assertDestinationSelfExempt($opt1[0], 'opt1[0]');
	}

	// -----------------------------------------------------------------------
	// Case (f): Marker in both NAT entry [0] AND filter entry [1]
	//   descr is pfB_-prefixed in both entries; family-specific suffix
	// -----------------------------------------------------------------------

	/**
	 * Scenario: descr marker present in both NAT and filter rule (inet).
	 *   Background: pfb_build_dns_redirect_rules() for inet.
	 *     Given iface='lan', ipprotocol='inet', exception=''.
	 *     When called.
	 *     Then [0].descr starts with 'pfB_' (pfb_fwobj_is_owned() marker).
	 *     And [1].descr starts with 'pfB_' (filter rule also owned).
	 *     And both descr values are the same marker string.
	 *     And descr contains '_v4' suffix (inet family).
	 */
	public function testInetDescrMarkerPresentInBothNatAndFilterEntries(): void
	{
		// Given.
		$result = pfb_build_dns_redirect_rules('lan', 'inet', '');

		$nat_descr    = $result[0]['descr'];
		$filter_descr = $result[1]['descr'];

		// Both entries have a descr.
		$this->assertArrayHasKey('descr', $result[0], '[0]: descr key present');
		$this->assertArrayHasKey('descr', $result[1], '[1]: descr key present');

		// Both start with 'pfB_'.
		$this->assertStringStartsWith('pfB_', $nat_descr,
			'[0]: NAT descr must start with pfB_ (pfb_fwobj_is_owned marker)'
		);
		$this->assertStringStartsWith('pfB_', $filter_descr,
			'[1]: filter descr must start with pfB_ (pfb_fwobj_is_owned marker)'
		);

		// Both carry the interface name.
		$this->assertStringContainsString('lan', $nat_descr, '[0]: NAT descr contains interface');
		$this->assertStringContainsString('lan', $filter_descr, '[1]: filter descr contains interface');

		// inet marker has '_v4' suffix.
		$this->assertStringContainsString('_v4', $nat_descr, '[0]: inet marker has _v4 suffix');
		$this->assertStringContainsString('_v4', $filter_descr, '[1]: filter inet marker has _v4 suffix');

		// Must NOT contain 'pfB DNSBL' (space) — would be misidentified as a DNSBL rule.
		$this->assertStringNotContainsString('pfB DNSBL', $nat_descr,
			'[0]: NAT descr must not contain pfB DNSBL (space) — would be bucketed as DNSBL'
		);
		$this->assertStringNotContainsString('pfB DNSBL', $filter_descr,
			'[1]: filter descr must not contain pfB DNSBL (space)'
		);
	}

	/**
	 * Scenario: descr marker present in both NAT and filter rule (inet6).
	 *   Background: pfb_build_dns_redirect_rules() for inet6.
	 *     Given iface='lan', ipprotocol='inet6', exception=''.
	 *     When called.
	 *     Then [0].descr and [1].descr both start with 'pfB_'.
	 *     And both contain '_v6' suffix (inet6 family).
	 *     And both contain the interface name.
	 */
	public function testInet6DescrMarkerPresentInBothNatAndFilterEntries(): void
	{
		// Given.
		$result = pfb_build_dns_redirect_rules('lan', 'inet6', '');

		$nat_descr    = $result[0]['descr'];
		$filter_descr = $result[1]['descr'];

		// Both start with 'pfB_'.
		$this->assertStringStartsWith('pfB_', $nat_descr,
			'[0]: inet6 NAT descr must start with pfB_'
		);
		$this->assertStringStartsWith('pfB_', $filter_descr,
			'[1]: inet6 filter descr must start with pfB_'
		);

		// inet6 marker has '_v6' suffix (NOT '_v4').
		$this->assertStringContainsString('_v6', $nat_descr, '[0]: inet6 marker has _v6 suffix');
		$this->assertStringContainsString('_v6', $filter_descr, '[1]: filter inet6 marker has _v6 suffix');
		$this->assertStringNotContainsString('_v4', $nat_descr, '[0]: inet6 marker must not have _v4 suffix');
		$this->assertStringNotContainsString('_v4', $filter_descr, '[1]: filter inet6 must not have _v4 suffix');

		// Both contain the interface name.
		$this->assertStringContainsString('lan', $nat_descr, '[0]: inet6 NAT descr contains interface');
		$this->assertStringContainsString('lan', $filter_descr, '[1]: inet6 filter descr contains interface');

		// Must NOT contain 'pfB DNSBL' (space).
		$this->assertStringNotContainsString('pfB DNSBL', $nat_descr,
			'[0]: inet6 NAT descr must not contain pfB DNSBL (space)'
		);
		$this->assertStringNotContainsString('pfB DNSBL', $filter_descr,
			'[1]: inet6 filter descr must not contain pfB DNSBL (space)'
		);
	}

	/**
	 * inet vs inet6 markers are distinct (different suffix).
	 *
	 * Scenario:
	 *   Background: markers are family-specific.
	 *     Given two calls — same iface, inet and inet6.
	 *     When both return markers.
	 *     Then the markers are NOT equal (suffix differs).
	 */
	public function testInetAndInet6MarkersAreDistinct(): void
	{
		$v4 = pfb_build_dns_redirect_rules('lan', 'inet', '');
		$v6 = pfb_build_dns_redirect_rules('lan', 'inet6', '');

		$this->assertNotSame($v4[0]['descr'], $v6[0]['descr'],
			'inet and inet6 markers must differ (family-specific suffix)'
		);
	}

	// -----------------------------------------------------------------------
	// Additional invariant: invalid ipprotocol throws
	// -----------------------------------------------------------------------

	/**
	 * Scenario: invalid ipprotocol throws InvalidArgumentException.
	 *   Background: only 'inet' and 'inet6' are valid families.
	 *     Given ipprotocol='inet4' (invalid).
	 *     When pfb_build_dns_redirect_rules() is called.
	 *     Then InvalidArgumentException is thrown.
	 */
	public function testInvalidIpprotocolThrowsInvalidArgumentException(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		pfb_build_dns_redirect_rules('lan', 'inet4', '');
	}

	// -----------------------------------------------------------------------
	// Return structure: always exactly two entries, both arrays
	// -----------------------------------------------------------------------

	/**
	 * Scenario: return structure is always [0 => array, 1 => array].
	 *   Background: caller expects exactly two entries.
	 *     Given any valid call.
	 *     When called.
	 *     Then result has exactly 2 entries at keys 0 and 1, both arrays.
	 */
	public function testReturnStructureIsAlwaysTwoArrayEntries(): void
	{
		$cases = [
			['lan', 'inet', ''],
			['lan', 'inet6', ''],
			['lan', 'inet', 'SomeAlias'],
			['opt1', 'inet6', 'SomeAlias'],
		];

		foreach ($cases as [$iface, $proto, $exception]) {
			$result = pfb_build_dns_redirect_rules($iface, $proto, $exception);
			$this->assertCount(2, $result,
				"({$iface},{$proto},{$exception}): must return exactly 2 entries"
			);
			$this->assertIsArray($result[0],
				"({$iface},{$proto},{$exception}): result[0] must be array"
			);
			$this->assertIsArray($result[1],
				"({$iface},{$proto},{$exception}): result[1] must be array"
			);
		}
	}
}
