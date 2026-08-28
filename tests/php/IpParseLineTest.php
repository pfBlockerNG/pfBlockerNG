<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Direct matrix for the pure generic IP-feed line parser extracted from the
 * sync loop.  The result array is the complete handoff contract to that loop.
 */
#[CoversFunction('pfb_ip_parse_line')]
final class IpParseLineTest extends TestCase
{
	private const RANGE = '/((?:\d{1,3}\.){3}\d{1,3})-((?:\d{1,3}\.){3}\d{1,3})/';
	private const IPV4 = '/(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/\d{1,2})?/';
	private const IPV6 = '/[0-9A-Fa-f:]+(?:\/\d{1,3})?/';

	/** @return array{vtype:string,pftype:string,custom:bool,cidr_floor_v4:int|string,cidr_floor_v6:int|string,suppression:string,range:string,ipv4:string,ipv6:string} */
	private function config(string $vtype, string $pftype = 'auto', bool $custom = TRUE, string $suppression = 'off', int|string $v4Floor = 'Disabled', int|string $v6Floor = 'Disabled'): array
	{
		return [
			'vtype'         => $vtype,
			'pftype'        => $pftype,
			'custom'        => $custom,
			'cidr_floor_v4' => $v4Floor,
			'cidr_floor_v6' => $v6Floor,
			'suppression'   => $suppression,
			'range'         => self::RANGE,
			'ipv4'          => self::IPV4,
			'ipv6'          => self::IPV6,
		];
	}

	/** @param array<string,mixed> $expected */
	private function assertLine(string $raw, array $config, array $expected): void
	{
		$this->assertSame($expected, pfb_ip_parse_line($raw, $config), "unexpected result for {$raw}");
	}

	/**
	 * @param array{entries?:list<string>,suppressed?:bool,parse_fail_delta?:int,detailed_parse_fail?:bool,messages?:list<string>} $overrides
	 * @return array{entries:list<string>,line:string,suppressed:bool,parse_fail_delta:int,detailed_parse_fail:bool,messages:list<string>}
	 */
	private function expectedResult(string $line, array $overrides = []): array
	{
		return array_replace([
			'entries'             => [],
			'line'                => $line,
			'suppressed'          => FALSE,
			'parse_fail_delta'    => 0,
			'detailed_parse_fail' => FALSE,
			'messages'            => [],
		], $overrides);
	}

	public function testBlankAndCommentPrefixesAreSkippedAfterTrim(): void
	{
		$config = $this->config('_v4');
		foreach (["  \n", ' # comment', ' ! generated', ' // generated'] as $line) {
			$this->assertLine($line, $config, [
				'entries' => [], 'line' => trim($line), 'suppressed' => FALSE,
				'parse_fail_delta' => 0, 'detailed_parse_fail' => FALSE, 'messages' => [],
			]);
		}
	}

	public function testIpv4AutoHostCidrAndCommentsPreserveOrder(): void
	{
		$config = $this->config('_v4');
		$this->assertLine("  1.2.3.4/32 # trailing\n", $config, [
			'entries' => ['1.2.3.4'], 'line' => '1.2.3.4/32', 'suppressed' => FALSE,
			'parse_fail_delta' => 0, 'detailed_parse_fail' => FALSE, 'messages' => [],
		]);
		$this->assertLine('1.2.3.0/24', $config, [
			'entries' => ['1.2.3.0/24'], 'line' => '1.2.3.0/24', 'suppressed' => FALSE,
			'parse_fail_delta' => 0, 'detailed_parse_fail' => FALSE, 'messages' => [],
		]);
	}

	public function testIpv4AutoIblockAndRangeExpand(): void
	{
		$config = $this->config('_v4');
		$this->assertLine('JKS Media, LLC:4.53.2.12-4.53.2.15', $config, $this->expectedResult(
			'4.53.2.12-4.53.2.15',
			['entries' => ['4.53.2.12/30']]
		));
		$this->assertLine('192.0.2.1-192.0.2.2', $config, $this->expectedResult(
			'192.0.2.1-192.0.2.2',
			['entries' => ['192.0.2.1', '192.0.2.2']]
		));
	}

	/**
	 * Scenario: an iBlocklist organisation name that itself contains a colon.
	 *   Given a PeerGuardian line whose "<Org Name>" part contains ':'
	 *   When the line is parsed
	 *   Then the whole range is recovered, exactly as for a colon-free org name.
	 * The separator is the LAST colon before the range, not the first (issue #1923).
	 */
	public function testIpv4AutoIblockOrgNameContainingColonStillYieldsTheRange(): void
	{
		$config = $this->config('_v4');
		$this->assertLine('Foo: Bar Inc:4.53.2.12-4.53.2.15', $config, $this->expectedResult(
			'4.53.2.12-4.53.2.15',
			['entries' => ['4.53.2.12/30']]
		));
	}

	/**
	 * Scenario: a non-iBlocklist line that merely happens to contain both '-' and ':'.
	 *   Given a Maltrail URL-path trail signature, which is not an address at all
	 *   When the line is parsed
	 *   Then the iBlocklist rewrite leaves it untouched, so the reported line is the
	 *        offending input rather than a mangled remnant.
	 * Before the gate, "…anti-sec:)" was rewritten to ")" (issue #1923).
	 */
	public function testIpv4AutoLeavesNonIblockLineWithDashAndColonIntact(): void
	{
		$config = $this->config('_v4');
		$trail = '/w00tw00t.at.blackhats.romanian.anti-sec:)';
		$this->assertLine($trail, $config, $this->expectedResult($trail));
	}

	/**
	 * Scenario: two sibling trail signatures that differ only by containing a '-'.
	 *   Given the two Maltrail w00tw00t trails, one with '-' and one without
	 *   When both are parsed
	 *   Then neither is counted as a parse failure, because neither is an address.
	 * The '-'-bearing sibling used to be rewritten into a letter-free remnant, which
	 * the final gate then mistook for a numeric parse failure (issue #1923).
	 */
	public function testIpv4AutoTrailSignaturesAreCountedSymmetrically(): void
	{
		$config = $this->config('_v4');
		$withDash = pfb_ip_parse_line('/w00tw00t.at.blackhats.romanian.anti-sec:)', $config);
		$withoutDash = pfb_ip_parse_line('/w00tw00t.at.ISC.SANS.DFind:)', $config);

		$this->assertSame(0, $withoutDash['parse_fail_delta'], 'dash-free sibling must not count as a parse failure');
		$this->assertSame(
			$withoutDash['parse_fail_delta'],
			$withDash['parse_fail_delta'],
			'both trail signatures must be counted the same way'
		);
		$this->assertSame(
			$withoutDash['detailed_parse_fail'],
			$withDash['detailed_parse_fail'],
			'both trail signatures must produce the same detailed-failure verdict'
		);
	}

	/**
	 * Scenario: an auto-typed feed ships a bare "IP/path" URL line (issue #1933).
	 *   Given the exact line shape that caused the issue #1922 outage
	 *   When the auto (non-regex) parser path handles it
	 *   Then the bare host is recovered — the first path segment is never read
	 *        as a CIDR mask (the regex path's owner-ruled outcome, PR #1932).
	 * Before, the auto path emitted '84.38.133.113/1' (= 0.0.0.0/1 aggregated).
	 */
	public function testIpv4AutoUrlPathSegmentIsNotACidrMask(): void
	{
		$line = '84.38.133.113/1/webpanel/login.php';
		$this->assertLine($line, $this->config('_v4', 'auto', FALSE), $this->expectedResult(
			$line,
			['entries' => ['84.38.133.113']]
		));
	}

	public function testIpv4RegexDeduplicatesAndSkipsCloudflare(): void
	{
		$config = $this->config('_v4', 'regex');
		$this->assertLine('from 1.2.3.4 to 1.2.3.4 and 5.6.7.8', $config, $this->expectedResult(
			'from 1.2.3.4 to 1.2.3.4 and 5.6.7.8',
			['entries' => ['1.2.3.4', '5.6.7.8']]
		));
		$this->assertLine('cf-footer-item 1.2.3.4', $config, $this->expectedResult('cf-footer-item 1.2.3.4'));
		$this->assertLine('version 1.2.3', $config, $this->expectedResult('version 1.2.3'));
	}

	public function testIpv4SuppressionFloorReplaysCoreMessage(): void
	{
		$config = $this->config('_v4', 'auto', FALSE, 'on', 24);
		$this->assertLine('8.8.8.0/16', $config, $this->expectedResult('8.8.8.0/16', [
			'entries'  => ['8.8.8.0/32'],
			'messages' => ["\n  Suppression CIDR Limit: 8.8.8.0/16"],
		]));
	}

	public function testIpv4RegexRangeCountsEachSuppressedExpandedCidr(): void
	{
		$this->assertLine(
			'192.0.2.1-192.0.2.10',
			$this->config('_v4', 'regex', FALSE, 'on'),
			$this->expectedResult('192.0.2.1-192.0.2.10', ['parse_fail_delta' => 5])
		);
	}

	public function testMalformedNumericLineRequestsDetailedParseFailureButAlphabeticIsSilent(): void
	{
		$config = $this->config('_v4');
		$this->assertLine('999.999.999.999', $config, $this->expectedResult('999.999.999.999', [
			'parse_fail_delta'    => 1,
			'detailed_parse_fail' => TRUE,
		]));
		$this->assertLine('not-an-address', $config, $this->expectedResult('not-an-address'));
		$this->assertLine('0', $config, $this->expectedResult('0'));
	}

	public function testOppositeFamilyIsSilentlySkipped(): void
	{
		$this->assertLine('2001:db8::1', $this->config('_v4'), $this->expectedResult('2001:db8::1'));
		$this->assertLine('192.0.2.1', $this->config('_v6'), $this->expectedResult('192.0.2.1'));
	}

	public function testIpv6AutoCanonicalisesCommentsAndMarksSuppression(): void
	{
		$config = $this->config('_v6');
		$this->assertLine('2001:0db8::1 # note', $config, $this->expectedResult(
			'2001:0db8::1 ',
			['entries' => ['2001:db8::1']]
		));
		$this->assertLine('fc00::1', $this->config('_v6', 'auto', FALSE, 'on'), $this->expectedResult(
			'fc00::1',
			['suppressed' => TRUE]
		));
	}

	public function testIpv6RangeAndMalformedRangeFallThroughToRegexOrFailure(): void
	{
		$config = $this->config('_v6');
		$this->assertLine('2001:db8::1-2001:db8::2', $config, $this->expectedResult(
			'2001:db8::1-2001:db8::2',
			['entries' => ['2001:db8::1/128', '2001:db8::2/128']]
		));
		$badConfig = $config;
		$badConfig['ipv6'] = '/(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})/';
		$this->assertLine('1234:5678', $badConfig, $this->expectedResult('1234:5678', [
			'parse_fail_delta'    => 1,
			'detailed_parse_fail' => TRUE,
		]));
	}

	public function testIpv6RegexDeduplicatesCloudflareAndComments(): void
	{
		$config = $this->config('_v6', 'regex');
		$this->assertLine('from 2001:db8::1#note to 2001:db8::1', $config, $this->expectedResult(
			'from 2001:db8::1#note to 2001:db8::1',
			['entries' => ['2001:db8::1']]
		));
		$this->assertLine('cf-footer-item 2001:db8::1', $config, $this->expectedResult('cf-footer-item 2001:db8::1'));
		$this->assertLine('plain-hostname', $config, $this->expectedResult('plain-hostname'));
	}

	public function testHostileWhitespaceQuotesAndInvalidUtf8StayPure(): void
	{
		$config = $this->config('_v4', 'regex');
		$this->assertLine("\t 1.2.3.4  \t", $config, $this->expectedResult('1.2.3.4', ['entries' => ['1.2.3.4']]));
		$this->assertLine('"1.2.3.4"', $config, $this->expectedResult('"1.2.3.4"', ['entries' => ['1.2.3.4']]));
		$this->assertLine("\xFF1.2.3.4", $config, $this->expectedResult("\xFF1.2.3.4", ['entries' => ['1.2.3.4']]));
	}

	public function testNonStringInputRaisesTypeErrorAtTrustBoundary(): void
	{
		$this->expectException(TypeError::class);
		/** @phpstan-ignore-next-line intentionally hostile non-string input */
		pfb_ip_parse_line([], $this->config('_v4'));
	}

	public function testOversizedNumericLineReturnsBoundedResultWithoutWriting(): void
	{
		$line = str_repeat('9', 100000);
		$this->assertLine($line, $this->config('_v4'), $this->expectedResult($line, [
			'parse_fail_delta'    => 1,
			'detailed_parse_fail' => TRUE,
		]));
	}

	public function testIpv4AutoMalformedRangeFallsThroughToRegex(): void
	{
		$this->assertLine('1.2.3.4-1.2.3.5-extra', $this->config('_v4'), $this->expectedResult(
			'1.2.3.4-1.2.3.5-extra',
			['entries' => ['1.2.3.4/31']]
		));
	}

	public function testIpv4AutoNulRangeEndpointsFallThroughToRegex(): void
	{
		$config = $this->config('_v4', 'auto', FALSE);
		$lines = [
			"5.61.209.0\0-5.61.209.255",
			"5.61.209.0-" . "\0" . "5.61.209.255",
		];
		foreach ($lines as $line) {
			$this->assertLine($line, $config, $this->expectedResult(
				$line,
				['entries' => ['5.61.209.0', '5.61.209.255']]
			));
		}
	}

	public function testIpv6AutoNulFirstRangeEndpointFallsThroughToRegex(): void
	{
		$line = "2001:4860:4860::\0-2001:4860:4860::3";
		$this->assertLine($line, $this->config('_v6', 'auto', FALSE), $this->expectedResult(
			$line,
			['entries' => ['2001:4860:4860::', '2001:4860:4860::3']]
		));
	}

	public function testIpv6AutoNulSecondRangeEndpointFallsThroughToRegex(): void
	{
		$line = "2001:4860:4860::-" . "\0" . "2001:4860:4860::3";
		$this->assertLine($line, $this->config('_v6', 'auto', FALSE), $this->expectedResult(
			$line,
			['entries' => ['2001:4860:4860::', '2001:4860:4860::3']]
		));
	}

	public function testIpv6RegexNulFirstRangeEndpointFallsThrough(): void
	{
		$line = "2001:4860:4860::\0-2001:4860:4860::3";
		$this->assertLine($line, $this->config('_v6', 'regex', FALSE), $this->expectedResult(
			$line,
			['entries' => ['2001:4860:4860::', '2001:4860:4860::3']]
		));
	}

	public function testIpv6RegexNulSecondRangeEndpointFallsThrough(): void
	{
		$line = "2001:4860:4860::-" . "\0" . "2001:4860:4860::3";
		$this->assertLine($line, $this->config('_v6', 'regex', FALSE), $this->expectedResult(
			$line,
			['entries' => ['2001:4860:4860::', '2001:4860:4860::3']]
		));
	}

	public function testIpv6AutoMixedNulRangeSafelyExtractsIpv6(): void
	{
		$line = "192.0.2.1-" . "\0" . "2001:4860:4860::3";
		$this->assertLine($line, $this->config('_v6', 'auto', FALSE), $this->expectedResult(
			$line,
			['entries' => ['2001:4860:4860::3']]
		));
	}

	public function testIpv6AutoOuterNulMixedRangesFallThroughToRegex(): void
	{
		$config = $this->config('_v6', 'auto', FALSE);
		$rows = [
			["\0" . "2001:4860:4860::3-192.0.2.1", '2001:4860:4860::3'],
			["2001:4860:4860::3-192.0.2.1" . "\0", '2001:4860:4860::3'],
			["\0" . "192.0.2.1-2001:4860:4860::3", '2001:4860:4860::3'],
			["192.0.2.1-2001:4860:4860::3" . "\0", '2001:4860:4860::3'],
		];
		foreach ($rows as [$line, $entry]) {
			$this->assertLine($line, $config, $this->expectedResult(
				trim($line),
				['entries' => [$entry]]
			));
		}
	}

	public function testIpv6EmptyAndInvalidRangesDoNotEmitEntries(): void
	{
		$config = $this->config('_v6');
		$config['ipv6'] = '/(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})/';
		foreach (['2001:db8::1-', '1234:5678-1234:5678'] as $line) {
			$this->assertLine($line, $config, $this->expectedResult($line));
		}
	}

	/**
	 * Scenario: DShield block.txt ships start/end/prefix as tab columns (issue #2602).
	 *   Given a production auto-typed feed row
	 *     5.61.209.0<TAB>5.61.209.255<TAB>24<TAB>...
	 *   When pfb_ip_parse_line runs with pftype=auto (URL suffix .txt)
	 *   Then entries are the declared CIDR, not the two extracted hosts.
	 * Stock auto sanitize of the TSV fails, parse_error takes the IPv4 regex
	 * fallback, and both columns become independent addresses. The shared
	 * hyphen RANGE constant is unused for this shape — do not widen it.
	 */
	public function testIpv4AutoDshieldTabRangeYieldsDeclaredCidr(): void
	{
		$config = $this->config('_v4', 'auto', FALSE);
		$line = "5.61.209.0\t5.61.209.255\t24\t339\tASN\tUS\tNone";
		$this->assertLine(
			$line,
			$config,
			$this->expectedResult($line, ['entries' => ['5.61.209.0/24']])
		);

		// Real DShield org column contains spaces; auto truncates at the
		// first space before the tab branch. The start/end/prefix prefix
		// of the line must still yield the declared /24.
		$spaced = "66.132.186.0\t66.132.186.255\t24\t580\tAKAMAI-LINODE-AP Akamai Connected Cloud\tSG\tnone@example.com";
		$truncated = strstr($spaced, ' ', TRUE);
		$this->assertLine(
			$spaced,
			$config,
			$this->expectedResult($truncated, ['entries' => ['66.132.186.0/24']])
		);
	}

	/**
	 * Scenario: a host-list feed writes a bare trailing .0 with no mask.
	 *   Given 8.152.209.0 (CINS shape) on the auto path
	 *   When parsed
	 *   Then pfb_sanitize_ipaddr leaves it as a host. This fixture has no
	 *        tab and never enters the DShield branch; it pins pre-existing
	 *        .0 behaviour (issue #320), not the new path.
	 */
	public function testIpv4AutoBareDotZeroHostIsNotWidenedToSlash24(): void
	{
		$this->assertLine(
			'8.152.209.0',
			$this->config('_v4', 'auto', FALSE),
			$this->expectedResult('8.152.209.0', ['entries' => ['8.152.209.0']])
		);
	}

	/**
	 * Scenario: tab-shaped rows that are not a consistent start/end/prefix.
	 *   Given reversed range, invalid/contradicting prefix, missing prefix,
	 *        or a port-as-third-column pair
	 *   When parsed
	 *   Then the tab branch falls through to the legacy two-host extract
	 *        instead of emitting a spanning cidr.
	 */
	public function testIpv4AutoDshieldTabInconsistentPrefixFallsThrough(): void
	{
		$config = $this->config('_v4', 'auto', FALSE);
		$legacyTwo = static function (string $a, string $b): array {
			return ['entries' => [$a, $b]];
		};

		$reversed = "5.61.209.255\t5.61.209.0\t24";
		$this->assertLine($reversed, $config, $this->expectedResult($reversed, $legacyTwo('5.61.209.255', '5.61.209.0')));

		$prefix99 = "5.61.209.0\t5.61.209.255\t99";
		$this->assertLine($prefix99, $config, $this->expectedResult($prefix99, $legacyTwo('5.61.209.0', '5.61.209.255')));

		$prefix33 = "5.61.209.0\t5.61.209.255\t33";
		$this->assertLine($prefix33, $config, $this->expectedResult($prefix33, $legacyTwo('5.61.209.0', '5.61.209.255')));

		$prefix0 = "5.61.209.0\t5.61.209.255\t0";
		$this->assertLine($prefix0, $config, $this->expectedResult($prefix0, $legacyTwo('5.61.209.0', '5.61.209.255')));

		$contradict = "5.61.209.0\t5.61.209.127\t24";
		$this->assertLine($contradict, $config, $this->expectedResult($contradict, $legacyTwo('5.61.209.0', '5.61.209.127')));

		$noPrefix = "5.61.209.0\t5.61.209.255";
		$this->assertLine($noPrefix, $config, $this->expectedResult($noPrefix, $legacyTwo('5.61.209.0', '5.61.209.255')));

		$portAsPrefix = "1.2.3.4\t9.8.7.6\t80\tpayload";
		$this->assertLine($portAsPrefix, $config, $this->expectedResult($portAsPrefix, $legacyTwo('1.2.3.4', '9.8.7.6')));

		$startNotNetwork = "5.61.209.1\t5.61.209.255\t24";
		$this->assertLine($startNotNetwork, $config, $this->expectedResult($startNotNetwork, $legacyTwo('5.61.209.1', '5.61.209.255')));

		// /23-sized span declared as /24: first derived chunk equals
		// start/24, count is 2. The count===1 clause is what rejects it.
		$overlong = "5.61.209.0\t5.61.210.255\t24";
		$this->assertLine($overlong, $config, $this->expectedResult($overlong, $legacyTwo('5.61.209.0', '5.61.210.255')));

		$threeDigitPrefix = "5.61.209.0\t5.61.209.255\t100";
		$this->assertLine($threeDigitPrefix, $config, $this->expectedResult($threeDigitPrefix, $legacyTwo('5.61.209.0', '5.61.209.255')));

		$ipTabText = "8.8.8.8\tnot-an-address";
		$this->assertLine($ipTabText, $config, $this->expectedResult($ipTabText, ['entries' => ['8.8.8.8']]));
	}

	public function testIpv4AutoDshieldTabNulEndpointsFallThrough(): void
	{
		$config = $this->config('_v4', 'auto', FALSE);
		foreach (["5.61.209.0\0\t5.61.209.255\t24", "5.61.209.0\t5.61.209.255\0\t24"] as $line) {
			$this->assertLine($line, $config, $this->expectedResult(
				$line,
				['entries' => ['5.61.209.0', '5.61.209.255']]
			));
		}
	}

	/**
	 * Scenario: a tab-delimited source contains rows from both address families.
	 *   Given matching IPv4 and IPv6 alias passes over the same rows
	 *   When each row is parsed independently
	 *   Then each pass emits only its family's declared CIDR and ignores the other.
	 */
	public function testAutoDshieldTabRangeUsesMatchingFamilyPerLine(): void
	{
		$v4Config = $this->config('_v4', 'auto', FALSE);
		$v6Config = $this->config('_v6', 'auto', FALSE);
		$v4Row = "5.61.209.0\t5.61.209.255\t24\t339\tASN\tUS\tNone";
		$v6Row = "2001:4860:4860:0:0:0:0:0\t2001:4860:4860::3\t126\t339\tASN\tUS\tNone";

		$this->assertLine(
			$v4Row,
			$v4Config,
			$this->expectedResult($v4Row, ['entries' => ['5.61.209.0/24']])
		);
		$this->assertLine($v6Row, $v4Config, $this->expectedResult($v6Row));
		$this->assertLine($v4Row, $v6Config, $this->expectedResult($v4Row));
		$this->assertLine(
			$v6Row,
			$v6Config,
			$this->expectedResult($v6Row, ['entries' => ['2001:4860:4860::/126']])
		);
		$this->assertLine(
			$v6Row,
			$this->config('_v6', 'regex', FALSE),
			$this->expectedResult($v6Row, ['entries' => ['2001:4860:4860::', '2001:4860:4860::3']])
		);
	}

	/** DShield tab rows retain the selected family's sanitizer side effects. */
	public function testAutoDshieldTabRangeReplaysSanitizerSideEffects(): void
	{
		$v4Row = "5.61.209.0\t5.61.209.255\t24";
		$this->assertLine(
			$v4Row,
			$this->config('_v4', 'auto', FALSE, 'on', 25),
			$this->expectedResult($v4Row, [
				'entries'  => ['5.61.209.0/32'],
				'messages' => ["\n  Suppression CIDR Limit: 5.61.209.0/24"],
			])
		);

		$v6Row = "fd00::\tfd00::3\t126";
		$this->assertLine(
			$v6Row,
			$this->config('_v6', 'auto', FALSE, 'on'),
			$this->expectedResult($v6Row, ['suppressed' => TRUE])
		);
	}

	/**
	 * Scenario: IPv6 tab rows do not describe exactly one declared CIDR.
	 *   Given reversed, invalid, contradictory, or overlong rows
	 *   When parsed by an IPv6 alias pass
	 *   Then the tab path falls through without silently widening the range.
	 */
	public function testIpv6AutoDshieldTabInconsistentPrefixFallsThrough(): void
	{
		$config = $this->config('_v6', 'auto', FALSE);
		$legacyTwo = static function (string $a, string $b): array {
			return ['entries' => [$a, $b]];
		};

		$reversed = "2001:4860:4860::3\t2001:4860:4860::\t126";
		$this->assertLine($reversed, $config, $this->expectedResult(
			$reversed,
			$legacyTwo('2001:4860:4860::3', '2001:4860:4860::')
		));

		$prefix129 = "2001:4860:4860::\t2001:4860:4860::3\t129";
		$this->assertLine($prefix129, $config, $this->expectedResult(
			$prefix129,
			$legacyTwo('2001:4860:4860::', '2001:4860:4860::3')
		));

		$contradict = "2001:4860:4860::\t2001:4860:4860::3\t127";
		$this->assertLine($contradict, $config, $this->expectedResult(
			$contradict,
			$legacyTwo('2001:4860:4860::', '2001:4860:4860::3')
		));

		$overlong = "2001:4860:4860::\t2001:4860:4860::4\t126";
		$this->assertLine($overlong, $config, $this->expectedResult(
			$overlong,
			$legacyTwo('2001:4860:4860::', '2001:4860:4860::4')
		));

		$numericThirdColumn = "2001:4860:4860::\t2001:4860:4860::3\t80\tpayload";
		$this->assertLine($numericThirdColumn, $config, $this->expectedResult(
			$numericThirdColumn,
			$legacyTwo('2001:4860:4860::', '2001:4860:4860::3')
		));

		$nulEndpoint = "2001:4860:4860::\0\t2001:4860:4860::3\t126";
		$this->assertLine($nulEndpoint, $config, $this->expectedResult(
			$nulEndpoint,
			$legacyTwo('2001:4860:4860::', '2001:4860:4860::3')
		));
	}
}
