<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4038 (slice 9b), from the decision of 2026-11-21 on #4037: the members of an ip-set or ip-aggregate are agreed between
 * Core and the Outpost by one fixture, tests/core/fixtures/ip_members.json. Core's canonical member function
 * (go/pfb_core/update/apply, Member) runs it from Go; this test runs it through the Outpost's member check:
 *   - the check gives each member as written the verdict the row records (outpost), the one Go relies on;
 *   - every member Core publishes (canonical) is one the check accepts, so no published body fails the Outpost's check;
 *   - Core never publishes a spelling the check refuses: a row the check refuses as written (a prefix length with a leading
 *     zero) is published, if at all, in another spelling the check accepts;
 *   - every member of a body the ipset corpus departure rows say Core publishes is one the check accepts.
 */
#[CoversFunction('pfb_outpost_ip_member_valid')]
final class IpMembersFixtureTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/ip_members.json';

	/** @return array<string, mixed> */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{0: array{member: string, family: string, outpost: bool, canonical: ?string, note: string}}> */
	public static function members(): array
	{
		$rows = [];
		foreach (self::fixture()['members'] as $row) {
			$rows[json_encode([$row['member'], $row['family']], JSON_THROW_ON_ERROR)] = [$row];
		}
		return $rows;
	}

	public function testTheFixtureIsTheMemberContractAndHoldsEveryHostileKind(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('ip-set-members', $doc['contract']);
		$keys = array_map(static fn (array $row): string => $row['family'] . ' ' . $row['member'], $doc['members']);
		$this->assertSame(array_values(array_unique($keys)), $keys, 'a member and family appear once');
		foreach (['1.2.3.4-1.2.3.9', '1.2.3.0/255.255.255.0', 'pfbipset-nx.invalid', 'fe80::1%em0', '1.2.3.4/33', '0.1.2.3', '::',
			'0.0.0.0/0', '::/0', '1.2.3.4/0'] as $hostile) {
			$this->assertContains($hostile, array_column($doc['members'], 'member'), "the hostile member {$hostile} has a row");
		}
		$this->assertNotSame([], $doc['ipset_departures'], 'the ipset corpus rows Core publishes differently are listed');
	}

	/** @param array{member: string, family: string, outpost: bool, canonical: ?string, note: string} $row */
	#[DataProvider('members')]
	public function testTheOutpostCheckAgreesWithWhatCorePublishes(array $row): void
	{
		$this->assertSame($row['outpost'], pfb_outpost_ip_member_valid($row['member'], $row['family']),
			json_encode($row['member']) . " in an {$row['family']} set: the check's verdict ({$row['note']})");
		if ($row['canonical'] === NULL) {
			return;
		}
		if (!$row['outpost']) {
			$this->assertNotSame($row['member'], $row['canonical'], json_encode($row['member']) . ': Core never publishes the spelling the check refuses');
		}
		$this->assertTrue(pfb_outpost_ip_member_valid($row['canonical'], $row['family']),
			json_encode($row['canonical']) . ": what Core publishes for " . json_encode($row['member']) . ' passes the check');
	}

	public function testEveryMemberCorePublishesForTheIpsetCorpusPassesTheCheck(): void
	{
		$checked = 0;
		foreach (self::fixture()['ipset_departures'] as $row) {
			foreach ($row['expect'] as $member) {
				$this->assertTrue(pfb_outpost_ip_member_valid($member, $row['family']), "{$row['case']} {$row['list']}: " . json_encode($member));
				$checked++;
			}
		}
		$this->assertGreaterThan(0, $checked, 'the departure rows publish members');
	}
}
