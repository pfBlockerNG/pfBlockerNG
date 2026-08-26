<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class IpRecomputeRanWiringTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_recompute_ran_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($this->root, 0777, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->root);
		$this->assertDirectoryDoesNotExist($this->root);
	}

	public function testRanFlagIsSetOnlyAfterTheMatchingFamilyRunnerCompletes(): void
	{
		$ranV4 = $ranV6 = FALSE;
		$families = [];
		pfb_ip_recompute_mark_ran('v4', static function () use (&$families): void {
			$families[] = 'v4';
		}, $ranV4, $ranV6);
		$this->assertSame(['v4'], $families);
		$this->assertTrue($ranV4);
		$this->assertFalse($ranV6);

		pfb_ip_recompute_mark_ran('v6', static function () use (&$families): void {
			$families[] = 'v6';
		}, $ranV4, $ranV6);
		$this->assertSame(['v4', 'v6'], $families);
		$this->assertTrue($ranV6);
	}

	public function testFailedRecomputeDoesNotAdvertiseThatFamilyAsRan(): void
	{
		$ranV4 = $ranV6 = FALSE;
		$this->expectException(RuntimeException::class);
		try {
			pfb_ip_recompute_mark_ran('v4', static function (): void {
				throw new RuntimeException('recompute failed');
			}, $ranV4, $ranV6);
		} finally {
			$this->assertFalse($ranV4);
			$this->assertFalse($ranV6);
		}
	}

	public function testSuppressionBodyUsesTheFamilySpecificRecomputeSignal(): void
	{
		$this->assertTrue(pfb_ip_suppress_body_active(TRUE, TRUE, TRUE, TRUE, FALSE, TRUE));
		$this->assertFalse(pfb_ip_suppress_body_active(TRUE, TRUE, TRUE, TRUE, FALSE, FALSE));
		$this->assertFalse(pfb_ip_suppress_body_active(TRUE, FALSE, TRUE, TRUE, FALSE, TRUE));
		$this->assertTrue(pfb_ip_suppress_body_active(TRUE, TRUE, TRUE, TRUE, TRUE, FALSE));
	}

	public function testRecomputeSignalSelectionFollowsTheRequestedAddressFamily(): void
	{
		$this->assertTrue(pfb_ip_suppress_body_for_vtype(TRUE, '_v4', TRUE, TRUE, FALSE, TRUE, FALSE));
		$this->assertFalse(pfb_ip_suppress_body_for_vtype(TRUE, '_v4', TRUE, TRUE, FALSE, FALSE, TRUE));
		$this->assertTrue(pfb_ip_suppress_body_for_vtype(TRUE, '_v6', TRUE, TRUE, FALSE, FALSE, TRUE));
		$this->assertFalse(pfb_ip_suppress_body_for_vtype(TRUE, '_v6', TRUE, TRUE, FALSE, TRUE, FALSE));
		$this->assertFalse(pfb_ip_suppress_body_for_vtype(TRUE, '_bogus', TRUE, TRUE, FALSE, TRUE, TRUE));
	}

	public function testClosingPassRequiresV4RecomputeWhenDedupIsOff(): void
	{
		$this->assertSame([TRUE, 'on'], pfb_ip_closing_pass_active(TRUE, FALSE));
		$this->assertSame([TRUE, 'off'], pfb_ip_closing_pass_active(FALSE, TRUE));
		$this->assertSame([FALSE, 'off'], pfb_ip_closing_pass_active(FALSE, FALSE));
	}

	public function testV6SnapshotPipelineWritesTheFamilySnapshot(): void
	{
		$source = "{$this->root}/Feed_v6.txt";
		$snapdir = "{$this->root}/snap";
		$origdir = "{$this->root}/orig";
		mkdir($snapdir);
		mkdir($origdir);
		file_put_contents($source, "2001:db8::1\n");

		pfb_ip_recompute_write_snapshot($source, 'Feed_v6', $snapdir, $origdir);

		$this->assertSame("2001:db8::1\n", file_get_contents("{$snapdir}/Feed_v6.snap"));
		$this->assertSame("1\n", file_get_contents("{$origdir}/Feed_v6.aggcount"));
	}

	public function testLiveFirewallDispatchConsumesFamilyRecomputeSignals(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertStringContainsString(
			'$suppression_body_active = pfb_ip_suppress_body_for_vtype($pfb[\'supp\'] === PfbToggle::On, $vtype, $pfb[\'supp_update\'], $pfbadv, in_array($alias, $final_alias_old), $pfb_recompute_ran_v4, $pfb_recompute_ran_v6)',
			$source,
			'issue #993: live firewall orchestration has no safe off-box driver; its one code-only pin must dispatch through the tested family seam'
		);
		$this->assertStringContainsString(
			'pfb_ip_closing_pass_active($pfb[\'dup\'] === PfbToggle::On, $pfb_recompute_ran_v4)',
			$source,
			'issue #993: final live closing dispatch is appliance-only; its code-only pin must pass the behavior-tested v4 recompute signal'
		);
	}
}
