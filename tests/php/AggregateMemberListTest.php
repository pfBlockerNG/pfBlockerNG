<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-11 Phase 4 — pin the membership contract of pfb_aggregate_member_list($type,$family),
 * the helper that decides which member files each per-type aggregate ("Uber") alias unions.
 *
 * The aggregate's CORRECTNESS is its membership: which files go into the union. This helper
 * is the single decision point, so pinning it off-box pins the set the live `aggregate`
 * action then dedups + iprange-collapses. The live pf-table / real-suppress-run / HAProxy
 * legs are the §7 manual smoke (CI cannot load pf tables); see the per-test notes for the
 * exact off-box-vs-deferred split.
 *
 * Feature: Per-type aggregate membership
 *   Background:
 *     Given a per-action-class member dir (deny/permit/match/native) of '<header>_<fam>.txt'
 *           files, written one-per-member by the update pass
 *     And   the helper maps a type label to its dir and globs '*_<family>.txt'
 *
 * Branch coverage (every condition, both sides):
 *   * each of the four known types -> its OWN dir (Deny/Permit/Match/Native), no cross-leak;
 *   * an unknown type -> [];  an unknown family -> [];
 *   * a missing dir -> [] (glob FALSE/empty);  an empty dir -> [];
 *   * the family filter: v4 vs v6 select disjoint subsets of the SAME dir;
 *   * the include/exclude rule: '*_<fam>.txt' INCLUDES feed members (incl. DNSBLIP and
 *     Deny-action GeoIP continents, which land in denydir by their action) and EXCLUDES
 *     '.update' markers, '.ip' feeds and non-family scratch files;
 *   * single member;  result is sorted.
 */
#[CoversFunction('pfb_aggregate_member_list')]
#[CoversFunction('pfb_member_file_is_placeholder_only')]
final class AggregateMemberListTest extends TestCase
{
	/** @var string Per-test sandbox root; one fresh dir tree per test. */
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_agg_' . getmypid() . '_' . uniqid();
		// The four per-type dirs the helper maps to (mirrors inc:47-50).
		foreach (['deny', 'permit', 'match', 'native'] as $d) {
			@mkdir("{$this->root}/{$d}", 0777, true);
		}
		$GLOBALS['pfb']['denydir']   = "{$this->root}/deny";
		$GLOBALS['pfb']['permitdir'] = "{$this->root}/permit";
		$GLOBALS['pfb']['matchdir']  = "{$this->root}/match";
		$GLOBALS['pfb']['nativedir'] = "{$this->root}/native";
		// Default: no placeholder configured -> the placeholder-only filter is a no-op, so
		// every membership test that does not opt in is unaffected. The placeholder test sets
		// it explicitly. Unset here for isolation (PHPUnit shares $GLOBALS across tests).
		unset($GLOBALS['pfb']['ip_ph']);
	}

	protected function tearDown(): void
	{
		// Best-effort recursive cleanup of the sandbox.
		$it = @glob("{$this->root}/*/*") ?: [];
		foreach ($it as $f) {
			@unlink($f);
		}
		// issue #1250: the matchgendir-exclusion test nests 'generated' under match/.
		foreach (@glob("{$this->root}/match/generated/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir("{$this->root}/match/generated");
		foreach (['deny', 'permit', 'match', 'native'] as $d) {
			@rmdir("{$this->root}/{$d}");
		}
		@rmdir($this->root);
	}

	/** Drop an empty file at <dir>/<name>, asserting the write succeeded. */
	private function touchMember(string $dir, string $name): string
	{
		$path = "{$GLOBALS['pfb'][$dir]}/{$name}";
		$this->assertNotFalse(@file_put_contents($path, ''), "could not create {$path}");
		return $path;
	}

	/** Write <content> to <dir>/<name>, asserting the write succeeded; return the path. */
	private function writeMember(string $dir, string $name, string $content): string
	{
		$path = "{$GLOBALS['pfb'][$dir]}/{$name}";
		$this->assertNotFalse(@file_put_contents($path, $content), "could not write {$path}");
		return $path;
	}

	/**
	 * Deny aggregate = the denydir union, and it INCLUDES the DNSBLIP feed member and any
	 * Deny-action GeoIP continent member "for free": both are written into denydir as plain
	 * '<header>_<fam>.txt' files by their action during the pass (DNSBLIP via $pfb['dnsbl_ip']
	 * routing, inc:10917-10930; continents via pfb_determine_list_detail by action, §1.5).
	 * The glob therefore picks them up with no special-casing.
	 *
	 *   Given denydir holds a feed member, DNSBLIP_v4.txt, and a Deny-action continent member
	 *   When  the Deny/v4 member list is computed
	 *   Then  ALL THREE are present (sorted), with no other dir's files mixed in.
	 */
	public function testDenyIncludesDnsblipAndDenyActionGeoIpContinent(): void
	{
		$feed      = $this->touchMember('denydir', 'feedA_v4.txt');
		$dnsblip   = $this->touchMember('denydir', 'DNSBLIP_v4.txt');
		$continent = $this->touchMember('denydir', 'Africa_v4.txt');	// a Deny-action GeoIP continent

		$got = pfb_aggregate_member_list('Deny', 'v4');

		$this->assertContains($dnsblip, $got, 'DNSBLIP member must fold into the Deny aggregate');
		$this->assertContains($continent, $got, 'Deny-action GeoIP continent must fold into the Deny aggregate');
		$this->assertContains($feed, $got, 'an ordinary Deny feed member must be present');
		$this->assertSame([$continent, $dnsblip, $feed], $got, 'exactly the denydir v4 members, sorted');
	}

	/**
	 * Effective (post-suppression) Deny set, off-box demonstrable half: the helper returns the
	 * denydir FILE PATHS, and those files are rewritten IN PLACE by the `suppress` shell action
	 * BEFORE the aggregate reads them (inc:11002-11013 precedes the build call at inc:11116), so
	 * "whatever the glob picks up is the effective set". A suppressed entry's ABSENCE from the
	 * unioned CONTENT is a property of the file's bytes after grepcidr runs — that content proof
	 * needs the live suppress pass and is the §7 manual-smoke item. What is provable off-box, and
	 * is pinned here, is the membership half: the helper unions exactly the denydir member files
	 * and adds NO further file of its own (it does not, e.g., re-read raw/orig feeds that would
	 * re-introduce a suppressed IP).
	 *
	 *   Given denydir holds the post-suppression member file (and a sibling raw '.orig' that the
	 *         helper must NOT pull in)
	 *   When  the Deny/v4 member list is computed
	 *   Then  only the post-suppression '<header>_v4.txt' is unioned; the raw sibling is excluded.
	 */
	public function testDenyUnionsOnlyTheEffectiveMemberFilesNotRawSiblings(): void
	{
		$effective = $this->touchMember('denydir', 'feedB_v4.txt');	// post-suppression member
		$this->touchMember('denydir', 'feedB_v4.orig');			// a raw sibling (must be ignored)
		$this->touchMember('denydir', 'feedB_v4.raw');			// another non-.txt scratch

		$got = pfb_aggregate_member_list('Deny', 'v4');

		$this->assertSame([$effective], $got, 'union = the effective .txt member only; no raw re-introduction');
	}

	/**
	 * Permit/Match/Native aggregates are exact unions of their OWN dir, with NO cross-type
	 * leakage: a member of one type's dir never appears in another type's aggregate. A continent
	 * routed to Permit appears in the Permit aggregate and is ABSENT from Deny (the §1.5 "GeoIP
	 * folds by action, never double-listed" guarantee), proving membership is dir-scoped.
	 *
	 *   Given each of the four dirs holds one distinct v4 member (incl. a Permit-action continent)
	 *   When  each type's v4 member list is computed
	 *   Then  each returns exactly its own dir's member and nothing from a sibling dir.
	 */
	public function testNoCrossTypeLeakageEachAggregateIsItsOwnDir(): void
	{
		$denyM      = $this->touchMember('denydir', 'd_v4.txt');
		$permitM    = $this->touchMember('permitdir', 'p_v4.txt');
		$permitGeo  = $this->touchMember('permitdir', 'Europe_v4.txt');	// a Permit-action continent
		$matchM     = $this->touchMember('matchdir', 'm_v4.txt');
		$nativeM    = $this->touchMember('nativedir', 'n_v4.txt');

		$deny   = pfb_aggregate_member_list('Deny', 'v4');
		$permit = pfb_aggregate_member_list('Permit', 'v4');
		$match  = pfb_aggregate_member_list('Match', 'v4');
		$native = pfb_aggregate_member_list('Native', 'v4');

		// Each aggregate = exactly its own dir.
		$this->assertSame([$denyM], $deny);
		$this->assertSame([$permitGeo, $permitM], $permit);	// sorted: 'Europe...' < 'p...'
		$this->assertSame([$matchM], $match);
		$this->assertSame([$nativeM], $native);

		// No cross-type leakage: a Permit-action continent is in Permit, NOT in Deny/Match/Native.
		$this->assertContains($permitGeo, $permit);
		$this->assertNotContains($permitGeo, $deny, 'Permit continent must not leak into Deny');
		$this->assertNotContains($permitGeo, $match);
		$this->assertNotContains($permitGeo, $native);
	}

	/**
	 * The family filter is a real branch: v4 and v6 select DISJOINT subsets of the SAME dir.
	 *
	 *   Given denydir holds both a _v4.txt and a _v6.txt member
	 *   When  Deny/v4 then Deny/v6 are computed
	 *   Then  each returns only its family's member (before: v4 has it / v6 lacks it, and vice versa).
	 */
	public function testFamilyFilterSelectsDisjointV4AndV6Subsets(): void
	{
		$v4 = $this->touchMember('denydir', 'feedC_v4.txt');
		$v6 = $this->touchMember('denydir', 'feedC_v6.txt');

		$gotV4 = pfb_aggregate_member_list('Deny', 'v4');
		$gotV6 = pfb_aggregate_member_list('Deny', 'v6');

		// v4 picks the v4 member and NOT the v6 one ...
		$this->assertSame([$v4], $gotV4);
		$this->assertNotContains($v6, $gotV4);
		// ... and v6 picks the v6 member and NOT the v4 one.
		$this->assertSame([$v6], $gotV6);
		$this->assertNotContains($v4, $gotV6);
	}

	/**
	 * The '*_<fam>.txt' glob is the include/exclude rule: it EXCLUDES '.update' markers, '.ip'
	 * feeds, the opposite family, and any non-family scratch file in the dir — only true
	 * '<header>_<fam>.txt' members are unioned.
	 *
	 *   Given denydir holds a valid _v4.txt member plus an .update marker, an .ip feed, a _v6.txt,
	 *         and an unsuffixed scratch file
	 *   When  Deny/v4 is computed
	 *   Then  only the valid member is returned.
	 */
	public function testGlobExcludesUpdateMarkersIpFeedsAndForeignScratch(): void
	{
		$member = $this->touchMember('denydir', 'feedD_v4.txt');
		$this->touchMember('denydir', 'DNSBLIP_v4.update');	// marker -> excluded
		$this->touchMember('denydir', 'feedD_v4.ip');		// embedded-IP feed -> excluded
		$this->touchMember('denydir', 'feedD_v6.txt');		// wrong family -> excluded
		$this->touchMember('denydir', 'scratch.txt');		// no _v4 suffix -> excluded

		$got = pfb_aggregate_member_list('Deny', 'v4');

		$this->assertSame([$member], $got, 'only the _v4.txt member; markers/.ip/foreign-family/scratch excluded');
	}

	/**
	 * A single member is returned as a one-element list (the smallest non-empty union).
	 */
	public function testSingleMemberReturnsOneElementList(): void
	{
		$only = $this->touchMember('nativedir', 'solo_v4.txt');
		$this->assertSame([$only], pfb_aggregate_member_list('Native', 'v4'));
	}

	/**
	 * Edge: an EMPTY dir (selected type with zero members) yields [] — the caller then builds a
	 * 0-byte aggregate + a '#'-placeholder consumer and loads NO pf table (the never-empty-file /
	 * no-empty-table contract lives in the shell action + the builder; this asserts the helper's
	 * end of it: no members to union).
	 *
	 *   Given denydir exists but holds no _v4 member
	 *   When  Deny/v4 is computed
	 *   Then  the list is empty.
	 */
	public function testEmptyDirReturnsEmptyList(): void
	{
		$this->assertSame([], pfb_aggregate_member_list('Deny', 'v4'));
	}

	/**
	 * Edge: a v4-only type returns [] for v6 (and vice versa) — pins the per-family build so a
	 * type with members in only one family does not fabricate a phantom member for the other.
	 *
	 *   Given denydir holds only a _v4 member
	 *   When  Deny/v6 is computed
	 *   Then  it is empty (before: Deny/v4 is non-empty, proving the dir is populated).
	 */
	public function testV4OnlyTypeIsEmptyForV6(): void
	{
		$this->touchMember('denydir', 'only4_v4.txt');
		$this->assertNotSame([], pfb_aggregate_member_list('Deny', 'v4'), 'dir is populated for v4');
		$this->assertSame([], pfb_aggregate_member_list('Deny', 'v6'), 'but empty for v6');
	}

	/**
	 * Edge: a missing dir yields [] (glob returns FALSE/empty), so the caller treats it as
	 * "nothing to aggregate" — no fatal, no warning.
	 */
	public function testMissingDirReturnsEmptyList(): void
	{
		$GLOBALS['pfb']['denydir'] = "{$this->root}/does_not_exist";
		$this->assertSame([], pfb_aggregate_member_list('Deny', 'v4'));
	}

	/**
	 * An unknown type and an unknown family BOTH short-circuit to [] (defensive: a bad config
	 * value can never reach a real glob). Asserts both bad-input branches.
	 */
	public function testUnknownTypeOrFamilyReturnsEmptyList(): void
	{
		// Populate a real dir so a wrong RESULT could only come from a missing guard.
		$this->touchMember('denydir', 'real_v4.txt');

		$this->assertSame([], pfb_aggregate_member_list('Bogus', 'v4'), 'unknown type');
		$this->assertSame([], pfb_aggregate_member_list('', 'v4'), 'empty type');
		$this->assertSame([], pfb_aggregate_member_list('Deny', 'v8'), 'unknown family');
		$this->assertSame([], pfb_aggregate_member_list('Deny', ''), 'empty family');
		// Sanity: the valid (Deny,v4) call against the same dir DOES return the member, proving
		// the [] above are the guard firing, not an empty dir.
		$this->assertNotSame([], pfb_aggregate_member_list('Deny', 'v4'));
	}

	/**
	 * The returned list is sorted (deterministic union input regardless of filesystem readdir
	 * order). Created out of order; asserted ascending by path.
	 */
	public function testResultIsSorted(): void
	{
		$z = $this->touchMember('denydir', 'zeta_v4.txt');
		$a = $this->touchMember('denydir', 'alpha_v4.txt');
		$m = $this->touchMember('denydir', 'mu_v4.txt');

		$got = pfb_aggregate_member_list('Deny', 'v4');
		$this->assertSame([$a, $m, $z], $got, 'members returned in sorted (ascending path) order');
	}

	/**
	 * R6 (issue #1250): a machine-generated Reputation artifact staged under matchdir's
	 * 'generated' subdirectory must NOT enter the Match aggregate merely because its name also
	 * matches '*_v4.txt' -- glob() does not descend into subdirectories, so relocating those
	 * artifacts off matchdir's top level (steps 1/1b) already excludes them; this pins that
	 * membership as a deliberate, user-visible narrowing (a reputation artifact was never a
	 * genuine Match-type list).
	 *
	 *   Given matchdir holds a genuine user Match-list member AND matchdir/generated holds a
	 *         reputation artifact that also matches '*_v4.txt'
	 *   When  the Match/v4 member list is computed
	 *   Then  the before-state is asserted first (the user member IS present), then the
	 *         artifact is confirmed ABSENT -- proving exclusion, not an accidentally-empty result.
	 */
	public function testMatchExcludesGeneratedReputationArtifact(): void
	{
		$userMember = $this->touchMember('matchdir', 'userlist_v4.txt');
		$genDir = "{$GLOBALS['pfb']['matchdir']}/generated";
		@mkdir($genDir, 0777, true);
		$this->assertNotFalse(@file_put_contents("{$genDir}/pfB_Match_Rep_Spam_v4.txt", ''));

		$got = pfb_aggregate_member_list('Match', 'v4');
		$this->assertContains($userMember, $got, 'precondition: the genuine user Match-list member is present');
		$this->assertSame([$userMember], $got, 'a matchgendir artifact must NOT enter the Match aggregate');
	}

	/**
	 * A placeholder-ONLY member file is EXCLUDED from the union. pfBlockerNG pads a zero-IP /
	 * failed feed (and an empty DNSBLIP file) with the synthetic $pfb['ip_ph'] -- '::'-prefixed
	 * for v6 -- so the per-alias file is never empty (inc:9901 / :10841); that internal hack
	 * must not pollute pfB_<Type>_Aggregated_<fam> with the fake IP. Only placeholder-ONLY
	 * files are dropped: a file mixing the placeholder with a real IP is kept, and a real-IP
	 * file is kept. Both the v4 and the '::'-prefixed v6 placeholder forms are covered. The
	 * contrast within one dir (placeholder file dropped, real/mixed files survive) is the
	 * before/after.
	 */
	public function testPlaceholderOnlyMembersAreExcluded(): void
	{
		$GLOBALS['pfb']['ip_ph'] = '127.1.7.7';

		// v4: a real feed, an empty-feed placeholder, and a placeholder+real mix.
		$real  = $this->writeMember('denydir', 'realfeed_v4.txt', "198.51.100.7\n");
		$this->writeMember('denydir', 'emptyfeed_v4.txt', "127.1.7.7\n");                  // placeholder-only -> dropped
		$mixed = $this->writeMember('denydir', 'mixed_v4.txt', "127.1.7.7\n203.0.113.9\n"); // a real IP present -> kept

		// glob sorts: emptyfeed, mixed, realfeed; after dropping the placeholder-only file: [mixed, real].
		$this->assertSame([$mixed, $real], pfb_aggregate_member_list('Deny', 'v4'),
			'v4: placeholder-only dropped; real + mixed kept');

		// v6: the placeholder is '::'-prefixed.
		$realv6 = $this->writeMember('denydir', 'realfeed_v6.txt', "2001:db8::1\n");
		$this->writeMember('denydir', 'emptyfeed_v6.txt', "::127.1.7.7\n");                 // placeholder-only -> dropped

		$this->assertSame([$realv6], pfb_aggregate_member_list('Deny', 'v6'),
			'v6: ::-prefixed placeholder dropped; real kept');
	}
}
