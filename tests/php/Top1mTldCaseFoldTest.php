<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #920 -- pfblockerng_top1m()'s TLD inclusion match is case-sensitive
 * while the include keys are always lowercase (the GUI's fixed
 * $options_alexa_inclusion list, pfblockerng_dnsbl.php, keys like 'ae'/'com').
 * A feed row with an uppercase/mixed-case domain (EXAMPLE.COM,
 * example.XN--P1AI) passed every guard, counted toward $linecnt, but silently
 * failed isset($pfb_include[$tld]) -- never whitelisted, no warning, no log.
 *
 * Fix: fold $domain to lowercase ONCE at extraction (before the TLD split,
 * the 'www.' strip, and the write), so the TLD compare, the www-strip, and
 * the written whitelist entries are all case-insensitive/canonical in one
 * spot -- downstream (pfb_unbound.py) already lowercases on ingest.
 *
 * Same issue also anchors the 'csv' parse mode's hostname guard regex with
 * the `D` modifier: without it, `$` matches before a trailing "\n" PHP's
 * multiline mode. str_getcsv() strips a bare trailing newline in every
 * mode, but a QUOTED UNTERMINATED field (e.g. a truncated/corrupted feed
 * line starting '"') retains it verbatim -- so pre-fix, that garbage row
 * passed the hostname guard, incremented $linecnt, and could flip a feed of
 * only such rows from "dead" (preserve prior whitelist) to "valid" (swap in
 * an empty build), silently wiping a good whitelist (same failure class as
 * the #886/#892 dead-feed guards this function already carries).
 *
 * Feature: TOP1M TLD inclusion match is case-insensitive; the csv-mode
 * hostname guard is anchored against a trailing-newline bypass
 *   Background:
 *     Given $pfb['dnsbl_top1m_inc'] names lowercase TLD(s) (the GUI's only
 *           possible shape)
 *
 * Branch coverage (every parse mode x case shape):
 *   * rank_domain (Tranco/Cisco, default resolved provider): uppercase
 *     domain matches a lowercase inclusion; mixed-case punycode TLD matches;
 *     'WWW.' is stripped AFTER folding; a folded TLD that still doesn't match
 *     still counts toward $linecnt (not a dead feed) but writes no entry;
 *     an already-lowercase row is unaffected (no regression).
 *   * csv (OpenPageRank/Majestic/Cloudflare -- each via its REAL registered
 *     descriptor from pfb_top1m_providers()): an uppercase/mixed-case domain
 *     folds and matches at every registered domain_col (0 Cloudflare,
 *     1 OpenPageRank, 2 Majestic); a quoted-unterminated field (domain_col 0
 *     AND domain_col 1) is REJECTED by the anchored regex, taking the
 *     dead-feed preserve-prior-whitelist path instead of the pre-fix wipe.
 */
#[CoversFunction('pfblockerng_top1m')]
final class Top1mTldCaseFoldTest extends TestCase
{
	private string $dbdir;

	/** Saved $GLOBALS['pfb'] keys this test touches, restored in tearDown for isolation. */
	private array $savedPfb = [];

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_top1m_casefold_' . getmypid() . '_' . uniqid();
		$this->assertTrue(@mkdir($this->dbdir, 0777, true), "could not create sandbox {$this->dbdir}");

		foreach (['dbdir', 'log', 'errlog', 'dnsbl_top1m_inc', 'dnsbl_top1m_cnt', 'runlog',
			  'runlog_active', 'hook_lifecycle', 'pnow'] as $key) {
			$this->savedPfb[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$key] : false;
		}

		$GLOBALS['pfb']['dbdir']		= $this->dbdir;
		$GLOBALS['pfb']['log']			= "{$this->dbdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']		= "{$this->dbdir}/pfblockerng_error.log";
		$GLOBALS['pfb']['dnsbl_top1m_inc']	= 'com';
		$GLOBALS['pfb']['dnsbl_top1m_cnt']	= '1000';
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active'],
		      $GLOBALS['pfb']['hook_lifecycle'], $GLOBALS['pfb']['pnow']);

		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['log'], ''), 'could not create main log');
		$this->assertNotFalse(file_put_contents($GLOBALS['pfb']['errlog'], ''), 'could not create error log');
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $key => $val) {
			if ($val === false) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $val;
			}
		}
		foreach ((array) (@glob("{$this->dbdir}/*") ?: []) as $f) {
			@unlink($f);
		}
		@rmdir($this->dbdir);
	}

	private function whitelistPath(): string
	{
		return "{$this->dbdir}/pfbalexawhitelist.txt";
	}

	private function csvPath(): string
	{
		return "{$this->dbdir}/top-1m.csv";
	}

	private function readErrLog(): string
	{
		$raw = file_get_contents($GLOBALS['pfb']['errlog']);
		$this->assertNotFalse($raw, 'could not read error log');
		return (string) $raw;
	}

	private function readMainLog(): string
	{
		$raw = file_get_contents($GLOBALS['pfb']['log']);
		$this->assertNotFalse($raw, 'could not read main log');
		return (string) $raw;
	}

	/**
	 * Row 1 -- default resolved provider (NO override -> rank_domain,
	 * domain_col 1, the Tranco/Cisco shape): an all-uppercase domain must
	 * still match the GUI's lowercase 'com' inclusion, and the entries
	 * written are canonical lowercase.
	 */
	public function testRankDomainUppercaseDomainMatchesLowercaseInclusionAndWritesLowercaseEntries(): void
	{
		$this->assertNotFalse(file_put_contents($this->csvPath(), "5,EXAMPLE.COM\n"), 'setup: uppercase-domain rank_domain row');

		pfblockerng_top1m();

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got,
			'an uppercase domain must fold to lowercase before the TLD compare and the write');
	}

	/**
	 * Row 2 -- rank_domain: a mixed-case punycode TLD ('example.XN--P1AI')
	 * must fold and match a lowercase 'xn--p1ai' inclusion, exactly as
	 * issue #904's all-lowercase punycode case already does.
	 */
	public function testRankDomainMixedCasePunycodeTldMatchesLowercaseInclusion(): void
	{
		$GLOBALS['pfb']['dnsbl_top1m_inc'] = 'xn--p1ai';
		$this->assertNotFalse(file_put_contents($this->csvPath(), "6,example.XN--P1AI\n"), 'setup: mixed-case punycode-TLD row');

		pfblockerng_top1m();

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame(".example.xn--p1ai,,\n,example.xn--p1ai,,\n,www.example.xn--p1ai,,\n", $got,
			'a mixed-case punycode TLD must fold to lowercase before the TLD compare');
	}

	/**
	 * Row 3 -- rank_domain: 'WWW.' must be stripped AFTER the fold, so an
	 * uppercase 'WWW.EXAMPLE.COM' still whitelists as example.com (never a
	 * literal 'www.example.com'-prefixed leftover from an un-folded strip).
	 */
	public function testRankDomainUppercaseWwwPrefixStrippedAfterFold(): void
	{
		$this->assertNotFalse(file_put_contents($this->csvPath(), "7,WWW.EXAMPLE.COM\n"), 'setup: uppercase www-prefixed row');

		pfblockerng_top1m();

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got,
			"the 'www.' strip must run against the FOLDED domain, not the raw uppercase value");
	}

	/**
	 * Row 4 -- negative guard: the fold must not OVER-match. An uppercase
	 * domain whose TLD genuinely is not in the inclusion set is still
	 * counted toward $linecnt (a valid parsed row -- not a dead feed) but
	 * writes no whitelist entry.
	 */
	public function testRankDomainUppercaseDomainNotMatchingInclusionCountsButWritesNoEntry(): void
	{
		$this->assertNotFalse(file_put_contents($this->csvPath(), "8,EXAMPLE.ORG\n"), 'setup: uppercase row, TLD not in the inclusion set');

		pfblockerng_top1m();

		$this->assertSame('', file_get_contents($this->whitelistPath()),
			'a valid row whose (folded) TLD does not match must write no entry, but still replace the build (not dead-feed)');
		$this->assertStringContainsString('Parsed 1 lines | Found 0 of 1000', $this->readMainLog(),
			'the row must still count toward $linecnt -- the feed is valid, just non-matching');
		$this->assertStringNotContainsString('keeping the previous TOP1M whitelist', $this->readMainLog(),
			'a non-matching row must never be classified as a dead feed');
	}

	/**
	 * Row 5 -- regression guard: an already-lowercase domain is unaffected
	 * by the fold (byte-identical to pre-fix behaviour).
	 */
	public function testRankDomainLowercaseControlStillMatchesUnaffectedByFold(): void
	{
		$this->assertNotFalse(file_put_contents($this->csvPath(), "9,example.com\n"), 'setup: already-lowercase row');

		pfblockerng_top1m();

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got,
			'an already-lowercase domain must match exactly as before -- no regression from the fold');
	}

	/**
	 * Row 6 -- 'csv' parse, domain_col 0 via the REAL registered Cloudflare
	 * descriptor (header=TRUE, single 'domain' column): an uppercase domain
	 * still passes the hostname guard (its character classes already cover
	 * both cases) and must fold before the TLD compare, same as the
	 * rank_domain rows above (PR #953 review: the real descriptor, not a
	 * synthetic no-header stand-in no registered provider matches).
	 */
	public function testCsvDomainCol0UppercaseDomainMatchesAndFoldsToLowercaseEntries(): void
	{
		$csv = "domain\n"
			. "EXAMPLE.COM\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: Cloudflare-shaped header + uppercase single-column domain');

		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Cloudflare->value]);

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got,
			'domain_col 0 (real Cloudflare descriptor) must fold an uppercase single-column domain the same as every other column shape');
	}

	/**
	 * Row 7 -- the `D` modifier anchor: a quoted-UNTERMINATED field (e.g.
	 * "\"example.com\n" with no closing quote) retains its trailing "\n"
	 * through str_getcsv() -- verified this session: str_getcsv() strips a
	 * bare trailing newline in every parse mode, but a quoted/unterminated
	 * field does not. Pre-fix (no `D`), `$` matches before that "\n" in PHP's
	 * default multiline `$`, so the regex WRONGLY accepts it, $linecnt goes
	 * to 1, and the "valid feed" branch REPLACES a good prior whitelist with
	 * an empty build. Post-fix (`D` anchors `$` to the true string end), the
	 * row is rejected, $linecnt stays 0, and the dead-feed path PRESERVES
	 * the prior whitelist + warns -- exactly the #886/#892 guard this
	 * function already relies on for other garbage-row shapes.
	 */
	public function testCsvDomainCol0QuotedUnterminatedNewlineRejectedPreservesPriorWhitelist(): void
	{
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		// Written directly (not via an escaped literal) so the unterminated quote + trailing
		// newline survive exactly as str_getcsv() would receive them from a real corrupted line.
		// Real Cloudflare descriptor (header=TRUE): the header row is skipped, the
		// quoted-unterminated row is the only data line.
		$this->assertNotFalse(file_put_contents($this->csvPath(), "domain\n\"example.com\n"), 'setup: header + quoted-unterminated single-column row');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Cloudflare->value]);

		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a quoted-unterminated field (trailing newline retained) must NOT be accepted as a valid hostname');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/**
	 * Row 8 -- same `D`-modifier anchor as row 7, but via the REAL registered
	 * OpenPageRank descriptor (header=TRUE, domain_col 1) -- a multi-column
	 * row whose Domain field is quoted-unterminated (e.g. a feed truncated
	 * mid-line) must be rejected the same way, after the header is skipped.
	 */
	public function testCsvDomainCol1HeaderModeQuotedUnterminatedNewlineRejectedPreservesPriorWhitelist(): void
	{
		$priorContent = ".real.com,,\n,real.com,,\n,www.real.com,,\n";
		$this->assertNotFalse(file_put_contents($this->whitelistPath(), $priorContent), 'setup: seed prior whitelist');
		$csv = "Rank,Domain,Extension,Open Page Rank,Referring Domains\n"
			. "1,\"example.com\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: header + quoted-unterminated Domain field');
		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()), 'before-state sanity');

		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		$this->assertSame($priorContent, file_get_contents($this->whitelistPath()),
			'a quoted-unterminated Domain field must NOT be accepted, even at a non-zero column with a header row');
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readErrLog());
		$this->assertStringContainsString('keeping the previous TOP1M whitelist', $this->readMainLog());
	}

	/**
	 * Row 8b -- 'csv' parse, domain_col 1 via the REAL registered OpenPageRank
	 * descriptor (header=TRUE): an uppercase Domain field must fold and match,
	 * completing the case-fold proof for every csv domain_col the provider
	 * registry names (0/1/2) against its real descriptor (PR #953 review: row 8
	 * only proved the /D anchor at this column, never the fold).
	 */
	public function testCsvDomainCol1OpenPageRankShapeUppercaseDomainMatchesAndFolds(): void
	{
		$csv = "Rank,Domain,Extension,Open Page Rank,Referring Domains\n"
			. "1,EXAMPLE.COM,com,7.5,1000\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: OpenPageRank-shaped header + uppercase Domain row');

		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::OpenPageRank->value]);

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got,
			'an uppercase Domain field at domain_col 1 (real OpenPageRank descriptor) must still fold and match');
	}

	/**
	 * Row 9 -- 'csv' parse, domain_col 2 (Majestic's real shape, header=TRUE):
	 * a mixed-case Domain field ('Example.CoM') must fold and match, proving
	 * the fix is not specific to domain_col 0/1.
	 */
	public function testCsvDomainCol2MajesticShapeMixedCaseDomainMatchesAndFolds(): void
	{
		$csv = "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n"
			. "1,1,Example.CoM,extra\n";
		$this->assertNotFalse(file_put_contents($this->csvPath(), $csv), 'setup: Majestic-shaped mixed-case Domain row');

		pfblockerng_top1m(pfb_top1m_providers()[PfbTop1mSource::Majestic->value]);

		$got = file_get_contents($this->whitelistPath());
		$this->assertNotFalse($got);
		$this->assertSame(".example.com,,\n,example.com,,\n,www.example.com,,\n", $got,
			'a mixed-case Domain field at a non-default column (Majestic, index 2) must still fold and match');
	}
}
