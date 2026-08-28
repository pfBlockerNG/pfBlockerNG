<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_unbound_python_sources() — ADR-06/07 shell->Python manifest writer. Builds
 * the per-feed manifest + per-feed IP-stripped raw files consumed by
 * pfb_unbound.py. This pins the parts the issue calls out: provenance tagging,
 * the chroot-relative (basename) raw path, and NDJSON-kind-driven (#1083 P4
 * retired the per-format tagging key end-to-end) plain-vs-ABP raw extraction.
 * It runs against a temp $pfb sandbox (no live box).
 *
 * Also covers the #51 temporary-unlock plumbing: the full build clears
 * config.user_unlock (Force/Cron re-lock), and pfb_unbound_python_sources_unlock()
 * recomputes it in place from the live pfb_unlock store (pfb_dnsbl_unlock_lines()).
 *
 * PFBL-01 boundary coverage (both sides of each new validation branch):
 *   - feed headers re-validated at the manifest choke point: a valid header builds
 *     its raw + manifest row exactly as before; a non-\w header is skipped + logged
 *     before any file is touched.
 *   - suppression (whitelist) lines and unlock-store domains must be
 *     PFB_FILTER_DOMAIN-valid to enter the manifest: valid lines (incl. the
 *     leading-dot wildcard form) pass unchanged with nothing logged; a failing
 *     line is skipped + logged, never silently dropped.
 */
#[CoversFunction('pfb_unbound_python_sources')]
#[CoversFunction('pfb_unbound_python_sources_patch')]
#[CoversFunction('pfb_unbound_python_sources_unlock')]
#[CoversFunction('pfb_dnsbl_unlock_lines')]
#[CoversFunction('pfb_dnsbl_whitelist_lines')]
final class UnboundPythonSourcesTest extends TestCase
{
	private const OLD_GENERATION = 'pfb_py_raw.0123456789abcdef0123456789abcdef';

	private string $tmp;
	private bool $hadPfb = FALSE;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		// Snapshot the global so this class's heavy $pfb mutations (temp paths,
		// replaced dnsblconfig subtree) don't leak into later test classes.
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_sources_' . uniqid('', TRUE);
		mkdir("{$this->tmp}/dnsbl", 0777, TRUE);
		mkdir("{$this->tmp}/db", 0777, TRUE);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'unbound_py_top1m'   => "{$this->tmp}/pfb_py_top1m.txt",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => PfbToggle::Off,
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			// issue #1255: DNSBL Wildcard Blocking (TLD) toggle; OFF by default here.
			'dnsbl_tld_wildcard' => '',
			'dnsblconfig'        => [
				'tld_wildcard_blacklist' => '',
				'tld_wildcard_exclusion' => '',
				'whitelist'              => '',
			],
		]);

		// Plain feed: NDJSON domain rows (#1083).
		file_put_contents("{$this->tmp}/dnsbl/feed1.txt",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'example.com') .
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'foo.com') .
			'{"kind":"domain","domain":"","log":"1","feed":"f","group":"g"}' . "\n");  // empty domain => skipped

		// ABP feed: NDJSON abp rows, raw payload passed through verbatim.
		file_put_contents("{$this->tmp}/dnsbl/abpfeed.txt",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, '||ads.example^') .
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, '@@||good.example^'));
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}

		rmdir_recursive($this->tmp);
	}

	private function feeds(): array
	{
		return [
			['header' => 'feed1',   'group' => 'pfb_grp', 'log' => '1', 'provenance' => 'feed'],
			['header' => 'abpfeed', 'group' => 'pfb_abp', 'log' => '0', 'provenance' => 'user'],
			['header' => 'missing', 'group' => 'pfb_x',   'log' => '1'],   // no .txt => skipped
		];
	}

	private function rawPath(array $manifest, string $feed): string
	{
		foreach ($manifest['feeds'] as $row) {
			if ($row['feed'] === $feed) {
				return dirname($GLOBALS['pfb']['unbound_py_sources']) . "/{$row['raw']}";
			}
		}
		$this->fail("manifest has no feed row for {$feed}");
	}

	public function testManifestStructureAndTagging(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());

		$this->assertSame(1, $m['version']);
		$this->assertCount(2, $m['feeds'], 'feed without a .txt must be skipped');

		// Closed key set (#1083 P4 retired the per-format tagging key end-to-end --
		// no other key may reappear under any name without this catching it).
		$closedKeySet = ['raw', 'feed', 'group', 'provenance', 'log_flag'];

		$plain = $m['feeds'][0];
		$this->assertSame('feed1', $plain['feed']);
		$this->assertSame('pfb_grp', $plain['group']);
		$this->assertSame($closedKeySet, array_keys(array_diff_key($plain, ['mode' => NULL])));
		$this->assertSame('feed', $plain['provenance']);
		$this->assertSame('1', $plain['log_flag']);
		$this->assertMatchesRegularExpression('/^pfb_py_raw\.[0-9a-f]{32}\/feed1\.raw$/D', $plain['raw']);

		// The 'abpfeed' NDJSON rows are 'abp'-kind; the writer routes their raw payload
		// verbatim purely from the NDJSON kind tag, independent of any feed-level format.
		$abp = $m['feeds'][1];
		$this->assertSame($closedKeySet, array_keys(array_diff_key($abp, ['mode' => NULL])));
		$this->assertSame('user', $abp['provenance']);
		$this->assertSame('0', $abp['log_flag']);
		$this->assertSame(dirname($plain['raw']), dirname($abp['raw']), 'all feed raws must share one generation');
		$this->assertSame('abpfeed.raw', basename($abp['raw']));
	}

	public function testProvenanceDefaultsToFeedWhenUnset(): void
	{
		$m = pfb_unbound_python_sources([
			['header' => 'feed1', 'group' => 'g', 'log' => '1'],
		]);
		$this->assertSame('feed', $m['feeds'][0]['provenance']);
	}

	// ADR-31: a Permit-action feed row carries 'mode' => 'permit' THROUGH the writer's
	// key remap into the manifest JSON, so the Python build (dnsbl_build_from_manifest
	// -> build()) routes its hosts into whiteDB as band-2 allows. A regression here
	// silently demotes every DNSWL allow-feed back to a plain block feed — the key was
	// dropped in this remap and only the live-VM smoke caught it.
	public function testPermitFeedCarriesModeIntoManifest(): void
	{
		file_put_contents("{$this->tmp}/dnsbl/permitfeed.txt",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'allow.example.com'));
		$m = pfb_unbound_python_sources([
			['header' => 'permitfeed', 'group' => 'g', 'log' => '1', 'provenance' => 'feed', 'mode' => 'permit'],
		]);
		$this->assertSame('permit', $m['feeds'][0]['mode'] ?? null,
			'a Permit-action row must carry mode=permit into the manifest JSON');
	}

	// The absent side of the deny branch: a feed row with no 'action'/'mode' emits NO
	// 'mode' key (byte-identical with pre-ADR-31 manifests; Python treats absent as deny).
	public function testAbsentModeOmitsKeyInManifest(): void
	{
		$m = pfb_unbound_python_sources([
			['header' => 'feed1', 'group' => 'g', 'log' => '1', 'provenance' => 'feed'],
		]);
		$this->assertArrayNotHasKey('mode', $m['feeds'][0], 'absent action => no mode key (byte-identical with pre-ADR-31)');
	}

	// The explicit-deny side of the same branch: a row carrying mode='deny' also emits NO
	// 'mode' key — the deny path is byte-identical whether the action is absent or 'Deny'.
	public function testExplicitDenyOmitsModeKeyInManifest(): void
	{
		$m = pfb_unbound_python_sources([
			['header' => 'feed1', 'group' => 'g', 'log' => '1', 'provenance' => 'feed', 'mode' => 'deny'],
		]);
		$this->assertArrayNotHasKey('mode', $m['feeds'][0], 'explicit deny => no mode key (byte-identical with pre-ADR-31)');
	}

	public function testPlainRawIsBareDomainColumn(): void
	{
		$manifest = pfb_unbound_python_sources($this->feeds());
		$raw = file_get_contents($this->rawPath($manifest, 'feed1'));
		$this->assertSame("example.com\nfoo.com\n", $raw);
	}

	public function testAbpRawIsVerbatim(): void
	{
		$manifest = pfb_unbound_python_sources($this->feeds());
		$raw = file_get_contents($this->rawPath($manifest, 'abpfeed'));
		$this->assertSame("||ads.example^\n@@||good.example^\n", $raw);
	}

	/**
	 * Scenario: a non-JSON garbage line in a staged '.txt' (#1083 -- the successor of
	 * the retired #1067 comma-first-residue class: any undecodable line, from any
	 * cause, is now silently skipped by pfb_dnsbl_ndjson_parse_row()).
	 *
	 * Given:  a '.txt' holding one legit NDJSON domain row and one line that is not
	 *         valid NDJSON at all
	 * When:   pfb_unbound_python_sources() rebuilds the per-feed raw
	 * Then:   the garbage line is skipped entirely — never extracted into a
	 *         blockable 'domain' — while the legit row still yields its domain
	 */
	public function testMalformedNonJsonLineIsSkippedNotExtracted(): void
	{
		file_put_contents("{$this->tmp}/dnsbl/stalefeed.txt",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'legit.example') .
			"not valid ndjson,stale-block.example,stale2.example##.ad\n");
		$manifest = pfb_unbound_python_sources([
			['header' => 'stalefeed', 'group' => 'g', 'log' => '1', 'provenance' => 'feed'],
		]);
		$raw = file_get_contents($this->rawPath($manifest, 'stalefeed'));
		$this->assertSame(
			"legit.example\n",
			$raw,
			'a non-JSON garbage line must not leak a blockable domain; got: ' . var_export($raw, TRUE)
		);
	}

	public function testMixedCompactAndLegacyRowsPreserveBareAndVerbatimPayloads(): void
	{
		file_put_contents("{$this->tmp}/dnsbl/mixedfeed.txt",
			"[\"d\",\"compact.example\"]\n" .
			"{\"kind\":\"domain\",\"domain\":\"legacy.example\",\"log\":\"1\",\"feed\":\"f\",\"group\":\"g\"}\n" .
			"[\"a\",\"||compact.example^\"]\n" .
			"{\"kind\":\"abp\",\"raw\":\"@@||legacy.example^\"}\n" .
			"[\"d\",\"\", \"extra\"]\n" .
			"[\"x\",\"skipped.example\"]\n");

		$manifest = pfb_unbound_python_sources([
			['header' => 'mixedfeed', 'group' => 'g', 'log' => '1', 'provenance' => 'feed'],
		]);
		$this->assertSame(
			"compact.example\nlegacy.example\n||compact.example^\n@@||legacy.example^\n",
			file_get_contents($this->rawPath($manifest, 'mixedfeed'))
		);
	}

	public function testConfigBlockEmptyWhenUnconfigured(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());
		// issue #1255: the public-suffix oracle is no longer carried in the manifest
		// (HSTS parity -- a shipped static file + ini flag instead); the key is absent.
		$this->assertArrayNotHasKey('tld_master', $m['config']);
		// issue #1328: pin the POST-RENAME (ADR-66) blob name too -- a writer
		// regression emitting the oracle under the new name would slip past the
		// old-name-only pin above.
		$this->assertArrayNotHasKey('tld_wildcard_master', $m['config']);
		$this->assertSame([], $m['config']['tld_wildcard_blacklist']);
		$this->assertSame([], $m['config']['user_whitelist']);
		$this->assertSame([], $m['config']['user_unlock']);
		$this->assertFalse($m['config']['top1m_enabled']);
	}

	// issue #1255: the TLD-Wildcard oracle leaves the manifest entirely (HSTS parity) --
	// present regardless of the dnsbl_tld_wildcard toggle. tld_wildcard_blacklist/
	// tld_wildcard_exclusion STAY (user config data) but are gated: OFF empties them even
	// when the operator configured them, so the toggle gates the WHOLE wildcard-blocking
	// contribution, not just the oracle.
	public function testTldMasterKeyAbsentAndBlacklistExclusionEmptyWhenDnsblTldOff(): void
	{
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_blacklist'] = base64_encode('evil-tld');
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_exclusion'] = base64_encode('good.example');

		$m = pfb_unbound_python_sources($this->feeds());

		$this->assertArrayNotHasKey('tld_master', $m['config'], 'tld_master must never appear in the manifest');
		$this->assertArrayNotHasKey('tld_wildcard_master', $m['config'], 'tld_wildcard_master (post-rename blob name) must never appear in the manifest');
		$this->assertSame([], $m['config']['tld_wildcard_blacklist'], 'OFF must empty tld_wildcard_blacklist even though it was configured');
		$this->assertSame([], $m['config']['tld_wildcard_exclusion'], 'OFF must empty tld_wildcard_exclusion even though it was configured');
	}

	public function testTldBlacklistAndExclusionPopulatedWhenDnsblTldOn(): void
	{
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = 'on';
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_blacklist'] = base64_encode('evil-tld');
		$GLOBALS['pfb']['dnsblconfig']['tld_wildcard_exclusion'] = base64_encode('good.example');

		$m = pfb_unbound_python_sources($this->feeds());

		$this->assertArrayNotHasKey('tld_master', $m['config'], 'tld_master must never appear in the manifest, even ON');
		$this->assertArrayNotHasKey('tld_wildcard_master', $m['config'], 'tld_wildcard_master (post-rename blob name) must never appear in the manifest, even ON');
		$this->assertSame(['evil-tld'], $m['config']['tld_wildcard_blacklist'], 'ON must populate tld_wildcard_blacklist from config');
		$this->assertSame(['good.example'], $m['config']['tld_wildcard_exclusion'], 'ON must populate tld_wildcard_exclusion from config');
	}

	public function testManifestIsWrittenAsJson(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());
		$json = file_get_contents("{$this->tmp}/pfb_py_sources.json");
		$this->assertSame($m, json_decode($json, TRUE));
	}

	// #51: a FULL build CLEARS the temporary unlock set even when the live store has
	// entries -- a Force/Cron deletes the store right after, so baking it in would let
	// unlocks survive the re-lock. The full build must emit user_unlock => [].
	public function testFullBuildClearsUserUnlockEvenWithStore(): void
	{
		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\nfoo.org,python\n");
		$m = pfb_unbound_python_sources($this->feeds());
		$this->assertSame([], $m['config']['user_unlock']);
	}

	// #51: pfb_dnsbl_unlock_lines() reads the pfb_unlock store and returns its domains.
	public function testDnsblUnlockLinesReadsStoreDomains(): void
	{
		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\nfoo.org,python\n");
		$this->assertSame(['evil.com', 'foo.org'], pfb_dnsbl_unlock_lines());
	}

	public function testDnsblUnlockLinesEmptyWhenStoreAbsent(): void
	{
		$this->assertSame([], pfb_dnsbl_unlock_lines());
	}

	// #51: the incremental path patches ONLY config.user_unlock from the live store,
	// leaving the rest of the manifest intact.
	public function testSourcesUnlockRecomputesFromStore(): void
	{
		$m = pfb_unbound_python_sources($this->feeds());            // full build: user_unlock => []
		$this->assertSame([], $m['config']['user_unlock']);

		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\nfoo.org,python\n");
		$this->assertTrue(pfb_unbound_python_sources_unlock());

		$patched = json_decode(file_get_contents("{$this->tmp}/pfb_py_sources.json"), TRUE);
		$this->assertSame(['evil.com', 'foo.org'], $patched['config']['user_unlock']);
		// The feeds and the rest of config are untouched by the in-place patch.
		$this->assertSame($m['feeds'], $patched['feeds']);
		$this->assertSame($m['config']['user_whitelist'], $patched['config']['user_whitelist']);
	}

	// Store deleted => manifest user_unlock cleared. This is BOTH the handler
	// 'lock'/'reunlock' that empties the store AND the Cron/Force re-lock step the fix
	// added at inc:3451 (pfb_update_unbound unlinks the store, then calls
	// pfb_unbound_python_sources_unlock so the reload re-reads a cleared whiteDB). With
	// the file gone pfb_dnsbl_unlock_lines() yields [] and the recompute empties the key.
	public function testSourcesUnlockEmptiesWhenStoreCleared(): void
	{
		pfb_unbound_python_sources($this->feeds());
		file_put_contents("{$this->tmp}/dnsbl_unlock", "evil.com,python\n");
		pfb_unbound_python_sources_unlock();

		unlink("{$this->tmp}/dnsbl_unlock");           // store emptied (lock / Cron / Force)
		$this->assertTrue(pfb_unbound_python_sources_unlock());
		$patched = json_decode(file_get_contents("{$this->tmp}/pfb_py_sources.json"), TRUE);
		$this->assertSame([], $patched['config']['user_unlock']);
	}

	public function testSourcesUnlockReturnsFalseWithoutManifest(): void
	{
		// No full build ran -> no manifest to patch.
		$this->assertFileDoesNotExist("{$this->tmp}/pfb_py_sources.json");
		$this->assertFalse(pfb_unbound_python_sources_unlock());
	}

	// --- PFBL-01: header re-validation at the manifest choke point ----------------

	private function logContents(): string
	{
		$path = $GLOBALS['pfb']['log'];
		return file_exists($path) ? (string) file_get_contents($path) : '';
	}

	private function errorLogContents(): string
	{
		$path = $GLOBALS['pfb']['errlog'];
		return file_exists($path) ? (string) file_get_contents($path) : '';
	}

	private function seedManifest(string $marker = 'old-manifest-secret'): string
	{
		$manifest = [
			'version' => 1,
			'config' => [
				'user_whitelist' => [$marker],
				'user_unlock' => [],
			],
			'feeds' => [[
				'raw' => self::OLD_GENERATION . '/old.raw',
				'feed' => 'old-feed-secret',
			]],
		];
		$json = (string) json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], $json);
		return $json;
	}

	public static function validFullManifestValues(): array
	{
		return [
			'ASCII' => [PfbToggle::On, "ascii.example\n"],
			'Unicode remains escaped' => [PfbToggle::On, "b\u{00FC}cher.example\n"],
			'quote and slash keep legacy escaping' => [PfbToggle::On, "quo\"te/path.example\n"],
			'empty list keeps legacy shape' => [PfbToggle::Off, ''],
		];
	}

	#[DataProvider('validFullManifestValues')]
	public function testFullManifestValidInputsKeepLegacyJsonBytes(PfbToggle $enabled, string $top1m): void
	{
		$GLOBALS['pfb']['dnsbl_top1m'] = $enabled;
		if ($enabled === PfbToggle::On) {
			file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", $top1m);
		}

		$manifest = pfb_unbound_python_sources([], $enabled === PfbToggle::On ? $this->top1mPublicationOps() : []);
		$published = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$legacy = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

		$this->assertNotFalse($legacy);
		$this->assertSame($legacy, $published, 'valid manifest JSON bytes must remain identical to the legacy encoder');
	}

	public static function malformedUtf8Values(): array
	{
		return [
			'isolated invalid byte' => ["\xFF"],
			'truncated three-byte sequence' => ["\xE2\x82"],
		];
	}

	#[DataProvider('malformedUtf8Values')]
	public function testFullManifestSubstitutesMalformedUtf8AndPublishes(string $invalid): void
	{
		$old_generation = dirname($GLOBALS['pfb']['unbound_py_rawdir']) . '/' . self::OLD_GENERATION;
		mkdir($old_generation, 0777, TRUE);
		file_put_contents("{$old_generation}/old.raw", 'old-raw-secret');
		$old = $this->seedManifest();
		$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
		file_put_contents("{$this->tmp}/db/pfbalexawhitelist.txt", $invalid . "\n");

		pfb_unbound_python_sources([], $this->top1mPublicationOps());

		$published = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$decoded = json_decode($published, TRUE);
		$this->assertSame(JSON_ERROR_NONE, json_last_error(), 'the replacement manifest must be valid JSON');
		$this->assertNotSame($old, $published, 'the stale manifest must be replaced');
		$this->assertTrue($decoded['config']['top1m_enabled']);
		$this->assertArrayNotHasKey('top1m_list', $decoded['config']);
		$this->assertSame($invalid . "\n", file_get_contents($GLOBALS['pfb']['unbound_py_top1m']));
		$this->assertSame(
			'old-raw-secret',
			file_get_contents("{$old_generation}/old.raw"),
			'the old generation remains readable until confirmed-apply garbage collection'
		);
	}

	public function testFullManifestResidualEncodingFailureLogsGenericErrorAndKeepsOldManifest(): void
	{
		$old_generation = dirname($GLOBALS['pfb']['unbound_py_rawdir']) . '/' . self::OLD_GENERATION;
		mkdir($old_generation, 0777, TRUE);
		file_put_contents("{$old_generation}/old.raw", 'old-raw-secret');
		$old = $this->seedManifest();

		$manifest = pfb_unbound_python_sources([
			['header' => 'feed1', 'group' => NAN, 'log' => '1'],
		]);
		$error = json_last_error_msg();

		$this->assertFalse($manifest, 'the full writer must reject an unencodable manifest');
		$this->assertSame($old, file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
		$this->assertSame('old-raw-secret', file_get_contents("{$old_generation}/old.raw"));
		$published = json_decode((string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']), TRUE);
		$this->assertIsArray($published);
		foreach ($published['feeds'] as $feed) {
			$raw_path = dirname($GLOBALS['pfb']['unbound_py_sources']) . "/{$feed['raw']}";
			$this->assertFileExists($raw_path, "published raw reference must still resolve: {$feed['raw']}");
		}
		$this->assertSame('Inf and NaN cannot be JSON encoded', $error);
		foreach ([$this->logContents(), $this->errorLogContents()] as $log) {
			$this->assertStringContainsString('DNSBL manifest JSON encoding failed: ' . $error, $log);
			$this->assertStringNotContainsString('old-manifest-secret', $log);
			$this->assertStringNotContainsString('old-raw-secret', $log);
			$this->assertStringNotContainsString('feed1', $log);
			$this->assertStringNotContainsString('example.com', $log);
			$this->assertStringNotContainsString('old.raw', $log);
			$this->assertStringNotContainsString('user_whitelist', $log);
			$this->assertStringNotContainsString('group', $log);
		}
	}

	private function top1mPublicationOps(): array
	{
		return [
			'top1m_atomic' => [
				'chown' => static fn(string $file, string $owner): bool => TRUE,
				'chgrp' => static fn(string $file, string $group): bool => TRUE,
				'chmod' => static fn(string $file, int $mode): bool => TRUE,
			],
		];
	}

	public static function validPatchValues(): array
	{
		return [
			'whitelist ASCII' => ['user_whitelist', ['ascii.example']],
			'unlock Unicode remains escaped' => ['user_unlock', ["b\u{00FC}cher.example"]],
			'whitelist quote and slash keep legacy escaping' => ['user_whitelist', ['quo"te/path.example']],
			'unlock empty list keeps legacy shape' => ['user_unlock', []],
		];
	}

	#[DataProvider('validPatchValues')]
	public function testManifestPatchValidInputsKeepLegacyJsonBytes(string $key, array $values): void
	{
		$old = $this->seedManifest();
		$expected = json_decode($old, TRUE);
		$expected['config'][$key] = $values;
		$legacy = json_encode($expected, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

		$this->assertTrue(pfb_unbound_python_sources_patch($key, $values));
		$this->assertNotFalse($legacy);
		$this->assertSame(
			$legacy,
			file_get_contents($GLOBALS['pfb']['unbound_py_sources']),
			'valid patch JSON bytes must remain identical to the legacy encoder'
		);
	}

	public static function malformedPatchValues(): array
	{
		return [
			'whitelist isolated invalid byte' => ['user_whitelist', "\xFF"],
			'whitelist truncated sequence' => ['user_whitelist', "\xE2\x82"],
			'unlock isolated invalid byte' => ['user_unlock', "\xFF"],
			'unlock truncated sequence' => ['user_unlock', "\xE2\x82"],
		];
	}

	#[DataProvider('malformedPatchValues')]
	public function testManifestPatchSubstitutesMalformedUtf8AndPublishes(string $key, string $invalid): void
	{
		$this->seedManifest();

		$this->assertTrue(pfb_unbound_python_sources_patch($key, [$invalid]));

		$published = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$decoded = json_decode($published, TRUE);
		$this->assertSame(JSON_ERROR_NONE, json_last_error(), 'the patched manifest must be valid JSON');
		$this->assertSame(["\u{FFFD}"], $decoded['config'][$key]);
		$this->assertSame(1, substr_count($published, '\\ufffd'), 'one malformed sequence must emit one replacement');
	}

	public static function residualPatchKeys(): array
	{
		return [
			'whitelist' => ['user_whitelist'],
			'unlock' => ['user_unlock'],
		];
	}

	#[DataProvider('residualPatchKeys')]
	public function testManifestPatchResidualEncodingFailureLogsGenericErrorAndKeepsOldManifest(string $key): void
	{
		$old = $this->seedManifest();

		$this->assertFalse(pfb_unbound_python_sources_patch($key, [NAN]));
		$error = json_last_error_msg();

		$this->assertSame($old, file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
		$this->assertSame('Inf and NaN cannot be JSON encoded', $error);
		foreach ([$this->logContents(), $this->errorLogContents()] as $log) {
			$this->assertStringContainsString('DNSBL manifest JSON encoding failed: ' . $error, $log);
			$this->assertStringNotContainsString('old-manifest-secret', $log);
			$this->assertStringNotContainsString('old-feed-secret', $log);
			$this->assertStringNotContainsString('old.raw', $log);
			$this->assertStringNotContainsString($key, $log);
		}
	}

	public function testInvalidHeaderRowIsSkippedAndLoggedValidRowsKept(): void
	{
		// Given a build whose feed list carries one non-\w header among valid rows
		// (its source file even exists, so only the validation can be the skip cause)
		file_put_contents("{$this->tmp}/dnsbl/bad.header.txt",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'example.com'));
		$feeds = $this->feeds();
		$feeds[] = ['header' => 'bad.header', 'group' => 'g', 'log' => '1'];
		$this->assertSame('', $this->logContents(), 'log must start empty');

		// When the manifest is built
		$m = pfb_unbound_python_sources($feeds);

		// Then the invalid row is absent, logged, and produced no raw file ...
		$this->assertSame(['feed1', 'abpfeed'], array_column($m['feeds'], 'feed'));
		$log = $this->logContents();
		$this->assertStringContainsString('pfb_unbound_python_sources', $log);
		$this->assertStringContainsString('Feed header failed validation', $log);
		$this->assertFileDoesNotExist(dirname($this->rawPath($m, 'feed1')) . '/bad.header.raw');

		// ... and the valid rows built exactly as in an all-valid run.
		$this->assertSame("example.com\nfoo.com\n",
			file_get_contents($this->rawPath($m, 'feed1')));
	}

	public function testAllValidHeadersBuildWithoutValidationLogging(): void
	{
		// The accept side of the same branch: an all-valid build logs no rejection.
		$this->assertSame('', $this->logContents(), 'log must start empty');
		$m = pfb_unbound_python_sources($this->feeds());
		$this->assertCount(2, $m['feeds']);
		$this->assertStringNotContainsString('failed validation', $this->logContents());
	}

	// --- PFBL-01: suppression (whitelist) lines must be domain-valid --------------

	public function testWhitelistKeepsValidDomainAndWildcardLinesUnchanged(): void
	{
		// Plain domain + leading-dot wildcard both pass through unchanged, no log.
		$GLOBALS['pfb']['dnsblconfig']['whitelist'] =
			base64_encode("good.example.com\r\n.wild.example.com");

		$this->assertSame(['good.example.com', '.wild.example.com'], pfb_dnsbl_whitelist_lines());
		$this->assertSame('', $this->logContents(), 'valid lines must not be logged');
	}

	public function testWhitelistSkipsAndLogsNonDomainLine(): void
	{
		// Given one failing line among valid ones, and an empty log
		$GLOBALS['pfb']['dnsblconfig']['whitelist'] =
			base64_encode("good.example.com\r\nbad domain;ls\r\n.wild.example.com");
		$this->assertSame('', $this->logContents(), 'log must start empty');

		// When the manifest whitelist is collected
		$lines = pfb_dnsbl_whitelist_lines();

		// Then only the valid lines remain and the rejection is logged
		$this->assertSame(['good.example.com', '.wild.example.com'], $lines);
		$log = $this->logContents();
		$this->assertStringContainsString('pfb_dnsbl_whitelist_lines', $log);
		$this->assertStringContainsString('failed validation', $log);
	}

	// --- PFBL-01: unlock-store domains re-validated at read -----------------------

	public function testUnlockLinesSkipAndLogNonDomainStoreRow(): void
	{
		// Given a store carrying one non-domain row among valid ones, and an empty log
		file_put_contents("{$this->tmp}/dnsbl_unlock",
			"evil.com,python\nbad;row.com,python\nfoo.org,python\n");
		$this->assertSame('', $this->logContents(), 'log must start empty');

		// When the store is read back for the manifest
		$lines = pfb_dnsbl_unlock_lines();

		// Then the failing row is skipped and logged; the valid rows survive
		$this->assertSame(['evil.com', 'foo.org'], $lines);
		$log = $this->logContents();
		$this->assertStringContainsString('pfb_dnsbl_unlock_lines', $log);
		$this->assertStringContainsString('failed validation', $log);
	}
}
