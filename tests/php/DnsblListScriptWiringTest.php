<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1926: DNSBL feeds save Pre/Post-process Script pickers that are never
 * executed. Wiring mirrors the IP loop's #1925 shape (staged normalized copy,
 * exit-status gated, manifest row kept on a pre-script failure with an existing
 * '.txt'); the DNSBL parse loop sits inside the thousands-of-lines sync loop
 * driving real appliance exec, so the call sites are pinned by source
 * inspection (same technique as ListScriptExitStatusTest /
 * GunzipTrailingNewlineWiringTest). The DNSBLIP mixed-feed fixture proves the
 * hazard the new help-text warning names: a pre-script that strips IP-shaped
 * lines silently shrinks the DNSBLIP alias.
 */
#[CoversFunction('pfb_dnsbl_norm_reuse_skip')]
#[CoversFunction('pfb_list_pre_script_run')]
#[CoversFunction('pfb_list_script_exec')]
#[CoversFunction('pfb_dnsbl_collect_feed_ip')]
final class DnsblListScriptWiringTest extends TestCase
{
	private static string $applySource;
	private static string $categoryEditSource;

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	public static function setUpBeforeClass(): void
	{
		$applySource = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		if ($applySource === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		self::$applySource = $applySource;

		$categoryEditSource = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($categoryEditSource === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}
		self::$categoryEditSource = $categoryEditSource;
	}

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_dlsw_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->tmp, 0755, TRUE);

		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
			'supp'   => PfbToggle::Off,
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		exec('chmod -R u+rwx ' . escapeshellarg($this->tmp));
		exec('rm -rf ' . escapeshellarg($this->tmp));
	}

	private function makeScript(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	// -----------------------------------------------------------------
	// (a) source-inspection wiring
	// -----------------------------------------------------------------

	public function testAliasHeadResolvesBothScriptsAfterSrcint(): void
	{
		$srcintPos = strpos(self::$applySource, "\$srcint = \$list['srcint'] ?? '' ?: FALSE;");
		$this->assertNotFalse($srcintPos, 'vacuity: the DNSBL per-alias srcint assignment must exist');

		$rowLoopPos = strpos(self::$applySource, "foreach (\$list['row'] as \$key => \$row) {", $srcintPos);
		$this->assertNotFalse($rowLoopPos, 'vacuity: the per-row loop that follows must exist');

		$between = substr(self::$applySource, $srcintPos, $rowLoopPos - $srcintPos);
		$this->assertStringContainsString('$pfb_dnsbl_script_pre', $between,
			'the pre-script must be resolved once per alias, mirroring the IP loop');
		$this->assertStringContainsString('$pfb_dnsbl_script_post', $between,
			'the post-script must be resolved once per alias, mirroring the IP loop');
		$this->assertStringContainsString('pfb_resolve_list_script(', $between,
			'resolution must go through the same containment-checked resolver as the IP loop');
	}

	public function testReuseSkipCallSitePassesTheUserScriptFlag(): void
	{
		$reuseSkipPos = strpos(self::$applySource, 'pfb_dnsbl_norm_reuse_skip(');
		$this->assertNotFalse($reuseSkipPos, 'vacuity: the DNSBL normalize/reuse-skip call site must exist');

		$callEnd = strpos(self::$applySource, 'unchanged after normalization.', $reuseSkipPos);
		$this->assertNotFalse($callEnd, 'vacuity: the reuse-skip branch body must exist');

		$call = substr(self::$applySource, $reuseSkipPos, $callEnd - $reuseSkipPos);
		$this->assertStringContainsString('$pfb_dnsbl_user_script', $call,
			'a configured pre/post script must force a full reparse every pass, same contract as the IP loop');

		$userScriptPos = strpos(self::$applySource, '$pfb_dnsbl_user_script = ');
		$this->assertNotFalse($userScriptPos, 'vacuity: the user-script computation must exist');
		$this->assertLessThan($reuseSkipPos, $userScriptPos,
			'$pfb_dnsbl_user_script must be computed before it is passed to the reuse-skip call');
	}

	public function testPreScriptWindowRunsAfterReuseSkipAndBeforeSchemeWarn(): void
	{
		$reuseSkipPos = strpos(self::$applySource, 'pfb_dnsbl_norm_reuse_skip(');
		$this->assertNotFalse($reuseSkipPos, 'vacuity: the DNSBL normalize/reuse-skip call site must exist');

		$schemeWarnPos = strpos(self::$applySource, 'pfb_dnsbl_scheme_skip_warn($pfb_scheme_skipped, $header);', $reuseSkipPos);
		$this->assertNotFalse($schemeWarnPos, 'vacuity: the scheme-skip warning call must exist');
		$this->assertGreaterThan($reuseSkipPos, $schemeWarnPos, 'the scheme-skip warning must sit after reuse-skip');

		$window = substr(self::$applySource, $reuseSkipPos, $schemeWarnPos - $reuseSkipPos);

		$this->assertStringContainsString('pfb_list_pre_script_run(', $window,
			'the pre-script must run through the staged-copy runner, mirroring the IP loop');
		$this->assertStringContainsString('continue;', $window,
			'a pre-script failure must skip the parse, keeping the last known-good staging');
		$this->assertStringContainsString('pfb_feed_manifest_row(', $window,
			'the failure branch must still emit a manifest row when a staged .txt exists -- '
			. 'dropping it would relocate the outage (#1841 class), not fix it');
		$this->assertStringContainsString('$staging_current_generation && file_exists("{$pfbfolder}/{$header}.txt")', $window,
			'the manifest-on-failure emission must be guarded on an existing staged .txt');
		$this->assertStringContainsString('" dnsbl {$elog}"', $window,
			'the pre-script args tail must carry the stable "dnsbl" discriminator -- DNSBL has no vtype');

		$fopenPos = strpos(self::$applySource, '@fopen($pfb_parse_path', $reuseSkipPos);
		$this->assertNotFalse($fopenPos, 'vacuity: the parse open must read the (possibly staged) parse path');
		$this->assertLessThan($schemeWarnPos, $fopenPos, 'the parse must happen before the scheme-skip warning');
		$this->assertGreaterThan($reuseSkipPos, $fopenPos, 'the parse must happen after reuse-skip');

		$this->assertStringNotContainsString('@fopen($pfb_norm[\'path\']', self::$applySource,
			'the raw normalized path must no longer be the parse source -- the pre-script may have staged a copy');
	}

	public function testStagedPreScriptCopyIsUnlinkedAfterParsing(): void
	{
		$fopenPos = strpos(self::$applySource, '@fopen($pfb_parse_path');
		$this->assertNotFalse($fopenPos, 'vacuity: the parse open must exist');

		$schemeWarnPos = strpos(self::$applySource, 'pfb_dnsbl_scheme_skip_warn($pfb_scheme_skipped, $header);', $fopenPos);
		$this->assertNotFalse($schemeWarnPos, 'vacuity: the scheme-skip warning must exist');

		$window = substr(self::$applySource, $fopenPos, $schemeWarnPos - $fopenPos);
		$this->assertStringContainsString('unlink_if_exists("{$file_dwn}.pre");', $window,
			'the transient staged pre-script copy must be cleaned up once parsed, mirroring the IP loop');
	}

	public function testPostScriptWindowRunsAfterSchemeWarn(): void
	{
		$schemeWarnPos = strpos(self::$applySource, 'pfb_dnsbl_scheme_skip_warn($pfb_scheme_skipped, $header);');
		$this->assertNotFalse($schemeWarnPos, 'vacuity: the scheme-skip warning call must exist');

		$dedupPos = strpos(self::$applySource, 'Remove duplicates and save any IPs found', $schemeWarnPos);
		$this->assertNotFalse($dedupPos, 'vacuity: the IP-dedup comment after parsing must exist');
		$this->assertGreaterThan($schemeWarnPos, $dedupPos);

		$window = substr(self::$applySource, $schemeWarnPos, $dedupPos - $schemeWarnPos);
		$this->assertStringContainsString('pfb_list_script_exec(', $window,
			'the post-script must run through the exit-status-honouring runner');
		$this->assertStringContainsString('" dnsbl {$elog}"', $window,
			'the post-script args tail must carry the stable "dnsbl" discriminator -- DNSBL has no vtype');
		$this->assertStringContainsString('@copy("{$file_dwn}.orig", "{$file_dwn}.post")', $window,
			'the post-script must run on a throwaway copy of the download, not the .orig itself');
		$this->assertStringContainsString('unlink_if_exists("{$file_dwn}.post");', $window,
			'the throwaway post-script copy must be cleaned up -- nothing downstream re-parses it');
		$this->assertStringContainsString('could not stage its input', $window,
			'a post-script staging copy failure must be logged naming the script -- a silent skip is undebuggable');
		$this->assertStringNotContainsString('.orig.post', $window,
			'the IP loop\'s backup/restore machinery is deliberately NOT mirrored -- the post-script '
			. 'edits a throwaway copy instead of an .orig that would be restored anyway');
	}

	// -----------------------------------------------------------------
	// (b) DNSBLIP mixed-feed regression fixture
	// -----------------------------------------------------------------

	/** @return list<string> */
	private function mixedFeedLines(): array
	{
		return [
			'example.com',
			'sub.example.org',
			'192.0.2.10',
			'198.51.100.20',
			'2001:db8::1',
			'2001:db8::dead:beef',
			'||ads.example.net^',
			'@@||allow.example.net^',
			'another-domain.test',
			'203.0.113.5',
			'||192.0.2.9^',
			'||2001:db8::9^',
		];
	}

	/**
	 * Mirrors the DNSBL loop's two collection sites: the ABP network anchor is
	 * unwrapped by pfb_dnsbl_abp_extract_ip() first, plain lines go straight to
	 * the collector.
	 *
	 * @return array{v4: int, v6: int}
	 */
	private function collectIpCounts(string $content): array
	{
		$ip4 = [];
		$ip6 = [];
		foreach (preg_split('/\R/', $content) as $line) {
			if ($line === '') {
				continue;
			}
			$abp_ip = pfb_dnsbl_abp_extract_ip($line);
			if ($abp_ip !== '') {
				pfb_dnsbl_collect_feed_ip($abp_ip, $abp_ip, FALSE, $ip4, $ip6);
				continue;
			}
			pfb_dnsbl_collect_feed_ip($line, $line, FALSE, $ip4, $ip6);
		}
		return ['v4' => count($ip4), 'v6' => count($ip6)];
	}

	public function testIdentityPreScriptPreservesDnsblipExtractionCounts(): void
	{
		$lines = $this->mixedFeedLines();
		$content = implode("\n", $lines) . "\n";

		// Before-state: the ORIGINAL content extracts exactly the 3 plain + 1 ABP v4
		// lines and the 2 plain + 1 ABP v6 lines above.
		$before = $this->collectIpCounts($content);
		$this->assertSame(4, $before['v4'], 'sanity: fixture must carry exactly 4 v4-shaped lines (incl. one ABP-anchored)');
		$this->assertSame(3, $before['v6'], 'sanity: fixture must carry exactly 3 v6-shaped lines (incl. one ABP-anchored)');

		$norm = "{$this->tmp}/feed.norm";
		file_put_contents($norm, $content);
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('dnsbl_pre_identity.sh', 'exit 0');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'dnsbl_pre_identity.sh', 'MyFeed',
			escapeshellarg($staged) . ' dnsbl', '');
		$this->assertTrue($result['ok'], 'an identity script must be honoured');

		$after = $this->collectIpCounts((string) file_get_contents($result['path']));
		$this->assertSame($before['v4'], $after['v4'],
			'an identity pre-script must not change the extracted v4 DNSBLIP count');
		$this->assertSame($before['v6'], $after['v6'],
			'an identity pre-script must not change the extracted v6 DNSBLIP count');
	}

	public function testStrippingPreScriptShrinksDnsblipExtractionCounts(): void
	{
		$lines = $this->mixedFeedLines();
		$content = implode("\n", $lines) . "\n";
		$before = $this->collectIpCounts($content);

		$norm = "{$this->tmp}/feed.norm";
		file_put_contents($norm, $content);
		$staged = "{$this->tmp}/feed.pre";
		// Strips every IP-shaped line -- plain AND ABP-anchored (||IP^) -- the exact
		// hazard the DNSBL help-text warning names: a careless pre-process script
		// silently shrinks the DNSBLIP alias.
		$script = $this->makeScript('dnsbl_pre_strip_ips.sh',
			"grep -Ev '^(\\|\\|)?[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\^?\$|^(\\|\\|)?[0-9a-fA-F:]+\\^?\$' \"\$1\" > \"\$1.tmp\" && mv \"\$1.tmp\" \"\$1\"");

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'dnsbl_pre_strip_ips.sh', 'MyFeed',
			escapeshellarg($staged) . ' dnsbl', '');
		$this->assertTrue($result['ok'], 'the stripping script itself must not fail (non-zero exit / delete)');

		$after = $this->collectIpCounts((string) file_get_contents($result['path']));
		$this->assertLessThan($before['v4'], $after['v4'],
			'a script that strips IP-shaped lines must shrink the extracted v4 DNSBLIP count '
			. '-- this is the failure the fixture must be able to detect');
		$this->assertLessThan($before['v6'], $after['v6'],
			'a script that strips IP-shaped lines must shrink the extracted v6 DNSBLIP count');
		$this->assertSame(0, $after['v4']);
		$this->assertSame(0, $after['v6']);
	}

	// -----------------------------------------------------------------
	// (c) www/ help-note render pin
	// -----------------------------------------------------------------

	public function testHelpNoteIsConditionedOnTheDnsblPrefixAndConcatenatedIntoScriptPreHelp(): void
	{
		$notePos = strpos(self::$categoryEditSource, '$script_dnsbl_note');
		$this->assertNotFalse($notePos, 'vacuity: the DNSBL-only help note assignment must exist');

		// ";\n" (not a bare ";") skips the "&nbsp;" HTML entity's own semicolon --
		// that entity sits mid-string, never followed by a newline.
		$noteEnd = strpos(self::$categoryEditSource, ";\n", $notePos);
		$this->assertNotFalse($noteEnd, 'vacuity: the note assignment must terminate');
		$noteAssignment = substr(self::$categoryEditSource, $notePos, $noteEnd - $notePos);

		$this->assertStringContainsString("\$list_prefix == 'dnsbl'", $noteAssignment,
			'the note must be conditioned on the dnsbl prefix -- the IP tab must never render it');
		$this->assertStringContainsString('DNSBLIP', $noteAssignment,
			'the note must name the alias it warns about');
		$this->assertStringContainsString('silently shrink', $noteAssignment,
			'the note must name the failure mode the DNSBLIP fixture proves');

		$fieldPos = strpos(self::$categoryEditSource, "'script_pre',");
		$this->assertNotFalse($fieldPos, 'vacuity: the script_pre Form_Select must exist');

		$sizePos = strpos(self::$categoryEditSource, "->setAttribute('size', \$options_script_pre_cnt);", $fieldPos);
		$this->assertNotFalse($sizePos, 'vacuity: the script_pre field must terminate with its size attribute');

		$fieldBlock = substr(self::$categoryEditSource, $fieldPos, $sizePos - $fieldPos);
		$this->assertStringContainsString('$script_dnsbl_note', $fieldBlock,
			'the note must be concatenated into the script_pre field\'s sethelp text');
	}
}
