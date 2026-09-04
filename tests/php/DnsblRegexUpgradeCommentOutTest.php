<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3194 — on package install/upgrade, stored Regex List lines that the
 * save-time Python probe would reject are commented out in place. The editor
 * stays advisory; there is no GET banner and no second validator.
 *
 * pfblockerng_install.inc cannot be included off-appliance, so the rewrite
 * lives in extra.inc (same DI/source-scan shape as pfb_install_psl_feed_policy_seed)
 * and the installer call site is pinned by php_strip_whitespace.
 */
#[CoversFunction('pfb_dnsbl_regex_upgrade_comment_out')]
#[CoversFunction('pfb_dnsbl_regex_validation_errors')]
#[CoversFunction('pfb_lint_parse_regex_errors')]
final class DnsblRegexUpgradeCommentOutTest extends TestCase
{
	private const INSTALL = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';
	private const EXTRA   = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';
	private const PAGE    = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
	private const UNBOUND = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfb_unbound.py';
	private const SRC     = __DIR__ . '/../../src';

	private const WHY = '# blocked at package upgrade: ';

	private static string $python;
	private static string $timeout;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		self::$python  = self::commandPath('python3');
		self::$timeout = self::commandPath('timeout');
	}

	private static function commandPath(string $command): string
	{
		$output = [];
		$status = 1;
		exec('command -v ' . escapeshellarg($command) . ' 2>/dev/null', $output, $status);
		if ($status !== 0 || $output === [] || trim($output[0]) === '') {
			throw new RuntimeException("required test command not found: {$command}");
		}
		return trim($output[0]);
	}

	private static function source(string $path): string
	{
		$src = file_get_contents($path);
		self::assertNotFalse($src, "test fixture unreadable: {$path}");
		return $src;
	}

	/** @return array<int, string> */
	private static function realProbe(string $contents, bool $cap): array
	{
		return pfb_dnsbl_regex_validation_errors($contents, self::$python, $cap, self::$timeout);
	}

	private static function anchoredPattern(int $length): string
	{
		if ($length < 2) {
			throw new InvalidArgumentException('length must be >= 2 to hold both anchors');
		}
		return '^' . str_repeat('a', $length - 2) . '$';
	}

	/**
	 * @param array{
	 *     list?: string,
	 *     stored?: string,
	 *     probe?: callable,
	 *     cap?: bool
	 * } $opts
	 * @return array{
	 *     written: list<array{0: string, 1: mixed}>,
	 *     notices: list<array<int, mixed>>,
	 *     statuses: list<string>,
	 *     flushes: list<string>,
	 *     probe_calls: int,
	 *     decoded: ?string
	 * }
	 */
	private function runUpgrade(array $opts = []): array
	{
		if (!function_exists('pfb_dnsbl_regex_upgrade_comment_out')) {
			$this->fail('pfb_dnsbl_regex_upgrade_comment_out() must exist so upgrade can comment out Python-rejected Regex List lines');
		}

		$written = [];
		$notices = [];
		$statuses = [];
		$flushes = [];
		$probe_calls = 0;
		$list = $opts['list'] ?? '';
		$stored = $opts['stored'] ?? base64_encode($list);
		$cap = $opts['cap'] ?? FALSE;
		$probe = $opts['probe'] ?? static function (string $contents, bool $regex_cap): array {
			return self::realProbe($contents, $regex_cap);
		};
		$wrapped_probe = static function (string $contents, bool $regex_cap) use ($probe, &$probe_calls): array {
			$probe_calls++;
			return $probe($contents, $regex_cap);
		};

		pfb_dnsbl_regex_upgrade_comment_out(
			static fn(): string => $stored,
			static function (string $key, mixed $value) use (&$written): void {
				$written[] = [$key, $value];
			},
			static function (string $message) use (&$flushes): void {
				$flushes[] = $message;
			},
			static function (string $status) use (&$statuses): void {
				$statuses[] = $status;
			},
			static function (...$args) use (&$notices): void {
				$notices[] = $args;
			},
			$wrapped_probe,
			$cap
		);

		$decoded = NULL;
		if ($written !== []) {
			$decoded = pfb_b64_text((string) $written[0][1]);
		}

		return [
			'written'      => $written,
			'notices'      => $notices,
			'statuses'     => $statuses,
			'flushes'      => $flushes,
			'probe_calls'  => $probe_calls,
			'decoded'      => $decoded,
		];
	}

	private function assertSilent(array $result): void
	{
		$this->assertSame([], $result['written'], 'must not rewrite the stored list');
		$this->assertSame([], $result['notices'], 'must not raise a file_notice');
		$this->assertSame([], $result['statuses'], 'must not write an install-log status');
		$this->assertSame([], $result['flushes'], 'must not call write_config');
	}

	private function assertPersistedAndAnnounced(array $result, string $decoded): void
	{
		$this->assertCount(1, $result['written'], 'rewrite must persist exactly once');
		$this->assertSame('dnsbl/pfb_regex_list', $result['written'][0][0]);
		$this->assertSame(base64_encode($decoded), $result['written'][0][1], 'persisted value must stay base64 like a GUI save');
		$this->assertSame($decoded, $result['decoded']);
		$this->assertCount(1, $result['flushes'], 'write_config must run after the rewrite');
		$this->assertCount(1, $result['notices'], 'file_notice must fire');
		$this->assertCount(1, $result['statuses'], 'update_status must fire');
		$notice = $result['notices'][0];
		$this->assertSame('pfBlockerNG', $notice[0]);
		$this->assertSame('pfBlockerNG', $notice[2]);
		$this->assertSame('/pfblockerng/pfblockerng_dnsbl.php', $notice[3]);
		$this->assertSame(2, $notice[4]);
		$this->assertSame($notice[1], $result['statuses'][0], 'install-log stream and file_notice must carry the same text');
	}

	// ---- valid / empty / infra: no rewrite, no notice --------------------------------

	public function testAValidListIsLeftUnchangedAndRaisesNoNotice(): void
	{
		$list = "^keep\\.example\\.com$\n(?P<X>A)\n";
		$result = $this->runUpgrade(['list' => $list]);
		$this->assertSame(1, $result['probe_calls'], 'a non-empty list must still be probed');
		$this->assertSilent($result);
	}

	public function testAnEmptyListDoesNotLaunchTheProbeAndRaisesNoNotice(): void
	{
		$probe = function (): array {
			$this->fail('empty Regex List must not launch the Python probe');
		};
		$result = $this->runUpgrade([
			'stored' => '',
			'probe'  => $probe,
		]);
		$this->assertSame(0, $result['probe_calls']);
		$this->assertSilent($result);
	}

	public function testAnInfrastructureDiagnosticDoesNotRewriteOrNotice(): void
	{
		$list = "^keep\\.example\\.com$\n";
		$result = $this->runUpgrade([
			'list'  => $list,
			'probe' => static fn(): array => ['Python regex validator: interpreter unavailable'],
		]);
		$this->assertSame(1, $result['probe_calls']);
		$this->assertSilent($result);
	}

	// ---- rewrite shape ----------------------------------------------------------------

	public function testInvalidLinesBecomeAWhyLinePlusCommentedOriginalAndNeighboursStay(): void
	{
		$list = "^keep\\.example\\.com$\n(unclosed\n^also\\.keep$\n";
		$result = $this->runUpgrade(['list' => $list]);
		$decoded = (string) $result['decoded'];
		$this->assertPersistedAndAnnounced($result, $decoded);

		$lines = preg_split('/\n/', $decoded, -1, PREG_SPLIT_NO_EMPTY);
		$this->assertSame('^keep\\.example\\.com$', $lines[0], 'the valid neighbour above the reject must stay');
		$this->assertSame('^also\\.keep$', $lines[count($lines) - 1], 'the valid neighbour below the reject must stay');
		$this->assertCount(4, $lines);
		$this->assertTrue(str_starts_with($lines[1], self::WHY), 'the why-line must use the specified prefix');
		$this->assertStringNotContainsString("\n", substr($lines[1], strlen(self::WHY)));
		$this->assertSame('# (unclosed', $lines[2], 'the original line must remain recoverable by deleting the "# " prefix');
		$this->assertStringContainsString('(unclosed', (string) $result['notices'][0][1]);
	}

	public function testAlreadyCommentedLinesAreLeftUntouched(): void
	{
		$list = "# already dead (a+)+\n(unclosed\n^keep\\.example\\.com$\n";
		$result = $this->runUpgrade(['list' => $list]);
		$decoded = (string) $result['decoded'];
		$this->assertPersistedAndAnnounced($result, $decoded);
		$this->assertStringContainsString("# already dead (a+)+\n", $decoded);
		$this->assertStringContainsString("# (unclosed\n", $decoded);
		$this->assertStringContainsString("^keep\\.example\\.com$\n", $decoded);
		$this->assertSame(1, substr_count($decoded, self::WHY));
	}

	public function testASecondUpgradeIsByteIdenticalAndSilent(): void
	{
		$list = "^keep\\.example\\.com$\n(unclosed\n";
		$first = $this->runUpgrade(['list' => $list]);
		$rewritten = (string) $first['decoded'];
		$this->assertNotSame($list, $rewritten);

		$second = $this->runUpgrade(['list' => $rewritten]);
		$this->assertSame(1, $second['probe_calls'], 'the rewritten list is non-empty so the probe still runs');
		$this->assertSilent($second);
	}

	// ---- notice cap -------------------------------------------------------------------

	public function testOneInvalidPatternIsNamedAndHasNoMoreTail(): void
	{
		$result = $this->runUpgrade([
			'list'  => "(unclosed\n",
			'probe' => static fn(): array => ['line 1: leftover: broken'],
		]);
		$notice = (string) $result['notices'][0][1];
		$this->assertStringContainsString('(unclosed', $notice);
		$this->assertStringNotContainsString(' more', $notice);
		$this->assertSame(1, substr_count((string) $result['decoded'], self::WHY));
	}

	public function testExactlyTenInvalidPatternsAreAllNamedWithNoMoreTail(): void
	{
		$lines = [];
		$errors = [];
		$patterns = [];
		for ($i = 1; $i <= 10; $i++) {
			$pattern = '(unclosed_' . sprintf('%02d', $i);
			$patterns[] = $pattern;
			$lines[] = $pattern;
			$errors[] = "line {$i}: leftover: broken";
		}
		$result = $this->runUpgrade([
			'list'  => implode("\n", $lines) . "\n",
			'probe' => static fn(): array => $errors,
		]);
		$notice = (string) $result['notices'][0][1];
		foreach ($patterns as $pattern) {
			$this->assertStringContainsString($pattern, $notice);
		}
		$this->assertStringNotContainsString(' more', $notice);
		$this->assertSame(10, substr_count((string) $result['decoded'], self::WHY));
	}

	public function testElevenInvalidPatternsNameTheFirstTenThenAndOneMoreAndStillRewriteAll(): void
	{
		$lines = [];
		$errors = [];
		$patterns = [];
		for ($i = 1; $i <= 11; $i++) {
			$pattern = '(unclosed_' . sprintf('%02d', $i);
			$patterns[] = $pattern;
			$lines[] = $pattern;
			$errors[] = "line {$i}: leftover: broken";
		}
		$result = $this->runUpgrade([
			'list'  => implode("\n", $lines) . "\n",
			'probe' => static fn(): array => $errors,
		]);
		$notice = (string) $result['notices'][0][1];
		foreach (array_slice($patterns, 0, 10) as $pattern) {
			$this->assertStringContainsString($pattern, $notice);
		}
		$this->assertStringNotContainsString($patterns[10], $notice);
		$this->assertStringContainsString('and 1 more', $notice);
		$this->assertSame(11, substr_count((string) $result['decoded'], self::WHY), 'the 11th reject is still commented out');
	}

	// ---- hostile stored input ---------------------------------------------------------

	public function testCrlfLineEndingsArePreservedThroughTheRewrite(): void
	{
		$list = "^keep\\.example\\.com$\r\n(unclosed\r\n^also\\.keep$\r\n";
		$result = $this->runUpgrade([
			'list'  => $list,
			'probe' => static fn(): array => ['line 2: leftover: broken'],
		]);
		$decoded = (string) $result['decoded'];
		$this->assertPersistedAndAnnounced($result, $decoded);
		$this->assertStringNotContainsString("\n", str_replace("\r\n", '', $decoded), 'must not introduce Unix newlines into a CRLF document');
		$this->assertStringContainsString("^keep\\.example\\.com$\r\n", $decoded);
		$this->assertStringContainsString("# (unclosed\r\n", $decoded);
		$this->assertStringContainsString("^also\\.keep$\r\n", $decoded);
		$this->assertStringContainsString("\r\n" . self::WHY, "\r\n" . $decoded);
	}

	public function testDiagnosticNewlinesCannotReenterAsALivePattern(): void
	{
		$result = $this->runUpgrade([
			'list'  => "^keep\\.example\\.com$\n",
			'probe' => static fn(): array => ["line 1: evil\n(a+)$\nstill: broken"],
		]);
		$decoded = (string) $result['decoded'];
		$this->assertPersistedAndAnnounced($result, $decoded);
		foreach (preg_split('/\R/', $decoded) as $line) {
			if ($line === '') {
				continue;
			}
			$this->assertTrue(
				str_starts_with(ltrim($line), '#'),
				'a newline smuggled in a diagnostic must not become a live Regex List line, got: ' . $line
			);
		}
		$this->assertStringContainsString(self::WHY, $decoded);
		$this->assertStringNotContainsString("\n(a+)$\n", $decoded);
	}

	public function testAnUnescapedHashPatternIsCommentedOut(): void
	{
		$list = "(#)\n^keep\\.example\\.com$\n";
		$result = $this->runUpgrade(['list' => $list]);
		$decoded = (string) $result['decoded'];
		$this->assertPersistedAndAnnounced($result, $decoded);
		$this->assertStringContainsString("# (#)\n", $decoded);
		$this->assertStringContainsString("^keep\\.example\\.com$\n", $decoded);
	}

	public function testTheLengthCapIsRespectedWhenOn(): void
	{
		$list = self::anchoredPattern(201) . "\n^keep\\.example\\.com$\n";
		$result = $this->runUpgrade(['list' => $list, 'cap' => TRUE]);
		$decoded = (string) $result['decoded'];
		$this->assertPersistedAndAnnounced($result, $decoded);
		$this->assertStringContainsString(self::WHY, $decoded);
		$this->assertStringContainsString('# ' . self::anchoredPattern(201) . "\n", $decoded);
	}

	public function testTheLengthCapIsRespectedWhenOff(): void
	{
		$list = self::anchoredPattern(201) . "\n^keep\\.example\\.com$\n";
		$result = $this->runUpgrade(['list' => $list, 'cap' => FALSE]);
		$this->assertSilent($result);
	}

	// ---- installer wiring / no banner / feed stays log-only / no fold-back ------------

	public function testInstallerDispatchesTheSeamAfterSettingsFamilyFinalize(): void
	{
		$source = php_strip_whitespace(self::INSTALL);
		$this->assertNotSame('', $source, 'installer source must be readable');
		$finalize = strpos($source, 'pfb_install_settings_family_finalize($pfb_installed_family);');
		$this->assertNotFalse($finalize, 'positive control: settings-family finalize stays the upgrade seam');
		$call = 'pfb_dnsbl_regex_upgrade_comment_out();';
		$seam = strpos($source, $call);
		$this->assertNotFalse($seam, 'installer must dispatch #3194 comment-out through pfb_dnsbl_regex_upgrade_comment_out()');
		$this->assertSame(1, substr_count($source, $call));
		$this->assertGreaterThan($finalize, $seam, 'comment-out must run after settings-family migrations');
	}

	public function testTheHelperUsesTheSaveTimePythonProbe(): void
	{
		$src = self::source(self::EXTRA);
		$start = strpos($src, 'function pfb_dnsbl_regex_upgrade_comment_out(');
		$this->assertNotFalse($start, 'the upgrade helper must live in extra.inc');
		$next = strpos($src, "\nfunction ", $start + 1);
		$body = $next === FALSE ? substr($src, $start) : substr($src, $start, $next - $start);
		$this->assertStringContainsString(
			'pfb_dnsbl_regex_validation_errors(',
			$body,
			'upgrade comment-out must reuse pfb_dnsbl_regex_validation_errors(), not a second engine'
		);
		$this->assertStringContainsString(
			'pfb_lint_parse_regex_errors(',
			$body,
			'line N: diagnostics must be counted via pfb_lint_parse_regex_errors()'
		);
	}

	public function testTheDnsblPageHasNoGetBannerAndDoesNotProbeOnPageLoad(): void
	{
		$page = self::source(self::PAGE);
		$this->assertStringContainsString(
			"new Form_Textarea(\n\t'pfb_regex_list',\n\t'Regex List'",
			$page,
			'positive control: the Regex List textarea still renders'
		);
		$this->assertSame(
			1,
			substr_count($page, 'pfb_dnsbl_regex_validation_errors('),
			'Python must run on save only — never a second page-load launch'
		);
		$this->assertStringNotContainsString('blocked at package upgrade', $page);
		$this->assertStringNotContainsString('pfb_dnsbl_regex_upgrade_comment_out', $page);
	}

	public function testFeedRegexStaysLogOnlyAndIsNeverRewritten(): void
	{
		$src = self::source(self::UNBOUND);
		$this->assertStringContainsString(
			'[pfBlockerNG]: dropping pathological user regex [ {} ] pattern [ {} ]',
			$src,
			'positive control: the user-regex drop path still logs'
		);
		$this->assertStringContainsString(
			'[pfBlockerNG]: dropping pathological {} regex feed [ {} ] pattern [ {} ] (catastrophic shape)',
			$src
		);
		$feed_at = strpos($src, '[pfBlockerNG]: dropping pathological {} regex feed [ {} ] pattern [ {} ] (catastrophic shape)');
		$this->assertNotFalse($feed_at);
		$region = substr($src, $feed_at, 400);
		$this->assertStringNotContainsString('file_notice', $region);
		$this->assertStringNotContainsString('pfb_regex_list', $region);
		$this->assertStringNotContainsString('blocked at package upgrade', $region);
	}

	public function testTheRetiredExceptionKeyAndFoldBackStayGoneFromSrc(): void
	{
		$hits = [];
		$fold = [];
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator(self::SRC, FilesystemIterator::SKIP_DOTS)
		);
		foreach ($iterator as $file) {
			if (!$file->isFile()) {
				continue;
			}
			$contents = (string) file_get_contents($file->getPathname());
			$rel = substr($file->getPathname(), strlen(self::SRC) + 1);
			if (str_contains($contents, 'pfb_regex_exception_list')) {
				$hits[] = $rel;
			}
			if (preg_match('/fold-back|fold_back|regex exception.*migrat|migrat.*regex exception/i', $contents) === 1) {
				$fold[] = $rel;
			}
		}
		$this->assertSame([], $hits, 'dnsbl/pfb_regex_exception_list must not re-enter src/');
		$this->assertSame([], $fold, 'no fold-back/migration of the pre-alpha exception list');
	}
}
