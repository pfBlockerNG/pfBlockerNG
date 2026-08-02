<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1797: the on-demand feed normalize stage ({base}.orig -> {base}.norm).
 *
 * Executes the REAL pipeline (iconv validity gate, C.UTF-8 sed strip+rtrim,
 * optional Python converter) against temp files. Character-class membership
 * for multi-byte codepoints (BOM/ZWJ as non-printable, NBSP in [:space:]) is
 * locale-DATA-defined and can lag on non-BSD userlands; those legs first
 * probe the platform's raw sed tables and skip with a reason where the data
 * diverges — the appliance behaviour itself is probe-pinned on CE 2.8
 * (FreeBSD 15) and Plus (FreeBSD 16). Everything ASCII is asserted
 * unconditionally on every platform.
 */
#[CoversFunction('pfb_feed_normalize')]
#[CoversFunction('pfb_feed_normalize_generate')]
#[CoversFunction('pfb_feed_convert_encoding')]
final class PfbFeedNormalizeTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_norm_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		@chmod($this->dir, 0755);
		foreach (glob("{$this->dir}/*") ?: [] as $f) {
			@chmod($f, 0644);
			@unlink($f);
		}
		foreach (glob("{$this->dir}/.pfbnorm_*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
	}

	private function writeOrig(string $content, string $name = 'feed'): string
	{
		$orig = "{$this->dir}/{$name}.orig";
		file_put_contents($orig, $content);
		return $orig;
	}

	/** Interpreter that would fail loudly if the converter were ever consulted. */
	private const NO_CONVERTER = '/nonexistent/pfb-test-python';

	private static function platformSedStrips(string $probe_in, string $expected): bool
	{
		$out = shell_exec('printf %s ' . escapeshellarg($probe_in) .
			" | LC_ALL=C.UTF-8 /usr/bin/sed -E 's/[^[:print:]\t]+|[[:space:]]+\$//g'");
		return $out === $expected;
	}

	// --- the pipeline core, ASCII-stable on every platform ---

	public function testValidUtf8FileNormalizesWithoutConsultingTheConverter(): void
	{
		// The iconv validity gate must decide BEFORE any detection: a valid
		// UTF-8 file reaches sed directly, so 'café' can never be
		// double-encoded to 'cafÃ©' by a wrong external charset declaration.
		$orig = $this->writeOrig("café\r\nx\n");
		$res  = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertTrue($res['normalized']);
		$this->assertSame("{$this->dir}/feed.norm", $res['path']);
		$this->assertSame("café\nx\n", file_get_contents($res['path']));
		$this->assertTrue($res['changed'], 'first normalization has no baseline and must report changed');
		$this->assertFileExists("{$this->dir}/feed.norm.src.xxhash128");
	}

	public function testMidLineCrIsRemovedAtTheFileLevel(): void
	{
		$orig = $this->writeOrig("ads.example.com\revil\n");
		$res  = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertSame("ads.example.comevil\n", file_get_contents($res['path']));
	}

	public function testTabSeparatedHostsRowKeepsInteriorTabs(): void
	{
		$orig = $this->writeOrig("127.0.0.1\tads.example.com\t\t\n");
		$res  = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertSame("127.0.0.1\tads.example.com\n", file_get_contents($res['path']));
	}

	public function testControlCharactersAreStrippedEverywhereAndTrailingWhitespaceTrimmed(): void
	{
		$orig = $this->writeOrig("a\x00b\x07c   \nkeep\n");
		$res  = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertSame("abc\nkeep\n", file_get_contents($res['path']));
	}

	public function testTrailingNewlineGuaranteeIsReapplied(): void
	{
		// BSD sed adds no trailing newline; .norm must re-apply the #1263
		// guarantee itself or downstream concatenation welds rows.
		$orig = $this->writeOrig('nolf.example.com');
		$res  = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertSame("nolf.example.com\n", file_get_contents($res['path']));
	}

	// --- multi-byte class membership: locale-data-gated legs ---

	public function testBomAndZwjAreStrippedAsNonPrintable(): void
	{
		if (!self::platformSedStrips("\xEF\xBB\xBFa\xE2\x80\x8Db", 'ab')) {
			$this->markTestSkipped('platform locale data does not class BOM/ZWJ as non-printable; appliance behaviour probe-pinned on CE 2.8 + Plus');
		}
		$orig = $this->writeOrig("\xEF\xBB\xBFbom\xE2\x80\x8Dzwj\n");
		$res  = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertSame("bomzwj\n", file_get_contents($res['path']));
	}

	public function testInteriorNbspIsDataWhileTrailingNbspIsTrimmed(): void
	{
		if (!self::platformSedStrips("end\xC2\xA0", 'end')) {
			$this->markTestSkipped('platform locale data does not class NBSP as [:space:]; appliance behaviour probe-pinned on CE 2.8 + Plus');
		}
		$orig = $this->writeOrig("mid\xC2\xA0dle\ntrail\xC2\xA0\n");
		$res  = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertSame("mid\xC2\xA0dle\ntrail\n", file_get_contents($res['path']));
	}

	// --- regeneration keyed by the recorded source digest ---

	public function testFreshNormIsReusedWithoutRegeneration(): void
	{
		$orig = $this->writeOrig("a.example.com\n");
		pfb_feed_normalize($orig, self::NO_CONVERTER);
		// Plant a sentinel: a reused .norm is NOT rewritten, so the sentinel
		// must survive a second call against the unchanged .orig.
		file_put_contents("{$this->dir}/feed.norm", "sentinel\n");
		$res = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertFalse($res['changed']);
		$this->assertSame("sentinel\n", file_get_contents($res['path']),
			'a source-digest-fresh .norm must be reused, not regenerated');
	}

	public function testOrigChurnThatNormalizesAwayReportsUnchanged(): void
	{
		// The processing-level gate's whole point: upstream CRLF churn changes
		// .orig but yields a byte-identical .norm -> downstream may skip.
		$orig = $this->writeOrig("a.example.com\nb.example.com\n");
		$first = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertTrue($first['changed']);
		$this->writeOrig("a.example.com\r\nb.example.com\r\n");
		$res = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertTrue($res['normalized']);
		$this->assertFalse($res['changed'],
			'a changed .orig with identical normalized content must report unchanged');
		$this->assertSame("a.example.com\nb.example.com\n", file_get_contents($res['path']));
	}

	public function testOrigChangeWithNewContentReportsChanged(): void
	{
		$orig = $this->writeOrig("a.example.com\n");
		pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->writeOrig("c.example.com\n");
		$res = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertTrue($res['changed']);
		$this->assertSame("c.example.com\n", file_get_contents($res['path']));
	}

	public function testMissingNormRegeneratesAndFailSafesToChanged(): void
	{
		$orig = $this->writeOrig("a.example.com\n");
		pfb_feed_normalize($orig, self::NO_CONVERTER);
		unlink("{$this->dir}/feed.norm");
		$res = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertTrue($res['normalized']);
		$this->assertSame("a.example.com\n", file_get_contents($res['path']));
		$this->assertTrue($res['changed'], 'no previous .norm to compare against -> fail-safe changed');
	}

	public function testTruncatedNormWithStaleSidecarRegenerates(): void
	{
		$orig = $this->writeOrig("a.example.com\nb.example.com\n");
		pfb_feed_normalize($orig, self::NO_CONVERTER);
		file_put_contents("{$this->dir}/feed.norm", 'a.exam');	// simulated partial write
		$this->writeOrig("a.example.com\nb.example.com\nc.example.com\n");
		$res = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertTrue($res['changed']);
		$this->assertSame("a.example.com\nb.example.com\nc.example.com\n", file_get_contents($res['path']));
	}

	public function testMissingBaselineSidecarFailSafesToChangedEvenWhenBytesMatch(): void
	{
		// The ADR-43 Force clear-hashes sweep removes the .norm.src sidecar so
		// the downstream-skip gate cannot fire on a forced pass.
		$orig = $this->writeOrig("a.example.com\n");
		pfb_feed_normalize($orig, self::NO_CONVERTER);
		unlink("{$this->dir}/feed.norm.src.xxhash128");
		$res = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertTrue($res['changed'],
			'a missing source-digest baseline must never report unchanged');
	}

	// --- fallback: parse .orig rather than yield an empty feed ---

	public function testMissingOrigFallsBackToTheOrigPath(): void
	{
		$res = pfb_feed_normalize("{$this->dir}/absent.orig", self::NO_CONVERTER);
		$this->assertSame("{$this->dir}/absent.orig", $res['path']);
		$this->assertFalse($res['normalized']);
		$this->assertTrue($res['changed']);
	}

	public function testUnwritableDirectoryFallsBackToParsingOrig(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses file permissions; the unwritable-dir denial cannot be simulated');
		}
		$orig = $this->writeOrig("a.example.com\n");
		chmod($this->dir, 0555);
		$res = pfb_feed_normalize($orig, self::NO_CONVERTER);
		$this->assertSame($orig, $res['path'], 'normalize failure must fall back to the raw .orig');
		$this->assertFalse($res['normalized']);
		$this->assertTrue($res['changed']);
	}

	// --- wiring guard: only the parse-loop consumers normalize ---

	/** #993: both live parse loops are unsafe off-appliance; only comment-free outer pins remain. */
	public function testLiveFeedDispatchNormalizesOnlyAtParseConsumers(): void
	{
		$apply = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertSame(2, substr_count($apply, '$pfb_norm = pfb_feed_normalize('),
			'live download consumers must normalize exactly once per DNSBL/IP parse loop');
		$inc = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertSame(0, substr_count($inc, '$pfb_norm = pfb_feed_normalize('),
			'the download/firewall orchestration include must not normalize before its live parse consumers');
	}

	// --- the Python converter leg (real charset_normalizer where available) ---

	private static function converterInterpreter(): ?string
	{
		$py = trim((string) shell_exec('command -v python3 2>/dev/null'));
		if ($py === '') {
			return null;
		}
		exec(escapeshellarg($py) . ' -c "import charset_normalizer" 2>/dev/null', $o, $ret);
		return $ret === 0 ? $py : null;
	}

	public function testNonUtf8FeedIsDetectedAndConvertedToUtf8(): void
	{
		$py = self::converterInterpreter();
		if ($py === null) {
			$this->markTestSkipped('no python3 with charset_normalizer available for the converter leg');
		}
		// A realistic Latin-1 body: enough text for deterministic detection.
		$body = str_repeat("b\xFCcher-stra\xDFe.example.com\ncaf\xE9.example.com\n", 200);
		$orig = $this->writeOrig($body);
		$res  = pfb_feed_normalize($orig, $py);
		$this->assertTrue($res['normalized']);
		$norm = file_get_contents($res['path']);
		$this->assertTrue(mb_check_encoding($norm, 'UTF-8'), 'converted output must be valid UTF-8');
		$this->assertStringContainsString('bücher', $norm);
		$this->assertStringContainsString('café', $norm);
	}

	public function testConversionUnavailableDegradesGracefullyNeverToAnEmptyFeed(): void
	{
		// With no interpreter resolvable ('' is the resolver's on-failure
		// value) an invalid-UTF-8 file reaches sed raw. FreeBSD sed passes the
		// invalid bytes through while still stripping controls; other libcs
		// (macOS) abort the regex on an illegal byte sequence, in which case
		// the helper must fall back to the raw .orig -- either way the feed is
		// parseable, never empty.
		$raw  = "caf\xE9\x07.example.com\n";
		$orig = $this->writeOrig($raw);
		$res  = pfb_feed_normalize($orig, '');
		if ($res['normalized']) {
			$norm = (string) file_get_contents($res['path']);
			$this->assertStringStartsWith('caf', $norm);
			$this->assertStringNotContainsString("\x07", $norm, 'the BEL control must be stripped in degraded mode');
		} else {
			$this->assertSame($orig, $res['path'], 'a failed normalization must fall back to the raw .orig');
			$this->assertSame($raw, file_get_contents($orig), 'the .orig baseline must stay untouched');
		}
		$this->assertTrue($res['changed'], 'degraded handling must never report a skippable unchanged verdict');
	}
}
