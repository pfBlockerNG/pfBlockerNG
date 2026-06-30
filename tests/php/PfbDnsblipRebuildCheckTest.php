<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsblip_rebuild_check() — DNSBLIP rebuild gate (issue #653).
 *
 * DNSBLIP_<fam> is the union of the *_v<fam>.ip files (IPs extracted from the DNSBL feeds). It was
 * rebuilt + re-filtered on every IP update; this gate makes it rebuild ONLY when the output is
 * missing or the .ip source set actually changed. Detection is content-addressed (ADR-42 style),
 * not mtime-based, since a .ip file may be rewritten with identical content each pass.
 *
 * Each case asserts the [rebuild, fingerprint] pair so the rebuild decision AND the stored-state
 * value are both pinned. The fingerprint reuses pfb_dnsbl_loaded_fingerprint().
 */
#[CoversFunction('pfb_dnsblip_rebuild_check')]
final class PfbDnsblipRebuildCheckTest extends TestCase
{
	private string $tmp;
	private string $out;
	private string $fp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_dnsblip_' . uniqid('', true);
		mkdir($this->tmp, 0o755, true);
		$this->out = "{$this->tmp}/DNSBLIP_v4.txt";
		$this->fp  = "{$this->out}.fp";
	}

	protected function tearDown(): void
	{
		array_map('unlink', glob("{$this->tmp}/*") ?: []);
		@rmdir($this->tmp);
	}

	private function ipfile(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, $body);
		return $path;
	}

	public function testRebuildsWhenOutputMissing(): void
	{
		// Given source .ip files but no DNSBLIP output yet
		$files = [$this->ipfile('a_v4.ip', "1.2.3.4\n")];
		// When checked (output + fp absent)
		[$rebuild, $fp] = pfb_dnsblip_rebuild_check($this->out, $files, $this->fp);
		// Then it must rebuild, and return the current fingerprint
		$this->assertTrue($rebuild, 'missing output must force a rebuild');
		$this->assertNotSame('', $fp);
	}

	public function testRebuildsWhenFingerprintSidecarMissing(): void
	{
		$files = [$this->ipfile('a_v4.ip', "1.2.3.4\n")];
		touch($this->out);                       // output exists, but no stored fingerprint
		[$rebuild] = pfb_dnsblip_rebuild_check($this->out, $files, $this->fp);
		$this->assertTrue($rebuild, 'a missing fingerprint sidecar must force a rebuild');
	}

	public function testSkipsWhenSourceUnchanged(): void
	{
		// Given a built output + a stored fingerprint matching the current .ip set
		$files = [$this->ipfile('a_v4.ip', "1.2.3.4\n"), $this->ipfile('b_v4.ip', "5.6.7.8\n")];
		touch($this->out);
		[$rebuild_first, $fp] = pfb_dnsblip_rebuild_check($this->out, $files, $this->fp);
		$this->assertTrue($rebuild_first, 'first build (no sidecar) rebuilds');
		file_put_contents($this->fp, $fp);       // caller persists the fingerprint on rebuild

		// When re-checked with the SAME source set
		[$rebuild_again, $fp_again] = pfb_dnsblip_rebuild_check($this->out, $files, $this->fp);

		// Then it skips the rebuild and the fingerprint is stable
		$this->assertFalse($rebuild_again, 'an unchanged .ip set must NOT rebuild');
		$this->assertSame($fp, $fp_again);
	}

	public function testRebuildsWhenSourceContentChanges(): void
	{
		$files = [$this->ipfile('a_v4.ip', "1.2.3.4\n")];
		touch($this->out);
		[, $fp] = pfb_dnsblip_rebuild_check($this->out, $files, $this->fp);
		file_put_contents($this->fp, $fp);

		// When a source feed's IPs change
		$this->ipfile('a_v4.ip', "1.2.3.4\n9.9.9.9\n");
		[$rebuild, $fp_new] = pfb_dnsblip_rebuild_check($this->out, $files, $this->fp);

		$this->assertTrue($rebuild, 'a changed .ip set must rebuild');
		$this->assertNotSame($fp, $fp_new, 'the fingerprint must reflect the new content');
	}

	public function testIsMtimeAgnostic(): void
	{
		// ADR-42 intent: a .ip rewritten with IDENTICAL content (newer mtime) is NOT a change.
		$path = $this->ipfile('a_v4.ip', "1.2.3.4\n");
		touch($this->out);
		[, $fp] = pfb_dnsblip_rebuild_check($this->out, [$path], $this->fp);
		file_put_contents($this->fp, $fp);

		// Rewrite same bytes, bump mtime well into the future
		file_put_contents($path, "1.2.3.4\n");
		touch($path, time() + 3600);

		[$rebuild] = pfb_dnsblip_rebuild_check($this->out, [$path], $this->fp);
		$this->assertFalse($rebuild, 'identical content with a newer mtime must NOT rebuild');
	}
}
