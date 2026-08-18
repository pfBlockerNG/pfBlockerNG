<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #2516 — the CA locations our networked pkg calls carry (issue #2514).
 *
 * Background: on pfSense Plus, pfSense-repo-setup writes a PKG_ENV block into pkg.conf
 * pinning SSL_CA_CERT_FILE to a Netgate-only CA bundle, and libpkg applies that block with
 * setenv(key, value, 1) — overwrite — so a value we pass for that variable loses. PKG_ENV
 * never sets SSL_CA_CERT_PATH, and libfetch loads file and path into one store via
 * SSL_CTX_load_verify_locations(ctx, ca_cert_file, ca_cert_path), so the path survives the
 * pin and gives a third-party catalog read the public roots it was missing.
 *
 * The bundle rides along because libfetch stops calling SSL_CTX_set_default_verify_paths()
 * as soon as EITHER variable is set: on a box with no pin, exporting the path alone would
 * SHRINK the store to a directory FreeBSD ships empty until certctl rehash populates it.
 *
 * These pin the prefix builder, whose output is spliced in front of the two networked pkg
 * commands in pfb_pkg_latest(). Every case asserts the exact string, so a guard that stops
 * guarding is red rather than merely different.
 */
#[CoversFunction('pfb_pkg_ca_env_prefix')]
final class PkgCaEnvPrefixTest extends TestCase
{
	private string $root = '';

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb-ca-' . bin2hex(random_bytes(6));
		mkdir($this->root, 0o755, true);
	}

	protected function tearDown(): void
	{
		foreach (['/certs/x.0', '/certs', '/cert.pem', '/bundle dir', "/cert's dir"] as $leaf) {
			$p = $this->root . $leaf;
			if (is_file($p)) {
				@chmod($p, 0o644);
			}
			if (is_file($p)) {
				unlink($p);
			} elseif (is_dir($p)) {
				rmdir($p);
			}
		}
		if (is_dir($this->root)) {
			rmdir($this->root);
		}
	}

	private function seedDir(): string
	{
		$dir = $this->root . '/certs';
		mkdir($dir, 0o755, true);
		file_put_contents($dir . '/x.0', "");
		return $dir;
	}

	private function seedBundle(string $content = "-----BEGIN CERTIFICATE-----\n"): string
	{
		$file = $this->root . '/cert.pem';
		file_put_contents($file, $content);
		return $file;
	}

	public function testBothLocationsPresentAreBothExported(): void
	{
		$dir = $this->seedDir();
		$file = $this->seedBundle();

		$this->assertSame(
			'SSL_CA_CERT_PATH=' . escapeshellarg($dir) . ' SSL_CA_CERT_FILE=' . escapeshellarg($file) . ' ',
			pfb_pkg_ca_env_prefix($dir, $file),
			'both locations exist, so both must reach pkg'
		);
	}

	public function testMissingDirectoryExportsOnlyTheBundle(): void
	{
		$file = $this->seedBundle();

		$this->assertSame(
			'SSL_CA_CERT_FILE=' . escapeshellarg($file) . ' ',
			pfb_pkg_ca_env_prefix($this->root . '/certs', $file),
			'a missing directory must not be handed to pkg'
		);
	}

	public function testMissingBundleExportsOnlyTheDirectory(): void
	{
		$dir = $this->seedDir();

		$this->assertSame(
			'SSL_CA_CERT_PATH=' . escapeshellarg($dir) . ' ',
			pfb_pkg_ca_env_prefix($dir, $this->root . '/cert.pem'),
			'a missing bundle must not be handed to pkg'
		);
	}

	public function testEmptyBundleIsRefusedButTheDirectoryStillExports(): void
	{
		$dir = $this->seedDir();
		$file = $this->seedBundle('');

		$this->assertSame(
			'SSL_CA_CERT_PATH=' . escapeshellarg($dir) . ' ',
			pfb_pkg_ca_env_prefix($dir, $file),
			'X509_STORE_load_locations() reads the file eagerly and abandons the path when that '
			. 'read fails, so a zero-byte bundle would cost the directory too'
		);
	}

	public function testUnreadableBundleIsRefusedButTheDirectoryStillExports(): void
	{
		if (posix_getuid() === 0) {
			$this->markTestSkipped('root reads mode-0000 files, so the guard cannot be observed as root');
		}
		$dir = $this->seedDir();
		$file = $this->seedBundle();
		chmod($file, 0o000);

		$this->assertSame(
			'SSL_CA_CERT_PATH=' . escapeshellarg($dir) . ' ',
			pfb_pkg_ca_env_prefix($dir, $file),
			'a bundle pkg cannot read would fail the eager load and cost the directory with it'
		);
	}

	public function testDirectoryAtTheBundlePathIsRefused(): void
	{
		$dir = $this->seedDir();
		$notABundle = $this->root . '/bundle dir';
		mkdir($notABundle, 0o755, true);

		$this->assertSame(
			'SSL_CA_CERT_PATH=' . escapeshellarg($dir) . ' ',
			pfb_pkg_ca_env_prefix($dir, $notABundle),
			'a directory is not a bundle, however non-empty it looks'
		);
	}

	public function testRegularFileAtTheDirectoryPathIsRefused(): void
	{
		$file = $this->seedBundle();
		$notADir = $this->root . '/cert.pem';

		$this->assertSame(
			'SSL_CA_CERT_FILE=' . escapeshellarg($file) . ' ',
			pfb_pkg_ca_env_prefix($notADir, $file),
			'a regular file is not a hashed store, and CApath must be a directory'
		);
	}

	public function testNeitherLocationPresentYieldsAnEmptyPrefix(): void
	{
		$this->assertSame(
			'',
			pfb_pkg_ca_env_prefix($this->root . '/certs', $this->root . '/cert.pem'),
			'with nothing to point at, the command must be left exactly as it was'
		);
	}

	public function testEmptyLocationOptsThatHalfOut(): void
	{
		$dir = $this->seedDir();
		$file = $this->seedBundle();

		$this->assertSame(
			'SSL_CA_CERT_FILE=' . escapeshellarg($file) . ' ',
			pfb_pkg_ca_env_prefix('', $file),
			'an empty path is an opt-out, not a location to test'
		);
		$this->assertSame(
			'SSL_CA_CERT_PATH=' . escapeshellarg($dir) . ' ',
			pfb_pkg_ca_env_prefix($dir, ''),
			'an empty bundle is an opt-out, not a location to test'
		);
	}

	public function testLocationsWithShellMetacharactersAreQuoted(): void
	{
		$dir = $this->root . "/cert's dir";
		mkdir($dir, 0o755, true);
		$file = $this->root . '/cert.pem';
		file_put_contents($file, "x\n");

		$prefix = pfb_pkg_ca_env_prefix($dir, $file);

		// Expectation written out by hand rather than through escapeshellarg(), which would
		// pass for naive quoting too: a single quote must close, escape, and reopen.
		$expected = "SSL_CA_CERT_PATH='" . $this->root . "/cert'\\''s dir' "
			. "SSL_CA_CERT_FILE='" . $this->root . "/cert.pem' ";

		$this->assertSame($expected, $prefix, 'a quote in a path must be shell-escaped, not passed through');
		$this->assertStringEndsWith(' ', $prefix, 'the prefix must be splice-ready');
	}

	/**
	 * Wiring: both networked commands in pfb_pkg_latest() must carry the prefix, and it has
	 * to sit in FRONT of the timeout(1) wrapper so the assignments reach pkg itself. The
	 * local `pkg query` reads are deliberately untouched — they never open a socket.
	 */
	public function testPkgLatestSplicesThePrefixBeforeTheTimeoutWrapper(): void
	{
		$src = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		$start = strpos($src, 'function pfb_pkg_latest(');
		$this->assertNotFalse($start, 'pfb_pkg_latest() is missing');
		$end = strpos($src, "\nfunction ", $start + 1);
		$body = $end === false ? substr($src, $start) : substr($src, $start, $end - $start);

		$this->assertStringContainsString(
			'pfb_pkg_ca_env_prefix()',
			$body,
			'the catalog read must carry the CA locations'
		);
		// Inspect EVERY exec( site, not just the double-quoted ones: reading only string
		// literals would let `$cmd = "..."; exec($cmd);` route around the prefix.
		$offset = 0;
		$sites = 0;
		while (($at = strpos($body, 'exec(', $offset)) !== false) {
			$sites++;
			$this->assertStringStartsWith(
				'exec("{$ca}{$tmo}',
				substr($body, $at, 40),
				'every command pfb_pkg_latest() runs must be a literal leading with the CA prefix, found: '
					. substr($body, $at, 40)
			);
			$offset = $at + 5;
		}
		$this->assertGreaterThan(0, $sites, 'pfb_pkg_latest() must still shell out at all');
	}
}
