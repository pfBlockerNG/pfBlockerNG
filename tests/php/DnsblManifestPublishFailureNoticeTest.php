<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65: a DNSBL manifest publish failure (the atomic write pfb_unbound_python_sources()
 * performs) must surface loudly -- pfb_logger() + file_notice(), mirroring the existing
 * MaxMind/VIP credential-notice pattern (issue #331) -- never silently swallowed as it was
 * before this phase.
 *
 * Drives the REAL pfb_unbound_python_sources(array()) (the no-feeds shape, so no raw file
 * is written -- only the manifest publish itself is exercised) with 'unbound_py_sources'
 * pointed at a read-only directory, so the underlying tempnam()/fopen() genuinely fails.
 */
#[CoversFunction('pfb_unbound_python_sources')]
final class DnsblManifestPublishFailureNoticeTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('running as root -- a 0555 dir does not block tempnam()/fopen() for root');
		}

		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb_test_file_notices'] = [];

		$this->tmp = sys_get_temp_dir() . '/pfb_manifest_notice_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/db", 0777, true);
		mkdir("{$this->tmp}/readonly", 0555, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/readonly/pfb_py_sources.json",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_tld_data'     => "{$this->tmp}/does_not_exist",
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsbl_tld_wildcard' => '',
			'dnsblconfig'        => [
				'tldblacklist' => '',
				'tldexclusion' => '',
				'suppression'  => '',
			],
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		unset($GLOBALS['pfb_test_file_notices']);

		chmod("{$this->tmp}/readonly", 0755); // restore writability so cleanup can remove it
		rmdir_recursive($this->tmp);
	}

	public function testPublishFailureIntoReadOnlyDirFiresANotice(): void
	{
		pfb_unbound_python_sources(array());

		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'exactly one notice raised on publish failure');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertSame('pfBlockerNG DNSBL', $notice['id']);
		$this->assertSame('/pfblockerng/pfblockerng_dnsbl.php', $notice['url']);
		$this->assertSame(2, $notice['priority']);
		$this->assertStringContainsString('pfb_py_sources.json', $notice['notice']);
		$this->assertFileDoesNotExist(
			"{$this->tmp}/readonly/pfb_py_sources.json",
			'the manifest must not appear to have published'
		);
	}

	public function testPublishSuccessFiresNoNotice(): void
	{
		// Contrast/vacuity pairing: the same call against a WRITABLE manifest path
		// must raise nothing.
		$GLOBALS['pfb']['unbound_py_sources'] = "{$this->tmp}/pfb_py_sources.json";

		pfb_unbound_python_sources(array());

		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'no notice on a successful publish');
		$this->assertFileExists("{$this->tmp}/pfb_py_sources.json");
	}
}
