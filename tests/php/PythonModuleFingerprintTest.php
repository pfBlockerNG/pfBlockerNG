<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3125 -- the python code fingerprint: pfb_unbound_py_module_fingerprint() digests the shipped module pair (md5
 * concat, pfb_unbound.py first, no separator), which the DNS proxy's decider record compares (pfb_dns_proxy_decider_changed()).
 * The PARITY_FP literal is pinned identically in tests/test_module_fingerprint.py; a digest-recipe change in either language
 * fails one of the two pins.
 */
final class PythonModuleFingerprintTest extends TestCase
{
	private const PARITY_FP = '0cc175b9c0f1b6a831c399e269772661'
		. '92eb5ffee6ae2fec3ad71c777531578f';
	private const EMPTY_FP = 'd41d8cd98f00b204e9800998ecf8427e'
		. 'd41d8cd98f00b204e9800998ecf8427e';

	private string $tmp;
	/** @var list<string> the module pair, in the digest's order */
	private array $pair = [];

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_py_module_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$this->pair = ["{$this->tmp}/pfb_unbound.py", "{$this->tmp}/pfb_dnsbl_regex_rules.py"];
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmp);
	}

	private function shipFiles(string $a = 'a', string $b = 'b'): void
	{
		file_put_contents($this->pair[0], $a);
		file_put_contents($this->pair[1], $b);
	}

	public function testFingerprintTwoFilesMatchesParityLiteral(): void
	{
		// for file bytes "a" and "b" the digest is the cross-language constant.
		$this->shipFiles();
		$this->assertSame(self::PARITY_FP, pfb_unbound_py_module_fingerprint($this->pair));
	}

	public function testFingerprintUnreadableOrMissingPathIsFalse(): void
	{
		// any unreadable member poisons the whole fingerprint -> FALSE, so an
		// unreadable shipped file never fakes a restart signal. The missing-path
		// shape runs under every uid; the chmod'd shape only when permissions bite.
		$this->shipFiles();
		$missing = "{$this->tmp}/absent.py";
		$this->assertFalse(pfb_unbound_py_module_fingerprint([$missing, $this->pair[1]]));

		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			return;
		}
		$locked = "{$this->tmp}/locked.py";
		file_put_contents($locked, 'secret');
		chmod($locked, 0000);
		try {
			$this->assertFalse(pfb_unbound_py_module_fingerprint([$locked, $this->pair[1]]));
		} finally {
			chmod($locked, 0644);
		}
	}

	public function testEmptiedShippedFilesStillFingerprintAsString(): void
	{
		// Hostile: emptied shipped files fingerprint to the md5-of-empty
		// pair -- still a string, still compares normally, no special case.
		$this->shipFiles('', '');
		$this->assertSame(self::EMPTY_FP, pfb_unbound_py_module_fingerprint($this->pair));
	}
}
