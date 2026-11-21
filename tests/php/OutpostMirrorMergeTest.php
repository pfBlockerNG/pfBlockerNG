<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4037 (slice 8c): what the Outpost apply does with the files a fetch wrote, before anything reaches pfctl. Each part is
 * checked line by line against the member rule of its resource and the canonical order (docs/misc/core-api-protocol.md
 * "Body and digest"); a delta becomes the new mirror by one streaming pass over the old mirror and the remove and add parts,
 * never holding the members in a PHP array; the digest of the result is the xxh128 Go's resource store computes.
 */
#[CoversFunction('pfb_outpost_part_check')]
#[CoversFunction('pfb_outpost_mirror_merge')]
#[CoversFunction('pfb_content_hash')]
final class OutpostMirrorMergeTest extends TestCase
{
	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfbmerge' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	private function file(string $name, string $body): string
	{
		$path = "{$this->dir}/{$name}";
		file_put_contents($path, $body);
		return $path;
	}

	/** @return array<string, array{?string, string}> */
	public static function acceptedParts(): array
	{
		return [
			'IPv4 addresses and CIDRs'        => ['ipv4', "0.0.0.0/0\n1.2.3.4\n1.2.3.4/32\n10.0.0.0/8\n255.255.255.255\n"],
			'IPv6 addresses and CIDRs'        => ['ipv6', "2001:db8::/32\n2001:db8::1\n::127.1.7.7\n::ffff:1.2.3.4\nfe80::/10\n"],
			'the longest IPv6 member'         => ['ipv6', "1111:2222:3333:4444:5555:6666:7777:8888/128\n"],
			'an empty part'                   => ['ipv4', ''],
			'JSON Lines of another resource'  => [NULL, "{\"cc\":\"AD\"}\n{\"cc\":\"AE\"}\n"],
			'a UTF-8 domain'                  => [NULL, "b\u{fc}cher.example\n"],
		];
	}

	#[DataProvider('acceptedParts')]
	public function testAPartOfMembersInCanonicalOrderIsAcceptedAndCounted(?string $family, string $body): void
	{
		$this->assertSame(['entries' => substr_count($body, "\n"), 'error' => NULL],
			pfb_outpost_part_check($this->file('part', $body), $family));
	}

	/** @return array<string, array{?string, string}> */
	public static function refusedParts(): array
	{
		return [
			'an IPv4 range'                   => ['ipv4', "1.2.3.4-1.2.3.9\n"],
			'a host name'                     => ['ipv4', "example.com\n"],
			'a comment'                       => ['ipv4', "# deny\n"],
			'a trailing comment'              => ['ipv4', "1.2.3.4 # deny\n"],
			'a blank line'                    => ['ipv4', "1.2.3.4\n\n"],
			'white space around a member'     => ['ipv4', " 1.2.3.4\n"],
			'a carriage return'               => ['ipv4', "1.2.3.4\r\n"],
			'a NUL'                           => ['ipv4', "1.2.3.4\x00\n"],
			'a leading zero in an octet'      => ['ipv4', "1.2.3.04\n"],
			'a prefix over 32'                => ['ipv4', "1.2.3.0/33\n"],
			'a prefix with a leading zero'    => ['ipv4', "1.2.3.0/024\n"],
			'a signed prefix'                 => ['ipv4', "1.2.3.0/+24\n"],
			'an empty prefix'                 => ['ipv4', "1.2.3.0/\n"],
			'a netmask prefix'                => ['ipv4', "1.2.3.0/255.255.255.0\n"],
			'an IPv6 member in an IPv4 set'   => ['ipv4', "2001:db8::1\n"],
			'an IPv4 member in an IPv6 set'   => ['ipv6', "1.2.3.4\n"],
			'a zone'                          => ['ipv6', "fe80::1%em0\n"],
			'upper-case hexadecimal'          => ['ipv6', "2001:DB8::1\n"],
			'an uncompressed IPv6 address'    => ['ipv6', "2001:db8:0:0:0:0:0:1\n"],
			'a prefix over 128'               => ['ipv6', "2001:db8::/129\n"],
			'a last line with no newline'     => ['ipv4', "1.2.3.4\n5.6.7.8"],
			'a line longer than any member'   => ['ipv4', str_repeat('1', 4096) . "\n"],
			'not sorted'                      => ['ipv4', "5.6.7.8\n1.2.3.4\n"],
			'a duplicate'                     => ['ipv4', "1.2.3.4\n1.2.3.4\n"],
			'an empty member of another kind' => [NULL, "\n"],
			'a # line of another kind'        => [NULL, "#x\n"],
			'a control character'             => [NULL, "a\x7fb\n"],
			'a C1 control character'          => [NULL, "a\u{85}b\n"],
			'invalid UTF-8'                   => [NULL, "a\xffb\n"],
			'unsorted lines of another kind'  => [NULL, "b\na\n"],
		];
	}

	#[DataProvider('refusedParts')]
	public function testAPartWithOneLineThatIsNotACanonicalMemberIsRefusedWhole(?string $family, string $body): void
	{
		$checked = pfb_outpost_part_check($this->file('part', $body), $family);

		$this->assertIsString($checked['error'], 'the part was accepted: ' . json_encode($checked));
		$this->assertNotSame('', $checked['error']);
	}

	public function testAMissingPartIsRefused(): void
	{
		$this->assertIsString(pfb_outpost_part_check("{$this->dir}/none", 'ipv4')['error']);
	}

	public function testTheMergeRemovesThenAddsInOneSortedPass(): void
	{
		$out = "{$this->dir}/out";
		$merged = pfb_outpost_mirror_merge($this->file('mirror', "1.1.1.1\n10.0.0.0/8\n192.0.2.7\n"), $this->file('remove', "1.1.1.1\n192.0.2.7\n"),
			$this->file('add', "0.0.0.1\n172.16.0.0/12\n9.9.9.9\n"), $out);

		$this->assertSame(['entries' => 4, 'error' => NULL], $merged);
		$this->assertSame("0.0.0.1\n10.0.0.0/8\n172.16.0.0/12\n9.9.9.9\n", file_get_contents($out));
	}

	/** @return array<string, array{string, string, string, string}> */
	public static function edgeMerges(): array
	{
		return [
			'into an empty mirror'           => ['', '', "1.1.1.1\n2.2.2.2\n", "1.1.1.1\n2.2.2.2\n"],
			'every member removed'           => ["1.1.1.1\n2.2.2.2\n", "1.1.1.1\n2.2.2.2\n", '', ''],
			'nothing changes'                => ["1.1.1.1\n", '', '', "1.1.1.1\n"],
			'adds after the last member'     => ["1.1.1.1\n", '', "8.8.8.8\n9.9.9.9\n", "1.1.1.1\n8.8.8.8\n9.9.9.9\n"],
			'a member removed and added back' => ["1.1.1.1\n", "1.1.1.1\n", "1.1.1.1\n", "1.1.1.1\n"],
		];
	}

	#[DataProvider('edgeMerges')]
	public function testTheMergeHandlesTheEdgesOfItsInputs(string $mirror, string $remove, string $add, string $expected): void
	{
		$out = "{$this->dir}/out";
		$merged = pfb_outpost_mirror_merge($this->file('mirror', $mirror), $this->file('remove', $remove), $this->file('add', $add), $out);

		$this->assertSame(['entries' => substr_count($expected, "\n"), 'error' => NULL], $merged);
		$this->assertSame($expected, file_get_contents($out));
	}

	/** @return array<string, array{string, string, string}> */
	public static function stoppedMerges(): array
	{
		return [
			'remove names a member the mirror lacks'     => ["1.1.1.1\n", "2.2.2.2\n", ''],
			'remove names one after the last member'     => ["1.1.1.1\n", "1.1.1.1\n9.9.9.9\n", ''],
			'add names a member the mirror already has'  => ["1.1.1.1\n2.2.2.2\n", '', "2.2.2.2\n"],
			'the mirror is not sorted'                   => ["2.2.2.2\n1.1.1.1\n", '', "3.3.3.3\n"],
			'the mirror has a duplicate'                 => ["1.1.1.1\n1.1.1.1\n", '', ''],
			'the mirror ends without a newline'          => ["1.1.1.1\n2.2.2.2", '', ''],
		];
	}

	#[DataProvider('stoppedMerges')]
	public function testAMergeThatCannotBeRightStopsAndLeavesNoResult(string $mirror, string $remove, string $add): void
	{
		$out = "{$this->dir}/out";
		$merged = pfb_outpost_mirror_merge($this->file('mirror', $mirror), $this->file('remove', $remove), $this->file('add', $add), $out);

		$this->assertIsString($merged['error'], 'the merge went through: ' . json_encode($merged));
		$this->assertFileDoesNotExist($out, 'a stopped merge left its result behind');
		$this->assertSame($mirror, file_get_contents("{$this->dir}/mirror"), 'the merge changed its input mirror');
	}

	public function testAMergeWhoseInputIsMissingStops(): void
	{
		$out = "{$this->dir}/out";
		$merged = pfb_outpost_mirror_merge("{$this->dir}/none", $this->file('remove', ''), $this->file('add', ''), $out);

		$this->assertIsString($merged['error']);
		$this->assertFileDoesNotExist($out);
	}

	/** @return array<string, array{string, string}> */
	public static function goDigests(): array
	{
		// pairs Go's tests pin for xxh128, the store's digest (go/pfb_core/resources/store.go openVerified)
		return [
			'go/pfb_core/internal/digest/digest_test.go' => ["a.example.com\nb.example.com\n", 'd615a18420594aec571c642da94065c4'],
			'go/pfb_core/feedfetch/digest_test.go same'  => ["same\n", '7e1402559176eb98e66aa82c39de3587'],
			'go/pfb_core/feedfetch/digest_test.go new'   => ["new\n", '07baf267a0c0ef53ec95a82711cc4758'],
		];
	}

	#[DataProvider('goDigests')]
	public function testTheDigestOfACanonicalBodyIsTheOneGoComputes(string $body, string $digest): void
	{
		$this->assertSame($digest, pfb_content_hash($this->file('body', $body)));
	}

	public function testAMergedMirrorHasTheDigestGoComputesForTheSameBody(): void
	{
		$out = "{$this->dir}/out";
		pfb_outpost_mirror_merge($this->file('mirror', "a.example.com\n"), $this->file('remove', ''), $this->file('add', "b.example.com\n"), $out);
		$this->assertSame('d615a18420594aec571c642da94065c4', pfb_content_hash($out));

		pfb_outpost_mirror_merge($this->file('mirror', "new\nsame\n"), $this->file('remove', "new\n"), $this->file('add', ''), $out);
		$this->assertSame('7e1402559176eb98e66aa82c39de3587', pfb_content_hash($out));
	}

	/**
	 * Run $code in a child PHP that loads the package as the suite does, then caps its memory at what it holds plus
	 * $headroom bytes: a list of the members would not fit under that cap.
	 *
	 * @return array{stdout: string, stderr: string, exit: int, termsig: int}
	 */
	private function underMemoryCap(string $code, int $headroom): array
	{
		$worker = "{$this->dir}/worker.php";
		file_put_contents($worker, "<?php\nrequire " . var_export(__DIR__ . '/bootstrap.php', TRUE) . ";\n"
			. "ini_set('memory_limit', (string) (memory_get_usage() + {$headroom}));\nmemory_reset_peak_usage();\n\$base = memory_get_usage();\n"
			. $code);
		return pfb_test_finish_process(pfb_test_start_process([PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'display_errors=stderr', $worker]), 300.0);
	}

	public function testTwoHundredThousandMembersMergeUnderAMemoryCapThatTheirListWouldExceed(): void
	{
		$members = [];
		for ($i = 0; $i < 200_000; $i++) {
			$members[] = sprintf('10.%d.%d.%d', $i >> 16, ($i >> 8) & 255, $i & 255);
		}
		sort($members, SORT_STRING);
		$remove = array_values(array_filter($members, static fn (int $k): bool => $k % 100 === 0, ARRAY_FILTER_USE_KEY));
		$add = [];
		for ($i = 0; $i < 1_000; $i++) {
			$add[] = sprintf('11.0.%d.%d', $i >> 8, $i & 255);
		}
		sort($add, SORT_STRING);
		$expected = array_merge(array_diff($members, $remove), $add);
		sort($expected, SORT_STRING);
		$lines = static fn (array $list): string => $list === [] ? '' : implode("\n", $list) . "\n";
		$mirror = $this->file('mirror', $lines($members));
		$removeFile = $this->file('remove', $lines($remove));
		$addFile = $this->file('add', $lines($add));
		$want = hash('xxh128', $lines($expected));
		unset($members, $remove, $add, $expected);
		$headroom = 8 << 20;

		// the cap bites: the same child cannot hold the mirror's members as a list
		$control = $this->underMemoryCap('$m = file(' . var_export($mirror, TRUE) . ", FILE_IGNORE_NEW_LINES);\necho count(\$m);\n", $headroom);
		$this->assertNotSame(0, $control['exit'], "the list of members fit under the cap, so the cap proves nothing: {$control['stdout']}");
		$this->assertStringContainsString('Allowed memory size', $control['stderr']);

		$run = $this->underMemoryCap('$t = hrtime(TRUE);' . "\n"
			. '$r = pfb_outpost_mirror_merge(' . implode(', ', array_map(static fn (string $p): string => var_export($p, TRUE),
				[$mirror, $removeFile, $addFile, "{$this->dir}/out"])) . ");\n"
			. 'echo json_encode($r + ["digest" => pfb_content_hash(' . var_export("{$this->dir}/out", TRUE) . '), "peak" => memory_get_peak_usage() - $base,'
			. ' "seconds" => (hrtime(TRUE) - $t) / 1e9]);' . "\n", $headroom);
		$this->assertSame(0, $run['exit'], "the merge did not finish under the cap: {$run['stderr']}");
		$this->assertSame('', $run['stderr']);
		$merged = json_decode($run['stdout'], TRUE, 4, JSON_THROW_ON_ERROR);
		fwrite(STDERR, sprintf("\n200,000-member merge: %.3f s, peak %d bytes above the loaded package\n", $merged['seconds'], $merged['peak']));
		$this->assertSame([NULL, 199_000, $want], [$merged['error'], $merged['entries'], $merged['digest']]);
	}
}
