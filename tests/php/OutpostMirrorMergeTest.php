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
#[CoversFunction('pfb_outpost_ip_member_valid')]
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
			// the Outpost checks that pf reads a line as one entry, not its spelling: that is Core's (decision on #4037)
			'upper-case hexadecimal'          => ['ipv6', "2001:DB8::A\n"],
			'mixed-case hexadecimal'          => ['ipv6', "2001:Db8::aB/64\n"],
			'an uncompressed IPv6 address'    => ['ipv6', "2001:db8:0:0:0:0:0:b\n"],
			'IPv6 with every zero written'    => ['ipv6', "0000:0000:0000:0000:0000:0000:0000:0001\n"],
			'IPv6 with a dotted IPv4 tail'    => ['ipv6', "0:0:0:0:0:ffff:1.2.3.4/128\n::ffff:1.2.3.4\n"],
			'the unspecified address'         => ['ipv6', "::\n::/0\n::1/128\n"],
			'IPv4 prefixes of every width'    => ['ipv4', "0.0.0.0/0\n1.2.3.4/32\n10.0.0.0/8\n"],
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
			'a leading zero in the first one' => ['ipv4', "010.1.1.1\n"],
			'a host name that looks like one' => ['ipv4', "pfbipset-nx.invalid\n"],
			'an IPv4 prefix of 33'            => ['ipv4', "1.2.3.4/33\n"],
			'a signed prefix of 8'            => ['ipv4', "1.0.0.0/+8\n"],
			'a trailing space'                => ['ipv4', "1.2.3.4 \n"],
			'a prefix with a trailing space'  => ['ipv4', "1.2.3.0/24 \n"],
			'two slashes'                     => ['ipv4', "1.2.3.0/24/8\n"],
			'a hexadecimal prefix'            => ['ipv6', "2001:db8::/a\n"],
			'an IPv6 prefix of 129'           => ['ipv6', "::1/129\n"],
			'an IPv6 prefix with a zero'      => ['ipv6', "2001:db8::/032\n"],
			'five hexadecimal digits'         => ['ipv6', "2001:0db80::1\n"],
			'two compressed runs'             => ['ipv6', "2001::db8::1\n"],
			'a last valid line with no newline' => ['ipv4', "1.2.3.4\n5.6.7.89"],
			'a prefix over 32'                => ['ipv4', "1.2.3.0/33\n"],
			'a prefix with a leading zero'    => ['ipv4', "1.2.3.0/024\n"],
			'a signed prefix'                 => ['ipv4', "1.2.3.0/+24\n"],
			'an empty prefix'                 => ['ipv4', "1.2.3.0/\n"],
			'a netmask prefix'                => ['ipv4', "1.2.3.0/255.255.255.0\n"],
			'a prefix with a trailing dot'    => ['ipv4', "1.2.3.0/24.\n"],
			'a prefix that is a fraction'     => ['ipv6', "::/.5\n"],
			'an IPv6 member in an IPv4 set'   => ['ipv4', "2001:db8::1\n"],
			'an IPv4 member in an IPv6 set'   => ['ipv6', "1.2.3.4\n"],
			'a zone'                          => ['ipv6', "fe80::1%em0\n"],
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

	/**
	 * A member of an IP set is read at most 64 bytes and its line feed at a time. No address or prefix the rule takes is longer
	 * than 49 bytes ("0000:0000:0000:0000:0000:ffff:255.255.255.255/128"), so a longer line is refused as too long, never read
	 * on as the start of another (review of slice 8c, L9).
	 */
	public function testAnIPLineOfSixtyFiveBytesIsRefusedAsLongerThanAMember(): void
	{
		$line = '0000:0000:0000:0000:0000:ffff:255.255.255.255/128';
		$this->assertSame(['entries' => 1, 'error' => NULL], pfb_outpost_part_check($this->file('part', "{$line}\n"), 'ipv6'));

		$long = pfb_outpost_part_check($this->file('part', str_repeat('0', 16) . "{$line}\n"), 'ipv6');
		$this->assertSame(65, 16 + strlen($line));
		$this->assertStringContainsString('line 1 is longer than a member', (string) $long['error']);

		$this->assertStringContainsString('line 1 is not a member',
			(string) pfb_outpost_part_check($this->file('part', str_repeat('0', 15) . "{$line}\n"), 'ipv6')['error']);
	}

	/**
	 * Each line of the IP set parity corpus (go/pfb_core/ipset/testdata/ipset.json) that today's pipeline leaves in a set it
	 * would publish, with why the Outpost refuses it: none of these is one address or one prefix of its set's family. Every
	 * other line of those lists is taken. A line is listed as "<family> <line>".
	 */
	private const CORPUS_REFUSED = [
		'ipv4 '                         => 'an empty line',
		'ipv4    '                      => 'white space only',
		"ipv4 \t1.1.1.1"                => 'a leading tab',
		'ipv4  1.1.1.1'                 => 'a leading space',
		'ipv4 1.1.1.1 '                 => 'a trailing space',
		"ipv4 1.1.1.1\r"                => 'a carriage return',
		"ipv4 1.1.1.2\r"                => 'a carriage return',
		"ipv4 2.2.2.2\r"                => 'a carriage return',
		'ipv4 1.1.1.12.2.2.2'           => 'two addresses welded by a missing line feed',
		'ipv4 2.2.2.23.3.3.3'           => 'two addresses welded by a missing line feed',
		'ipv4 #'                        => 'the placeholder of an empty set',
		'ipv4 # c'                      => 'a comment',
		'ipv4  # not a comment'         => 'a comment after a space',
		'ipv4 1.1.1.1 tail'             => 'trailing text',
		'ipv4 1.2.3.7 tail'             => 'trailing text',
		'ipv4 foo 1.2.3.5'              => 'leading text',
		'ipv4 010.1.1.1'                => 'a leading zero in an octet, which inet_pton refuses',
		'ipv4 010.9.9.9'                => 'a leading zero in an octet, which inet_pton refuses',
		'ipv4 1.2.3.4/33'               => 'a prefix longer than 32',
		'ipv4 1.2.3.9/33'               => 'a prefix longer than 32',
		'ipv4 1.2.3.0/255.255.255.0'    => 'a netmask in place of a prefix length',
		'ipv4 1.2.3.4-1.2.3.9'          => 'a range',
		'ipv4 192.0.2.1-192.0.2.9'      => 'a range',
		'ipv4 5.5.5.1-5.5.5.9'          => 'a range',
		'ipv4 name.invalid'             => 'a host name',
		'ipv4 name.invalid/24'          => 'a host name with a prefix',
		'ipv4 pfbipset-nx.invalid'      => 'a host name',
		'ipv4 ::ffff:1.2.3.8'           => 'an IPv6 address in an IPv4 set',
		'ipv4 2001:db8::/32'            => 'an IPv6 prefix in an IPv4 set',
		'ipv4 2001:db9::5'              => 'an IPv6 address in an IPv4 set',
		'ipv6 pfbipset-nx.invalid'      => 'a host name',
		'ipv6 fe80::1%em0'              => 'a zone',
		'ipv6 ::1/129'                  => 'a prefix longer than 128',
		'ipv6 2001:db9::2 tail'         => 'trailing text',
		'ipv6 x 2001:db9::3'            => 'leading text',
		'ipv6 1.2.3.4'                  => 'an IPv4 address in an IPv6 set',
		'ipv6 127.1.7.7'                => 'an IPv4 address in an IPv6 set',
		'ipv6 203.0.113.1'              => 'an IPv4 address in an IPv6 set',
		'ipv6 203.0.113.2'              => 'an IPv4 address in an IPv6 set',
		'ipv6 203.0.113.3'              => 'an IPv4 address in an IPv6 set',
		'ipv6 203.0.113.4'              => 'an IPv4 address in an IPv6 set',
	];

	/**
	 * Every line the corpus records in a list that is a set's content: the member files of the per-feed steps (cidr_aggregate,
	 * preprocess, suppress), the deny files (recompute, pmax, closing, and the pipeline's deny_final), the canonical sets
	 * (canonical, and the pipeline's canonical), the union's aggregate and consumer files (and the pipeline's), and the DNSBLIP
	 * content. Bookkeeping lists (master, mastercat, counts, match, kept, sources, logs) are not sets, and a list recorded only by
	 * its digest has no lines. A file named *_v4 or *_v6, or a pipeline union by the files it kept, gives the family; else the case.
	 *
	 * @return array<string, array{string, string}> per "<family> <line>", once
	 */
	public static function corpusSetLines(): array
	{
		$corpus = json_decode((string) file_get_contents(__DIR__ . '/../../go/pfb_core/ipset/testdata/ipset.json'), TRUE, 64, JSON_THROW_ON_ERROR);
		$rows = [];
		$family = static fn (string $name, string $case): string => preg_match('/_v([46])(?:\.txt)?$/D', $name, $m) === 1 ? "ipv{$m[1]}" : 'ip' . $case;
		$add = static function (mixed $list, string $f) use (&$rows): void {
			if (is_array($list) && array_is_list($list)) {
				foreach ($list as $line) {
					$rows["{$f} {$line}"] = [$line, $f];
				}
			}
		};
		foreach ($corpus['cases'] as $case) {
			$e = $case['expect'];
			$f = $family('', $case['family']);
			match ($case['op']) {
				'canonical'                                 => $add($e['set'], $f),
				'cidr_aggregate', 'preprocess', 'suppress'  => $add($e['members'] ?? NULL, $f),
				'union'                                     => [$add($e['aggregate'], $f), $add($e['consumer'], $f)],
				'dnsblip'                                   => $add($e['content'], $f),
				'recompute', 'pmax', 'closing'              => array_map(static fn (string $file, mixed $l) => $add($l, $family($file, $case['family'])),
					array_keys($e['deny'] ?? []), array_values($e['deny'] ?? [])),
				'pipeline'                                  => array_map(static function (array $pass) use ($add, $family, $case): void {
					foreach (['canonical', 'deny_final'] as $k) {
						foreach ($pass[$k] ?? [] as $file => $l) {
							$add($l, $family((string) $file, $case['family']));
						}
					}
					foreach ($pass['aggregate'] ?? [] as $union) {
						$uf = $family((string) ($union['kept'][0] ?? ''), $case['family']);
						$add($union['aggregate'], $uf);
						$add($union['consumer'], $uf);
					}
				}, $e['passes']),
				default                                     => NULL,
			};
		}
		ksort($rows, SORT_STRING);
		return $rows;
	}

	/** The Outpost takes every line of the corpus that pf reads as one entry of its set's family, and only those (L1). */
	#[DataProvider('corpusSetLines')]
	public function testACorpusLineIsTakenExactlyWhenItIsOneAddressOrPrefix(string $line, string $family): void
	{
		$refused = self::CORPUS_REFUSED["{$family} {$line}"] ?? NULL;
		$this->assertSame($refused === NULL, pfb_outpost_ip_member_valid($line, $family),
			$refused === NULL ? 'a line that is one address or prefix was refused' : "a line was taken although it is {$refused}");
	}

	public function testEveryRefusedLineOfTheListIsALineOfTheCorpus(): void
	{
		$rows = self::corpusSetLines();
		$this->assertSame([], array_values(array_diff(array_keys(self::CORPUS_REFUSED), array_keys($rows))),
			'the list names a line the corpus no longer holds');
		$this->assertGreaterThan(800, count($rows), 'the corpus walk found fewer set lines than the corpus holds');
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
