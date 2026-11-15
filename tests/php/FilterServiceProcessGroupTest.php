<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Executes the generated start body with owned endpoints, never the appliance service. */
final class FilterServiceProcessGroupTest extends TestCase
{
	public static function readers(): array
	{
		return ['tail' => ['tail_pfb'], 'clog' => ['clog_pfb']];
	}

	#[DataProvider('readers')]
	public function testReaderAndPhpLeaveTheUpdateProcessGroup(string $reader): void
	{
		$this->assertTrue(function_exists('posix_getpgrp'), 'PGID proof requires the POSIX extension');
		$this->assertTrue(is_executable('/usr/bin/setsid'), 'the Linux daemon stand-in requires setsid');
		$dir = sys_get_temp_dir() . '/pfb_filter_group_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($dir, 0700));
		$originalPfb = $GLOBALS['pfb'];
		$originalRc = $GLOBALS['pfb_test_rcfiles'] ?? [];
		$originalWrites = $GLOBALS['pfb_test_rcfile_writes'] ?? [];
		$proc = NULL;
		try {
			$write = static function (string $name, string $body) use ($dir): string {
				$path = "{$dir}/{$name}";
				file_put_contents($path, $body);
				chmod($path, 0755);
				return $path;
			};
			$noop = $write('noop', "#!/bin/sh\nexit 0\n");
			$enabled = $write('enabled', "#!/bin/sh\nprintf on\n");
			$daemon = $write('daemon', "#!/bin/sh\n[ \"\$1\" = '-f' ] && shift\nexec /usr/bin/setsid \"\$@\"\n");
			// Both ends report their own PGID; a token proves the generated pipe still connects them.
			$endpoint = <<<'PHP'
#!/PHP_BINARY
<?php
$dir = __DIR__;
$role = basename(__FILE__) === 'php_pfb' ? 'php' : 'reader';
file_put_contents("$dir/$role.pgid", (string) posix_getpgrp());
if ($role === 'reader') {
	fwrite(STDOUT, "owned-filter-record\n");
	fflush(STDOUT);
} else {
	file_put_contents("$dir/record", (string) fgets(STDIN));
}
$deadline = microtime(TRUE) + 10;
while (!is_file("$dir/release") && microtime(TRUE) < $deadline) {
	usleep(10000);
}
file_put_contents("$dir/$role.done", 'done');
PHP;
			$endpoint = str_replace('#!/PHP_BINARY', '#!' . PHP_BINARY, $endpoint);
			$readerPath = $write($reader, $endpoint);
			$phpPath = $write('php_pfb', $endpoint);
			touch("{$dir}/filter.log");
			$GLOBALS['pfb']['daemon'] = $daemon;
			pfb_filter_service();
			$this->assertArrayHasKey('pfb_filter.sh', $GLOBALS['pfb_test_rcfiles']);
			$start = $GLOBALS['pfb_test_rcfiles']['pfb_filter.sh']['start'];
			// Substitute platform endpoints only: leave the generated launch/pipeline syntax intact.
			$start = strtr($start, [
				'/usr/local/sbin/read_xml_tag.sh' => $enabled,
				'/usr/local/sbin/clog_pfb' => $reader === 'clog_pfb' ? $readerPath : "{$dir}/absent-clog",
				'/usr/bin/tail_pfb' => $readerPath,
				'/usr/local/bin/php_pfb' => $phpPath,
				'/usr/local/bin' => $dir,
				'/usr/bin/stat' => $noop,
				'/usr/bin/logger' => $noop,
				'/usr/sbin/daemon' => $daemon,
				'/var/log/filter.log' => "{$dir}/filter.log",
				'/var/log/pfblockerng/dnsbl.log' => "{$dir}/dnsbl.log",
				'/var/log/pfblockerng/dns_reply.log' => "{$dir}/dns_reply.log",
			]);
			$script = $write('start', "#!/bin/bash\nrc_stop() { :; }\n{$start}\n");
			$proc = proc_open(['/bin/bash', $script], [
				0 => ['file', '/dev/null', 'r'],
				1 => ['file', "{$dir}/stdout", 'w'],
				2 => ['file', "{$dir}/stderr", 'w'],
			], $pipes);
			$this->assertIsResource($proc);
			$this->assertTrue($this->awaitFiles($dir, ['reader.pgid', 'php.pgid', 'record']),
				'the generated start must execute both controlled endpoints: ' . (string) @file_get_contents("{$dir}/stderr"));
			foreach (['reader', 'php'] as $role) {
				$this->assertNotSame(posix_getpgrp(), (int) file_get_contents("{$dir}/{$role}.pgid"),
					"{$reader}: {$role} must escape the Update caller process group");
			}
			$this->assertSame(file_get_contents("{$dir}/reader.pgid"), file_get_contents("{$dir}/php.pgid"),
				'the reader and PHP must belong to one detached service process group');
			$this->assertSame("owned-filter-record\n", file_get_contents("{$dir}/record"),
				'the detached pipeline must preserve reader-to-PHP input');
		} finally {
			touch("{$dir}/release");
			$this->awaitFiles($dir, ['reader.done', 'php.done']);
			if (is_resource($proc)) {
				proc_close($proc);
			}
			$GLOBALS['pfb'] = $originalPfb;
			$GLOBALS['pfb_test_rcfiles'] = $originalRc;
			$GLOBALS['pfb_test_rcfile_writes'] = $originalWrites;
			rmdir_recursive($dir);
		}
	}

	private function awaitFiles(string $dir, array $names): bool
	{
		$deadline = microtime(TRUE) + 5;
		do {
			clearstatcache();
			$ready = TRUE;
			foreach ($names as $name) {
				$ready = $ready && is_file("{$dir}/{$name}") && filesize("{$dir}/{$name}") > 0;
			}
			if ($ready) {
				return TRUE;
			}
			usleep(10000);
		} while (microtime(TRUE) < $deadline);
		return FALSE;
	}
}
