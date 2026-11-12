<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3842: Core's state directory ($pfb['core_state'], the settings store with its secrets) follows Keep Settings on
 * package removal: a keep-off removal deletes it once pfb_core is stopped; a keep-on removal leaves it for the reinstall.
 */
#[CoversFunction('pfb_core_state_teardown')]
final class PfbCoreStateTeardownTest extends TestCase
{
	private array $savedPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_state_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		file_put_contents("{$this->dir}/settings.json", '{"format":1}');
		$GLOBALS['pfb']['core_state'] = $this->dir;
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		if (is_dir($this->dir)) {
			rmdir_recursive($this->dir);
		}
	}

	public function testAKeepOffRemovalDeletesCoresState(): void
	{
		$this->assertFileExists("{$this->dir}/settings.json", 'before: the store is there');
		pfb_core_state_teardown(PfbToggle::Off);
		$this->assertDirectoryDoesNotExist($this->dir, 'keep off must delete the settings store, secrets included');
	}

	public function testAKeepOnRemovalKeepsCoresState(): void
	{
		pfb_core_state_teardown(PfbToggle::On);
		$this->assertFileExists("{$this->dir}/settings.json", 'keep on must leave the settings store for the reinstall');
	}

	public function testTheRemovalTearsTheStateDownOnlyAfterStoppingCore(): void
	{
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$start = strpos($source, 'function pfblockerng_php_pre_deinstall_command');
		$this->assertNotFalse($start);
		$end = strpos($source, "\n}\n", $start);
		$body = substr($source, $start, $end - $start);
		$stop = strpos($body, "stop_service('pfb_core');");
		$teardown = strpos($body, "pfb_core_state_teardown(\$pfb['keep']);");
		$this->assertNotFalse($stop, 'the removal stops pfb_core');
		$this->assertNotFalse($teardown, 'the removal calls pfb_core_state_teardown with Keep Settings');
		$this->assertGreaterThan($stop, $teardown, 'a running Core could write its store again after the delete');
	}
}
