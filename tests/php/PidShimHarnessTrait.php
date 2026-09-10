<?php

declare(strict_types=1);

trait PidShimHarnessTrait
{
	/** @var list<string> Stale shim paths planted for recycled-PID tests. */
	private array $planted = [];

	abstract protected function pidShimPrefix(): string;

	protected function tearDown(): void
	{
		$this->sweepPlantedShims();
	}

	protected function sweepPlantedShims(): void
	{
		foreach ($this->planted as $path) {
			@unlink($path . '/guiconfig.inc');
			@rmdir($path);
		}
		$this->planted = [];
	}

	private function pidShimPreamble(string $mkdirError): string
	{
		$prefix = var_export('/' . $this->pidShimPrefix(), TRUE);
		$error = var_export($mkdirError . "\n", TRUE);

		return <<<PHP
\$shim = sys_get_temp_dir() . {$prefix} . getmypid() . '_' . bin2hex(random_bytes(8));
if (!mkdir(\$shim, 0700, TRUE)) {
	fwrite(STDERR, {$error});
	exit(1);
}
register_shutdown_function(static function () use (\$shim): void {
	@unlink(\$shim . '/guiconfig.inc');
	@rmdir(\$shim);
});
file_put_contents(\$shim . '/guiconfig.inc', "<?php");
set_include_path(\$shim . PATH_SEPARATOR . get_include_path());
PHP;
	}

	private function plantStaleShim(int $pid): void
	{
		$residue = sys_get_temp_dir() . '/' . $this->pidShimPrefix() . $pid;
		$this->planted[] = $residue;
		@mkdir($residue, 0777, TRUE);
		\PHPUnit\Framework\Assert::assertDirectoryExists($residue);
	}

	/** @return list<string> Shim directories owned by child PID $pid, with or without a per-invocation suffix. */
	private function shimResidue(int $pid): array
	{
		$prefix = sys_get_temp_dir() . '/' . $this->pidShimPrefix() . $pid;
		return array_merge(glob($prefix) ?: [], glob($prefix . '_*') ?: []);
	}
}
