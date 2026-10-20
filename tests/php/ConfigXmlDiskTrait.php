<?php

declare(strict_types=1);

/**
 * issue #3515 -- config.xml as a file, for tests of what a write pfSense does not make leaves behind. write_config() copies the
 * in-memory config to $disk unless it is told to answer FALSE (a rule refused the write) or -1 (config.xml was not written),
 * and a fresh config_read_file() replaces the in-memory copy with $disk, as pfSense's own read does. A test that holds the
 * DNS config lock reads config.xml afresh, so it sees $disk, never what its own process changed and did not get written.
 *
 * The using test class unsets $GLOBALS['pfb_test_write_config_hook'], ['pfb_test_write_config_result'],
 * ['pfb_test_config_read_hook'] and ['pfb_test_config_read_calls'] when it ends.
 */
trait ConfigXmlDiskTrait
{
	/** @var array<string,mixed> config.xml as it is on disk */
	private array $disk = [];

	/** @return array<string,array{mixed}> pfSense's write_config() answers for a write it did not make: FALSE (refused), -1 (config.xml not written) */
	public static function refusedWrites(): array
	{
		return ['the write is refused' => [FALSE], 'config.xml could not be written' => [-1]];
	}

	/**
	 * Take the config as it stands as what is on disk, and from here on refuse what $answer says to.
	 *
	 * @param mixed       $answer          write_config()'s answer for a refused write (FALSE or -1); NULL = no write is refused
	 * @param string|null $refusedWrite    only a write whose description contains this is refused; NULL = every write is
	 */
	private function configXmlOnDisk(mixed $answer = NULL, ?string $refusedWrite = NULL): void
	{
		$this->disk = $GLOBALS['config'];
		$GLOBALS['pfb_test_write_config_hook'] = function (string $description) use ($answer, $refusedWrite): void {
			if ($answer !== NULL && ($refusedWrite === NULL || str_contains($description, $refusedWrite))) {
				$GLOBALS['pfb_test_write_config_result'] = $answer;
				return;
			}
			unset($GLOBALS['pfb_test_write_config_result']);
			$this->disk = $GLOBALS['config'];
		};
		$GLOBALS['pfb_test_config_read_hook'] = function (): void {
			if (end($GLOBALS['pfb_test_config_read_calls']) === [FALSE, FALSE]) {
				$GLOBALS['config'] = $this->disk;
			}
		};
	}

	/** A value in config.xml as it is on disk, $default when absent. */
	private function onDisk(string $path, mixed $default = NULL): mixed
	{
		$node = $this->disk;
		foreach (explode('/', $path) as $key) {
			if (!is_array($node) || !array_key_exists($key, $node)) {
				return $default;
			}
			$node = $node[$key];
		}
		return $node;
	}
}
