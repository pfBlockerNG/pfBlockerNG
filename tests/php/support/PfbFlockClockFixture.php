<?php

declare(strict_types=1);

/** Loads reflected production function bodies with virtual microtime()/usleep(). */
final class PfbFlockClockFixture
{
	/** @var list<int> */
	public array $sleeps = [];

	/** @var array<int,self> */
	private static array $registry = [];

	private float $now = 0.0;
	private ?Closure $onSleep = NULL;

	public function setOnSleep(?Closure $onSleep): void
	{
		$this->onSleep = $onSleep;
	}

	public function microtime(bool $asFloat): string|float
	{
		return $asFloat ? $this->now : sprintf('%.8f %d', fmod($this->now, 1.0), (int) $this->now);
	}

	public function usleep(int $microseconds): void
	{
		$this->sleeps[] = $microseconds;
		$this->now += $microseconds / 1_000_000;
		if ($this->onSleep !== NULL) {
			($this->onSleep)();
		}
	}

	public static function forSlot(int $slot): self
	{
		return self::$registry[$slot];
	}

	/**
	 * @param list<string> $functions
	 * @return non-empty-string
	 */
	public function loadChain(array $functions): string
	{
		$slot = count(self::$registry);
		self::$registry[$slot] = $this;

		$namespace = 'PfbFlockClock' . bin2hex(random_bytes(6));
		$bodies = '';
		foreach ($functions as $function) {
			$reflection = new ReflectionFunction($function);
			$file = $reflection->getFileName();
			$lines = $file !== FALSE ? file($file) : FALSE;
			if ($lines === FALSE) {
				throw new RuntimeException("Could not read source for {$function}()");
			}
			$bodies .= implode('', array_slice(
				$lines,
				$reflection->getStartLine() - 1,
				$reflection->getEndLine() - $reflection->getStartLine() + 1
			)) . "\n";
		}

		eval(<<<PHP
			namespace {$namespace};

			function microtime(bool \$as_float = false) {
				return \PfbFlockClockFixture::forSlot({$slot})->microtime(\$as_float);
			}

			function usleep(int \$microseconds): void {
				\PfbFlockClockFixture::forSlot({$slot})->usleep(\$microseconds);
			}

			{$bodies}
			PHP);

		return $namespace;
	}
}
