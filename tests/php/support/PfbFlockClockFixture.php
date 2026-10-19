<?php

declare(strict_types=1);

/** Loads reflected production function bodies with virtual microtime(), hrtime() and usleep(). */
final class PfbFlockClockFixture
{
	/** @var list<int> */
	public array $sleeps = [];

	/** @var array<int,WeakReference<self>> */
	private static array $registry = [];

	/** A loop that ticks this often never reached its condition: stuck, not slow. Above the longest wait a loaded body can ask for. */
	private const MAX_TICKS = 500_000;

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

	public function hrtime(bool $asNumber): int|array
	{
		$nanoseconds = (int) round($this->now * 1_000_000_000);
		return $asNumber ? $nanoseconds : [intdiv($nanoseconds, 1_000_000_000), $nanoseconds % 1_000_000_000];
	}

	public function usleep(int $microseconds): void
	{
		if (count($this->sleeps) >= self::MAX_TICKS) {
			throw new RuntimeException('STUCK/ENVIRONMENT: the virtual clock ticked ' . self::MAX_TICKS . ' times; the awaited condition never came');
		}
		$this->sleeps[] = $microseconds;
		$this->now += $microseconds / 1_000_000;
		if ($this->onSleep !== NULL) {
			($this->onSleep)();
		}
	}

	public static function forSlot(int $slot): self
	{
		return self::$registry[$slot]->get()
			?? throw new RuntimeException('Clock fixture outlived its test');
	}

	/**
	 * @param list<string> $functions
	 * @param array<string,bool|int|float|string> $constants constants the loaded bodies see in place of the global ones
	 * @return non-empty-string
	 */
	public function loadChain(array $functions, array $constants = []): string
	{
		$slot = count(self::$registry);
		self::$registry[$slot] = WeakReference::create($this);

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

		$constantLines = '';
		foreach ($constants as $name => $value) {
			$constantLines .= "const {$name} = " . var_export($value, TRUE) . ";\n";
		}

		eval(<<<PHP
			namespace {$namespace};
			{$constantLines}

			function microtime(bool \$as_float = false) {
				return \PfbFlockClockFixture::forSlot({$slot})->microtime(\$as_float);
			}

			function usleep(int \$microseconds): void {
				\PfbFlockClockFixture::forSlot({$slot})->usleep(\$microseconds);
			}

			function hrtime(bool \$as_number = false) {
				return \PfbFlockClockFixture::forSlot({$slot})->hrtime(\$as_number);
			}

			{$bodies}
			PHP);

		return $namespace;
	}
}
