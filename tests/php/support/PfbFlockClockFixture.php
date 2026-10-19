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
	private ?Closure $onIdle = NULL;

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

	/**
	 * Answers a select that finds nothing ready: given the seconds it may wait, the seconds until the data it has just
	 * released is readable, or NULL when nothing arrives within that wait.
	 */
	public function setIdle(?Closure $onIdle): void
	{
		$this->onIdle = $onIdle;
	}

	public function now(): float
	{
		return $this->now;
	}

	/**
	 * stream_select() on the virtual clock. A stream ready now is answered by the real call, with no wait. Otherwise the idle
	 * hook decides, and the clock moves on by the seconds it returns, or by the whole wait when it returns NULL.
	 * Without a hook this is the real call.
	 */
	public function select(?array &$read, ?array &$write, ?array &$except, ?int $seconds, ?int $microseconds = 0): int|false
	{
		if ($this->onIdle === NULL) {
			return stream_select($read, $write, $except, $seconds, $microseconds);
		}
		$ready = self::pollNow($read, $write, $except);
		if ($ready !== 0) {
			return $ready;
		}
		$wait = ($seconds ?? 0) + ($microseconds ?? 0) / 1_000_000;
		$arrives = ($this->onIdle)($wait);
		if ($arrives === NULL) {
			$this->now += $wait;
			return 0;
		}
		$this->now += $arrives;
		$ready = self::pollNow($read, $write, $except);
		if ($ready !== 1) {
			throw new RuntimeException('STUCK/ENVIRONMENT: the idle hook released data that is not readable: select answered ' . var_export($ready, TRUE));
		}
		return $ready;
	}

	/** The real zero-timeout poll: the caller's arrays change only when it reports a ready stream. */
	private static function pollNow(?array &$read, ?array &$write, ?array &$except): int|false
	{
		$r = $read;
		$w = $write;
		$e = $except;
		$n = stream_select($r, $w, $e, 0, 0);
		if ($n > 0) {
			$read = $r;
			$write = $w;
			$except = $e;
		}
		return $n;
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

			function stream_select(&\$read, &\$write, &\$except, ?int \$seconds, ?int \$microseconds = 0) {
				return \PfbFlockClockFixture::forSlot({$slot})->select(\$read, \$write, \$except, \$seconds, \$microseconds);
			}

			{$bodies}
			PHP);

		return $namespace;
	}
}
