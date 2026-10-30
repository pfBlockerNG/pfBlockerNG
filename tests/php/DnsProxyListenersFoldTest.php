<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3599 -- what pfb_dns_proxy_listeners() reads out of the gateway's log once a running gateway changes its listeners
 * (docs/specs/pfb-dns-live-listen-addresses.md, D3). A start logs `starting pid <pid>` first. The latest complete start is the
 * lines after the last such line before the last `ready upstream` line; then, in log order, the lines after that ready line up to the
 * next `starting pid` line (a start in progress) or the log's end add (`listening <kind> <host:port>`) and remove (`stopped listening
 * <kind> <host:port>`) listeners. `refused` keeps the start's own reasons. A log with no such marker (an older gateway's) is read
 * exactly as before: from the second-to-last `ready upstream` line.
 *
 * Without the marker, what a running gateway logs after its ready line falls inside the NEXT start's range: a listener added to the old
 * process would be credited to a new one that never bound it.
 */
#[CoversFunction('pfb_dns_proxy_listeners')]
final class DnsProxyListenersFoldTest extends TestCase
{
	private const READY = 'ready upstream 127.0.0.1:5353 pid 4242';

	private string $dir = '';
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		$this->savedGlobals['pfb'] = [array_key_exists('pfb', $GLOBALS), $GLOBALS['pfb'] ?? NULL];
		$this->dir = sys_get_temp_dir() . '/pfb_listeners_fold_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], ['dns_proxy_log' => "{$this->dir}/dns_proxy.log"]);
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->dir);
	}

	/** @param list<string> $lines */
	private function log(array $lines, bool $append = FALSE): void
	{
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], implode("\n", $lines) . "\n", $append ? FILE_APPEND : 0);
	}

	/**
	 * What the log says is served, as "<kind> <host:port>" in the order the parser holds them.
	 *
	 * @return list<string>|null NULL = no complete start
	 */
	private function served(?int $since = NULL, ?string $pid = NULL): ?array
	{
		$listeners = pfb_dns_proxy_listeners($since, $pid);
		if ($listeners === NULL) {
			return NULL;
		}
		$served = [];
		foreach ($listeners['listening'] as $kind => $addresses) {
			foreach (array_keys($addresses) as $at) {
				$served[] = "{$kind} {$at}";
			}
		}
		return $served;
	}

	public function testAListenerAddedAfterTheReadyLineIsServedAndOneRemovedIsNot(): void
	{
		// Given a start that listened on two addresses, a listener added after its ready line and another taken away
		$this->log([
			'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'listening udp+tcp [::1]:53', self::READY,
			'listening udp+tcp 192.0.2.1:53', 'stopped listening udp+tcp [::1]:53',
		]);

		// Then the added one is served and the removed one is not
		$this->assertSame(['udp+tcp 127.0.0.1:53', 'udp+tcp 192.0.2.1:53'], $this->served());
	}

	public function testTheLinesAfterTheReadyLineAreAppliedInOrder(): void
	{
		// Given a listener that is removed and added again, one that is added and removed, and one that is added last
		$this->log([
			'starting pid 4242', 'listening dot 127.0.0.1:853', self::READY,
			'stopped listening dot 127.0.0.1:853', 'listening dot 127.0.0.1:853',
			'listening dot 192.0.2.1:853', 'stopped listening dot 192.0.2.1:853',
			'listening dot [::1]:853',
		]);

		// Then the ones whose last line adds them are served and the one whose last line removes it is not
		$this->assertSame(['dot 127.0.0.1:853', 'dot [::1]:853'], $this->served());
	}

	public function testARemoveNamesTheKindItRemovesItFrom(): void
	{
		// Given plain DNS and DoT on the same address, and a remove of DoT's
		$this->log([
			'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'listening dot 127.0.0.1:53', self::READY,
			'stopped listening dot 127.0.0.1:53',
		]);

		// Then plain DNS is still served
		$this->assertSame(['udp+tcp 127.0.0.1:53'], $this->served());
	}

	public function testARemoveOfAListenerNeverServedChangesNothing(): void
	{
		// Given a remove for a listener that no line added
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::READY, 'stopped listening udp+tcp 192.0.2.1:53']);

		// Then it is a no-op
		$this->assertSame(['udp+tcp 127.0.0.1:53'], $this->served());
	}

	public function testAnAddressIsSpelledAsTheGatewayPrintsItWhenItIsAddedAndWhenItIsRemoved(): void
	{
		// Given an IPv6 address added in one spelling and removed in another that means the same address
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::READY, 'listening udp+tcp [2001:DB8:0:0:0:0:0:1]:53']);
		$this->assertSame(['udp+tcp 127.0.0.1:53', 'udp+tcp [2001:db8::1]:53'], $this->served(), 'before: the compressed spelling is served');
		$this->log(['stopped listening udp+tcp [2001:db8::1]:53'], TRUE);

		// Then the removal finds it
		$this->assertSame(['udp+tcp 127.0.0.1:53'], $this->served());
	}

	public function testAListenerAddedToAPreviousStartIsNotCreditedToTheNextStart(): void
	{
		// Given a start that served A and had B added after its ready line, and a later start that bound only A
		$log = [
			'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'ready upstream 127.0.0.1:5353 pid 4242', 'listening udp+tcp 192.0.2.1:53',
			'starting pid 4300', 'listening udp+tcp 127.0.0.1:53', 'ready upstream 127.0.0.1:5353 pid 4300',
		];
		$this->log($log);

		// Then the new start serves only A: B belonged to the process that is gone
		$this->assertSame(['udp+tcp 127.0.0.1:53'], $this->served());
		// and the same log with no `starting pid` lines (an older gateway's) is read as it always was: the live add is credited
		$this->log(array_values(array_filter($log, static fn (string $line): bool => !str_starts_with($line, 'starting pid '))));
		$this->assertSame(['udp+tcp 192.0.2.1:53', 'udp+tcp 127.0.0.1:53'], $this->served(), 'a log with no marker reads as before');
	}

	public function testALaterStartThatHasNotBecomeReadyIsIgnored(): void
	{
		// Given a complete start with a listener added after its ready line, and a later start that has logged some listeners and no ready line
		$this->log([
			'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::READY, 'listening udp+tcp 192.0.2.1:53',
			'starting pid 4300', 'listening udp+tcp [::1]:53', 'stopped listening udp+tcp 127.0.0.1:53',
		]);

		// Then the complete start and its own changes are what is served: the start in progress adds and removes nothing
		$this->assertSame(['udp+tcp 127.0.0.1:53', 'udp+tcp 192.0.2.1:53'], $this->served());
	}

	public function testOnlyTheLatestStartBeforeTheReadyLineIsRead(): void
	{
		// Given a start that never became ready, and a second one that did
		$this->log([
			'starting pid 4200', 'listening udp+tcp 192.0.2.1:53',
			'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'cannot listen on [::1]:53: bind: address already in use', self::READY,
		]);

		// Then the first one's listener is not the second's, and the second's refusal is its own
		$this->assertSame(['udp+tcp 127.0.0.1:53'], $this->served());
		$this->assertSame(['[::1]:53' => 'bind: address already in use'], pfb_dns_proxy_listeners()['refused'] ?? NULL);
	}

	public function testALogWithNoStartingLineIsReadAsBefore(): void
	{
		// Given an older gateway's log: two starts and no `starting pid` line, the first start's listener not in the second's
		$this->log([
			'listening udp+tcp 192.0.2.1:53', 'cannot listen on 127.0.0.1:53: bind: address already in use', 'ready upstream 127.0.0.1:5353 pid 4200',
			'listening udp+tcp 127.0.0.1:53', 'cannot listen on [::1]:53: bind: address already in use', 'ready upstream 127.0.0.1:5353 pid 4242',
		]);

		// Then only the lines after the second-to-last ready line and up to the last one count, refusals included
		$this->assertSame(['udp+tcp 127.0.0.1:53'], $this->served());
		$this->assertSame(['[::1]:53' => 'bind: address already in use'], pfb_dns_proxy_listeners()['refused'] ?? NULL);
	}

	public function testARefusalAfterTheReadyLineIsNotTheStartsReason(): void
	{
		// Given a refusal line after the ready line
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::READY, 'cannot listen on [::1]:53: bind: address already in use']);

		// Then it is no refusal of the start
		$this->assertSame([], pfb_dns_proxy_listeners()['refused'] ?? NULL);
	}

	public function testALogWithNoReadyLineHasNoCompleteStart(): void
	{
		// Given a start that has not become ready, with a live-looking line
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'listening udp+tcp 192.0.2.1:53']);

		// Then there is nothing to read
		$this->assertNull($this->served());
	}

	public function testLinesOfOtherWritersAndTrailingSpacesDoNotMatterBetweenTheChanges(): void
	{
		// Given decider lines between the changes, and trailing spaces on the change lines
		$this->log([
			'starting pid 4242', 'listening udp+tcp 127.0.0.1:53   ', self::READY,
			'decider: restarted', 'listening udp+tcp 192.0.2.1:53   ', 'pfb_dns_gateway: something', 'stopped listening udp+tcp 127.0.0.1:53  ',
		]);

		// Then the changes apply
		$this->assertSame(['udp+tcp 192.0.2.1:53'], $this->served());
	}

	public function testOnlyTheBytesAfterTheSizeTakenBeforeAStartAreItsLog(): void
	{
		// Given a previous start with a live add, and the log's size from before a new start that serves one address and gets one added
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::READY, 'listening udp+tcp 192.0.2.1:53']);
		$since = pfb_dns_proxy_log_size();
		$this->log(['starting pid 4300', 'listening udp+tcp [::1]:53', 'ready upstream 127.0.0.1:5353 pid 4300', 'listening udp+tcp 127.0.0.1:53'], TRUE);

		// Then only the new start's lines are read, its live add among them
		$this->assertSame(['udp+tcp [::1]:53', 'udp+tcp 127.0.0.1:53'], $this->served($since));
	}

	/** @return array<string,array{?string,bool}> the readiness-marker pid the panel asks for, and whether the log's latest complete start is it */
	public static function pids(): array
	{
		return [
			'the pid that logged the last ready line' => ['4300', TRUE],
			'the pid of the start before' => ['4242', FALSE],
			'a pid that merely starts with it' => ['430', FALSE],
			'a pid that is no number' => ['4300x', FALSE],
			'no pid asked for' => [NULL, TRUE],
		];
	}

	#[DataProvider('pids')]
	public function testTheReadyLinesPidIsStillMatchedWhenListenersChangedAfterIt(?string $pid, bool $read): void
	{
		// Given a log whose last ready line is pid 4300's, with a live add after it
		$this->log([
			'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'ready upstream 127.0.0.1:5353 pid 4242',
			'starting pid 4300', 'listening udp+tcp 127.0.0.1:53', 'ready upstream 127.0.0.1:5353 pid 4300', 'listening udp+tcp 192.0.2.1:53',
		]);

		// Then the panel's pid decides whether the record is its own, and a record that is gives the live add too
		$this->assertSame($read ? ['udp+tcp 127.0.0.1:53', 'udp+tcp 192.0.2.1:53'] : NULL, $this->served(NULL, $pid));
	}
}
