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
 *
 * A log cut by the read limit inside its latest start, with the start's beginning (its `starting pid` line, or a second `ready upstream`
 * line) out of the read, is flagged `partial`: its listeners may be missing from what is read. The read grows from 64 KiB until it holds
 * the beginning. pfb_dns_proxy_host_port() spells an IPv4-mapped IPv6 address as the IPv4 address, as the gateway logs it.
 */
#[CoversFunction('pfb_dns_proxy_listeners')]
#[CoversFunction('pfb_dns_proxy_log_lines')]
#[CoversFunction('pfb_dns_proxy_host_port')]
final class DnsProxyListenersFoldTest extends TestCase
{
	private const READY = 'ready upstream 127.0.0.1:5353 pid 4242';
	/** The gateway log's read limit: a start whose beginning is further back is not judged. */
	private const READ_LIMIT = PFB_DNS_PROXY_LOG_READ_MAX;

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

	public function testAStoppedLineBeforeTheReadyLineIsNotApplied(): void
	{
		// Given a start whose log has a `stopped listening` line for a listener it reported, before its ready line
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', 'listening udp+tcp [::1]:53', 'stopped listening udp+tcp 127.0.0.1:53', self::READY]);

		// Then the start's own report stands: only a line after the ready line removes a listener
		$this->assertSame(['udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53'], $this->served());
	}

	/** @return list<string> lines of another writer: 70,000 bytes, more than the 64 KiB the log is read within */
	private static function filler(): array
	{
		return array_fill(0, 700, str_repeat('f', 99));
	}

	/** Other output the gateway logs: $bytes of it, as lines of 100 bytes, each ended by a newline (one string, not one array item a line). */
	private static function other(int $bytes): string
	{
		return str_repeat(str_repeat('f', 99) . "\n", intdiv($bytes, 100) + 1);
	}

	public function testAWindowThatCutOffTheLatestStartsMarkerIsFlaggedPartial(): void
	{
		// Given a log whose latest start's `starting pid` line and first listener are beyond the read limit, its last listener and ready line inside it
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::other(self::READ_LIMIT + 100000), 'listening udp+tcp [::1]:53', self::READY]);
		$this->assertGreaterThan(self::READ_LIMIT, pfb_dns_proxy_log_size(), 'before: the log is longer than the read limit');
		$this->assertNotContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the marker is outside the window');

		// Then the record says it may miss listeners, and what the read shows is read as for a log with no marker
		$this->assertTrue(pfb_dns_proxy_listeners()['partial'] ?? NULL);
		$this->assertSame(['udp+tcp [::1]:53'], $this->served());
	}

	public function testAWindowThatHoldsTheLatestStartsMarkerIsNotPartial(): void
	{
		// Given a log longer than 64 KiB whose latest start, `starting pid` line included, is inside the last 64 KiB
		$this->log([...self::filler(), 'starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::READY]);
		$this->assertGreaterThan(65536, pfb_dns_proxy_log_size(), 'before: the log is longer than the window');
		$this->assertContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the marker is inside the window');

		// Then the record is whole
		$this->assertFalse(pfb_dns_proxy_listeners()['partial'] ?? NULL);
	}

	public function testAMarkerSeventyKiBBackIsReadWithinTheReadLimitAndIsNotPartial(): void
	{
		// Given a log longer than 64 KiB whose latest start's `starting pid` line and first listener are 70 KB before its ready line
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', ...self::filler(), 'listening udp+tcp [::1]:53', self::READY]);
		$this->assertGreaterThan(65536, pfb_dns_proxy_log_size(), 'before: the log is longer than the first window');
		$this->assertNotContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the marker is outside the first window');

		// Then the read grew to hold the start: the record is whole, and both of its listeners are served
		$this->assertFalse(pfb_dns_proxy_listeners()['partial'] ?? NULL);
		$this->assertSame(['udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53'], $this->served());
	}

	public function testAShortLogWithNoMarkerIsNotPartial(): void
	{
		// Given an older gateway's log: short, with no `starting pid` line
		$this->log(['listening udp+tcp 127.0.0.1:53', self::READY]);

		// Then the record is whole: nothing was cut
		$this->assertFalse(pfb_dns_proxy_listeners()['partial'] ?? NULL);
	}

	public function testALegacyLogWithTwoReadyLinesInTheReadIsNotPartial(): void
	{
		// Given an older gateway's log (no `starting pid` line) longer than 64 KiB: other output, an older start, then the latest start
		$this->log([...self::filler(), 'listening udp+tcp 127.0.0.1:53', self::READY, 'listening udp+tcp 127.0.0.1:53', 'listening udp+tcp [::1]:53', self::READY]);
		$this->assertGreaterThan(65536, pfb_dns_proxy_log_size(), 'before: the log is longer than the first window');
		$this->assertNotContains('starting pid 4242', pfb_dns_proxy_log_lines(), 'before: the log has no marker');

		// Then the latest start's beginning, the older start's ready line, is in the read: the record is whole
		$this->assertFalse(pfb_dns_proxy_listeners()['partial'] ?? NULL);
		$this->assertSame(['udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53'], $this->served());
	}

	public function testAStartAboutEightMiBBackIsReadWithinTheReadLimitAndIsWhole(): void
	{
		// Given a start whose `starting pid` line and first listener are 8 MB before its ready line: only the 16 MiB read holds them
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', self::other(8000000) . 'listening udp+tcp [::1]:53', self::READY]);
		$this->assertGreaterThan(4 * 1048576, pfb_dns_proxy_log_size(), 'before: the start is beyond the 4 MiB read');

		// Then the read grew to hold it: the record is whole, and both of its listeners are served
		$this->assertFalse(pfb_dns_proxy_listeners()['partial'] ?? NULL);
		$this->assertSame(['udp+tcp 127.0.0.1:53', 'udp+tcp [::1]:53'], $this->served());
	}

	public function testTheLineTheReadLimitCutsInsideOfIsNeverParsed(): void
	{
		// Given a log of the read limit plus two bytes whose first line, a DoT line with one byte in front of it, is cut by the read
		// one byte in: what the read sees of it is a complete-looking `listening dot 192.0.2.1:853`
		$first = "Xlistening dot 192.0.2.1:853\n";
		$last = "listening udp+tcp 127.0.0.1:53\n" . self::READY . "\n";
		$size = self::READ_LIMIT + 2;
		file_put_contents($GLOBALS['pfb']['dns_proxy_log'], $first . str_repeat('f', $size - strlen($first) - strlen($last) - 1) . "\n" . $last);
		$this->assertSame($size, pfb_dns_proxy_log_size(), 'before: the fixture is the length that cuts the first line at the limit');

		// Then the cut line is dropped: the record is partial and holds only the listener logged in full
		$this->assertTrue(pfb_dns_proxy_listeners()['partial'] ?? NULL);
		$this->assertSame(['udp+tcp 127.0.0.1:53'], $this->served());
	}

	public function testAGrownReadNeverReachesBeforeSince(): void
	{
		// Given an older complete start, then $since, then a start that has logged its marker and a listener but no ready line yet,
		// followed by more than 64 KiB of other output
		$this->log(['starting pid 111', 'listening udp+tcp 192.0.2.9:53', 'ready upstream 127.0.0.1:5353 pid 111']);
		$since = pfb_dns_proxy_log_size();
		$this->log(['starting pid 4242', 'listening udp+tcp 127.0.0.1:53', ...self::filler()], TRUE);

		// Then the read from $since holds no ready line: the older start is not taken for this one
		$this->assertNull($this->served($since));
	}

	/** @return array<string,array{string,string,string}> a host as an rc script or the gateway's log spells it, a port, and the host:port as the gateway prints it */
	public static function hostPorts(): array
	{
		return [
			'an IPv4 address' => ['127.0.0.1', '53', '127.0.0.1:53'],
			'an IPv6 address, compressed and bracketed' => ['2001:DB8:0:0:0:0:0:1', '53', '[2001:db8::1]:53'],
			'an IPv4-mapped address in dotted form' => ['::ffff:127.0.0.1', '53', '127.0.0.1:53'],
			'an IPv4-mapped address in hex form' => ['::FFFF:7f00:1', '53', '127.0.0.1:53'],
			'an IPv4-mapped wildcard' => ['::ffff:0.0.0.0', '853', '0.0.0.0:853'],
			'an address that is not mapped but has the same tail' => ['64:ff9b::7f00:1', '53', '[64:ff9b::7f00:1]:53'],
			'a text that is no address' => ['127.1', '53', '127.1:53'],
		];
	}

	#[DataProvider('hostPorts')]
	public function testHostPortSpellsAnAddressAsTheGatewayPrintsIt(string $host, string $port, string $printed): void
	{
		$this->assertSame($printed, pfb_dns_proxy_host_port($host, $port));
	}
}
