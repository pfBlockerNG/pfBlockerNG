<?php

declare(strict_types=1);

/**
 * issue #3515 -- seeds the two files the DNS proxy's readiness is read from, as real files, and answers liveness through the
 * isvalidpid() double (a test never starts a process): the daemon's child pidfile ($pfb['dns_proxy_pidfile'], what
 * `daemon -p` writes) and the listener-ready marker ($pfb['dns_proxy_ready'], what the proxy's --ready-file writes).
 * The bootstrap points both at its own sandbox, so a test never reads or writes the appliance's /var/run or /var/unbound.
 */
trait DnsProxyReadySeedTrait
{
	private function proxyPidfile(): string
	{
		return (string) $GLOBALS['pfb']['dns_proxy_pidfile'];
	}

	private function proxyMarker(): string
	{
		return (string) $GLOBALS['pfb']['dns_proxy_ready'];
	}

	/** A proxy whose child is $child: its pidfile names it and the double says it lives; the marker is $marker ('' = absent). */
	private function seedProxy(string $child, ?string $marker, bool $alive = TRUE): void
	{
		file_put_contents($this->proxyPidfile(), "{$child}\n");
		if ($marker === NULL) {
			@unlink($this->proxyMarker());
		} else {
			file_put_contents($this->proxyMarker(), $marker);
		}
		$GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()] = $alive;
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_PIDFILE] = $alive;
	}

	/** The proxy as the real one comes up: child 4242, and the marker it publishes once it serves. */
	private function proxyServes(string $child = '4242'): void
	{
		$this->seedProxy($child, "{$child}\n");
	}

	/** A process that lives and never publishes the marker: a listener that failed to bind or to initialize. */
	private function proxyLivesButNeverServes(string $child = '4242'): void
	{
		$this->seedProxy($child, NULL);
	}

	private function clearProxyFiles(): void
	{
		@unlink($this->proxyPidfile());
		@unlink($this->proxyMarker());
		unset($GLOBALS['pfb_test_valid_pids'][$this->proxyPidfile()], $GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_PIDFILE]);
	}
}
