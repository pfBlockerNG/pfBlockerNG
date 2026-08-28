<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #662 — the rc.d service daemons must detach their standard file descriptors.
 *
 * Functions under test:
 *   pfb_filter_service() — generates /usr/local/etc/rc.d/pfb_filter.sh (the firewall
 *                          filter-log daemon: tail_pfb|php_pfb, or clog_pfb|php_pfb).
 *   pfb_dnsbl_service()  — generates /usr/local/etc/rc.d/pfb_dnsbl.sh (the DNSBL
 *                          lighttpd_pfb webserver).
 *
 * Intent: these daemons are (re)started via start_service() during a package
 * install/upgrade, which runs under the Package-Manager output capture pipe. A daemon
 * launched without detaching its std fds inherits that pipe and holds it open for its
 * whole life, so pkg's streamed output never reaches EOF and the upgrade page's live log
 * freezes (and shows incomplete after a reload). Each daemon launch must therefore
 * redirect its std fds away from the inherited descriptor.
 *
 * The test captures the generated rc 'start' body via the write_rcfile() double
 * (pfsense_doubles.php records each $rc into $GLOBALS['pfb_test_rcfiles']) and asserts
 * the redirect is present. Fail-before/pass-after: on the pre-fix code the daemons were
 * backgrounded as a bare `... filterlog &` / a bare `lighttpd_pfb -f ...`, so the redirect
 * assertions fail; after the fix they pass.
 */
#[CoversFunction('pfb_filter_service')]
#[CoversFunction('pfb_dnsbl_service')]
final class FilterDaemonRedirectTest extends TestCase
{
	private function startBody(string $rcfile, callable $generator): string
	{
		$GLOBALS['pfb_test_rcfiles'] = [];
		$generator();
		$this->assertArrayHasKey($rcfile, $GLOBALS['pfb_test_rcfiles'], "write_rcfile() never produced {$rcfile}");
		return (string) ($GLOBALS['pfb_test_rcfiles'][$rcfile]['start'] ?? '');
	}

	public function testFilterDaemonDetachesStdFds(): void
	{
		// When the firewall-filter rc.d script is generated
		$start = $this->startBody('pfb_filter.sh', 'pfb_filter_service');

		// Then the backgrounded filter-log daemon is NOT a bare `... filterlog &` (which
		// would inherit the caller's pipe), but a grouped pipeline whose outer std fds are
		// redirected to /dev/null so the inherited descriptor is released (#662).
		$this->assertStringNotContainsString(
			"filterlog &\n",
			$start,
			'the filter-log daemon is still backgrounded with a bare "& " that inherits the caller pipe (#662)'
		);
		$this->assertStringContainsString(
			'filterlog ; } >/dev/null 2>&1 </dev/null &',
			$start,
			'the filter-log daemon launch must detach its std fds (group + >/dev/null 2>&1 </dev/null) (#662)'
		);
	}

	public function testDnsblWebserverDetachesStdFds(): void
	{
		// When the DNSBL rc.d script is generated
		$start = $this->startBody('pfb_dnsbl.sh', 'pfb_dnsbl_service');

		// Then the lighttpd_pfb webserver launch redirects its std fds, so its self-forked
		// daemon child does not inherit and hold the caller's pipe (#662).
		$this->assertMatchesRegularExpression(
			'#lighttpd_pfb -f \S+ >/dev/null 2>&1 </dev/null#',
			$start,
			'the DNSBL lighttpd_pfb launch must detach its std fds (#662)'
		);
	}
}
