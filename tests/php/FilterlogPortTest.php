<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_filterlog_port() — the pure port-field selector for a parsed
 * filter.log CSV row (issue #713, bug 12).
 *
 * The filter.log CSV layout differs by IP version: a v4 row's ports live at
 * $d[20] (src) / $d[21] (dst); a v6 row -- fewer leading fields -- carries them
 * at $d[17] (src) / $d[18] (dst). Confirmed against the "Log: Protocol
 * ID/Protocol/SRC IP/DST IP/SRC Port/DST Port" comment and CSV-build code a few
 * hundred lines below pfb_daemon_filterlog()'s port-selection site (both v4 and
 * v6 branches use the same $d[20]/$d[21] vs $d[17]/$d[18] indices there). The
 * old port-selection at the 'in'/'out' branch used the v4 indices ($d[20]/$d[21])
 * unconditionally, so a v6 flow read the wrong CSV field as its port and
 * mis-attributed the local_hosts reverse-lookup key.
 *
 * Scenario A: v4 inbound (dst is local)  -> dst port at $d[21]
 * Scenario B: v4 outbound (src is local) -> src port at $d[20]
 * Scenario C: v6 inbound (dst is local)  -> dst port at $d[18]
 * Scenario D: v6 outbound (src is local) -> src port at $d[17]
 */
#[CoversFunction('pfb_filterlog_port')]
final class FilterlogPortTest extends TestCase
{
	// A synthetic $d row with a distinct marker at every candidate port index,
	// so a wrong-index read is caught rather than accidentally matching.
	private function rowFor(int $ipVersion): array {
		$d = [];
		$d[8]  = $ipVersion;
		$d[17] = 'v6_src_17';
		$d[18] = 'v6_dst_18';
		$d[20] = 'v4_src_20';
		$d[21] = 'v4_dst_21';
		return $d;
	}

	// ---------- Scenario A — v4 inbound ----------

	public function testV4Inbound_ReturnsDstPortAt21(): void
	{
		// Given: a v4 row.
		$d = $this->rowFor(4);

		// When: the flow is inbound (dst is the local client).
		$port = pfb_filterlog_port($d, TRUE);

		// Then: the v4 dst-port field ($d[21]) is used.
		$this->assertSame('v4_dst_21', $port,
			"expected: v4 inbound reads \$d[21];\nactual: {$port}");
	}

	// ---------- Scenario B — v4 outbound ----------

	public function testV4Outbound_ReturnsSrcPortAt20(): void
	{
		// Given: a v4 row.
		$d = $this->rowFor(4);

		// When: the flow is outbound (src is the local client).
		$port = pfb_filterlog_port($d, FALSE);

		// Then: the v4 src-port field ($d[20]) is used.
		$this->assertSame('v4_src_20', $port,
			"expected: v4 outbound reads \$d[20];\nactual: {$port}");
	}

	// ---------- Scenario C — v6 inbound (the regression) ----------

	/**
	 * The regression this bug fixes: a v6 inbound flow must read the v6 dst-port
	 * index ($d[18]), not the v4 index ($d[21]).
	 */
	public function testV6Inbound_ReturnsDstPortAt18(): void
	{
		// Given: a v6 row.
		$d = $this->rowFor(6);

		// When: the flow is inbound (dst is the local client).
		$port = pfb_filterlog_port($d, TRUE);

		// Then: the v6 dst-port field ($d[18]) is used -- NOT the v4 $d[21].
		$this->assertSame('v6_dst_18', $port,
			"expected: v6 inbound reads \$d[18], not the v4 \$d[21];\nactual: {$port}");
	}

	// ---------- Scenario D — v6 outbound (the regression) ----------

	public function testV6Outbound_ReturnsSrcPortAt17(): void
	{
		// Given: a v6 row.
		$d = $this->rowFor(6);

		// When: the flow is outbound (src is the local client).
		$port = pfb_filterlog_port($d, FALSE);

		// Then: the v6 src-port field ($d[17]) is used -- NOT the v4 $d[20].
		$this->assertSame('v6_src_17', $port,
			"expected: v6 outbound reads \$d[17], not the v4 \$d[20];\nactual: {$port}");
	}
}
