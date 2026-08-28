<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the ip_remove handler's ip-validation shape (issue #1412): a single
 * ``pfb_filter($_POST['ip'], PFB_FILTER_IP, ...)`` call replaced the retired
 * v4-only, /24-/32-only split-capture regex. This exercises that EXACT call
 * (pfb_filter()/is_ipaddr() are untouched by #1412 -- this is coverage of
 * the validator the handler now relies on, not a behaviour it changes)
 * against hostile-input shapes: a v4-mapped IPv6 literal must be ACCEPTED
 * as an ordinary v6
 * address (the retired regex's mixed hex/dotted branch handled this shape
 * too -- the replacement must not regress it), while the SAME literal with a
 * CIDR suffix must be REJECTED, exactly like any other masked input.
 */
#[CoversFunction('pfb_filter')]
final class IpRemoveFilterHostileInputTest extends TestCase
{
	/** A v4-mapped v6 bare address is a valid IP -- the handler must accept it. */
	public function testV4MappedV6BareAddressIsAccepted(): void
	{
		$result = pfb_filter('::ffff:192.168.1.1', PFB_FILTER_IP, 'ip_remove test');

		$this->assertNotFalse($result, 'a v4-mapped v6 bare address must be accepted by PFB_FILTER_IP');
		$this->assertSame('::ffff:192.168.1.1', $result);
	}

	/** The SAME v4-mapped address with a CIDR suffix is rejected -- no mask is ever accepted. */
	public function testV4MappedV6CidrShapeIsRejected(): void
	{
		$result = pfb_filter('::ffff:192.168.1.1/64', PFB_FILTER_IP, 'ip_remove test');

		$this->assertSame('', $result, 'a CIDR-shaped input (any family, any mask) must be rejected by PFB_FILTER_IP');
	}

	/** A plain v6 CIDR is rejected -- the retired regex's unread v6 capture group is moot now. */
	public function testPlainV6CidrShapeIsRejected(): void
	{
		$result = pfb_filter('2001:db8::5/64', PFB_FILTER_IP, 'ip_remove test');

		$this->assertSame('', $result);
	}

	/** A plain v4 CIDR is rejected -- the retired regex's ONE admitted shape, now uniformly refused. */
	public function testPlainV4CidrShapeIsRejected(): void
	{
		$result = pfb_filter('198.18.5.9/16', PFB_FILTER_IP, 'ip_remove test');

		$this->assertSame('', $result);
	}
}
