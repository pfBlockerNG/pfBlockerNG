<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * DNSBL settings save: the web server port fields are text inputs. A crafted array posted to one is an input error; pfSense's
 * is_port() passed it to getservbyname(), which threw a TypeError (a 500) (issue #4000).
 *
 * The page cannot be required off-appliance, so its real port-validation region is extracted from the shipped source and
 * evaluated (PageStatementLoader.php) over the is_port() double, a copy of pfSense's util.inc.
 */
#[CoversNothing]
final class DnsblPortFieldTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function tearDown(): void
	{
		$_POST = [];
	}

	/**
	 * @param array<string, mixed> $post
	 * @return list<string> the input errors the port check records
	 */
	private static function validatePorts(array $post, bool $vipDemand): array
	{
		$_POST = $post;
		$scope = pfb_test_page_eval(
			pfb_test_page_region(self::PAGE, '// The web server ports are required', "// Validate Adv. firewall rule 'Protocol' setting"),
			['pfb_vip_demand' => $vipDemand, 'input_errors' => []]
		);
		return $scope['input_errors'];
	}

	public function testValidPortsPass(): void
	{
		$this->assertSame([], self::validatePorts(['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443'], TRUE));
	}

	public function testAnArrayPostedToAPortIsAnInputError(): void
	{
		foreach ([TRUE, FALSE] as $vipDemand) {
			$this->assertSame(
				['DNSBL Port is invalid!', 'DNSBL SSL Port is invalid!'],
				self::validatePorts(['pfb_dnsport' => ['8081'], 'pfb_dnsport_ssl' => [['x']]], $vipDemand),
				$vipDemand ? 'VIP in use' : 'VIP not in use'
			);
		}
	}
}
