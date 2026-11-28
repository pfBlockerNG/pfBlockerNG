<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SpoaTest extends TestCase
{
	public function testListenAddressValidation(): void
	{
		foreach (['127.0.0.1:10090', '[::1]:10091', 'unix:/var/run/pfb_core/spoa.sock', 'unix:/var/empty/spoa.sock'] as $ok) {
			$this->assertTrue(pfb_spoa_listen_valid($ok), "expected valid listen address: {$ok}");
		}
		foreach (['', '0.0.0.0:10090', '192.168.1.1:10090', '127.0.0.1:0', '127.0.0.1:70000', 'unix:relative.sock', 'unix:/var/run/../spoa.sock', "127.0.0.1:10090\n"] as $bad) {
			$this->assertFalse(pfb_spoa_listen_valid($bad), "expected invalid listen address: {$bad}");
		}
	}

	public function testAliasesAndTimeoutValidation(): void
	{
		$this->assertTrue(pfb_spoa_aliases_valid(''));
		$this->assertTrue(pfb_spoa_aliases_valid('pfB_PRI1_v4, pfB_PRI1_v6'));
		$this->assertFalse(pfb_spoa_aliases_valid('pfB_PRI1_v4;rm -rf /'));
		$this->assertFalse(pfb_spoa_aliases_valid('pfB_PRI1_v4,,pfB_PRI2_v4'));

		$this->assertTrue(pfb_spoa_timeout_valid('50ms'));
		$this->assertTrue(pfb_spoa_timeout_valid('500ms'));
		$this->assertTrue(pfb_spoa_timeout_valid('30s'));
		$this->assertFalse(pfb_spoa_timeout_valid('10ms'));
		$this->assertFalse(pfb_spoa_timeout_valid('31s'));
		$this->assertFalse(pfb_spoa_timeout_valid('1m'));
	}

	public function testHaproxySnippetGenerationOrderAndTransport(): void
	{
		$tcp = pfb_spoa_haproxy_snippets('127.0.0.1:10090', '127.0.0.1:10091', FALSE);
		$this->assertStringContainsString('option var-prefix pfb', $tcp['spoe_core']);
		$this->assertStringContainsString('option var-prefix crowdsec', $tcp['spoe_crowdsec']);
		$this->assertStringNotContainsString('method=method', $tcp['spoe_crowdsec']);
		$this->assertStringContainsString('server pfb-core 127.0.0.1:10090 check', $tcp['haproxy_backends']);
		$this->assertStringContainsString('server pfb-crowdsec 127.0.0.1:10091 check', $tcp['haproxy_backends']);
		$pfbPos = strpos($tcp['haproxy_frontend'], 'send-spoe-group pfb-core');
		$csPos = strpos($tcp['haproxy_frontend'], 'send-spoe-group pfb-crowdsec');
		$this->assertIsInt($pfbPos);
		$this->assertIsInt($csPos);
		$this->assertLessThan($csPos, $pfbPos, 'pfb-core must be evaluated before pfb-crowdsec');

		$unixAppSec = pfb_spoa_haproxy_snippets('unix:/var/run/pfb_core/spoa.sock', 'unix:/var/run/pfb_crowdsec/spoa.sock', TRUE);
		$this->assertStringContainsString('server pfb-core unix@/var/run/pfb_core/spoa.sock check', $unixAppSec['haproxy_backends']);
		$this->assertStringContainsString('server pfb-crowdsec unix@/var/run/pfb_crowdsec/spoa.sock check', $unixAppSec['haproxy_backends']);
		$this->assertStringContainsString('method=method', $unixAppSec['spoe_crowdsec']);
	}

	public function testCrowdsecValidateAndConfigJsonWithSpoaAndAppsec(): void
	{
		$post = [
			'enable'                => 'on',
			'lapi_url'              => 'http://192.0.2.10:8080',
			'api_key'               => 'secret-key-123',
			'log_level'             => 'info',
			'rules_all_interfaces'  => 'on',
			'rules_interfaces'      => [],
			'rules_log'             => '',
			'rules_tag'             => '',
			'rule_v4'               => 'on',
			'rule_v6'               => 'on',
			'spoa_enable'           => 'on',
			'spoa_listen'           => '127.0.0.1:10091',
			'appsec_url'            => 'http://192.0.2.10:7422',
			'appsec_timeout'        => '750ms',
			'appsec_failure_action' => 'passthrough',
		];
		$res = pfb_crowdsec_validate($post, '', ['wan', 'lan']);
		$this->assertSame([], $res['errors']);
		$json = json_decode(pfb_crowdsec_config_json($res['values']), TRUE, 8, JSON_THROW_ON_ERROR);
		$this->assertSame('127.0.0.1:10091', $json['spoa_listen']);
		$this->assertSame('http://192.0.2.10:7422', $json['appsec_url']);
		$this->assertSame('750ms', $json['appsec_timeout']);
		$this->assertSame('passthrough', $json['appsec_failure_action']);

		// When SPOA is off, spoa_listen and appsec_* are omitted from JSON.
		$post['spoa_enable'] = '';
		$resOff = pfb_crowdsec_validate($post, '', ['wan', 'lan']);
		$this->assertSame([], $resOff['errors']);
		$jsonOff = json_decode(pfb_crowdsec_config_json($resOff['values']), TRUE, 8, JSON_THROW_ON_ERROR);
		$this->assertArrayNotHasKey('spoa_listen', $jsonOff);
		$this->assertArrayNotHasKey('appsec_url', $jsonOff);
	}

	public function testCrowdsecStatusReadParsesSpoaMetrics(): void
	{
		$tmp = tempnam(sys_get_temp_dir(), 'pfb_cs_spoa_');
		$this->assertIsString($tmp);
		try {
			file_put_contents($tmp, json_encode([
				'version'                  => '0.1.0',
				'start_time'               => 1000,
				'update_frequency_seconds' => 10,
				'updated_at'               => 1010,
				'last_pull'                => 1010,
				'last_error_time'          => 0,
				'last_error'               => '',
				'lapi_requests'            => 5,
				'lapi_errors'              => 0,
				'banned'                   => ['ipv4' => ['total' => 2, 'origins' => []], 'ipv6' => ['total' => 0, 'origins' => []]],
				'dropped'                  => ['ipv4' => ['packets' => 0, 'bytes' => 0], 'ipv6' => ['packets' => 0, 'bytes' => 0]],
				'spoa'                     => [
					'enabled'        => TRUE,
					'listen'         => '127.0.0.1:10091',
					'appsec_enabled' => TRUE,
					'lookups'        => 42,
					'blocked'        => 7,
					'errors'         => 1,
					'appsec_lookups' => 35,
					'appsec_blocked' => 2,
					'appsec_errors'  => 0,
					'entries_v4'     => 2,
					'entries_v6'     => 0,
				],
			], JSON_THROW_ON_ERROR));
			$st = pfb_crowdsec_status_read($tmp);
			$this->assertIsArray($st);
			$this->assertSame(42, $st['spoa']['lookups']);
			$this->assertSame(7, $st['spoa']['blocked']);
			$this->assertSame(35, $st['spoa']['appsec_lookups']);
		} finally {
			@unlink($tmp);
		}
	}
}
