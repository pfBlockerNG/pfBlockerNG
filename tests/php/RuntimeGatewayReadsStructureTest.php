<?php

declare(strict_types=1);

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3450: the runtime consumers of the 12 newly registered IP scalars read them
 * through PfbConfig::read(), so the registry default is the only default. The value tests
 * prove PfbConfig's semantics; only a structure pin fails when a consumer goes back to the
 * old `$pfb['ipconfig'][...] ?: <default>` expression.
 *
 * The update pass's own reads are pinned by behaviour, not by where their text sits (owner decision on #4037, 2026-11-22):
 * its settings step, pfb_apply_settings(), is shared with the version 2 apply, and a raw copy of the IP settings that disagrees
 * with config.xml must not reach what it sets. The scan for raw reads still covers the settings step and the pass itself.
 */
final class RuntimeGatewayReadsStructureTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local/';

	/** The registered IP keys a raw array read of which would bypass the registry default (the DNSBL ones are pinned by RuntimeToggleOwnershipStructureTest). */
	private const KEYS = [
		'ip_placeholder', 'maxmind_locale', 'maxmind_account', 'maxmind_key', 'asn_reporting', 'asn_token',
		'inbound_interface', 'inbound_deny_action', 'outbound_interface', 'outbound_deny_action',
		'pass_order', 'autorule_suffix',
	];

	/** @return iterable<string,array{0:string,1:?string,2:list<string>}> file, function (NULL = whole file), expected gateway keys */
	public static function consumerProvider(): iterable
	{
		// The update pass's settings step reads the six keys; the pass reads none of the twelve off a raw copy, anywhere in it.
		yield 'pfb_apply_settings' => ['pkg/pfblockerng/pfblockerng_apply.inc', 'pfb_apply_settings', [
			'ip/inbound_deny_action', 'ip/outbound_deny_action', 'ip/pass_order', 'ip/autorule_suffix',
			'ip/ip_placeholder', '"ip/{$type}_interface"',
		]];
		yield 'sync_package_pfblockerng' => ['pkg/pfblockerng/pfblockerng_apply.inc', 'sync_package_pfblockerng', []];
		yield 'pfb_global' => ['pkg/pfblockerng/pfblockerng.inc', 'pfb_global', [
			'ip/maxmind_locale', 'ip/asn_reporting', 'ip/asn_token', 'ip/maxmind_account', 'ip/maxmind_key',
		]];
		yield 'pfb_ip_placeholder' => ['pkg/pfblockerng/pfblockerng.inc', 'pfb_ip_placeholder', ['ip/ip_placeholder']];
		yield 'dnsbl page quick-fill' => ['www/pfblockerng/pfblockerng_dnsbl.php', NULL, ['ip/inbound_interface', 'ip/outbound_interface']];
	}

	/** @param list<string> $expected */
	#[DataProvider('consumerProvider')]
	public function testConsumerReadsRegisteredKeysThroughTheGatewayOnly(string $file, ?string $function, array $expected): void
	{
		$source = file_get_contents(self::SRC . $file);
		if (!is_string($source)) {
			throw new RuntimeException("test bootstrap: failed to read {$file}");
		}
		$ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($source);
		if (!is_array($ast)) {
			throw new RuntimeException("test bootstrap: failed to parse {$file}");
		}

		$finder = new NodeFinder();
		$scope = $ast;
		if ($function !== NULL) {
			$node = $finder->findFirst($ast, static fn (Node $n): bool =>
				$n instanceof Stmt\Function_ && $n->name->toString() === $function);
			$this->assertInstanceOf(Stmt\Function_::class, $node, "{$function} must exist");
			$scope = [$node];
		}

		$printer = new Standard();
		$text = static fn (Node $arg): ?string => match (TRUE) {
			$arg instanceof Node\Scalar\String_ => $arg->value,
			$arg instanceof Node\Scalar\InterpolatedString => $printer->prettyPrintExpr($arg),
			default => NULL,
		};

		$reads = [];
		foreach ($finder->findInstanceOf($scope, Expr\StaticCall::class) as $call) {
			if ($call->class instanceof Node\Name && $call->class->toString() === 'PfbConfig'
				&& $call->name instanceof Node\Identifier && $call->name->toString() === 'read'
				&& isset($call->args[0]) && $call->args[0] instanceof Node\Arg) {
				$reads[] = $text($call->args[0]->value);
			}
		}
		foreach ($expected as $key) {
			$this->assertContains($key, $reads, "{$file}: {$key} must be read through PfbConfig::read()");
		}

		// A registered key read off any array but the $pfb result bag is a raw read that bypasses the default.
		$raw = [];
		foreach ($finder->findInstanceOf($scope, Expr\ArrayDimFetch::class) as $fetch) {
			$bag = $fetch->var instanceof Expr\Variable && $fetch->var->name === 'pfb';
			$dim = $fetch->dim === NULL ? NULL : $text($fetch->dim);
			if (!$bag && $dim !== NULL && (in_array($dim, self::KEYS, TRUE) || str_ends_with($dim, '_interface"'))) {
				$raw[] = $dim;
			}
		}
		$this->assertSame([], $raw, "{$file}: registered keys must not be read from a raw config array");
	}

	/**
	 * The settings step takes the six registered IP keys it consumes from config.xml through PfbConfig: an absent key is the
	 * registry default, a stored key is what is stored, and pfb_global()'s raw copy
	 * ($pfb['ipconfig']) never decides either.
	 */
	public function testTheSettingsStepTakesTheRegisteredIpKeysFromTheGatewayNotFromARawCopy(): void
	{
		global $pfb;

		$saved = ['pfb' => $pfb, 'config' => $GLOBALS['config'] ?? []];
		$env   = ['PFB_IP_PLACEHOLDER' => getenv('PFB_IP_PLACEHOLDER'), 'PFB_REENTRY_TIMEOUT' => getenv('PFB_REENTRY_TIMEOUT'),
			'PFB_USE_MFS_TMPVAR' => getenv('PFB_USE_MFS_TMPVAR')];
		$dir   = sys_get_temp_dir() . '/pfb_settings_' . bin2hex(random_bytes(4));
		mkdir($dir, 0700);
		try {
			$ip  = 'installedpackages/pfblockerngipsettings/config/0';
			$run = static function () use ($dir): void {
				global $pfb;
				// what pfb_global() leaves, with every path the step may remove inside the test's own directory
				$pfb['dnsbl']        = PfbToggle::Off;
				$pfb['dnsblconfig']  = ['action' => 'Disabled', 'top1m_count' => '', 'top1m_inclusion' => '', 'aliaslog' => ''];
				$pfb['aliasarchive'] = "{$dir}/aliastables";
				$pfb['dnsblarchive'] = "{$dir}/dnsbl_cache";
				$pfb['ipconfig']     = ['inbound_deny_action' => 'match', 'outbound_deny_action' => 'match', 'pass_order' => 'order_3',
					'autorule_suffix' => 'ar', 'ip_placeholder' => '10.9.9.9', 'inbound_interface' => 'raw0', 'outbound_interface' => 'raw1'];
				pfb_apply_settings();
			};
			$GLOBALS['config'] = [];
			config_set_path("{$ip}/enable_float", '');
			foreach (['et_update', 'ccwhite', 'ccblack', 'etblock', 'etmatch', 'p24_max_var', 'p24_dmax_var', 'p24_pmax_var', 'ccexclude'] as $key) {
				config_set_path("installedpackages/pfblockerngreputation/config/0/{$key}", '');
			}
			config_set_path('installedpackages/pfblockernglistsv4/config', [['aliasname' => 'Beta', 'action' => 'Deny_Both']]);

			// Given config.xml without the keys
			$run();
			$this->assertSame(['block', 'reject', 'order_0', ' auto rule', '127.1.7.7', [], []],
				[$pfb['deny_action_inbound'], $pfb['deny_action_outbound'], $pfb['order'], $pfb['suffix'], $pfb['ip_ph'],
					$pfb['inbound_interfaces'], $pfb['outbound_interfaces']],
				'absent keys read as the registry defaults, never as the raw copy');

			// When config.xml stores each key
			foreach (['inbound_deny_action' => 'reject', 'outbound_deny_action' => 'block', 'pass_order' => 'order_2',
				'autorule_suffix' => 'ar', 'ip_placeholder' => '127.9.9.9', 'inbound_interface' => 'wan', 'outbound_interface' => 'lan,opt1'] as $key => $value) {
				config_set_path("{$ip}/{$key}", $value);
			}
			$run();
			$this->assertSame(['reject', 'block', 'order_2', ' AR', '127.9.9.9', ['wan'], ['lan', 'opt1']],
				[$pfb['deny_action_inbound'], $pfb['deny_action_outbound'], $pfb['order'], $pfb['suffix'], $pfb['ip_ph'],
					$pfb['inbound_interfaces'], $pfb['outbound_interfaces']],
				'stored keys are what the step sets');
			$this->assertSame('127.9.9.9', getenv('PFB_IP_PLACEHOLDER'), 'the shell script is handed the stored placeholder');
		} finally {
			$pfb = $saved['pfb'];
			$GLOBALS['config'] = $saved['config'];
			foreach ($env as $name => $value) {
				putenv($value === FALSE ? $name : "{$name}={$value}");
			}
			rmdir_recursive($dir);
		}
	}
}
