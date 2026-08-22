<?php

declare(strict_types=1);

define('PFB_REPO_GENERATE_HOOK', sys_get_temp_dir() . '/pfb-ca-ui-hook-' . bin2hex(random_bytes(4)));

if (!function_exists('gettext')) {
	function gettext(string $text): string
	{
		return $text;
	}
}

function pkg_version_compare(string $left, string $right): string
{
	$result = version_compare($left, $right);
	return $result < 0 ? '<' : ($result > 0 ? '>' : '=');
}

class Form
{
	public array $sections = [];
	public array $globals = [];

	public function add(object $section): void
	{
		$this->sections[] = $section;
	}

	public function addGlobal(object $input): void
	{
		$this->globals[] = $input;
	}
}

class Form_Section
{
	public array $inputs = [];

	public function __construct(public string $title)
	{
	}

	public function addInput(object $input): object
	{
		$this->inputs[] = $input;
		return $input;
	}
}

class Form_Checkbox
{
	public string $help = '';

	public function __construct(
		public string $name,
		public string $label,
		public string $description,
		public bool $checked,
		public string $value
	) {
	}

	public function setHelp(string $help): self
	{
		$this->help = $help;
		return $this;
	}
}

class Form_Input
{
	public function __construct(
		public string $name,
		public string $label,
		public string $type,
		public string $value
	) {
	}
}

$root_path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng';
require_once $root_path . '/pfblockerng_extra.inc';
require_once $root_path . '/pfblockerng_software.inc';

$failures = 0;

function row(string $name, callable $check): void
{
	global $failures;
	try {
		$check();
		echo "PASS {$name}\n";
	} catch (Throwable $error) {
		$failures++;
		echo "FAIL {$name}: {$error->getMessage()}\n";
	}
}

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

row('consent controls execute through the shipped form helper', static function (): void {
	$form = new Form();
	pfb_pkgconf_ca_add_form_controls($form, false);
	check(count($form->sections) === 1, 'one consent section rendered');
	$section = $form->sections[0];
	check($section->title === 'Package manager CA trust', 'section title');
	check(count($section->inputs) === 1 && $section->inputs[0] instanceof Form_Checkbox, 'checkbox rendered');
	$checkbox = $section->inputs[0];
	check($checkbox->name === 'pfb_pkg_ca_consent', 'checkbox name');
	check($checkbox->value === 'on' && !$checkbox->checked, 'checkbox token and state');
	check(str_contains($checkbox->help, 'SSL_CA_CERT_PATH=/etc/ssl/certs'), 'owned line help');
	check(str_contains($checkbox->help, 're-applies the line at boot'), 'reapply help');
	check(count($form->globals) === 1, 'hidden marker rendered');
	check($form->globals[0]->name === 'pfb_pkg_ca_consent_shown', 'hidden marker name');

	$enabled = new Form();
	pfb_pkgconf_ca_add_form_controls($enabled, true);
	check($enabled->sections[0]->inputs[0]->checked, 'enabled consent renders checked');
	check(str_contains($enabled->sections[0]->inputs[0]->help, 'before each package check'), 'runtime hook help');
});

row('login generation: help names login.conf, never pkg.conf; old generation unchanged', static function (): void {
	file_put_contents(PFB_REPO_GENERATE_HOOK, "#!/bin/sh\n# verbs: login-ca-sync login-ca-revoke\nexit 0\n");
	$form = new Form();
	pfb_pkgconf_ca_add_form_controls($form, true);
	$help = $form->sections[0]->inputs[0]->help;
	check(str_contains($help, '/etc/login.conf'), 'login-generation help names /etc/login.conf');
	check(!str_contains($help, 'pkg.conf'), 'login-generation help does not name pkg.conf');
	unlink(PFB_REPO_GENERATE_HOOK);
	$legacy = new Form();
	pfb_pkgconf_ca_add_form_controls($legacy, false);
	check(str_contains($legacy->sections[0]->inputs[0]->help, 'pkg.conf'), 'old-generation help still names pkg.conf');
});

row('package PHP exposes only the hook delegation boundary', static function (): void {
	$command = new ReflectionFunction('pfb_pkgconf_ca_command');
	$apply = new ReflectionFunction('pfb_pkgconf_ca_apply');
	check($command->getNumberOfParameters() === 1, 'command accepts only the action');
	check($apply->getNumberOfParameters() === 2, 'apply accepts token and prior consent');
	$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_software.inc');
	check(is_string($source), 'software source');
	foreach (['pfb_pkg_ca_env_prefix', 'pfb_pkgconf_ca_sync', 'pfb_pkgconf_write_atomic', 'pfb_pkgconf_ca_tick'] as $removed) {
		check(!str_contains($source, "function {$removed}"), "{$removed} removed");
	}
	$product = tempnam(sys_get_temp_dir(), 'pfb-plus-');
	check(is_string($product), 'product fixture');
	file_put_contents($product, "pfSense Plus\n");
	check(pfb_pkg_ca_is_plus($product), 'Plus detected');
	file_put_contents($product, "pfSense Community Edition\n");
	check(!pfb_pkg_ca_is_plus($product), 'CE rejected');
	@unlink($product);
});

echo $failures === 0 ? "ALL PASS\n" : "{$failures} FAILURES\n";
exit($failures === 0 ? 0 : 1);
