<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Package pages cannot be included as a whole off-appliance: they require pfSense's absolute
 * runtime files, read live config, and several perform config/service/file mutations before exit.
 * The recursive code/XML audit therefore pins containment without executing unrelated pages;
 * php_strip_whitespace excludes comments/docblocks from every PHP/INC assertion.
 */
final class HookEditFileContainmentTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const SRC = self::ROOT . '/src';
	private const HOOK_EDIT = self::ROOT . '/src/usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc';
	private const MUTATING_FUNCTIONS = [
		'pfb_hook_editor_delete',
		'pfb_edit_hooks_controller',
		'pfb_edit_hooks_request',
	];

	public function testExactlyOneShippingPhpIncluderAndNoXmlIncluder(): void
	{
		$php = $this->phpReferences();
		$this->assertSame(
			['usr/local/www/pfblockerng/pfblockerng_edit_hooks.php'],
			$php,
			'only the privilege-gated Edit Hooks page may include the destructive hook file'
		);
		$this->assertSame([], $this->xmlReferences(), 'package XML must not widen destructive hook scope');
	}

	public function testExactlyOneShippingDefinition(): void
	{
		$definitions = array_fill_keys(self::MUTATING_FUNCTIONS, []);
		foreach ($this->shippingFiles() as $path) {
			$source = php_strip_whitespace($path);
			foreach (self::MUTATING_FUNCTIONS as $function) {
				if (str_contains($source, "function {$function}(")) {
					$definitions[$function][] = $this->relative($path);
				}
			}
		}
		foreach ($definitions as $function => $files) {
			$this->assertSame(
				['usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc'],
				$files,
				"{$function} must exist only in the page-scoped destructive include"
			);
		}
	}

	public function testPackageWideIncludeDoesNotLoadDestructiveOperation(): void
	{
		$result = $this->runChild(<<<'PHP'
require %s . '/tests/php/bootstrap.php';
foreach (['pfb_hook_editor_delete', 'pfb_edit_hooks_controller', 'pfb_edit_hooks_request'] as $function) {
	if (function_exists($function)) {
		exit(1);
	}
}
PHP
);
		$this->assertSame(0, $result['status'], $result['stderr']);
	}

	public function testIntendedHookFileLoadsOperation(): void
	{
		$result = $this->runChild(<<<'PHP'
require %s . '/src/usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc';
foreach (['pfb_hook_editor_delete', 'pfb_edit_hooks_controller', 'pfb_edit_hooks_request'] as $function) {
	if (!function_exists($function)) {
		exit(1);
	}
	$reflection = new ReflectionFunction($function);
	if (realpath((string) $reflection->getFileName()) !== realpath(%s . '/src/usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc')) {
		exit(2);
	}
}
PHP
);
		$this->assertSame(0, $result['status'], $result['stderr']);
	}

	/** @return list<string> */
	private function phpReferences(): array
	{
		$references = [];
		foreach ($this->shippingFiles() as $path) {
			$source = php_strip_whitespace($path);
			if (str_contains($source, 'pfblockerng_hook_edit.inc')) {
				$references[] = $this->relative($path);
			}
		}
		return $references;
	}

	/** @return list<string> */
	private function xmlReferences(): array
	{
		$references = [];
		foreach ($this->shippingFiles('xml') as $path) {
			$xml = simplexml_load_file($path, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOBLANKS);
			$this->assertNotFalse($xml, "invalid shipping XML: {$path}");
			foreach ($xml->xpath('//include_file') ?: [] as $include) {
				if (trim((string) $include) === '/usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc') {
					$references[] = $this->relative($path);
				}
			}
		}
		return $references;
	}

	/** @return list<string> */
	private function shippingFiles(string $extension = ''): array
	{
		$files = [];
		$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::SRC, FilesystemIterator::SKIP_DOTS));
		foreach ($iterator as $file) {
			/** @var SplFileInfo $file */
			if (!$file->isFile()) {
				continue;
			}
			if ($extension !== '' ? $file->getExtension() !== $extension : !in_array($file->getExtension(), ['php', 'inc'], TRUE)) {
				continue;
			}
			$files[] = $file->getPathname();
		}
		sort($files, SORT_STRING);
		return $files;
	}

	private function relative(string $path): string
	{
		return ltrim(str_replace(self::SRC, '', $path), '/');
	}

	/** @return array{status:int,stdout:string,stderr:string} */
	private function runChild(string $template): array
	{
		$root = var_export(self::ROOT, TRUE);
		$script = sprintf($template, $root, $root);
		$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		return ['status' => $status, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
	}
}
