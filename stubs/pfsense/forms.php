<?php
/**
 * pfSense WebUI form-builder class stubs — static analysis only (PHPStan / Intelephense).
 *
 * HAND-MAINTAINED (not produced by scripts/update-pfsense-stubs.py): these are the
 * /usr/local/www/classes/Form/* widget classes the WebUI pages instantiate. PHPStan
 * level 0 only needs the symbols to exist; a variadic constructor plus a __call that
 * returns $this faithfully model the widgets' fluent API without pinning every method
 * signature — e.g. (new Form_Input(...))->setHelp(...)->setAttribute(...),
 * $section->addInput(...), $group->add(...), $form->add($section).
 *
 * This lets PHPStan resolve the WebUI pages instead of baselining every "Instantiated
 * class Form_* not found" — see CLAUDE.md "stub over baseline".
 *
 * Not shipped — stubs/ is excluded from release archives.
 */

abstract class _PfbFormWidgetStub
{
    public function __construct(mixed ...$args) {}

    public function __call(string $name, array $arguments): static
    {
        return $this;
    }
}

class Form extends _PfbFormWidgetStub {}

class Form_Section extends _PfbFormWidgetStub {}

class Form_Group extends _PfbFormWidgetStub {}

class Form_Input extends _PfbFormWidgetStub {}

class Form_Select extends _PfbFormWidgetStub {}

class Form_Checkbox extends _PfbFormWidgetStub {}

class Form_Button extends _PfbFormWidgetStub {}

class Form_StaticText extends _PfbFormWidgetStub {}

class Form_Textarea extends _PfbFormWidgetStub {}
