<?php
/**
 * pfSense WebUI form-builder class stubs — static analysis only (PHPStan / Intelephense).
 *
 * HAND-MAINTAINED (not produced by scripts/update-pfsense-stubs.py): the
 * /usr/local/www/classes/Form/* widget classes the WebUI pages instantiate.
 * PHPStan level 2 needs REAL method declarations — a variadic __call (level 0's
 * trick) is not honoured: it still reports "Call to an undefined method" for
 * every call site regardless. Method names/params/return types below mirror
 * pfSense CE 2.8.0's dated commit ed6c2eb8 (2025-05-28 — the mirror carries no
 * RELENG_2_8_0 tag/branch): src/usr/local/www/classes/Form.class.php and
 * Form/{Element,Section,Group,Input,Button,Select,Checkbox,StaticText,
 * Textarea}.class.php; only members pfBlockerNG's WebUI actually calls are
 * declared (verified by grep over src/usr/local/www/pfblockerng) — upstream
 * has more, unused ones are omitted (issue #1159).
 *
 * Not shipped — stubs/ is excluded from release archives.
 */

// @codingStandardsIgnoreFile

class Form_Element
{
    public function __construct(mixed ...$args) {}

    public function addClass(string ...$classes): static
    {
        return $this;
    }

    public function removeClass(string $class): static
    {
        return $this;
    }

    public function setAttribute(string $key, mixed $value = null): static
    {
        return $this;
    }

    public function __toString(): string
    {
        return '';
    }
}

class Form extends Form_Element
{
    public function add(Form_Section $section): Form_Section
    {
        return $section;
    }

    public function setAction(string $url): static
    {
        return $this;
    }

    public function addGlobal(Form_Input $input): Form_Input
    {
        return $input;
    }
}

class Form_Section extends Form_Element
{
    public function add(Form_Group $group): Form_Group
    {
        return $group;
    }

    /** Shortcut: wraps $input in its own Form_Group and adds that. */
    public function addInput(Form_Input $input): Form_Input
    {
        return $input;
    }

    /** Shortcut: wraps $input (+ an optional confirm field) in its own Form_Group. */
    public function addPassword(Form_Input $input, bool $confirmfield = true): Form_Input
    {
        return $input;
    }
}

class Form_Group extends Form_Element
{
    /**
     * Returns its own argument (upstream: `return $input;`) — templated so a
     * chained call on the caller's own Form_Input subtype (e.g. displayAsRadio()
     * on a Form_Checkbox) still resolves.
     *
     * @template TInput of Form_Input
     * @param TInput $input
     * @return TInput
     */
    public function add(Form_Input $input): Form_Input
    {
        return $input;
    }

    public function setHelp(mixed ...$args): static
    {
        return $this;
    }
}

class Form_Input extends Form_Element
{
    public function setHelp(mixed ...$args): static
    {
        return $this;
    }

    public function setWidth(int|float $size): static
    {
        return $this;
    }
}

class Form_Select extends Form_Input {}

class Form_Checkbox extends Form_Input
{
    public function displayAsRadio(?string $id = null): static
    {
        return $this;
    }
}

class Form_Button extends Form_Input {}

class Form_StaticText extends Form_Input {}

class Form_Textarea extends Form_Input {}
