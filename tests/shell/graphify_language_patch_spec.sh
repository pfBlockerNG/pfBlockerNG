#shellcheck shell=sh
# Vendored Graphify language-override patch (issue #2810, upstream
# Graphify-Labs/graphify#3075). The script resolves both itself and its patch from
# its own checkout, so every example runs a copy of it inside a fixture checkout
# carrying a synthetic two-file patch, against a throwaway package tree named by
# PFB_GRAPHIFY_PACKAGE_DIR. The real installed Graphify is never touched.

Describe 'patch-graphify.sh'
  project_root="${SHELLSPEC_PROJECT_ROOT:-$PWD}"

  setup() {
    . "$project_root/scripts/lib/git-env-scrub.sh"
    pfb_scrub_git_env
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/graphify_language_patch.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1

    repo="$fixture/checkout root"
    git_fixture init -q "$repo" || return 1
    mkdir -p "$repo/scripts/agent" "$repo/scripts/lib" "$repo/.agents/patches" \
      "$repo/graphify-out/cache/ast" "$repo/graphify-out/cache/semantic" || return 1
    cp "$project_root/scripts/agent/patch-graphify.sh" "$repo/scripts/agent/" || return 1
    cp "$project_root/scripts/agent/agent_env.sh" "$repo/scripts/agent/" || return 1
    cp "$project_root/scripts/lib/git-env-scrub.sh" "$repo/scripts/lib/" || return 1
    script_abs="$repo/scripts/agent/patch-graphify.sh"
    printf '%s\n' stale > "$repo/graphify-out/cache/ast/entry.json"
    printf '%s\n' keep > "$repo/graphify-out/cache/semantic/entry.json"

    cat > "$repo/.agents/patches/graphify-3075-language-overrides.patch" <<'PATCH'
diff --git a/graphify/extract.py b/graphify/extract.py
--- a/graphify/extract.py
+++ b/graphify/extract.py
@@ -1,3 +1,4 @@
 SUFFIX_DISPATCH = {
     ".inc": "pascal",
 }
+SUFFIX_OVERRIDES = True
diff --git a/graphify/rcfile.py b/graphify/rcfile.py
new file mode 100644
--- /dev/null
+++ b/graphify/rcfile.py
@@ -0,0 +1,2 @@
+def activate_language_overrides(root):
+    return {".inc": ".php"}
PATCH

    package="$fixture/site packages/graphify"
    mkdir -p "$package"
    true > "$package/__init__.py"
    cat > "$package/extract.py" <<'EXTRACT'
SUFFIX_DISPATCH = {
    ".inc": "pascal",
}
EXTRACT
    cp "$package/extract.py" "$fixture/extract.py.before"
    export PFB_GRAPHIFY_PACKAGE_DIR="$package"
  }

  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'applies the vendored patch and purges the language-blind AST cache'
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The stderr should include 'Graphify-Labs/graphify#3075'
    The stderr should include "$package"
    The stderr should include 'purged'
    The contents of file "$package/rcfile.py" should include 'activate_language_overrides'
    The contents of file "$package/extract.py" should include 'SUFFIX_OVERRIDES = True'
    The path "$repo/graphify-out/cache/ast" should not be exist
    The file "$repo/graphify-out/cache/semantic/entry.json" should be exist
  End

  It 'no-ops without purging when the package already provides the override API'
    cat > "$package/rcfile.py" <<'RCFILE'
def activate_language_overrides(root):
    return {}
RCFILE
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The stderr should include 'already provides'
    Assert [ "$(cmp -s "$package/extract.py" "$fixture/extract.py.before"; printf '%s' "$?")" -eq 0 ]
    The file "$repo/graphify-out/cache/ast/entry.json" should be exist
  End

  It 'is a clean no-op on a second run that neither repatches nor purges again'
    When run sh -c 'sh "$1" "$2" >/dev/null || exit 1; mkdir -p "$2/graphify-out/cache/ast" && printf rebuilt > "$2/graphify-out/cache/ast/entry.json" && exec sh "$1" "$2"' _ "$script_abs" "$repo"
    The status should equal 0
    The stderr should include 'already provides'
    The contents of file "$repo/graphify-out/cache/ast/entry.json" should equal 'rebuilt'
    Assert [ "$(grep -c 'SUFFIX_OVERRIDES = True' "$package/extract.py")" -eq 1 ]
  End

  It 'fails loudly and changes nothing when the vendored patch does not apply'
    printf '%s\n' 'unrelated module' > "$package/extract.py"
    cp "$package/extract.py" "$fixture/extract.py.mismatch"
    When run sh "$script_abs" "$repo"
    The status should not equal 0
    The stderr should include 'Graphify-Labs/graphify#3075'
    The stderr should include 'extract.py'
    The path "$package/rcfile.py" should not be exist
    Assert [ "$(cmp -s "$package/extract.py" "$fixture/extract.py.mismatch"; printf '%s' "$?")" -eq 0 ]
    The file "$repo/graphify-out/cache/ast/entry.json" should be exist
  End

  It 'patches only the package tree named by PFB_GRAPHIFY_PACKAGE_DIR'
    other="$fixture/other site/graphify"
    mkdir -p "$other"
    true > "$other/__init__.py"
    cp "$fixture/extract.py.before" "$other/extract.py"
    When run sh "$script_abs" "$repo"
    The status should equal 0
    The stderr should include "$package"
    The path "$other/rcfile.py" should not be exist
    Assert [ "$(cmp -s "$other/extract.py" "$fixture/extract.py.before"; printf '%s' "$?")" -eq 0 ]
  End

  It 'defaults to the current git worktree root when run from a subdirectory'
    When run sh -c 'cd "$1/scripts" && exec sh "$2"' _ "$repo" "$script_abs"
    The status should equal 0
    The stderr should include 'purged'
    The path "$repo/graphify-out/cache/ast" should not be exist
  End

  It 'reports an install hint when Graphify is absent and no package tree is named'
    unset PFB_GRAPHIFY_PACKAGE_DIR
    minimal_path="$(dirname "$(command -v git)"):$(dirname "$(command -v dirname)"):$(dirname "$(command -v sh)")"
    When run env PATH="$minimal_path" sh "$script_abs" "$repo"
    The status should not equal 0
    The stderr should include 'uv tool install --upgrade graphifyy'
    The file "$repo/graphify-out/cache/ast/entry.json" should be exist
  End

  It 'skips with a warning when the graphify on PATH is not a Python program'
    unset PFB_GRAPHIFY_PACKAGE_DIR
    stubdir="$fixture/stub bin"
    mkdir -p "$stubdir"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/graphify"
    printf '#!/bin/sh\nexit 1\n' > "$stubdir/python3"
    chmod +x "$stubdir/graphify" "$stubdir/python3"
    When run env PATH="$stubdir:$PATH" sh "$script_abs" "$repo"
    The status should equal 0
    The stderr should include 'cannot locate'
    The path "$package/rcfile.py" should not be exist
    The file "$repo/graphify-out/cache/ast/entry.json" should be exist
  End

  It 'falls back to the ambient python3 when the graphify wrapper hides its interpreter'
    unset PFB_GRAPHIFY_PACKAGE_DIR
    stubdir="$fixture/stub bin"
    mkdir -p "$stubdir"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/graphify"
    cat > "$stubdir/python3" <<PYTHON3
#!/bin/sh
case "\$2" in
  *graphify.__file__*) printf '%s\n' "$package" ;;
  *) exit 1 ;;
esac
PYTHON3
    chmod +x "$stubdir/graphify" "$stubdir/python3"
    When run env PATH="$stubdir:$PATH" sh "$script_abs" "$repo"
    The status should equal 0
    The stderr should include 'Graphify-Labs/graphify#3075'
    The contents of file "$package/rcfile.py" should include 'activate_language_overrides'
    The path "$repo/graphify-out/cache/ast" should not be exist
  End

  It 'rejects a target that is not a git worktree'
    When run sh "$script_abs" "$fixture/not a checkout"
    The status should equal 2
    The stderr should include 'is not a git worktree'
    The path "$package/rcfile.py" should not be exist
  End

  It 'rejects more than one repository argument'
    When run sh "$script_abs" "$repo" extra
    The status should equal 2
    The stderr should include 'usage: patch-graphify.sh [REPOSITORY]'
    The path "$package/rcfile.py" should not be exist
  End
End
