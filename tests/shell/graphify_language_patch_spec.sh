#shellcheck shell=sh
# Vendored Graphify language-override patch (issue #2810, upstream
# Graphify-Labs/graphify#3075). The script resolves its patch from its own checkout and
# the package to patch from the interpreter named on the shebang of the `graphify` on
# PATH, so every example runs a copy of the script inside a fixture checkout carrying a
# synthetic two-file patch, behind a fixture `graphify` whose shebang names a fixture
# interpreter that answers for a throwaway package tree. The two isolation examples name
# the ambient python3 instead -- a stub can neither honour nor ignore -I -- and the
# PYTHONPATH one reaches it through a venv-shaped fixture that owns the throwaway
# package. Nothing here reaches the real installed Graphify.

Describe 'patch-graphify.sh'
  project_root="${SHELLSPEC_PROJECT_ROOT:-$PWD}"

  # The ambient python3 imports whatever graphify IT can see, which is why the script
  # refuses to use it; the hostile-cwd example still needs a real one to import with.
  ambient_python3_has_graphify() { python3 -I -c 'import graphify' >/dev/null 2>&1; }

  # Stand-in for the interpreter inside a uv tool venv: it answers the script's two
  # probes for the fixture package instead of importing anything. The override-API
  # answer is read back off the package tree, so it flips exactly when a run patches
  # it -- an already-provided override and a fresh apply cannot both be faked.
  make_interpreter() {
    mkdir -p "$(dirname "$1")"
    cat > "$1" <<INTERPRETER
#!/bin/sh
case "\$*" in
  *os.path.dirname*) printf '%s\n' '$package' ;;
  *activate_language_overrides*)
    grep -q 'def activate_language_overrides' '$package/rcfile.py' 2>/dev/null || exit 1
    ;;
  *) exit 9 ;;
esac
INTERPRETER
    chmod +x "$1"
  }

  # A real uv tool venv, built for the decoy example, which needs a REAL interpreter: a
  # stub can neither honour nor ignore -I, so no example resting on one can observe the
  # isolation. A symlinked python3 plus a pyvenv.cfg naming its home makes that
  # interpreter treat $fixture/venv as its own prefix, so it finds the throwaway package
  # on its DEFAULT sys.path with nothing injected, and system site packages are excluded
  # so a machine-installed Graphify cannot answer either. The minor version is read off
  # the interpreter, never hardcoded: it names the site-packages directory.
  make_venv() {
    real_python3=$(command -v python3) || return 1
    pyver=$("$real_python3" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")') || return 1
    venv_package="$fixture/venv/lib/python$pyver/site-packages/graphify"
    mkdir -p "$fixture/venv/bin" "$venv_package" || return 1
    ln -s "$real_python3" "$fixture/venv/bin/python3" || return 1
    printf 'home = %s\ninclude-system-site-packages = false\nversion = %s\n' \
      "$(dirname "$real_python3")" "$pyver" > "$fixture/venv/pyvenv.cfg" || return 1
    cp "$package/__init__.py" "$package/extract.py" "$venv_package/" || return 1
    printf '#!%s\nexit 0\n' "$fixture/venv/bin/python3" > "$stubdir/graphify" || return 1
  }

  setup() {
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/graphify_language_patch.XXXXXX") || return 1
    fixture=$(CDPATH='' cd "$fixture" && pwd -P) || return 1

    checkout="$fixture/checkout root"
    mkdir -p "$checkout/scripts/agent" "$checkout/.agents/patches" || return 1
    cp "$project_root/scripts/agent/patch-graphify.sh" "$checkout/scripts/agent/" || return 1
    cp "$project_root/scripts/agent/agent_env.sh" "$checkout/scripts/agent/" || return 1
    script_abs="$checkout/scripts/agent/patch-graphify.sh"

    cat > "$checkout/.agents/patches/graphify-3075-language-overrides.patch" <<'PATCH'
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

    # A uv tool venv's own interpreter, named on the CLI's shebang -- the only path the
    # script trusts. Deliberately NOT on PATH: an example that neuters the shebang must
    # not be able to reach a working interpreter by any other route.
    interpreter="$fixture/toolvenv/bin/python3"
    make_interpreter "$interpreter"

    stubdir="$fixture/toolbin"
    mkdir -p "$stubdir"
    printf '#!%s\nexit 0\n' "$interpreter" > "$stubdir/graphify"
    chmod +x "$stubdir/graphify"
    PATH="$stubdir:$PATH"
    export PATH
  }

  cleanup() { rm -rf "$fixture"; }
  BeforeEach 'setup'
  AfterEach 'cleanup'

  It 'applies the vendored patch to the package its shebang interpreter reports'
    When run sh "$script_abs"
    The status should equal 0
    The stderr should include 'Graphify-Labs/graphify#3075'
    The stderr should include "$package"
    The contents of file "$package/rcfile.py" should include 'activate_language_overrides'
    The contents of file "$package/extract.py" should include 'SUFFIX_OVERRIDES = True'
  End

  It 'no-ops when the package already provides the override API'
    cat > "$package/rcfile.py" <<'RCFILE'
def activate_language_overrides(root):
    return {}
RCFILE
    When run sh "$script_abs"
    The status should equal 0
    The stderr should include 'already provides'
    Assert [ "$(cmp -s "$package/extract.py" "$fixture/extract.py.before"; printf '%s' "$?")" -eq 0 ]
  End

  It 'fails loudly and changes nothing when the vendored patch does not apply'
    printf '%s\n' 'unrelated module' > "$package/extract.py"
    cp "$package/extract.py" "$fixture/extract.py.mismatch"
    When run sh "$script_abs"
    The status should not equal 0
    The stderr should include 'Graphify-Labs/graphify#3075'
    The stderr should include 'extract.py'
    The path "$package/rcfile.py" should not be exist
    Assert [ "$(cmp -s "$package/extract.py" "$fixture/extract.py.mismatch"; printf '%s' "$?")" -eq 0 ]
  End

  It 'leaves no patch backup behind an apply that lands with an offset'
    # A CLEAN apply writes no backup on either implementation this repository runs on,
    # so a planted stale file would prove nothing. What DOES make patch write one is an
    # offset apply: one extra line ahead of the hunk shifts it, and GNU patch 2.8 and
    # Apple patch 2.0 both then write `extract.py.orig` unless the apply passes
    # --no-backup-if-mismatch.
    { printf '%s\n' '# shifts the hunk by one line'; cat "$package/extract.py"; } > "$fixture/shifted"
    mv "$fixture/shifted" "$package/extract.py"
    When run sh "$script_abs"
    The status should equal 0
    The stderr should include 'applied Graphify-Labs/graphify#3075'
    The contents of file "$package/rcfile.py" should include 'activate_language_overrides'
    The contents of file "$package/extract.py" should include 'SUFFIX_OVERRIDES = True'
    Assert [ -z "$(find "$fixture/site packages" \( -name '*.orig' -o -name '*.~[0-9]*~' \) -print)" ]
  End

  It 'leaves no backup and touches no neighbour for a patched path holding a space'
    # The tab-terminated name is the only space-bearing form BOTH implementations
    # resolve -- Apple patch rejects git's C-quoted form outright. So any parser that
    # reads the `+++` line and truncates at whitespace sees `graphify/with`: it misses
    # the real backup and hits the unrelated neighbour planted below.
    # --no-backup-if-mismatch needs no such parser, and this example goes red the
    # moment one comes back.
    {
      printf 'diff --git a/graphify/with space.py b/graphify/with space.py\n'
      printf -- '--- a/graphify/with space.py\t1970-01-01\n'
      printf '+++ b/graphify/with space.py\t1970-01-01\n'
      printf '@@ -1,1 +1,2 @@\n SPACED = True\n+SPACED_OVERRIDE = True\n'
    } >> "$checkout/.agents/patches/graphify-3075-language-overrides.patch"
    # The pad line shifts the hunk, which is what makes patch want a backup at all.
    { printf '%s\n' '# pad'; printf '%s\n' 'SPACED = True'; } > "$package/with space.py"
    printf 'neighbour\n' > "$package/with.orig"
    When run sh "$script_abs"
    The status should equal 0
    The stderr should include 'applied Graphify-Labs/graphify#3075'
    The contents of file "$package/with space.py" should include 'SPACED_OVERRIDE = True'
    The path "$package/with.orig" should be exist
    Assert [ -z "$(find "$fixture/site packages" \( -name '*.~[0-9]*~' -o \( -name '*.orig' ! -name 'with.orig' \) \) -print)" ]
  End

  It 'skips with a warning when the graphify shebang does not name a Python interpreter'
    # The ambient python3 is NOT a fallback: another interpreter imports another
    # graphify, so falling back patches an unrelated package and reports success. A
    # working python3 sits on PATH here precisely to prove nothing reaches for it.
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/graphify"
    make_interpreter "$stubdir/python3"
    When run sh "$script_abs"
    The status should equal 0
    The stderr should include 'does not name a Python interpreter'
    The path "$package/rcfile.py" should not be exist
    Assert [ "$(cmp -s "$package/extract.py" "$fixture/extract.py.before"; printf '%s' "$?")" -eq 0 ]
  End

  It 'skips with a warning when the shebang interpreter cannot import graphify'
    printf '#!/bin/sh\nexit 1\n' > "$interpreter"
    When run sh "$script_abs"
    The status should equal 0
    The stderr should include 'cannot locate'
    The path "$package/rcfile.py" should not be exist
  End

  It 'ignores a hostile module in the working directory it is called from'
    # Both probes run isolated (-I), which keeps the caller's directory off sys.path, so
    # a graphify.py beside the caller can neither answer for the installed package nor
    # execute at all.
    Skip if 'the ambient python3 imports a graphify of its own' ambient_python3_has_graphify
    hostile="$fixture/hostile cwd"
    mkdir -p "$hostile"
    cat > "$hostile/graphify.py" <<HOSTILE
import pathlib
pathlib.Path('$hostile/executed').write_text('executed')
__file__ = '$hostile/graphify.py'
HOSTILE
    printf '#!%s\nexit 0\n' "$(command -v python3)" > "$stubdir/graphify"
    When run sh -c 'cd "$1" && exec sh "$2"' _ "$hostile" "$script_abs"
    The status should equal 0
    The stderr should include 'cannot locate'
    The path "$hostile/executed" should not be exist
    The path "$hostile/rcfile.py" should not be exist
    The path "$package/rcfile.py" should not be exist
  End

  It 'ignores a decoy graphify injected through PYTHONPATH'
    # The other half of the isolation: -I drops PYTHONPATH, the user site directory and
    # any .pth-injected path, so only the interpreter's own package can answer. A stub
    # interpreter can neither honour nor ignore -I, so this example runs a real one out
    # of a venv-shaped fixture. Drop -I and the decoy imports first, the script resolves
    # the DECOY as the installed package, and the run patches the wrong tree.
    make_venv
    decoy="$fixture/decoy/graphify"
    mkdir -p "$decoy"
    true > "$decoy/__init__.py"
    printf '%s\n' 'DECOY = True' > "$decoy/extract.py"
    cp "$decoy/extract.py" "$fixture/decoy.extract.before"
    When run env PYTHONPATH="$fixture/decoy" sh "$script_abs"
    The status should equal 0
    The stderr should include 'applied Graphify-Labs/graphify#3075'
    The stderr should include "$venv_package"
    The contents of file "$venv_package/rcfile.py" should include 'activate_language_overrides'
    The contents of file "$venv_package/extract.py" should include 'SUFFIX_OVERRIDES = True'
    The path "$decoy/rcfile.py" should not be exist
    Assert [ "$(cmp -s "$decoy/extract.py" "$fixture/decoy.extract.before"; printf '%s' "$?")" -eq 0 ]
  End

  It 'fails with the install hint when graphify is absent from PATH'
    minimal_path="$(dirname "$(command -v sed)"):$(dirname "$(command -v sh)"):$(dirname "$(command -v dirname)")"
    When run env PATH="$minimal_path" sh "$script_abs"
    The status should not equal 0
    The stderr should include 'uv tool install --upgrade graphifyy'
    The path "$package/rcfile.py" should not be exist
  End
End
