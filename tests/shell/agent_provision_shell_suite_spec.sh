#shellcheck shell=sh
# provision-shell-suite.sh pins the shellspec suite's CI-only inputs onto a dev host
# (issue #3189): the real FireHOL iprange and the comma-decimal de_DE.UTF-8 locale,
# verified with the same checks .github/workflows/test.yml runs. The privileged
# commands are stubbed, so these examples pin WHICH commands run, the idempotent
# re-run on an already-provisioned host, and that a failed verification is loud --
# never the packages themselves.

Describe 'provision-shell-suite.sh'
  script="${PFB_ROOT}/scripts/agent/provision-shell-suite.sh"
  sandbox="$SHELLSPEC_TMPBASE/provision"
  stubdir="$sandbox/bin"
  statedir="$sandbox/state"
  # The script's children see ONLY this PATH: core/ carries symlinks to the real
  # unprivileged tools, bin/ the stubs for everything privileged or probed -- no
  # real iprange or locale on the host can leak into the fixture.
  suitepath="$stubdir:$sandbox/core"

  make_sandbox() {
    rm -rf "$sandbox"
    mkdir -p "$stubdir" "$statedir" "$sandbox/core"
    ln -s /usr/bin/id "$sandbox/core/id"
    ln -s /usr/bin/grep "$sandbox/core/grep"
    ln -s /usr/bin/chmod "$sandbox/core/chmod"
    # env resolves `sh` through the NEW PATH, so the sandbox must carry the shell too.
    ln -s /usr/bin/sh "$sandbox/core/sh"
    printf '#!/bin/sh\nexec "$@"\n' > "$stubdir/sudo"
    # An iprange install must make the binary probe succeed, like the real package.
    {
      printf '#!/bin/sh\necho "$*" >> "%s"\n' "$statedir/apt"
      printf 'case "$*" in *iprange*) printf "#!/bin/sh\\nexit 0\\n" > "%s/iprange"; chmod +x "%s/iprange";; esac\n' "$stubdir" "$stubdir"
    } > "$stubdir/apt-get"
    printf '#!/bin/sh\necho "$*" >> "%s"\necho "$*" >> "%s"\n' "$statedir/locales" "$statedir/locale-gen" > "$stubdir/locale-gen"
    printf '#!/bin/sh\necho "$*" >> "%s"\n' "$statedir/alt" > "$stubdir/update-alternatives"
    cat > "$stubdir/locale" <<STUB
#!/bin/sh
have() { [ -f "$statedir/locales" ] && grep -q de_DE "$statedir/locales"; }
case \${1:-} in
-a)
  if have; then printf 'C\\nC.utf8\\nde_DE.utf8\\n'; else printf 'C\\nC.utf8\\n'; fi
  ;;
-k)
  if have && [ "\${LC_ALL:-}" = de_DE.UTF-8 ]; then printf 'decimal_point=","\\n'; else printf 'decimal_point="."\\n'; fi
  ;;
esac
STUB
    cat > "$stubdir/awk" <<STUB
#!/bin/sh
if [ "\${LC_ALL:-}" = de_DE.UTF-8 ] && [ -f "$statedir/locales" ] && grep -q de_DE "$statedir/locales" && [ -z "\${PFB_SPEC_AWK_DOTTED:-}" ]; then
  printf '1,50'
else
  printf '1.50'
fi
STUB
    chmod +x "$stubdir"/*
  }

  seeded() {
    make_sandbox
    printf 'de_DE.UTF-8\n' > "$statedir/locales"
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/iprange"
    chmod +x "$stubdir/iprange"
  }

  cleanup() { rm -rf "$sandbox"; }
  Before 'make_sandbox'
  After 'cleanup'

  It 'installs iprange and the de_DE.UTF-8 locale when both are missing'
    When run env PATH="$suitepath" sh "$script"
    The status should equal 0
    The contents of file "$statedir/apt" should include 'update'
    The contents of file "$statedir/apt" should include 'install -y iprange'
    The contents of file "$statedir/apt" should include 'install -y --no-install-recommends mawk locales'
    The contents of file "$statedir/alt" should include '--set awk /usr/bin/mawk'
    The contents of file "$statedir/locale-gen" should include 'de_DE.UTF-8'
    The lines of output should equal 1
    The output should include 'shell suite provisioned'
  End

  It 're-runs without installing anything when the host is already provisioned'
    seeded
    When run env PATH="$suitepath" sh "$script"
    The status should equal 0
    Assert [ ! -e "$statedir/apt" ]
    Assert [ ! -e "$statedir/locale-gen" ]
    The output should include 'shell suite provisioned'
  End

  It 'fails loudly when the awk decimal check still fails after provisioning'
    seeded
    When run env PATH="$suitepath" PFB_SPEC_AWK_DOTTED=1 sh "$script"
    The status should equal 1
    The stderr should include 'provision failed'
    The stderr should include 'awk'
  End
End
