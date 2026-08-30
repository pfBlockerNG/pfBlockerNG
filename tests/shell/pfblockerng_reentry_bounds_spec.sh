#shellcheck shell=sh
# pfblockerng_reentry_bounds_spec.sh — issue #2016 / #2488.
#
# Every BLOCKING nested pfblockerng.php re-entry in pfblockerng.sh goes through ONE seam,
# pfb_reentry(), which runs the child under timeout(1) in default (reaper) mode and, on
# 124, names the expiry on stdout and in ${errorlog}. #2488 is the degradation class the
# budget must be immune to: an empty / non-numeric / zero pfbreentrytimeout floors to the
# function's own default, so no knob can turn a capped wait back into an unbounded one.
#
# Hermetic and bounded. pathtimeout is either a recording shim (argv rows, which run
# nothing) or the REAL timeout(1) resolved from PATH (expiry rows); pathphp is always a
# fake interpreter in the example's tmpdir whose longest branch sleeps 30s, so even a
# regression that drops the bound entirely fails a row instead of hanging the suite.
#
# shellcheck disable=SC2329  # every function here is invoked indirectly: by shellspec's
#   Before/After/BeforeAll hooks or by name from a `When call` line.
# shellcheck disable=SC2034  # the path*/log/alias/dedup assignments are pfblockerng.sh
#   globals -- they are read by the sourced production code, not by this file.

# Recording stand-in for timeout(1): appends its own argv to <its dir>/argv.rec and exits
# 0 without running anything, so a row can assert exactly what the seam composed.
make_timeout_recorder() {
  pathtimeout="${work}/timeout"
  cat > "${pathtimeout}" <<'EOF'
#!/bin/sh
{
	printf 'ARGV=%s\n' "$*"
	while [ $# -gt 0 ]; do
		case "$1" in
		-s|-k) shift 2 ;;
		*) break ;;
		esac
	done
	printf 'DURATION=%s\n' "${1-}"
	printf 'PHP=%s\n' "${2-}"
	printf 'SCRIPT=%s\n' "${3-}"
	if [ $# -gt 3 ]; then
		shift 3
		for _a in "$@"; do printf 'ARG=%s\n' "$_a"; done
	fi
} >> "$(dirname "$0")/argv.rec"
exit 0
EOF
  chmod +x "${pathtimeout}"
  rec="${work}/argv.rec"
  true > "${rec}"
}

# Fake interpreter for pathphp: ignores $1 (the re-entry target) and branches on the verb.
make_fake_php() {
  pathphp="${work}/php"
  cat > "${pathphp}" <<'EOF'
#!/bin/sh
shift
case "$1" in
quick) echo "child ran: $1"; exit 0 ;;
hang)  sleep 30; exit 0 ;;
boom)  echo 'child failed'; exit 7 ;;
esac
exit 0
EOF
  chmod +x "${pathphp}"
}

# Grade the duration the seam actually handed timeout(1): OK <secs> for a non-empty
# digits-only word, BAD <secs> for anything an AND-list bound could degrade into.
reentry_duration() {
  pfb_reentry "$@" >/dev/null 2>&1
  _d="$(sed -n 's/^DURATION=//p' "${rec}" | head -n 1)"
  case "${_d}" in
  ''|*[!0-9]*) printf 'BAD %s\n' "${_d}" ;;
  *) printf 'OK %s\n' "${_d}" ;;
  esac
}

# reentry_duration_for BUDGET VERB… — '-' leaves pfbreentrytimeout unset.
reentry_duration_for() {
  if [ "$1" = '-' ]; then
    unset pfbreentrytimeout
  else
    pfbreentrytimeout="$1"
  fi
  shift
  reentry_duration "$@"
}

# The verb + arguments the seam handed the child, one recorded word each, '|'-joined.
reentry_args() {
  pfb_reentry "$@" >/dev/null 2>&1
  sed -n 's/^ARG=//p' "${rec}" | tr '\n' '|'
}

# The interpreter + re-entry target the seam handed timeout(1), '|'-joined.
reentry_target() {
  pfb_reentry "$@" >/dev/null 2>&1
  sed -n -e 's/^PHP=//p' -e 's/^SCRIPT=//p' "${rec}" | tr '\n' '|'
}

# Drive the seam under the REAL timeout(1). A gate whose tool is missing is a failure,
# never a skip; and a wait that outlives its budget prints SALVAGE so the row fails
# loudly instead of passing slowly.
run_bounded_reentry() {
  pathtimeout="$(command -v timeout 2>/dev/null)"
  if [ -z "${pathtimeout}" ]; then
    echo 'MISSING-TIMEOUT-BINARY: these rows need a real timeout(1) on PATH'
    return 1
  fi
  _t0="$(date +%s)"
  pfb_reentry "$@"
  _rc=$?
  _el=$(( $(date +%s) - _t0 ))
  if [ "${_el}" -gt 15 ]; then
    echo "SALVAGE: stuck/environment -- the re-entry took ${_el}s against a ${pfbreentrytimeout}s budget"
  fi
  return "${_rc}"
}

# Drive a shipped pfblockerng.sh function and report the verb + args the seam recorded.
# Its own chatter is discarded: the pin is the recorded re-entry, not the progress text.
recorded_reentry_of() {
  "$1" >/dev/null 2>&1
  sed -n 's/^ARG=//p' "${rec}" | tr '\n' '|'
}

# The shipped init defaults for the re-entry seam. pfb_source() skips the PFB_SOURCED
# init block, so these get a source pin; sorted so the order inside the block is free.
init_defaults() {
  grep -E '^[[:space:]]*(pathphp|pathpfbphp)=' "${PFB_PKGDIR}/pfblockerng.sh" \
    | sed 's/^[[:space:]]*//' | LC_ALL=C sort | tr '\n' '|'
}

# The shipped init line that seeds the ONE global budget (issue #2851): the stored
# General -> Advanced value, normalized through pfb_reentry_timeout() before the seam
# can ever see it. A source pin for the same reason as init_defaults above.
init_budget_line() {
  grep -E '^[[:space:]]*pfbreentrytimeout=' "${PFB_PKGDIR}/pfblockerng.sh" | sed 's/^[[:space:]]*//'
}

# The top-level `dnsbl-control` case arm runs after the PFB_SOURCED guard returns, so it
# has no off-appliance driver: pin its shipped text, both halves.
dnsbl_control_arm() {
  sed -n '/^[[:space:]]*dnsbl-control)/,/^[[:space:]]*;;/p' "${PFB_PKGDIR}/pfblockerng.sh"
}

Describe 'pfb_reentry() budget floor (issue #2016/#2488)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbrebudget.XXXXXX")"
    errorlog="${work}/error.log"; true > "${errorlog}"
    pathpfbphp="${work}/pfblockerng.php"
    make_fake_php
    make_timeout_recorder
  }
  cleanup() { rm -rf "${work}"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'floors an unset budget to its own positive default'
    When call reentry_duration_for - probe
    The output should equal 'OK 1800'
  End

  It 'floors an empty budget'
    When call reentry_duration_for '' probe
    The output should equal 'OK 1800'
  End

  It 'floors a non-numeric budget'
    When call reentry_duration_for abc probe
    The output should equal 'OK 1800'
  End

  It 'floors a zero budget'
    When call reentry_duration_for 0 probe
    The output should equal 'OK 1800'
  End

  It 'floors a budget carrying a trailing space'
    When call reentry_duration_for '7 ' probe
    The output should equal 'OK 1800'
  End

  It 'honours a huge all-digit budget'
    When call reentry_duration_for 99999999 probe
    The output should equal 'OK 99999999'
  End

  It 'honours a valid budget'
    When call reentry_duration_for 42 probe
    The output should equal 'OK 42'
  End

  It 'never runs the child in --foreground mode'
    # Default (reaper) mode is mandatory: a hung download pass must die as a whole tree;
    # --foreground would signal php alone and orphan a blocked fetch.
    When call reentry_duration_for 42 probe
    The output should equal 'OK 42'
    The contents of file "${rec}" should include 'ARGV=-s TERM -k 5 42'
    The contents of file "${rec}" should not include '--foreground'
  End

  It 'runs the single-sourced interpreter against the single-sourced re-entry target'
    When call reentry_target probe
    The output should equal "${pathphp}|${pathpfbphp}|"
  End

  It 'hands the child every argument as its own word'
    When call reentry_args dnsbl-control disable 300
    The output should equal 'dnsbl-control|disable|300|'
  End

  It 'keeps an argument containing a space as one word'
    When call reentry_args probe 'two words'
    The output should equal 'probe|two words|'
  End
End

Describe 'pfb_reentry() expiry and pass-through (issue #2016)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbreexec.XXXXXX")"
    errorlog="${work}/error.log"; true > "${errorlog}"
    pathpfbphp="${work}/pfblockerng.php"
    pfbreentrytimeout=2
    make_fake_php
  }
  cleanup() { rm -rf "${work}"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'returns 124 and names the expiry on stdout and in the error log'
    When call run_bounded_reentry hang
    The status should equal 124
    The stdout should include 'Nested pfblockerng.php [ hang ] TIMED OUT after 2s and was killed'
    The stdout should not include 'SALVAGE:'
    The contents of file "${errorlog}" should include 'Nested pfblockerng.php [ hang ] TIMED OUT after 2s and was killed'
  End

  It 'returns 0 for a healthy re-entry, runs the child, and names no expiry'
    When call run_bounded_reentry quick
    The status should be success
    The stdout should include 'child ran: quick'
    The stdout should not include 'TIMED OUT'
    The stdout should not include 'SALVAGE:'
    The contents of file "${errorlog}" should not include 'TIMED OUT'
  End

  It 'returns a plain non-zero child status unchanged and names no expiry'
    # The 124 branch must discriminate, not fire on every failing child.
    When call run_bounded_reentry boom
    The status should equal 7
    The stdout should include 'child failed'
    The stdout should not include 'TIMED OUT'
    The contents of file "${errorlog}" should not include 'TIMED OUT'
  End
End

Describe 'every shell re-entry call site reaches the bounded seam (issue #2016)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbreroute.XXXXXX")"
    errorlog="${work}/error.log"; true > "${errorlog}"
    geoiplog="${work}/geoip.log"; true > "${geoiplog}"
    extraslog="${work}/extras.log"; true > "${extraslog}"
    now='2026-08-28 00:00:00'
    pathpfbphp="${work}/pfblockerng.php"
    make_fake_php
    make_timeout_recorder

    # whoisconvert(): an ASN entry with asn.csv absent is the branch that re-enters.
    pfborig="${work}/orig/"; mkdir -p "${pfborig}"
    alias='RouteList'
    max='_v4'
    dedup='AS64500'
    pathasncsv="${work}/absent-asn.csv"
    pathhost="${work}/host"
    printf '#!/bin/sh\nexit 1\n' > "${pathhost}"; chmod +x "${pathhost}"

    # iptoasn() / reputation_depends(): mmdblookup present, its databases absent.
    pathgeoip="${work}/mmdblookup"
    printf '#!/bin/sh\nexit 0\n' > "${pathgeoip}"; chmod +x "${pathgeoip}"
    pathasndat="${work}/absent-asn.mmdb"
    pathgeoipdat="${work}/absent-country.mmdb"
  }
  cleanup() { rm -rf "${work}"; }
  BeforeAll 'pfb_source'
  Before 'setup'
  After 'cleanup'

  It 'whoisconvert() fetches the IPinfo databases through the seam'
    When call recorded_reentry_of whoisconvert
    The output should equal 'asn_shell|scheduled|'
  End

  It 'iptoasn() fetches the IPinfo databases through the seam'
    When call recorded_reentry_of iptoasn
    The output should equal 'asn|'
  End

  It 'reputation_depends() fetches the MaxMind database through the seam'
    When call recorded_reentry_of reputation_depends
    The output should equal 'bu|scheduled|'
  End

  It 'the top-level dnsbl-control arm forwards through the seam'
    When call dnsbl_control_arm
    The output should include 'pfb_reentry dnsbl-control "$@"'
    The output should include 'exitnow "$?"'
    The output should not include '/usr/local/bin/php'
  End

  It 'ships the re-entry interpreter and target as init defaults'
    When call init_defaults
    The output should equal 'pathpfbphp=/usr/local/www/pfblockerng/pfblockerng.php|pathphp=/usr/local/bin/php|'
  End

  It 'seeds the one global budget from the stored setting through the resolver'
    # issue #2851: the ceiling is no longer a hardcoded init literal -- it is the ONE
    # registered gen-section key, normalized before any seam can see it.
    When call init_budget_line
    The output should include 'read_xml_tag.sh'
    The output should include 'installedpackages/pfblockerng/config/pfb_reentry_timeout'
    The output should include 'pfb_reentry_timeout "$('
  End
End

Describe 'pfb_reentry_timeout() accepted window (issue #2851)'
  # The shell half of the ONE global nested-pass budget: whole seconds 60..7200
  # inclusive are honoured, and every other stored value -- absent, empty, non-numeric,
  # decimal, negative, zero, below-60, above-7200, overflow -- resolves to the finite
  # 1800-second default. The PHP half runs the same matrix in
  # tests/php/ReentryTimeoutSettingTest.php, and that file also pins the two windows
  # against each other so they cannot drift apart.
  BeforeAll 'pfb_source'

  It 'honours the minimum'
    When call pfb_reentry_timeout 60
    The output should equal 60
  End

  It 'honours one second above the minimum'
    When call pfb_reentry_timeout 61
    The output should equal 61
  End

  It 'honours a mid-range budget'
    When call pfb_reentry_timeout 900
    The output should equal 900
  End

  It 'honours the default spelled out'
    When call pfb_reentry_timeout 1800
    The output should equal 1800
  End

  It 'honours one second below the maximum'
    When call pfb_reentry_timeout 7199
    The output should equal 7199
  End

  It 'honours the maximum'
    When call pfb_reentry_timeout 7200
    The output should equal 7200
  End

  It 'reads a leading-zero digit run as decimal, never as octal'
    # POSIX test(1) compares decimal, so 0060 is sixty seconds here and sixty seconds in
    # PHP -- arithmetic expansion would have made it octal forty-eight.
    When call pfb_reentry_timeout 0060
    The output should equal 0060
  End

  It 'falls back when no value is stored at all'
    When call pfb_reentry_timeout
    The output should equal 1800
  End

  It 'falls back on an empty stored value'
    When call pfb_reentry_timeout ''
    The output should equal 1800
  End

  It 'falls back on a non-numeric stored value'
    When call pfb_reentry_timeout abc
    The output should equal 1800
  End

  It 'falls back on a decimal stored value'
    When call pfb_reentry_timeout 1.5
    The output should equal 1800
  End

  It 'falls back on fractional seconds'
    When call pfb_reentry_timeout 60.5
    The output should equal 1800
  End

  It 'falls back on a negative stored value'
    When call pfb_reentry_timeout -5
    The output should equal 1800
  End

  It 'falls back on zero'
    When call pfb_reentry_timeout 0
    The output should equal 1800
  End

  It 'falls back one second below the minimum'
    When call pfb_reentry_timeout 59
    The output should equal 1800
  End

  It 'falls back one second above the maximum'
    When call pfb_reentry_timeout 7201
    The output should equal 1800
  End

  It 'falls back far above the maximum'
    When call pfb_reentry_timeout 99999999
    The output should equal 1800
  End

  It 'falls back on a 64-bit overflow instead of saturating into the window'
    When call pfb_reentry_timeout 99999999999999999999
    The output should equal 1800
  End

  It 'falls back on a leading space'
    When call pfb_reentry_timeout ' 900'
    The output should equal 1800
  End

  It 'falls back on a trailing space'
    When call pfb_reentry_timeout '900 '
    The output should equal 1800
  End

  It 'falls back on a signed value'
    When call pfb_reentry_timeout '+900'
    The output should equal 1800
  End

  It 'falls back on exponent notation'
    When call pfb_reentry_timeout 1e3
    The output should equal 1800
  End

  It 'falls back on a hexadecimal value'
    When call pfb_reentry_timeout 0x384
    The output should equal 1800
  End

  It 'falls back on a thousands separator'
    When call pfb_reentry_timeout '1,800'
    The output should equal 1800
  End
End
