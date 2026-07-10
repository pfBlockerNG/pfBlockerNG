#shellcheck shell=sh
# build-repo.sh fallback catalog layout (issue #1081).
#
# Two defects are pinned here:
#
#   1) The canonical .pkg copy was named "<name> <version>.pkg" (a SPACE --
#      pkg_nv used '%n %v'), but `pkg repo` records and clients fetch the
#      hyphenated "<name>-<version>.pkg"; the served path never resolved.
#
#   2) The catalog was laid out under release/<ABI>/, contradicting ADR-20's
#      varver keying AND this script's own --print-conf url
#      (release/<varver>/<arch>). The varver cannot be derived from the
#      package (an ABI is not 1:1 with an edition/version), so the build mode
#      now REQUIRES --varver and lays out release/<varver>/<arch>/.
#
# The pkg(8) stub serves `query -F` from key=value lines inside the fake .pkg
# and materialises `pkg repo <dir>` as a packagesite.pkg marker, so the layout
# is asserted without a libpkg binary.

Describe 'build-repo.sh catalog layout (issue #1081)'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/brlayout.XXXXXX")"
    mkdir -p "${work}/bin" "${work}/in" "${work}/out"

    cat > "${work}/bin/pkg" <<'EOF'
#!/bin/sh
cmd="$1"; shift
case "$cmd" in
	query)
		[ "$1" = "-F" ] || exit 64
		f="$2"; fmt="$3"
		name="$(sed -n 's/^name=//p' "$f")"
		version="$(sed -n 's/^version=//p' "$f")"
		abi="$(sed -n 's/^abi=//p' "$f")"
		case "$fmt" in
			'%q')    printf '%s\n' "$abi" ;;
			'%n %v') printf '%s %s\n' "$name" "$version" ;;
			'%n-%v') printf '%s-%s\n' "$name" "$version" ;;
			'%dn')   sed -n 's/^dep=//p' "$f" ;;
			*) exit 64 ;;
		esac ;;
	repo)
		touch "$1/packagesite.pkg" ;;
	*) exit 64 ;;
esac
EOF
    chmod +x "${work}/bin/pkg"
  }
  cleanup() { rm -rf "$work"; }
  Before 'setup'
  After 'cleanup'

  fake_pkg() { # $1 file, $2 name, $3 version, $4 abi, $5.. deps
    _f="${work}/in/$1"; shift
    { printf 'name=%s\nversion=%s\nabi=%s\n' "$1" "$2" "$3"; shift 3
      for d in "$@"; do printf 'dep=%s\n' "$d"; done
    } > "$_f"
  }
  run_build() {
    PATH="${work}/bin:${PATH}" PKG_BIN=pkg \
      sh "${PFB_ROOT}/scripts/build-repo.sh" --in "${work}/in" --out "${work}/out" "$@"
  }

  It 'lays the catalog out under release/<varver>/<arch>/ with hyphenated names'
    fake_pkg a.pkg pfSense-pkg-pfBlockerNG 4.0.1 FreeBSD:15:amd64 php83
    fake_pkg b.pkg pfSense-pkg-pfBlockerNG 4.0.2 FreeBSD:15:amd64 php83
    When call run_build --varver ce-2.8
    The status should be success
    The stderr should include 'release/ce-2.8/amd64'
    # Hyphenated canonical names (defect 1) in the varver bucket (defect 2)...
    The path "${work}/out/release/ce-2.8/amd64/pfSense-pkg-pfBlockerNG-4.0.1.pkg" should be exist
    The path "${work}/out/release/ce-2.8/amd64/pfSense-pkg-pfBlockerNG-4.0.2.pkg" should be exist
    # ...pkg repo ran on the bucket, and no ABI-keyed dir was created.
    The path "${work}/out/release/ce-2.8/amd64/packagesite.pkg" should be exist
    The path "${work}/out/release/FreeBSD:15:amd64" should not be exist
  End

  It 'requires --varver in build mode (the key cannot be derived from the package)'
    fake_pkg a.pkg pfSense-pkg-pfBlockerNG 4.0.1 FreeBSD:15:amd64 php83
    When call run_build
    The status should equal 2
    The stderr should include '--varver'
  End

  Describe 'hostile --varver values'
    # The value becomes a directory that is rm -rf'd + rebuilt, so anything but
    # a plain lowercase segment must be rejected before any filesystem work.
    Parameters
      '../etc'
      'ce/2.8'
      'CE-2.8'
      'ce_2.8'
      'ce-2.8;rm -rf x'
    End

    It "rejects hostile --varver value: $1"
      fake_pkg a.pkg pfSense-pkg-pfBlockerNG 4.0.1 FreeBSD:15:amd64 php83
      When call run_build --varver "$1"
      The status should equal 2
      The stderr should include 'unsafe or invalid --varver'
      # No filesystem layout may happen for a rejected value.
      The path "${work}/out/release" should not be exist
    End
  End

  Describe 'hostile ABI metadata'
    # validate_abi(): the ABI becomes a path segment that is rm -rf'd +
    # rebuilt. The guard must reject under ANY ambient locale (issue #1148: a
    # collating UTF-8 locale lets a case-range class admit accented letters).
    Parameters
      'FreeBSD:15:amdé64'
      'FreeBSD/15/amd64'
      'FreeBSD:..:amd64'
    End

    It "rejects hostile ABI metadata: $1"
      fake_pkg a.pkg pfSense-pkg-pfBlockerNG 4.0.1 "$1" php83
      When call run_build --varver ce-2.8
      The status should equal 1
      The stderr should include 'unsafe or invalid ABI'
      # validate_abi() runs before the bucket is laid out.
      The path "${work}/out/release" should not be exist
    End
  End

  Describe 'trailing-newline bypass'
    # A TRAILING newline is deleted by $(...) stripping, so an emptiness check
    # on the tr remainder silently accepts it — the guards compare against a
    # sentinel instead. Values built via printf: Parameters cannot carry \n.
    # Only --varver gets a row: argv delivers a raw newline, while an ABI rides
    # line-based metadata extraction (sed -n 's/^abi=//p'), which cannot emit
    # one — validate_abi() carries the same sentinel purely as parity.
    It 'rejects a --varver with a trailing newline'
      hostile="$(printf 'ce-2.8\nZ')"; hostile="${hostile%Z}"
      fake_pkg a.pkg pfSense-pkg-pfBlockerNG 4.0.1 FreeBSD:15:amd64 php83
      When call run_build --varver "$hostile"
      The status should equal 2
      The stderr should include 'unsafe or invalid --varver'
      The path "${work}/out/release" should not be exist
    End
  End

  It 'fails loud on a mixed-ABI input instead of mixing editions in one bucket'
    fake_pkg a.pkg pfSense-pkg-pfBlockerNG 4.0.1 FreeBSD:15:amd64 php83
    fake_pkg b.pkg pfSense-pkg-pfBlockerNG 4.0.1_1 FreeBSD:16:amd64 php85
    When call run_build --varver ce-2.8
    The status should equal 1
    The stderr should include 'mixed ABIs'
  End

  It 'still fails loud on a same-name+version+ABI flavor collision'
    fake_pkg a.pkg pfSense-pkg-pfBlockerNG 4.0.1 FreeBSD:15:amd64 php83
    fake_pkg b.pkg pfSense-pkg-pfBlockerNG 4.0.1 FreeBSD:15:amd64 php85
    When call run_build --varver ce-2.8
    The status should equal 1
    The stderr should include 'FLAVOR COLLISION'
  End
End
