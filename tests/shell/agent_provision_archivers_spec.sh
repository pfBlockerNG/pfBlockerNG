#shellcheck shell=sh
# PATH-aware appliance-archiver provisioning: package tools are stubbed; the /usr tree is a fixture.

Describe 'provision-archivers.sh'
  project_root="${SHELLSPEC_PROJECT_ROOT:-$PWD}"
  script_abs="$project_root/scripts/agent/provision-archivers.sh"
  gnu_tar_banner='tar (GNU tar) 1.35'
  info_zip_banner='UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.'

  make_base_path() {
    destination=$1
    mkdir -p "$destination"
    for tool in basename cat chmod cp dirname env grep ln mkdir mv pwd readlink rm sh; do
      tool_path=$(command -v "$tool" 2>/dev/null) || continue
      ln -s "$tool_path" "$destination/$tool"
    done
  }

  # A tool that answers every invocation with its version banner.
  banner_stub() {
    { echo '#!/bin/sh'; echo "echo '$2'"; } > "$1"
    chmod +x "$1"
  }

  setup() {
    fixture=$(mktemp -d "${TMPDIR:-/tmp}/agent_provision_archivers.XXXXXX") || return 1
    fixture=$(cd "$fixture" && pwd -P) || return 1
    root="$fixture/root"
    usr_bin="$root/usr/bin"
    local_bin="$root/usr/local/bin"
    usr_sbin="$root/usr/sbin"
    mkdir -p "$usr_bin" "$local_bin" "$usr_sbin"
    banner_stub "$usr_bin/tar" "$gnu_tar_banner"
    banner_stub "$usr_bin/unzip" "$info_zip_banner"

    packages="$fixture/packages"
    mkdir -p "$packages"
    banner_stub "$packages/bsdtar" 'bsdtar 3.7.4 - libarchive 3.7.4'
    banner_stub "$packages/bsdunzip" 'bsdunzip 3.7.4 - libarchive 3.7.4'
    banner_stub "$packages/rsync" 'rsync  version 3.4.1  protocol version 32'

    basebin="$fixture/base-bin"
    activebin="$fixture/active-bin"
    make_base_path "$basebin"
    mkdir -p "$activebin"
    call_log="$fixture/calls.log"

    cat > "$activebin/id" <<'ID'
#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = -u ] || exit 9
printf '%s\n' "${ARCHIVER_TEST_UID:-1000}"
ID
    cat > "$activebin/uname" <<'UNAME'
#!/bin/sh
case "${1:-}" in
  ''|-s) printf '%s\n' "${AGENT_TEST_OS:-Linux}" ;;
  *) exit 9 ;;
esac
UNAME
    cat > "$activebin/sudo" <<'SUDO'
#!/bin/sh
printf 'sudo:%s\n' "$*" >> "$ARCHIVER_CALL_LOG"
[ "${ARCHIVER_SUDO_RC:-0}" -eq 0 ] || exit "$ARCHIVER_SUDO_RC"
exec "$@"
SUDO
    cat > "$activebin/apt-get" <<'APT_GET'
#!/bin/sh
printf 'apt-get:%s\n' "$*" >> "$ARCHIVER_CALL_LOG"
for argument do
  case "$argument" in
    libarchive-tools) cp "$ARCHIVER_PACKAGES/bsdtar" "$ARCHIVER_PACKAGES/bsdunzip" "$ARCHIVER_USR_BIN/" ;;
    rsync) cp "$ARCHIVER_PACKAGES/rsync" "$ARCHIVER_USR_BIN/" ;;
  esac
done
APT_GET
    cat > "$activebin/dpkg-divert" <<'DPKG_DIVERT'
#!/bin/sh
printf 'dpkg-divert:%s\n' "$*" >> "$ARCHIVER_CALL_LOG"
[ -z "${ARCHIVER_DIVERT_CLASH:-}" ] || {
  echo "dpkg-divert: error: clashes with 'local diversion to $ARCHIVER_DIVERT_CLASH'" >&2
  exit 2
}
DPKG_DIVERT
    chmod +x "$activebin"/*

    export ARCHIVER_CALL_LOG="$call_log"
    export ARCHIVER_PACKAGES="$packages"
    export ARCHIVER_USR_BIN="$usr_bin"
    unset ARCHIVER_TEST_UID ARCHIVER_SUDO_RC ARCHIVER_DIVERT_CLASH AGENT_TEST_OS
    # Debian's default user PATH shape: /usr/local/bin ahead of /usr/bin.
    PATH="$activebin:$local_bin:$usr_bin:$basebin"; export PATH
  }

  cleanup() {
    rm -rf "$fixture"
  }

  BeforeEach 'setup'
  AfterEach 'cleanup'

  tar_link() { readlink "$usr_bin/tar"; }
  unzip_link() { readlink "$usr_bin/unzip"; }
  rsync_link() { readlink "$local_bin/rsync"; }
  usr_tar_version() { "$usr_bin/tar" --version; }
  usr_unzip_version() { "$usr_bin/unzip" --version; }
  local_tar_version() { "$local_bin/tar" --version; }
  local_unzip_version() { "$local_bin/unzip" -v; }
  sbin_tar_version() { "$usr_sbin/tar" --version; }
  sbin_unzip_version() { "$usr_sbin/unzip" -v; }

  gnu_tools_untouched() {
    [ ! -L "$usr_bin/tar" ] && [ ! -L "$usr_bin/unzip" ] &&
      [ "$("$usr_bin/tar" --version)" = "$gnu_tar_banner" ] &&
      [ "$("$usr_bin/unzip" -v)" = "$info_zip_banner" ] &&
      [ ! -e "$local_bin/tar" ] && [ ! -e "$local_bin/unzip" ] && [ ! -e "$local_bin/rsync" ]
  }

  It 'installs the appliance archivers through sudo and diverts the GNU tools to the PATH directory ahead of usr/bin'
    When run sh "$script_abs" "$root"
    The status should equal 0
    The result of function tar_link should equal bsdtar
    The result of function unzip_link should equal bsdunzip
    The result of function rsync_link should equal "$usr_bin/rsync"
    The result of function usr_tar_version should equal 'bsdtar 3.7.4 - libarchive 3.7.4'
    The result of function usr_unzip_version should equal 'bsdunzip 3.7.4 - libarchive 3.7.4'
    The result of function local_tar_version should equal "$gnu_tar_banner"
    The result of function local_unzip_version should equal "$info_zip_banner"
    The contents of file "$call_log" should equal "$(printf '%s\n' \
      'sudo:apt-get update' \
      'apt-get:update' \
      'sudo:apt-get install -y --no-install-recommends libarchive-tools rsync' \
      'apt-get:install -y --no-install-recommends libarchive-tools rsync' \
      "sudo:dpkg-divert --no-rename --divert $local_bin/tar --add $usr_bin/tar" \
      "dpkg-divert:--no-rename --divert $local_bin/tar --add $usr_bin/tar" \
      "sudo:mv $usr_bin/tar $local_bin/tar" \
      "sudo:ln -sfn bsdtar $usr_bin/tar" \
      "sudo:dpkg-divert --no-rename --divert $local_bin/unzip --add $usr_bin/unzip" \
      "dpkg-divert:--no-rename --divert $local_bin/unzip --add $usr_bin/unzip" \
      "sudo:mv $usr_bin/unzip $local_bin/unzip" \
      "sudo:ln -sfn bsdunzip $usr_bin/unzip" \
      "sudo:ln -sfn $usr_bin/rsync $local_bin/rsync")"
  End

  It 'runs the package tools directly as root'
    When run env ARCHIVER_TEST_UID=0 sh "$script_abs" "$root"
    The status should equal 0
    The result of function tar_link should equal bsdtar
    The result of function unzip_link should equal bsdunzip
    The contents of file "$call_log" should not include 'sudo:'
    The contents of file "$call_log" should include "dpkg-divert:--no-rename --divert $local_bin/tar --add $usr_bin/tar"
  End

  It 'installs only the packages whose binaries are missing'
    cp "$packages/bsdtar" "$packages/bsdunzip" "$usr_bin/"
    When run sh "$script_abs" "$root"
    The status should equal 0
    The contents of file "$call_log" should include 'apt-get:install -y --no-install-recommends rsync'
    The contents of file "$call_log" should not include 'libarchive-tools'
  End

  It 'diverts to usr/sbin when that is the system directory PATH searches before usr/bin'
    PATH="$activebin:$usr_sbin:$usr_bin:$local_bin:$basebin"
    When run sh "$script_abs" "$root"
    The status should equal 0
    The result of function tar_link should equal bsdtar
    The result of function sbin_tar_version should equal "$gnu_tar_banner"
    The result of function sbin_unzip_version should equal "$info_zip_banner"
    The result of function rsync_link should equal "$usr_bin/rsync"
    The contents of file "$call_log" should include "dpkg-divert:--no-rename --divert $usr_sbin/tar --add $usr_bin/tar"
    The contents of file "$call_log" should include "dpkg-divert:--no-rename --divert $usr_sbin/unzip --add $usr_bin/unzip"
    The contents of file "$call_log" should not include "$local_bin/tar"
  End

  It 'refuses before changing anything when no system directory precedes usr/bin on PATH'
    PATH="$activebin:$usr_bin:$local_bin:$basebin"
    When run sh "$script_abs" "$root"
    The status should equal 1
    The stderr should include 'PATH'
    The file "$call_log" should not be exist
    Assert gnu_tools_untouched
  End

  It 'sees through a merged-usr bin symlink that shadows every candidate directory'
    ln -s usr/bin "$root/bin"
    PATH="$activebin:$root/bin:$local_bin:$usr_bin:$basebin"
    When run sh "$script_abs" "$root"
    The status should equal 1
    The stderr should include 'PATH'
    The file "$call_log" should not be exist
    Assert gnu_tools_untouched
  End

  It 'ignores per-user PATH entries ahead of the system directories'
    user_bin="$fixture/home/.local/bin"
    mkdir -p "$user_bin"
    PATH="$activebin:$user_bin:$local_bin:$usr_bin:$basebin"
    When run sh "$script_abs" "$root"
    The status should equal 0
    The result of function local_tar_version should equal "$gnu_tar_banner"
    The contents of file "$call_log" should not include "$user_bin"
  End

  It 'is a change-free, privilege-free no-op on a host that is already wired'
    When run sh -c 'sh "$1" "$2" && cp "$3" "$3.first" && ARCHIVER_SUDO_RC=1 sh "$1" "$2"' \
      _ "$script_abs" "$root" "$call_log"
    The status should equal 0
    The contents of file "$call_log" should equal "$(cat "$call_log.first")"
    The result of function tar_link should equal bsdtar
    The result of function unzip_link should equal bsdunzip
  End

  It 'stops at a clashing existing diversion before moving GNU tar'
    When run env ARCHIVER_DIVERT_CLASH="$usr_sbin/tar" sh "$script_abs" "$root"
    The status should not equal 0
    The stderr should include 'clashes'
    The contents of file "$call_log" should not include 'mv '
    Assert [ ! -L "$usr_bin/tar" ]
    The result of function usr_tar_version should equal "$gnu_tar_banner"
  End

  It 'refuses to overwrite when both the original and its diverted copy exist'
    banner_stub "$local_bin/tar" 'tar (something else)'
    When run sh "$script_abs" "$root"
    The status should equal 1
    The stderr should include 'resolve by hand'
    The contents of file "$call_log" should not include 'mv '
    The contents of file "$call_log" should not include 'ln '
    Assert [ ! -L "$usr_bin/tar" ]
    The result of function usr_tar_version should equal "$gnu_tar_banner"
  End

  It 'fails closed when the absolute path resolves to something other than libarchive'
    banner_stub "$usr_bin/bsdtar" 'not libarchive at all'
    cp "$packages/bsdunzip" "$usr_bin/"
    ln -sfn bsdtar "$usr_bin/tar"
    When run sh "$script_abs" "$root"
    The status should equal 1
    The stderr should include "$usr_bin/tar is not bsdtar"
  End

  It 'fails closed when a bare name stops resolving to the GNU tool'
    banner_stub "$activebin/unzip" 'bsdunzip 3.7.4 - libarchive 3.7.4'
    When run sh "$script_abs" "$root"
    The status should equal 1
    The stderr should include "bare 'unzip'"
    The stderr should include 'Info-ZIP'
  End

  It 'refuses on a non-Linux host before touching anything'
    When run env AGENT_TEST_OS=Darwin sh "$script_abs" "$root"
    The status should equal 1
    The stderr should include 'Linux'
    The file "$call_log" should not be exist
    Assert gnu_tools_untouched
  End

  It 'rejects more than one root argument'
    When run sh "$script_abs" "$root" extra
    The status should equal 2
    The stderr should include 'usage: provision-archivers.sh [ROOT]'
    The file "$call_log" should not be exist
  End
End
