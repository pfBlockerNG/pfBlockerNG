#shellcheck shell=sh
# pfb_dns.sh architecture-selector contract (issue #3513). One package ships a pfb-dns binary per
# FreeBSD architecture; the wrapper runs the one that matches `uname -p` and nothing else.
#
# Real stub executables stand in for the binaries and log which one ran; a fake `uname` first on
# PATH answers for the machine. The wrapper copy sits in a private `dns_proxy/` tree, found the way
# the packaged one finds its own `bin/`.
#
#   exit status of the binary  — a matching binary exists and ran (exec)
#   exit status 3              — no pfb-dns payload shipped at all (legacy package)
#   exit status 1              — payload shipped but unusable here (unknown machine, own-arch binary
#                                missing or not executable): the caller must not fall back

Describe 'pfb_dns.sh'
  setup() {
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbdns.XXXXXX")"
    log="${work}/log"
    true > "${log}"
    mkdir -p "${work}/dns_proxy" "${work}/fakebin"
    cp "${PFB_PKGDIR}/dns_proxy/pfb_dns.sh" "${work}/dns_proxy/pfb_dns.sh"
    cat > "${work}/fakebin/uname" <<EOF
#!/bin/sh
printf 'uname %s\n' "\$*" >> "${log}"
printf '%s\n' "\${FAKE_MACHINE}"
EOF
    chmod +x "${work}/fakebin/uname"
  }

  cleanup() {
    rm -rf "${work}"
  }

  # ship ARCH... — a real executable stub per shipped architecture directory, logging its own name
  # and each argument on its own line.
  ship() {
    for _arch in "$@"; do
      mkdir -p "${work}/dns_proxy/bin/freebsd-${_arch}"
      cat > "${work}/dns_proxy/bin/freebsd-${_arch}/pfb-dns" <<EOF
#!/bin/sh
printf 'ran %s\n' "${_arch}" >> "${log}"
for _a in "\$@"; do printf 'arg <%s>\n' "\${_a}" >> "${log}"; done
exit "\${STUB_STATUS:-0}"
EOF
      chmod +x "${work}/dns_proxy/bin/freebsd-${_arch}/pfb-dns"
    done
  }

  run_wrapper() {
    PATH="${work}/fakebin:${PATH}" FAKE_MACHINE="${machine}" STUB_STATUS="${stub_status:-0}" \
      sh "${work}/dns_proxy/pfb_dns.sh" "$@"
  }

  It 'runs the amd64 binary on an amd64 machine and passes every argument through byte-for-byte'
    setup
    ship amd64 arm64
    machine=amd64
    When call run_wrapper 'a b' '$(touch pwned)' '*.txt'
    The status should be success
    The contents of file "${log}" should equal "$(printf 'uname -p\nran amd64\narg <a b>\narg <$(touch pwned)>\narg <*.txt>\n')"
    The path "${work}/pwned" should not be exist
    cleanup
  End

  It 'runs the arm64 binary on an aarch64 machine'
    setup
    ship amd64 arm64
    machine=aarch64
    When call run_wrapper
    The status should be success
    The contents of file "${log}" should equal "$(printf 'uname -p\nran arm64\n')"
    cleanup
  End

  It 'treats arm64 as the aarch64 machine name'
    setup
    ship amd64 arm64
    machine=arm64
    When call run_wrapper
    The status should be success
    The contents of file "${log}" should equal "$(printf 'uname -p\nran arm64\n')"
    cleanup
  End

  It 'fails loudly on an unknown machine and runs no binary'
    setup
    ship amd64 arm64
    machine=unknown
    When call run_wrapper
    The status should equal 1
    The stderr should include 'unknown'
    The contents of file "${log}" should equal "uname -p"
    cleanup
  End

  It 'fails loudly on a machine it does not ship a binary for and runs no binary'
    setup
    ship amd64 arm64
    machine=riscv64
    When call run_wrapper
    The status should equal 1
    The stderr should include 'riscv64'
    The contents of file "${log}" should equal "uname -p"
    cleanup
  End

  It 'fails loudly when uname answers nothing'
    setup
    ship amd64 arm64
    machine=''
    When call run_wrapper
    The status should equal 1
    The stderr should be present
    The contents of file "${log}" should equal "uname -p"
    cleanup
  End

  It 'never lets the machine name steer it to another path'
    setup
    ship amd64 arm64
    machine='../freebsd-amd64'
    When call run_wrapper
    The status should equal 1
    The stderr should be present
    The contents of file "${log}" should equal "uname -p"
    cleanup
  End

  It 'fails loudly, and does not run the other architecture, when its own binary is missing'
    setup
    ship arm64
    machine=amd64
    When call run_wrapper
    The status should equal 1
    The stderr should include 'freebsd-amd64'
    The contents of file "${log}" should equal "uname -p"
    cleanup
  End

  It 'fails loudly, and does not run the other architecture, when an arm64 machine has only the amd64 binary'
    setup
    ship amd64
    machine=arm64
    When call run_wrapper
    The status should equal 1
    The stderr should include 'freebsd-arm64'
    The contents of file "${log}" should equal "uname -p"
    cleanup
  End

  It 'fails loudly when its own binary is not executable'
    setup
    ship amd64 arm64
    chmod 0644 "${work}/dns_proxy/bin/freebsd-amd64/pfb-dns"
    machine=amd64
    When call run_wrapper
    The status should equal 1
    The stderr should include 'freebsd-amd64'
    The contents of file "${log}" should equal "uname -p"
    cleanup
  End

  It 'reports a legacy package (no payload at all) with status 3, distinct from every failure'
    setup
    machine=amd64
    When call run_wrapper
    The status should equal 3
    The stderr should include 'no pfb-dns'
    cleanup
  End

  It 'reports an empty bin tree as a legacy package too'
    setup
    mkdir -p "${work}/dns_proxy/bin/freebsd-amd64" "${work}/dns_proxy/bin/freebsd-arm64"
    machine=amd64
    When call run_wrapper
    The status should equal 3
    The stderr should include 'no pfb-dns'
    cleanup
  End

  It 'returns the binary exit status unchanged'
    setup
    ship amd64
    machine=amd64
    stub_status=7
    When call run_wrapper
    The status should equal 7
    cleanup
  End

  It 'finds its own bin tree through a hostile CDPATH'
    setup
    ship amd64
    mkdir -p "${work}/decoy/dns_proxy/bin/freebsd-amd64"
    cat > "${work}/decoy/dns_proxy/bin/freebsd-amd64/pfb-dns" <<EOF
#!/bin/sh
printf 'ran decoy\n' >> "${log}"
EOF
    chmod +x "${work}/decoy/dns_proxy/bin/freebsd-amd64/pfb-dns"
    machine=amd64
    run_relative() {
      cd "${work}" || return 1
      CDPATH="${work}/decoy" PATH="${work}/fakebin:${PATH}" FAKE_MACHINE=amd64 sh dns_proxy/pfb_dns.sh
    }
    When call run_relative
    The status should be success
    The contents of file "${log}" should equal "$(printf 'uname -p\nran amd64\n')"
    cleanup
  End

  # daemon(8) writes the pid of the process it starts to the child pidfile; the stop and the start's
  # "already serving" check both read it. exec must leave pfb-dns as that very process.
  It 'execs the binary, so the process the caller started is the one that runs pfb-dns'
    setup
    mkdir -p "${work}/dns_proxy/bin/freebsd-amd64"
    cat > "${work}/dns_proxy/bin/freebsd-amd64/pfb-dns" <<EOF
#!/bin/sh
printf '%s\n' "\$\$" > "${work}/binary.pid"
EOF
    chmod +x "${work}/dns_proxy/bin/freebsd-amd64/pfb-dns"
    run_as_daemon_child() {
      PATH="${work}/fakebin:${PATH}" FAKE_MACHINE=amd64 \
        sh -c 'printf "%s\n" "$$" > "$1/caller.pid"; exec /bin/sh "$1/dns_proxy/pfb_dns.sh"' sh "${work}" || return 1
      if [ "$(cat "${work}/caller.pid")" = "$(cat "${work}/binary.pid")" ]; then
        echo same
      else
        echo "caller $(cat "${work}/caller.pid") ran pfb-dns as $(cat "${work}/binary.pid")"
      fi
    }
    When call run_as_daemon_child
    The output should equal 'same'
    cleanup
  End
End
