# shellcheck shell=sh
# issue #4069: go/pfb_crowdsec is the CrowdSec bouncer's own Go module. A change under it selects the Go gate chain run
# in that module (gofmt, vet, race tests, both FreeBSD cross-builds) and not the gateway's.
Describe 'run-gates.sh CrowdSec Go gate selection'
  # shellcheck disable=SC2034 # consumed by the Included script's source-only guard
  AGENT_SOURCE_ONLY=1
  Include scripts/agent/run-gates.sh

  # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
  crowdsec_gate='cd go/pfb_crowdsec && gofmt_out=$(gofmt -l .) && test -z "$gofmt_out" && go vet ./... && go test -race -count=1 ./... && CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o /dev/null . && CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -o /dev/null .'
  # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
  go_gate='cd go/pfb_dns_gateway && gofmt_out=$(gofmt -l .) && test -z "$gofmt_out" && go vet ./... && go test -race -count=1 ./... && CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o /dev/null . && CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -o /dev/null .'
  # shellcheck disable=SC2016 # the literal $( ) is the pinned command text
  shellspec_gate='shellspec --shell $(command -v dash || command -v sh)'

  Describe 'a path under go/pfb_crowdsec/'
    Parameters
      'go/pfb_crowdsec/daemon.go'
      'go/pfb_crowdsec/go.mod'
    End

    It "selects the CrowdSec Go gate alone for '$1', then ShellSpec"
      Data "$1"
      When call gates_for
      The line 1 of output should equal "$crowdsec_gate"
      The line 2 of output should equal "$shellspec_gate"
      The lines of output should equal 2
    End
  End

  It 'selects both Go gates, gateway first, when both modules change'
    Data
      #|go/pfb_crowdsec/daemon.go
      #|go/pfb_dns_gateway/acl.go
    End
    When call gates_for
    The output should equal "$go_gate
$crowdsec_gate
$shellspec_gate"
  End

  It 'resolves the toolchain for the CrowdSec gate (a missing go fails it)'
    When call gate_command "$crowdsec_gate"
    The output should start with 'PATH="$PATH:'
    The output should include 'TOOL-MISSING: go'
    The output should end with "$crowdsec_gate"
  End
End
