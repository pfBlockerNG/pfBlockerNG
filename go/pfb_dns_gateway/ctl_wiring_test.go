package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// The control socket in the gateway's life: bound while it is still root, reported before it says ready, and kept when it
// gives root up.

func ctlConfig(t *testing.T) (config, *capture, string) {
	t.Helper()
	cfg, logs := lifecycleConfig(t, "serve")
	path, _ := goodPEM(t)
	sock := filepath.Join(shortTempDir(t), "run", "ctl.sock")
	cfg.dotListen, cfg.dotPort, cfg.tlsPEM, cfg.ctlSocket = cfg.listen, freePort(t), path, sock
	return cfg, logs, sock
}

// The directory and the socket are made, and the certificate file read, before the privilege drop: afterwards nobody can
// create a thing in a root-only directory, and the gateway no longer can read what only root can.
func TestTheControlSocketIsBoundBeforeThePrivilegeDrop(t *testing.T) {
	cfg, logs, sock := ctlConfig(t)
	var atDrop os.FileInfo
	var atDropErr error
	cfg.drop = func() error { atDrop, atDropErr = os.Lstat(sock); return nil }
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	if atDropErr != nil || atDrop.Mode()&os.ModeSocket == 0 {
		t.Fatalf("at the privilege drop the control socket was %v (err %v), want it bound", atDrop, atDropErr)
	}
}

// Reported with the other sockets, before `ready upstream`: whoever waits for readiness may push at once.
func TestTheControlSocketIsReportedBeforeReady(t *testing.T) {
	cfg, logs, sock := ctlConfig(t)
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	text := logs.text()
	at, ready := strings.Index(text, "control socket "+sock), strings.Index(text, "ready upstream")
	if at < 0 || ready < at {
		t.Fatalf("`control socket %s` must be reported before `ready upstream`:\n%s", sock, text)
	}
}

// A control socket that cannot be made costs the renewal, not the service: the reason is logged once, the certificate that
// was read at start keeps being served, and plain DNS is untouched.
func TestAControlSocketThatCannotBeBoundIsLoggedAndTheTLSTransportsServe(t *testing.T) {
	cfg, logs, _ := ctlConfig(t)
	blocker := filepath.Join(shortTempDir(t), "afile")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.ctlSocket = filepath.Join(blocker, "ctl.sock") // a file where the directory goes
	srv, err := start(cfg, logs.logf)
	if err != nil {
		t.Fatalf("a control socket that cannot be bound must not stop the gateway: %v", err)
	}
	defer srv.shutdown()
	text := logs.text()
	if n := strings.Count(text, "control socket: "); n != 1 || !strings.Contains(text, "cannot be renewed without a restart") {
		t.Fatalf("want one line saying the certificate cannot be renewed without a restart, got %d:\n%s", n, text)
	}
	if !strings.Contains(text, "listening dot ") {
		t.Fatalf("the certificate read at start must still be served over DoT:\n%s", text)
	}
}

// The listener survives the drop: a gateway that has given up root still takes the push of the root that started it. Root
// only, like every real setuid here; the push comes from this process (root), the credential is the kernel's.
func TestTheControlSocketTakesPushesAfterTheRealPrivilegeDrop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("a real setuid: needs root to switch user")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no user `nobody` to drop to")
	}
	root := newPKI(t, nil, "drop root", true)
	file := filepath.Join(shortTempDir(t), "tls.pem")
	if err := os.WriteFile(file, chainPEM(t, newPKI(t, root, "localhost", false)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctl := filepath.Join(shortTempDir(t), "run", "ctl.sock")
	gw := startGatewayProcess(t, []string{
		"--listen", "127.0.0.1", "--port", "0", "--unbound-conf", "/nonexistent/unbound.conf", "--user", "nobody",
		"--dot-listen", "127.0.0.1", "--dot-port", "0", "--tls-pem", file, "--ctl-socket", ctl,
	}, decider("serve"))
	dot := listeningAddr(t, gw.waitLine("listening dot "), "dot")
	gw.waitLine("ready upstream ")
	if uid := realUID(t, gw.cmd.Process.Pid); uid != nobody.Uid {
		t.Fatalf("the gateway runs as uid %s, want %s: the drop did not happen", uid, nobody.Uid)
	}
	r := &reloadRig{t: t, ctl: ctl, root: root, m: tlsMaterial{pool: root.pool()}, gw: gw, dot: dot}
	pushed := newPKI(t, root, "localhost", false)
	r.rotate(pushed)
	leaf, err := dotExchange(r, buildQuery(t, 9, "example.", true))
	if err != nil || !leaf.Equal(pushed.cert) {
		t.Fatalf("DoT after the push to a gateway that is no longer root: cert %v err %v, want serial %v", leaf, err, pushed.cert.SerialNumber)
	}
}
