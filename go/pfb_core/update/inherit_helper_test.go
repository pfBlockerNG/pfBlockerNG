package update

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("PFB_INHERIT_HELPER") == "1" {
		f, err := os.OpenFile(os.Getenv("PFB_INHERIT_MARKER"), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "inherit helper:", err)
			os.Exit(2)
		}
		_, _ = f.WriteString("alive\n")
		f.Close()
		pidFile, err := os.OpenFile(os.Getenv("PFB_INHERIT_PID"), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "inherit helper:", err)
			os.Exit(2)
		}
		fmt.Fprintln(pidFile, os.Getpid())
		pidFile.Close()
		hold, err := os.OpenFile(os.Getenv("PFB_INHERIT_HOLD"), os.O_RDWR, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "inherit helper:", err)
			os.Exit(2)
		}
		var release [1]byte
		_, _ = hold.Read(release[:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}
