package spoa

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestParityWithCore ensures go/pfb_crowdsec/spoa stays byte-identical to go/pfb_core/internal/spoa.
// pfb_crowdsec is stdlib-only (scripts/build-pfb-dns.py forbids any require/replace in its go.mod).
func TestParityWithCore(t *testing.T) {
	coreDir := filepath.Join("..", "..", "pfb_core", "internal", "spoa")
	for _, name := range []string{"codec.go", "radix.go", "server.go"} {
		a, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b, err := os.ReadFile(filepath.Join(coreDir, name))
		if err != nil {
			t.Fatalf("read core %s: %v", name, err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs from %s; keep both copies identical", name, filepath.Join(coreDir, name))
		}
	}
}
