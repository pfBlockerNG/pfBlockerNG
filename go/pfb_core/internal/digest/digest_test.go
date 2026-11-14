package digest

import (
	"os"
	"path/filepath"
	"testing"
)

// The digests of "a.example.com\nb.example.com\n" as PHP computes them (hash('xxh128', ...) and md5()): what the sidecars hold.
const (
	body    = "a.example.com\nb.example.com\n"
	bodyXXH = "d615a18420594aec571c642da94065c4"
	bodyMD5 = "656857e20485ca265627f808633dbb65"
)

func TestDigestsAreWhatPHPWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Bytes([]byte(body)); got != bodyXXH {
		t.Errorf("Bytes = %s, want %s", got, bodyXXH)
	}
	if got, err := File(path); err != nil || got != bodyXXH {
		t.Errorf("File = %s, %v; want %s", got, err, bodyXXH)
	}
	if got, err := MD5File(path); err != nil || got != bodyMD5 {
		t.Errorf("MD5File = %s, %v; want %s", got, err, bodyMD5)
	}
	if _, err := File(path + ".missing"); err == nil {
		t.Error("File of a missing file succeeded")
	}
}

func TestReadIsPfbHashRead(t *testing.T) {
	const padded = " \t" + bodyXXH + "\r\n\x00\x0b"
	cases := []struct {
		name         string
		xxh, md5     *string
		algo, digest string
	}{
		{"no sidecar", nil, nil, "", ""},
		{"xxh128", ptr(bodyXXH), nil, XXH128, bodyXXH},
		{"padding is trimmed the way pfb_hash_read() trims it", ptr(padded), nil, XXH128, bodyXXH},
		{"xxh128 wins over md5", ptr(bodyXXH), ptr(bodyMD5), XXH128, bodyXXH},
		{"legacy md5 alone", nil, ptr(bodyMD5), MD5, bodyMD5},
		{"a corrupt xxh128 never falls back to the md5 behind it", ptr("zz"), ptr(bodyMD5), "", ""},
		{"an upper-case digest is corrupt", ptr("D615A18420594AEC571C642DA94065C4"), nil, "", ""},
		{"a short digest is corrupt", ptr(bodyXXH[:31]), nil, "", ""},
		{"a long digest is corrupt", ptr(bodyXXH + "0"), nil, "", ""},
		{"a corrupt md5", nil, ptr("garbage"), "", ""},
		{"an empty sidecar", ptr(""), nil, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := filepath.Join(t.TempDir(), "feed.orig")
			for algo, content := range map[string]*string{XXH128: c.xxh, MD5: c.md5} {
				if content != nil {
					if err := os.WriteFile(base+"."+algo, []byte(*content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if algo, digest := Read(base); algo != c.algo || digest != c.digest {
				t.Errorf("Read = %q, %q; want %q, %q", algo, digest, c.algo, c.digest)
			}
		})
	}
	t.Run("an unreadable sidecar is no baseline", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "feed.orig")
		if err := os.Mkdir(base+"."+XXH128, 0o700); err != nil { // a directory where the sidecar belongs: it exists, it cannot be read
			t.Fatal(err)
		}
		if err := os.WriteFile(base+"."+MD5, []byte(bodyMD5), 0o600); err != nil {
			t.Fatal(err)
		}
		if algo, digest := Read(base); algo != "" || digest != "" {
			t.Errorf("Read = %q, %q; want no baseline", algo, digest)
		}
	})
}

func ptr(s string) *string { return &s }
