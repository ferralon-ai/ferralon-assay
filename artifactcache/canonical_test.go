package artifactcache

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

const testRoot = "/var/cache/ferralon/artifacts"

// hexOf is a 64-byte pattern (sha512) and its 32-byte prefix (sha256) for round-trip tests.
var raw64 = func() []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i * 7)
	}
	b[0] = 0xFB // yields '+' in base64-std
	b[3] = 0xFF // yields '/' in base64-std
	return b
}()

// Test 1.1–1.5: canonicalization round-trip, cross-form equality, keyspace separation.
func TestCanonicalPathRoundTrip(t *testing.T) {
	raw32 := raw64[:32]

	t.Run("1.1 sha256 hex (PyPI form)", func(t *testing.T) {
		hx := hex.EncodeToString(raw32)
		algo, dec, err := DecodeDigest("sha256:" + hx)
		if err != nil {
			t.Fatalf("DecodeDigest: %v", err)
		}
		if algo != "sha256" || len(dec) != 32 {
			t.Fatalf("algo=%q len=%d, want sha256/32", algo, len(dec))
		}
		path, err := CanonicalPath(testRoot, "sha256:"+hx)
		if err != nil {
			t.Fatalf("CanonicalPath: %v", err)
		}
		want := filepath.Join(testRoot, "sha256", hx[:2], hx)
		if path != want {
			t.Fatalf("path = %q, want %q", path, want)
		}
	})

	t.Run("1.2 sha512 base64-std with /+= (npm/NuGet form)", func(t *testing.T) {
		b64 := base64.StdEncoding.EncodeToString(raw64)
		if !strings.ContainsAny(b64, "/+=") {
			t.Fatalf("fixture base64 %q lacks the /+= chars this case must exercise", b64)
		}
		path, err := CanonicalPath(testRoot, "sha512:"+b64)
		if err != nil {
			t.Fatalf("CanonicalPath: %v", err)
		}
		seg := filepath.Base(path)
		if len(seg) != 128 {
			t.Fatalf("canonical seg len = %d, want 128 hex chars", len(seg))
		}
		if strings.ContainsAny(seg, "/+=") {
			t.Fatalf("canonical seg %q still contains a wire char /+=", seg)
		}
		if strings.ToLower(seg) != seg {
			t.Fatalf("canonical seg %q is not lowercase", seg)
		}
		assertUnderRoot(t, path)
	})

	t.Run("1.3 base64url variant → same seg as std", func(t *testing.T) {
		std, err := CanonicalPath(testRoot, "sha512:"+base64.StdEncoding.EncodeToString(raw64))
		if err != nil {
			t.Fatal(err)
		}
		urlform, err := CanonicalPath(testRoot, "sha512:"+base64.URLEncoding.EncodeToString(raw64))
		if err != nil {
			t.Fatalf("base64url decode: %v", err)
		}
		if std != urlform {
			t.Fatalf("base64url path %q != base64-std path %q for the same bytes", urlform, std)
		}
	})

	t.Run("1.4 cross-form equality: hex == base64", func(t *testing.T) {
		hexPath, err := CanonicalPath(testRoot, "sha512:"+hex.EncodeToString(raw64))
		if err != nil {
			t.Fatal(err)
		}
		b64Path, err := CanonicalPath(testRoot, "sha512:"+base64.StdEncoding.EncodeToString(raw64))
		if err != nil {
			t.Fatal(err)
		}
		if hexPath != b64Path {
			t.Fatalf("hex path %q != base64 path %q for identical raw bytes", hexPath, b64Path)
		}
	})

	t.Run("1.5 keyspace separation: sha256 vs sha512 coincident hex prefix", func(t *testing.T) {
		// Same first 32 bytes → same 64-hex prefix, but different algorithm segment.
		p256, err := CanonicalPath(testRoot, "sha256:"+hex.EncodeToString(raw32))
		if err != nil {
			t.Fatal(err)
		}
		p512, err := CanonicalPath(testRoot, "sha512:"+hex.EncodeToString(raw64))
		if err != nil {
			t.Fatal(err)
		}
		if p256 == p512 {
			t.Fatal("sha256 and sha512 digests collided onto one path")
		}
		if !strings.Contains(p256, filepath.Join("sha256", "")) || !strings.Contains(p512, filepath.Join("sha512", "")) {
			t.Fatalf("algorithm is not its own path segment: %q / %q", p256, p512)
		}
	})
}

// Test 1.6–1.9: reject cases and the traversal probe.
func TestDecodeDigestRejects(t *testing.T) {
	cases := []struct {
		name   string
		digest string
	}{
		{"1.6 unknown algo md5", "md5:" + strings.Repeat("0", 32)},
		{"1.6 unknown algo sha999", "sha999:" + strings.Repeat("0", 64)},
		{"1.7 wrong length (sha256 decoding to 30 bytes)", "sha256:" + strings.Repeat("0", 60)},
		{"1.8 undecodable payload (non-hex, non-b64 length)", "sha256:" + strings.Repeat("g", 40)},
		{"1.8 missing ':' separator", "sha256" + strings.Repeat("0", 64)},
		{"1.9 traversal ../../etc/passwd", "sha256:../../etc/passwd"},
		{"1.9 traversal encoded ..%2F..", "sha512:..%2F.." + strings.Repeat("0", 80)},
		{"empty digest", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := DecodeDigest(tc.digest); !errors.Is(err, ErrMalformedRef) {
				t.Fatalf("DecodeDigest(%q) err = %v, want ErrMalformedRef", tc.digest, err)
			}
			path, err := CanonicalPath(testRoot, tc.digest)
			if !errors.Is(err, ErrMalformedRef) {
				t.Fatalf("CanonicalPath(%q) err = %v, want ErrMalformedRef", tc.digest, err)
			}
			if path != "" {
				t.Fatalf("CanonicalPath(%q) produced a path %q on a malformed digest", tc.digest, path)
			}
		})
	}
}

// Test 1.9 belt-and-suspenders: no ACCEPTED digest ever yields a path with a ".." component
// or one that escapes the root.
func TestNoAcceptedDigestEscapesRoot(t *testing.T) {
	accepted := []string{
		"sha1:" + hex.EncodeToString(raw64[:20]),
		"sha256:" + hex.EncodeToString(raw64[:32]),
		"sha512:" + hex.EncodeToString(raw64),
		"sha512:" + base64.StdEncoding.EncodeToString(raw64),
	}
	for _, d := range accepted {
		path, err := CanonicalPath(testRoot, d)
		if err != nil {
			t.Fatalf("CanonicalPath(%q): %v", d, err)
		}
		assertUnderRoot(t, path)
	}
}

func assertUnderRoot(t *testing.T, path string) {
	t.Helper()
	rel, err := filepath.Rel(testRoot, path)
	if err != nil {
		t.Fatalf("filepath.Rel(%q, %q): %v", testRoot, path, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.Contains(rel, "..") {
		t.Fatalf("path %q escapes root (rel %q)", path, rel)
	}
}
