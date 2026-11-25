package trigger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// jsLaunchDigest is the report.SBOM.JSLaunchDigest of the tree at dir: a sha256 over the "scripts"
// and "bin" fields of every first-party package.json, keyed by its path relative to dir. A
// package.json under node_modules or a dot-directory is not first-party and is skipped. One that
// cannot be read or parsed is hashed whole, so any edit to it still moves the digest. "" when dir
// is "" or holds no first-party package.json.
func jsLaunchDigest(dir string) string {
	if dir == "" {
		return ""
	}
	h := sha256.New()
	found := false
	// WalkDir visits entries in lexical order, so the digest does not depend on the filesystem's.
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "package.json" || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return nil
		}
		found = true
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		h.Write(launchFields(p))
		h.Write([]byte{'\n'})
		return nil
	})
	if !found {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// launchFields is the canonical JSON of a package.json's "scripts" and "bin" fields (keys sorted,
// whitespace dropped), or the file's own bytes, marked, when it does not parse.
func launchFields(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []byte("unreadable")
	}
	var m struct {
		Scripts any `json:"scripts"`
		Bin     any `json:"bin"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return append([]byte("unparsed\x00"), raw...)
	}
	out, err := json.Marshal([]any{m.Scripts, m.Bin})
	if err != nil {
		return append([]byte("unparsed\x00"), raw...)
	}
	return out
}
