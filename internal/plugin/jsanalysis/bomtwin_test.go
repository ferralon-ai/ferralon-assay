package jsanalysis

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// encodeBOM encodes UTF-8 text s behind the named byte-order mark.
func encodeBOM(enc, s string) string {
	if enc == "UTF-8" {
		return "\xef\xbb\xbf" + s
	}
	order, unit := binary.AppendByteOrder(binary.LittleEndian), 2
	switch enc {
	case "UTF-16BE":
		order = binary.BigEndian
	case "UTF-32LE":
		unit = 4
	case "UTF-32BE":
		order, unit = binary.BigEndian, 4
	}
	var b []byte
	for _, r := range string(rune(0xFEFF)) + s {
		if unit == 4 {
			b = order.AppendUint32(b, uint32(r))
			continue
		}
		for _, u := range utf16.Encode([]rune{r}) {
			b = order.AppendUint16(b, u)
		}
	}
	return string(b)
}

// commentLines returns n UTF-8 bytes of comment lines, ending in a newline.
func commentLines(line string, n int) string {
	var b strings.Builder
	for b.Len()+len(line) < n {
		b.WriteString(line)
	}
	b.WriteString(strings.Repeat("#", n-b.Len()-1) + "\n")
	return b.String()
}

// A byte-order mark never changes the JavaScript verdict for a file judged by its head: an .npmrc,
// a candidate when its head names a rewriting setting or fills HeadSize (the file may go on), in
// each of the five marked encodings, gets the same candidates (rule and FullyRead) and the same
// Exhaustive as its twin, the same text in UTF-8 without the mark. The bodies put the setting
// before and past the HeadSize cut in UTF-8 bytes, carry a NUL, fill the cut exactly, and cross
// HeadSize in one encoding and not the other.
//
// The scope is files judged by their head. A name-matched manifest is read in full by its parser,
// which does not decode a mark, so a marked one is not fully read and withholds
// (TestResolveVersions_MarkedManifestWithholds).
func TestResolveVersions_BOMTwins(t *testing.T) {
	const setting = "overrides[absent-package]=1.0.0\n"
	eLine := "# résumé café ééé\r\n"
	cjkLine := "# 中文注释中文注释\n"
	hs := buildtree.HeadSize
	bodies := []struct{ name, body string }{
		{"ASCII registry only", "registry=https://registry.npmjs.org/\n"},
		{"ASCII setting", "registry=https://registry.npmjs.org/\n" + setting},
		{"e-heavy, setting within the cut", commentLines(eLine, 20000) + setting},
		{"e-heavy, no setting, below the cut", commentLines(eLine, hs-1)},
		{"e-heavy, setting past the cut", commentLines(eLine, hs+100) + setting},
		{"NUL in a comment", "# a\x00b\nregistry=https://registry.npmjs.org/\n"},
		{"ASCII filling the cut exactly", commentLines("# x\n", hs)},
		{"CJK, UTF-8 past the cut, UTF-16 within it", commentLines(cjkLine, 72000)},
		{"ASCII, UTF-8 within the cut, UTF-16 and UTF-32 past it", commentLines("# some words\n", 40000)},
	}
	verdict := func(body string) string {
		dir := writeLockTree(t, map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, ".npmrc": body})
		r := resolveJS(t, dir, "absent-package")
		got := fmt.Sprintf("found=%v exhaustive=%v", r.Found, r.Exhaustive)
		for _, c := range ManifestCandidates(dir) {
			if strings.HasSuffix(c.Path, ".npmrc") {
				got += fmt.Sprintf(" candidate=%s:%v", c.Why, c.FullyRead)
			}
		}
		return got
	}
	for _, b := range bodies {
		want := verdict(b.body)
		for _, enc := range []string{"UTF-8", "UTF-16LE", "UTF-16BE", "UTF-32LE", "UTF-32BE"} {
			t.Run(b.name+"/"+enc, func(t *testing.T) {
				if got := verdict(encodeBOM(enc, b.body)); got != want {
					t.Errorf("verdict = %q, want the twin's %q", got, want)
				}
			})
		}
	}
}

// A name-matched package-lock.json or package.json in UTF-16LE is not fully read: Exhaustive is
// withheld, and a coordinate only the unread lockfile records is never found.
func TestResolveVersions_MarkedManifestWithholds(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		files                map[string]string
		wantExpress, wantExh bool
	}{
		{"UTF-8 twin", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3}, true, true},
		{"UTF-16LE package-lock.json", map[string]string{"package.json": exPkgJSON, "package-lock.json": encodeBOM("UTF-16LE", exLockV3)}, false, false},
		{"UTF-16LE package.json", map[string]string{"package.json": encodeBOM("UTF-16LE", exPkgJSON), "package-lock.json": exLockV3}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeLockTree(t, tc.files)
			if r := resolveJS(t, dir, "absent-package"); r.Found || r.Exhaustive != tc.wantExh {
				t.Errorf("absent-package found=%v exhaustive=%v; want not found, exhaustive=%v", r.Found, r.Exhaustive, tc.wantExh)
			}
			if r := resolveJS(t, dir, "express"); r.Found != tc.wantExpress {
				t.Errorf("express found=%v, want %v", r.Found, tc.wantExpress)
			}
		})
	}
}
