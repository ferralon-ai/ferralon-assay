package pythonanalysis

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

// A byte-order mark never changes the Python verdict for a file judged by its head: a requirement
// file found by content, in each of the five marked encodings, gets the same candidates (rule and
// FullyRead) and the same Found and Exhaustive as its twin, the same text in UTF-8 without the
// mark. The bodies put the requirement before, across, at and past the HeadSize cut in UTF-8
// bytes, carry a NUL, and cross HeadSize in one encoding and not the other.
//
// The scope is files judged by their head. A name-matched manifest is read in full by its parser,
// which does not decode a mark, so a marked one is not fully read and withholds
// (TestResolveVersions_MarkedRequirementsTxtWithholds).
func TestResolveVersions_BOMTwins(t *testing.T) {
	const req = "pyjwt==2.8.0\n"
	eLine := "# résumé café ééé\r\n"
	cjkLine := "# 中文注释中文注释\n"
	hs := buildtree.HeadSize
	bodies := []struct{ name, body string }{
		{"ASCII", "# pins\n" + req},
		{"e-heavy", commentLines(eLine, 20000) + req},
		{"requirement ends at the cut", commentLines(eLine, hs-len(req)) + req},
		{"requirement straddles the cut", commentLines(eLine, hs-5) + req},
		{"requirement starts at the cut", commentLines(eLine, hs) + req},
		{"requirement past the cut", commentLines(eLine, hs+100) + req},
		{"NUL before the requirement", "# a\x00b\n" + req},
		{"CJK, UTF-8 past the cut, UTF-16 within it", commentLines(cjkLine, 72000) + req},
		{"ASCII, UTF-8 within the cut, UTF-16 and UTF-32 past it", commentLines("# some words\n", 40000) + req},
	}
	verdict := func(body string) string {
		dir := writeTree(t, map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject, "deps.pins": body})
		r := resolveVersion(t, dir, "PyJWT")
		got := fmt.Sprintf("found=%v exhaustive=%v", r.Found, r.Exhaustive)
		for _, c := range ManifestCandidates(dir) {
			if strings.HasSuffix(c.Path, "deps.pins") {
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

// A name-matched requirements.txt in UTF-16LE, which pip decodes, is not fully read: a
// requirement only it holds withholds and is never found.
func TestResolveVersions_MarkedRequirementsTxtWithholds(t *testing.T) {
	const reqs = "flask==2.0.0\r\npyjwt==2.8.0\r\n"
	for _, tc := range []struct {
		name, content          string
		wantFound, wantFullyRd bool
	}{
		{"UTF-8 twin", reqs, true, true},
		{"UTF-16LE", encodeBOM("UTF-16LE", reqs), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"uv.lock": exUVLock, "pyproject.toml": exPyproject, "requirements.txt": tc.content})
			r := resolveVersion(t, dir, "PyJWT")
			if r.Found != tc.wantFound || r.Exhaustive {
				t.Errorf("PyJWT found=%v exhaustive=%v; want found=%v, not exhaustive", r.Found, r.Exhaustive, tc.wantFound)
			}
			for _, c := range ManifestCandidates(dir) {
				if strings.HasSuffix(c.Path, "requirements.txt") && c.FullyRead != tc.wantFullyRd {
					t.Errorf("requirements.txt FullyRead = %v, want %v", c.FullyRead, tc.wantFullyRd)
				}
			}
		})
	}
}
