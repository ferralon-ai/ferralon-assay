package javaanalysis

// pomxml.go — the single POM XML-decode entry point. Go's encoding/xml decoder only accepts
// UTF-8; Maven POMs are frequently ISO-8859-1 (latin1) or another declared encoding. Routing
// every POM decode through unmarshalPOM wires a CharsetReader so a declared-encoding POM decodes
// in-process (no exec, no net — C2/C5) instead of failing and degrading to honest-absent residue.

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"

	"golang.org/x/net/html/charset"
)

// unmarshalPOM decodes a pom.xml byte slice into v, honoring the document's declared charset.
// UTF-8 input decodes unchanged; latin1 and other labels named by charset.NewReaderLabel now
// decode instead of erroring. Genuinely malformed/undecodable XML still returns an error, so the
// caller's honest-absent residue path is preserved.
func unmarshalPOM(data []byte, v any) error {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = charset.NewReaderLabel
	return d.Decode(v)
}

// pomRefs returns the name of every ${...} expression in a POM outside the parts a consumer of a
// cached POM never reads: <build> and <reporting>, of the project or of a profile, never run in
// another project's build. <properties> blocks are left out too; a reader follows a property's
// value from its definition, so only a value that is itself reached counts. Comments are not
// read. ok is false when the XML does not decode or an expression isn't one plain name (nested,
// or unterminated), so what it reaches can't be bounded.
func pomRefs(data []byte) (refs map[string]bool, ok bool) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.CharsetReader = charset.NewReaderLabel
	refs = map[string]bool{}
	var stack []string
	var text strings.Builder
	flush := func() bool {
		s := text.String()
		text.Reset()
		return scanRefs(s, refs)
	}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return refs, len(stack) == 0 && flush()
		}
		if err != nil {
			return nil, false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if !flush() {
				return nil, false
			}
			top := len(stack) == 1
			inProfile := len(stack) == 3 && stack[1] == "profiles" && stack[2] == "profile"
			if name := t.Name.Local; (top || inProfile) && (name == "build" || name == "reporting" || name == "properties") {
				if err := d.Skip(); err != nil {
					return nil, false
				}
				continue
			}
			for _, a := range t.Attr {
				if !scanRefs(a.Value, refs) {
					return nil, false
				}
			}
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if !flush() || len(stack) == 0 {
				return nil, false
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			text.Write(t)
		}
	}
}

// scanRefs adds each ${name} in s to refs, and reports false for an expression that isn't one
// plain name.
func scanRefs(s string, refs map[string]bool) bool {
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			return true
		}
		end := strings.IndexByte(s[start:], '}')
		if end < 0 {
			return false
		}
		name := s[start+2 : start+end]
		if name == "" || strings.ContainsAny(name, "${") {
			return false
		}
		refs[name] = true
		s = s[start+end+1:]
	}
}
