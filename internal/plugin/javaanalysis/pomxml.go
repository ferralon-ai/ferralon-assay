package javaanalysis

// pomxml.go — the single POM XML-decode entry point. Go's encoding/xml decoder only accepts
// UTF-8; Maven POMs are frequently ISO-8859-1 (latin1) or another declared encoding. Routing
// every POM decode through unmarshalPOM wires a CharsetReader so a declared-encoding POM decodes
// in-process (no exec, no net — C2/C5) instead of failing and degrading to honest-absent residue.

import (
	"bytes"
	"encoding/xml"

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
