package pythonanalysis

import (
	"bytes"
	"strings"
	"testing"
)

// TestClassifyContent pins every archive suffix and magic, every executable magic, and the
// Unicode decodings: each entry must classify as listed.
func TestClassifyContent(t *testing.T) {
	for _, ext := range archiveExts {
		if _, kind := classifyContent("f"+ext, []byte("text")); kind != contentArchive {
			t.Errorf("suffix %s: kind %d, want archive", ext, kind)
		}
		if _, kind := classifyContent("F"+strings.ToUpper(ext), []byte("text")); kind != contentArchive {
			t.Errorf("suffix %s in upper case: kind %d, want archive", ext, kind)
		}
	}
	for _, m := range archiveMagic {
		if _, kind := classifyContent("f", append(append([]byte{}, m...), 0, 0, 0)); kind != contentArchive {
			t.Errorf("magic %q: kind %d, want archive", m, kind)
		}
	}
	for _, m := range executableMagic {
		if _, kind := classifyContent("f", append(append([]byte{}, m...), 0, 0, 0)); kind != contentExecutable {
			t.Errorf("magic %q: kind %d, want executable", m, kind)
		}
	}
	const cmd = "pip install black\n"
	for name, data := range map[string]string{
		"utf-8":        cmd,
		"utf-8 bom":    "\xef\xbb\xbf" + cmd,
		"latin-1":      "# caf\xe9\n" + cmd,
		"utf-16le bom": utf16Text(cmd, false, true),
		"utf-16be bom": utf16Text(cmd, true, true),
		"utf-16le":     utf16Text(cmd, false, false),
		"utf-16be":     utf16Text(cmd, true, false),
		"utf-32le bom": "\xff\xfe\x00\x00" + utf32le(cmd),
		"utf-32be bom": "\x00\x00\xfe\xff" + utf32be(cmd),
	} {
		text, kind := classifyContent("f", []byte(data))
		if kind != contentText || !bytes.Contains(text, []byte(cmd)) {
			t.Errorf("%s: kind %d, text %q; want text containing %q", name, kind, text, cmd)
		}
	}
	if _, kind := classifyContent("logo.png", []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")); kind != contentBinary {
		t.Errorf("png: kind %d, want binary", kind)
	}
	if _, kind := classifyContent("f", []byte("#!/bin/sh\nexit\n"+zipText(map[string]string{"a": "b"}))); kind != contentArchive {
		t.Errorf("zip behind a prefix: kind %d, want archive", kind)
	}
}

func utf32be(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		b.Write([]byte{byte(r >> 24), byte(r >> 16), byte(r >> 8), byte(r)})
	}
	return b.String()
}
