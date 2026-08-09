// bundle.go — the leave-behind bundle writer and the on-disk artifact shapes.
// Mirrors the resultsink.Local pattern: fixed, stable filenames; MkdirAll on
// write; plain os.WriteFile; skip nothing that a live generator produced. Each
// artifact carries a small honesty header so an agent reading one file knows the
// cgx command behind it and the confidence model it must respect.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Stable bundle paths. Downstream agents address artifacts by these names.
const (
	fileManifest = "manifest.json"
	fileAtlas    = "atlas.json"
	fileDeadCode = "dead-code.json"
	fileDataFlow = "data-flow.json"
	filePRDiff   = "pr-diff.json"
	dirSymbols   = "symbols"
	dirBlast     = "blast-radius"
)

// bundle writes JSON artifacts under a root directory.
type bundle struct {
	dir string
}

// writeJSON marshals v (indented, newline-terminated) to dir/relpath, creating
// parents as needed, and returns the number of bytes written.
func (b *bundle) writeJSON(relpath string, v any) (int, error) {
	full := filepath.Join(b.dir, relpath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return 0, err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return 0, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return 0, err
	}
	return len(data), nil
}

// artifactMeta is the honesty header on every artifact file.
type artifactMeta struct {
	Kind        string   `json:"kind"`
	Description string   `json:"description"`
	GeneratedBy []string `json:"generated_by"` // cgx argv(s) that produced this artifact
	Honesty     string   `json:"honesty"`      // confidence model the reader must respect
}

// rawOrNull returns r as an any that marshals verbatim, or nil (JSON null) when
// cgx emitted no envelope — so a missing envelope reads as null, never "{}".
func rawOrNull(r json.RawMessage) any {
	if len(r) == 0 {
		return nil
	}
	return r
}

// unquote decodes a CQL string cell; on any non-string cell it returns the raw
// bytes so nothing is silently dropped.
func unquote(r json.RawMessage) string {
	var s string
	if err := json.Unmarshal(r, &s); err == nil {
		return s
	}
	return string(r)
}

// --- shared classification helpers -----------------------------------------

// isFirstParty excludes vendored and testdata-fixture paths so hub/dead-code
// views describe the app, not its bundled dependencies or repro corpora.
func isFirstParty(file string) bool {
	if strings.HasPrefix(file, "vendor/") || strings.Contains(file, "/vendor/") {
		return false
	}
	if strings.Contains(file, "corpus/testdata/") {
		return false
	}
	return true
}

// isExportedGo reports whether the final FQN segment names a Go-exported symbol
// (leading upper-case rune) — the exported-but-unused signal that separates an
// API-surface candidate from truly dead code.
func isExportedGo(fqn string) bool {
	seg := fqn
	if i := strings.LastIndex(fqn, "::"); i >= 0 {
		seg = fqn[i+2:]
	}
	seg = strings.TrimPrefix(seg, "(*")
	seg = strings.TrimPrefix(seg, "(")
	for _, r := range seg {
		return unicode.IsUpper(r)
	}
	return false
}

// isTestSymbol reports whether an FQN/file pair is test scaffolding.
func isTestSymbol(row searchRow) bool {
	if strings.HasSuffix(row.File, "_test.go") {
		return true
	}
	seg := row.Fqn
	if i := strings.LastIndex(seg, "::"); i >= 0 {
		seg = seg[i+2:]
	}
	return strings.HasPrefix(seg, "Test") || strings.HasPrefix(seg, "Benchmark") || strings.HasPrefix(seg, "Fuzz")
}

// cardName turns an FQN into a filesystem-safe card filename within a package
// directory, dropping the leading "<pkg>::" and collapsing Go receiver/pointer
// punctuation into readable, unique names (e.g. hostmatch::(*Matcher)::Allows ->
// Matcher.Allows.json).
func cardName(pkg, fqn string) string {
	name := strings.TrimPrefix(fqn, pkg+"::")
	name = strings.NewReplacer(
		"(*", "",
		"(", "",
		")", "",
		"*", "",
		"::", ".",
	).Replace(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String() + ".json"
}
