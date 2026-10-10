// Package compiledb discovers and parses a JSON compilation database (compile_commands.json,
// https://clang.llvm.org/docs/JSONCompilationDatabase.html) into per-translation-unit build
// context: the source file, its language mode (c or c++), std level, target triple and compiler
// identity.
//
// It is engine-independent. The parsed TUs feed the lane's build manifest, and the raw bytes are
// kept unmodified on DB.Raw so a graph engine that wants the database itself can be handed exactly
// what the build wrote.
//
// Nothing here guesses. An invocation the parser cannot read faithfully (a response file, an MSVC
// driver, a compiler wrapper with no compiler after it) is recorded on TU.Unhandled; a field the
// invocation does not state (no -std=, no --target) is left empty, meaning "the compiler's
// default", never filled in.
package compiledb

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileName is the conventional compilation database name.
const FileName = "compile_commands.json"

// Lang is a translation unit's language mode.
type Lang string

const (
	LangC   Lang = "c"
	LangCXX Lang = "c++"
)

// Unhandled reasons: the part of an invocation the parser declined to interpret.
const (
	UnhandledResponseFile = "response_file"    // an @file argument; its flags were not expanded
	UnhandledMSVC         = "msvc_driver"      // cl/clang-cl flag syntax; std and target not parsed
	UnhandledWrapper      = "compiler_wrapper" // a ccache-style wrapper with no compiler argument after it
)

// Skip reasons: why a database entry is not a C/C++ translation unit.
const (
	SkipHeader    = "header"           // a header entry; a header is not a translation unit
	SkipLang      = "unsupported_lang" // a TU in a language this lane does not analyze (asm, objc, cuda, ...)
	SkipMalformed = "malformed_entry"  // missing directory/file, no command, or an unparseable command string
)

// Compiler is the compiler identity read from an invocation's argv.
type Compiler struct {
	Driver  string `json:"driver"`            // argv[0] after wrapper stripping, as written
	Family  string `json:"family,omitempty"`  // "gcc", "clang" or "msvc"; empty for a generic driver (cc, c++) or an unknown one
	Wrapper string `json:"wrapper,omitempty"` // the stripped wrapper (ccache, sccache, distcc, ...), if any
}

// TU is one translation unit: one compile_commands.json entry that compiles C or C++.
type TU struct {
	File      string   `json:"file"`      // absolute, cleaned
	Directory string   `json:"directory"` // absolute, cleaned
	Lang      Lang     `json:"lang"`
	Std       string   `json:"std,omitempty"`    // as written (-std=gnu17 -> "gnu17"); empty = compiler default
	Target    string   `json:"target,omitempty"` // --target triple, or a cross-compiler driver's triple prefix; empty = host default
	Compiler  Compiler `json:"compiler"`
	Unhandled []string `json:"unhandled,omitempty"` // sorted Unhandled* reasons
}

// Skipped is a database entry that did not become a TU, kept as evidence.
type Skipped struct {
	Index  int    `json:"index"` // position in the database array
	File   string `json:"file,omitempty"`
	Reason string `json:"reason"` // a Skip* reason
	Detail string `json:"detail,omitempty"`
}

// DB is a parsed compilation database.
type DB struct {
	Path    string    `json:"path"` // the file the database was read from
	Raw     []byte    `json:"-"`    // the bytes as read, for hand-off to an engine
	TUs     []TU      `json:"tus"`
	Skipped []Skipped `json:"skipped,omitempty"`
}

// HasUnsupportedTU reports whether any entry is a translation unit in a language the lane does
// not analyze. Headers do not count: a header is not a compilation unit.
func (db DB) HasUnsupportedTU() bool {
	for _, s := range db.Skipped {
		if s.Reason == SkipLang {
			return true
		}
	}
	return false
}

// HasMalformedEntry reports whether any entry could not be read at all.
func (db DB) HasMalformedEntry() bool {
	for _, s := range db.Skipped {
		if s.Reason == SkipMalformed {
			return true
		}
	}
	return false
}

// ErrMalformed is returned (wrapped) when the database is not a JSON array of entry objects.
var ErrMalformed = errors.New("compiledb: malformed compilation database")

// Discover returns the compilation databases under root, best candidate first: root itself, then
// root/build, then any other directory up to two levels down, each level in lexical order. Hidden
// directories and dependency trees are not searched. An empty result means none was found.
func Discover(root string) []string {
	var out []string
	add := func(dir string) {
		p := filepath.Join(dir, FileName)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			for _, seen := range out {
				if seen == p {
					return
				}
			}
			out = append(out, p)
		}
	}
	add(root)
	add(filepath.Join(root, "build"))
	level := []string{root}
	for depth := 0; depth < 2; depth++ {
		var next []string
		for _, dir := range level {
			for _, sub := range subdirs(dir) {
				add(sub)
				next = append(next, sub)
			}
		}
		level = next
	}
	return out
}

// subdirs lists dir's searchable subdirectories in lexical order.
func subdirs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || skipDir(e.Name()) {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out
}

func skipDir(name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}
	switch name {
	case "node_modules", "vendor", "third_party", "third-party", "external", "_deps":
		return true
	}
	return false
}

// Load reads and parses the database at path.
func Load(path string) (DB, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return DB{}, fmt.Errorf("compiledb: read %q: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return DB{}, fmt.Errorf("compiledb: resolve %q: %w", path, err)
	}
	return Parse(raw, abs)
}

// entry is one raw database object. Arguments is preferred over Command when both are present,
// as the spec directs.
type entry struct {
	Directory *string  `json:"directory"`
	File      *string  `json:"file"`
	Arguments []string `json:"arguments"`
	Command   *string  `json:"command"`
}

// Parse parses raw as the database stored at path. A relative entry directory resolves against
// the database's own directory; a relative file against the entry directory. Entries that are not
// C/C++ translation units are returned on DB.Skipped, never dropped silently.
func Parse(raw []byte, path string) (DB, error) {
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return DB{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	db := DB{Path: path, Raw: raw}
	base := filepath.Dir(path)
	for i, e := range entries {
		tu, skip := parseEntry(e, base)
		if skip != nil {
			skip.Index = i
			db.Skipped = append(db.Skipped, *skip)
			continue
		}
		db.TUs = append(db.TUs, tu)
	}
	return db, nil
}

func parseEntry(e entry, base string) (TU, *Skipped) {
	if e.Directory == nil || *e.Directory == "" || e.File == nil || *e.File == "" {
		return TU{}, &Skipped{Reason: SkipMalformed, Detail: "entry lacks directory or file"}
	}
	dir := *e.Directory
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(base, dir)
	}
	dir = filepath.Clean(dir)
	file := *e.File
	if !filepath.IsAbs(file) {
		file = filepath.Join(dir, file)
	}
	file = filepath.Clean(file)

	argv := e.Arguments
	if len(argv) == 0 {
		if e.Command == nil {
			return TU{}, &Skipped{File: file, Reason: SkipMalformed, Detail: "entry has neither arguments nor command"}
		}
		var err error
		argv, err = SplitCommand(*e.Command)
		if err != nil {
			return TU{}, &Skipped{File: file, Reason: SkipMalformed, Detail: err.Error()}
		}
	}
	if len(argv) == 0 {
		return TU{}, &Skipped{File: file, Reason: SkipMalformed, Detail: "empty command"}
	}

	inv := readInvocation(argv, *e.File, file, dir)
	switch inv.kind {
	case kindHeader:
		return TU{}, &Skipped{File: file, Reason: SkipHeader}
	case kindOther:
		return TU{}, &Skipped{File: file, Reason: SkipLang, Detail: inv.otherLang}
	}
	return TU{
		File:      file,
		Directory: dir,
		Lang:      inv.lang,
		Std:       inv.std,
		Target:    inv.target,
		Compiler:  inv.compiler,
		Unhandled: inv.unhandled,
	}, nil
}
