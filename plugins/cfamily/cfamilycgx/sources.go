package cfamilycgx

import (
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis/compiledb"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// fileLang is how cgx reads a file, which its extension alone decides: cgx is handed no
// compilation database, so a TU's -x flag or driver never reaches it.
type fileLang int

const (
	langNone fileLang = iota
	langC
	langCXX
	langCHeader   // .h: cgx parses it as C whatever includes it
	langCXXHeader // .hh .hpp .hxx
)

func langOf(p string) fileLang {
	switch strings.ToLower(path.Ext(p)) {
	case ".c":
		return langC
	case ".cc", ".cpp", ".cxx":
		return langCXX
	case ".h":
		return langCHeader
	case ".hh", ".hpp", ".hxx":
		return langCXXHeader
	}
	return langNone
}

func (l fileLang) source() bool { return l == langC || l == langCXX }
func (l fileLang) header() bool { return l == langCHeader || l == langCXXHeader }

// cSyntax: the file is read as C, where a call through a struct member is a function pointer.
func (l fileLang) cSyntax() bool { return l == langC || l == langCHeader }

// Reasons the tree itself carries, before cgx runs.
const (
	// A translation unit cgx produced no symbol for (or one that could not be staged: outside
	// the build directory, or missing). Loud: that unit's calls are absent from the graph.
	reasonEmptyTU = plugin.PartialReasonToolFailure + ":empty_tu"
	// No compilation database and no C/C++ source in the tree: nothing was analyzed.
	reasonNoSources = plugin.PartialReasonNoManifest + ":no_sources"
	// A TU's database language disagrees with the language cgx reads its extension as, or its
	// extension is one cgx does not read at all.
	reasonTULang = plugin.PartialReasonUnsupported + ":cgx_tu_lang"
	// The build compiles C++ and the tree has .h headers, which cgx parses as C: C++ in them
	// (classes, namespaces, templates) is misread.
	reasonHAsC = plugin.PartialReasonUnsupported + ":cgx_h_as_c"
)

// selection is the set of files staged for cgx and what staging them declared.
type selection struct {
	files   []string // staged, relative to the build directory, sorted
	tus     []string // staged translation units, each checked for symbols after indexing
	reasons map[string]bool
}

// selectSources picks what cgx indexes. With a compilation database: each of its translation
// units plus every header in the tree (a database names no headers, and which a TU includes is
// a preprocessor question cgx does not answer). With none: every C/C++ source and header. Files
// under a CMakeFiles directory (CMake's compiler-probe sources) are never staged.
func selectSources(work string, db *compiledb.DB, candidates []string) selection {
	sel := selection{reasons: map[string]bool{}}
	var headers, sources []string
	for _, f := range candidates {
		if underCMakeFiles(f) {
			continue
		}
		switch l := langOf(f); {
		case l.header():
			headers = append(headers, f)
		case l.source():
			sources = append(sources, f)
		}
	}

	hasCXX := false
	if db == nil {
		sel.reasons[plugin.PartialReasonNoManifest] = true
		if len(sources) == 0 {
			sel.reasons[reasonNoSources] = true
		}
		sel.tus = sources
		for _, s := range sources {
			hasCXX = hasCXX || langOf(s) == langCXX
		}
	} else {
		for _, tu := range db.TUs {
			rel, ok := relInside(work, tu.File)
			if !ok {
				sel.reasons[reasonEmptyTU] = true
				continue
			}
			l := langOf(rel)
			if !l.source() {
				sel.reasons[reasonTULang] = true
				continue
			}
			if (tu.Lang == compiledb.LangCXX) != (l == langCXX) {
				sel.reasons[reasonTULang] = true
			}
			hasCXX = hasCXX || tu.Lang == compiledb.LangCXX || l == langCXX
			sel.tus = append(sel.tus, rel)
		}
		sel.tus = sortedUnique(sel.tus)
	}
	if hasCXX {
		for _, h := range headers {
			if langOf(h) == langCHeader {
				sel.reasons[reasonHAsC] = true
				break
			}
		}
	}
	sel.files = sortedUnique(append(append([]string{}, sel.tus...), headers...))
	return sel
}

// relInside returns file relative to work, slash-separated, when it is an existing regular file
// inside work.
func relInside(work, file string) (string, bool) {
	abs, err := filepath.EvalSymlinks(file)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(work, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func underCMakeFiles(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "CMakeFiles" {
			return true
		}
	}
	return false
}

func sortedUnique(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
