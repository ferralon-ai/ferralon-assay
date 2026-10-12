package cfamilyanalysis

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis/compiledb"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Provenance of a toolchain identity. The values are the RuntimeSource vocabulary of RFC 0001 §3.
const (
	sourceDeclared  = "declared"   // a committed build file
	sourceAmbient   = "ambient"    // build-host state, not committed (a CMake cache)
	sourceCompileDB = "compile_db" // reconstructed from compile_commands.json invocations
)

// Localised partiality reasons for build-context derivation, on existing base codes.
const (
	reasonCompileDBEmpty      = plugin.PartialReasonNoManifest + ":compile_db_empty"         // a database with no C/C++ translation units
	reasonCompileDBUnreadable = plugin.PartialReasonToolFailure + ":compile_db"              // the database could not be read or is not an entry array
	reasonCompileDBEntry      = plugin.PartialReasonToolFailure + ":compile_db_entry"        // an entry lacks directory/file/command or its command does not split
	reasonBuildConfig         = plugin.PartialReasonEnvConditionUnresolved + ":build_config" // several databases (build configurations); one was read
	reasonTULang              = plugin.PartialReasonUnsupported + ":tu_lang"                 // a TU in a language the lane does not analyze
)

// reasonUnhandled localises a TU's compiledb.Unhandled* reason (response_file, msvc_driver,
// compiler_wrapper) onto unsupported_phase1: the invocation's flags were not fully read.
func reasonUnhandled(u string) string { return plugin.PartialReasonUnsupported + ":" + u }

// toolchain is one distinct toolchain the build uses. Its fields are RFC 0001 §3's RuntimeSpec
// (Name, Toolchain, Source, Target, Lang, StdLevel); Version stays empty because neither a
// compilation database nor a CMake cache records the compiler's version.
type toolchain struct {
	Name      string // compiler identity: "gcc", "clang", "msvc", or the driver name ("cc")
	Toolchain string // the compiler driver as invoked
	Source    string // sourceCompileDB or sourceAmbient
	Target    string // target triple; empty = the compiler's host default
	Lang      string // "c" or "c++"
	StdLevel  string // std as written ("gnu17"); empty = the compiler's default
}

// generator is a detected build generator, RFC 0001 §3's ResolverSpec. Its Source is always
// sourceDeclared: the generator is read off a committed build file.
type generator struct {
	Name    string
	Command string
}

// buildContext is the C-family lane's engine-independent build context: the input BuildManifest
// emits, and the database a graph engine is handed.
type buildContext struct {
	Partiality plugin.Partiality
	Runtimes   []toolchain
	Resolvers  []generator
	DB         *compiledb.DB // nil when no database was read
}

// generators are probed in this order; a tree may carry several.
var generators = []struct {
	gen     generator
	markers []string
}{
	{generator{"cmake", "cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"}, []string{"CMakeLists.txt"}},
	{generator{"meson", "meson setup build"}, []string{"meson.build"}},
	{generator{"bazel", "bazel build //..."}, []string{"MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"}},
	{generator{"make", "make"}, []string{"GNUmakefile", "Makefile", "makefile"}},
}

// deriveBuildContext reads the build context of the C/C++ tree at buildDir.
//
// Runtimes come from the first compilation database Discover finds: one per distinct
// (target, lang, std, compiler) across its translation units, Source compile_db. With no database
// but a CMake cache, the cache's C and C++ compilers become ambient runtimes with no target or
// std, since the cache does not state them. With neither, Runtimes is empty: no toolchain is
// fabricated. Every such gap is a declared reason; a C++ TU is carried exactly as a C one is.
//
// Resolvers are the generators whose committed build file is at the root; none declares
// no_manifest.
func deriveBuildContext(buildDir string) (buildContext, error) {
	fi, err := os.Stat(buildDir)
	if err != nil {
		return buildContext{}, fmt.Errorf("cfamilyanalysis: stat build dir %q: %w", buildDir, err)
	}
	if !fi.IsDir() {
		return buildContext{}, fmt.Errorf("cfamilyanalysis: build dir %q is not a directory", buildDir)
	}

	var bc buildContext
	reasons := newReasonSet()

	for _, g := range generators {
		for _, m := range g.markers {
			if mfi, err := os.Stat(filepath.Join(buildDir, m)); err == nil && mfi.Mode().IsRegular() {
				bc.Resolvers = append(bc.Resolvers, g.gen)
				break
			}
		}
	}
	if len(bc.Resolvers) == 0 {
		reasons.add(plugin.PartialReasonNoManifest)
	}

	dbs := compiledb.Discover(buildDir)
	switch {
	case len(dbs) == 0:
		reasons.add(plugin.PartialReasonNoManifest)
		bc.Runtimes = ambientRuntimes(buildDir)
	default:
		if len(dbs) > 1 {
			reasons.add(reasonBuildConfig)
		}
		db, err := compiledb.Load(dbs[0])
		if err != nil {
			reasons.add(reasonCompileDBUnreadable)
			break
		}
		bc.DB = &db
		bc.Runtimes = compileDBRuntimes(db, reasons)
	}

	bc.Partiality = reasons.partiality()
	return bc, nil
}

// compileDBRuntimes groups the database's TUs into distinct toolchains and adds a reason for every
// part of the database that was not read in full.
func compileDBRuntimes(db compiledb.DB, reasons reasonSet) []toolchain {
	if len(db.TUs) == 0 {
		reasons.add(reasonCompileDBEmpty)
	}
	if db.HasUnsupportedTU() {
		reasons.add(reasonTULang)
	}
	if db.HasMalformedEntry() {
		reasons.add(reasonCompileDBEntry)
	}
	seen := map[toolchain]bool{}
	var out []toolchain
	for _, tu := range db.TUs {
		for _, u := range tu.Unhandled {
			reasons.add(reasonUnhandled(u))
		}
		tc := toolchain{
			Name:      tu.Compiler.Identity(),
			Toolchain: tu.Compiler.Driver,
			Source:    sourceCompileDB,
			Target:    tu.Target,
			Lang:      string(tu.Lang),
			StdLevel:  tu.Std,
		}
		if !seen[tc] {
			seen[tc] = true
			out = append(out, tc)
		}
	}
	sortToolchains(out)
	return out
}

// ambientRuntimes reads the C and C++ compilers CMake recorded in the first CMakeCache.txt found.
func ambientRuntimes(buildDir string) []toolchain {
	caches := compiledb.Find(buildDir, "CMakeCache.txt")
	if len(caches) == 0 {
		return nil
	}
	data, err := os.ReadFile(caches[0])
	if err != nil {
		return nil
	}
	langs := map[string]string{"CMAKE_C_COMPILER": string(compiledb.LangC), "CMAKE_CXX_COMPILER": string(compiledb.LangCXX)}
	var out []toolchain
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(key, ":")
		lang, ok := langs[name]
		value = strings.TrimSpace(value)
		if !ok || value == "" || strings.HasSuffix(value, "-NOTFOUND") {
			continue
		}
		c := compiledb.CompilerFromDriver(value)
		out = append(out, toolchain{Name: c.Identity(), Toolchain: value, Source: sourceAmbient, Lang: lang})
	}
	sortToolchains(out)
	return out
}

func sortToolchains(ts []toolchain) {
	sort.Slice(ts, func(i, j int) bool {
		a, b := ts[i], ts[j]
		if a.Lang != b.Lang {
			return a.Lang < b.Lang
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.StdLevel != b.StdLevel {
			return a.StdLevel < b.StdLevel
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Toolchain < b.Toolchain
	})
}
