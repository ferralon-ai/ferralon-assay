package pythonanalysis

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/internal/pep440"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
)

// moduleProbe looks up paths relative to a manifest's directory: clear reports whether
// nothing is there, and files returns the files at p read here, or nil.
type moduleProbe struct {
	clear func(p string) bool
	files func(p string) []string
}

// versionRead is the module a backend reads a dynamic version or description from without
// importing it: the files it may be, the name whose assignment holds the version ("" when
// only the description is read), whether the module's docstring is read too, and whether the
// backend may read the module as text in the locale's encoding, as setuptools before 65.4.1
// does (setuptoolsReadsBytes), so only ASCII is read the same everywhere.
type versionRead struct {
	files     []string
	attr      string
	docstring bool
	ascii     bool
}

// static reports whether src holds what vr reads as plain string literals.
func (vr *versionRead) static(src []byte) bool {
	if vr.ascii && bytes.ContainsFunc(src, func(r rune) bool { return r >= utf8.RuneSelf }) {
		return false
	}
	return staticAssigned(src, vr.attr, vr.docstring)
}

// versionModule returns the module a manifest's setuptools or flit_core backend reads its
// dynamic metadata from, nil when it reads none. ok is false when the module is not one this
// resolves to a single place.
//
// setuptools reads tool.setuptools.dynamic version = {attr = "pkg.mod.NAME"} from pkg/mod.py,
// else pkg/mod/__init__.py, under the directory tool.setuptools.package-dir maps pkg to, else
// its "" entry. setuptools 70 maps the longest leading part of the module name and earlier
// releases its first name only, joining the last segment of that entry's directory to the
// name as a module path, so an entry for a dotted leading part, or one whose directory does
// not end in a plain name, withholds. With no "" entry, no other entry, and
// neither packages nor py-modules listed, setuptools discovers the layout: src when that
// directory is there, else the manifest's own, so the module must be in one of them and
// nothing of its name in the other. A packages.find table, which can add package-dir entries,
// or ext-modules withholds, as does attr anywhere else in the dynamic table.
//
// flit reads a dynamic version from __version__ and a dynamic description from the docstring
// of the module tool.flit.module.name names, else the project name with - as _: the package
// directory with its __init__.py, or the .py file, beside the manifest or under src, which
// flit refuses unless exactly one is there.
func versionModule(doc rootProject, backend string, pr moduleProbe) (*versionRead, bool) {
	switch backend {
	case "", "setuptools.build_meta", "setuptools.build_meta:__legacy__":
		return setuptoolsVersionModule(doc, pr)
	case "flit_core.buildapi":
		return flitVersionModule(doc, pr)
	}
	return nil, true
}

func setuptoolsVersionModule(doc rootProject, pr moduleProbe) (*versionRead, bool) {
	st := doc.Tool.Setuptools
	for k, sub := range st.Dynamic {
		if k != "version" && (k == "attr" || hasKey(sub, "attr")) {
			return nil, false
		}
	}
	t, isTable := st.Dynamic["version"].(map[string]any)
	if _, there := t["attr"]; !isTable || !there {
		return nil, !hasKey(st.Dynamic["version"], "attr")
	}
	desc, isString := t["attr"].(string)
	parts := strings.Split(desc, ".")
	if len(t) != 1 || !isString || len(parts) < 2 || slices.ContainsFunc(parts, func(p string) bool { return !isIdentifier(p) }) {
		return nil, false
	}
	attr, mod := parts[len(parts)-1], parts[:len(parts)-1]
	if _, find := st.Packages.(map[string]any); find || st.ExtModules != nil {
		return nil, false
	}
	dirs := map[string]string{}
	switch m := st.PackageDir.(type) {
	case nil:
	case map[string]any:
		for k, v := range m {
			s, ok := v.(string)
			if !ok || !leadingUpOnly(s) {
				return nil, false
			}
			dirs[k] = s
		}
	default:
		return nil, false
	}
	for k := range dirs {
		if strings.Contains(k, ".") && strings.HasPrefix(desc, k+".") {
			return nil, false
		}
	}
	start := ""
	if d, ok := dirs[mod[0]]; ok {
		if last := d[strings.LastIndex(d, "/")+1:]; last == "" || strings.Contains(last, ".") {
			return nil, false
		}
		start = path.Join(append([]string{d}, mod[1:]...)...)
	} else {
		_, rooted := dirs[""]
		start = path.Join(append([]string{dirs[""]}, mod...)...)
		if !rooted && len(dirs) == 0 && st.Packages == nil && st.PyModules == nil && !pr.clear("src") {
			if !pr.clear(start) || !pr.clear(start+".py") {
				return nil, false
			}
			start = path.Join("src", start)
		}
	}
	var files []string
	if files = pr.files(start + ".py"); files == nil && pr.clear(start+".py") {
		files = pr.files(start + "/__init__.py")
	}
	if files == nil {
		return nil, false
	}
	return &versionRead{files: files, attr: attr, ascii: !setuptoolsReadsBytes(doc)}, true
}

// setuptoolsBytes is the first setuptools release that reads a module for a dynamic attr as
// bytes, decoded as Python decodes source, rather than as text in the locale's encoding.
var setuptoolsBytes, _ = pep440.Parse("65.4.1")

// setuptoolsReadsBytes reports whether build-system.requires holds setuptools to
// setuptoolsBytes or later: a setuptools requirement, with no marker or direct reference, one
// of whose clauses sets a floor (>=, >, ==, ~=, ===) at that release or past it. The build's
// own environment installs it from that requirement, and no-build-isolation, which would use
// another, withholds elsewhere.
func setuptoolsReadsBytes(doc rootProject) bool {
	if doc.BuildSystem == nil {
		return false
	}
	reqs, _ := doc.BuildSystem.Requires.([]any)
	for _, r := range reqs {
		s, _ := r.(string)
		req, ok := parsePEP508(s)
		if !ok || req.URL != "" || req.Marker != "" || normalizePyCoordinate(req.Name) != "setuptools" || req.Specifier == "" {
			continue
		}
		for _, clause := range strings.Split(req.Specifier, ",") {
			for _, op := range []string{"===", "~=", "==", ">=", ">"} {
				ver, ok := strings.CutPrefix(clause, op)
				if !ok {
					continue
				}
				if op == "==" {
					ver = strings.TrimSuffix(ver, ".*")
				}
				if v, ok := pep440.Parse(ver); ok && pep440.Compare(v, setuptoolsBytes) >= 0 {
					return true
				}
				break
			}
		}
	}
	return false
}

func flitVersionModule(doc rootProject, pr moduleProbe) (*versionRead, bool) {
	if doc.Project == nil {
		return nil, false
	}
	version := slices.Contains(doc.Project.Dynamic, "version")
	description := slices.Contains(doc.Project.Dynamic, "description")
	if !version && !description {
		return nil, true
	}
	var names []string
	if n := doc.Tool.Flit.Module.Name; n != nil {
		s, ok := n.(string)
		if !ok {
			return nil, false
		}
		names = []string{s}
	} else {
		s, ok := doc.Project.Name.(string)
		if !ok || strings.ContainsAny(s, ".") || s != strings.ToLower(s) {
			return nil, false
		}
		// A name with - is flit's with _, and nothing may be there under the name as written.
		names = []string{strings.ReplaceAll(s, "-", "_")}
		if strings.Contains(s, "-") {
			names = append(names, s)
		}
	}
	parts := strings.Split(names[0], ".")
	if slices.ContainsFunc(parts, func(p string) bool { return !isIdentifier(p) }) {
		return nil, false
	}
	var files []string
	for _, loc := range []string{"", "src"} {
		for _, name := range names[1:] {
			if p := path.Join(loc, name); !pr.clear(p) || !pr.clear(p+".py") {
				return nil, false
			}
		}
		p := path.Join(append([]string{loc}, parts...)...)
		found := pr.files(p + "/__init__.py")
		if found == nil {
			if !pr.clear(p) {
				return nil, false
			}
			if found = pr.files(p + ".py"); found == nil && !pr.clear(p+".py") {
				return nil, false
			}
		}
		if found != nil {
			if files != nil {
				return nil, false
			}
			files = found
		}
	}
	if files == nil {
		return nil, false
	}
	vr := &versionRead{files: files, docstring: description}
	if version {
		vr.attr = "__version__"
	}
	return vr, true
}

// versionStatic reports whether the backend of the manifest at dir (relative to the nearest
// pyproject.toml; "" for that one) reads its dynamic metadata, if any, from a module bound
// here, each copy of which holds it as a plain string literal (staticAssigned), so imports
// nothing to build.
func versionStatic(doc rootProject, backend string, b scriptsurface.Binder, dir string) bool {
	vr, ok := versionModule(doc, backend, moduleProbe{
		clear: func(p string) bool { return b.Clear("pyproject.toml", path.Join(dir, p)) },
		files: func(p string) []string { return b.Beside("pyproject.toml", path.Join(dir, p)) },
	})
	if !ok || vr == nil {
		return ok
	}
	for _, f := range vr.files {
		data, err := readRegular(f)
		if err != nil || !vr.static(data) {
			return false
		}
	}
	return true
}

// versionModules returns the module files beside the pyproject.toml at manifest that its
// backend reads dynamic metadata from as plain string literals, none of them itself an
// install surface: the files version resolution reads for a scriptsurface.Binder to bind.
func versionModules(manifest string) []string {
	data, err := readRegular(manifest)
	if err != nil {
		return nil
	}
	var doc rootProject
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil
	}
	backend := ""
	if bs := doc.BuildSystem; bs != nil {
		backend = strings.TrimSpace(bs.Backend)
	}
	dir := filepath.Dir(manifest)
	vr, ok := versionModule(doc, backend, moduleProbe{
		clear: func(p string) bool {
			_, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(p)))
			return errors.Is(err, fs.ErrNotExist)
		},
		files: func(p string) []string {
			f := filepath.Join(dir, filepath.FromSlash(p))
			if fi, err := os.Lstat(f); err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			return []string{f}
		},
	})
	if !ok || vr == nil {
		return nil
	}
	var out []string
	for _, f := range vr.files {
		src, err := readRegular(f)
		if err != nil || !vr.static(src) {
			continue
		}
		head, _ := buildtree.Head(f)
		if _, surface := pyInstallSurface(f, head); !surface {
			out = append(out, f)
		}
	}
	return out
}

var codingCookie = regexp.MustCompile(`^[ \t]*#.*?coding[:=][ \t]*([-\w.]+)`)

// staticAssigned reports whether the Python module src holds attr ("" for none) as setuptools
// and flit read it without importing the module: at least one top-level attr = "...", and
// every top-level line that names attr is one, a single-line string with no prefix, escape or
// concatenation, holding text. Both take the first top-level assignment to the name, so a
// value bound inside a block is not read. With docstring, the module must open with a string
// holding text, which flit reads for a description. A module that is not UTF-8 as Python reads
// it, whose lines Python splits other than at \n, or with non-ASCII outside its literals and
// comments, where Python folds look-alike identifiers together, is not read.
func staticAssigned(src []byte, attr string, docstring bool) bool {
	src = bytes.TrimPrefix(src, []byte("\xEF\xBB\xBF"))
	if !utf8.Valid(src) || bytes.ContainsAny(src, "\f\x00") || bytes.Contains(bytes.ReplaceAll(src, []byte("\r\n"), nil), []byte("\r")) {
		return false
	}
	text := strings.ReplaceAll(string(src), "\r\n", "\n")
	for i, line := range strings.SplitN(text, "\n", 3) {
		if i < 2 {
			if m := codingCookie.FindStringSubmatch(line); m != nil && !slices.Contains([]string{"utf-8", "utf8", "utf_8"}, strings.ToLower(m[1])) {
				return false
			}
		}
	}
	clean, lits := stripPythonLiterals(text)
	if strings.ContainsFunc(clean, func(r rune) bool { return r >= utf8.RuneSelf }) {
		return false
	}
	r := []rune(clean)
	src32 := []rune(text)
	plain, first, opened := 0, true, !docstring
	for _, ll := range runeLogicalLines(r) {
		seg := r[ll.start:ll.end]
		line := strings.TrimSpace(string(seg))
		if first && docstring {
			at := ll.start + slices.IndexFunc(seg, func(c rune) bool { return !unicode.IsSpace(c) })
			lit, isLit := lits[at]
			if line != "_" || !isLit || !closed(src32, at, lit) || !textual(lit.body) {
				return false
			}
			opened = true
		}
		first = false
		if ll.indented || attr == "" || !namesIdent(line, attr) {
			continue
		}
		rest, ok := strings.CutPrefix(line, attr)
		rest, eq := strings.CutPrefix(strings.TrimSpace(rest), "=")
		if !ok || !eq || strings.TrimSpace(rest) != "_" {
			return false
		}
		at := ll.start + utf8.RuneCountInString(attr) // an unindented line opens with the name
		for at < ll.end && r[at] != '_' {
			at++
		}
		lit, isLit := lits[at]
		if !isLit || !closed(src32, at, lit) || literalTriple(src32, at) || strings.ContainsAny(lit.body, "\\\n") || !textual(lit.body) {
			return false
		}
		plain++
	}
	return opened && (attr == "" || plain > 0)
}

// runeLine is one logical line of cleaned source by rune range, and whether its first
// physical line is indented.
type runeLine struct {
	start, end int
	indented   bool
}

// runeLogicalLines splits cleaned source as logicalLines does, keeping each logical line's
// rune range.
func runeLogicalLines(r []rune) []runeLine {
	var out []runeLine
	start, depth, open := 0, 0, false
	cur := runeLine{}
	for i := 0; i <= len(r); i++ {
		if i < len(r) && r[i] != '\n' {
			continue
		}
		line := string(r[start:i])
		if !open && strings.TrimSpace(line) != "" {
			cur = runeLine{start: start, indented: line[0] == ' ' || line[0] == '\t'}
			open = true
		}
		if open {
			depth += bracketDelta(line)
			if depth <= 0 && !strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
				cur.end = i
				out = append(out, cur)
				open, depth = false, 0
			}
		}
		start = i + 1
	}
	if open {
		cur.end = len(r)
		out = append(out, cur)
	}
	return out
}

// namesIdent reports whether name appears in line as a whole identifier.
func namesIdent(line, name string) bool {
	for i := 0; ; {
		j := strings.Index(line[i:], name)
		if j < 0 {
			return false
		}
		j += i
		before, _ := utf8.DecodeLastRuneInString(line[:j])
		after, _ := utf8.DecodeRuneInString(line[j+len(name):])
		if (j == 0 || !isIdentPart(before)) && (j+len(name) == len(line) || !isIdentPart(after)) {
			return true
		}
		i = j + len(name)
	}
}

// closed reports whether the literal opening at rune index at ends in its own quote.
func closed(src []rune, at int, lit strLiteral) bool {
	q := 1
	if literalTriple(src, at) {
		q = 3
	}
	return lit.end-at >= 2*q && lit.end <= len(src) && src[lit.end-1] == src[at]
}

func literalTriple(src []rune, at int) bool {
	return at+2 < len(src) && src[at+1] == src[at] && src[at+2] == src[at]
}

// textual reports whether a literal's raw body opens, past any whitespace, with a rune that is
// not an escape, so its value holds text.
func textual(body string) bool {
	t := strings.TrimLeftFunc(body, unicode.IsSpace)
	return t != "" && t[0] != '\\'
}

func isIdentifier(s string) bool {
	for i, c := range s {
		if !isIdentPart(c) || i == 0 && unicode.IsDigit(c) {
			return false
		}
	}
	return s != ""
}

// leadingUpOnly reports whether s is a relative, literal path whose only .. parts lead it.
func leadingUpOnly(s string) bool {
	if strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\\*?[{$~") {
		return false
	}
	named := false
	for _, part := range strings.Split(s, "/") {
		if part == ".." && named {
			return false
		}
		named = named || part != ".." && part != "." && part != ""
	}
	return true
}
