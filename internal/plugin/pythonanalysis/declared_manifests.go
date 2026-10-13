package pythonanalysis

// Declared-specifier readers for setuptools/hatch build definitions: setup.cfg, setup.py, and
// hatch_build.py. None of these is ever executed. Each yields DECLARED dependencies: an exact
// "==" pin resolves as everywhere else, a range is carried in Constraint with Resolved=false,
// and nothing here ever derives a version from a range.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- setup.cfg ---------------------------------------------------------------

// parseSetupCfg reads setup.cfg's "[options] install_requires" and every key of
// "[options.extras_require]" (scanSetupCfg). Entries that are not well-formed PEP 508
// requirements are skipped. ok is false when scanSetupCfg's is.
func parseSetupCfg(path string, data []byte) ([]plugin.ResolvedDependency, bool) {
	scan := scanSetupCfg(path, data)
	var out []plugin.ResolvedDependency
	for _, spec := range scan.specs {
		if d, valid := declaredDependency(spec, "setup.cfg"); valid {
			out = append(out, d)
		}
	}
	return out, scan.ok
}

// setupCfgScan is what scanSetupCfg read from one setup.cfg.
type setupCfgScan struct {
	specs      []string // install_requires and extras_require entries, "file:" lists expanded
	buildSpecs []string // setup_requires entries: build-time only
	files      []string // requirement files a "file:" value named, each read in full
	ok         bool
}

// scanSetupCfg reads the dependency lists of a setup.cfg. Values are setuptools list fields: a
// dangling list (one requirement per indented continuation line) or a single-line
// ';'-separated string. An install_requires or extras_require value that starts with "file:"
// names comma-separated requirement files relative to setup.cfg, which are read in its place
// (readRequirementSpecs). ok is false when a referenced file cannot be read, is not local to
// setup.cfg's directory, or holds a line that is not a well-formed requirement, and when "file:"
// appears anywhere but at the start of a value (setuptools rejects that).
func scanSetupCfg(path string, data []byte) setupCfgScan {
	var (
		scan    = setupCfgScan{ok: true}
		section string
		key     string
		inList  bool     // inside a dependency-list value's continuation lines
		head    string   // the value text on the key line
		cont    []string // the value's continuation lines
	)
	build := func() bool { return key == "setup_requires" }
	add := func(spec string) {
		spec = strings.TrimSpace(stripCfgInlineComment(spec))
		if spec == "" {
			return
		}
		if strings.HasPrefix(spec, "file:") {
			scan.ok = false
			return
		}
		if build() {
			scan.buildSpecs = append(scan.buildSpecs, spec)
		} else {
			scan.specs = append(scan.specs, spec)
		}
	}
	flush := func() {
		if !inList {
			return
		}
		inList = false
		whole := strings.TrimSpace(strings.Join(append([]string{head}, cont...), "\n"))
		if spec, isFile := strings.CutPrefix(whole, "file:"); isFile && !build() {
			specs, files, fileOK := readRequirementSpecs(filepath.Dir(path), spec)
			for _, s := range specs {
				if _, valid := parsePEP508(s); !valid {
					fileOK = false
				}
			}
			scan.specs = append(scan.specs, specs...)
			scan.files = append(scan.files, files...)
			scan.ok = scan.ok && fileOK
			return
		}
		if head != "" {
			for _, part := range splitCfgSemicolons(head) {
				add(part)
			}
		}
		for _, c := range cont {
			add(c)
		}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		if indented && inList {
			cont = append(cont, trimmed)
			continue
		}
		flush()
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			continue
		}
		if indented {
			continue // continuation of a value we do not read
		}
		k := strings.IndexAny(trimmed, "=:")
		if k < 0 {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(trimmed[:k]))
		switch {
		case section == "options" && (key == "install_requires" || key == "setup_requires"),
			section == "options.extras_require":
			inList, head, cont = true, strings.TrimSpace(trimmed[k+1:]), nil
		}
	}
	flush()
	return scan
}

// readRequirementFiles reads the comma-separated requirement files a setuptools "file:"
// directive (or a pyproject "file" key) names, relative to dir, as declared dependencies. ok is
// false when readRequirementSpecs's is, or a line is not a well-formed PEP 508 requirement.
func readRequirementFiles(dir, spec, source string) ([]plugin.ResolvedDependency, bool) {
	specs, _, ok := readRequirementSpecs(dir, spec)
	var out []plugin.ResolvedDependency
	for _, s := range specs {
		d, valid := declaredDependency(s, source)
		if !valid {
			return out, false
		}
		out = append(out, d)
	}
	return out, ok
}

// readRequirementSpecs returns the requirement lines of the comma-separated requirement files
// spec names relative to dir, and the files it read. ok is false when a path is empty,
// absolute, a URL, or resolves (symlinks included) outside dir, when a file cannot be read, or
// when a line is a pip option (-r, -c, -e, --hash): setuptools does not follow them, so their
// presence means the file is not what it is read as.
func readRequirementSpecs(dir, spec string) (specs, files []string, ok bool) {
	for _, p := range strings.Split(spec, ",") {
		target, local := localFile(dir, strings.TrimSpace(p))
		if !local {
			return specs, files, false
		}
		data, err := os.ReadFile(target)
		if err != nil {
			return specs, files, false
		}
		files = append(files, filepath.Clean(target))
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(stripCfgInlineComment(strings.TrimRight(raw, "\r")))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "-") {
				return specs, files, false
			}
			specs = append(specs, line)
		}
	}
	return specs, files, true
}

// localFile resolves p against dir and returns it when it names a file inside dir, symlinks
// resolved. Absolute paths, URLs, and paths that escape dir are refused, as setuptools refuses a
// "file:" path outside the project root.
func localFile(dir, p string) (string, bool) {
	if p == "" || strings.Contains(p, "://") || filepath.IsAbs(p) {
		return "", false
	}
	target := filepath.Join(dir, p)
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", false
	}
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(realDir, realTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return target, true
}

// splitCfgSemicolons splits a single-line setuptools list value on ';'. A segment that does
// not parse as a requirement is rejoined to the previous one, so "pkg; python_version<'3.8'"
// keeps its marker instead of producing a junk "python_version" entry.
func splitCfgSemicolons(val string) []string {
	var out []string
	for _, seg := range strings.Split(val, ";") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if _, ok := parsePEP508(seg); !ok && len(out) > 0 {
			out[len(out)-1] += "; " + seg
			continue
		}
		out = append(out, seg)
	}
	return out
}

// stripCfgInlineComment drops a " #"/" ;" inline comment. A requirement never contains a
// whitespace-preceded '#', and a marker's ';' is never whitespace-preceded in practice; a
// marker written "pkg ; marker" survives because splitCfgSemicolons rejoins it.
func stripCfgInlineComment(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
	}
	return s
}

// --- setup.py ----------------------------------------------------------------

// parseSetupPy reads every literal "install_requires = [ ... ]" list and every literal
// "extras_require = { "name": [ ... ], ... }" dict in setup.py (keyword argument or variable
// assignment). A value is accepted only when every element is a plain string literal; one
// computed element (a name, a call, an f-string, a comprehension) rejects the whole value,
// because a partial read would silently misstate what is declared. The file is never executed.
// Whether the read is complete is setupPyComplete's question, not this reader's.
func parseSetupPy(data []byte) ([]plugin.ResolvedDependency, bool) {
	specs, _ := scanSetupPy(string(data))
	var out []plugin.ResolvedDependency
	for _, e := range specs {
		if d, ok := declaredDependency(e, "setup.py"); ok {
			out = append(out, d)
		}
	}
	return out, true
}

// setupPyComplete reports whether parseSetupPy read every dependency setup.py declares: each
// occurrence of install_requires or extras_require (in code, a string, or a comment alike) is a
// literal value parseSetupPy reads, and nothing is passed through a "**" splat, which can carry
// either keyword unseen. Anything else (setup(install_requires=REQS), install_requires.append,
// a requirements file read at build time) means the declared set is computed.
func setupPyComplete(data []byte) bool {
	_, complete := scanSetupPy(string(data))
	return complete
}

// setupPyRuntimeKeys are the setup() keywords that declare what installing the project
// installs; setupPyBuildKeys declare what only building it installs.
var (
	setupPyRuntimeKeys = []string{"install_requires", "extras_require"}
	setupPyBuildKeys   = []string{"setup_requires"}
)

// scanSetupPy returns the requirement strings of every literal install_requires list and
// extras_require dict in src, and whether every occurrence of either name was such a literal
// and src holds no "**" outside string literals and comments.
func scanSetupPy(src string) (specs []string, complete bool) {
	specs, complete = scanSetupPyKeys(src, setupPyRuntimeKeys)
	return specs, complete && !hasPySplat(src)
}

// scanSetupPyKeys returns the requirement strings of every literal value assigned to one of
// keys in src (a list, or a dict of lists for extras_require), and whether every occurrence of
// those names was such a literal.
func scanSetupPyKeys(src string, keys []string) (specs []string, complete bool) {
	complete = true
	for _, key := range keys {
		for i := 0; ; {
			k := strings.Index(src[i:], key)
			if k < 0 {
				break
			}
			start := i + k
			i = start + len(key)
			if start > 0 && isIdentChar(src[start-1]) || i < len(src) && isIdentChar(src[i]) {
				continue
			}
			j := skipPySpace(src, i)
			if j >= len(src) || src[j] != '=' || j+1 < len(src) && src[j+1] == '=' {
				complete = false
				continue
			}
			j = skipPySpace(src, j+1)
			var (
				elems []string
				ok    bool
			)
			switch {
			case key == "extras_require" && j < len(src) && src[j] == '{':
				elems, i, ok = literalStringListDict(src, j+1)
			case key != "extras_require" && j < len(src) && src[j] == '[':
				elems, i, ok = literalStringList(src, j+1)
			}
			if !ok {
				complete = false
				continue
			}
			specs = append(specs, elems...)
		}
	}
	return specs, complete
}

// literalStringListDict reads a dict starting just after '{' whose keys are string literals and
// whose values are literal string lists, and returns every list element. next is the index after
// the closing '}' (or where scanning stopped); ok is false for any other shape.
func literalStringListDict(src string, i int) (elems []string, next int, ok bool) {
	for {
		i = skipPySpaceAndComments(src, i)
		if i >= len(src) {
			return nil, i, false
		}
		if src[i] == '}' {
			return elems, i + 1, true
		}
		_, nx, isF, lit := readPyString(src, i)
		if !lit || isF {
			return nil, i + 1, false
		}
		i = skipPySpaceAndComments(src, nx)
		if i >= len(src) || src[i] != ':' {
			return nil, i, false
		}
		i = skipPySpaceAndComments(src, i+1)
		if i >= len(src) || src[i] != '[' {
			return nil, i, false
		}
		vals, nx, ok := literalStringList(src, i+1)
		if !ok {
			return nil, nx, false
		}
		elems = append(elems, vals...)
		i = skipPySpaceAndComments(src, nx)
		if i >= len(src) {
			return nil, i, false
		}
		switch src[i] {
		case ',':
			i++
		case '}':
			return elems, i + 1, true
		default:
			return nil, i, false
		}
	}
}

// hasPySplat reports whether src holds "**" outside string literals and comments.
func hasPySplat(src string) bool {
	for i := 0; i < len(src); {
		switch {
		case src[i] == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case startsPyString(src, i) && (i == 0 || !isIdentChar(src[i-1])):
			if _, next, _, ok := readPyString(src, i); ok {
				i = next
			} else {
				i++
			}
		case strings.HasPrefix(src[i:], "**"):
			return true
		default:
			i++
		}
	}
	return false
}

// literalStringList reads list elements starting just after '[' and returns them when every
// element is a string literal (adjacent literals concatenate). next is the index after the
// closing ']' (or where scanning stopped); ok is false for any non-literal element.
func literalStringList(src string, i int) (elems []string, next int, ok bool) {
	for {
		i = skipPySpaceAndComments(src, i)
		if i >= len(src) {
			return nil, i, false
		}
		if src[i] == ']' {
			return elems, i + 1, true
		}
		var val strings.Builder
		for {
			s, nx, isF, lit := readPyString(src, i)
			if !lit || isF {
				return nil, i + 1, false
			}
			val.WriteString(s)
			i = skipPySpaceAndComments(src, nx)
			if i >= len(src) || !startsPyString(src, i) {
				break
			}
		}
		elems = append(elems, val.String())
		if i >= len(src) {
			return nil, i, false
		}
		switch src[i] {
		case ',':
			i++
		case ']':
			return elems, i + 1, true
		default:
			return nil, i, false
		}
	}
}

// --- hatch_build.py ----------------------------------------------------------

// parseHatchBuild reads string literals from a hatch build hook that parse as PEP 508
// requirements carrying a version specifier, a direct reference, or extras. A bare word is not
// taken as a requirement: in an arbitrary Python file it is far more likely to be a key, a
// path, or prose. The hook is never executed; these are declared dependencies only.
func parseHatchBuild(data []byte) ([]plugin.ResolvedDependency, bool) {
	src := string(data)
	var out []plugin.ResolvedDependency
	seen := map[string]bool{}
	for i := 0; i < len(src); {
		c := src[i]
		if c == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		if startsPyString(src, i) && (i == 0 || !isIdentChar(src[i-1])) {
			s, next, isF, ok := readPyString(src, i)
			if !ok {
				i++
				continue
			}
			i = next
			if isF {
				continue
			}
			r, valid := parsePEP508(s)
			if !valid || (r.Specifier == "" && r.URL == "" && len(r.Extras) == 0) {
				continue
			}
			d, ok := declaredDependency(s, "hatch_build.py")
			if !ok {
				continue
			}
			k := normalizePyCoordinate(d.Coordinate) + "\x00" + d.Version + "\x00" + d.Constraint
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, d)
			continue
		}
		i++
	}
	return out, true
}

// --- Python lexical helpers --------------------------------------------------

func isIdentChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func skipPySpace(src string, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t' || src[i] == '\n' || src[i] == '\r' || src[i] == '\\') {
		i++
	}
	return i
}

func skipPySpaceAndComments(src string, i int) int {
	for {
		i = skipPySpace(src, i)
		if i < len(src) && src[i] == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		return i
	}
}

// pyStringPrefix returns the length of a string-literal prefix (r, u, b, f, and two-letter
// combinations, any case) at i that is immediately followed by a quote, or -1 when no string
// literal starts at i.
func pyStringPrefix(src string, i int) int {
	for n := 0; n <= 2 && i+n < len(src); n++ {
		if c := src[i+n]; c == '"' || c == '\'' {
			for _, p := range strings.ToLower(src[i : i+n]) {
				if !strings.ContainsRune("rubf", p) {
					return -1
				}
			}
			return n
		}
	}
	return -1
}

func startsPyString(src string, i int) bool { return pyStringPrefix(src, i) >= 0 }

// readPyString reads one Python string literal starting at i (prefix included) and returns
// its value, the index after it, whether it is an f-string (its value is a template, not a
// literal), and ok=false when no well-formed literal starts at i.
func readPyString(src string, i int) (val string, next int, fstring bool, ok bool) {
	n := pyStringPrefix(src, i)
	if n < 0 {
		return "", i, false, false
	}
	prefix := strings.ToLower(src[i : i+n])
	raw := strings.ContainsRune(prefix, 'r')
	fstring = strings.ContainsRune(prefix, 'f')
	i += n
	q := src[i]
	delim := string(q)
	if strings.HasPrefix(src[i:], strings.Repeat(string(q), 3)) {
		delim = strings.Repeat(string(q), 3)
	}
	i += len(delim)
	var b strings.Builder
	for i < len(src) {
		if strings.HasPrefix(src[i:], delim) {
			return b.String(), i + len(delim), fstring, true
		}
		c := src[i]
		if c == '\n' && len(delim) == 1 {
			return "", i, fstring, false
		}
		if c == '\\' && i+1 < len(src) {
			if raw {
				b.WriteByte(c)
				b.WriteByte(src[i+1])
			} else {
				switch e := src[i+1]; e {
				case '\\', '\'', '"':
					b.WriteByte(e)
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '\n':
				default:
					b.WriteByte(c)
					b.WriteByte(e)
				}
			}
			i += 2
			continue
		}
		b.WriteByte(c)
		i++
	}
	return "", i, fstring, false
}
