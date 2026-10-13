package pythonanalysis

// Declared-specifier readers for setuptools/hatch build definitions: setup.cfg, setup.py, and
// hatch_build.py. None of these is ever executed. Each yields DECLARED dependencies: an exact
// "==" pin resolves as everywhere else, a range is carried in Constraint with Resolved=false,
// and nothing here ever derives a version from a range.

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

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
	buildSpecs []string // setup_requires and tests_require entries: build- and test-time only
	files      []string // requirement files a "file:" value named, each read in full
	ok         bool
}

// scanSetupCfg reads the dependency lists of a setup.cfg as setuptools does: readCfg parses the
// file under configparser's rules, and each install_requires, setup_requires and tests_require
// option of [options], and every option of [options.extras_require], is a setuptools
// requirement list (setupCfgList). An install_requires or extras_require value that starts with
// "file:" names comma-separated requirement files relative to setup.cfg, whose text is read as
// the list in its place (readCfgFiles). ok is false when readCfg's, readCfgFiles's or
// setupCfgList's is.
func scanSetupCfg(path string, data []byte) setupCfgScan {
	sections, ok := readCfg(data)
	if !ok {
		return setupCfgScan{}
	}
	scan := setupCfgScan{ok: true}
	for _, sec := range sections {
		for _, o := range sec.options {
			runtime := sec.name == "options.extras_require"
			if sec.name == "options" {
				switch cfgOptionID(sec.name, o.key) {
				case "install_requires":
					runtime = true
				case "setup_requires", "tests_require":
				default:
					continue
				}
			} else if !runtime {
				continue
			}
			value := o.value()
			if spec, isFile := strings.CutPrefix(value, "file:"); isFile && runtime {
				text, files, fileOK := readCfgFiles(filepath.Dir(path), spec)
				scan.files = append(scan.files, files...)
				if !fileOK {
					scan.ok = false
					continue
				}
				value = text
			}
			specs, listOK := setupCfgList(value, runtime)
			if runtime {
				scan.specs = append(scan.specs, specs...)
			} else {
				scan.buildSpecs = append(scan.buildSpecs, specs...)
			}
			scan.ok = scan.ok && listOK
		}
	}
	return scan
}

// cfgSection is one setup.cfg section as configparser reads it, options in file order.
type cfgSection struct {
	name    string
	options []cfgOption
}

// cfgOption is one option: its key as written (right-trimmed) and its value lines, the text
// after the delimiter first and each continuation or blank line after it.
type cfgOption struct {
	key   string
	lines []string
}

// value is the option's value as configparser returns it: lines joined with "\n", trailing
// whitespace trimmed.
func (o cfgOption) value() string {
	return strings.TrimRight(strings.Join(o.lines, "\n"), " \t\n")
}

// cfgOptionID is the name setuptools files an option under: in [options] it lowercases the key
// and replaces '-' with '_'; it leaves extras_require keys as written.
func cfgOptionID(section, key string) string {
	if section != "options" {
		return key
	}
	return strings.ReplaceAll(strings.ToLower(key), "-", "_")
}

// setupCfgSections are the setuptools sections whose names contain "options". setuptools
// matches that word case-sensitively and drops dots after it ("[options..extras_require]" is
// read as extras), so any other section whose name contains it, in any case, is not read.
var setupCfgSections = map[string]bool{
	"options":                      true,
	"options.extras_require":       true,
	"options.packages.find":        true,
	"options.entry_points":         true,
	"options.package_data":         true,
	"options.exclude_package_data": true,
	"options.data_files":           true,
}

// readCfg parses a setup.cfg as setuptools' ConfigParser does (strict, optionxform=str,
// BasicInterpolation, "#" and ";" full-line comments only, empty lines kept in values). Every
// line is exactly one of: a full-line comment, which changes no state; a blank line, which
// adds an empty line to an open value; a continuation, indented deeper than the line that
// opened the current option; a section header; or a "key = value" or "key: value" option,
// split at the first '=' or ':'. ok is false, and nothing is read, for any line that is none
// of these, and for every form setuptools rejects or may read differently: text cfgTextOK
// refuses, a '%' outside a comment (interpolation), a duplicate section, a key repeated in a
// section under cfgOptionID, a DEFAULT section (its options join every section), a non-ASCII
// key (Python and Go lowercase it differently), a header with text after its ']', and a
// section named for options that setupCfgSections does not list.
func readCfg(data []byte) (sections []cfgSection, ok bool) {
	if !cfgTextOK(data) {
		return nil, false
	}
	var (
		open   bool // an option is open: deeper-indented lines continue its value
		indent int  // indentation of the last header or option line
		seen   = map[string]bool{}
		keys   map[string]bool
	)
	addLine := func(s string) {
		opts := sections[len(sections)-1].options
		opts[len(opts)-1].lines = append(opts[len(opts)-1].lines, s)
	}
	for _, line := range strings.Split(universalNewlines(string(data)), "\n") {
		text := strings.Trim(line, " \t")
		if strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		if text == "" {
			if open {
				addLine("")
			}
			continue
		}
		if strings.Contains(text, "%") {
			return nil, false
		}
		lead := len(line) - len(strings.TrimLeft(line, " \t"))
		if open && lead > indent {
			addLine(text)
			continue
		}
		indent = lead
		if strings.HasPrefix(text, "[") {
			name, header := cfgHeader(text)
			if !header || seen[name] || strings.EqualFold(name, "DEFAULT") ||
				strings.Contains(strings.ToLower(name), "options") && !setupCfgSections[name] {
				return nil, false
			}
			seen[name] = true
			sections = append(sections, cfgSection{name: name})
			keys, open = map[string]bool{}, false
			continue
		}
		k := strings.IndexAny(text, "=:")
		if len(sections) == 0 || k < 0 {
			return nil, false
		}
		sec := &sections[len(sections)-1]
		key := strings.TrimRight(text[:k], " \t")
		id := cfgOptionID(sec.name, key)
		if key == "" || !cfgASCII(key) || keys[id] {
			return nil, false
		}
		keys[id] = true
		sec.options = append(sec.options, cfgOption{key: key, lines: []string{strings.Trim(text[k+1:], " \t")}})
		open = true
	}
	return sections, true
}

// cfgHeader returns the name of a "[name]" header line: everything between the first '[' and
// the last ']', as configparser takes it. ok is false when the name is empty or text follows
// the ']' (configparser ignores that text).
func cfgHeader(text string) (string, bool) {
	if len(text) < 3 || !strings.HasSuffix(text, "]") {
		return "", false
	}
	return text[1 : len(text)-1], true
}

// cfgTextOK reports whether data is text setuptools reads as this package does: valid UTF-8
// (setuptools fails on anything else), with no control character or whitespace beyond tab,
// space and line breaks. Python strips and splits lines on the others (form feed, NEL, no-break space, ...),
// where Go's line handling here does not.
func cfgTextOK(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for _, r := range string(data) {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
		case r < 0x20 || r == 0x7f || r > 0x7f && unicode.IsSpace(r):
			return false
		}
	}
	return true
}

// cfgASCII reports whether s is all ASCII, where Python's and Go's lowercasing agree.
func cfgASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// universalNewlines converts "\r\n" and lone "\r" line breaks to "\n", as Python's text-mode
// open does.
func universalNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// setupCfgList returns the entries of a setuptools requirement list value: split into lines
// when it holds a line break, else on ';', each entry trimmed and empty ones dropped. For
// install_requires and extras_require (dropComments) setuptools also drops entries that start
// with '#'. ok is false when an entry is not a well-formed PEP 508 requirement or has a marker
// that is not strictly well formed (strictMarker): setuptools fails on both. ok is also false
// when an entry ends in a backslash: setuptools joins it to the next entry (join_continuation)
// before parsing, and the joined requirement is not read here.
func setupCfgList(value string, dropComments bool) (specs []string, ok bool) {
	sep := ";"
	if strings.Contains(value, "\n") {
		sep = "\n"
	}
	ok = true
	for _, e := range strings.Split(value, sep) {
		e = strings.Trim(e, " \t")
		if e == "" || dropComments && strings.HasPrefix(e, "#") {
			continue
		}
		if setuptoolsJoins(e) {
			ok = false
			continue
		}
		r, valid := parsePEP508(e)
		if !valid || r.Marker != "" && !strictMarker(r.Marker) {
			ok = false
			continue
		}
		specs = append(specs, e)
	}
	return specs, ok
}

// markerEnvVars are the PEP 508 environment marker variables.
var markerEnvVars = map[string]bool{
	"os_name":                        true,
	"sys_platform":                   true,
	"platform_machine":               true,
	"platform_python_implementation": true,
	"platform_release":               true,
	"platform_system":                true,
	"platform_version":               true,
	"python_version":                 true,
	"python_full_version":            true,
	"implementation_name":            true,
	"implementation_version":         true,
	"extra":                          true,
}

// strictMarker reports whether m is a well-formed PEP 508 marker naming only marker variables,
// so a ';'-joined second requirement ("six;pyjwt==2.10.0") is never taken for a marker.
func strictMarker(m string) bool {
	toks, err := lexMarker(m)
	if err != nil {
		return false
	}
	for _, t := range toks {
		if t.kind == tokVar && !markerEnvVars[t.text] {
			return false
		}
	}
	p := &markerParser{toks: toks}
	_, err = p.parseOr()
	return err == nil && p.pos == len(toks)
}

// readCfgFiles returns the text setuptools reads for a "file:" value naming the comma-separated
// files in spec relative to dir: their contents joined with "\n". ok is false when a path is
// not local to dir (localFile), a file cannot be read, or its text is one cfgTextOK refuses.
func readCfgFiles(dir, spec string) (text string, files []string, ok bool) {
	var parts []string
	for _, p := range strings.Split(spec, ",") {
		target, local := localFile(dir, strings.TrimSpace(p))
		if !local {
			return "", files, false
		}
		data, err := readRegular(target)
		if err != nil {
			return "", files, false
		}
		files = append(files, filepath.Clean(target))
		if !cfgTextOK(data) {
			return "", files, false
		}
		parts = append(parts, universalNewlines(string(data)))
	}
	return strings.Join(parts, "\n"), files, true
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
// presence means the file is not what it is read as. Comment lines drop and an inline comment
// is cut before a line is read, as _reqs.parse does; ok is also false when what is left ends
// in a backslash (setuptoolsJoins).
func readRequirementSpecs(dir, spec string) (specs, files []string, ok bool) {
	for _, p := range strings.Split(spec, ",") {
		target, local := localFile(dir, strings.TrimSpace(p))
		if !local {
			return specs, files, false
		}
		data, err := readRegular(target)
		if err != nil {
			return specs, files, false
		}
		files = append(files, filepath.Clean(target))
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(stripCfgInlineComment(strings.TrimRight(raw, "\r")))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "-") || setuptoolsJoins(line) {
				return specs, files, false
			}
			specs = append(specs, line)
		}
	}
	return specs, files, true
}

// setuptoolsJoins reports whether setuptools joins entry, one entry of a requirement list after
// the reader's own comment handling, to the entry after it. Every setuptools requirement list
// goes through _reqs.parse, whose join_continuation drops the last two characters of an entry
// that ends in a backslash and appends the next entry: "pyjw@\" then "t==2.10.0" installs
// pyjwt==2.10.0. setuptools splits a list element at line breaks first, so a line of entry
// ending in a backslash counts. A reader withholds the manifest rather than read the halves.
func setuptoolsJoins(entry string) bool {
	return slices.ContainsFunc(pyLines(entry), func(l string) bool {
		return strings.HasSuffix(strings.TrimSpace(l), `\`)
	})
}

// setuptoolsReadsAsWritten reports whether _reqs.parse reads a setup.py requirement list
// element, as readPyString decoded it, as the one requirement it spells: it holds no line break
// (yield_lines makes each line an entry), no " #" (drop_comment cuts there), and no backslash.
// A backslash is either one setuptools joins on (setuptoolsJoins) or an escape readPyString
// leaves undecoded, such as "\f" or "\x0b", which Python decodes to a line break.
func setuptoolsReadsAsWritten(elem string) bool {
	return len(pyLines(elem)) <= 1 && !strings.Contains(elem, " #") && !strings.Contains(elem, `\`) && !setuptoolsJoins(elem)
}

// pyLines splits s at every line boundary Python's str.splitlines recognizes, dropping empty
// lines.
func pyLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case '\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', '\u2028', '\u2029':
			return true
		}
		return false
	})
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

// stripCfgInlineComment drops a whitespace-preceded "#" inline comment, which a requirement
// never contains.
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
// installs; setupPyBuildKeys declare what only building or testing it installs.
var (
	setupPyRuntimeKeys = []string{"install_requires", "extras_require"}
	setupPyBuildKeys   = []string{"setup_requires", "tests_require"}
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
// those names was such a literal whose every element setuptools reads as written
// (setuptoolsReadsAsWritten).
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
			if !ok || slices.ContainsFunc(elems, func(e string) bool { return !setuptoolsReadsAsWritten(e) }) {
				complete = false
			}
			if !ok {
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
