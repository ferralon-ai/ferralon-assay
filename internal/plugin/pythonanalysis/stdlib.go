package pythonanalysis

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/pep440"
)

// A CPython release is written major*100+minor: 207 is 2.7, 314 is 3.14. The tables below
// model 2.7 and 3.0 through 3.14.
const oldestModelledRelease = 207

// modelledReleases lists the releases the tables model, oldest first.
var modelledReleases = []int{207, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314}

// releaseSpan is a run of modelled releases that ship a module: from span[0] up to, but not
// including, span[1]. A zero span[1] means every later release ships it too.
type releaseSpan [2]int

// interpreterRange is the set of CPython releases a build may run on, as the tables model
// them.
type interpreterRange struct {
	releases []int // admitted modelled releases
	newer    bool  // admits a release newer than every modelled one
}

// assumedInterpreter stands in when a build declares no interpreter: CPython 3.8 or later.
var assumedInterpreter = interpreterRange{releases: releasesFrom(308), newer: true}

// anyInterpreter stands in when a build declares an interpreter this lane cannot read: every
// modelled release and every later one.
var anyInterpreter = interpreterRange{releases: releasesFrom(oldestModelledRelease), newer: true}

func releasesFrom(first int) []int {
	for i, r := range modelledReleases {
		if r >= first {
			return modelledReleases[i:]
		}
	}
	return nil
}

// buildInterpreter reads the interpreter range the build at dir declares, through the same
// requires-python, lockfile, .python-version chain the build manifest reports.
func buildInterpreter(dir string) interpreterRange {
	spec := declaredPython(dir)
	if spec == "" {
		return assumedInterpreter
	}
	if r, ok := parseInterpreterRange(spec); ok {
		return r
	}
	return anyInterpreter
}

var pythonVersionPin = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

// parseInterpreterRange reads a requires-python specifier, or a bare .python-version pin
// ("3.12", "3.12.4"), into the modelled releases it admits. A release is admitted when any
// of its patch levels satisfies every clause. ok is false when a clause doesn't parse or the
// range admits no modelled or newer release (one that admits only releases older than 2.7).
func parseInterpreterRange(spec string) (interpreterRange, bool) {
	spec = strings.TrimSpace(spec)
	if pythonVersionPin.MatchString(spec) {
		if strings.Count(spec, ".") == 1 {
			spec = "==" + spec + ".*"
		} else {
			spec = "==" + spec
		}
	}
	var clauses []string
	for _, c := range strings.Split(spec, ",") {
		if c = strings.TrimSpace(c); c != "" {
			clauses = append(clauses, c)
		}
	}
	if len(clauses) == 0 {
		return interpreterRange{}, false
	}
	admits := func(major, minor, maxPatch int) (bool, bool) {
		for patch := 0; patch <= maxPatch; patch++ {
			raw := fmt.Sprintf("%d.%d.%d", major, minor, patch)
			v, _ := pep440.Parse(raw)
			all := true
			for _, c := range clauses {
				sat, ok := pep440.Satisfies(v, raw, c)
				if !ok {
					return false, false
				}
				all = all && sat
			}
			if all {
				return true, true
			}
		}
		return false, true
	}
	var r interpreterRange
	for _, rel := range modelledReleases {
		hit, ok := admits(rel/100, rel%100, 99)
		if !ok {
			return interpreterRange{}, false
		}
		if hit {
			r.releases = append(r.releases, rel)
		}
	}
	for _, rel := range []int{315, 316, 317, 318, 319, 320, 325, 330, 340, 400, 401, 500} {
		hit, ok := admits(rel/100, rel%100, 20)
		if !ok {
			return interpreterRange{}, false
		}
		r.newer = r.newer || hit
	}
	if len(r.releases) == 0 && !r.newer {
		return interpreterRange{}, false
	}
	return r, true
}

// ships reports whether every release in r provides top as a standard-library module. A
// release newer than the tables is taken to keep what 3.14 ships.
func (r interpreterRange) ships(top string) bool {
	if stdlibModules[top] {
		return true
	}
	spans, ok := stdlibBounded[top]
	if !ok {
		return false
	}
	for _, rel := range r.releases {
		if !shippedIn(spans, rel) {
			return false
		}
	}
	return !r.newer || spans[len(spans)-1][1] == 0
}

func shippedIn(spans []releaseSpan, rel int) bool {
	for _, s := range spans {
		if rel >= s[0] && (s[1] == 0 || rel < s[1]) {
			return true
		}
	}
	return false
}

// The tables come from CPython's sources at each release tag: Python/stdlib_module_names.h
// (the list behind sys.stdlib_module_names) for 3.10 through 3.14, and for 2.7 through 3.9
// the top-level modules and packages under Lib/ plus the extension modules setup.py,
// Modules/Setup and PC/config.c build. Test and example modules are left out. A module only
// 2.7 ships is left out too, so a build that runs only on 2.7 fails closed on it.

// stdlibModules holds the top-level modules every modelled release ships.
var stdlibModules = map[string]bool{
	"__future__": true, "_ast": true, "_bisect": true, "_codecs": true, "_codecs_cn": true,
	"_codecs_hk": true, "_codecs_iso2022": true, "_codecs_jp": true, "_codecs_kr": true,
	"_codecs_tw": true, "_collections": true, "_csv": true, "_ctypes": true, "_curses": true,
	"_curses_panel": true, "_elementtree": true, "_functools": true, "_hashlib": true,
	"_heapq": true, "_json": true, "_locale": true, "_lsprof": true, "_md5": true,
	"_multibytecodec": true, "_multiprocessing": true, "_pickle": true, "_random": true,
	"_socket": true, "_sqlite3": true, "_sre": true, "_ssl": true, "_strptime": true,
	"_struct": true, "_symtable": true, "_threading_local": true, "_tkinter": true,
	"_warnings": true, "_weakref": true, "_weakrefset": true, "abc": true, "antigravity": true,
	"array": true, "ast": true, "atexit": true, "base64": true, "bdb": true, "binascii": true,
	"bisect": true, "bz2": true, "cProfile": true, "calendar": true, "cmath": true, "cmd": true,
	"code": true, "codecs": true, "codeop": true, "collections": true, "colorsys": true,
	"compileall": true, "contextlib": true, "copy": true, "csv": true, "ctypes": true,
	"curses": true, "datetime": true, "dbm": true, "decimal": true, "difflib": true, "dis": true,
	"doctest": true, "email": true, "encodings": true, "errno": true, "fcntl": true,
	"filecmp": true, "fileinput": true, "fnmatch": true, "fractions": true, "ftplib": true,
	"functools": true, "gc": true, "genericpath": true, "getopt": true, "getpass": true,
	"gettext": true, "glob": true, "grp": true, "gzip": true, "hashlib": true, "heapq": true,
	"hmac": true, "idlelib": true, "imaplib": true, "inspect": true, "io": true,
	"itertools": true, "json": true, "keyword": true, "linecache": true, "locale": true,
	"logging": true, "mailbox": true, "marshal": true, "math": true, "mimetypes": true,
	"mmap": true, "modulefinder": true, "msvcrt": true, "multiprocessing": true, "netrc": true,
	"nt": true, "ntpath": true, "nturl2path": true, "numbers": true, "opcode": true,
	"operator": true, "optparse": true, "os": true, "pdb": true, "pickle": true,
	"pickletools": true, "pkgutil": true, "platform": true, "plistlib": true, "poplib": true,
	"posix": true, "posixpath": true, "pprint": true, "profile": true, "pstats": true,
	"pty": true, "pwd": true, "py_compile": true, "pyclbr": true, "pydoc": true, "pyexpat": true,
	"quopri": true, "random": true, "re": true, "readline": true, "resource": true,
	"rlcompleter": true, "runpy": true, "sched": true, "select": true, "shelve": true,
	"shlex": true, "shutil": true, "signal": true, "site": true, "smtplib": true, "socket": true,
	"sqlite3": true, "sre_compile": true, "sre_constants": true, "sre_parse": true, "ssl": true,
	"stat": true, "string": true, "stringprep": true, "struct": true, "subprocess": true,
	"symtable": true, "sys": true, "syslog": true, "tabnanny": true, "tarfile": true,
	"tempfile": true, "termios": true, "textwrap": true, "this": true, "threading": true,
	"time": true, "timeit": true, "token": true, "tokenize": true, "trace": true,
	"traceback": true, "tty": true, "turtle": true, "types": true, "unicodedata": true,
	"unittest": true, "urllib": true, "uuid": true, "warnings": true, "wave": true,
	"weakref": true, "webbrowser": true, "winsound": true, "wsgiref": true, "xml": true,
	"zipfile": true, "zipimport": true, "zlib": true,
}

// stdlibBounded holds the top-level modules only some modelled releases ship, with the runs
// of releases that ship each.
var stdlibBounded = map[string][]releaseSpan{
	"_abc":                       {{307, 0}},
	"_abcoll":                    {{207, 303}},
	"_aix_support":               {{309, 0}},
	"_android_support":           {{313, 0}},
	"_apple_support":             {{314, 0}},
	"_ast_unparse":               {{314, 0}},
	"_asyncio":                   {{306, 0}},
	"_blake2":                    {{306, 0}},
	"_bootlocale":                {{304, 310}},
	"_bootsubprocess":            {{309, 312}},
	"_bsddb":                     {{207, 301}},
	"_bytesio":                   {{300, 301}},
	"_bz2":                       {{303, 0}},
	"_collections_abc":           {{304, 0}},
	"_colorize":                  {{313, 0}},
	"_compat_pickle":             {{301, 0}},
	"_compression":               {{305, 314}},
	"_contextvars":               {{307, 0}},
	"_crypt":                     {{303, 313}},
	"_datetime":                  {{302, 0}},
	"_dbm":                       {{300, 0}},
	"_decimal":                   {{303, 0}},
	"_dummy_thread":              {{300, 309}},
	"_fileio":                    {{300, 301}},
	"_frozen_importlib":          {{303, 0}},
	"_frozen_importlib_external": {{305, 0}},
	"_gdbm":                      {{300, 0}},
	"_gestalt":                   {{300, 304}},
	"_hmac":                      {{314, 0}},
	"_imp":                       {{303, 0}},
	"_interpchannels":            {{313, 0}},
	"_interpqueues":              {{313, 0}},
	"_interpreters":              {{313, 0}},
	"_io":                        {{207, 300}, {301, 0}},
	"_ios_support":               {{313, 0}},
	"_lzma":                      {{303, 0}},
	"_markupbase":                {{300, 0}},
	"_msi":                       {{207, 313}},
	"_opcode":                    {{304, 0}},
	"_opcode_metadata":           {{313, 0}},
	"_operator":                  {{304, 0}},
	"_osx_support":               {{303, 0}},
	"_overlapped":                {{304, 0}},
	"_peg_parser":                {{309, 310}},
	"_posixshmem":                {{308, 0}},
	"_posixsubprocess":           {{302, 0}},
	"_py_abc":                    {{307, 0}},
	"_py_warnings":               {{314, 0}},
	"_pydatetime":                {{312, 0}},
	"_pydecimal":                 {{305, 0}},
	"_pyio":                      {{207, 300}, {301, 0}},
	"_pylong":                    {{312, 0}},
	"_pyrepl":                    {{313, 0}},
	"_queue":                     {{307, 0}},
	"_remote_debugging":          {{314, 0}},
	"_scproxy":                   {{207, 300}, {302, 0}},
	"_sha":                       {{207, 303}},
	"_sha1":                      {{300, 0}},
	"_sha2":                      {{312, 0}},
	"_sha256":                    {{207, 312}},
	"_sha3":                      {{306, 0}},
	"_sha512":                    {{207, 312}},
	"_signal":                    {{305, 0}},
	"_sitebuiltins":              {{304, 0}},
	"_stat":                      {{304, 0}},
	"_statistics":                {{308, 0}},
	"_string":                    {{302, 0}},
	"_stringio":                  {{300, 301}},
	"_subprocess":                {{207, 303}},
	"_suggestions":               {{313, 0}},
	"_sysconfig":                 {{313, 0}},
	"_thread":                    {{300, 0}},
	"_tokenize":                  {{311, 0}},
	"_tracemalloc":               {{304, 0}},
	"_types":                     {{314, 0}},
	"_typing":                    {{311, 0}},
	"_uuid":                      {{307, 0}},
	"_winapi":                    {{303, 0}},
	"_wmi":                       {{313, 0}},
	"_zoneinfo":                  {{309, 0}},
	"_zstd":                      {{314, 0}},
	"aifc":                       {{207, 313}},
	"annotationlib":              {{314, 0}},
	"argparse":                   {{207, 300}, {302, 0}},
	"asynchat":                   {{207, 312}},
	"asyncio":                    {{304, 0}},
	"asyncore":                   {{207, 312}},
	"audioop":                    {{207, 313}},
	"binhex":                     {{207, 311}},
	"build_class":                {{300, 302}},
	"builtins":                   {{300, 0}},
	"cgi":                        {{207, 313}},
	"cgitb":                      {{207, 313}},
	"chunk":                      {{207, 313}},
	"compression":                {{314, 0}},
	"concurrent":                 {{302, 0}},
	"configparser":               {{300, 0}},
	"contextvars":                {{307, 0}},
	"copyreg":                    {{300, 0}},
	"crypt":                      {{207, 313}},
	"dataclasses":                {{307, 0}},
	"distutils":                  {{207, 312}},
	"dummy_threading":            {{207, 309}},
	"ensurepip":                  {{304, 0}},
	"enum":                       {{304, 0}},
	"faulthandler":               {{303, 0}},
	"formatter":                  {{207, 310}},
	"fpectl":                     {{207, 307}},
	"fpetest":                    {{207, 307}},
	"graphlib":                   {{309, 0}},
	"html":                       {{300, 0}},
	"http":                       {{300, 0}},
	"imghdr":                     {{207, 313}},
	"imp":                        {{207, 312}},
	"importlib":                  {{207, 300}, {301, 0}},
	"ipaddress":                  {{303, 0}},
	"lib2to3":                    {{207, 313}},
	"lzma":                       {{303, 0}},
	"macpath":                    {{207, 308}},
	"macurl2path":                {{207, 307}},
	"mailcap":                    {{207, 313}},
	"msilib":                     {{207, 313}},
	"nis":                        {{207, 313}},
	"nntplib":                    {{207, 313}},
	"os2emxpath":                 {{207, 304}},
	"ossaudiodev":                {{207, 313}},
	"parser":                     {{207, 310}},
	"pathlib":                    {{304, 0}},
	"pipes":                      {{207, 313}},
	"pydoc_data":                 {{207, 300}, {301, 0}},
	"pydoc_topics":               {{300, 301}},
	"queue":                      {{300, 0}},
	"reprlib":                    {{300, 0}},
	"secrets":                    {{306, 0}},
	"selectors":                  {{304, 0}},
	"smtpd":                      {{207, 312}},
	"sndhdr":                     {{207, 313}},
	"socketserver":               {{300, 0}},
	"spwd":                       {{207, 313}},
	"statistics":                 {{304, 0}},
	"sunau":                      {{207, 313}},
	"symbol":                     {{207, 310}},
	"sysconfig":                  {{207, 300}, {302, 0}},
	"telnetlib":                  {{207, 313}},
	"tkinter":                    {{300, 0}},
	"tomllib":                    {{311, 0}},
	"tracemalloc":                {{304, 0}},
	"turtledemo":                 {{302, 0}},
	"typing":                     {{305, 0}},
	"uu":                         {{207, 313}},
	"venv":                       {{303, 0}},
	"winreg":                     {{300, 0}},
	"xdrlib":                     {{207, 313}},
	"xmlrpc":                     {{300, 0}},
	"zipapp":                     {{305, 0}},
	"zoneinfo":                   {{309, 0}},
}
