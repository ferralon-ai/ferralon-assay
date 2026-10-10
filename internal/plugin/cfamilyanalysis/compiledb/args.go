package compiledb

import (
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// SplitCommand splits a database "command" string into argv using the POSIX shell quoting rules
// the spec prescribes: whitespace separates words, single quotes are literal, double quotes allow
// backslash escapes of " \ $ and `, and a bare backslash escapes the next character. It does not
// expand variables or globs. An unterminated quote or trailing backslash is an error.
func SplitCommand(cmd string) ([]string, error) {
	var (
		argv    []string
		cur     strings.Builder
		inWord  bool
		inS     bool
		inD     bool
		escaped bool
	)
	for _, r := range cmd {
		switch {
		case escaped:
			if inD && !strings.ContainsRune(`"\$`+"`", r) {
				cur.WriteRune('\\')
			}
			cur.WriteRune(r)
			escaped = false
		case inS:
			if r == '\'' {
				inS = false
			} else {
				cur.WriteRune(r)
			}
		case r == '\\':
			escaped, inWord = true, true
		case inD:
			if r == '"' {
				inD = false
			} else {
				cur.WriteRune(r)
			}
		case r == '\'':
			inS, inWord = true, true
		case r == '"':
			inD, inWord = true, true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inWord {
				argv = append(argv, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inS || inD || escaped {
		return nil, errors.New("unterminated quote or escape in command")
	}
	if inWord {
		argv = append(argv, cur.String())
	}
	return argv, nil
}

type tuKind int

const (
	kindTU tuKind = iota
	kindHeader
	kindOther
)

type invocation struct {
	kind      tuKind
	lang      Lang
	otherLang string
	std       string
	target    string
	compiler  Compiler
	unhandled []string
}

// wrappers are argv[0] launchers that run the real compiler named by the next argument.
var wrappers = map[string]bool{
	"ccache": true, "sccache": true, "distcc": true, "icecc": true, "gomacc": true, "buildcache": true,
}

// readInvocation reads one entry's argv. rawFile is the entry's file field as written and absFile
// its resolved form; either may be how the source appears in argv.
func readInvocation(argv []string, rawFile, absFile, dir string) invocation {
	var inv invocation
	unhandled := map[string]bool{}

	for len(argv) > 0 && wrappers[driverStem(argv[0])] {
		inv.compiler.Wrapper = filepath.Base(argv[0])
		argv = argv[1:]
		if len(argv) == 0 || strings.HasPrefix(argv[0], "-") {
			unhandled[UnhandledWrapper] = true
			break
		}
	}

	var args []string
	if len(argv) > 0 && !unhandled[UnhandledWrapper] {
		inv.compiler.Driver = argv[0]
		inv.compiler.Family = driverFamily(argv[0])
		args = argv[1:]
	}
	msvc := inv.compiler.Family == "msvc"
	if msvc {
		unhandled[UnhandledMSVC] = true
	}

	// -x applies to the inputs that follow it, so the mode in force where the source argument
	// appears is the one that counts. If the source never appears in argv, the last -x seen wins.
	xAtFile, xLast, sawFile := "", "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "@") && len(a) > 1 {
			unhandled[UnhandledResponseFile] = true
			continue
		}
		if msvc {
			switch strings.ToUpper(a) {
			case "/TC", "-TC":
				xLast = "c"
			case "/TP", "-TP":
				xLast = "c++"
			}
			continue
		}
		switch {
		case a == "-x" && i+1 < len(args):
			i++
			xLast = args[i]
		case strings.HasPrefix(a, "-x") && len(a) > 2:
			xLast = a[2:]
		case strings.HasPrefix(a, "-std="):
			inv.std = a[len("-std="):]
		case strings.HasPrefix(a, "--std="):
			inv.std = a[len("--std="):]
		case (a == "-target" || a == "--target") && i+1 < len(args):
			i++
			inv.target = args[i]
		case strings.HasPrefix(a, "--target="):
			inv.target = a[len("--target="):]
		case strings.HasPrefix(a, "-target="):
			inv.target = a[len("-target="):]
		case !sawFile && isSourceArg(a, rawFile, absFile, dir):
			sawFile = true
			xAtFile = xLast
		}
	}
	x := xAtFile
	if !sawFile {
		x = xLast
	}
	if x == "none" {
		x = ""
	}
	if inv.target == "" && !msvc {
		inv.target = driverTriple(inv.compiler.Driver)
	}

	inv.kind, inv.lang, inv.otherLang = classify(x, absFile, inv.compiler.Driver)
	for r := range unhandled {
		inv.unhandled = append(inv.unhandled, r)
	}
	sort.Strings(inv.unhandled)
	return inv
}

func isSourceArg(a, rawFile, absFile, dir string) bool {
	if a == rawFile || a == absFile {
		return true
	}
	if !filepath.IsAbs(a) && filepath.Clean(filepath.Join(dir, a)) == absFile {
		return true
	}
	return false
}

// classify decides the TU's language from an explicit -x mode, else the file extension, else
// nothing: a C++ driver (g++, clang++, c++) compiles a .c or preprocessed .i file as C++, so the
// driver breaks the tie for those two extensions only.
func classify(x, file, driver string) (tuKind, Lang, string) {
	if x != "" {
		switch x {
		case "c":
			return kindTU, LangC, ""
		case "c++":
			return kindTU, LangCXX, ""
		case "c-header", "c++-header", "c-system-header", "c++-system-header", "c-header-unit", "c++-header-unit", "c++-user-header":
			return kindHeader, "", ""
		case "cpp-output":
			return kindTU, LangC, ""
		case "c++-cpp-output":
			return kindTU, LangCXX, ""
		}
		return kindOther, "", x
	}
	ext := filepath.Ext(file)
	switch ext {
	case ".c", ".i":
		if isCXXDriver(driver) {
			return kindTU, LangCXX, ""
		}
		return kindTU, LangC, ""
	case ".cc", ".cp", ".cpp", ".cxx", ".c++", ".C", ".CPP", ".ii", ".cppm", ".ixx":
		return kindTU, LangCXX, ""
	case ".h", ".H", ".hh", ".hpp", ".hxx", ".h++", ".hp", ".HPP", ".inl", ".ipp", ".tcc", ".tpp":
		return kindHeader, "", ""
	}
	if ext == "" {
		return kindOther, "", "unknown"
	}
	return kindOther, "", strings.TrimPrefix(ext, ".")
}

var versionSuffix = regexp.MustCompile(`-[0-9][0-9.]*$`)

// driverStem is argv[0]'s basename without .exe or a trailing -<version>: "gcc-12" -> "gcc".
func driverStem(driver string) string {
	b := filepath.Base(driver)
	b = strings.TrimSuffix(strings.TrimSuffix(b, ".exe"), ".EXE")
	return versionSuffix.ReplaceAllString(b, "")
}

// compilerTail returns the compiler token a stem ends in ("aarch64-linux-gnu-gcc" -> "gcc") and
// the prefix before it, or "" when the stem names no known compiler.
func compilerTail(stem string) (tail, prefix string) {
	for _, c := range []string{"clang++", "clang-cl", "clang", "g++", "gcc", "c++", "cc", "cl"} {
		if stem == c {
			return c, ""
		}
		if strings.HasSuffix(stem, "-"+c) {
			return c, strings.TrimSuffix(stem, "-"+c)
		}
	}
	return "", ""
}

func driverFamily(driver string) string {
	tail, _ := compilerTail(driverStem(driver))
	switch tail {
	case "gcc", "g++":
		return "gcc"
	case "clang", "clang++":
		return "clang"
	case "cl", "clang-cl":
		return "msvc"
	}
	return ""
}

func isCXXDriver(driver string) bool {
	tail, _ := compilerTail(driverStem(driver))
	return tail == "g++" || tail == "clang++" || tail == "c++"
}

// knownTripleArches is the set of first components driverTriple accepts. A hyphenated driver
// name like "my-custom-gcc" has a prefix that COUNTS like a triple (two dash-separated parts) but
// is not one; gating on a known arch keeps driverTriple from inventing a Target for it.
var knownTripleArches = map[string]bool{
	"x86_64": true, "i386": true, "i486": true, "i586": true, "i686": true,
	"aarch64": true, "aarch64_be": true, "arm": true, "armeb": true,
	"armv6": true, "armv7": true, "armv7a": true, "armv7l": true, "thumbv7": true,
	"mips": true, "mipsel": true, "mips64": true, "mips64el": true,
	"powerpc": true, "powerpc64": true, "powerpc64le": true, "ppc64": true, "ppc64le": true,
	"riscv32": true, "riscv64": true, "sparc": true, "sparc64": true, "s390x": true,
	"wasm32": true, "wasm64": true,
}

// isPlausibleTriple reports whether prefix parses as arch-vendor-os[-env]: 2 to 4 dash-separated
// components whose first names a known architecture.
func isPlausibleTriple(prefix string) bool {
	parts := strings.Split(prefix, "-")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	return knownTripleArches[parts[0]]
}

// driverTriple returns the target triple a cross-compiler driver's name carries
// ("arm-none-eabi-gcc" -> "arm-none-eabi"). Only a prefix that parses as a plausible triple
// (isPlausibleTriple) is taken as one; anything else — a hyphenated driver name that merely LOOKS
// like a triple — yields no Target rather than a fabricated one.
func driverTriple(driver string) string {
	if driver == "" {
		return ""
	}
	_, prefix := compilerTail(driverStem(driver))
	if !isPlausibleTriple(prefix) {
		return ""
	}
	return prefix
}
