package javaanalysis

// launchoptions.go — the JVM launch options a checkout can set, for the JVM reachability lanes.
// A launch option can run code no call graph shows before main: an agent, a system class
// loader, a security manager, a logging config class, a provider the JDK looks up by property,
// a classpath entry. The lanes model only an allowlist of options known not to load or select
// code. Every file in the checkout is scanned for launch-option tokens; each occurrence is
// either classified inert, accounted for by a reader that can see its whole value, or it
// withholds Searched. Options that only the deploy environment sets (platform config vars,
// another repository's entrypoint, an env file outside the checkout) are residue.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	// PartialReasonLaunchAgent: a launch surface loads a Java agent (-javaagent, -agentlib,
	// -agentpath, -Xrun, a JAR's Launcher-Agent-Class) or extends the boot classpath.
	PartialReasonLaunchAgent = plugin.PartialReasonRelationshipUnexpressed + ":launch_jvm_agent"
	// PartialReasonLaunchOption: a launch surface sets a JVM option outside the modeled
	// allowlist, names options in a form that cannot be read, or cannot itself be read.
	PartialReasonLaunchOption = plugin.PartialReasonRelationshipUnexpressed + ":launch_jvm_option"
)

// LaunchOptionReasons scans every file under buildDir and returns the reasons its launch-option
// tokens declare, sorted: none when every occurrence is accounted for. Only node_modules and
// site-packages are skipped. A file or directory that cannot be read, and a symlink that
// dangles, escapes buildDir, or leads into a skipped directory, withholds Searched.
func LaunchOptionReasons(buildDir string) []string {
	s := &launchScan{reasons: map[string]bool{}}
	s.walk(buildDir)
	out := make([]string, 0, len(s.reasons))
	for r := range s.reasons {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// launchSkipDirs hold another ecosystem's installed packages, owned by the JS and Python lanes.
var launchSkipDirs = map[string]bool{"node_modules": true, "site-packages": true}

type launchScan struct {
	reasons map[string]bool
}

func (s *launchScan) unreadable() { s.reasons[PartialReasonLaunchOption] = true }
func (s *launchScan) agent()      { s.reasons[PartialReasonLaunchAgent] = true }

// walk visits every file under root at its real path. A symlinked directory is walked at its
// real path when that lies inside root's real path and outside a skipped directory; links are
// never followed by the directory walk itself, and each link target directory is walked at
// most once, so the walk terminates on cycles. It dedupes onto buildtree.Walk after #97 merges.
func (s *launchScan) walk(root string) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		s.unreadable()
		return
	}
	walked := map[string]bool{realRoot: true}
	s.walkDir(realRoot, realRoot, walked)
}

func (s *launchScan) walkDir(realRoot, dir string, walked map[string]bool) {
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.unreadable()
			return nil
		}
		rel, _ := filepath.Rel(realRoot, path)
		switch {
		case d.IsDir():
			if path != dir && launchSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
		case d.Type()&fs.ModeSymlink != 0:
			s.link(realRoot, path, rel, walked)
		case d.Type().IsRegular():
			s.file(path, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		s.unreadable()
	}
}

// link resolves one symlink: an in-root directory is walked at its real path, an in-root file
// is read through the link, and anything else withholds Searched.
func (s *launchScan) link(realRoot, path, rel string, walked map[string]bool) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		s.unreadable() // dangling, or a component cannot be read
		return
	}
	trel, err := filepath.Rel(realRoot, target)
	if err != nil || trel == ".." || strings.HasPrefix(trel, ".."+string(filepath.Separator)) {
		s.unreadable() // escapes the checkout
		return
	}
	for _, part := range strings.Split(trel, string(filepath.Separator)) {
		if launchSkipDirs[part] {
			s.unreadable()
			return
		}
	}
	fi, err := os.Stat(target)
	if err != nil {
		s.unreadable()
		return
	}
	switch {
	case fi.IsDir():
		if !walked[target] {
			walked[target] = true
			s.walkDir(realRoot, target, walked)
		}
	case fi.Mode().IsRegular():
		s.file(path, filepath.ToSlash(rel))
	}
}

const (
	// launchTextLimit is the largest file read whole; larger files are scanned in windows
	// with no reader context, so every name or classpath token in them withholds Searched.
	launchTextLimit = 8 << 20
	launchWindow    = 1 << 20
	launchOverlap   = 512
	// launchNestedLimit bounds a JAR read into memory from inside a distribution archive.
	launchNestedLimit = 64 << 20
)

func launchHasSuffix(lower string, suffixes ...string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(lower, x) {
			return true
		}
	}
	return false
}

func isCodeArchive(lower string) bool { return launchHasSuffix(lower, ".jar", ".war", ".ear") }
func isTarArchive(lower string) bool  { return launchHasSuffix(lower, ".tar", ".tgz", ".tar.gz") }

// file scans one checkout file. A code archive is read for its manifest only; a distribution
// archive (.zip, .tar, .tgz) is read entry by entry; anything else is scanned as text.
func (s *launchScan) file(path, rel string) {
	lower := strings.ToLower(rel)
	switch {
	case isCodeArchive(lower):
		zr, err := zip.OpenReader(path)
		if err != nil {
			s.unreadable()
			return
		}
		defer zr.Close()
		s.manifest(&zr.Reader)
		return
	case strings.HasSuffix(lower, ".zip"):
		zr, err := zip.OpenReader(path)
		if err != nil {
			s.unreadable()
			return
		}
		defer zr.Close()
		s.zipEntries(&zr.Reader)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		s.unreadable()
		return
	}
	defer f.Close()
	if isTarArchive(lower) {
		s.tarEntries(f, !strings.HasSuffix(lower, ".tar"))
		return
	}
	fi, err := f.Stat()
	if err != nil {
		s.unreadable()
		return
	}
	s.content(rel, false, f, fi.Size())
}

// content scans one file's bytes: whole when small enough, else in windows.
func (s *launchScan) content(rel string, inDist bool, r io.Reader, size int64) {
	if size >= 0 && size <= launchTextLimit {
		data, err := io.ReadAll(r)
		if err != nil {
			s.unreadable()
			return
		}
		s.text(rel, inDist, data)
		return
	}
	buf := make([]byte, launchWindow+launchOverlap)
	carry := 0
	for {
		n, err := io.ReadFull(r, buf[carry:])
		chunk := buf[:carry+n]
		final := errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
		s.tokensOnly(chunk, final)
		if final {
			return
		}
		if err != nil {
			s.unreadable()
			return
		}
		carry = copy(buf, chunk[len(chunk)-launchOverlap:])
	}
}

// manifest reads a JAR's META-INF/MANIFEST.MF: a Launcher-Agent-Class starts an agent when
// the JAR is launched with -jar, and a Class-Path extends the classpath of every launch that
// puts the JAR on it.
func (s *launchScan) manifest(zr *zip.Reader) {
	for _, f := range zr.File {
		if !strings.EqualFold(f.Name, "META-INF/MANIFEST.MF") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.unreadable()
			return
		}
		data, err := io.ReadAll(io.LimitReader(rc, launchTextLimit))
		rc.Close()
		if err != nil {
			s.unreadable()
			return
		}
		text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n ", "")
		for _, line := range strings.Split(text, "\n") {
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "launcher-agent-class":
				s.agent()
			case "class-path":
				if strings.TrimSpace(value) != "" {
					s.unreadable()
				}
			}
		}
	}
}

func (s *launchScan) zipEntries(zr *zip.Reader) {
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			s.unreadable()
			continue
		}
		s.entry(f.Name, rc, int64(f.UncompressedSize64))
		rc.Close()
	}
}

func (s *launchScan) tarEntries(r io.Reader, gz bool) {
	if gz {
		zr, err := gzip.NewReader(r)
		if err != nil {
			s.unreadable()
			return
		}
		defer zr.Close()
		r = zr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			s.unreadable()
			return
		}
		if h.Typeflag == tar.TypeReg {
			s.entry(h.Name, tr, h.Size)
		}
	}
}

// entry scans one distribution-archive entry: a nested code archive for its manifest, a class
// file not at all (its code is the call graph's), anything else as text.
func (s *launchScan) entry(name string, r io.Reader, size int64) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".class"):
	case isCodeArchive(lower) || strings.HasSuffix(lower, ".zip"):
		data, err := io.ReadAll(io.LimitReader(r, launchNestedLimit+1))
		if err != nil || len(data) > launchNestedLimit {
			s.unreadable()
			return
		}
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			s.unreadable()
			return
		}
		s.manifest(zr)
	default:
		s.content(name, true, r, size)
	}
}

// jvmOptionVar reports whether an environment variable carries JVM options for the program:
// the JVM's and the java launcher's own variables, JAVA_OPTS-style variables, and a Gradle
// start script's <APP>_OPTS. The build tools' variables configure their own JVM.
func isJVMOptionVar(name string) bool {
	return !buildToolVars[name] && (strings.Contains(name, "JAVA_TOOL_OPTIONS") ||
		strings.Contains(name, "JAVA_OPTIONS") || strings.Contains(name, "_OPTS"))
}

// buildToolVars configure a build tool's own JVM, not the program's.
var buildToolVars = map[string]bool{"GRADLE_OPTS": true, "MAVEN_OPTS": true, "SBT_OPTS": true, "ANT_OPTS": true}

// options classifies one option list, token by token.
func (s *launchScan) options(tokens []string) {
	for i := 0; i < len(tokens); i++ {
		switch classifyLaunchOption(tokens[i]) {
		case optionAgent:
			s.agent()
		case optionUnmodeled:
			s.unreadable()
		case optionTakesValue:
			i++
		}
	}
}

type optionClass int

const (
	optionInert optionClass = iota
	optionTakesValue
	optionAgent
	optionUnmodeled
)

var agentOptionPrefixes = []string{"-javaagent:", "-agentlib:", "-agentpath:", "-Xrun", "-Xbootclasspath"}

// inertProperties are system properties that select no code: the JDK reads them as plain
// values. Encoding properties are inert only for a standard charset (inertEncodings).
var inertProperties = map[string]bool{
	"java.awt.headless": true, "java.net.preferIPv4Stack": true,
	"java.net.preferIPv6Addresses": true, "java.security.egd": true,
	"user.language": true, "user.country": true, "user.region": true, "user.variant": true,
	"user.script": true, "user.timezone": true, "user.name": true,
}

var encodingProperties = map[string]bool{
	"file.encoding": true, "sun.jnu.encoding": true, "stdout.encoding": true, "stderr.encoding": true,
}

// inertEncodings are the charsets every JDK resolves from java.base without a provider lookup.
var inertEncodings = map[string]bool{
	"UTF-8": true, "UTF8": true, "US-ASCII": true, "ISO-8859-1": true, "UTF-16": true,
	"UTF-16BE": true, "UTF-16LE": true, "COMPAT": true,
}

var inertFlags = map[string]bool{
	"-server": true, "-client": true, "-ea": true, "-da": true, "-esa": true, "-dsa": true,
	"-enableassertions": true, "-disableassertions": true,
	"-enablesystemassertions": true, "-disablesystemassertions": true,
}

var inertFlagPrefixes = []string{"-Xmx", "-Xms", "-Xss", "-Xmn", "-Xlog:", "-verbose:", "-ea:", "-da:",
	"-enableassertions:", "-disableassertions:"}

// inertXX are -XX options that size or tune the VM and load no code.
var inertXX = map[string]bool{
	"MaxRAMPercentage": true, "InitialRAMPercentage": true, "MinRAMPercentage": true, "MaxRAM": true,
	"MetaspaceSize": true, "MaxMetaspaceSize": true, "MaxDirectMemorySize": true,
	"ReservedCodeCacheSize": true, "UseG1GC": true, "UseParallelGC": true, "UseSerialGC": true,
	"UseZGC": true, "ZGenerational": true, "UseShenandoahGC": true, "UseContainerSupport": true,
	"ExitOnOutOfMemoryError": true, "CrashOnOutOfMemoryError": true,
	"HeapDumpOnOutOfMemoryError": true, "HeapDumpPath": true, "MaxGCPauseMillis": true,
	"ActiveProcessorCount": true, "UseStringDeduplication": true,
}

// valueOptions take the next token as their value; module access options grant reflective
// access only. Classpath, JAR and module-path options name the launch's code and are
// unmodeled.
var valueOptions = map[string]bool{"--add-opens": true, "--add-exports": true, "--add-reads": true}

func classifyLaunchOption(opt string) optionClass {
	for _, p := range agentOptionPrefixes {
		if strings.HasPrefix(opt, p) {
			return optionAgent
		}
	}
	if valueOptions[opt] {
		return optionTakesValue
	}
	for _, p := range []string{"--add-opens=", "--add-exports=", "--add-reads="} {
		if strings.HasPrefix(opt, p) {
			return optionInert
		}
	}
	if inertFlags[opt] {
		return optionInert
	}
	for _, p := range inertFlagPrefixes {
		if strings.HasPrefix(opt, p) {
			return optionInert
		}
	}
	if prop, ok := strings.CutPrefix(opt, "-D"); ok {
		name, value, _ := strings.Cut(prop, "=")
		switch {
		case encodingProperties[name]:
			if inertEncodings[strings.ToUpper(value)] {
				return optionInert
			}
		case inertProperties[name]:
			return optionInert
		}
		return optionUnmodeled
	}
	if xx, ok := strings.CutPrefix(opt, "-XX:"); ok {
		name := strings.TrimLeft(xx, "+-")
		name, _, _ = strings.Cut(name, "=")
		if inertXX[name] {
			return optionInert
		}
	}
	return optionUnmodeled
}

// expansionWord matches a word that is one whole variable expansion: $NAME, ${NAME},
// ${NAME:-default} and the other parameter forms, $(NAME), %NAME%.
var expansionWord = regexp.MustCompile(`^(?:\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::?[-=+?][^}]*)?\}?|\$\(([A-Za-z_][A-Za-z0-9_]*)\)|%([A-Za-z_][A-Za-z0-9_]*)%)$`)

// splitOptionWords splits a shell-quoted option string into words. A word that is a whole
// expansion of another JVM option variable is that variable's value, read where it is set (or
// deploy-time residue); any other word that expands a variable cannot be read.
func splitOptionWords(value string) (words []string, unreadable bool) {
	for _, w := range strings.Fields(strings.NewReplacer(`"`, " ", "'", " ", `\`, " ").Replace(value)) {
		if m := expansionWord.FindStringSubmatch(w); m != nil {
			if !isJVMOptionVar(m[1] + m[2] + m[3]) {
				unreadable = true
			}
			continue
		}
		if strings.Contains(w, "$") || strings.Contains(w, "%") || strings.Contains(w, "`") {
			if classifyLaunchOption(w) == optionAgent {
				words = append(words, w) // an agent whatever path it names
				continue
			}
			if prop, ok := strings.CutPrefix(w, "-D"); ok {
				// A property's value is read only for the encoding properties.
				name, _, _ := strings.Cut(prop, "=")
				if !strings.ContainsAny(name, "$%`") && !encodingProperties[name] {
					words = append(words, w)
					continue
				}
			}
			unreadable = true
			continue
		}
		words = append(words, w)
	}
	return words, unreadable
}

func (s *launchScan) optionString(value string) {
	words, unreadable := splitOptionWords(value)
	if unreadable {
		s.unreadable()
	}
	s.options(words)
}

// optionHead finds candidate launch-option tokens; launchOptionToken validates each.
var optionHead = regexp.MustCompile(`-(?:D|XX:|javaagent|agentlib|agentpath|Xrun|Xbootclasspath|cp|classpath|jar|p)|--(?:add-modules|upgrade-module-path|patch-module|limit-modules|class-path|module-path)`)

type launchToken struct {
	start, end int
	word       string
}

func isLaunchDelim(b byte) bool {
	return b <= ' ' || b == 0x7f || strings.IndexByte("\"'`,[]();|&<>}\\", b) >= 0
}

// leftBoundary reports whether a token may start at i: at a word start, or after the `:-` of a
// parameter default.
func leftBoundary(data []byte, i int) bool {
	if i == 0 {
		return true
	}
	b := data[i-1]
	if b <= ' ' || strings.IndexByte("\"'`[](){},;=:+|&<>", b) >= 0 {
		return true
	}
	return b == '-' && i >= 2 && data[i-2] == ':'
}

var propertyNameByte = func() (t [256]bool) {
	for _, c := range "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-${%" {
		t[c] = true
	}
	return t
}()

// launchOptionTokens returns every launch-option token in data. A token is a whole word; one
// that touches a control byte or is not UTF-8 is binary data, not text, and is skipped.
func launchOptionTokens(data []byte) []launchToken {
	var out []launchToken
	for pos := 0; pos < len(data); {
		loc := optionHead.FindIndex(data[pos:])
		if loc == nil {
			break
		}
		h := pos + loc[0]
		head := string(data[h : pos+loc[1]])
		if !leftBoundary(data, h) {
			pos = h + 1
			continue
		}
		end := h
		for end < len(data) && !isLaunchDelim(data[end]) {
			end++
		}
		pos = end
		if binaryAdjacent(data, h, end) {
			continue
		}
		word := string(data[h:end])
		if !utf8.ValidString(word) {
			continue
		}
		switch head {
		case "-D":
			name, _, _ := strings.Cut(word[2:], "=")
			if name == "" || !validPropertyName(name) {
				continue
			}
			if strings.HasSuffix(word, "=") && end < len(data) && (data[end] == '"' || data[end] == '\'') {
				if close := bytes.IndexByte(data[end+1:], data[end]); close >= 0 && bytes.IndexByte(data[end+1:end+1+close], '\n') < 0 {
					word += string(data[end+1 : end+1+close])
					end += close + 2
					pos = end
				}
			}
		case "-XX:":
			if len(word) == len(head) {
				continue
			}
		case "-cp", "-classpath", "-jar", "-p":
			if word != head {
				continue
			}
		case "--class-path", "--module-path", "--add-modules", "--upgrade-module-path", "--patch-module", "--limit-modules":
			if word != head && !strings.HasPrefix(word, head+"=") {
				continue
			}
		}
		out = append(out, launchToken{start: h, end: end, word: word})
	}
	return out
}

// binaryAdjacent reports whether data[a:b] touches a control byte other than whitespace: a
// string in a binary serialization (a class file, Gradle's execution history), not text. The
// launcher reads no options from such a file; options embedded in binaries are residue.
func binaryAdjacent(data []byte, a, b int) bool {
	ctl := func(c byte) bool { return c < ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v' }
	return a > 0 && ctl(data[a-1]) || b < len(data) && ctl(data[b])
}

func validPropertyName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !propertyNameByte[name[i]] {
			return false
		}
	}
	return true
}

func isClasspathToken(w string) bool {
	switch w {
	case "-cp", "-classpath", "-jar", "--class-path", "--module-path":
		return true
	}
	return strings.HasPrefix(w, "--class-path=") || strings.HasPrefix(w, "--module-path=")
}

// launchName finds the names that carry JVM options without being options themselves: option
// variables, the Gradle and Maven DSL properties that become launch options, and the JAR
// manifest attributes that start an agent or extend the classpath.
var launchName = regexp.MustCompile(`\b[A-Za-z0-9_]*(?:JAVA_TOOL_OPTIONS|JAVA_OPTIONS|_OPTS)[A-Za-z0-9_]*\b|\b(?:applicationDefaultJvmArgs|defaultJvmOpts|jvmFlags?|jvmArguments)\b|\bLauncher-Agent-Class\b|\bClass-Path\b`)

// launchNames returns the launch-name occurrences in text. A file with a NUL byte is a binary
// serialization (a class file, Gradle's execution history) that the launcher reads no options
// from: a name in it is data, and options embedded in binaries are residue. Option tokens in
// binaries still classify themselves.
func launchNames(data []byte) [][]int {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	var out [][]int
	for _, loc := range launchName.FindAllIndex(data, -1) {
		if !binaryAdjacent(data, loc[0], loc[1]) {
			out = append(out, loc)
		}
	}
	return out
}

var launchDSLNames = map[string]bool{
	"applicationDefaultJvmArgs": true, "defaultJvmOpts": true, "jvmFlags": true, "jvmFlag": true, "jvmArguments": true,
}

// tokensOnly classifies the tokens of a window of a large file, with no reader context. An
// occurrence running into the window's end is read whole from the next, overlapping window.
func (s *launchScan) tokensOnly(data []byte, final bool) {
	for _, t := range launchOptionTokens(data) {
		if t.word == "-p" || !final && t.end == len(data) {
			continue
		}
		s.options([]string{t.word})
	}
	for _, loc := range launchNames(data) {
		n := string(data[loc[0]:loc[1]])
		if !final && loc[1] == len(data) {
			continue
		}
		switch {
		case n == "Launcher-Agent-Class":
			s.agent()
		case !buildToolVars[n]:
			s.unreadable()
		}
	}
}

type launchSpanKind int

const (
	// spanBuild: a build tool's own JVM or command line. Its -D and -XX options are claimed,
	// except properties a build plugin turns into launch options (jib.*, spring-boot.*).
	spanBuild launchSpanKind = iota
	// spanDev: a Gradle jvmArgs or Maven argLine, which configure test and dev-run JVMs only.
	spanDev
)

type launchSpan struct {
	start, end int
	kind       launchSpanKind
}

// launchFile is one text file under scan, with the reader context its occurrences need.
type launchFile struct {
	s           *launchScan
	data        []byte
	lines       []int // start offset of each line
	gradlew     bool
	startScript bool
	spans       []launchSpan
	yamlLines   map[int]bool // 1-based lines whose name occurrence a YAML reader classified
	template    map[int]bool // 0-based start-script template comment lines
}

func (s *launchScan) text(rel string, inDist bool, data []byte) {
	tokens := launchOptionTokens(data)
	names := launchNames(data)
	javaCtx := bytes.Contains(data, []byte("java")) && (bytes.Contains(data, []byte("-p")) || bytes.Contains(data, []byte("@")))
	if len(tokens) == 0 && len(names) == 0 && !javaCtx {
		return
	}
	base := strings.ToLower(rel[strings.LastIndex(rel, "/")+1:])
	f := &launchFile{s: s, data: data, gradlew: base == "gradlew" || base == "gradlew.bat",
		startScript: isStartScript(rel, inDist), yamlLines: map[int]bool{}, template: map[int]bool{}}
	f.lines = append(f.lines, 0)
	for i, b := range data {
		if b == '\n' && i+1 < len(data) {
			f.lines = append(f.lines, i+1)
		}
	}
	f.buildSpans(rel)
	f.devSpans()
	if f.gradlew || f.startScript {
		for i := range f.lines {
			if startScriptCommentLines[strings.Join(strings.Fields(f.line(i)), " ")] {
				f.template[i] = true
			}
		}
	}
	if launchHasSuffix(base, ".yaml", ".yml", ".json") {
		f.yaml()
	}
	for _, t := range tokens {
		f.option(t)
	}
	for _, loc := range names {
		f.name(loc[0], loc[1])
	}
	if javaCtx {
		f.javaContext()
	}
}

// isStartScript reports whether rel is a Gradle-generated start script: build/scripts/<name>
// or build/install/<app>/bin/<name> in any project, or <app>/bin/<name> in a distribution.
func isStartScript(rel string, inDist bool) bool {
	parts := strings.Split(rel, "/")
	n := len(parts)
	if inDist {
		return n == 3 && parts[1] == "bin"
	}
	return n >= 3 && parts[n-3] == "build" && parts[n-2] == "scripts" ||
		n >= 5 && parts[n-5] == "build" && parts[n-4] == "install" && parts[n-2] == "bin"
}

// startScriptCommentLines are the comment lines of Gradle's start-script and wrapper templates
// that name options.
var startScriptCommentLines = map[string]bool{
	"# * -classpath": true, "# * -D...appname settings": true, "# * --module-path (only if needed)": true,
}

func (f *launchFile) lineOf(off int) int {
	return sort.Search(len(f.lines), func(i int) bool { return f.lines[i] > off }) - 1
}

func (f *launchFile) lineEnd(i int) int {
	if i+1 < len(f.lines) {
		return f.lines[i+1] - 1
	}
	return len(f.data)
}

func (f *launchFile) line(i int) string {
	return strings.TrimRight(string(f.data[f.lines[i]:f.lineEnd(i)]), "\r\n")
}

func (f *launchFile) inSpan(off int, kind launchSpanKind) bool {
	for _, sp := range f.spans {
		if sp.kind == kind && off >= sp.start && off < sp.end {
			return true
		}
	}
	return false
}

// logicalLines returns the byte ranges of the file's logical lines: backslash continuations
// (and caret continuations in batch files) are joined.
func (f *launchFile) logicalLines() [][2]int {
	var out [][2]int
	start := 0
	for i := range f.lines {
		l := strings.TrimRight(f.line(i), " \t")
		if (strings.HasSuffix(l, `\`) || strings.HasSuffix(l, "^")) && i+1 < len(f.lines) {
			continue
		}
		out = append(out, [2]int{f.lines[start], f.lineEnd(i)})
		start = i + 1
	}
	return out
}

// launchWords splits a command line into words and the separators ; | & between commands.
var launchWords = regexp.MustCompile(`[;|&]+|[^\s"'\[\](),;|&]+`)

var buildToolCommands = map[string]bool{
	"mvn": true, "mvnw": true, "mvn.cmd": true, "mvnw.cmd": true, "gradle": true, "gradlew": true,
	"gradle.bat": true, "gradlew.bat": true, "sbt": true, "ant": true, "cmake": true, "gcc": true,
	"g++": true, "cc": true, "clang": true, "clang++": true,
}

func commandBase(w string) string {
	w = w[strings.LastIndexAny(w, `/\`)+1:]
	return strings.ToLower(w)
}

func isJavaCommand(w string) bool {
	switch commandBase(w) {
	case "java", "java.exe", "javaw", "javaw.exe":
		return true
	}
	return false
}

// buildSpans marks the build tools' own option surfaces: the wrapper scripts and .mvn
// config files whole, a build-tool command up to the next command or java word, and a line
// that assigns a build tool's option variable or Gradle's daemon JVM arguments.
func (f *launchFile) buildSpans(rel string) {
	if f.gradlew || strings.HasSuffix(rel, ".mvn/jvm.config") || strings.HasSuffix(rel, ".mvn/maven.config") ||
		rel == ".mvn/jvm.config" || rel == ".mvn/maven.config" {
		f.spans = append(f.spans, launchSpan{0, len(f.data), spanBuild})
		return
	}
	for _, ll := range f.logicalLines() {
		seg := f.data[ll[0]:ll[1]]
		open := -1
		for _, loc := range launchWords.FindAllIndex(seg, -1) {
			w := string(seg[loc[0]:loc[1]])
			switch {
			case strings.ContainsAny(w[:1], ";|&") || isJavaCommand(w):
				if open >= 0 {
					f.spans = append(f.spans, launchSpan{ll[0] + open, ll[0] + loc[0], spanBuild})
					open = -1
				}
			case open < 0 && buildToolCommands[commandBase(w)]:
				open = loc[1]
			case open < 0:
				k := w
				if i := strings.IndexAny(k, "=:"); i >= 0 {
					k = k[:i]
				}
				if buildToolVars[k] || k == "org.gradle.jvmargs" || k == "kotlin.daemon.jvmargs" {
					open = loc[0]
				}
			}
		}
		if open >= 0 {
			f.spans = append(f.spans, launchSpan{ll[0] + open, ll[1], spanBuild})
		}
	}
}

var devArgs = regexp.MustCompile(`\bjvmArgs\b|<argLine>`)

// devSpans marks Gradle jvmArgs (Test, JavaExec, bootRun) and Maven argLine (Surefire,
// Failsafe): JVMs the build starts for tests and dev runs, never the deployed program.
func (f *launchFile) devSpans() {
	for _, loc := range devArgs.FindAllIndex(f.data, -1) {
		end := f.lineEnd(f.lineOf(loc[0]))
		if string(f.data[loc[0]:loc[1]]) == "<argLine>" {
			if i := bytes.Index(f.data[loc[1]:], []byte("</argLine>")); i >= 0 {
				end = max(end, loc[1]+i)
			}
		} else {
			rest := string(f.data[loc[1]:])
			trimmed := strings.TrimLeft(rest, " \t")
			for _, op := range []string{"+=", "=", ".addAll", ".add", ".set"} {
				if strings.HasPrefix(trimmed, op) {
					trimmed = strings.TrimLeft(trimmed[len(op):], " \t")
					break
				}
			}
			if expr, ok := bracketedExpr(trimmed); ok {
				end = max(end, loc[1]+len(rest)-len(trimmed)+len(expr))
			}
		}
		f.spans = append(f.spans, launchSpan{loc[0], end, spanDev})
	}
}

// option classifies one option token.
func (f *launchFile) option(t launchToken) {
	if t.word == "-p" || f.inSpan(t.start, spanDev) || f.template[f.lineOf(t.start)] {
		return
	}
	if isClasspathToken(t.word) {
		if !f.templateClasspath(t) {
			f.s.unreadable()
		}
		return
	}
	switch classifyLaunchOption(t.word) {
	case optionAgent:
		f.s.agent()
	case optionUnmodeled:
		if !f.inSpan(t.start, spanBuild) || !buildClaimable(t.word) {
			f.s.unreadable()
		}
	}
}

func buildClaimable(w string) bool {
	if strings.HasPrefix(w, "-XX:") {
		return true
	}
	prop, ok := strings.CutPrefix(w, "-D")
	return ok && !strings.HasPrefix(prop, "jib.") && !strings.HasPrefix(prop, "spring-boot.")
}

// templateClasspath reports whether a classpath token is the Gradle template's own: a start
// script's -classpath "$CLASSPATH", or the wrapper script's wrapper JAR.
func (f *launchFile) templateClasspath(t launchToken) bool {
	if !f.gradlew && !f.startScript {
		return false
	}
	rest := strings.TrimLeft(string(f.data[t.end:min(t.end+64, len(f.data))]), " \t")
	switch t.word {
	case "-classpath":
		return strings.HasPrefix(rest, `"$CLASSPATH"`) || strings.HasPrefix(rest, `"%CLASSPATH%"`)
	case "-jar":
		return f.gradlew && (strings.HasPrefix(rest, `"$APP_HOME/gradle/wrapper/gradle-wrapper.jar"`) ||
			strings.HasPrefix(rest, `"%APP_HOME%\gradle\wrapper\gradle-wrapper.jar"`))
	}
	return false
}

// name classifies one occurrence of a launch name. An option variable is accounted for when it
// is expanded, sits on a comment line, is assigned a literal on the same line, or a YAML/JSON
// reader attached it to a scalar value; a DSL property when its value is a literal list.
func (f *launchFile) name(a, b int) {
	n := string(f.data[a:b])
	switch n {
	case "Launcher-Agent-Class":
		f.s.agent()
		return
	case "Class-Path":
		f.s.unreadable()
		return
	}
	if f.inSpan(a, spanDev) || buildToolVars[n] || launchExpansion(f.data, a, b) {
		return
	}
	li := f.lineOf(a)
	line := f.line(li)
	if isLaunchCommentLine(line) {
		return
	}
	if launchDSLNames[n] {
		f.dsl(a, b)
		return
	}
	if f.yamlLines[li+1] {
		return
	}
	col := a - f.lines[li]
	if v, ok := assignedValue(line, col, col+len(n)); ok {
		f.s.optionString(v)
		return
	}
	switch strings.TrimSpace(line[:col]) + "|" + strings.TrimSpace(line[col+len(n):]) {
	case "export|", "unset|":
		return
	}
	f.s.unreadable()
}

// launchExpansion reports whether data[a:b] is a variable expansion: $NAME, ${NAME}, $(NAME),
// %NAME%, !NAME!, or a GitHub Actions ${{ env.NAME }} context reference.
func launchExpansion(data []byte, a, b int) bool {
	switch {
	case a >= 1 && data[a-1] == '$':
		return true
	case a >= 2 && data[a-2] == '$' && (data[a-1] == '{' || data[a-1] == '('):
		return true
	case a >= 1 && b < len(data) && (data[a-1] == '%' && data[b] == '%' || data[a-1] == '!' && data[b] == '!'):
		return true
	}
	lineStart := bytes.LastIndexByte(data[:a], '\n') + 1
	prefix := string(data[lineStart:a])
	for _, ctx := range []string{"env.", "secrets.", "vars."} {
		if strings.HasSuffix(prefix, ctx) {
			open := strings.LastIndex(prefix, "${{")
			return open >= 0 && !strings.Contains(prefix[open:], "}}")
		}
	}
	return false
}

func isLaunchCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	lower := strings.ToLower(t)
	for _, p := range []string{"#", "//", "/*", "*", "<!--", "::", ";", "@rem"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return lower == "rem" || strings.HasPrefix(lower, "rem ")
}

var assignOp = regexp.MustCompile(`^\s*(\?=|\+=|::=|:=|=|:)\s*`)

// assignedValue returns the literal a line assigns to the name at line[a:b]: NAME=value and
// the make/YAML/JSON/TOML operators, Dockerfile's legacy ENV NAME value, Kotlin's "NAME" to
// "value", and a call's ("NAME", "value"). ok is false when the value is not on the line.
func assignedValue(line string, a, b int) (string, bool) {
	after := line[b:]
	quoted := a > 0 && (line[a-1] == '"' || line[a-1] == '\'') && strings.HasPrefix(after, line[a-1:a])
	if quoted {
		after = after[1:]
	}
	var rest string
	op := ""
	if m := assignOp.FindStringSubmatch(after); m != nil {
		op, rest = m[1], after[len(m[0]):]
	} else if strings.EqualFold(strings.TrimSpace(line[:a]), "ENV") && strings.HasPrefix(after, " ") {
		op, rest = "ENV", strings.TrimSpace(after)
	} else if m := regexp.MustCompile(`^\s+to\s+|^\s*,\s*`).FindString(after); quoted && m != "" {
		if strings.TrimSpace(m) == "," && !strings.HasSuffix(strings.TrimRight(line[:a-1], " \t"), "(") {
			return "", false
		}
		op, rest = strings.TrimSpace(m), after[len(m):]
	} else {
		return "", false
	}
	rest = strings.TrimRight(rest, " \t\r")
	if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
		q := rest[0]
		for i := 1; i < len(rest); i++ {
			switch rest[i] {
			case '\\':
				i++
			case q:
				return rest[1:i], true
			}
		}
		return "", false // the literal continues past the line
	}
	if op == ":" && (rest == "" || rest[0] == '|' || rest[0] == '>') {
		return "", false // a YAML block or nested value
	}
	if i := strings.Index(rest, " #"); i >= 0 {
		rest = rest[:i]
	}
	return rest, true
}

var xmlTag = regexp.MustCompile(`<[^>]*>`)

// dsl classifies a Gradle or Maven DSL property that becomes launch options: an XML element's
// text (a property reference in it cannot be read), or an assignment, call or set(...) whose value is a
// list of string literals (or a + concatenation of such lists). Anything else cannot be read.
func (f *launchFile) dsl(a, b int) {
	d := f.data
	n := string(d[a:b])
	if a >= 2 && d[a-2] == '<' && d[a-1] == '/' {
		return
	}
	if a >= 1 && d[a-1] == '<' {
		gt := bytes.IndexByte(d[b:], '>')
		if gt < 0 {
			f.s.unreadable()
			return
		}
		if gt > 0 && d[b+gt-1] == '/' {
			return
		}
		body := d[b+gt+1:]
		end := bytes.Index(body, []byte("</"+n+">"))
		if end < 0 {
			f.s.unreadable()
			return
		}
		f.s.optionString(xmlTag.ReplaceAllString(string(body[:end]), " "))
		return
	}
	rest := string(d[b:])
	trimmed := strings.TrimLeft(rest, " \t")
	switch {
	case strings.HasPrefix(trimmed, "+="):
		trimmed = trimmed[2:]
	case strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, "=="):
		trimmed = trimmed[1:]
	case strings.HasPrefix(trimmed, ".set("):
		trimmed = trimmed[4:]
	case strings.HasPrefix(trimmed, "("):
	case len(trimmed) < len(rest) && (strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, "'")):
	default:
		f.s.unreadable() // a read, or a mutation of the property
		return
	}
	lits, ok := literalListExpr(trimmed)
	if !ok {
		f.s.unreadable()
		return
	}
	for _, lit := range lits {
		if strings.Contains(lit, "$") {
			if prop, ok := strings.CutPrefix(lit, "-D"); !ok || strings.ContainsAny(strings.SplitN(prop, "=", 2)[0], "$") {
				f.s.unreadable()
				continue
			}
		}
		f.s.options([]string{lit})
	}
}

var (
	stringLiteral = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`)
	listWrapper   = regexp.MustCompile(`\b(listOf|mutableListOf|arrayListOf|setOf|arrayOf)\b|[()\[\],\s]`)
)

// literalListExpr reads a value made only of string literals: string literals and list
// expressions of them, joined by + or ,, followed by nothing but the end of the statement.
func literalListExpr(text string) ([]string, bool) {
	var lits []string
	for {
		text = strings.TrimLeft(text, " \t")
		var item string
		if strings.HasPrefix(text, `"`) || strings.HasPrefix(text, "'") {
			loc := stringLiteral.FindStringIndex(text)
			if loc == nil || loc[0] != 0 {
				return nil, false
			}
			item = text[:loc[1]]
		} else {
			expr, ok := bracketedExpr(text)
			if !ok {
				return nil, false
			}
			item = expr
		}
		if strings.TrimSpace(listWrapper.ReplaceAllString(stringLiteral.ReplaceAllString(item, ""), "")) != "" {
			return nil, false
		}
		for _, m := range stringLiteral.FindAllStringSubmatch(item, -1) {
			lits = append(lits, m[1]+m[2])
		}
		text = strings.TrimLeft(text[len(item):], " \t")
		if strings.HasPrefix(text, "+") || strings.HasPrefix(text, ",") {
			text = text[1:]
			continue
		}
		end, _, _ := strings.Cut(text, "\n")
		end = strings.TrimSpace(end)
		for _, p := range []string{"", "}", ")", ";", "//", "/*"} {
			if p == "" && end == "" || p != "" && strings.HasPrefix(end, p) {
				return lits, true
			}
		}
		return nil, false
	}
}

// bracketedExpr returns the leading list expression of text: an optional wrapper call name,
// then a balanced (...) or [...] group. ok is false when text does not start that way.
func bracketedExpr(text string) (string, bool) {
	trimmed := strings.TrimLeft(text, " \t")
	i := 0
	for i < len(trimmed) && (trimmed[i] == '_' || trimmed[i] >= 'a' && trimmed[i] <= 'z' || trimmed[i] >= 'A' && trimmed[i] <= 'Z') {
		i++
	}
	if i >= len(trimmed) || trimmed[i] != '(' && trimmed[i] != '[' {
		return "", false
	}
	depth := 0
	var quote byte
	for j := i; j < len(trimmed); j++ {
		c := trimmed[j]
		switch {
		case quote != 0:
			if c == '\\' {
				j++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[':
			depth++
		case c == ')' || c == ']':
			depth--
			if depth == 0 {
				return trimmed[:j+1], true
			}
		}
	}
	return "", false
}

// javaContext finds the options that are launch options only after a java command word: -p
// (the module path) and @argfile. A k8s command/args split is joined by the YAML reader.
func (f *launchFile) javaContext() {
	for _, ll := range f.logicalLines() {
		seg := f.data[ll[0]:ll[1]]
		if isLaunchCommentLine(string(seg)) || !bytes.Contains(seg, []byte("java")) {
			continue
		}
		java := false
		for _, loc := range launchWords.FindAllIndex(seg, -1) {
			w := string(seg[loc[0]:loc[1]])
			switch {
			case strings.ContainsAny(w[:1], ";|&"):
				java = false
			case isJavaCommand(w):
				java = true
			case java && javaContextOption(w) && !f.inSpan(ll[0]+loc[0], spanDev):
				f.s.unreadable()
			}
		}
	}
}

func javaContextOption(w string) bool { return w == "-p" || len(w) > 1 && w[0] == '@' }

// yaml reads a YAML or JSON file: a mapping entry NAME: scalar, a {name: NAME, value: scalar}
// entry, and a container's command/args, whose concatenation is one command line. A name the
// reader attaches to a scalar is classified here and its line recorded; a name it cannot
// attach (valueFrom, a block it cannot parse) is left to withhold Searched.
func (f *launchFile) yaml() {
	dec := yaml.NewDecoder(bytes.NewReader(f.data))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return
		}
		f.yamlNode(&doc)
	}
}

func (f *launchFile) yamlNode(n *yaml.Node) {
	if n.Kind != yaml.MappingNode {
		for _, c := range n.Content {
			f.yamlNode(c)
		}
		return
	}
	var nameNode, value *yaml.Node
	var command, args []string
	hasCommand := false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch {
		case k.Value == "name" && v.Kind == yaml.ScalarNode && isJVMOptionVar(v.Value):
			nameNode = v
		case k.Value == "value":
			value = v
		case isJVMOptionVar(k.Value) && v.Kind == yaml.ScalarNode:
			f.s.optionString(v.Value)
			f.yamlLines[k.Line] = true
		case k.Value == "command" || k.Value == "entrypoint":
			hasCommand = k.Value == "command" || hasCommand
			command = append(command, yamlWords(v)...)
		case k.Value == "args":
			args = yamlWords(v)
		}
		f.yamlNode(v)
	}
	if nameNode != nil && value != nil && value.Kind == yaml.ScalarNode {
		f.s.optionString(value.Value)
		f.yamlLines[nameNode.Line] = true
	}
	java := false
	for _, w := range append(command, args...) {
		if isJavaCommand(w) {
			java = true
		} else if java && javaContextOption(w) {
			f.s.unreadable()
		}
	}
	if !hasCommand && len(command) == 0 {
		for _, w := range args {
			if javaContextOption(w) && w != "-p" {
				f.s.unreadable() // the image's entrypoint may be java
			}
		}
	}
}

// yamlWords returns a command's words: a list's scalars, or a scalar's fields.
func yamlWords(n *yaml.Node) []string {
	switch n.Kind {
	case yaml.ScalarNode:
		return strings.Fields(n.Value)
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				out = append(out, strings.Fields(c.Value)...)
			}
		}
		return out
	}
	return nil
}
