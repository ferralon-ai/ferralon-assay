package javaanalysis

// inventory_maven_profile.go — Maven profile activation, evaluated three-valued: a profile is
// active, inactive, or undecided. Only facts the build actually fixes are used.
//
// Every reader here is an allow-list: what it doesn't fully decide leaves the profile undecided.
//
// Explicit selection comes first, as in Maven's DefaultProfileSelector: a profile the invocation
// deactivates is off, one it activates is on. The invocation's selection (its -P list together with
// settings.xml <activeProfiles>) is a run condition the caller states (TargetEnv "maven.profiles");
// Assay never infers it. Until it is stated, every profile of the reactor's POMs and their parents
// is undecided, since -P or settings.xml can switch any of them on or off. A profile .mvn/maven.config
// selects or deselects is undecided too, and every one is when .mvn holds anything off the
// readers' allow-lists (see withMavenConfig). Dependency POMs and imported BOMs never see -P, so
// explicit selection doesn't apply to them.
//
// Otherwise a profile's conditions are ANDed. Maven counts a condition when its element is present,
// empty or not, so each present element is one:
//   - <jdk> against the java.version of the JVM running Maven (what `mvn -v` reports), as the
//     caller provides it (TargetEnv "java.version"); not the compile target or a toolchains JDK.
//     Without it, or when .mvn defines java.version, every <jdk> condition is undecided;
//   - <property> against the values the caller states in TargetEnv; a property it doesn't state,
//     or one .mvn defines, is undecided, never assumed absent, since a -D on the command line or a
//     settings.xml profile can set it;
//   - <file>, <os>, an empty <jdk>, and any activation element or <property> child this reader
//     does not know are always undecided: a file test is decided by the tree Maven saw when it
//     started, which the build or earlier CI steps may have changed since;
//   - a second <activation>, a repeated condition, a <property> without exactly one non-empty name,
//     or a value holding an interpolation expression leaves the whole profile undecided.
//
// An undecided profile is never applied, and a dependency it could re-version, direct or
// transitive, is left with an unresolved version rather than the one it has without the profile.
// It costs a profile_activation reason unless every element in it is on profileElements' inert
// list for its POM, or is modelled and provably changes nothing: no property, and no consequential
// declaration (see consequential), which in a reactor POM is any dependency or managed version at
// all, and in a dependency POM one the resolver keeps or management for a coordinate the POM
// declares. The reason is scoped to the dependencies the profile can add or re-version plus their
// closure, and to first-party code and its closure, since code nobody loaded can call back into
// the build. That scope is unbounded whenever any of it cannot be read from the cache, the profile
// sets a property, holds an element off the list, or has a build section, an outside module or a
// repository. It is mirrored run-wide.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// targetEnvJavaVersion is the TargetEnv key carrying the java.version of the JVM that runs the
// subject's Maven build, named after the system property Maven's <jdk> activation reads.
const targetEnvJavaVersion = "java.version"

// targetEnvMavenProfiles is the TargetEnv key carrying the subject build's explicit profile
// selection, in -P syntax ("a,!b"): its -P list and settings.xml <activeProfiles> together. A lone
// "," states that nothing is selected; an absent or blank value is no statement at all.
const targetEnvMavenProfiles = "maven.profiles"

// The .mvn facts resolveMaven reads from the checkout ride to profile evaluation on a copy of
// TargetEnv under these keys. They start with a NUL, which no property name in a POM can contain,
// so a <property> activation never reads them.
const (
	mavenConfigProfiles = "\x00.mvn/maven.config profiles" // comma-joined ids it selects or deselects
	mavenConfigUnknown  = "\x00.mvn unknown"               // set when .mvn holds anything this reader doesn't decide
	mavenConfigDefine   = "\x00.mvn define "               // prefix of each property name maven.config or jvm.config sets
)

// configDefines reports whether .mvn/maven.config or .mvn/jvm.config sets the property name.
func configDefines(targetEnv map[string]string, name string) bool {
	_, ok := targetEnv[mavenConfigDefine+name]
	return ok
}

type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func triAnd(a, b tri) tri {
	switch {
	case a == triFalse || b == triFalse:
		return triFalse
	case a == triUnknown || b == triUnknown:
		return triUnknown
	}
	return triTrue
}

func triOr(a, b tri) tri {
	switch {
	case a == triTrue || b == triTrue:
		return triTrue
	case a == triUnknown || b == triUnknown:
		return triUnknown
	}
	return triFalse
}

func triNot(a tri) tri {
	switch a {
	case triTrue:
		return triFalse
	case triFalse:
		return triTrue
	}
	return triUnknown
}

func triOf(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

// activationEnv is what profile activation is evaluated against.
type activationEnv struct {
	targetEnv map[string]string
	// selection is the invocation's explicit profile selection, nil for a POM that never sees it
	// (a dependency's POM, an imported BOM, and their parents).
	selection *profileSelection
}

// profileSelection is what the build invocation is known to select and deselect.
type profileSelection struct {
	stated           bool            // the caller stated the -P list and settings activeProfiles
	active, inactive map[string]bool // that statement
	config           map[string]bool // ids .mvn/maven.config selects or deselects
	configUnknown    bool            // .mvn/maven.config has a selection that can't be read in full
}

type explicitState int8

const (
	explicitNone explicitState = iota // not selected either way: conditions decide
	explicitOn
	explicitOff
	explicitUnknown
)

func (s *profileSelection) explicit(id string) explicitState {
	if s == nil {
		return explicitNone
	}
	if id == "" {
		id = "default" // Maven's id for a profile that declares none
	}
	switch {
	case !s.stated || s.configUnknown || s.config[id]:
		return explicitUnknown
	case s.inactive[id]:
		return explicitOff // deactivation wins, as in DefaultProfileSelector
	case s.active[id]:
		return explicitOn
	}
	return explicitNone
}

// selectionOf reads the explicit selection a reactor POM's profiles are evaluated under.
func selectionOf(targetEnv map[string]string) *profileSelection {
	s := &profileSelection{active: map[string]bool{}, inactive: map[string]bool{}, config: map[string]bool{}}
	if v := strings.TrimSpace(targetEnv[targetEnvMavenProfiles]); v != "" {
		s.stated = true
		for _, tok := range strings.Split(v, ",") {
			if id, off, ok := profileToken(tok); ok && off {
				s.inactive[id] = true
			} else if ok {
				s.active[id] = true
			}
		}
	}
	for _, id := range strings.Split(targetEnv[mavenConfigProfiles], ",") {
		if id != "" {
			s.config[id] = true
		}
	}
	_, s.configUnknown = targetEnv[mavenConfigUnknown]
	return s
}

// profileToken parses one element of a -P list: "id" or "+id" selects, "!id" or "-id" deselects,
// and Maven 4's "?" (optional) prefix is dropped.
func profileToken(tok string) (id string, off, ok bool) {
	tok = javaTrim(tok)
	tok = strings.TrimPrefix(tok, "?")
	switch {
	case strings.HasPrefix(tok, "!"), strings.HasPrefix(tok, "-"):
		off, tok = true, tok[1:]
	case strings.HasPrefix(tok, "+"):
		tok = tok[1:]
	}
	tok = strings.TrimPrefix(tok, "?")
	return tok, off, tok != ""
}

// withMavenConfig returns targetEnv plus what the build's .mvn directory says. Maven reads
// .mvn/maven.config and .mvn/jvm.config from the first .mvn directory at or above the directory
// it starts in. Each is read against an allow-list: a profile selection (-P), a property
// definition (-D), and options known to change neither which profiles are active nor what the
// dependency graph is. Anything else, a file that can't be read, or a .mvn/extensions.xml makes
// the reader's result unknown: every reactor profile is undecided, and so is every <jdk> and
// <property> condition anywhere. A property it defines leaves every condition on that property
// undecided, and a defined java.version every <jdk> condition. A .mvn nested between buildDir and
// a reactor POM counts too (nestedMvn): a build started there reads it instead.
func withMavenConfig(targetEnv map[string]string, buildDir string, pomPaths []string) map[string]string {
	f := readMvnDir(buildDir)
	nested := nestedMvn(buildDir, pomPaths)
	f.defines = append(f.defines, nested.defines...)
	f.unknown = f.unknown || nested.unknown
	if len(f.ids) == 0 && len(f.defines) == 0 && !f.unknown {
		return targetEnv
	}
	out := make(map[string]string, len(targetEnv)+len(f.defines)+2)
	for k, v := range targetEnv {
		out[k] = v
	}
	if len(f.ids) > 0 {
		out[mavenConfigProfiles] = strings.Join(f.ids, ",")
	}
	for _, k := range f.defines {
		out[mavenConfigDefine+k] = "true"
	}
	if f.unknown {
		out[mavenConfigUnknown] = "true"
	}
	return out
}

// mvnFacts is what a .mvn directory's files say about profile activation.
type mvnFacts struct {
	ids     []string // profiles maven.config selects or deselects
	defines []string // properties maven.config or jvm.config sets
	unknown bool     // something there this reader doesn't decide
}

// nestedMvn reads each .mvn directory below buildDir in a directory that holds a reactor POM or
// lies between one and buildDir. A maven.config or extensions.xml there, or one that can't be
// ruled absent, is unknown; a jvm.config there is read like the top one's.
func nestedMvn(buildDir string, pomPaths []string) mvnFacts {
	var f mvnFacts
	root := filepath.Clean(buildDir)
	seen := map[string]bool{}
	for _, p := range pomPaths {
		for dir := filepath.Dir(filepath.Clean(p)); dir != root && !seen[dir]; dir = filepath.Dir(dir) {
			seen[dir] = true
			if rel, err := filepath.Rel(root, dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				f.unknown = true // not below buildDir: what governs it isn't known
				return f
			}
			mvn := filepath.Join(dir, ".mvn")
			if !ruledAbsent(filepath.Join(mvn, "maven.config")) || !ruledAbsent(filepath.Join(mvn, "extensions.xml")) {
				f.unknown = true
				return f
			}
			defines, unknown := readJVMConfig(filepath.Join(mvn, "jvm.config"))
			f.defines = append(f.defines, defines...)
			f.unknown = f.unknown || unknown
		}
	}
	return f
}

// ruledAbsent reports whether path provably doesn't exist.
func ruledAbsent(path string) bool {
	_, err := os.Lstat(path)
	return err != nil && (os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR))
}

func readMvnDir(buildDir string) mvnFacts {
	dir, err := filepath.Abs(buildDir)
	if err != nil {
		return mvnFacts{unknown: true}
	}
	for {
		if fi, err := os.Stat(filepath.Join(dir, ".mvn")); err == nil && fi.IsDir() {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return mvnFacts{}
		}
		dir = parent
	}
	mvn := filepath.Join(dir, ".mvn")
	f := readMavenConfig(filepath.Join(mvn, "maven.config"))
	defines, unknown := readJVMConfig(filepath.Join(mvn, "jvm.config"))
	f.defines = append(f.defines, defines...)
	f.unknown = f.unknown || unknown
	// Seam: #138 adds mavenCoreExtensions, which also reads maven.ext.class.path; fold this
	// check into it once that lands on main.
	if !ruledAbsent(filepath.Join(mvn, "extensions.xml")) {
		f.unknown = true // a core extension can rewrite the model, activation included
	}
	return f
}

// readMavenConfig reads .mvn/maven.config. Maven 3.9 takes each line as one argument and skips
// blank and # lines; Maven 3.8 and earlier split the file on whitespace. A line is read only when
// both agree on it: a comment without an option on it, a profile selection in the shapes
// profileLine models, or one option from configLine's allow-list.
func readMavenConfig(path string) mvnFacts {
	var f mvnFacts
	data, err := readMavenConfigFile(path)
	if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
		return f
	}
	if err != nil {
		f.unknown = true
		return f
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.ContainsRune(line, '\ufeff') {
			f.unknown = true // a byte-order mark hides what the line's first token is
			continue
		}
		toks := strings.Fields(line)
		if len(toks) == 0 {
			continue
		}
		if strings.HasPrefix(toks[0], "#") {
			if hasOption(toks) {
				f.unknown = true // Maven 3.8 reads the options on a comment line
			}
			continue
		}
		if list, selects, ok := profileLine(toks); selects {
			if !ok {
				f.unknown = true
				continue
			}
			f.ids = append(f.ids, list...)
			continue
		}
		key, ok := configLine(toks)
		switch {
		case !ok:
			f.unknown = true
		case key != "":
			f.defines = append(f.defines, key)
		}
	}
	return f
}

func hasOption(toks []string) bool {
	for _, t := range toks {
		if strings.HasPrefix(strings.TrimLeft(t, `"'`), "-") {
			return true
		}
	}
	return false
}

// inertFlags are the maven.config options, exactly as written, that take no value and change
// neither profile activation nor the dependency graph. Abbreviated long options are not on it:
// which option an abbreviation means depends on the Maven version's option set.
var inertFlags = map[string]bool{
	"-B": true, "--batch-mode": true,
	"-q": true, "--quiet": true,
	"-X": true, "--debug": true,
	"-e": true, "--errors": true,
	"-o": true, "--offline": true,
	"-U": true, "--update-snapshots": true,
	"-nsu": true, "--no-snapshot-updates": true,
	"-N": true, "--non-recursive": true,
	"-C": true, "--strict-checksums": true,
	"-c": true, "--lax-checksums": true,
	"-fae": true, "--fail-at-end": true,
	"-ff": true, "--fail-fast": true,
	"-fn": true, "--fail-never": true,
	"-V": true, "--show-version": true,
	"-v": true, "--version": true,
	"-ntp": true, "--no-transfer-progress": true,
	"-am": true, "--also-make": true,
	"-amd": true, "--also-make-dependents": true,
	"-h": true, "--help": true,
}

// inertValueOptions are the maven.config options that take a value and change neither profile
// activation nor the dependency graph: thread count, builder, log file, toolchains, and which
// reactor modules run. attached is whether a short form may carry its value attached ("-T4"):
// it may only when no other Maven option's name starts with this one's, so Maven's longest-prefix
// match can't pick another option (-l is excluded for -llr).
var inertValueOptions = []struct {
	short, long string
	attached    bool
}{
	{"-T", "--threads", true},
	{"-b", "--builder", true},
	{"-l", "--log-file", false},
	{"-t", "--toolchains", true},
	{"-gt", "--global-toolchains", true},
	{"-rf", "--resume-from", true},
	{"-pl", "--projects", true},
}

// configLine reads one maven.config line that selects no profile. ok is true only for a line
// holding one option from the allow-list: an inert flag, an inert option with its value attached,
// after "=", or as the line's only other token, or a property definition (-Dk=v, -Dk, -D k=v,
// --define=k=v, --define k=v) whose name is literal; key is that name. Anything else, settings
// (-s, -gs) and an alternate POM (-f) among it, is not ok.
func configLine(toks []string) (key string, ok bool) {
	t := toks[0]
	if key, isDefine := defineOption(toks); isDefine {
		return key, key != ""
	}
	if inertFlags[t] {
		return "", len(toks) == 1
	}
	for _, o := range inertValueOptions {
		switch {
		case t == o.short || t == o.long:
			return "", len(toks) == 2
		case strings.HasPrefix(t, o.short+"=") || strings.HasPrefix(t, o.long+"="):
			return "", len(toks) == 1
		case o.attached && strings.HasPrefix(t, o.short) && len(t) > len(o.short):
			return "", len(toks) == 1
		}
	}
	return "", false
}

// defineOption reads a property definition. isDefine is set for any -D or --define line; key is
// empty unless the line is one of the modelled shapes with a literal property name, and never set
// for maven.ext.class.path, which loads a core extension.
func defineOption(toks []string) (key string, isDefine bool) {
	t := toks[0]
	var v string
	switch {
	case t == "-D" || t == "--define":
		if len(toks) != 2 {
			return "", true
		}
		v = toks[1]
	case strings.HasPrefix(t, "--define="):
		v = strings.TrimPrefix(t, "--define=")
	case strings.HasPrefix(t, "-D"):
		v = t[2:]
	default:
		return "", false
	}
	if len(toks) != 1 && t != "-D" && t != "--define" {
		return "", true
	}
	return propertyKey(v), true
}

// propertyKey returns the name a k=v or k definition sets, or "" when it isn't a literal name.
func propertyKey(v string) string {
	k, _, _ := strings.Cut(v, "=")
	k = javaTrim(k)
	if k == "" || strings.ContainsAny(k, "\"'${}\\ \t") || k == "maven.ext.class.path" {
		return ""
	}
	return k
}

// readJVMConfig reads .mvn/jvm.config, which the mvn script splits on whitespace and passes to
// the JVM that runs Maven. Each token must be a -D property definition with a literal name, or a
// JVM option from inertJVMOption's allow-list; a # anywhere but at the start of a line is unknown,
// since Maven versions differ on whether the rest of the line is dropped. A file that can't be
// read is unknown.
func readJVMConfig(path string) (defines []string, unknown bool) {
	data, err := readMavenConfigFile(path)
	if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
		return nil, false
	}
	if err != nil {
		return nil, true
	}
	for _, line := range strings.Split(string(data), "\n") {
		toks := strings.Fields(line)
		if len(toks) == 0 {
			continue
		}
		if strings.ContainsRune(line, '\ufeff') {
			unknown = true
			continue
		}
		if strings.HasPrefix(toks[0], "#") {
			unknown = unknown || hasOption(toks)
			continue
		}
		if strings.Contains(line, "#") {
			unknown = true
			continue
		}
		for i := 0; i < len(toks); i++ {
			t := toks[i]
			switch {
			case strings.HasPrefix(t, "-D"):
				if k := propertyKey(t[2:]); k != "" {
					defines = append(defines, k)
				} else {
					unknown = true
				}
			case inertJVMOption(t):
			case jvmModuleOptions[t] && i+1 < len(toks):
				i++
			default:
				unknown = true
			}
		}
	}
	return defines, unknown
}

// jvmModuleOptions take the next token as their value.
var jvmModuleOptions = map[string]bool{"--add-opens": true, "--add-exports": true, "--add-reads": true, "--add-modules": true}

// inertJVMOption reports whether a jvm.config token is a JVM option that sets memory, stack, a
// listed -XX: flag, module access, or assertions: nothing that loads code into Maven or sets a
// property.
func inertJVMOption(t string) bool {
	switch t {
	case "-ea", "-da", "-enableassertions", "-disableassertions", "-server", "-client":
		return true
	}
	for _, p := range []string{"-Xmx", "-Xms", "-Xss", "--add-opens=", "--add-exports=", "--add-reads=", "--add-modules="} {
		if strings.HasPrefix(t, p) && len(t) > len(p) {
			return true
		}
	}
	if flag, ok := strings.CutPrefix(t, "-XX:"); ok {
		return inertXXFlag(flag)
	}
	return false
}

// inertXXBool and inertXXValue are the -XX: flags jvm.config may carry: garbage collector choice,
// heap, metaspace and code-cache sizing, and JIT tiering. Each only tunes the JVM; none reads a
// file or takes a class or agent. Any other -XX: flag is unknown, VMOptionsFile and Flags among
// them, since both read further JVM options (a -D included) from a file.
var (
	inertXXBool = map[string]bool{
		"UseG1GC": true, "UseParallelGC": true, "UseSerialGC": true, "UseZGC": true,
		"TieredCompilation": true, "UseStringDeduplication": true, "UseCompressedOops": true,
	}
	inertXXValue = map[string]bool{
		"MaxMetaspaceSize": true, "MetaspaceSize": true, "ReservedCodeCacheSize": true,
		"MaxRAMPercentage": true, "InitialRAMPercentage": true, "MinRAMPercentage": true,
		"TieredStopAtLevel": true, "ParallelGCThreads": true, "ConcGCThreads": true,
	}
)

// inertXXFlag reads what follows -XX: as "+Name", "-Name" for a listed boolean flag or
// "Name=value" for a listed valued flag, the value being a plain size, count or percentage.
func inertXXFlag(f string) bool {
	if name, ok := strings.CutPrefix(f, "+"); ok {
		return inertXXBool[name]
	}
	if name, ok := strings.CutPrefix(f, "-"); ok {
		return inertXXBool[name]
	}
	name, value, ok := strings.Cut(f, "=")
	if !ok || !inertXXValue[name] || value == "" {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r == '.' || strings.ContainsRune("kKmMgGtT", r)) {
			return false
		}
	}
	return true
}

// profileLine reads one maven.config line. selects is false when no token on it is, or could be,
// a profile selection. Maven takes the whole line as one argument, so a line that selects is read
// only in the shapes modelled here: the option first, its value attached or in the next token,
// and a list written with spaces after its commas ("-P a, b") continuing on the line. Any token
// left over, a second option, or an option that isn't first leaves ok false: the line selects
// profiles this reader can't name.
func profileLine(toks []string) (ids []string, selects, ok bool) {
	for _, tok := range toks {
		if _, kind := profileOption(tok); kind != optionNone {
			selects = true
			break
		}
	}
	if !selects {
		return nil, false, false
	}
	v, kind := profileOption(toks[0])
	i := 0
	switch kind {
	case optionValue:
	case optionNeedsValue:
		if len(toks) < 2 {
			return nil, true, false
		}
		i, v = 1, toks[1]
	default:
		return nil, true, false
	}
	for strings.HasSuffix(v, ",") && i+1 < len(toks) && !strings.HasPrefix(toks[i+1], "-") {
		i++
		v += toks[i]
	}
	if i+1 < len(toks) {
		return nil, true, false
	}
	ids, ok = profileList(v)
	return ids, true, ok
}

type optionKind int

const (
	optionNone       optionKind = iota // not a profile selection
	optionValue                        // a selection with its value attached
	optionNeedsValue                   // a selection whose value is the next token
	optionUnknown                      // a selection, or possibly one, this reader doesn't parse
)

// profileOption classifies one maven.config token: -P, -P=, --activate-profiles and
// --activate-profiles=, with the value attached or in the next token. A short-option cluster
// holding P, an abbreviation of --activate-profiles, or a quoted selection is unknown.
func profileOption(tok string) (string, optionKind) {
	if strings.HasPrefix(tok, `"`) || strings.HasPrefix(tok, "'") {
		if _, kind := profileOption(strings.Trim(tok, `"'`)); kind != optionNone {
			return "", optionUnknown // a quoted selection: how Maven unquotes it isn't modelled
		}
		return "", optionNone
	}
	switch {
	case tok == "-P" || tok == "--activate-profiles":
		return "", optionNeedsValue
	case strings.HasPrefix(tok, "--activate-profiles="):
		return strings.TrimPrefix(tok, "--activate-profiles="), optionValue
	case strings.HasPrefix(tok, "-P="):
		return strings.TrimPrefix(tok, "-P="), optionValue
	case strings.HasPrefix(tok, "-P"):
		return tok[2:], optionValue
	case strings.HasPrefix(tok, "--"):
		name, _, _ := strings.Cut(tok, "=")
		if len(name) > 2 && strings.HasPrefix("--activate-profiles", name) {
			return "", optionUnknown
		}
		return "", optionNone
	case strings.HasPrefix(tok, "-D"):
		return "", optionNone
	case strings.HasPrefix(tok, "-") && strings.Contains(tok, "P"):
		return "", optionUnknown
	}
	return "", optionNone
}

// profileList splits a -P value into the profile ids it selects or deselects. A value that is empty, has an empty element, or holds anything outside a
// plain id (quotes, interpolation, =, a backslash) is not parsed.
func profileList(v string) ([]string, bool) {
	if v == "" || strings.ContainsAny(v, "\"'$=\\{}") {
		return nil, false
	}
	var ids []string
	for _, tok := range strings.Split(v, ",") {
		id, _, ok := profileToken(tok)
		if !ok {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

// readMavenConfigFile reads path only when it is a regular file. The open doesn't block, so a
// FIFO in the checkout fails the read instead of waiting for a writer.
func readMavenConfigFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return io.ReadAll(f)
}

// evalProfiles returns the activation state of each profile of one POM. Explicit selection
// decides first; otherwise a profile with no activation condition is inactive, and
// activeByDefault applies only when no other profile of the same POM is active.
func evalProfiles(profiles []mvnProfile, env activationEnv) []tri {
	out := make([]tri, len(profiles))
	byDefault := make([]bool, len(profiles))
	anyActive := triFalse
	for i, pr := range profiles {
		switch env.selection.explicit(pr.ID) {
		case explicitOn:
			out[i] = triTrue
		case explicitOff:
			out[i] = triFalse
		case explicitUnknown:
			out[i] = triUnknown
		default:
			out[i] = evalConditions(pr.Activation, env)
			byDefault[i] = out[i] == triFalse && pr.Activation.ActiveByDefault
		}
		anyActive = triOr(anyActive, out[i])
	}
	for i := range profiles {
		if byDefault[i] {
			out[i] = triNot(anyActive)
		}
	}
	return out
}

// evalConditions ANDs every condition present (Maven 3.2.2+). No condition at all is inactive.
func evalConditions(a mvnActivation, env activationEnv) tri {
	present := false
	res := triTrue
	add := func(t tri) {
		present = true
		res = triAnd(res, t)
	}
	if a.Undecidable {
		return triUnknown
	}
	_, configUnknown := env.targetEnv[mavenConfigUnknown]
	if a.JDK != "" {
		if configUnknown || configDefines(env.targetEnv, targetEnvJavaVersion) {
			add(triUnknown) // the build overrides java.version with a value not compared here
		} else {
			add(evalJDK(a.JDK, env.targetEnv[targetEnvJavaVersion]))
		}
	}
	if a.OS || a.File || a.Other {
		add(triUnknown)
	}
	if a.PropName != "" {
		if configUnknown || configDefines(env.targetEnv, strings.TrimPrefix(a.PropName, "!")) {
			add(triUnknown) // the build sets the property itself
		} else {
			add(evalProperty(a.PropName, a.PropValue, env.targetEnv))
		}
	}
	if !present {
		return triFalse
	}
	return res
}

// evalProperty follows Maven's PropertyProfileActivator against caller-stated values: "!name"
// activates when the property is unset, a value activates on equality ("!value" on inequality).
// A property the caller doesn't state is undecided. java.version is compared in the form Maven's
// JVM reports it, and a partial stated version ("17") can't decide equality with a value it
// prefixes.
func evalProperty(name, value string, env map[string]string) tri {
	negName := strings.HasPrefix(name, "!")
	name = strings.TrimPrefix(name, "!")
	if name == "" {
		return triUnknown
	}
	got, present := env[name]
	if !present || name == targetEnvMavenProfiles {
		return triUnknown
	}
	partial := false
	if name == targetEnvJavaVersion {
		var ok bool
		if got, partial, ok = mavenJavaVersion(got); !ok {
			return triUnknown
		}
	}
	if value != "" {
		negValue := strings.HasPrefix(value, "!")
		want := strings.TrimPrefix(value, "!")
		eq := triOf(got == want)
		if partial && (got == want || strings.HasPrefix(want, got+".") || strings.HasPrefix(want, got+"_")) {
			eq = triUnknown
		}
		if negValue {
			return triNot(eq)
		}
		return eq
	}
	set := triOf(got != "")
	if negName {
		return triNot(set)
	}
	return set
}

// mavenJavaVersion turns a stated Java version into the form of the java.version system property:
// JDK 8 and earlier report "1.N.0_U", so "8" is "1.8" and "8.0.382" is "1.8.0_382". Build
// metadata ("+8") is dropped. partial is true when the version has fewer than three components
// and so stands for every version it prefixes; ok is false when it isn't a version.
func mavenJavaVersion(v string) (out string, partial, ok bool) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	toks := numericTokens(v)
	if toks == nil {
		return "", false, false
	}
	partial = len(toks) < 3
	if toks[0] >= 2 && toks[0] <= 8 {
		v = "1." + strconv.Itoa(toks[0])
		if len(toks) > 1 {
			v += "." + strconv.Itoa(toks[1])
		}
		if len(toks) > 2 {
			v += "_" + strconv.Itoa(toks[2])
		}
	}
	return v, partial, true
}

// evalJDK follows Maven's JdkVersionProfileActivator (3.9.11) against the provided java.version,
// within the selector grammar modelled here; any other selector is undecided, never read as
// Maven's verdict:
//   - a prefix ("11", "1.8", "1.8.0_382"): digits, with "." or "_" before each further run;
//   - a negated prefix ("!1.8"), the same with a leading "!";
//   - a two-bound range ("[11,)", "(,1.8]", "[1.8,11)"), each bound empty or one to three
//     dot-separated numbers, compared on the first three numeric components of java.version.
//
// Maven parses a range bound by splitting on "." alone and applies no grammar to the spec, so a
// one-token range ("[17]"), a bound holding "_" ("[1.8.0_382,1.8.0_400)"), a missing bracket or
// a third bound each mean something accidental there, or throw and leave the profile inactive
// with a warning. Those stay undecided here. A provided version with fewer than three components
// ("11") stands for every version it prefixes, so a condition that differs across them is
// undecided; a provided version outside jdkVersion's shape is undecided against everything.
func evalJDK(spec, version string) tri {
	version, partial, ok := mavenJavaVersion(version)
	if !ok || !jdkVersion.MatchString(version) {
		return triUnknown // nothing the conditions can be compared against
	}
	if neg, ok := strings.CutPrefix(spec, "!"); ok {
		if !jdkPrefixSpec.MatchString(neg) {
			return triUnknown
		}
		return triNot(jdkPrefix(neg, version, partial))
	}
	if m := jdkRangeSpec.FindStringSubmatch(spec); m != nil {
		return jdkRange(m, version, partial)
	}
	if jdkPrefixSpec.MatchString(spec) {
		return jdkPrefix(spec, version, partial)
	}
	return triUnknown
}

var (
	jdkPrefixSpec = regexp.MustCompile(`^[0-9]+(?:[._][0-9]+)*$`)
	jdkRangeSpec  = regexp.MustCompile(`^([\[(])\s*([0-9]{1,9}(?:\.[0-9]{1,9}){0,2})?\s*,\s*([0-9]{1,9}(?:\.[0-9]{1,9}){0,2})?\s*([\])])$`)
	// jdkVersion is the shape of a java.version every range compares without Maven failing to parse it.
	jdkVersion = regexp.MustCompile(`^[0-9]{1,9}(?:\.[0-9]{1,9})*(?:_[0-9]{1,9})?$`)
)

func jdkPrefix(spec, version string, partial bool) tri {
	switch {
	case strings.HasPrefix(version, spec):
		return triTrue
	case partial && strings.HasPrefix(spec, version):
		return triUnknown
	}
	return triFalse
}

type jdkBound struct {
	value  []int // nil = unbounded
	closed bool
}

// jdkRange evaluates a range jdkRangeSpec matched: m[1] and m[4] are its brackets, m[2] and m[3]
// its bounds.
func jdkRange(m []string, version string, partial bool) tri {
	bound := func(v, bracket string) jdkBound {
		b := jdkBound{closed: bracket == "[" || bracket == "]"}
		if v != "" {
			b.value = pad3(numericTokens(v), 0)
		}
		return b
	}
	lower, upper := bound(m[2], m[1]), bound(m[3], m[4])
	toks := numericTokens(version)
	lo := inJDKRange(pad3(toks, 0), lower, upper)
	if !partial {
		return triOf(lo)
	}
	if hi := inJDKRange(pad3(toks, 1<<30), lower, upper); hi != lo {
		return triUnknown
	}
	return triOf(lo)
}

func inJDKRange(v []int, lower, upper jdkBound) bool {
	left := jdkRelation(v, lower, true)
	if left == 0 {
		return true
	}
	if left < 0 {
		return false
	}
	return jdkRelation(v, upper, false) <= 0
}

func jdkRelation(v []int, b jdkBound, isLeft bool) int {
	if b.value == nil {
		if isLeft {
			return 1
		}
		return -1
	}
	for i := 0; i < 3; i++ {
		if v[i] < b.value[i] {
			return -1
		}
		if v[i] > b.value[i] {
			return 1
		}
	}
	if !b.closed {
		if isLeft {
			return -1
		}
		return 1
	}
	return 0
}

// numericTokens splits a version on . _ - and returns its leading numeric components; nil when
// the first is not a number.
func numericTokens(v string) []int {
	var out []int
	for _, t := range strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '_' || r == '-' }) {
		n, err := strconv.Atoi(t)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func pad3(t []int, fill int) []int {
	out := make([]int, 3)
	for i := range out {
		if i < len(t) {
			out[i] = t[i]
		} else {
			out[i] = fill
		}
	}
	return out
}

// --- what an undecided profile can change ------------------------------------

// undecidedProfile is a profile whose activation could not be decided and that can change the
// graph. touched lists the dependency declarations it can add or re-version, with every
// version it can resolve to; bounded is false when some of that cannot be pinned down.
type undecidedProfile struct {
	path    string // disclosure: the declaring POM and profile id
	touched []mvnDep
	bounded bool
	// anyVersion: what the profile re-versions is unknown, so any version in its reach may change.
	anyVersion bool
}

// declEntry is one dependency or managed-version declaration of a POM chain. owner is the
// index of the profile declaring it in profileList order, -1 for a POM body.
type declEntry struct {
	dep   mvnDep
	mgmt  bool
	owner int
}

// profileScope is what profileTouches reads about the POM chain being modelled.
type profileScope struct {
	entries []declEntry
	// defs maps each property name to every raw value any POM body or profile of the chain
	// gives it, for following references transitively.
	defs map[string][]string
	// forDependency is true for a POM read from the cache.
	forDependency bool
}

func newProfileScope(chain []*mvnPOM, profileList []mvnProfile, forDependency bool) profileScope {
	ps := profileScope{defs: map[string][]string{}, forDependency: forDependency}
	idx := 0
	for _, anc := range chain {
		for _, d := range anc.Deps {
			ps.entries = append(ps.entries, declEntry{dep: d, owner: -1})
		}
		for _, d := range anc.DepMgmt {
			ps.entries = append(ps.entries, declEntry{dep: d, mgmt: true, owner: -1})
		}
		for k, v := range anc.Properties {
			ps.defs[k] = append(ps.defs[k], v)
		}
		for range anc.Profiles {
			pr := profileList[idx]
			for _, d := range pr.Deps {
				ps.entries = append(ps.entries, declEntry{dep: d, owner: idx})
			}
			for _, d := range pr.DepMgmt {
				ps.entries = append(ps.entries, declEntry{dep: d, mgmt: true, owner: idx})
			}
			for k, v := range pr.Properties {
				ps.defs[k] = append(ps.defs[k], v)
			}
			idx++
		}
	}
	return ps
}

// isImportBOM matches DefaultModelBuilder's exact test: type "pom" and scope "import".
func isImportBOM(d mvnDep) bool {
	return d.Scope == "import" && defaultType(d.Type) == "pom"
}

// propagatesToConsumer reports whether a dependency declared in a cached POM lands on a
// consumer's graph. An unresolved scope or optional flag counts as propagating.
func propagatesToConsumer(d mvnDep) bool {
	if strings.EqualFold(d.Optional, "true") {
		return false
	}
	switch defaultScope(d.Scope) {
	case "test", "provided", "system", "import":
		return false
	}
	return true
}

// elementRule is what one child element of an undecided profile costs.
type elementRule int8

const (
	elementUnlisted elementRule = iota // off the allow-list: what the profile changes can't be bounded
	elementInert                       // changes nothing the build's dependency graph or code reads
	elementModelled                    // read, and costed by profileTouches and profileExtras
)

// profileElements is the allow-list of a profile's child elements, as {reactor lineage,
// dependency POM}. Every child of an undecided profile must be on it. One that isn't (a Maven 4
// addition, a misspelling, or something Maven ignores) leaves the profile unbounded, as does
// <distributionManagement> in a dependency's POM, whose <relocation> moves the artifact the
// consumer resolves. <build> and <modules> in a dependency's POM never run in the consumer's build.
var profileElements = map[string][2]elementRule{
	"id":                     {elementInert, elementInert},
	"activation":             {elementInert, elementInert},
	"reporting":              {elementInert, elementInert},
	"reports":                {elementInert, elementInert},
	"distributionManagement": {elementInert, elementUnlisted},
	"build":                  {elementModelled, elementInert},
	"modules":                {elementModelled, elementInert},
	"dependencies":           {elementModelled, elementModelled},
	"dependencyManagement":   {elementModelled, elementModelled},
	"properties":             {elementModelled, elementModelled},
	"repositories":           {elementModelled, elementModelled},
	"pluginRepositories":     {elementModelled, elementModelled},
}

// profileUnlisted reports whether a profile has a child element off profileElements' allow-list
// for its POM: cached for a dependency's POM, an imported BOM, or their parents.
func profileUnlisted(pr mvnProfile, cached bool) bool {
	col := 0
	if cached {
		col = 1
	}
	for _, name := range pr.Elements {
		rule, ok := profileElements[name]
		if !ok || rule[col] == elementUnlisted {
			return true
		}
	}
	return false
}

// consequential reports which entries can change the resolved graph. In a reactor module's
// lineage every one can. In a dependency's POM every one can unless it is on this allow-list:
//   - a dependency Maven's resolver drops before mediation (droppedBelow) whose literal
//     groupId:artifactId every other entry of the chain declares only that way too: whichever of
//     them Maven merges, the result is still dropped, so it adds a coordinate the consumer never
//     sees rather than re-declaring one it does;
//   - a managed version, not an imported BOM, for a literal groupId:artifactId no dependency of the
//     chain declares: below the consumer, Maven 3's resolver applies only the consumer's own
//     management, so it has nothing to manage.
func (ps profileScope) consequential() []bool {
	out := make([]bool, len(ps.entries))
	declared, kept := map[string]bool{}, map[string]bool{}
	for _, e := range ps.entries {
		if !e.mgmt {
			declared[e.dep.ga()] = true
		}
		if e.mgmt || !droppedBelow(e.dep) {
			kept[e.dep.ga()] = true
		}
	}
	for i, e := range ps.entries {
		literal := e.dep.GroupID != "" && e.dep.ArtifactID != "" && !strings.Contains(e.dep.ga(), "${")
		switch {
		case !ps.forDependency || !literal:
			out[i] = true
		case e.mgmt:
			out[i] = isImportBOM(e.dep) || declared[e.dep.ga()]
		default:
			out[i] = kept[e.dep.ga()]
		}
	}
	return out
}

// droppedBelow reports whether a dependency declared in a dependency's POM is one Maven's
// resolver drops before mediation (OptionalDependencySelector, ScopeDependencySelector): a literal
// optional true, or a literal test or provided scope.
func droppedBelow(d mvnDep) bool {
	return strings.EqualFold(d.Optional, "true") || d.Scope == "test" || d.Scope == "provided"
}

// referencedProps returns every property name raw refers to, following definitions.
func (ps profileScope) referencedProps(raws ...string) map[string]bool {
	seen := map[string]bool{}
	queue := append([]string{}, raws...)
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for {
			start := strings.Index(s, "${")
			if start < 0 {
				break
			}
			end := strings.IndexByte(s[start:], '}')
			if end < 0 {
				break
			}
			name := s[start+2 : start+end]
			s = s[start+end+1:]
			if !seen[name] {
				seen[name] = true
				queue = append(queue, ps.defs[name]...)
			}
		}
	}
	return seen
}

// profileTouches returns what profile idx can change: its own consequential declarations, a
// re-declaration's scope or optional change included (it moves how the graph mediates and scopes
// that dependency), and every consequential declaration whose coordinates reference a property it
// sets. Each is
// resolved under the model without the profile and with it; an imported BOM contributes every
// version it manages. A declaration that resolves to no literal coordinate in either, or a BOM
// that isn't cached or doesn't read in full, leaves the result unbounded.
func profileTouches(ps profileScope, idx int, pr mvnProfile, em *effectiveModel, rawProps map[string]string, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string, depth int) (touched []mvnDep, bounded bool) {
	cons := ps.consequential()
	var picked []declEntry
	for i, e := range ps.entries {
		if !cons[i] {
			continue
		}
		if e.owner == idx {
			picked = append(picked, e)
			continue
		}
		if len(pr.Properties) == 0 {
			continue
		}
		refs := ps.referencedProps(e.dep.GroupID, e.dep.ArtifactID, e.dep.Version, e.dep.Scope, e.dep.Type, e.dep.Optional)
		for k := range pr.Properties {
			if refs[k] {
				picked = append(picked, e)
				break
			}
		}
	}
	if len(picked) == 0 {
		return nil, true
	}

	overlay := make(map[string]string, len(rawProps)+len(pr.Properties))
	for k, v := range rawProps {
		overlay[k] = v
	}
	for k, v := range pr.Properties {
		overlay[k] = v
	}
	interpProps(overlay)
	overlayManaged := map[string]string{}
	for _, m := range pr.DepMgmt {
		if v, ok := interp(m.Version, overlay); ok {
			overlayManaged[m.ga()] = v
		}
	}

	bounded = true
	for _, e := range picked {
		if e.mgmt && isImportBOM(e.dep) {
			managed, ok := profileBOMManaged(e.dep, []map[string]string{em.props, overlay}, reactor, cache, targetEnv, depth)
			if !ok {
				return nil, false
			}
			touched = append(touched, managed...)
			continue
		}
		seen := map[string]bool{}
		for _, props := range []map[string]string{em.props, overlay} {
			g, okG := interp(e.dep.GroupID, props)
			a, okA := interp(e.dep.ArtifactID, props)
			if !okG || !okA {
				continue
			}
			var versions []string
			if v, ok := interp(e.dep.Version, props); ok {
				versions = append(versions, v)
			} else if javaTrim(e.dep.Version) == "" {
				if v, ok := em.managed[g+":"+a]; ok {
					versions = append(versions, v)
				}
				if v, ok := overlayManaged[g+":"+a]; ok {
					versions = append(versions, v)
				}
			}
			for _, v := range versions {
				if !isLiteralVersion(v) {
					continue
				}
				d := e.dep
				d.GroupID, d.ArtifactID, d.Version = g, a, v
				if k := gavKey(g, a, v); !seen[k] {
					seen[k] = true
					touched = append(touched, d)
				}
			}
		}
		if len(seen) == 0 {
			bounded = false
		}
	}
	return touched, bounded
}

// profileBOMManaged reads an imported BOM under each property set and returns every version it
// manages, as managed declarations. ok is false when a BOM coordinate doesn't interpolate to a
// literal, the BOM isn't cached, or reading it leaves anything undecided or unread.
func profileBOMManaged(bom mvnDep, propSets []map[string]string, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string, depth int) ([]mvnDep, bool) {
	if depth > 10 {
		return nil, false
	}
	var out []mvnDep
	seen := map[string]bool{}
	for _, props := range propSets {
		g, okG := interp(bom.GroupID, props)
		a, okA := interp(bom.ArtifactID, props)
		v, okV := interp(bom.Version, props)
		if !okG || !okA || !okV || !isLiteralVersion(v) {
			return nil, false
		}
		pom, ok := cache.get(g, a, v)
		if !ok {
			return nil, false
		}
		if !bomProfilesDecided(pom, reactor, cache, targetEnv, depth) {
			return nil, false
		}
		sub := buildEffectiveModel(pom, reactor, cache, targetEnv, depth+1)
		if len(sub.residue) > 0 || len(sub.undecided) > 0 {
			return nil, false
		}
		for ga, mv := range sub.managed {
			mg, ma, _ := strings.Cut(ga, ":")
			if k := gavKey(mg, ma, mv); !seen[k] && isLiteralVersion(mv) {
				seen[k] = true
				out = append(out, mvnDep{GroupID: mg, ArtifactID: ma, Version: mv, Scope: "import"})
			}
		}
	}
	return out, true
}

// bomProfilesDecided reports whether every profile in a BOM's lineage that could change what it
// manages is decided. A dependency POM's own model counts only the managed versions its
// dependencies use; a BOM's managed versions are all it contributes.
func bomProfilesDecided(bom *mvnPOM, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string, depth int) bool {
	chain := parentChain(bom, reactor, cache, depth+1)
	if chain.parentMissing {
		return false
	}
	env := activationEnv{targetEnv: targetEnv}
	for _, anc := range chain.poms {
		for i, st := range evalProfiles(anc.Profiles, env) {
			pr := anc.Profiles[i]
			if st == triUnknown && (len(pr.DepMgmt) > 0 || len(pr.Properties) > 0 || profileUnlisted(pr, true)) {
				return false
			}
		}
	}
	return true
}

// profileExtras reports whether a profile contributes something besides dependencies, managed
// versions and properties that can still change what the build runs: a repository (artifacts may
// resolve elsewhere), and, for a POM in the reactor's own lineage, a build section (plugins can
// unpack or copy code onto the classpath, or change what first-party code is compiled) or a
// module of self's that is not in the reactor this reader walked. Dependency POMs' build sections
// and modules never run in the consumer's build.
func profileExtras(pr mvnProfile, owner, self *mvnPOM, reactor map[string]*mvnPOM) bool {
	if pr.Repositories {
		return true
	}
	if self.path == "" {
		return false
	}
	if pr.Build {
		return true
	}
	if owner != self || len(pr.Modules) == 0 {
		return false
	}
	inReactor := map[string]bool{}
	for _, rp := range reactor {
		if rp.path != "" {
			inReactor[filepath.Clean(rp.path)] = true
		}
	}
	for _, m := range pr.Modules {
		if strings.Contains(m, "${") {
			return true
		}
		path := filepath.Join(filepath.Dir(self.path), filepath.FromSlash(strings.ReplaceAll(m, "\\", "/")))
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			path = filepath.Join(path, "pom.xml")
		}
		if !inReactor[filepath.Clean(path)] {
			return true
		}
	}
	return false
}

// mavenPackage renders a version-less Maven PURL, the form ScopedReason Package and Targets use.
func mavenPackage(group, artifact string) string {
	return "pkg:maven/" + group + "/" + artifact
}

// closureLimit caps how many POMs one Targets closure reads before it gives up as unbounded.
const closureLimit = 2000

// profileScoped turns a model's undecided profiles into scoped reasons. pkg is the package whose
// dependency list the profiles belong to ("" for a reactor module). rootManaged is the reactor
// module's dependencyManagement, which also pins the versions of transitive dependencies.
func profileScoped(em effectiveModel, pkg string, rootManaged map[string]string, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) []plugin.ScopedReason {
	var out []plugin.ScopedReason
	for _, u := range em.undecided {
		sr := plugin.ScopedReason{Reason: reasonProfileActivation, Package: pkg, Path: u.path}
		if u.bounded {
			if t, ok := cache.closure(reactor, targetEnv, u.touched, rootManaged); ok {
				sr.Targets = t
			}
		}
		out = append(out, sr)
	}
	return out
}

// withFirstPartyBound widens every bounded scoped reason by first-party code. A profile-added
// package is a JAR nobody loaded: it can hold first-party objects and call them through its own
// or platform interfaces, or by reflection, and those calls reach whatever first-party code
// reaches. So each bound gains "" and the closure of the module's own dependencies outside test
// scope, plus whatever the module's undecided profiles could add. When that closure cannot be
// read in full, no bound holds and every Targets becomes nil.
func withFirstPartyBound(scoped []plugin.ScopedReason, em effectiveModel, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) []plugin.ScopedReason {
	var firstParty []string
	computed, ok := false, false
	for i := range scoped {
		if scoped[i].Targets == nil {
			continue
		}
		if !computed {
			firstParty, ok = firstPartyClosure(em, reactor, cache, targetEnv)
			computed = true
		}
		if !ok {
			scoped[i].Targets = nil
			continue
		}
		set := map[string]bool{"": true}
		for _, t := range scoped[i].Targets {
			set[t] = true
		}
		for _, t := range firstParty {
			set[t] = true
		}
		targets := make([]string, 0, len(set))
		for t := range set {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		scoped[i].Targets = targets
	}
	return scoped
}

// firstPartyClosure returns every package the module's code can reach through its dependencies.
// ok is false when that set is not a bound.
func firstPartyClosure(em effectiveModel, reactor map[string]*mvnPOM, cache *mavenCache, targetEnv map[string]string) ([]string, bool) {
	var roots []mvnDep
	for _, d := range em.deps {
		if d.Scope != "test" {
			roots = append(roots, d)
		}
	}
	for _, u := range em.undecided {
		if !u.bounded {
			return nil, false
		}
		roots = append(roots, u.touched...)
	}
	return cache.closure(reactor, targetEnv, roots, em.managed)
}

// closure returns every package reachable from roots over the cached POMs, roots included,
// counting the dependencies undecided profiles can add along the way. ok is false when some
// POM, version or profile on the way cannot be read, so the set is not a bound. managed is the
// reactor module's dependencyManagement: Maven resolves a transitive dependency it names at the
// managed version, so that version's POM is walked as well as the declared one.
func (c *mavenCache) closure(reactor map[string]*mvnPOM, targetEnv map[string]string, roots []mvnDep, managed map[string]string) ([]string, bool) {
	pkgs := map[string]bool{}
	seen := map[string]bool{}
	queue := append([]mvnDep{}, roots...)
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if !isLiteralVersion(d.GroupID) || !isLiteralVersion(d.ArtifactID) || !isLiteralVersion(d.Version) {
			return nil, false
		}
		pkgs[mavenPackage(d.GroupID, d.ArtifactID)] = true
		if mv, ok := managed[d.GroupID+":"+d.ArtifactID]; ok && mv != d.Version {
			md := d
			md.Version = mv
			queue = append(queue, md)
		}
		key := gavKey(d.GroupID, d.ArtifactID, d.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(seen) > closureLimit {
			return nil, false
		}
		pom, ok := c.get(d.GroupID, d.ArtifactID, d.Version)
		if !ok {
			return nil, false
		}
		m := buildEffectiveModel(pom, reactor, c, targetEnv, 1)
		for _, r := range m.residue {
			if r != reasonProfileActivation {
				return nil, false
			}
		}
		for _, u := range m.undecided {
			if !u.bounded {
				return nil, false
			}
			queue = append(queue, u.touched...)
		}
		for _, cd := range m.deps {
			if propagatesToConsumer(cd) {
				queue = append(queue, cd)
			}
		}
	}
	out := make([]string, 0, len(pkgs))
	for p := range pkgs {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, true
}

// dedupScoped drops repeated scoped reasons and sorts the rest.
func dedupScoped(in []plugin.ScopedReason) []plugin.ScopedReason {
	seen := map[string]bool{}
	var out []plugin.ScopedReason
	for _, s := range in {
		k := s.Reason + "\x00" + s.Package + "\x00" + s.Path + "\x00" + strings.Join(s.Targets, ",")
		if s.Targets == nil {
			k += "\x00nil"
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Path < out[j].Path
	})
	return out
}
