package javaanalysis

// launchoptions.go — the JVM launch options a build's checked-in launch surfaces set, for the
// JVM reachability lanes. A launch option can run code no call graph shows before main: an
// agent, a system class loader, a security manager, a logging config class, a provider the
// JDK looks up by property. The lanes model only an allowlist of options known not to load
// or select code; any other option, and any surface that names options in a form this file
// cannot read, withholds Searched. Options set only in the deploy environment (a runtime
// JAVA_OPTS, a container entrypoint script) are not in the checkout and are residue.

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const (
	// PartialReasonLaunchAgent: a launch surface loads a Java agent (-javaagent, -agentlib,
	// -agentpath, a JAR's Launcher-Agent-Class) or extends the boot classpath.
	PartialReasonLaunchAgent = plugin.PartialReasonRelationshipUnexpressed + ":launch_jvm_agent"
	// PartialReasonLaunchOption: a launch surface sets a JVM option outside the modeled
	// allowlist, or names options in a form that cannot be read.
	PartialReasonLaunchOption = plugin.PartialReasonRelationshipUnexpressed + ":launch_jvm_option"
)

// LaunchOptionReasons reads every launch surface under buildDir and returns the reasons its
// options declare, sorted: none when every option found is allowlisted. Surfaces read: Gradle
// start scripts (unix and .bat DEFAULT_JVM_OPTS), applicationDefaultJvmArgs in the root build
// file, Dockerfiles (ENV for the JVM option variables, java ENTRYPOINT/CMD), Procfiles, YAML
// deploy manifests, and the Launcher-Agent-Class of the project's own JARs.
func LaunchOptionReasons(buildDir string) []string {
	s := &launchScan{reasons: map[string]bool{}}
	s.startScripts(buildDir)
	s.gradleBuildFiles(buildDir)
	s.projectJars(buildDir)
	_ = filepath.WalkDir(buildDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != buildDir && launchSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		lower := strings.ToLower(name)
		switch {
		case isDockerfile(lower):
			s.dockerfile(path)
		case name == "Procfile":
			s.procfile(path)
		case strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"):
			s.yamlManifest(path)
		}
		return nil
	})
	out := make([]string, 0, len(s.reasons))
	for r := range s.reasons {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// launchSkipDirs are not launch surfaces: build output (its start scripts and JARs are read
// by path), caches, VCS and CI metadata (CI options configure the build, not the program).
var launchSkipDirs = map[string]bool{
	".git": true, ".github": true, ".gradle": true, ".m2": true, ".idea": true,
	"build": true, "target": true, "node_modules": true, "out": true,
}

func isDockerfile(lower string) bool {
	return lower == "dockerfile" || lower == "containerfile" ||
		strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile")
}

// jvmOptionVars are the environment variables the JVM, the java launcher, or a Gradle start
// script reads options from. A Gradle start script also reads <APP>_OPTS (isJVMOptionVar).
var jvmOptionVars = map[string]bool{
	"JAVA_OPTS": true, "JAVA_TOOL_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "_JAVA_OPTIONS": true,
	"JAVA_OPTIONS": true, "DEFAULT_JVM_OPTS": true,
}

// buildToolVars configure a build tool's own JVM, not the program's.
var buildToolVars = map[string]bool{"GRADLE_OPTS": true, "MAVEN_OPTS": true, "SBT_OPTS": true}

func isJVMOptionVar(name string) bool {
	return jvmOptionVars[name] || strings.HasSuffix(name, "_OPTS") && !buildToolVars[name]
}

type launchScan struct {
	reasons map[string]bool
}

func (s *launchScan) unreadable() { s.reasons[PartialReasonLaunchOption] = true }

// options classifies one option list, token by token.
func (s *launchScan) options(tokens []string) {
	for i := 0; i < len(tokens); i++ {
		switch classifyLaunchOption(tokens[i]) {
		case optionAgent:
			s.reasons[PartialReasonLaunchAgent] = true
		case optionUnmodeled:
			s.reasons[PartialReasonLaunchOption] = true
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

var agentOptionPrefixes = []string{"-javaagent:", "-agentlib:", "-agentpath:", "-Xbootclasspath"}

// inertProperties are system properties that select no code: the JDK reads them as plain
// values. Encoding properties are inert only for a standard charset (inertEncodings).
var inertProperties = map[string]bool{
	"java.awt.headless": true, "java.io.tmpdir": true, "java.net.preferIPv4Stack": true,
	"java.net.preferIPv6Addresses": true, "java.security.egd": true,
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

// valueOptions take the next token as their value. The classpath and JAR they name are the
// launch's code identity, which the lanes read from the start script or the inventory; module
// access options grant reflective access only.
var valueOptions = map[string]bool{
	"-cp": true, "-classpath": true, "--class-path": true, "-jar": true,
	"--add-opens": true, "--add-exports": true, "--add-reads": true,
}

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
		case inertProperties[name], strings.HasPrefix(name, "user.") && len(name) > len("user."):
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

// splitOptionWords splits a shell-quoted option string into words. A word that expands a
// variable cannot be read and is returned as unreadable.
func splitOptionWords(value string) (words []string, unreadable bool) {
	for _, w := range strings.Fields(strings.NewReplacer(`"`, " ", "'", " ", `\`, " ").Replace(value)) {
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

// startScripts reads DEFAULT_JVM_OPTS from every Gradle start script, unix and .bat.
func (s *launchScan) startScripts(buildDir string) {
	for _, pattern := range []string{filepath.Join("build", "scripts", "*"), filepath.Join("build", "install", "*", "bin", "*")} {
		paths, _ := filepath.Glob(filepath.Join(buildDir, pattern))
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
				if v, ok := strings.CutPrefix(line, "DEFAULT_JVM_OPTS="); ok {
					s.optionString(v)
				} else if len(line) > len("set DEFAULT_JVM_OPTS=") && strings.EqualFold(line[:len("set DEFAULT_JVM_OPTS=")], "set DEFAULT_JVM_OPTS=") {
					s.optionString(line[len("set DEFAULT_JVM_OPTS="):])
				}
			}
		}
	}
}

var (
	defaultJvmArgsAssign = regexp.MustCompile(`applicationDefaultJvmArgs\s*(\+?=)?`)
	stringLiteral        = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`)
	listWrapper          = regexp.MustCompile(`\b(listOf|mutableListOf|arrayListOf|setOf|arrayOf)\b|[()\[\],\s]`)
)

// gradleBuildFiles reads applicationDefaultJvmArgs from the root build file: a list of string
// literals, each one option. Any other expression cannot be read.
func (s *launchScan) gradleBuildFiles(buildDir string) {
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		data, err := os.ReadFile(filepath.Join(buildDir, name))
		if err != nil {
			continue
		}
		text := string(data)
		for _, loc := range defaultJvmArgsAssign.FindAllStringSubmatchIndex(text, -1) {
			if loc[2] < 0 {
				s.unreadable() // a read or a method call on the property
				continue
			}
			expr, ok := bracketedExpr(text[loc[1]:])
			if !ok {
				s.unreadable()
				continue
			}
			var opts []string
			for _, m := range stringLiteral.FindAllStringSubmatch(expr, -1) {
				lit := m[1] + m[2]
				if strings.Contains(lit, "$") {
					if prop, ok := strings.CutPrefix(lit, "-D"); !ok || strings.ContainsAny(strings.SplitN(prop, "=", 2)[0], "$") {
						s.unreadable()
						continue
					}
				}
				opts = append(opts, lit)
			}
			if strings.TrimSpace(listWrapper.ReplaceAllString(stringLiteral.ReplaceAllString(expr, ""), "")) != "" {
				s.unreadable()
			}
			for _, o := range opts {
				s.options([]string{o})
			}
		}
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

// projectJars reads the manifest of each JAR the project itself builds: a Launcher-Agent-Class
// starts an agent before main when the JAR is launched with -jar.
func (s *launchScan) projectJars(buildDir string) {
	var jars []string
	for _, pattern := range []string{filepath.Join("build", "libs", "*.jar"), filepath.Join("target", "*.jar")} {
		m, _ := filepath.Glob(filepath.Join(buildDir, pattern))
		jars = append(jars, m...)
	}
	for _, j := range jars {
		zr, err := zip.OpenReader(j)
		if err != nil {
			s.unreadable()
			continue
		}
		for _, f := range zr.File {
			if f.Name != "META-INF/MANIFEST.MF" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				s.unreadable()
				break
			}
			sc := bufio.NewScanner(rc)
			for sc.Scan() {
				if strings.HasPrefix(strings.ToLower(sc.Text()), "launcher-agent-class:") {
					s.reasons[PartialReasonLaunchAgent] = true
				}
			}
			rc.Close()
		}
		zr.Close()
	}
}

// dockerfile reads ENV/ARG values of the JVM option variables, and every java command in an
// ENTRYPOINT, CMD or RUN-free exec line. A variable a java command expands is resolved from
// the file's own ENV/ARG; one the file never sets comes from the deploy environment (residue).
func (s *launchScan) dockerfile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	vars := map[string]string{}
	var commands []string
	for _, line := range joinContinuations(string(data)) {
		instr, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
		rest = strings.TrimSpace(rest)
		switch strings.ToUpper(instr) {
		case "ENV", "ARG":
			for k, v := range dockerAssignments(rest, strings.ToUpper(instr) == "ENV") {
				vars[k] = v
				if isJVMOptionVar(k) {
					s.optionString(v)
				}
			}
		case "ENTRYPOINT", "CMD":
			commands = append(commands, rest)
		}
	}
	for _, c := range commands {
		var words []string
		if strings.HasPrefix(c, "[") {
			if err := json.Unmarshal([]byte(c), &words); err != nil {
				s.unreadable()
				continue
			}
			if len(words) >= 3 && (words[0] == "sh" || words[0] == "/bin/sh" || words[0] == "bash" || words[0] == "/bin/bash") && words[1] == "-c" {
				words = strings.Fields(words[2])
			}
		} else {
			words = strings.Fields(c)
		}
		s.javaCommand(words, vars)
	}
}

// joinContinuations folds backslash-continued lines and drops comments.
func joinContinuations(text string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`) + " ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// dockerAssignments parses an ENV/ARG body: KEY=VALUE pairs (values optionally quoted), or
// the legacy ENV "KEY VALUE" form. An ARG without a default is omitted.
func dockerAssignments(body string, env bool) map[string]string {
	out := map[string]string{}
	if !strings.Contains(strings.SplitN(body, " ", 2)[0], "=") {
		if k, v, ok := strings.Cut(body, " "); ok && env {
			out[k] = strings.TrimSpace(v)
		}
		return out
	}
	for len(body) > 0 {
		body = strings.TrimLeft(body, " \t")
		k, rest, ok := strings.Cut(body, "=")
		if !ok {
			break
		}
		var v string
		if strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, "'") {
			q := rest[0]
			end := strings.IndexByte(rest[1:], q)
			if end < 0 {
				v, body = rest[1:], ""
			} else {
				v, body = rest[1:end+1], rest[end+2:]
			}
		} else {
			v, body, _ = strings.Cut(rest, " ")
		}
		out[k] = v
	}
	return out
}

// javaCommand classifies the options of every java invocation in words: the tokens after a
// `java` word up to the main class or the -jar value. Leading NAME=value assignments to a JVM
// option variable are option strings too. vars resolves $NAME/${NAME} words.
func (s *launchScan) javaCommand(words []string, vars map[string]string) {
	for i, w := range words {
		if k, v, ok := strings.Cut(w, "="); ok && isJVMOptionVar(k) && !strings.HasPrefix(k, "-") {
			s.optionString(v)
			continue
		}
		if w != "java" && !strings.HasSuffix(w, "/java") {
			continue
		}
		for j := i + 1; j < len(words); j++ {
			opt := words[j]
			if name, ok := shellVar(opt); ok {
				if v, set := vars[name]; set && !isJVMOptionVar(name) {
					s.optionString(v) // a JVM option variable's value was read where it was set
				}
				continue
			}
			if strings.HasPrefix(opt, "@") {
				s.unreadable() // an argument file
				continue
			}
			if !strings.HasPrefix(opt, "-") {
				break // the main class: the rest are program arguments
			}
			c := classifyLaunchOption(opt)
			s.options([]string{opt})
			if c == optionTakesValue {
				if opt == "-jar" {
					break
				}
				j++
			}
		}
	}
}

var shellVarWord = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$`)

func shellVar(w string) (string, bool) {
	m := shellVarWord.FindStringSubmatch(strings.Trim(w, `"'`))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// procfile reads every process line as a command.
func (s *launchScan) procfile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		_, cmd, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		s.javaCommand(strings.Fields(cmd), nil)
	}
}

var jvmOptionVarMention = regexp.MustCompile(`\b(JAVA_OPTS|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS|JAVA_OPTIONS|[A-Z][A-Z0-9_]*_OPTS)\b`)

// yamlManifest reads a YAML file that mentions a JVM option variable or a java command: a
// mapping entry VAR: value, a Kubernetes-style {name: VAR, value: ...} entry, a list item
// VAR=value, or a command list starting with java. A mention it cannot attach to a value (a
// valueFrom, a block it cannot parse) is unreadable.
func (s *launchScan) yamlManifest(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	mentions := jvmOptionVarMention.MatchString(string(data))
	if !mentions && !strings.Contains(string(data), "java") {
		return
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	found := false
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if !errors.Is(err, io.EOF) {
				if mentions {
					s.unreadable()
				}
				return
			}
			break
		}
		found = s.yamlNode(&doc) || found
	}
	if mentions && !found {
		s.unreadable()
	}
}

// yamlNode walks n and reports whether it attached any JVM option variable to a value.
func (s *launchScan) yamlNode(n *yaml.Node) bool {
	found := false
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			found = s.yamlNode(c) || found
		}
	case yaml.MappingNode:
		var nameVar string
		var value *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			switch {
			case k.Value == "name" && v.Kind == yaml.ScalarNode && isJVMOptionVar(v.Value):
				nameVar = v.Value
			case k.Value == "value":
				value = v
			case isJVMOptionVar(k.Value):
				found = true
				if v.Kind == yaml.ScalarNode {
					s.optionString(v.Value)
				} else {
					s.unreadable()
				}
				continue
			}
			found = s.yamlNode(v) || found
		}
		if nameVar != "" {
			found = true
			if value != nil && value.Kind == yaml.ScalarNode {
				s.optionString(value.Value)
			} else {
				s.unreadable() // valueFrom, or no value
			}
		}
	case yaml.SequenceNode:
		var words []string
		scalars := true
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				words = append(words, c.Value)
				if k, v, ok := strings.Cut(c.Value, "="); ok && isJVMOptionVar(k) {
					found = true
					s.optionString(v)
				}
			} else {
				scalars = false
				found = s.yamlNode(c) || found
			}
		}
		if scalars && len(words) > 0 {
			if words[0] == "java" || strings.HasSuffix(words[0], "/java") {
				s.javaCommand(words, nil)
			} else if len(words) >= 3 && words[1] == "-c" {
				s.javaCommand(strings.Fields(words[2]), nil)
			}
		}
	case yaml.ScalarNode:
		if strings.HasPrefix(n.Value, "java ") {
			s.javaCommand(strings.Fields(n.Value), nil)
		}
	}
	return found
}
