package javaanalysis

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The SAFE set: the only Gradle build-script statements a lock confirmation admits. Each one is
// literal and can't move a resolved version off what the lock and the literal declarations say.
// Everything else fails closed, whatever it does.
//
// Top level (and inside allprojects {} / subprojects {}, whose bodies are top level again):
//
//   - plugins { ... } holding only core plugin ids: id 'java' / id("java"), or a bare kts id
//     (java, `java-library`), from gradleCorePlugins; apply plugin: '<core id>' and
//     apply(plugin = "<core id>") too;
//   - repositories { ... } holding only mavenCentral(), google(), mavenLocal(),
//     gradlePluginPortal(), maven("<url>"), or maven { url '<url>' } / url = "<url>" /
//     url = uri("<url>");
//   - dependencies { ... } holding only declarations on a configuration from gradleSafeConfigs:
//     a string coordinate 'g:a[:v[:classifier]][@ext]', bare or parenthesized; Groovy map
//     notation group: 'g', name: 'a'[, version: 'v'] on one line, unparenthesized; or
//     project('<path>'), bare or parenthesized;
//   - dependencyLocking { lockAllConfigurations() }, exactly that;
//   - group, version, description: a string literal, with or without '=';
//   - sourceCompatibility / targetCompatibility (also as java.<name>, or inside java {}): a
//     string, a number or JavaVersion.VERSION_<n>;
//   - java { toolchain { languageVersion = JavaLanguageVersion.of(<n>) } }, the set(...) form,
//     withSourcesJar(), withJavadocJar(), and the top-level java.toolchain.languageVersion forms;
//   - application { mainClass = '<name>' } / mainClass.set("<name>") / mainClassName = '<name>';
//   - test {}, tasks.test {}, tasks.named('test') {} or tasks.named<Test>("test") {} holding only
//     useJUnitPlatform().
//
// A string literal here is single- or double-quoted on one line, with no '$' and no backslash.
// A statement ends at a line break or ';' outside parentheses and brackets, so a statement that
// continues on the next line fails closed.

// gradleCorePlugins are the core plugin ids the SAFE set admits.
var gradleCorePlugins = map[string]bool{
	"java": true, "java-library": true, "application": true, "groovy": true,
	"idea": true, "eclipse": true, "maven-publish": true, "base": true,
}

// gradleSafeConfigs are the configurations a SAFE dependency declaration may name.
var gradleSafeConfigs = map[string]bool{
	"implementation": true, "api": true, "compileOnly": true, "compileOnlyApi": true,
	"runtimeOnly": true, "annotationProcessor": true, "testImplementation": true,
	"testCompileOnly": true, "testRuntimeOnly": true, "testAnnotationProcessor": true,
	"compile": true, "runtime": true, "testCompile": true, "testRuntime": true,
}

// gradleBuildSafe reports whether every script Gradle would evaluate for the build at root is
// made only of SAFE statements, so that the build can't select a version other than the one its
// lock and literal declarations name. The scripts in scope are the settings scripts, which must
// pass the settings allow-list (gradleSettingsProjects, which rejects includeBuild, apply and
// the rest), and the build scripts of root and every project they include. The SAFE set has no
// apply from, so no applied script is ever in scope. Code Gradle loads that no SAFE statement
// names still runs: buildSrc/ and build-logic/ (with or without a build script of their own),
// and init scripts in a Gradle user home kept in the checkout (.gradle/init.d,
// .gradle/init.gradle[.kts]). Any of these present, or any script that can't be read, makes the
// build unsafe. why names the first reason, for tests and evidence.
func gradleBuildSafe(root string) (why string, ok bool) {
	for _, rel := range []string{"buildSrc", "build-logic", ".gradle/init.d", ".gradle/init.gradle", ".gradle/init.gradle.kts"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil || !missing(err) {
			return rel + " is present", false
		}
	}
	projects, ok := gradleProjects(root)
	if !ok {
		return "settings script is not on the settings allow-list", false
	}
	dirs := make([]string, 0, len(projects))
	for dir := range projects {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		for _, path := range gradleScriptsIn(dir) {
			data, err := readRegular(path)
			if err != nil {
				return relToBase(root, path) + " cannot be read", false
			}
			if !gradleScriptSafe(string(data)) {
				return relToBase(root, path) + " holds a statement outside the SAFE set", false
			}
		}
	}
	return "", true
}

// gradleScriptSafe reports whether every top-level statement of a Gradle build script (raw
// text, comments included) is in the SAFE set. A script whose comments, strings or brackets
// can't be read reliably is not.
func gradleScriptSafe(raw string) bool {
	src, ok := stripGradleCommentsChecked(raw)
	if !ok {
		return false
	}
	toks, ok := gradleTokens(src)
	if !ok {
		return false
	}
	return gradleAllSafe(toks, gradleSafeTop)
}

// gradleToken kinds: 'w' a word (an identifier path such as tasks.named, or a backquoted kts
// identifier), 's' a literal string, 'x' a string that isn't literal, 'n' a number, 'p' one
// punctuation character, ';' a line break or semicolon.
type gradleToken struct {
	kind byte
	text string
}

// gradleTokens needs no special case for a triple-quoted string: it reads as adjacent strings,
// which no SAFE statement holds, or as a string that doesn't close on its line, which fails.
func gradleTokens(src string) ([]gradleToken, bool) {
	var out []gradleToken
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '\n' || c == ';':
			out = append(out, gradleToken{';', ""})
			i++
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(src) && src[j] != c && src[j] != '\n' {
				j++
			}
			if j >= len(src) || src[j] != c {
				return nil, false
			}
			s := src[i+1 : j]
			kind := byte('s')
			if strings.ContainsAny(s, `$\`) {
				kind = 'x'
			}
			out = append(out, gradleToken{kind, s})
			i = j + 1
		case c == '`':
			j := i + 1
			for j < len(src) && (isGradleWordByte(src[j]) || src[j] == '-' || src[j] == '.') {
				j++
			}
			if j >= len(src) || src[j] != '`' || j == i+1 {
				return nil, false
			}
			out = append(out, gradleToken{'w', src[i+1 : j]})
			i = j + 1
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (src[j] >= '0' && src[j] <= '9' || src[j] == '.' || src[j] == '_') {
				j++
			}
			out = append(out, gradleToken{'n', src[i:j]})
			i = j
		case isGradleWordByte(c):
			j := i
			for j < len(src) && isGradleWordByte(src[j]) {
				j++
				if j+1 < len(src) && src[j] == '.' && isGradleWordByte(src[j+1]) && !(src[j+1] >= '0' && src[j+1] <= '9') {
					j++
				}
			}
			out = append(out, gradleToken{'w', src[i:j]})
			i = j
		default:
			out = append(out, gradleToken{'p', string(c)})
			i++
		}
	}
	return out, true
}

// gradleStatements splits tokens into statements at the ';' tokens outside every bracket. A line
// break inside parentheses or brackets continues the statement; one inside braces is kept for
// the block's own statements. ok is false for brackets that don't balance.
func gradleStatements(toks []gradleToken) ([][]gradleToken, bool) {
	var out [][]gradleToken
	var cur []gradleToken
	var stack []string
	closer := map[string]string{")": "(", "]": "[", "}": "{"}
	for _, t := range toks {
		if t.kind == 'p' {
			switch t.text {
			case "(", "[", "{":
				stack = append(stack, t.text)
			case ")", "]", "}":
				if len(stack) == 0 || stack[len(stack)-1] != closer[t.text] {
					return nil, false
				}
				stack = stack[:len(stack)-1]
			}
		}
		if t.kind == ';' {
			if len(stack) == 0 {
				if len(cur) > 0 {
					out = append(out, cur)
				}
				cur = nil
				continue
			}
			if stack[len(stack)-1] != "{" {
				continue
			}
		}
		cur = append(cur, t)
	}
	if len(stack) != 0 {
		return nil, false
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out, true
}

// gradleAllSafe reports whether every statement in toks satisfies safe.
func gradleAllSafe(toks []gradleToken, safe func([]gradleToken) bool) bool {
	stmts, ok := gradleStatements(toks)
	if !ok {
		return false
	}
	for _, st := range stmts {
		if !safe(st) {
			return false
		}
	}
	return true
}

// gradleBlock splits "<head> { <body> }" when the brace opened first at the top of the statement
// closes as its last token.
func gradleBlock(st []gradleToken) (head, body []gradleToken, ok bool) {
	depth, open := 0, -1
	for i, t := range st {
		if t.kind != 'p' {
			continue
		}
		switch t.text {
		case "(", "[":
			depth++
		case ")", "]":
			depth--
		case "{":
			if depth == 0 && open < 0 {
				open = i
			}
			depth++
		case "}":
			depth--
			if depth == 0 && open >= 0 {
				return st[:open], st[open+1 : i], i == len(st)-1
			}
		}
	}
	return nil, nil, false
}

// gradleMatch reports whether st is exactly pat, where "W", "S" and "N" stand for any word,
// literal string or number and capture its text; anything else must equal a word's or a
// punctuation character's text.
func gradleMatch(st []gradleToken, pat ...string) ([]string, bool) {
	if len(st) != len(pat) {
		return nil, false
	}
	var caps []string
	for i, p := range pat {
		t := st[i]
		switch p {
		case "W", "S", "N":
			if t.kind != map[string]byte{"W": 'w', "S": 's', "N": 'n'}[p] {
				return nil, false
			}
			caps = append(caps, t.text)
		default:
			if (t.kind != 'w' && t.kind != 'p') || t.text != p {
				return nil, false
			}
		}
	}
	return caps, true
}

func gradleMatchAny(st []gradleToken, pats ...[]string) ([]string, bool) {
	for _, p := range pats {
		if caps, ok := gradleMatch(st, p...); ok {
			return caps, true
		}
	}
	return nil, false
}

func gradleSafeTop(st []gradleToken) bool {
	if head, body, ok := gradleBlock(st); ok {
		switch {
		case gradleIs(head, "plugins"):
			return gradleAllSafe(body, gradleSafePlugin)
		case gradleIs(head, "repositories"):
			return gradleAllSafe(body, gradleSafeRepository)
		case gradleIs(head, "dependencies"):
			return gradleAllSafe(body, gradleSafeDependency)
		case gradleIs(head, "dependencyLocking"):
			stmts, ok := gradleStatements(body)
			if !ok || len(stmts) != 1 {
				return false
			}
			_, ok = gradleMatch(stmts[0], "lockAllConfigurations", "(", ")")
			return ok
		case gradleIs(head, "java"):
			return gradleAllSafe(body, gradleSafeJava)
		case gradleIs(head, "application"):
			return gradleAllSafe(body, gradleSafeApplication)
		case gradleIs(head, "allprojects"), gradleIs(head, "subprojects"):
			return gradleAllSafe(body, gradleSafeTop)
		case gradleIsTestTask(head):
			return gradleAllSafe(body, func(st []gradleToken) bool {
				_, ok := gradleMatch(st, "useJUnitPlatform", "(", ")")
				return ok
			})
		}
		return false
	}
	if gradleSafeProperty(st, "group", "version", "description") {
		return true
	}
	if gradleSafeCompatibility(st, "sourceCompatibility", "targetCompatibility", "java.sourceCompatibility", "java.targetCompatibility") {
		return true
	}
	if gradleSafeToolchain(st, "java.toolchain.languageVersion") {
		return true
	}
	if caps, ok := gradleMatchAny(st,
		[]string{"apply", "plugin", ":", "S"},
		[]string{"apply", "(", "plugin", "=", "S", ")"},
	); ok {
		return gradleCorePlugins[caps[0]]
	}
	return false
}

// gradleIs reports whether a block head is exactly the word name.
func gradleIs(head []gradleToken, name string) bool {
	_, ok := gradleMatch(head, name)
	return ok
}

func gradleIsTestTask(head []gradleToken) bool {
	if gradleIs(head, "test") || gradleIs(head, "tasks.test") {
		return true
	}
	caps, ok := gradleMatchAny(head,
		[]string{"tasks.named", "(", "S", ")"},
		[]string{"tasks.named", "<", "Test", ">", "(", "S", ")"},
	)
	return ok && caps[0] == "test"
}

// gradleSafeProperty matches "<name> = '<literal>'" or "<name> '<literal>'".
func gradleSafeProperty(st []gradleToken, names ...string) bool {
	caps, ok := gradleMatchAny(st, []string{"W", "=", "S"}, []string{"W", "S"})
	return ok && gradleOneOf(caps[0], names)
}

// gradleSafeCompatibility matches "<name> [=] <string | number | JavaVersion.VERSION_n>".
func gradleSafeCompatibility(st []gradleToken, names ...string) bool {
	if len(st) == 0 || st[0].kind != 'w' || !gradleOneOf(st[0].text, names) {
		return false
	}
	v := st[1:]
	if len(v) > 0 && v[0].kind == 'p' && v[0].text == "=" {
		v = v[1:]
	}
	if len(v) != 1 {
		return false
	}
	switch v[0].kind {
	case 's', 'n':
		return true
	case 'w':
		n := strings.TrimPrefix(v[0].text, "JavaVersion.VERSION_")
		return n != v[0].text && n != "" && strings.Trim(n, "0123456789_") == ""
	}
	return false
}

// gradleSafeToolchain matches "<name> = JavaLanguageVersion.of(<n>)" and
// "<name>.set(JavaLanguageVersion.of(<n>))".
func gradleSafeToolchain(st []gradleToken, name string) bool {
	_, ok := gradleMatchAny(st,
		[]string{name, "=", "JavaLanguageVersion.of", "(", "N", ")"},
		[]string{name + ".set", "(", "JavaLanguageVersion.of", "(", "N", ")", ")"},
	)
	return ok
}

func gradleSafeJava(st []gradleToken) bool {
	if head, body, ok := gradleBlock(st); ok {
		return gradleIs(head, "toolchain") && gradleAllSafe(body, func(st []gradleToken) bool {
			return gradleSafeToolchain(st, "languageVersion")
		})
	}
	if gradleSafeCompatibility(st, "sourceCompatibility", "targetCompatibility") || gradleSafeToolchain(st, "toolchain.languageVersion") {
		return true
	}
	_, ok := gradleMatchAny(st, []string{"withSourcesJar", "(", ")"}, []string{"withJavadocJar", "(", ")"})
	return ok
}

func gradleSafeApplication(st []gradleToken) bool {
	_, ok := gradleMatchAny(st,
		[]string{"mainClass", "=", "S"},
		[]string{"mainClass.set", "(", "S", ")"},
		[]string{"mainClassName", "=", "S"},
	)
	return ok
}

func gradleSafePlugin(st []gradleToken) bool {
	caps, ok := gradleMatchAny(st, []string{"id", "S"}, []string{"id", "(", "S", ")"}, []string{"W"})
	return ok && gradleCorePlugins[caps[0]]
}

func gradleSafeRepository(st []gradleToken) bool {
	if head, body, ok := gradleBlock(st); ok {
		return gradleIs(head, "maven") && gradleAllSafe(body, func(st []gradleToken) bool {
			_, ok := gradleMatchAny(st,
				[]string{"url", "S"},
				[]string{"url", "=", "S"},
				[]string{"url", "=", "uri", "(", "S", ")"},
				[]string{"url", "uri", "(", "S", ")"},
			)
			return ok
		})
	}
	_, ok := gradleMatchAny(st,
		[]string{"mavenCentral", "(", ")"},
		[]string{"google", "(", ")"},
		[]string{"mavenLocal", "(", ")"},
		[]string{"gradlePluginPortal", "(", ")"},
		[]string{"maven", "(", "S", ")"},
	)
	return ok
}

// gradleSafeDependency admits only the declaration forms gradleDeclarations reads, so every
// version a SAFE script declares is checked against the lock.
func gradleSafeDependency(st []gradleToken) bool {
	if len(st) == 0 || st[0].kind != 'w' || !gradleSafeConfigs[st[0].text] {
		return false
	}
	arg := st[1:]
	if caps, ok := gradleMatchAny(arg, []string{"S"}, []string{"(", "S", ")"}); ok {
		return gradleCoordinateString.MatchString(caps[0])
	}
	if _, ok := gradleMatchAny(arg,
		[]string{"project", "(", "S", ")"},
		[]string{"(", "project", "(", "S", ")", ")"},
	); ok {
		return true
	}
	if _, ok := gradleMatch(arg, "group", ":", "S", ",", "name", ":", "S"); ok {
		return true
	}
	_, ok := gradleMatch(arg, "group", ":", "S", ",", "name", ":", "S", ",", "version", ":", "S")
	return ok
}

func gradleOneOf(s string, names []string) bool {
	for _, n := range names {
		if s == n {
			return true
		}
	}
	return false
}

// isGradleWordByte reports an identifier character ('$' excluded).
func isGradleWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
