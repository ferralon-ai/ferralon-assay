package javaanalysis

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// PartialReasonUnmodeledDependency: a Gradle build script declares a dependency in a form the
// inventory does not model (files(), fileTree(), project(), a flatDir repository, an included
// build, a variable), or a script cannot be read, so the analysed classpath may be missing
// code the build puts on its own.
const PartialReasonUnmodeledDependency = plugin.PartialReasonRelationshipUnexpressed + ":gradle_unmodeled_dependency"

// UnmodeledGradleDependencies scans every Gradle script (*.gradle, *.gradle.kts) under
// buildDir, skipping the directories the source walk skips, and returns one sorted
// "<rel>:<line>: <form>" entry per dependency declaration it does not model. nil means every
// declaration is modeled; a caller that lists a sink as Searched must have nil here.
//
// Modeled: inside a `dependencies { }` block (or a nested `constraints { }`), a statement
// naming a configuration (an identifier or a string) whose arguments are each a string
// literal, Groovy or Kotlin map notation over group, name, version, classifier and ext, a
// `libs.` version-catalog accessor, or platform(), enforcedPlatform(), testFixtures() or
// kotlin() around those, optionally followed by a configuration closure. Every such form
// names a module, which the lockfile and the module cache account for.
//
// Everything else is an entry: any other statement or argument in a dependencies block
// (files(), fileTree(), project(), gradleApi(), a variable, an expression); a `dependencies`
// reference that is not a block (dependencies.add); flatDir, includeBuild,
// dependencySubstitution, withDependencies and defaultDependencies anywhere; an `apply from`
// that is not a string naming a script this scan reads; and a script that cannot be read or
// lexed.
func UnmodeledGradleDependencies(buildDir string) []string {
	var scripts []string
	found := map[string]bool{}
	err := filepath.WalkDir(buildDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			found[relOrPath(buildDir, path)+":0: unreadable"] = true
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != buildDir && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if gradleScript(d.Name()) {
			scripts = append(scripts, path)
		}
		return nil
	})
	if err != nil {
		found[".:0: unreadable"] = true
	}
	read := make(map[string]bool, len(scripts))
	for _, p := range scripts {
		read[filepath.Clean(p)] = true
	}
	for _, p := range scripts {
		rel := relOrPath(buildDir, p)
		data, err := os.ReadFile(p)
		if err != nil {
			found[rel+":0: unreadable"] = true
			continue
		}
		for _, f := range gradleDeclFindings(data, strings.HasSuffix(p, ".kts"), func(target string, fromRoot bool) bool {
			base := filepath.Dir(p)
			if fromRoot {
				base = buildDir
			}
			return read[filepath.Clean(filepath.Join(base, target))]
		}) {
			found[rel+":"+f] = true
		}
	}
	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func gradleScript(name string) bool {
	return strings.HasSuffix(name, ".gradle") || strings.HasSuffix(name, ".gradle.kts")
}

func relOrPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

// gradleTokKind classifies one token of a Gradle script.
type gradleTokKind int

const (
	gtIdent gradleTokKind = iota
	gtString
	gtPunct
	gtNewline
)

type gradleTok struct {
	kind gradleTokKind
	text string // identifier name, punctuation, or the string's literal body
	line int
	tmpl bool // a string holding a ${} or $name template
}

// lexGradle splits a Groovy or Kotlin script into identifiers, string literals, punctuation
// and newlines, dropping comments and other whitespace. ok is false when a comment, string or
// slashy string does not close.
func lexGradle(data []byte, kts bool) ([]gradleTok, bool) {
	var toks []gradleTok
	line := 1
	for i := 0; i < len(data); {
		c := data[i]
		at := data[i:]
		switch {
		case c == '\n':
			toks = append(toks, gradleTok{kind: gtNewline, text: "\n", line: line})
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			i++
		case c == '\\' && i+1 < len(data) && (data[i+1] == '\n' || data[i+1] == '\r'):
			i++ // a line continuation
		case bytes.HasPrefix(at, []byte("//")):
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case bytes.HasPrefix(at, []byte("/*")):
			j, ok := skipBlockComment(data, i, kts)
			if !ok {
				return nil, false
			}
			line += bytes.Count(data[i:j], []byte("\n"))
			i = j
		case stringQuote(at, kts) != "":
			q := stringQuote(at, kts)
			j, ok := skipString(data, i, q, kts)
			if !ok {
				return nil, false
			}
			body := string(data[i+len(q) : j-len(q)])
			toks = append(toks, gradleTok{kind: gtString, text: body, line: line, tmpl: q[0] == '"' && strings.Contains(body, "$")})
			line += strings.Count(body, "\n")
			i = j
		case c == '/' && !kts && !gradleOperand(toks):
			// A Groovy slashy string: '/' where an operand is expected.
			j := i + 1
			for j < len(data) && data[j] != '/' {
				if data[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(data) {
				return nil, false
			}
			body := string(data[i+1 : j])
			toks = append(toks, gradleTok{kind: gtString, text: body, line: line, tmpl: strings.Contains(body, "$")})
			line += strings.Count(body, "\n")
			i = j + 1
		case c == '`':
			j := bytes.IndexAny(at[1:], "`\n")
			if j < 0 || at[1+j] != '`' {
				return nil, false
			}
			toks = append(toks, gradleTok{kind: gtIdent, text: string(at[1 : 1+j]), line: line})
			i += j + 2
		case gradleIdentByte(c):
			j := i + 1
			for j < len(data) && gradleIdentByte(data[j]) {
				j++
			}
			toks = append(toks, gradleTok{kind: gtIdent, text: string(data[i:j]), line: line})
			i = j
		default:
			toks = append(toks, gradleTok{kind: gtPunct, text: string(c), line: line})
			i++
		}
	}
	return toks, true
}

func gradleIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

// gradleOperand reports whether the last significant token ends an operand, so a following
// '/' divides.
func gradleOperand(toks []gradleTok) bool {
	if len(toks) == 0 {
		return false
	}
	t := toks[len(toks)-1]
	return t.kind == gtIdent || t.kind == gtString || t.kind == gtPunct && (t.text == ")" || t.text == "]")
}

// gradleAnywhere are names that change what a build resolves wherever they appear.
var gradleAnywhere = map[string]bool{
	"flatDir": true, "includeBuild": true, "dependencySubstitution": true,
	"withDependencies": true, "defaultDependencies": true,
}

// gradleMapKeys are the map-notation keys of a module dependency.
var gradleMapKeys = map[string]bool{"group": true, "name": true, "version": true, "classifier": true, "ext": true}

// gradleWrappers take a module notation and return one.
var gradleWrappers = map[string]bool{"platform": true, "enforcedPlatform": true, "testFixtures": true, "kotlin": true}

// gradleDeclFindings returns "<line>: <form>" for each unmodeled declaration in one script.
// local reports whether an `apply from` target, relative to the script (or to the build root
// when fromRoot), is a script the scan reads.
func gradleDeclFindings(data []byte, kts bool, local func(target string, fromRoot bool) bool) []string {
	toks, ok := lexGradle(data, kts)
	if !ok {
		return []string{"0: unlexable"}
	}
	match, ok := gradleDeclMatch(toks)
	if !ok {
		return []string{"0: unbalanced brackets"}
	}
	p := &gradleDecls{toks: toks, match: match, kts: kts}
	for i, t := range toks {
		if t.kind != gtIdent {
			continue
		}
		switch {
		case gradleAnywhere[t.text]:
			p.add(t.line, t.text)
		case t.text == "apply" && !(i > 0 && toks[i-1].kind == gtPunct && toks[i-1].text == "."):
			p.apply(i, local)
		case t.text == "dependencies":
			if j := p.next(i + 1); j < len(toks) && toks[j].text == "{" && toks[j].kind == gtPunct {
				p.block(j)
			} else {
				p.add(t.line, "dependencies reference")
			}
		}
	}
	return p.out
}

// gradleDeclMatch pairs every opening bracket with its closing one. ok is false when they do not
// balance.
func gradleDeclMatch(toks []gradleTok) (map[int]int, bool) {
	match := map[int]int{}
	var open []int
	pair := map[string]string{")": "(", "]": "[", "}": "{"}
	for i, t := range toks {
		if t.kind != gtPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			open = append(open, i)
		case ")", "]", "}":
			if len(open) == 0 || toks[open[len(open)-1]].text != pair[t.text] {
				return nil, false
			}
			match[open[len(open)-1]] = i
			open = open[:len(open)-1]
		}
	}
	return match, len(open) == 0
}

type gradleDecls struct {
	toks  []gradleTok
	match map[int]int
	kts   bool
	out   []string
}

func (p *gradleDecls) add(line int, form string) {
	p.out = append(p.out, fmt.Sprintf("%d: %s", line, form))
}

// next returns the index of the first token at or after i that is not a newline.
func (p *gradleDecls) next(i int) int {
	for i < len(p.toks) && p.toks[i].kind == gtNewline {
		i++
	}
	return i
}

func (p *gradleDecls) punct(i int, s string) bool {
	return i < len(p.toks) && p.toks[i].kind == gtPunct && p.toks[i].text == s
}

// apply checks a Project.apply call: an apply that names `from` must name, as a string with
// no template other than a leading $rootDir, a script this scan reads.
func (p *gradleDecls) apply(i int, local func(string, bool) bool) {
	j := i + 1
	end := len(p.toks)
	switch {
	case p.punct(j, "("):
		end = p.match[j]
		j++
	case p.punct(j, "{"):
		p.add(p.toks[i].line, "apply block")
		return
	default:
		for k := j; k < len(p.toks); k++ {
			if p.toks[k].kind == gtNewline || p.punct(k, ";") || p.punct(k, "}") {
				end = k
				break
			}
		}
	}
	for k := j; k < end; k++ {
		t := p.toks[k]
		if t.kind != gtIdent || t.text != "from" || !(p.punct(k+1, ":") || p.punct(k+1, "=")) {
			continue
		}
		v := k + 2
		ok := v < end && p.toks[v].kind == gtString && (v+1 == end || p.punct(v+1, ","))
		if ok {
			target, fromRoot := p.toks[v].text, false
			for _, pre := range []string{"$rootDir/", "${rootDir}/", "${project.rootDir}/", "${rootProject.rootDir}/"} {
				if rest, cut := strings.CutPrefix(target, pre); cut && p.toks[v].tmpl {
					target, fromRoot = rest, true
					break
				}
			}
			ok = !strings.ContainsAny(target, "$:") && local(filepath.FromSlash(target), fromRoot)
		}
		if !ok {
			p.add(t.line, "apply from")
		}
	}
}

// block checks each statement of the dependencies block opening at token open.
func (p *gradleDecls) block(open int) {
	end := p.match[open]
	for i := open + 1; i < end; {
		i = p.next(i)
		if i >= end {
			return
		}
		if p.punct(i, ";") {
			i++
			continue
		}
		stop, ok := p.statement(i, end)
		if !ok {
			p.add(p.toks[i].line, "unmodeled declaration "+p.form(i, end))
			stop = p.statementEnd(i, end)
		}
		i = stop
	}
}

// form names a rejected statement by its head token.
func (p *gradleDecls) form(i, end int) string {
	t := p.toks[i]
	s := t.text
	if t.kind == gtString {
		s = `"` + s + `"`
	}
	if j := i + 1; j < end && p.toks[j].kind == gtPunct && p.toks[j].text != "{" && p.toks[j].text != "(" {
		return s + " " + p.toks[j].text
	}
	if j := p.argStart(i+1, end); j < end && p.toks[j].kind == gtIdent {
		return s + " " + p.toks[j].text
	}
	return s
}

func (p *gradleDecls) argStart(i, end int) int {
	if p.punct(i, "(") {
		return i + 1
	}
	return i
}

// statementEnd returns the index after the statement starting at i: the first newline,
// semicolon or block end outside brackets.
func (p *gradleDecls) statementEnd(i, end int) int {
	for i < end {
		t := p.toks[i]
		switch {
		case t.kind == gtNewline || p.punct(i, ";"):
			return i + 1
		case t.kind == gtPunct && (t.text == "(" || t.text == "[" || t.text == "{"):
			i = p.match[i] + 1
		default:
			i++
		}
	}
	return end
}

// statement parses one modeled declaration starting at i. It returns the index after it, or
// ok=false when the statement is not a modeled form.
func (p *gradleDecls) statement(i, end int) (int, bool) {
	head := p.toks[i]
	if head.kind != gtIdent && !(head.kind == gtString && !head.tmpl) {
		return 0, false
	}
	j := i + 1
	if head.kind == gtIdent && head.text == "constraints" && p.punct(j, "{") {
		p.block(j)
		return p.terminated(p.match[j]+1, end)
	}
	switch {
	case p.punct(j, "("):
		close := p.match[j]
		if !p.args(j+1, close) {
			return 0, false
		}
		j = close + 1
		if p.punct(j, "{") {
			j = p.match[j] + 1
		}
	case head.kind == gtIdent && !p.kts && j < end && p.toks[j].kind != gtNewline && !p.punct(j, ";"):
		// Groovy command syntax: arguments run to the end of the line, and a trailing comma
		// continues them on the next.
		stop := j
		for stop < end {
			t := p.toks[stop]
			if t.kind == gtNewline && !p.punct(stop-1, ",") || p.punct(stop, ";") {
				break
			}
			if t.kind == gtPunct && (t.text == "(" || t.text == "[" || t.text == "{") {
				stop = p.match[stop] + 1
				continue
			}
			stop++
		}
		if !p.args(j, stop) {
			return 0, false
		}
		j = stop
	default:
		return 0, false
	}
	return p.terminated(j, end)
}

// terminated accepts a statement ending at j: only a newline, semicolon or the block end may
// follow it.
func (p *gradleDecls) terminated(j, end int) (int, bool) {
	if j >= end {
		return end, true
	}
	if p.toks[j].kind == gtNewline || p.punct(j, ";") {
		return j + 1, true
	}
	return 0, false
}

// args reports whether the comma-separated arguments in toks[i:end] are each modeled.
func (p *gradleDecls) args(i, end int) bool {
	seen := false
	for i = p.next(i); i < end; i = p.next(i) {
		var ok bool
		if i, ok = p.arg(i, end); !ok {
			return false
		}
		seen = true
		i = p.next(i)
		if i < end {
			if !p.punct(i, ",") {
				return false
			}
			i++
		}
	}
	return seen
}

// arg parses one modeled argument at i and returns the index after it.
func (p *gradleDecls) arg(i, end int) (int, bool) {
	t := p.toks[i]
	switch {
	case t.kind == gtString:
		return i + 1, true
	case t.kind != gtIdent:
		return 0, false
	case gradleMapKeys[t.text] && (p.punct(i+1, ":") && !p.kts || p.punct(i+1, "=") && p.kts):
		return p.value(p.next(i+2), end)
	case gradleWrappers[t.text] && p.punct(i+1, "("):
		close := p.match[i+1]
		if close >= end || !p.args(i+2, close) {
			return 0, false
		}
		return close + 1, true
	case t.text == "libs":
		j := i + 1
		for p.punct(j, ".") && j+1 < end && p.toks[j+1].kind == gtIdent {
			j += 2
		}
		if j == i+1 {
			return 0, false
		}
		return j, true
	}
	return 0, false
}

// value parses a map-notation value: a string, or a dotted name with no call.
func (p *gradleDecls) value(i, end int) (int, bool) {
	if i >= end {
		return 0, false
	}
	switch p.toks[i].kind {
	case gtString:
		return i + 1, true
	case gtIdent:
		j := i + 1
		for p.punct(j, ".") && j+1 < end && p.toks[j+1].kind == gtIdent {
			j += 2
		}
		return j, true
	}
	return 0, false
}
