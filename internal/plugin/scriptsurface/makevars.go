package scriptsurface

import (
	"regexp"
	"strings"
)

var (
	// makeRefRE is a recipe word that is one make variable reference and nothing else.
	makeRefRE = regexp.MustCompile(`^\$(?:\(([A-Za-z_][A-Za-z0-9_]*)\)|\{([A-Za-z_][A-Za-z0-9_]*)\})$`)
	// makeAssignRE is a make variable assignment: its directives, name, operator and value.
	makeAssignRE  = regexp.MustCompile(`^((?:(?:override|export|private|unexport)\s+)*)([^\s:=#?+!]+)\s*(:::=|::=|:=|\?=|\+=|!=|=)\s*(.*)$`)
	makeDefineRE  = regexp.MustCompile(`^(?:(?:override|export|private)\s+)*define\s+([^\s:=#?+!]+)`)
	makeIncludeRE = regexp.MustCompile(`^(?:-|s)?include\s`)
	// makeRunRE finds a make run in any text; its group is the rest of that command.
	makeRunRE = regexp.MustCompile(`(?:^|[\s;&|(\x60"'])(?:g?make|\$\(MAKE\)|\$\{MAKE\})(?:\s([^;&|\n]*)|$)`)
	// makeArgSetRE is a variable a make run sets on its command line, which no makefile
	// assignment overrides.
	makeArgSetRE = regexp.MustCompile(`(?:^|\s)['"]?([A-Za-z_][A-Za-z0-9_]*)\s*(?:::?=|:?=|\+=|\?=|!=)`)
	// makeEnvFlagRE is make's -e: the environment overrides every makefile assignment.
	makeEnvFlagRE = regexp.MustCompile(`(?:^|\s)(?:--environment-overrides|-[A-Za-z]*e[A-Za-z]*)(?:\s|$)`)
	// makeFlagsRE names a variable through which a run's flags and overrides reach make.
	makeFlagsRE = regexp.MustCompile(`\b(?:GNU)?MAKE(?:FLAGS|OVERRIDES)\b`)
)

// makeAll is the key in Veto.makeSet that every make variable is overridden.
const makeAll = ""

// makePrograms returns, for a makefile's text, each variable every assignment of which, global
// or target-specific, Spec.Program reads as an installer program, mapped to that program. A
// variable another makefile may assign (include), one a conditional, appending or shell
// assignment, an override or define sets, or one this cannot tell from another (a computed
// name, eval, a recipe prefix other than tab) maps to nothing, so its references stay
// expansions.
func makePrograms(src string, program func(string) (string, bool)) map[string]string {
	values := map[string][]string{}
	unbounded := map[string]bool{}
	if strings.Contains(src, "$(eval") || strings.Contains(src, "${eval") || strings.Contains(src, ".RECIPEPREFIX") {
		return nil
	}
	var define bool
	for _, line := range makeLogicalLines(src) {
		if define {
			define = strings.TrimSpace(line) != "endef"
			continue
		}
		if strings.HasPrefix(line, "\t") {
			continue // a recipe line: what it sets is the shell's, not make's
		}
		s := strings.TrimSpace(stripMakeComment(line))
		if s == "" {
			continue
		}
		if makeIncludeRE.MatchString(s) {
			return nil
		}
		if m := makeDefineRE.FindStringSubmatch(s); m != nil {
			unbounded[m[1]] = true
			define = true
			continue
		}
		m := makeAssignment(s)
		if m == nil {
			continue
		}
		directives, name, op, value := m[1], m[2], m[3], m[4]
		if strings.ContainsAny(name, "$%") {
			return nil
		}
		switch {
		case strings.Contains(directives, "override"), op == "?=", op == "+=", op == "!=":
			unbounded[name] = true
		default:
			values[name] = append(values[name], value)
		}
	}
	out := map[string]string{}
	for name, vals := range values {
		if unbounded[name] {
			continue
		}
		prog, ok := "", true
		for _, val := range vals {
			p, isProg := program(val)
			if !isProg {
				ok = false
				break
			}
			if prog == "" {
				prog = p
			}
		}
		if ok && prog != "" {
			out[name] = prog
		}
	}
	return out
}

// makeAssignment matches a makefile line, comment and indent off, that assigns a variable:
// globally, or after a rule's targets for those targets alone.
func makeAssignment(s string) []string {
	if m := makeAssignRE.FindStringSubmatch(s); m != nil {
		return m
	}
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return nil
	}
	return makeAssignRE.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(s[i+1:], ":")))
}

// makeProgramAssignment reports whether a makefile line outside a recipe assigns a variable
// makePrograms resolved: it sets the installer a recipe runs through the variable, and runs
// nothing itself.
func (v *Veto) makeProgramAssignment(line string) bool {
	if v.makeVars == nil || strings.HasPrefix(line, "\t") {
		return false
	}
	m := makeAssignment(strings.TrimSpace(stripMakeComment(line)))
	if m == nil {
		return false
	}
	_, ok := v.makeVars[m[2]]
	return ok
}

// makeLogicalLines joins a makefile's backslash continuations outside recipes, as make reads them.
func makeLogicalLines(src string) []string {
	var lines []string
	var cur strings.Builder
	for _, l := range strings.Split(src, "\n") {
		l = strings.TrimSuffix(l, "\r")
		if n := len(l) - len(strings.TrimRight(l, `\`)); n%2 == 1 {
			cur.WriteString(l[:len(l)-1])
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(l)
		lines = append(lines, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

// stripMakeComment drops a line's comment: a # that no backslash escapes.
func stripMakeComment(line string) string {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case '#':
			return line[:i]
		}
	}
	return line
}

// noteMakeOverrides records each make variable the text sets on a make command line, and every
// variable when a run's flags may (-e, MAKEFLAGS): an assignment in the makefile does not bound it.
func (v *Veto) noteMakeOverrides(src string) {
	if v.spec.Program == nil {
		return
	}
	if makeFlagsRE.MatchString(src) {
		v.makeSet[makeAll] = true
	}
	for _, m := range makeRunRE.FindAllStringSubmatch(src, -1) {
		if makeEnvFlagRE.MatchString(m[1]) {
			v.makeSet[makeAll] = true
		}
		for _, a := range makeArgSetRE.FindAllStringSubmatch(m[1], -1) {
			v.makeSet[a[1]] = true
		}
	}
}

// makeProgram resolves a command's first word when it is a reference to a variable the
// makefile being read assigns only installer programs (makePrograms).
func (v *Veto) makeProgram(seg segment) segment {
	if v.makeVars == nil {
		return seg
	}
	m := makeRefRE.FindStringSubmatch(seg.words[0])
	if m == nil {
		return seg
	}
	name := m[1] + m[2]
	prog, ok := v.makeVars[name]
	if !ok {
		return seg
	}
	v.makeResolved[name] = true
	seg.words = append([]string{prog}, seg.words[1:]...)
	seg.expands = hasExpansion(seg.words)
	return seg
}

// makeOverridden reports whether a make run anywhere in the build may set a variable a
// command was resolved through. Call it after the walk.
func (v *Veto) makeOverridden() bool {
	for name := range v.makeResolved {
		if v.makeSet[name] || v.makeSet[makeAll] {
			return true
		}
	}
	return false
}
