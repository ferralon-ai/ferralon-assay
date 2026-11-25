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
	// makeCondRE opens a conditional block, whose assignments make may skip.
	makeCondRE = regexp.MustCompile(`^(?:ifdef|ifndef|ifeq|ifneq)(?:\s|\(|$)`)
	// makeRunRE finds a make run in any text, by path or through $MAKE, in a shell line or a
	// one-line list-form argv (["make", "-e"]); its group is the rest of that command.
	makeRunRE = regexp.MustCompile(`(?:^|[\s;&|(\x60"'\[,/])(?:g?make|\$\(MAKE\)|\$\{MAKE\}|\$MAKE\b)['"]?(?:[\s,]([^;&|\n]*)|$)`)
	// makeListRunRE finds a list-form make argv that may span lines; its group is the rest of
	// the list.
	makeListRunRE = regexp.MustCompile(`['"](?:[^'"\s]*/)?g?make['"]\s*,([^\])]*)`)
	// makeArgSetRE is a variable a make run sets on its command line, which no makefile
	// assignment overrides.
	makeArgSetRE = regexp.MustCompile(`(?:^|[\s,\[])['"]?([A-Za-z_][A-Za-z0-9_]*)\s*(?:::?=|:?=|\+=|\?=|!=)`)
	// makeEnvFlagRE is make's -e, under any abbreviation of --environment-overrides, and its
	// --eval/-E, which may assign anything: either overrides every makefile assignment.
	makeEnvFlagRE = regexp.MustCompile(`(?:^|[\s,'"\[])(?:--e|-[A-Za-z]*[eE])`)
	// makeFlagsRE names a variable through which a run's flags and overrides reach make.
	makeFlagsRE = regexp.MustCompile(`\b(?:GNU)?MAKE(?:FLAGS|OVERRIDES)\b`)
)

// makeAll is the key in Veto.makeSet that every make variable is overridden.
const makeAll = ""

// makePrograms returns, for a makefile's text, each variable every assignment of which, global
// or target-specific, Spec.Program reads as an installer program, mapped to that program. A
// variable another makefile may assign (include), one with no global assignment (the
// environment sets it outside the targets that assign it), one a conditional, appending or
// shell assignment, an assignment inside an ifdef/ifndef/ifeq/ifneq block, an override or
// define sets, or one this cannot tell from another (a computed name, eval, a recipe prefix
// other than tab) maps to nothing, so its references stay expansions.
func makePrograms(src string, program func(string) (string, bool)) map[string]string {
	values := map[string][]string{}
	unbounded := map[string]bool{}
	if strings.Contains(src, "$(eval") || strings.Contains(src, "${eval") || strings.Contains(src, ".RECIPEPREFIX") {
		return nil
	}
	global := map[string]bool{}
	var define bool
	conditional := 0
	for _, line := range makeLogicalLines(src) {
		if define {
			define = strings.TrimSpace(stripMakeComment(line)) != "endef"
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
		switch {
		case makeCondRE.MatchString(s):
			conditional++
			continue
		case s == "endif" && conditional > 0:
			conditional--
			continue
		}
		if m := makeDefineRE.FindStringSubmatch(s); m != nil {
			unbounded[m[1]] = true
			define = true
			continue
		}
		m, targeted := makeAssignment(s)
		if m == nil {
			continue
		}
		directives, name, op, value := m[1], m[2], m[3], m[4]
		if strings.ContainsAny(name, "$%") {
			return nil
		}
		switch {
		case strings.Contains(directives, "override"), op == "?=", op == "+=", op == "!=", conditional > 0:
			unbounded[name] = true
		default:
			values[name] = append(values[name], value)
			global[name] = global[name] || !targeted
		}
	}
	out := map[string]string{}
	for name, vals := range values {
		if unbounded[name] || !global[name] {
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
// globally, or, targeted, after a rule's targets for those targets alone.
func makeAssignment(s string) (m []string, targeted bool) {
	if m := makeAssignRE.FindStringSubmatch(s); m != nil {
		return m, false
	}
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return nil, false
	}
	return makeAssignRE.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(s[i+1:], ":"))), true
}

// makeProgramAssignment reports whether a makefile line outside a recipe assigns a variable
// makePrograms resolved: it sets the installer a recipe runs through the variable, and runs
// nothing itself.
func (v *Veto) makeProgramAssignment(line string) bool {
	if v.makeVars == nil || strings.HasPrefix(line, "\t") {
		return false
	}
	m, _ := makeAssignment(strings.TrimSpace(stripMakeComment(line)))
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
	src = strings.NewReplacer("\\\r\n", " ", "\\\n", " ").Replace(src)
	runs := append(makeRunRE.FindAllStringSubmatch(src, -1), makeListRunRE.FindAllStringSubmatch(src, -1)...)
	for _, m := range runs {
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
