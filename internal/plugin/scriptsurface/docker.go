package scriptsurface

import (
	"encoding/json"
	"maps"
	"path"
	"path/filepath"
	"strings"
)

// dockerEvent is one change to a stage's filesystem, by container path: a COPY from the
// build context (hosts, the host files or directories copied), or a taint at dst, under dst
// when dir, or everywhere when all.
type dockerEvent struct {
	dst   string
	hosts []string
	dir   bool
	taint bool
	all   bool
}

type dockerStage struct {
	events  []dockerEvent
	wd      string
	wdKnown bool
}

const (
	pathAbsent = iota
	pathBound
	pathTainted
)

// lookup returns the host files a container path holds, newest change first.
func (st *dockerStage) lookup(v *Veto, f string) ([]string, int) {
	for i := len(st.events) - 1; i >= 0; i-- {
		e := st.events[i]
		if e.all {
			return nil, pathTainted
		}
		under := e.dir && (e.dst == "/" || strings.HasPrefix(f, e.dst+"/"))
		if f != e.dst && !under {
			continue
		}
		if e.taint {
			return nil, pathTainted
		}
		if !e.dir {
			return e.hosts, pathBound
		}
		rel := filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(f, e.dst), "/"))
		var hs []string
		for _, h := range e.hosts {
			hf := filepath.Join(h, rel)
			switch regular, there, known := v.stat(hf); {
			case !known || there && !regular && !isDir(hf):
				return nil, pathTainted
			case regular:
				hs = append(hs, hf)
			}
		}
		if len(hs) > 0 {
			return hs, pathBound
		}
	}
	return nil, pathAbsent
}

func (st *dockerStage) taintAll() { st.events = append(st.events, dockerEvent{all: true}) }

// resolve returns a container path for p, from the WORKDIR when relative.
func (st *dockerStage) resolve(p string) (string, bool) {
	switch {
	case p == "" || strings.ContainsAny(p, "$`"):
		return "", false
	case path.IsAbs(p):
		return path.Clean(p), true
	case st.wdKnown:
		return path.Join(st.wd, p), true
	}
	return "", false
}

// copyInstr records a COPY or ADD. Only a plain COPY of existing build-context paths maps
// files; anything else taints its destination, or everything when that is unknown.
func (st *dockerStage) copyInstr(v *Veto, ctxs []string, rest string, add bool) {
	var args []string
	if strings.HasPrefix(rest, "[") {
		if json.Unmarshal([]byte(rest), &args) != nil {
			st.taintAll()
			return
		}
	} else {
		args = strings.Fields(rest)
	}
	plain := !add
	var operands []string
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			switch name, _, _ := strings.Cut(a, "="); name {
			case "--chown", "--chmod", "--link":
			default:
				plain = false // --from, --parents, --exclude and the rest
			}
			continue
		}
		operands = append(operands, a)
	}
	if len(operands) < 2 {
		st.taintAll()
		return
	}
	dest, srcs := operands[len(operands)-1], operands[:len(operands)-1]
	destC, ok := st.resolve(dest)
	if !ok {
		st.taintAll()
		return
	}
	if !plain || hasExpansion(srcs) {
		st.events = append(st.events, dockerEvent{dst: destC, dir: true, taint: true})
		return
	}
	// A file copied to a directory lands inside it: a dest written as one, or the WORKDIR,
	// which exists once set.
	destDir := strings.HasSuffix(dest, "/") || path.Base("/"+dest) == "." || len(srcs) > 1 || st.wdKnown && destC == st.wd
	var mapped []dockerEvent
	add1 := func(e dockerEvent) {
		for i := range mapped {
			if mapped[i].dst == e.dst && mapped[i].dir == e.dir {
				mapped[i].hosts = append(mapped[i].hosts, e.hosts...)
				return
			}
		}
		mapped = append(mapped, e)
	}
	// A source this cannot place (outside root, unexaminable, matching nothing) may have put
	// anything under the destination.
	unplaced := false
	for _, src := range srcs {
		rel := filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+src), "/"))
		glob := strings.ContainsAny(src, "*?[")
		placed := false
		for _, ctx := range ctxs {
			pattern := filepath.Join(ctx, rel)
			matches := []string{pattern}
			if glob {
				var ok bool
				if matches, ok = v.glob(pattern); !ok {
					unplaced = true
					continue
				}
			}
			for _, m := range matches {
				regular, there, known := v.stat(m)
				switch {
				case !v.inRoot(m) || !known:
					unplaced = true
				case isDir(m):
					add1(dockerEvent{dst: destC, hosts: []string{m}, dir: true})
					placed = true
				case regular:
					dst := destC
					if destDir || glob {
						dst = path.Join(destC, filepath.Base(m))
					}
					add1(dockerEvent{dst: dst, hosts: []string{m}})
					placed = true
				case there:
					unplaced = true
				}
			}
		}
		unplaced = unplaced || !placed
	}
	if len(mapped) == 0 || unplaced {
		st.events = append(st.events, dockerEvent{dst: destC, dir: true, taint: true})
		return
	}
	st.events = append(st.events, mapped...)
}

// dockerCursor is the container directory a RUN, CMD or ENTRYPOINT command runs in.
type dockerCursor struct {
	v     *Veto
	st    *dockerStage
	dir   string
	known bool
	mark  venvMark
}

func (c *dockerCursor) cd(words []string) {
	if !c.known {
		return
	}
	if len(words) != 2 || words[0] == "popd" || words[1] == "-" || strings.HasPrefix(words[1], "~") {
		c.known = false
		return
	}
	if path.IsAbs(words[1]) {
		c.dir = path.Clean(words[1])
	} else {
		c.dir = path.Join(c.dir, words[1])
	}
}

// other taints the whole stage: a command that is not an allowed install may write anywhere.
func (c *dockerCursor) other() { c.st.taintAll() }

func (c *dockerCursor) fork() cursor {
	f := *c
	return &f
}

// Prefixed is nil: a package root inside the image is not a build-tree directory the walk
// reads.
func (c *dockerCursor) Prefixed(string, string, ...string) []string { return nil }

func (c *dockerCursor) File(p string) bool { return c.Hosts(p) != nil }

// sourced is false: a file in the image is not one the walk checks.
func (c *dockerCursor) sourced(string) bool { return false }

func (c *dockerCursor) at(p string) (string, bool) {
	switch {
	case p == "" || strings.ContainsAny(p, "$`*?[~"):
		return "", false
	case path.IsAbs(p):
		return path.Clean(p), true
	case !c.known || c.mark.lost:
		return "", false
	}
	return path.Join(c.dir, p), true
}

// present is true for a path the stage has bound or tainted: a file copied in, or one a
// command may have written.
func (c *dockerCursor) present(p string) bool {
	f, ok := c.at(p)
	if !ok {
		return true
	}
	_, state := c.st.lookup(c.v, f)
	return state != pathAbsent
}

func (c *dockerCursor) venv() *venvMark { return &c.mark }

func (c *dockerCursor) Hosts(p string) []string {
	if !path.IsAbs(p) && !c.known || strings.ContainsAny(p, "*?[~") {
		return nil
	}
	f := path.Clean(p)
	if !path.IsAbs(p) {
		f = path.Join(c.dir, p)
	}
	hosts, state := c.st.lookup(c.v, f)
	if state != pathBound || len(hosts) == 0 {
		return nil
	}
	for _, h := range hosts {
		if !c.v.read(h) {
			return nil
		}
	}
	c.v.bind(p)
	return hosts
}

func (c *dockerCursor) Nearest(name string, locks ...string) []string {
	if !c.known {
		return nil
	}
	for d := c.dir; ; d = path.Dir(d) {
		hosts, state := c.st.lookup(c.v, path.Join(d, name))
		switch state {
		case pathTainted:
			return nil
		case pathBound:
			for _, h := range hosts {
				if !c.v.read(h) {
					return nil
				}
			}
			if len(locks) > 0 && !c.lockAbove(d, locks) {
				return nil
			}
			c.v.bind(name)
			for _, l := range locks {
				c.v.bind(l)
			}
			return hosts
		}
		if d == "/" {
			return nil
		}
	}
}

// lockAbove reports whether the nearest of locks at or above the container directory dir was
// copied from the build context, read here, and is unchanged since.
func (c *dockerCursor) lockAbove(dir string, locks []string) bool {
	for ; ; dir = path.Dir(dir) {
		for _, l := range locks {
			hosts, state := c.st.lookup(c.v, path.Join(dir, l))
			switch state {
			case pathTainted:
				return false
			case pathBound:
				for _, h := range hosts {
					if !c.v.read(h) {
						return false
					}
				}
				return true
			}
		}
		if dir == "/" {
			return false
		}
	}
}

var (
	dockerPlain = map[string]bool{
		"ENV": true, "ARG": true, "LABEL": true, "EXPOSE": true, "USER": true, "VOLUME": true,
		"STOPSIGNAL": true, "MAINTAINER": true, "SHELL": true,
	}
)

// dockerReadingsMax bounds the readings dockerfile checks a Dockerfile in.
const dockerReadingsMax = 64

// dockerfile applies the rule to a Dockerfile, stage by stage. CMD and ENTRYPOINT run after
// every RUN, so they are checked against the stage as it ends.
//
// dockerHeredocs takes a line's instruction as BuildKit's splitCommand does and splits its
// words at Unicode blanks as BuildKit's lexer does, but reads those words as BuildKit does
// only where the line holds no $, backslash or backtick; elsewhere it may open a heredoc
// BuildKit doesn't, whose body would then hide instructions BuildKit runs. Where both open
// heredocs, they agree on how many and on their names, except on a line with a
// ${name<op>word} expansion, which is withheld (dockerUnsure). So the file is read once for
// each way the heredocs on such lines may go, open or not, and checked in every reading.
func (v *Veto) dockerfile(file, src string) string {
	readings := []map[int]bool{{}}
	for n := 0; n < len(readings); n++ {
		if n == dockerReadingsMax {
			return "Dockerfile heredocs too many to read each way"
		}
		opens := readings[n]
		lines, docs, joined, unsure := dockerLines(src, func(start int, line string) bool {
			if !strings.ContainsAny(line, "$\\`") {
				return true
			}
			if _, ok := opens[start]; !ok {
				shut := maps.Clone(opens)
				shut[start] = false
				readings = append(readings, shut)
				opens[start] = true
			}
			return opens[start]
		})
		if unsure {
			return "Dockerfile heredoc beside a ${name<op>word} expansion"
		}
		if why := v.dockerReading(file, lines, docs, joined); why != "" {
			return why
		}
	}
	return ""
}

// dockerReading applies the rule to one reading of a Dockerfile: its instructions, the
// heredocs each opens and whether the last is joined, from dockerLines.
func (v *Veto) dockerReading(file string, lines []string, docs map[int][]heredoc, joined bool) string {
	ctxs := []string{filepath.Dir(file)}
	if ctxs[0] != v.root {
		ctxs = append(ctxs, v.root)
	}
	if !joined && v.hasToken(lines[len(lines)-1]) {
		return "install command in an unjoined continuation"
	}
	names := map[string]bool{}
	st := &dockerStage{}
	var deferred []segment
	flush := func() string {
		for _, seg := range deferred {
			cur := &dockerCursor{v: v, st: st, dir: st.wd, known: st.wdKnown}
			if why := v.command(seg, cur, 0); why != "" {
				return why
			}
		}
		deferred = nil
		return ""
	}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' {
			continue
		}
		word, rest, _ := strings.Cut(line, " ")
		instr, rest := strings.ToUpper(word), strings.TrimSpace(rest)
		if hd := docs[i]; hd != nil {
			body, hidden := line, false
			for _, d := range hd {
				var text []string
				for i++; i < len(lines) && !d.ends(lines[i]); i++ {
					body += "\n" + lines[i]
					l := lines[i]
					if d.dash {
						l = strings.TrimLeft(l, "\t")
					}
					text = append(text, l)
				}
				hidden = hidden || v.shellHides(strings.Join(text, "\n"))
			}
			if v.hasToken(body) || hidden {
				return "install command in a heredoc"
			}
			v.mention(strings.Fields(body))
			st.taintAll()
			continue
		}
		hasTok := v.hasToken(rest)
		switch {
		case instr == "FROM":
			if why := flush(); why != "" {
				return why
			}
			st = &dockerStage{}
			f := strings.Fields(rest)
			for len(f) > 0 && strings.HasPrefix(f[0], "--") {
				f = f[1:]
			}
			if len(f) > 0 && names[strings.ToLower(f[0])] {
				st.taintAll() // a stage built on an earlier one holds whatever that one wrote
			}
			if len(f) >= 3 && strings.EqualFold(f[1], "as") {
				names[strings.ToLower(f[2])] = true
			}
		case instr == "WORKDIR":
			p := strings.Trim(rest, `"`)
			if c, ok := st.resolve(p); ok {
				st.wd, st.wdKnown = c, true
			} else {
				st.wdKnown = false
			}
		case instr == "COPY" || instr == "ADD":
			st.copyInstr(v, ctxs, rest, instr == "ADD")
		case instr == "RUN" || instr == "CMD" || instr == "ENTRYPOINT":
			for instr == "RUN" && strings.HasPrefix(rest, "--") {
				_, rest, _ = strings.Cut(rest, " ")
				rest = strings.TrimSpace(rest)
			}
			var segs []segment
			ok := true
			if strings.HasPrefix(rest, "[") {
				segs, ok = execForm(rest)
			} else {
				segs, ok, _ = shellSegments(rest)
			}
			if !ok {
				if hasTok {
					return "install command that does not tokenise"
				}
				v.mention(strings.Fields(rest))
				if instr == "RUN" {
					st.taintAll()
				}
				continue
			}
			if instr != "RUN" {
				deferred = append(deferred, segs...)
				continue
			}
			cur := &dockerCursor{v: v, st: st, dir: st.wd, known: st.wdKnown}
			for _, seg := range segs {
				if why := v.command(seg, cur, 0); why != "" {
					return why
				}
			}
		case dockerPlain[instr]:
		default: // ONBUILD, HEALTHCHECK and anything unknown run elsewhere or not at all
			if v.hasToken(line) {
				return "install command in " + instr
			}
		}
	}
	return flush()
}

// shellHides reports whether text, read as a shell script, holds an installer that only its
// line continuations show.
func (v *Veto) shellHides(text string) bool {
	lines, _, hidden, _ := logicalLinesAt(text, kindShell)
	for _, l := range append(lines, hidden...) {
		if v.hasToken(l) {
			return true
		}
	}
	return false
}
