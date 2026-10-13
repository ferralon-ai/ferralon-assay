package jsanalysis

// installdocker.go follows lockfiles and scripts into container images. A lockfile install
// inside a Dockerfile (RUN, CMD, ENTRYPOINT, HEALTHCHECK) is sound only if the lockfile at its
// working directory in the image is a lockfile the lane read. The image state is simulated per
// stage: WORKDIR, COPY/ADD (with --from a stage, --parents, globs and .dockerignore), and RUN
// bind mounts record where each file in the image came from. Anything the simulation cannot
// pin down (an unknown working directory, a variable path, a RUN that moves files around) makes
// the provenance unknown, and a lockfile install there withholds every refutation. Content the
// scanner cannot see at all withholds every refutation outright: COPY --from an image that is
// not a stage of this Dockerfile, ADD of a URL or git source, and ADD of an archive it would
// extract. A script the image runs by path is read where the simulation says it came from and
// scanned as this stage's shell; one it cannot trace withholds every refutation unless it sits
// in a system bin directory or a node_modules tree.
//
// The build context is not written in the Dockerfile, so the simulation runs once per
// candidate: the Dockerfile's directory, each of its ancestors up to the build dir, and every
// context a compose file, workflow, script or deploy config names. A candidate is dropped only
// when the build could not run with it: a source path it lacks exists in another candidate.
// Everything the remaining candidates find applies.

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var lockNamesOf = map[string][]string{
	"npm":  {"npm-shrinkwrap.json", "package-lock.json"},
	"yarn": {"yarn.lock"},
	"pnpm": {"pnpm-lock.yaml"},
}

func isLockName(n string) bool {
	switch n {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock":
		return true
	}
	return false
}

// dMap records that container path dst holds a context file (srcFile), the contents of a
// context directory (srcDir), or something the scanner cannot see (unknown).
type dMap struct {
	dst     string
	srcFile string
	srcDir  string
	dir     bool
	unknown bool
}

type dStage struct {
	name    string
	workdir string // absolute container path, "" when unknown
	maps    []dMap
	tainted bool // a file move or an unresolvable copy may have replaced any lockfile
	// npmAt maps container directories where a passing npm lockfile install ran to the
	// build-relative lockfile root it installed from, for the runner exception.
	npmAt map[string]string
}

func (s *dStage) clone() *dStage {
	c := *s
	c.maps = append([]dMap(nil), s.maps...)
	c.npmAt = map[string]string{}
	for k, v := range s.npmAt {
		c.npmAt[k] = v
	}
	return &c
}

// dockerRun is one simulation of one Dockerfile under one candidate context.
type dockerRun struct {
	sc       *installScan // collector for this candidate
	file     string
	ctx      string // build-relative context dir
	ignores  []*ignoreSet
	stages   []*dStage
	cur      *dStage
	tmp      []dMap          // RUN --mount maps, live for one instruction
	missing  map[string]bool // source keys absent in this context
	present  map[string]bool
	instrIdx int
}

type dInstr struct {
	op       string
	args     string
	heredocs []string
}

var directiveLine = regexp.MustCompile(`^#\s*([a-zA-Z]+)\s*=\s*(\S+)\s*$`)

// parseDockerfile splits a Dockerfile into instructions, honouring the escape directive,
// line continuations, comments and heredocs.
func parseDockerfile(text string) []dInstr {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	esc := "\\"
	i := 0
	for ; i < len(lines); i++ {
		m := directiveLine.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			break
		}
		if strings.EqualFold(m[1], "escape") && (m[2] == "`" || m[2] == "\\") {
			esc = m[2]
		}
	}
	var out []dInstr
	var cur strings.Builder
	for ; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if strings.HasPrefix(t, "#") || (t == "" && cur.Len() == 0) {
			continue
		}
		if strings.HasSuffix(t, esc) {
			cur.WriteString(strings.TrimSuffix(t, esc) + " ")
			continue
		}
		cur.WriteString(t)
		full := strings.TrimSpace(cur.String())
		cur.Reset()
		if full == "" {
			continue
		}
		op, args, _ := strings.Cut(full, " ")
		in := dInstr{op: strings.ToUpper(op), args: strings.TrimSpace(args)}
		for _, m := range heredocStart.FindAllStringSubmatchIndex(in.args, -1) {
			if m[0] > 0 && in.args[m[0]-1] == '<' {
				continue // a here-string, not a heredoc
			}
			term := in.args[m[2]:m[3]]
			stripTabs := strings.HasPrefix(in.args[m[0]:], "<<-")
			var body []string
			for i++; i < len(lines); i++ {
				l := lines[i]
				if stripTabs {
					l = strings.TrimLeft(l, "\t")
				}
				if strings.TrimRight(l, " \r") == term {
					break
				}
				body = append(body, l)
			}
			in.heredocs = append(in.heredocs, strings.Join(body, "\n"))
		}
		out = append(out, in)
	}
	return out
}

// dockerfile scans one Dockerfile: the prod-keeps-dev check over its text, then the install
// simulation under every candidate context.
func (sc *installScan) dockerfile(f scannedFile) {
	text := string(f.data)
	sc.keepDevText(f.rel, text, true)
	instrs := parseDockerfile(text)
	dir := path.Dir(f.rel)
	if dir == "." {
		dir = ""
	}
	var cands []string
	seen := map[string]bool{}
	addCand := func(c string) {
		if seen[c] {
			return
		}
		if fi, err := os.Stat(filepath.Join(sc.real, filepath.FromSlash(c))); err != nil || !fi.IsDir() {
			return
		}
		seen[c] = true
		cands = append(cands, c)
	}
	for d := dir; ; d = parentDir(d) {
		addCand(d)
		if d == "" {
			break
		}
	}
	for _, c := range sc.contexts {
		addCand(c)
	}
	sort.Strings(cands)

	runs := make([]*dockerRun, 0, len(cands))
	for _, c := range cands {
		cs := &installScan{m: sc.m, installed: sc.installed, real: sc.real, roots: sc.roots, ctxUnknown: sc.ctxUnknown}
		dr := &dockerRun{sc: cs, file: f.rel, ctx: c, missing: map[string]bool{}, present: map[string]bool{}}
		dr.loadIgnores(dir)
		dr.simulate(instrs)
		runs = append(runs, dr)
	}
	for _, dr := range runs {
		dead := false
		for k := range dr.missing {
			for _, other := range runs {
				if other != dr && other.present[k] {
					dead = true
				}
			}
		}
		if dead {
			continue
		}
		if dr.sc.all != "" && sc.all == "" {
			sc.all = dr.sc.all
		}
		sc.keepDev = append(sc.keepDev, dr.sc.keepDev...)
	}
}

func (dr *dockerRun) veto(why string) {
	label := dr.ctx
	if label == "" {
		label = "."
	}
	dr.sc.vetoAll(dr.file, why+" (build context "+label+")")
}

func (dr *dockerRun) simulate(instrs []dInstr) {
	dr.cur = &dStage{}
	for i, in := range instrs {
		dr.instrIdx = i
		switch in.op {
		case "FROM":
			dr.from(in.args)
		case "WORKDIR":
			dr.cur.workdir = dr.containerPath(in.args)
		case "COPY", "ADD":
			dr.copy(in)
		case "RUN":
			dr.run(in)
		case "CMD", "ENTRYPOINT":
			dr.exec(jsonCommand(in.args))
		case "HEALTHCHECK":
			if _, cmd, ok := strings.Cut(in.args, "CMD "); ok {
				dr.exec(jsonCommand(cmd))
			}
		case "ONBUILD":
			inner, rest, _ := strings.Cut(in.args, " ")
			if strings.EqualFold(inner, "RUN") {
				// Runs in a child build whose image state the scanner cannot see.
				saved := dr.cur
				dr.cur = &dStage{tainted: true}
				dr.exec(rest)
				dr.cur = saved
			}
		}
	}
}

func (dr *dockerRun) from(args string) {
	f := strings.Fields(args)
	var img, name string
	for i := 0; i < len(f); i++ {
		switch {
		case strings.HasPrefix(f[i], "--"):
		case strings.EqualFold(f[i], "AS") && i+1 < len(f):
			name = f[i+1]
			i++
		case img == "":
			img = f[i]
		}
	}
	st := &dStage{}
	if prior := dr.stage(img); prior != nil {
		st = prior.clone()
	} else if dynamicTok(img) {
		st.tainted = true // a variable may name an earlier stage
	}
	st.name = strings.ToLower(name)
	dr.stages = append(dr.stages, st)
	dr.cur = st
}

// stage resolves a stage reference by name or index.
func (dr *dockerRun) stage(ref string) *dStage {
	ref = strings.ToLower(ref)
	for i := len(dr.stages) - 1; i >= 0; i-- {
		if dr.stages[i].name != "" && dr.stages[i].name == ref {
			return dr.stages[i]
		}
	}
	if n, ok := atoi(ref); ok && n < len(dr.stages) {
		return dr.stages[n]
	}
	return nil
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// containerPath resolves p against the stage's working directory: "" when unknown.
func (dr *dockerRun) containerPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" || dynamicTok(p) {
		return ""
	}
	if strings.HasPrefix(p, "/") {
		return path.Clean(p)
	}
	if dr.cur.workdir == "" {
		return ""
	}
	return path.Join(dr.cur.workdir, p)
}

// splitInstrArgs splits COPY/ADD/RUN arguments into leading --flags and the rest (JSON exec
// form or whitespace words).
func splitInstrArgs(args string) (flags map[string][]string, words []string) {
	flags = map[string][]string{}
	f := strings.Fields(args)
	i := 0
	for ; i < len(f) && strings.HasPrefix(f[i], "--"); i++ {
		k, v, _ := strings.Cut(f[i], "=")
		flags[k] = append(flags[k], v)
	}
	rest := strings.TrimSpace(strings.Join(f[i:], " "))
	if strings.HasPrefix(rest, "[") {
		if j := jsonCommand(rest); j != rest {
			return flags, strings.Fields(j)
		}
	}
	return flags, f[i:]
}

func (dr *dockerRun) copy(in dInstr) {
	flags, words := splitInstrArgs(in.args)
	if len(words) < 2 {
		dr.cur.tainted = true
		return
	}
	srcs, destRaw := words[:len(words)-1], words[len(words)-1]
	dest := dr.containerPath(destRaw)
	if dest == "" {
		dr.cur.tainted = true
		return
	}
	destIsDir := len(srcs) > 1 || strings.HasSuffix(destRaw, "/") || destRaw == "." || strings.HasSuffix(destRaw, "/.")
	unknownAt := func(dst string) { dr.cur.maps = append(dr.cur.maps, dMap{dst: dst, unknown: true}) }
	if len(flags["--exclude"]) > 0 {
		unknownAt(dest) // an excluded lockfile would be absent where the simulation puts one
		return
	}
	parents := len(flags["--parents"]) > 0
	if from := flags["--from"]; len(from) > 0 {
		src := dr.stage(from[0])
		if src == nil || dynamicTok(from[0]) {
			dr.veto("COPY --from=" + from[0] + ": copies from an image the scanner cannot see")
			return
		}
		for _, s := range srcs {
			if dynamicTok(s) || !strings.HasPrefix(s, "/") && src.workdir == "" {
				unknownAt(dest)
				continue
			}
			sp := s
			if !strings.HasPrefix(sp, "/") {
				sp = path.Join(src.workdir, sp)
			}
			dr.translate(src, path.Clean(sp), dest, destIsDir)
		}
		return
	}
	add := in.op == "ADD"
	for _, raw := range srcs {
		s := strings.Trim(raw, `"'`)
		lower := strings.ToLower(s)
		switch {
		case strings.HasPrefix(s, "<<"):
			unknownAt(dest)
			continue
		case dynamicTok(s):
			unknownAt(dest)
			continue
		case add && (strings.Contains(s, "://") || strings.HasPrefix(s, "git@")):
			dr.veto("ADD " + s + ": adds a remote source the scanner cannot see")
			return
		}
		rel := joinRel(dr.ctx, strings.TrimPrefix(s, "/"))
		if rel == "." {
			rel = ""
		}
		if rel == ".." || strings.HasPrefix(rel, "../") {
			unknownAt(dest)
			continue
		}
		key := in.op + "\x00" + strconv.Itoa(dr.instrIdx) + "\x00" + s
		var matches []string
		if hasGlob(s) {
			got, _ := filepath.Glob(filepath.Join(dr.sc.real, filepath.FromSlash(rel)))
			for _, g := range got {
				r, _ := filepath.Rel(dr.sc.real, g)
				r = filepath.ToSlash(r)
				if !dr.ignored(r, false) {
					matches = append(matches, r)
				}
			}
		} else if _, err := os.Stat(filepath.Join(dr.sc.real, filepath.FromSlash(rel))); err == nil && !dr.ignored(rel, false) {
			matches = []string{rel}
		}
		if len(matches) == 0 {
			dr.missing[key] = true
			unknownAt(dest)
			continue
		}
		dr.present[key] = true
		for _, mt := range matches {
			fi, err := os.Stat(filepath.Join(dr.sc.real, filepath.FromSlash(mt)))
			if err != nil {
				unknownAt(dest)
				continue
			}
			sub := strings.TrimPrefix(strings.TrimPrefix(mt, dr.ctx), "/")
			if fi.IsDir() {
				dst := dest
				if parents {
					dst = path.Join(dest, sub)
				}
				dr.cur.maps = append(dr.cur.maps, dMap{dst: dst, srcDir: mt, dir: true})
				dr.nodeModulesCopied(mt)
				continue
			}
			if add && (strings.HasSuffix(lower, ".tar") || strings.Contains(lower, ".tar.") || strings.HasSuffix(lower, ".tgz") ||
				strings.HasSuffix(lower, ".txz") || strings.HasSuffix(lower, ".tbz2")) {
				dr.veto("ADD " + s + ": extracts an archive whose contents the scanner cannot see")
				return
			}
			dst := dest
			switch {
			case parents:
				dst = path.Join(dest, sub)
			case destIsDir:
				dst = path.Join(dest, path.Base(mt))
			}
			dr.cur.maps = append(dr.cur.maps, dMap{dst: dst, srcFile: mt})
		}
	}
}

// translate copies the provenance of src's path sp into the current stage at dest.
func (dr *dockerRun) translate(src *dStage, sp, dest string, destIsDir bool) {
	if src.tainted {
		dr.cur.tainted = true
	}
	for _, m := range src.maps {
		switch {
		case m.dst == sp || strings.HasPrefix(m.dst, sp+"/"):
			dst := dest
			if m.dst != sp {
				dst = path.Join(dest, strings.TrimPrefix(m.dst, sp+"/"))
			} else if !m.dir && !m.unknown && destIsDir {
				dst = path.Join(dest, path.Base(sp))
			}
			m.dst = dst
			dr.cur.maps = append(dr.cur.maps, m)
		case strings.HasPrefix(sp, m.dst+"/") && (m.dir || m.unknown):
			sub := strings.TrimPrefix(sp, m.dst+"/")
			n := dMap{dst: dest, unknown: m.unknown}
			if m.dir {
				if fi, err := os.Stat(filepath.Join(dr.sc.real, filepath.FromSlash(joinRel(m.srcDir, sub)))); err == nil && fi.IsDir() {
					n.dir, n.srcDir = true, normRel(joinRel(m.srcDir, sub))
				} else {
					n.srcFile = normRel(joinRel(m.srcDir, sub))
					if destIsDir {
						n.dst = path.Join(dest, path.Base(sp))
					}
				}
			}
			dr.cur.maps = append(dr.cur.maps, n)
		}
	}
}

func normRel(r string) string {
	if r == "." {
		return ""
	}
	return r
}

var bindMountKey = regexp.MustCompile(`^(type|source|src|target|dst|destination|from)=(.*)$`)

func (dr *dockerRun) run(in dInstr) {
	flags, words := splitInstrArgs(in.args)
	dr.tmp = nil
	for _, spec := range flags["--mount"] {
		kv := map[string]string{"type": "bind"}
		for _, part := range strings.Split(spec, ",") {
			if m := bindMountKey.FindStringSubmatch(part); m != nil {
				k := m[1]
				switch k {
				case "src":
					k = "source"
				case "dst", "destination":
					k = "target"
				}
				kv[k] = m[2]
			}
		}
		target := dr.containerPath(kv["target"])
		if target == "" {
			dr.cur.tainted = true
			continue
		}
		if kv["type"] != "bind" || kv["from"] != "" {
			dr.tmp = append(dr.tmp, dMap{dst: target, unknown: true})
			continue
		}
		srcRel := normRel(joinRel(dr.ctx, strings.TrimPrefix(kv["source"], "/")))
		if kv["source"] == "" {
			srcRel = dr.ctx
		}
		if dynamicTok(kv["source"]) || srcRel == ".." || strings.HasPrefix(srcRel, "../") {
			dr.tmp = append(dr.tmp, dMap{dst: target, unknown: true})
			continue
		}
		fi, err := os.Stat(filepath.Join(dr.sc.real, filepath.FromSlash(srcRel)))
		switch {
		case err != nil:
			dr.tmp = append(dr.tmp, dMap{dst: target, unknown: true})
		case fi.IsDir():
			dr.tmp = append(dr.tmp, dMap{dst: target, srcDir: srcRel, dir: true})
		default:
			dr.tmp = append(dr.tmp, dMap{dst: target, srcFile: srcRel})
		}
	}
	text := strings.Join(words, " ")
	for _, h := range in.heredocs {
		text += "\n" + h
	}
	dr.exec(text)
	dr.tmp = nil
}

// exec scans shell text run in the current stage.
func (dr *dockerRun) exec(text string) {
	dir := cwd{unknown: true}
	if dr.cur.workdir != "" {
		dir = knownDirs(dr.cur.workdir)
	}
	dr.sc.shell(text, shellCtx{file: dr.file, dir: dir, docker: dr})
}

// lockMove taints the stage when a RUN command may replace or create a lockfile the
// simulation tracks: a file move or copy naming one, a recursive copy, an archive extraction,
// a git checkout, or a download.
func (dr *dockerRun) lockMove(tool string, args []string) {
	names := false
	for _, a := range args {
		if isLockName(path.Base(cleanTok(a))) {
			names = true
		}
	}
	switch tool {
	case "mv", "rsync", "unzip", "bsdtar", "7z", "curl", "wget":
		if tool == "mv" || tool == "rsync" || tool == "unzip" || tool == "bsdtar" || tool == "7z" || names {
			dr.cur.tainted = true
		}
	case "cp", "ln", "install":
		if names {
			dr.cur.tainted = true
		}
		for _, a := range args {
			a = cleanTok(a)
			if a == "-r" || a == "-R" || a == "-a" || a == "--recursive" || a == "--archive" ||
				(strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a, "rRa")) {
				dr.cur.tainted = true
			}
		}
	case "tar":
		for _, a := range args {
			a = cleanTok(a)
			if a == "--extract" || a == "--get" || (!strings.HasPrefix(a, "--") && strings.Contains(strings.TrimPrefix(a, "-"), "x")) {
				dr.cur.tainted = true
			}
		}
	case "git":
		for _, a := range args {
			switch cleanTok(a) {
			case "clone", "checkout", "pull", "reset", "switch", "restore", "apply", "am", "merge", "stash", "worktree":
				dr.cur.tainted = true
			}
		}
	}
}

// systemBins are the image directories a base image's own scripts live in.
var systemBins = map[string]bool{"/bin": true, "/usr/bin": true, "/usr/local/bin": true, "/sbin": true, "/usr/sbin": true, "/usr/local/sbin": true}

// script reads a script the image runs by path (a shell with a script argument, or a command
// named by a path) and scans it as shell in this stage and working directory.
func (dr *dockerRun) script(tool, head string, args []string, dir cwd, ctx *shellCtx, line string) {
	var p string
	switch tool {
	case "sh", "bash", "zsh", "dash", "ash", "ksh":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				p = cleanTok(a)
				break
			}
		}
	default:
		if h := cleanTok(head); strings.Contains(h, "/") {
			p = h
		}
	}
	if p == "" || strings.Contains("/"+p+"/", "/node_modules/") {
		return
	}
	cp := dr.containerPath(p)
	if cp == "" {
		dr.veto(line + ": runs a script at a path the scanner cannot resolve")
		return
	}
	if dr.cur.tainted {
		dr.veto(line + ": runs " + cp + ", which a file move or unresolved copy may have replaced")
		return
	}
	src, unknown := dr.provenance(cp)
	switch {
	case unknown:
		dr.veto(line + ": runs " + cp + ", which comes from a source the scanner cannot see")
	case src == "":
		if !systemBins[path.Dir(cp)] {
			dr.veto(line + ": runs " + cp + ", which the scanner cannot trace to the build context")
		}
	case ctx.depth >= 8:
		dr.veto(line + ": scripts nest too deep to follow")
	default:
		data, err := readRegular(filepath.Join(dr.sc.real, filepath.FromSlash(src)))
		if err != nil {
			dr.veto(line + ": runs " + src + ", which is unreadable")
			return
		}
		dr.sc.shell(string(data), shellCtx{file: dr.file + " (" + src + ")", dir: dir, docker: dr, depth: ctx.depth + 1})
	}
}

// argless checks a lockfile install in the image: at every working directory it may run in,
// the dialect's lockfile must come from a lane-read lockfile of that dialect.
func (dr *dockerRun) argless(sc *installScan, dialect string, dir cwd, line string, frozen bool) {
	switch {
	case sc.ctxUnknown != "":
		dr.veto(line + ": a docker build context (" + sc.ctxUnknown + ") is not resolved, so the image's lockfile is unknown")
		return
	case dr.cur.tainted:
		dr.veto(line + ": the image's lockfile may have been replaced (unresolved copy, move or base stage)")
		return
	case dir.unknown || len(dir.dirs) == 0:
		dr.veto(line + ": installs from a lockfile in an image directory the scanner cannot determine")
		return
	}
	names := lockNamesOf[dialect]
	if len(names) == 0 {
		dr.veto(line + ": the lane does not read " + dialect + "'s lockfile")
		return
	}
	for _, d := range dir.dirs {
		found := false
		for _, n := range names {
			src, unknown := dr.provenance(path.Join(d, n))
			switch {
			case unknown:
				dr.veto(line + ": " + path.Join(d, n) + " in the image comes from a source the scanner cannot see")
				return
			case src == "":
				continue
			}
			found = true
			root := normRel(path.Dir(src))
			if !slicesContains(names, path.Base(src)) {
				dr.veto(line + ": " + path.Join(d, n) + " in the image is " + src + ", not a " + dialect + " lockfile")
				return
			}
			if sc.checkRoot(dr.file, line, dialect, root) && dialect == "npm" {
				if dr.cur.npmAt == nil {
					dr.cur.npmAt = map[string]string{}
				}
				dr.cur.npmAt[d] = root
			}
		}
		if !found {
			dr.veto(line + ": no " + dialect + " lockfile at " + d + " in the image")
			return
		}
	}
}

// provenance returns the build-relative source of container file p, "" when nothing the
// simulation tracks puts a file there, or unknown.
func (dr *dockerRun) provenance(p string) (src string, unknown bool) {
	maps := append(append([]dMap(nil), dr.cur.maps...), dr.tmp...)
	for i := len(maps) - 1; i >= 0; i-- {
		m := maps[i]
		under := p == m.dst || strings.HasPrefix(p, m.dst+"/") || m.dst == "/"
		switch {
		case !under:
		case m.unknown:
			return "", true
		case !m.dir:
			if p == m.dst {
				return m.srcFile, false
			}
		default:
			s := normRel(joinRel(m.srcDir, strings.TrimPrefix(strings.TrimPrefix(p, m.dst), "/")))
			if fi, err := os.Stat(filepath.Join(dr.sc.real, filepath.FromSlash(s))); err == nil && !fi.IsDir() && !dr.ignored(s, false) {
				return s, false
			}
		}
	}
	return "", false
}

// nodeModulesCopied records a prod-keeps-dev hit when a directory copy takes a lockfile
// root's node_modules into the image: whatever the build machine installed, dev dependencies
// included, ships.
func (dr *dockerRun) nodeModulesCopied(srcDir string) {
	for _, r := range dr.sc.roots {
		if srcDir != "" && r != srcDir && !strings.HasPrefix(r, srcDir+"/") {
			continue
		}
		nm := joinRel(r, "node_modules")
		if r == "" {
			nm = "node_modules"
		}
		if !dr.ignored(nm, true) {
			label := dr.ctx
			if label == "" {
				label = "."
			}
			dr.sc.hit(dr.file, "copies "+nm+" into the image (not excluded by .dockerignore, build context "+label+")")
			return
		}
	}
}

// --- .dockerignore ----------------------------------------------------------------------

type ignoreRule struct {
	re     *regexp.Regexp
	negate bool
}

type ignoreSet struct{ rules []ignoreRule }

// loadIgnores reads the ignore files for this context: the Dockerfile-specific
// <Dockerfile>.dockerignore beside it (which replaces the context's .dockerignore), and
// .containerignore.
func (dr *dockerRun) loadIgnores(dfDir string) {
	read := func(rel string) {
		data, err := readRegular(filepath.Join(dr.sc.real, filepath.FromSlash(rel)))
		if os.IsNotExist(err) {
			return
		}
		if err != nil {
			dr.sc.vetoAll(rel, "unreadable")
			dr.sc.hit(rel, "unreadable")
			return
		}
		dr.ignores = append(dr.ignores, parseIgnore(string(data)))
	}
	specific := normRel(joinRel(dfDir, path.Base(dr.file)+".dockerignore"))
	if _, err := os.Stat(filepath.Join(dr.sc.real, filepath.FromSlash(specific))); err == nil {
		read(specific)
	} else {
		read(normRel(joinRel(dr.ctx, ".dockerignore")))
	}
	read(normRel(joinRel(dr.ctx, ".containerignore")))
}

func parseIgnore(text string) *ignoreSet {
	s := &ignoreSet{}
	for _, line := range strings.Split(text, "\n") {
		p := strings.TrimSpace(line)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		p = strings.Trim(path.Clean("/"+strings.TrimSpace(p)), "/")
		if p == "" || p == "." {
			continue
		}
		s.rules = append(s.rules, ignoreRule{re: regexp.MustCompile("^" + globRegex(p) + "$"), negate: neg})
	}
	return s
}

// globRegex converts a Go-style glob with ** to a regular expression over '/'-paths.
func globRegex(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		case c == '[':
			j := strings.IndexByte(p[i:], ']')
			if j < 0 {
				b.WriteString(`\[`)
				continue
			}
			cls := p[i+1 : i+j]
			if strings.HasPrefix(cls, "^") || strings.HasPrefix(cls, "!") {
				cls = "^" + cls[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(cls, `\`, `\\`) + "]")
			i += j
		case c == '\\' && i+1 < len(p):
			i++
			b.WriteString(regexp.QuoteMeta(string(p[i])))
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

// ignores reports whether rel (context-relative) is excluded: the last rule matching rel or
// one of its parents decides.
func (s *ignoreSet) ignores(rel string) bool {
	out := false
	for _, r := range s.rules {
		for p := rel; p != ""; p = parentDir(p) {
			if r.re.MatchString(p) {
				out = !r.negate
				break
			}
		}
	}
	return out
}

// ignored reports whether build-relative path rel is outside the context's view. With all
// false (lockfiles) one ignore set excluding it is enough, so the simulation never counts a
// lockfile the image may lack; with all true (node_modules) every set must exclude it, so a
// tree the image may receive is never assumed absent.
func (dr *dockerRun) ignored(rel string, all bool) bool {
	cr := rel
	if dr.ctx != "" {
		if rel != dr.ctx && !strings.HasPrefix(rel, dr.ctx+"/") {
			return false
		}
		cr = strings.TrimPrefix(strings.TrimPrefix(rel, dr.ctx), "/")
	}
	if cr == "" {
		return false
	}
	if len(dr.ignores) == 0 {
		return false
	}
	for _, s := range dr.ignores {
		got := s.ignores(cr)
		if got && !all {
			return true
		}
		if !got && all {
			return false
		}
	}
	return all
}
