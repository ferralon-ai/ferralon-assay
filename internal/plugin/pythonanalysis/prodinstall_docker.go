package pythonanalysis

// Dockerfiles as install surfaces. Every RUN, CMD, ENTRYPOINT and HEALTHCHECK is a production
// command. A requirement file a command names is placed through the stage's WORKDIR and the
// COPY/ADD instructions and bind mounts that put files in the image; the build context is the
// Dockerfile's directory or the repository root, and a file that could come from either, with
// different content, vetoes. COPY --from or RUN --mount from an image the Dockerfile does not
// build vetoes, and a FROM image outside the official library is recorded for disclosure: its
// own packages are not read.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type dockerfile struct {
	sc     *installScan
	rel    string
	stages []*dockerStage
}

type dockerStage struct {
	name       string
	base       *dockerStage
	cwd        string
	cwdUnknown bool
	copies     []dockerCopy
	writes     []fileWrite // RUN commands that may change files, in order
}

// dockerCopy is one COPY, ADD or bind mount: its sources, relative to the build context or to
// the from stage's root, and its absolute destination.
type dockerCopy struct {
	srcs        []string
	dest        string
	destUnknown bool
	dirDest     bool
	parents     bool
	from        *dockerStage
	inline      bool // a heredoc
	remote      bool // a URL or git source
}

// dockerRunCtx is what one command in an image sees.
type dockerRunCtx struct {
	df         *dockerfile
	stage      *dockerStage
	cwd        string
	cwdUnknown bool
	mounts     []dockerCopy
	build      bool        // a RUN: what it writes stays in the stage
	runStart   int         // the stage's writes before this RUN
	local      []fileWrite // what a CMD, ENTRYPOINT or HEALTHCHECK writes, while it runs
}

var dockerInstruction = regexp.MustCompile(`^\s*([A-Za-z]+)(?:\s+(.*))?$`)

// heredocRe matches a heredoc opener: <<EOF, <<-EOF, <<"EOF".
var heredocRe = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`)

func (sc *installScan) scanDockerfile(rel, text string) {
	df := &dockerfile{sc: sc, rel: rel}
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		start := i
		line := lines[i]
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		for strings.HasSuffix(strings.TrimRight(line, " \t\r"), "\\") && i+1 < len(lines) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t\r"), "\\") + " "
			i++
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "#") {
				i++
			}
			if i < len(lines) {
				line += lines[i]
			}
		}
		var heredocs []string
		for _, m := range heredocRe.FindAllStringSubmatch(line, -1) {
			var body []string
			for i+1 < len(lines) {
				i++
				if strings.TrimSpace(lines[i]) == m[1] {
					break
				}
				body = append(body, lines[i])
			}
			heredocs = append(heredocs, strings.Join(body, "\n"))
		}
		c := scanCtx{file: rel, where: fmt.Sprintf("%s:%d", rel, start+1), prod: true}
		df.instruction(c, strings.TrimSpace(line), heredocs)
	}
}

func (df *dockerfile) current() *dockerStage {
	if len(df.stages) == 0 {
		df.stages = append(df.stages, &dockerStage{cwd: "/"})
	}
	return df.stages[len(df.stages)-1]
}

// stageRef resolves a --from value to a stage of this Dockerfile, by name or index.
func (df *dockerfile) stageRef(ref string) *dockerStage {
	for _, s := range df.stages {
		if s.name != "" && strings.EqualFold(s.name, ref) {
			return s
		}
	}
	if n, err := strconv.Atoi(ref); err == nil && n >= 0 && n < len(df.stages)-1 {
		return df.stages[n]
	}
	return nil
}

func (df *dockerfile) instruction(c scanCtx, line string, heredocs []string) {
	sc := df.sc
	m := dockerInstruction.FindStringSubmatch(line)
	if m == nil {
		sc.lineCheck(c, line)
		return
	}
	args := m[2]
	switch strings.ToUpper(m[1]) {
	case "FROM":
		df.from(c, args)
	case "WORKDIR":
		st := df.current()
		d := strings.Trim(strings.TrimSpace(args), `"'`)
		switch {
		case strings.ContainsAny(d, "$`"):
			st.cwdUnknown = true
		case path.IsAbs(d):
			st.cwd, st.cwdUnknown = path.Clean(d), false
		default:
			st.cwd = path.Join(st.cwd, d)
		}
	case "COPY", "ADD":
		df.copy(c, args, heredocs)
	case "RUN":
		df.run(c, args, heredocs)
	case "CMD", "ENTRYPOINT":
		df.shell(c, args, nil, heredocs, false)
	case "HEALTHCHECK":
		if i := strings.Index(strings.ToUpper(args), "CMD"); i >= 0 {
			df.shell(c, args[i+3:], nil, heredocs, false)
		}
	case "ONBUILD":
		df.instruction(c, args, heredocs)
	case "ENV", "ARG", "LABEL", "EXPOSE", "USER", "VOLUME", "STOPSIGNAL", "SHELL", "MAINTAINER":
		sc.lineCheck(c, line)
	default:
		df.shell(c, line, nil, heredocs, false)
	}
}

// lineCheck vetoes a line that carries an installer token outside any command.
func (sc *installScan) lineCheck(c scanCtx, line string) {
	if installCommandRe.MatchString(line) {
		sc.veto(c, "an install command the scanner does not parse")
	}
}

var officialImageRe = regexp.MustCompile(`^(?:docker\.io/)?(?:library/)?[a-z0-9][a-z0-9._-]*(?::[\w.-]+)?(?:@sha256:[0-9a-f]+)?$`)

func (df *dockerfile) from(c scanCtx, args string) {
	f := strings.Fields(args)
	var image, name string
	for i := 0; i < len(f); i++ {
		if strings.HasPrefix(f[i], "--") {
			continue
		}
		if image == "" {
			image = f[i]
			continue
		}
		if strings.EqualFold(f[i], "as") && i+1 < len(f) {
			name = f[i+1]
			break
		}
	}
	st := &dockerStage{name: name, cwd: "/"}
	if base := df.stageRef(image); base != nil && !isDigits(image) {
		st.base, st.cwd, st.cwdUnknown = base, base.cwd, base.cwdUnknown
	} else if image != "" && !strings.EqualFold(image, "scratch") && (strings.ContainsAny(image, "$`") || !officialImageRe.MatchString(image)) {
		df.sc.images[image] = true
	}
	df.stages = append(df.stages, st)
}

func isDigits(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// installerConfigDest returns why a COPY or ADD to dest withholds: it places a file where pip
// or uv reads configuration (pip.conf or pip.ini in /etc, /etc/xdg/pip, ~/.pip, ~/.config/pip
// or a virtual environment; uv.toml in /etc/uv or ~/.config/uv), or a single source under a
// file name the scanner cannot read.
func installerConfigDest(dest string, dirDest bool, srcs []string) string {
	if dirDest {
		return ""
	}
	base := strings.ToLower(path.Base(dest))
	switch {
	case installerConfigNames[base]:
		return fmt.Sprintf("places %s, an installer configuration file the scanner does not read", dest)
	case strings.ContainsAny(base, "$`") && len(srcs) == 1 && path.Clean(srcs[0]) != ".":
		return fmt.Sprintf("copies to %s, a file name the scanner cannot read: it may be an installer configuration file", dest)
	}
	return ""
}

// installerConfigNames are the file names pip and uv read configuration from.
var installerConfigNames = setOf("pip.conf", "pip.ini", "uv.toml")

var copyFlagsWithValue = setOf("--from", "--chown", "--chmod", "--exclude", "--checksum")
var copyFlags = setOf("--link", "--parents", "--keep-git-dir")

func (df *dockerfile) copy(c scanCtx, args string, heredocs []string) {
	sc := df.sc
	st := df.current()
	var words []string
	cp := dockerCopy{}
	rest := strings.TrimSpace(args)
	for strings.HasPrefix(rest, "--") {
		flag, after, _ := strings.Cut(rest, " ")
		name, val, eq := strings.Cut(flag, "=")
		switch {
		case copyFlags[name] && !eq:
			cp.parents = cp.parents || name == "--parents"
		case copyFlagsWithValue[name] && eq:
			if name == "--from" {
				if strings.Contains(val, "://") || strings.ContainsAny(val, "$`") {
					sc.veto(c, "copies from %s, which the scanner does not read", val)
					return
				}
				from := df.stageRef(val)
				if from == nil {
					sc.veto(c, "copies from %s, an image the scanner does not read", val)
					return
				}
				cp.from = from
			}
		default:
			sc.veto(c, "COPY option %s is not parsed", name)
			return
		}
		rest = strings.TrimSpace(after)
	}
	if strings.HasPrefix(rest, "[") {
		words = shellTokens(rest)
	} else {
		words = strings.Fields(rest)
	}
	if len(words) < 2 {
		sc.veto(c, "COPY with no destination the scanner can read")
		return
	}
	dest := words[len(words)-1]
	for _, s := range words[:len(words)-1] {
		switch {
		case heredocRe.MatchString(s):
			cp.inline = true
		case strings.Contains(s, "://") || strings.HasPrefix(s, "git@"):
			cp.remote = true
		default:
			cp.srcs = append(cp.srcs, strings.TrimPrefix(path.Clean(s), "/"))
		}
	}
	cp.dirDest = strings.HasSuffix(dest, "/") || len(words) > 2 || dest == "."
	if why := installerConfigDest(dest, cp.dirDest, words[:len(words)-1]); why != "" {
		sc.veto(c, "%s", why)
		return
	}
	switch {
	case strings.ContainsAny(dest, "$`") || (!path.IsAbs(dest) && st.cwdUnknown):
		cp.destUnknown = true
	case path.IsAbs(dest):
		cp.dest = path.Clean(dest)
	default:
		cp.dest = path.Join(st.cwd, dest)
	}
	st.copies = append(st.copies, cp)
	_ = heredocs
}

var mountFlagRe = regexp.MustCompile(`^--(mount|network|security|device)=(\S+)\s*`)

func (df *dockerfile) run(c scanCtx, args string, heredocs []string) {
	var mounts []dockerCopy
	rest := strings.TrimSpace(args)
	for {
		m := mountFlagRe.FindStringSubmatch(rest)
		if m == nil {
			break
		}
		rest = rest[len(m[0]):]
		if m[1] != "mount" {
			continue
		}
		mount, ok := df.mount(c, m[2])
		if !ok {
			return
		}
		if mount != nil {
			mounts = append(mounts, *mount)
		}
	}
	if strings.HasPrefix(rest, "--") {
		flag, _, _ := strings.Cut(rest, " ")
		df.sc.veto(c, "RUN option %s is not parsed", flag)
		return
	}
	df.shell(c, rest, mounts, heredocs, true)
}

// mount reads a RUN --mount value: a bind mount is a transient copy; cache, tmpfs, secret and
// ssh mounts place no repository file.
func (df *dockerfile) mount(c scanCtx, spec string) (*dockerCopy, bool) {
	kv := map[string]string{}
	for _, p := range strings.Split(spec, ",") {
		k, v, _ := strings.Cut(p, "=")
		kv[k] = v
	}
	typ := kv["type"]
	if typ == "" {
		typ = "bind"
	}
	if typ != "bind" {
		if typ == "cache" && kv["from"] != "" && df.stageRef(kv["from"]) == nil {
			df.sc.veto(c, "mounts %s, an image the scanner does not read", kv["from"])
			return nil, false
		}
		return nil, true
	}
	target := kv["target"]
	if target == "" {
		target = kv["dst"]
	}
	if target == "" {
		target = kv["destination"]
	}
	cp := &dockerCopy{dirDest: true}
	st := df.current()
	switch {
	case target == "" || strings.ContainsAny(target, "$`") || (!path.IsAbs(target) && st.cwdUnknown):
		cp.destUnknown = true
	case path.IsAbs(target):
		cp.dest = path.Clean(target)
	default:
		cp.dest = path.Join(st.cwd, target)
	}
	src := kv["source"]
	if src == "" {
		src = kv["src"]
	}
	if src == "" {
		src = "."
	}
	cp.srcs = []string{strings.TrimPrefix(path.Clean(src), "/")}
	cp.dirDest = false // a bind mount places its source at the target exactly
	if from := kv["from"]; from != "" {
		stage := df.stageRef(from)
		if stage == nil {
			df.sc.veto(c, "mounts from %s, an image the scanner does not read", from)
			return nil, false
		}
		cp.from = stage
	}
	return cp, true
}

// shell scans a command (or its heredoc bodies) as production shell in the image; build
// reports a RUN, which runs while the image is built.
func (df *dockerfile) shell(c scanCtx, cmd string, mounts []dockerCopy, heredocs []string, build bool) {
	st := df.current()
	run := &dockerRunCtx{df: df, stage: st, cwd: st.cwd, cwdUnknown: st.cwdUnknown, mounts: mounts, build: build, runStart: len(st.writes)}
	c.st = &textState{bases: []string{"."}, docker: run}
	if len(heredocs) > 0 {
		cmd = heredocRe.ReplaceAllString(cmd, "")
	}
	if strings.TrimSpace(cmd) != "" {
		df.sc.scanLine(c, cmd)
	}
	for _, body := range heredocs {
		df.sc.scanText(c, body)
	}
}

// locate returns the build-context paths that put the container path p in place, latest copy
// first, keeping only those that exist; why says why none can be named.
func (r *dockerRunCtx) locate(p string) (srcs []string, why string) {
	if strings.ContainsAny(p, "$`") {
		return nil, "is a variable or substitution"
	}
	cp := path.Clean(p)
	if !path.IsAbs(cp) {
		if r.cwdUnknown {
			return nil, "is read after a change of directory the scanner cannot follow"
		}
		cp = path.Join(r.cwd, cp)
	}
	var wins []writeWindow
	srcs, why, found, _ := r.df.resolve(r.mounts, cp, 0, &wins)
	if why != "" {
		return nil, why
	}
	// A bind mount is placed when this command starts; a copy, when its COPY runs.
	ws := append(windowWrites(wins), r.local...)
	if found {
		ws = append(ws, r.stage.writes[r.runStart:]...)
	} else {
		srcs, why, found = r.df.resolveStage(r.stage, cp, 0, &wins)
		if why != "" {
			return nil, why
		}
		if !found {
			return nil, "is not copied into the image"
		}
		ws = append(windowWrites(wins), r.local...)
	}
	if w := changedBy(ws, cp); w != nil {
		return nil, fmt.Sprintf("may be changed after it is placed: %s runs %s, which is not known to leave it as it is", w.where, w.what)
	}
	return srcs, ""
}

// resolveStage finds the latest copy in st or a stage it builds on that places cp, and adds to
// wins the writes that run after it: the rest of that stage, and every stage built on it.
func (df *dockerfile) resolveStage(st *dockerStage, cp string, depth int, wins *[]writeWindow) ([]string, string, bool) {
	var after []*dockerStage
	for s := st; s != nil; s = s.base {
		srcs, why, found, idx := df.resolve(s.copies, cp, depth, wins)
		if why != "" {
			return nil, why, false
		}
		if found {
			if why := df.placedOnce(s, idx, cp, srcs); why != "" {
				return nil, why, false
			}
			for _, a := range after {
				*wins = append(*wins, writeWindow{a, -1})
			}
			*wins = append(*wins, writeWindow{s, idx})
			return srcs, "", true
		}
		after = append(after, s)
	}
	return nil, "", false
}

// placedOnce returns why cp withholds when a COPY before s.copies[idx], in s or a stage it
// builds on, also places it from anything other than srcs: which content lands is then
// unknown (a .dockerignore can leave the later copy without it).
func (df *dockerfile) placedOnce(s *dockerStage, idx int, cp string, srcs []string) string {
	for st, n := s, idx; st != nil; st, n = st.base, -1 {
		if n < 0 {
			n = len(st.copies)
		}
		for i := n - 1; i >= 0; i-- {
			c := st.copies[i]
			if c.destUnknown {
				return "may also be placed by a COPY whose destination the scanner cannot read"
			}
			cands := copyCandidates(c, cp)
			if len(cands) == 0 {
				continue
			}
			if c.inline || c.remote || c.from != nil {
				return "is placed by more than one COPY, which may differ"
			}
			var out []string
			for _, cand := range cands {
				if df.sc.contextFile(df.rel, cand) {
					out = append(out, cand)
				}
			}
			if len(out) > 0 && !sameStrings(out, srcs) {
				return "is placed by more than one COPY of different files"
			}
		}
	}
	return ""
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !containsString(b, x) {
			return false
		}
	}
	return true
}

// resolve finds the latest copy that places cp: found reports one did, at copies[idx].
func (df *dockerfile) resolve(copies []dockerCopy, cp string, depth int, wins *[]writeWindow) ([]string, string, bool, int) {
	if depth > 8 {
		return nil, "is copied through stages the scanner does not follow", false, -1
	}
	for i := len(copies) - 1; i >= 0; i-- {
		c := copies[i]
		if c.destUnknown {
			return nil, "may be placed by a COPY whose destination the scanner cannot read", false, -1
		}
		cands := copyCandidates(c, cp)
		if len(cands) == 0 {
			continue
		}
		if c.inline {
			return nil, "is written inline by the Dockerfile", false, -1
		}
		if c.remote {
			return nil, "may be fetched from a URL", false, -1
		}
		if c.from != nil {
			var out []string
			for _, cand := range cands {
				srcs, why, found := df.resolveStage(c.from, path.Join("/", cand), depth+1, wins)
				if why != "" {
					return nil, why, false, -1
				}
				if found {
					out = append(out, srcs...)
				}
			}
			if len(out) > 0 {
				return out, "", true, i
			}
			continue
		}
		var out []string
		for _, cand := range cands {
			if df.sc.contextFile(df.rel, cand) {
				out = append(out, cand)
			}
		}
		if len(out) > 0 {
			return out, "", true, i
		}
	}
	return nil, "", false, -1
}

// copyCandidates returns the sources of c that could land at cp: a file copied to the
// destination name, a file copied into a destination directory, or a file inside a directory
// copied there; with --parents, the source path is kept under the destination.
func copyCandidates(c dockerCopy, cp string) []string {
	if c.inline || c.remote {
		if cp == c.dest || strings.HasPrefix(cp, c.dest+"/") {
			return []string{""}
		}
		return nil
	}
	var out []string
	add := func(s string) {
		s = strings.TrimPrefix(path.Clean(s), "/")
		if s != ".." && !strings.HasPrefix(s, "../") && !containsString(out, s) {
			out = append(out, s)
		}
	}
	for _, src := range c.srcs {
		dest := c.dest
		if c.parents {
			dest = path.Join(c.dest, path.Dir(src))
		}
		glob := strings.ContainsAny(src, "*?[")
		if cp == dest && !c.dirDest && !glob {
			add(src)
		}
		r, ok := strings.CutPrefix(cp, strings.TrimSuffix(dest, "/")+"/")
		if dest == "/" {
			r, ok = strings.TrimPrefix(cp, "/"), true
		}
		if !ok || r == "" {
			continue
		}
		if glob {
			first, tail, _ := strings.Cut(r, "/")
			if m, _ := path.Match(path.Base(src), first); m {
				add(path.Join(path.Dir(src), first, tail))
			}
			continue
		}
		add(path.Join(src, r)) // src is a directory
		if !strings.Contains(r, "/") && r == path.Base(src) {
			add(src) // src is a file copied into the directory
		}
	}
	return out
}

// contextFile reports whether a build-context path names a regular repository file in either
// candidate context: the Dockerfile's directory or the repository root.
func (sc *installScan) contextFile(dockerRel, src string) bool {
	for _, b := range []string{path.Dir(dockerRel), "."} {
		cand := path.Clean(path.Join(b, src))
		if cand == ".." || strings.HasPrefix(cand, "../") {
			continue
		}
		if info, err := os.Stat(filepath.Join(sc.root, filepath.FromSlash(cand))); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
