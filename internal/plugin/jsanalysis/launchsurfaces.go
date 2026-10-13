package jsanalysis

// launchsurfaces.go finds the launch commands launch.go reads: package.json start scripts,
// Dockerfile stages, compose services, Kubernetes containers, systemd units, Procfiles, and the
// deploy platforms' start commands. A process-manager config the reader does not model (pm2's
// ecosystem file) withholds on presence.
//
// A container's launch command runs in the image its Dockerfile builds. The reader follows a
// script the container runs through the Docker build simulation (installdocker.go) to the file
// in the build dir it came from. An image the Dockerfile builds on supplies its own ENTRYPOINT
// and CMD; the reader models the official node image's docker-entrypoint.sh, the empty
// entrypoint of scratch and the official distribution images, and withholds for every other.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type imgKind int

const (
	imgOther    imgKind = iota // an image the reader does not model
	imgDynamic                 // a variable names the image
	imgScratch                 // no entrypoint, no command
	imgNode                    // the official node image: docker-entrypoint.sh
	imgBare                    // an official distribution image: no entrypoint, a shell command
	imgOfficial                // another official image, with its own entrypoint and command
)

// bareImages are official distribution images with no ENTRYPOINT whose CMD is a shell.
var bareImages = map[string]bool{
	"alpine": true, "debian": true, "ubuntu": true, "busybox": true, "fedora": true, "centos": true,
	"rockylinux": true, "almalinux": true, "amazonlinux": true, "oraclelinux": true,
}

func imageKindOf(ref string) imgKind {
	if dynamicTok(ref) || ref == "" {
		return imgDynamic
	}
	r := strings.ToLower(ref)
	if i := strings.IndexByte(r, '@'); i >= 0 {
		r = r[:i]
	}
	if i := strings.LastIndexByte(r, ':'); i > strings.LastIndexByte(r, '/') {
		r = r[:i]
	}
	for _, p := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		r = strings.TrimPrefix(r, p)
	}
	r = strings.TrimPrefix(r, "library/")
	switch {
	case r == "scratch":
		return imgScratch
	case strings.Contains(r, "/"):
		return imgOther
	case r == "node":
		return imgNode
	case bareImages[r]:
		return imgBare
	}
	return imgOfficial
}

// imageCtx is the container a launch command runs in: a stage of a Dockerfile the reader read
// (df), or an image it only knows by reference.
type imageCtx struct {
	df   *dockerImage
	idx  int
	kind imgKind
	ref  string
}

// launchCmd is an ENTRYPOINT or CMD: exec form (words) or shell form (text).
type launchCmd struct {
	set   bool
	exec  bool
	words []shWord
	shell string
}

// rawWords marks words whose text a shell would expand, for a container runtime that passes
// them as they are.
func rawWords(argv []string) []shWord {
	out := make([]shWord, len(argv))
	for i, a := range argv {
		d := strings.ContainsAny(a, "$`")
		out[i] = shWord{text: a, dynamic: d, raw: d}
	}
	return out
}

func parseLaunchCmd(v string) launchCmd {
	t := strings.TrimSpace(v)
	if strings.HasPrefix(t, "[") {
		var argv []string
		if json.Unmarshal([]byte(t), &argv) == nil {
			return launchCmd{set: true, exec: true, words: rawWords(argv)}
		}
	}
	return launchCmd{set: true, shell: t}
}

func (c launchCmd) argv() []shWord {
	switch {
	case !c.set:
		return nil
	case c.exec:
		return c.words
	}
	return []shWord{{text: "/bin/sh"}, {text: "-c"}, {text: c.shell, dynamic: true, raw: true}}
}

type dockerStage struct {
	name       string
	ref        string
	kind       imgKind
	ep, cmd    launchCmd
	cmdLocal   bool // CMD was set in this stage, so a later ENTRYPOINT keeps it
	health     []launchCmd
	referenced bool // a later stage builds on it or copies from it
	workdir    string
	runTexts   []string // every RUN, inherited ones included
}

type dockerImage struct {
	rel       string
	instrs    []dInstr
	stages    []*dockerStage
	simulated bool
	runs      []*dockerRun // the build simulations under the candidate contexts not ruled out
	cands     []string
}

var mountFrom = regexp.MustCompile(`(?:^|,)from=([^,\s]+)`)

// loadDockerfile reads the stages of a Dockerfile: base image, working directory, ENTRYPOINT,
// CMD and HEALTHCHECK, inherited from an earlier stage a stage builds on.
func loadDockerfile(rel string, data []byte) *dockerImage {
	img := &dockerImage{rel: rel, instrs: parseDockerfile(string(data))}
	var cur *dockerStage
	stageRef := func(ref string) *dockerStage {
		ref = strings.ToLower(ref)
		for i := len(img.stages) - 1; i >= 0; i-- {
			if img.stages[i].name != "" && img.stages[i].name == ref {
				return img.stages[i]
			}
		}
		if n, ok := atoi(ref); ok && n < len(img.stages) {
			return img.stages[n]
		}
		return nil
	}
	for _, in := range img.instrs {
		if in.op != "FROM" && cur == nil {
			continue
		}
		switch in.op {
		case "FROM":
			var ref, name string
			f := strings.Fields(in.args)
			for i := 0; i < len(f); i++ {
				switch {
				case strings.HasPrefix(f[i], "--"):
				case strings.EqualFold(f[i], "AS") && i+1 < len(f):
					name = f[i+1]
					i++
				case ref == "":
					ref = f[i]
				}
			}
			st := &dockerStage{ref: ref, kind: imageKindOf(ref)}
			if prior := stageRef(ref); prior != nil {
				prior.referenced = true
				c := *prior
				c.health = append([]launchCmd(nil), prior.health...)
				c.runTexts = append([]string(nil), prior.runTexts...)
				c.referenced, c.cmdLocal = false, false
				st = &c
			} else if st.kind == imgNode || st.kind == imgBare || st.kind == imgScratch {
				st.workdir = "/"
			}
			st.name = strings.ToLower(name)
			img.stages = append(img.stages, st)
			cur = st
		case "WORKDIR":
			p := strings.Trim(strings.TrimSpace(in.args), `"'`)
			switch {
			case p == "" || dynamicTok(p):
				cur.workdir = ""
			case path.IsAbs(p):
				cur.workdir = path.Clean(p)
			case cur.workdir != "":
				cur.workdir = path.Join(cur.workdir, p)
			}
		case "ENTRYPOINT":
			cur.ep = parseLaunchCmd(in.args)
			if !cur.cmdLocal {
				cur.cmd = launchCmd{}
			}
		case "CMD":
			cur.cmd = parseLaunchCmd(in.args)
			cur.cmdLocal = true
		case "HEALTHCHECK":
			f := strings.Fields(in.args)
			i := 0
			for i < len(f) && strings.HasPrefix(f[i], "--") {
				i++
			}
			switch {
			case i < len(f) && strings.EqualFold(f[i], "NONE"):
				cur.health = nil
			case i < len(f) && strings.EqualFold(f[i], "CMD"):
				_, rest, _ := strings.Cut(in.args, f[i])
				cur.health = []launchCmd{parseLaunchCmd(rest)}
			}
		case "COPY", "ADD":
			flags, _ := splitInstrArgs(in.args)
			for _, v := range flags["--from"] {
				if s := stageRef(v); s != nil {
					s.referenced = true
				}
			}
		case "RUN":
			flags, words := splitInstrArgs(in.args)
			for _, spec := range flags["--mount"] {
				if m := mountFrom.FindStringSubmatch(spec); m != nil {
					if s := stageRef(m[1]); s != nil {
						s.referenced = true
					}
				}
			}
			cur.runTexts = append(cur.runTexts, strings.Join(append([]string{strings.Join(words, " ")}, in.heredocs...), "\n"))
		}
	}
	return img
}

// simulate runs the build simulation under every candidate context: the Dockerfile's
// directory, its ancestors, and every context a launch surface names. A candidate is dropped
// only when a source path it lacks exists in another.
func (img *dockerImage) simulate(lr *launchReader) {
	if img.simulated {
		return
	}
	img.simulated = true
	real := lr.m.buildReal
	dir := dirOf(img.rel)
	var cands []string
	seen := map[string]bool{}
	addCand := func(c string) {
		if seen[c] {
			return
		}
		if fi, err := os.Stat(filepath.Join(real, filepath.FromSlash(c))); err != nil || !fi.IsDir() {
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
	for _, c := range lr.contexts {
		addCand(c)
	}
	sort.Strings(cands)
	var runs []*dockerRun
	for _, c := range cands {
		cs := &installScan{m: lr.m, real: real}
		dr := &dockerRun{sc: cs, file: img.rel, ctx: c, missing: map[string]bool{}, present: map[string]bool{}}
		dr.loadIgnores(dir)
		dr.simulate(img.instrs)
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
		if !dead {
			img.runs = append(img.runs, dr)
			img.cands = append(img.cands, dr.ctx)
		}
	}
}

// readOnlyTools leave the files they name unchanged.
var readOnlyTools = map[string]bool{
	"chmod": true, "chown": true, "chgrp": true, "ls": true, "cat": true, "test": true, "[": true,
	"stat": true, "file": true, "head": true, "tail": true, "grep": true, "wc": true,
	"sha256sum": true, "sha1sum": true, "md5sum": true,
}

func isRunSep(r rune) bool { return strings.ContainsRune(" \t\n;&|<>()'\"=`", r) }

// runModifies reports whether a RUN in the stage may write the file at container path cp: it
// names the file other than as an argument to a tool that only reads or re-modes it.
func runModifies(texts []string, cp string) bool {
	base := path.Base(cp)
	for _, t := range texts {
		hit := false
		for _, tok := range strings.FieldsFunc(t, isRunSep) {
			if path.Base(tok) == base {
				hit = true
			}
		}
		if !hit {
			continue
		}
		cmds, why := splitShell(t)
		if why != "" {
			return true
		}
		named := false
		for _, c := range cmds {
			for _, w := range c[1:] {
				if path.Base(w.text) == base {
					named = true
					if !readOnlyTools[path.Base(c[0].text)] {
						return true
					}
				}
			}
		}
		if !named {
			return true // named by a redirect, which splitShell drops
		}
	}
	return false
}

// containerFile resolves container path cp in the current image's stage under every build
// context still possible: the build-dir files it came from, whether some context puts nothing
// there (absent), or whether the simulation cannot tell (unknown). strict also treats a stage a
// file move or unresolved copy touched, or a RUN naming the file, as unknown.
func (lr *launchReader) containerFile(cp string, strict bool) (srcs []string, absent, unknown bool) {
	df, idx := lr.img.df, lr.img.idx
	df.simulate(lr)
	if lr.out.launchCands == nil {
		lr.out.launchCands = map[string]map[string]bool{}
	}
	if lr.out.launchCands[df.rel] == nil {
		lr.out.launchCands[df.rel] = map[string]bool{}
	}
	for _, c := range df.cands {
		lr.out.launchCands[df.rel][c] = true
	}
	if strict && runModifies(df.stages[idx].runTexts, cp) {
		return nil, false, true
	}
	seen := map[string]bool{}
	for _, dr := range df.runs {
		if idx >= len(dr.stages) {
			unknown = true
			continue
		}
		s := dr.stages[idx]
		if strict && s.tainted {
			unknown = true
			continue
		}
		dr.cur, dr.tmp = s, nil
		src, unk := dr.provenance(cp)
		switch {
		case unk:
			unknown = true
		case src == "":
			absent = true
		case !seen[src]:
			seen[src] = true
			srcs = append(srcs, src)
		}
	}
	if len(df.runs) == 0 {
		unknown = true
	}
	return srcs, absent, unknown
}

// runImage evaluates the process an image starts: a shell-form ENTRYPOINT ignores CMD, an
// exec-form ENTRYPOINT takes CMD as arguments (a shell-form CMD as `/bin/sh -c`), and with no
// ENTRYPOINT the base image's applies.
func (lr *launchReader) runImage(label string, kind imgKind, ref string, ep, cmd launchCmd, dir string) {
	switch {
	case ep.set && !ep.exec:
		lr.shell(label, ep.shell, dir, 0)
	case ep.set:
		lr.command(label, append(append([]shWord(nil), ep.words...), cmd.argv()...), dir, 0)
	case kind == imgNode:
		lr.nodeEntrypoint(label, cmd.argv(), dir, 0)
	case kind == imgScratch || kind == imgBare:
		if cmd.set {
			lr.command(label, cmd.argv(), dir, 0)
		}
	case kind == imgDynamic:
		lr.ls.gap("%s: a variable names the base image, whose launch command is not known", label)
	default:
		lr.ls.gap("%s: the base image %s supplies the launch command", label, ref)
	}
}

// nodeEntrypoint models the official node image's docker-entrypoint.sh: an option or a
// JavaScript file runs under node, anything else runs as the command.
func (lr *launchReader) nodeEntrypoint(label string, args []shWord, dir string, depth int) {
	if len(args) == 0 {
		return
	}
	a := args[0]
	if !a.dynamic && (strings.HasPrefix(a.text, "-") || codeExts[strings.ToLower(path.Ext(a.text))]) {
		lr.node(label, args, dir, depth)
		return
	}
	lr.command(label, args, dir, depth)
}

func (lr *launchReader) enter(img *imageCtx) {
	lr.img, lr.pos, lr.posKnown = img, nil, true
}

func stageDir(workdir string) string {
	if workdir == "" {
		return unknownDir
	}
	return workdir
}

func stageLabel(rel string, idx int, st *dockerStage) string {
	if st.name != "" {
		return rel + " stage " + st.name
	}
	return rel + " stage " + strconv.Itoa(idx)
}

// dockerfile evaluates every stage a build may run: the final stage, and every other stage
// that sets a launch command or that no later stage builds on (a --target build).
func (lr *launchReader) dockerfile(img *dockerImage) {
	for idx, st := range img.stages {
		if idx != len(img.stages)-1 && !st.ep.set && !st.cmd.set && st.referenced {
			continue
		}
		label := stageLabel(img.rel, idx, st)
		lr.enter(&imageCtx{df: img, idx: idx, kind: st.kind, ref: st.ref})
		dir := stageDir(st.workdir)
		lr.runImage(label, st.kind, st.ref, st.ep, st.cmd, dir)
		lr.health(label+" HEALTHCHECK", st.health, dir)
	}
}

func (lr *launchReader) health(label string, cmds []launchCmd, dir string) {
	for _, h := range cmds {
		if h.exec {
			lr.command(label, h.words, dir, 0)
		} else {
			lr.shell(label, h.shell, dir, 0)
		}
	}
}

// --- compose ----------------------------------------------------------------------------

// composeWords reads a compose command: a list is the argv, a string is split into one, and
// anything compose interpolates ($VAR, ${VAR}; $$ is a literal $) is a variable.
func composeWords(v any) (launchCmd, bool) {
	switch t := v.(type) {
	case nil:
		return launchCmd{}, true
	case string:
		cmds, why := splitShell(strings.ReplaceAll(t, "$$", "\x01"))
		if why != "" || len(cmds) > 1 {
			return launchCmd{}, false
		}
		if len(cmds) == 0 {
			return launchCmd{}, true
		}
		out := make([]shWord, len(cmds[0]))
		for i, w := range cmds[0] {
			out[i] = shWord{text: strings.ReplaceAll(w.text, "\x01", "$"), dynamic: strings.Contains(w.text, "$")}
		}
		return launchCmd{set: true, exec: true, words: out}, true
	case []any:
		out := make([]shWord, 0, len(t))
		for _, e := range t {
			switch e.(type) {
			case map[string]any, []any:
				return launchCmd{}, false
			}
			s := strings.ReplaceAll(fmt.Sprint(e), "$$", "\x01")
			out = append(out, shWord{text: strings.ReplaceAll(s, "\x01", "$"), dynamic: strings.Contains(s, "$")})
		}
		return launchCmd{set: true, exec: true, words: out}, true
	}
	return launchCmd{}, false
}

func composeServices(data []byte) (map[string]any, bool) {
	var doc map[string]any
	if yaml.Unmarshal(data, &doc) != nil {
		return nil, false
	}
	svcs, ok := doc["services"].(map[string]any)
	return svcs, ok
}

// composeBuild resolves a service's build to the Dockerfile and stage it builds.
func (lr *launchReader) composeBuild(rel string, b any) (ctxRel, dfRel, target string, why string) {
	ctx, df := ".", "Dockerfile"
	switch t := b.(type) {
	case string:
		ctx = t
	case map[string]any:
		if _, ok := t["dockerfile_inline"]; ok {
			return "", "", "", "an inline Dockerfile"
		}
		if s, ok := t["context"].(string); ok {
			ctx = s
		}
		if s, ok := t["dockerfile"].(string); ok {
			df = s
		}
		if s, ok := t["target"].(string); ok {
			target = s
		}
	default:
		return "", "", "", "a build the reader cannot parse"
	}
	if dynamicTok(ctx) || dynamicTok(df) || dynamicTok(target) || strings.Contains(ctx, "://") || strings.HasPrefix(ctx, "git@") || path.IsAbs(ctx) || path.IsAbs(df) {
		return "", "", "", "a build context or Dockerfile the reader cannot resolve"
	}
	ctxRel = normRel(joinRel(dirOf(rel), ctx))
	if !lr.m.inside(ctxRel) {
		return "", "", "", "a build context outside the build dir"
	}
	return ctxRel, normRel(joinRel(ctxRel, df)), strings.ToLower(target), ""
}

// treeMount reports whether a service bind-mounts part of the build dir.
func treeMount(svc map[string]any) bool {
	vols, _ := svc["volumes"].([]any)
	for _, v := range vols {
		switch t := v.(type) {
		case string:
			if strings.HasPrefix(t, ".") {
				return true
			}
		case map[string]any:
			if s, ok := t["source"].(string); ok && t["type"] == "bind" && strings.HasPrefix(s, ".") {
				return true
			}
		}
	}
	return false
}

// compose reads every service's launch command and healthcheck in the image it runs.
func (lr *launchReader) compose(rel string, svcs map[string]any) {
	for _, n := range sortedKeys(svcs) {
		svc, ok := svcs[n].(map[string]any)
		if !ok {
			continue
		}
		label := rel + " service " + n
		ep, okE := composeWords(svc["entrypoint"])
		cmd, okC := composeWords(svc["command"])
		if !okE || !okC {
			lr.ls.gap("%s: launch command not parsed", label)
			continue
		}
		var img *imageCtx
		var base, baseCmd launchCmd
		dir := unknownDir
		overridden := ep.set || cmd.set
		if b, ok := svc["build"]; ok {
			_, dfRel, target, why := lr.composeBuild(rel, b)
			if why != "" {
				lr.ls.gap("%s: builds from %s", label, why)
				continue
			}
			df := lr.images[dfRel]
			if df == nil || len(df.stages) == 0 {
				lr.ls.gap("%s: builds %s, which is not a Dockerfile the reader read", label, dfRel)
				continue
			}
			idx := len(df.stages) - 1
			if target != "" {
				idx = -1
				for i, st := range df.stages {
					if st.name == target {
						idx = i
					}
				}
				if idx < 0 {
					lr.ls.gap("%s: builds stage %s, which %s does not define", label, target, dfRel)
					continue
				}
			}
			st := df.stages[idx]
			img = &imageCtx{df: df, idx: idx, kind: st.kind, ref: st.ref}
			base, baseCmd, dir = st.ep, st.cmd, stageDir(st.workdir)
			overridden = overridden || target != ""
		} else {
			ref, _ := svc["image"].(string)
			if s, ok := svc["image"]; ok && ref == "" {
				ref = fmt.Sprint(s)
			}
			img = &imageCtx{kind: imageKindOf(ref), ref: ref}
			mount := treeMount(svc)
			if (img.kind == imgOfficial || img.kind == imgBare) && !mount {
				continue // another official image, running none of the build dir
			}
			if !ep.set && !cmd.set && !(mount && img.kind != imgNode) {
				continue // the image's own launch command, running none of the build dir
			}
			overridden = true
		}
		if wd, ok := svc["working_dir"].(string); ok {
			dir = unknownDir
			if path.IsAbs(wd) && !dynamicTok(wd) {
				dir = path.Clean(wd)
			}
			overridden = true
		}
		if ep.set {
			base, baseCmd = ep, launchCmd{}
		}
		if cmd.set {
			baseCmd = cmd
		}
		lr.enter(img)
		if overridden {
			lr.runImage(label, img.kind, img.ref, base, baseCmd, dir)
		}
		if hc, ok := svc["healthcheck"].(map[string]any); ok {
			lr.composeHealth(label+" healthcheck", hc["test"], dir)
		}
	}
}

func (lr *launchReader) composeHealth(label string, test any, dir string) {
	switch t := test.(type) {
	case nil:
	case string:
		lr.shell(label, t, dir, 0)
	case []any:
		c, ok := composeWords(t)
		if !ok || len(c.words) == 0 {
			lr.ls.gap("%s: not parsed", label)
			return
		}
		switch c.words[0].text {
		case "NONE":
		case "CMD":
			lr.command(label, c.words[1:], dir, 0)
		case "CMD-SHELL":
			if len(c.words) > 1 {
				if c.words[1].dynamic {
					lr.ls.gap("%s: a variable sets the healthcheck command", label)
					return
				}
				lr.shell(label, c.words[1].text, dir, 0)
			}
		default:
			lr.ls.gap("%s: not parsed", label)
		}
	default:
		lr.ls.gap("%s: not parsed", label)
	}
}

// --- Kubernetes -------------------------------------------------------------------------

// k8sWords reads a container command or args list: $(VAR) is a variable Kubernetes expands
// ($$ escapes it), and any other $ a shell would expand.
func k8sWords(v any) ([]shWord, bool, bool) {
	if v == nil {
		return nil, false, true
	}
	l, ok := v.([]any)
	if !ok {
		return nil, true, false
	}
	out := make([]shWord, 0, len(l))
	for _, e := range l {
		switch e.(type) {
		case map[string]any, []any:
			return nil, true, false
		}
		s := fmt.Sprint(e)
		t := strings.ReplaceAll(s, "$$", "")
		pre := strings.Contains(t, "$(") || strings.Contains(s, "{{")
		d := pre || strings.ContainsAny(t, "$`")
		out = append(out, shWord{text: s, dynamic: d, raw: d && !pre})
	}
	return out, true, true
}

// k8s reads every container of a manifest: its command and args, and every exec probe or
// lifecycle hook, in its image.
func (lr *launchReader) k8s(label string, v any, img *imageCtx, dir string) {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			lr.k8s(label, e, img, dir)
		}
	case map[string]any:
		if ref, ok := t["image"].(string); ok {
			name, _ := t["name"].(string)
			label += " container " + name
			img = &imageCtx{kind: imageKindOf(ref), ref: ref}
			if (img.kind == imgOfficial || img.kind == imgBare) && t["volumeMounts"] == nil {
				return // another official image, with no volume the build dir could reach it by
			}
			dir = unknownDir
			if wd, ok := t["workingDir"].(string); ok && path.IsAbs(wd) && !dynamicTok(wd) {
				dir = path.Clean(wd)
			}
			if !lr.k8sContainer(label, t, img, dir) {
				return
			}
		}
		if ex, ok := t["exec"].(map[string]any); ok {
			w, set, ok := k8sWords(ex["command"])
			switch {
			case !ok:
				lr.ls.gap("%s: exec command not parsed", label)
			case set:
				lr.enter(img)
				lr.command(label+" exec", w, dir, 0)
			}
		}
		for _, k := range sortedKeys(t) {
			switch k {
			case "exec", "command", "args":
				continue
			}
			lr.k8s(label, t[k], img, dir)
		}
	}
}

func (lr *launchReader) k8sContainer(label string, c map[string]any, img *imageCtx, dir string) bool {
	if _, ok := c["script"]; ok {
		lr.ls.gap("%s: runs an inline script", label)
		return false
	}
	if _, ok := c["source"]; ok {
		lr.ls.gap("%s: runs an inline script", label)
		return false
	}
	cmd, cmdSet, ok1 := k8sWords(c["command"])
	args, argsSet, ok2 := k8sWords(c["args"])
	if !ok1 || !ok2 {
		lr.ls.gap("%s: launch command not parsed", label)
		return false
	}
	lr.enter(img)
	switch {
	case cmdSet:
		lr.command(label, append(cmd, args...), dir, 0)
	case !argsSet:
	case img.kind == imgNode:
		lr.nodeEntrypoint(label, args, dir, 0)
	case img.kind == imgScratch || img.kind == imgBare:
		lr.command(label, args, dir, 0)
	default:
		lr.ls.gap("%s: the image %s supplies the command its args run under", label, img.ref)
	}
	return true
}

// manifestDocs decodes every document of a YAML stream.
func manifestDocs(data []byte) ([]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []any
	for {
		var d any
		err := dec.Decode(&d)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return docs, nil
			}
			return nil, err
		}
		docs = append(docs, d)
	}
}

func isManifest(d any) bool {
	m, ok := d.(map[string]any)
	if !ok {
		return false
	}
	_, a := m["apiVersion"].(string)
	_, k := m["kind"].(string)
	return a && k
}

// --- systemd ----------------------------------------------------------------------------

var (
	systemdExecKeys = map[string]bool{
		"ExecStart": true, "ExecStartPre": true, "ExecStartPost": true, "ExecReload": true,
		"ExecStop": true, "ExecStopPost": true, "ExecCondition": true,
	}
	systemdSpecifier = regexp.MustCompile(`%[A-Za-z]`)
)

// systemd reads every Exec line of a unit. Specifiers (%i) and environment references are
// variables; the working directory is a host path, not the build dir.
func (lr *launchReader) systemd(rel string, data []byte) {
	text := strings.ReplaceAll(string(data), "\\\n", " ")
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || !systemdExecKeys[strings.TrimSpace(k)] {
			continue
		}
		v = strings.TrimSpace(v)
		at := false
		for v != "" && strings.ContainsRune("@-:+!|", rune(v[0])) {
			at = at || v[0] == '@'
			v = v[1:]
		}
		if v == "" {
			continue
		}
		v = strings.ReplaceAll(v, "%%", "\x01")
		v = systemdSpecifier.ReplaceAllStringFunc(v, func(s string) string { return "${_" + s[1:] + "}" })
		label := rel + " " + strings.TrimSpace(k)
		cmds, why := splitShell(v)
		if why != "" {
			lr.ls.gap("%s: launch command not parsed (%s)", label, why)
			continue
		}
		lr.enter(nil)
		for _, c := range cmds {
			for i := range c {
				c[i].dynamic = c[i].dynamic || strings.Contains(c[i].text, "${_")
				c[i].text = strings.ReplaceAll(c[i].text, "\x01", "%")
			}
			if at && len(c) > 1 {
				c = append(c[:1:1], c[2:]...)
			}
			lr.command(label, c, unknownDir, 0)
		}
	}
}

// --- deploy platforms -------------------------------------------------------------------

// platformCmd evaluates a platform's command value: a string is shell text, a list the argv.
func (lr *launchReader) platformCmd(label string, v any, dir string) {
	switch t := v.(type) {
	case nil:
	case string:
		lr.shell(label, t, dir, 0)
	case []any:
		w := make([]shWord, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				lr.ls.gap("%s: launch command not parsed", label)
				return
			}
			w = append(w, shWord{text: s, dynamic: dynamicTok(s)})
		}
		lr.command(label, w, dir, 0)
	default:
		lr.ls.gap("%s: launch command not parsed", label)
	}
}

func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// platform reads a deploy platform config's start, release and deploy-hook commands.
func (lr *launchReader) platform(rel string, data []byte) {
	name := path.Base(rel)
	dir := dirOf(rel)
	v, err := parseConfig(rel, data)
	if err != nil {
		lr.ls.gap("%s: deploy config not parsed", rel)
		return
	}
	lr.enter(nil)
	each := func(m any, f func(k string, e any)) {
		mm, _ := m.(map[string]any)
		for _, k := range sortedKeys(mm) {
			f(k, mm[k])
		}
	}
	switch {
	case name == "render.yaml" || name == "render.yml":
		svcs, _ := dig(v, "services").([]any)
		for i, s := range svcs {
			for _, k := range []string{"startCommand", "preDeployCommand", "dockerCommand"} {
				lr.platformCmd(fmt.Sprintf("%s services[%d].%s", rel, i, k), dig(s, k), dir)
			}
		}
	case name == "fly.toml":
		lr.fly(rel, v, dir)
	case strings.HasPrefix(name, "railway."):
		for _, k := range []string{"startCommand", "preDeployCommand"} {
			lr.platformCmd(rel+" deploy."+k, dig(v, "deploy", k), dir)
		}
	case strings.HasPrefix(name, "nixpacks."):
		lr.platformCmd(rel+" start.cmd", dig(v, "start", "cmd"), dir)
	case name == "app.yaml" || name == "app.yml":
		lr.platformCmd(rel+" entrypoint", dig(v, "entrypoint"), dir)
		for _, kind := range []string{"services", "workers", "jobs"} {
			l, _ := dig(v, kind).([]any)
			for i, s := range l {
				lr.platformCmd(fmt.Sprintf("%s %s[%d].run_command", rel, kind, i), dig(s, "run_command"), dir)
			}
		}
	case name == "heroku.yml":
		each(dig(v, "run"), func(k string, e any) {
			if m, ok := e.(map[string]any); ok {
				e = m["command"]
			}
			lr.platformCmd(rel+" run."+k, e, dir)
		})
		lr.platformCmd(rel+" release.command", dig(v, "release", "command"), dir)
	case name == "app.json":
		each(dig(v, "scripts"), func(k string, e any) {
			if m, ok := e.(map[string]any); ok {
				e = m["command"]
			}
			lr.platformCmd(rel+" scripts."+k, e, dir)
		})
	case name == ".platform.app.yaml":
		lr.platformCmd(rel+" web.commands.start", dig(v, "web", "commands", "start"), dir)
		each(dig(v, "workers"), func(k string, e any) {
			lr.platformCmd(rel+" workers."+k, dig(e, "commands", "start"), dir)
		})
		for _, k := range []string{"deploy", "post_deploy"} {
			lr.platformCmd(rel+" hooks."+k, dig(v, "hooks", k), dir)
		}
	case path.Base(dir) == ".ebextensions":
		for _, sec := range []string{"container_commands", "commands"} {
			each(dig(v, sec), func(k string, e any) {
				lr.platformCmd(rel+" "+sec+"."+k, dig(e, "command"), parentDir(dir))
			})
		}
	}
}

// fly reads fly.toml's process commands, release command and entrypoint override, in the
// image its Dockerfile builds when it has one.
func (lr *launchReader) fly(rel string, v any, dir string) {
	df := lr.images[normRel(joinRel(dir, "Dockerfile"))]
	if s, ok := dig(v, "build", "dockerfile").(string); ok {
		df = lr.images[normRel(joinRel(dir, s))]
		if df == nil {
			lr.ls.gap("%s: builds %s, which is not a Dockerfile the reader read", rel, s)
			return
		}
	}
	if ref, ok := dig(v, "build", "image").(string); ok && df == nil {
		lr.ls.gap("%s: runs the image %s, whose launch command is not known", rel, ref)
		return
	}
	cmds := map[string]any{}
	if p, ok := dig(v, "processes").(map[string]any); ok {
		for k, e := range p {
			cmds["processes."+k] = e
		}
	}
	if e := dig(v, "experimental", "cmd"); e != nil {
		cmds["experimental.cmd"] = e
	}
	if e := dig(v, "deploy", "release_command"); e != nil {
		cmds["deploy.release_command"] = e
	}
	epv := dig(v, "experimental", "entrypoint")
	if df == nil || len(df.stages) == 0 {
		for _, k := range sortedKeys(cmds) {
			lr.platformCmd(rel+" "+k, cmds[k], dir)
		}
		lr.platformCmd(rel+" experimental.entrypoint", epv, dir)
		return
	}
	idx := len(df.stages) - 1
	st := df.stages[idx]
	ep := st.ep
	if epv != nil {
		c, ok := composeWords(epv)
		if !ok {
			lr.ls.gap("%s experimental.entrypoint: not parsed", rel)
			return
		}
		ep = c
	}
	if len(cmds) == 0 && epv != nil {
		cmds[""] = nil
	}
	for _, k := range sortedKeys(cmds) {
		c, ok := composeWords(cmds[k])
		if !ok {
			lr.ls.gap("%s %s: not parsed", rel, k)
			continue
		}
		if !c.set {
			c = st.cmd
		}
		lr.enter(&imageCtx{df: df, idx: idx, kind: st.kind, ref: st.ref})
		lr.runImage(strings.TrimSpace(rel+" "+k), st.kind, st.ref, ep, c, stageDir(st.workdir))
	}
}

// --- Procfile ---------------------------------------------------------------------------

var procName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// procfile reads every process line of a Procfile.
func (lr *launchReader) procfile(rel string, data []byte) {
	dir := dirOf(rel)
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		proc, cmd, ok := strings.Cut(t, ":")
		if !ok || !procName.MatchString(proc) {
			lr.ls.gap("%s: launch line not parsed (%q)", rel, t)
			continue
		}
		lr.enter(nil)
		lr.shell(rel+" "+proc, cmd, dir, 0)
	}
}

// --- the walk ---------------------------------------------------------------------------

// launchSkipDirs hold editor, CI and vendored files, never a deploy's launch command.
var launchSkipDirs = map[string]bool{".git": true, ".github": true, ".devcontainer": true, ".vscode": true, ".idea": true, "vendor": true}

func isPM2Config(name string) bool {
	lower := strings.ToLower(name)
	if !strings.HasPrefix(lower, "ecosystem") && !strings.HasPrefix(lower, "pm2") {
		return false
	}
	switch path.Ext(lower) {
	case ".js", ".cjs", ".mjs", ".ts", ".json", ".json5", ".yml", ".yaml":
		return true
	}
	return false
}

func isSystemdUnit(rel string) bool {
	return strings.HasSuffix(rel, ".service") || strings.HasSuffix(path.Dir(rel), ".service.d") && strings.HasSuffix(rel, ".conf")
}

// read reads every launch surface in the build dir.
func (lr *launchReader) read() {
	var dockerfiles, composes, yamls, jsons, units, platforms, procfiles, hooks []string
	walkTree(lr.m.buildReal, func(_, rel string, _ fs.DirEntry) error {
		for _, seg := range strings.Split(path.Dir(rel), "/") {
			if launchSkipDirs[seg] {
				return nil
			}
		}
		name := path.Base(rel)
		lower := strings.ToLower(name)
		kind := surfaceOf(rel, name, nil)
		switch {
		case isPM2Config(name):
			lr.ls.gap("%s: a pm2 process file, whose launch commands the reader does not follow", rel)
		case kind == surfDocker:
			dockerfiles = append(dockerfiles, rel)
		case kind == surfCompose:
			composes = append(composes, rel)
		case strings.HasPrefix(name, "Procfile"):
			procfiles = append(procfiles, rel)
		case platformFiles[name] || path.Base(path.Dir(rel)) == ".ebextensions" && path.Ext(lower) == ".config":
			platforms = append(platforms, rel)
		case isSystemdUnit(rel):
			units = append(units, rel)
		case strings.HasPrefix(rel, ".platform/hooks/") || strings.HasPrefix(rel, ".platform/confighooks/"):
			hooks = append(hooks, rel)
		case yamlExt(name):
			yamls = append(yamls, rel)
		case path.Ext(lower) == ".json" && name != "package.json" && name != "package-lock.json":
			jsons = append(jsons, rel)
		}
		return nil
	}, func(string, string) {})

	read := func(rel string) ([]byte, bool) {
		data, err := lr.m.readFirstParty(rel)
		if err != nil {
			lr.ls.gap("launch surface %s %s", rel, unreadableWhy(err))
			return nil, false
		}
		return data, true
	}

	for _, ms := range lr.out.scripts {
		if _, ok := ms.scripts["start"]; ok {
			lr.enter(nil)
			lr.script(ms.rel+" scripts.start", "start", 0)
		}
	}

	// Build contexts the compose files and fly.toml name join the Docker simulation's
	// candidates.
	composeData := map[string]map[string]any{}
	for _, rel := range composes {
		data, ok := read(rel)
		if !ok {
			continue
		}
		svcs, ok := composeServices(data)
		if !ok {
			lr.ls.gap("%s: compose file not parsed", rel)
			continue
		}
		composeData[rel] = svcs
	}
	var yamlDocs = map[string][]any{}
	for _, rel := range yamls {
		data, ok := read(rel)
		if !ok {
			continue
		}
		docs, err := manifestDocs(data)
		if err != nil {
			if bytes.Contains(data, []byte("apiVersion:")) && bytes.Contains(data, []byte("image:")) {
				lr.ls.gap("%s: manifest not parsed (a template?)", rel)
			}
			continue
		}
		if len(docs) == 1 {
			if svcs, ok := dig(docs[0], "services").(map[string]any); ok && !isManifest(docs[0]) {
				composeData[rel] = svcs
				continue
			}
		}
		yamlDocs[rel] = docs
	}
	for _, rel := range sortedMapKeys(composeData) {
		for _, n := range sortedKeys(composeData[rel]) {
			if b := dig(composeData[rel][n], "build"); b != nil {
				if c, _, _, why := lr.composeBuild(rel, b); why == "" {
					lr.contexts = append(lr.contexts, c)
				}
			}
		}
	}
	for _, rel := range platforms {
		if path.Base(rel) == "fly.toml" {
			lr.contexts = append(lr.contexts, dirOf(rel))
		}
	}

	lr.images = map[string]*dockerImage{}
	for _, rel := range dockerfiles {
		if data, ok := read(rel); ok {
			lr.images[rel] = loadDockerfile(rel, data)
		}
	}
	for _, rel := range dockerfiles {
		if img := lr.images[rel]; img != nil {
			lr.dockerfile(img)
		}
	}
	for _, rel := range sortedMapKeys(composeData) {
		lr.compose(rel, composeData[rel])
	}
	for _, rel := range sortedMapKeys(yamlDocs) {
		for _, d := range yamlDocs[rel] {
			if isManifest(d) {
				lr.k8s(rel, d, nil, unknownDir)
			}
		}
	}
	for _, rel := range jsons {
		data, ok := read(rel)
		if !ok || !bytes.Contains(data, []byte(`"apiVersion"`)) || !bytes.Contains(data, []byte(`"kind"`)) {
			continue
		}
		var d any
		if json.Unmarshal(data, &d) == nil {
			var docs []any
			if l, ok := dig(d, "items").([]any); ok {
				docs = l
			} else {
				docs = []any{d}
			}
			for _, x := range docs {
				if isManifest(x) {
					lr.k8s(rel, x, nil, unknownDir)
				}
			}
		}
	}
	for _, rel := range units {
		if data, ok := read(rel); ok {
			lr.systemd(rel, data)
		}
	}
	for _, rel := range platforms {
		if data, ok := read(rel); ok {
			lr.platform(rel, data)
		}
	}
	for _, rel := range procfiles {
		if data, ok := read(rel); ok {
			lr.procfile(rel, data)
		}
	}
	for _, rel := range hooks {
		lr.enter(nil)
		lr.followTree(rel, rel, nil, "", 0, fileShell)
	}
	lr.enter(nil)
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
