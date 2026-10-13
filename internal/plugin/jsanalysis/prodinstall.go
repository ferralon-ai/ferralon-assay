package jsanalysis

// prodinstall.go looks for evidence that the repo's deploy path installs dev dependencies,
// which voids the class (i) assumption (dev/tooling groups are not installed at runtime).
//
// The surfaces are installscan.go's, found by walking the whole build tree. Read whole:
// Dockerfiles and Containerfiles (judged per FROM stage), Makefiles, justfiles, Procfiles,
// every shell script, Jenkinsfiles, Cloud Build configs, every package.json script, any YAML,
// TOML or JSON config read by command keys (the CI dialects, deploy platforms and manifests),
// and any other file that carries an install command. Read per deploy job: GitHub workflows whose file name or `name:` says deploy/
// release/publish/docker, plus, in any workflow, a job that sets an `environment:` not named
// exactly test, testing, ci, dev or development (case-insensitive; an expression counts), uses
// docker/build-push-action or uses an action whose name says deploy/publish, with its local
// actions and reusable workflows expanded; GitLab jobs whose environment, stage or name says
// deploy. Also: a .npmrc that forces dev dependencies in, docker-compose service commands, and
// a Dockerfile directory copy that takes a lockfile root's node_modules into the image without
// .dockerignore excluding it.
//
// An install (npm install/ci, yarn [install], pnpm install) keeps dev dependencies unless it
// passes a production flag, runs under NODE_ENV=production, or is followed in the same
// Dockerfile stage or script by a production prune or reinstall. Forcing dev dependencies in
// (--include=dev, --also=dev, --production=false, or NPM_CONFIG_PRODUCTION=false /
// NPM_CONFIG_INCLUDE=dev in the environment) outranks every production signal. Unreadable or
// unparseable files count as evidence: the check fails closed.

import (
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	deployWord    = regexp.MustCompile(`(?i)deploy|release|publish|docker`)
	deployAction  = regexp.MustCompile(`(?i)deploy|publish`)
	prodEnvLine   = regexp.MustCompile(`(?i)^\s*(?:ENV|export|ARG)\b.*\bNODE_ENV[=\s]+["']?production\b`)
	keepDevLine   = regexp.MustCompile(`(?i)^\s*(?:ENV|export|ARG)\b.*\bNPM_CONFIG_(?:PRODUCTION[=\s]+["']?false|(?:INCLUDE|ALSO)[=\s]+["']?dev)`)
	segmentSplit  = regexp.MustCompile(`&&|\|\||;|\|`)
	envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	procLabel     = regexp.MustCompile(`^[A-Za-z][\w-]*:$`) // "run:", a Procfile "release:"
)

// prodInstallKeepsDev returns the first deploy-path install that keeps dev dependencies, as
// "<file>: <command>", or "" when none is in scope. The surfaces it reads are installscan.go's.
func prodInstallKeepsDev(buildReal string) string {
	if hits := scanBuild(buildReal, nil, nil).keepDev; len(hits) > 0 {
		return hits[0]
	}
	return ""
}

// nonDeployEnvironments are the only environment names that do not mark a deploy job.
var nonDeployEnvironments = map[string]bool{"test": true, "testing": true, "ci": true, "dev": true, "development": true}

// isDeploy reports whether a job deploys: it targets an environment other than a test/dev one
// (an expression counts), builds and pushes an image, or uses a deploy/publish action.
func (j ghJob) isDeploy() bool {
	if env := environmentName(j.Environment); env != nil && !nonDeployEnvironments[strings.ToLower(*env)] {
		return true
	}
	for _, s := range j.Steps {
		uses := strings.ToLower(s.Uses)
		if strings.HasPrefix(uses, "docker/build-push-action") {
			return true
		}
		if i := strings.IndexByte(uses, '@'); i >= 0 {
			uses = uses[:i]
		}
		if deployAction.MatchString(uses) {
			return true
		}
	}
	return false
}

// environmentName returns a job's environment name (`environment: x` or `environment: {name:
// x}`), "" when it is set without a literal name, or nil when it is unset.
func environmentName(n yaml.Node) *string {
	name := ""
	switch n.Kind {
	case 0:
		return nil
	case yaml.ScalarNode:
		name = n.Value
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "name" && n.Content[i+1].Kind == yaml.ScalarNode {
				name = n.Content[i+1].Value
			}
		}
	}
	return &name
}

// workflowKeepsDev applies the deploy-job check to one workflow. Every job is judged when the
// workflow deploys by its name, can be called by another workflow (on: workflow_call), or all
// is set; otherwise the deploy jobs and every job they need, transitively, since a needed job's
// output is what the deploy job ships. A judged job's local actions (uses: ./path) and local
// reusable workflows contribute their run steps; one the scanner cannot resolve counts as
// evidence.
func (sc *installScan) workflowKeepsDev(rel, name string, wf ghWorkflow, all bool) []string {
	var hits []string
	every := all || deployWord.MatchString(name) || deployWord.MatchString(wf.Name) ||
		slicesContains(nodeWords(wf.On), "workflow_call")
	judged := map[string]bool{}
	var queue []string
	for _, id := range sortedJobIDs(wf.Jobs) {
		if every || wf.Jobs[id].isDeploy() {
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if judged[id] {
			continue
		}
		judged[id] = true
		queue = append(queue, nodeWords(wf.Jobs[id].Needs)...)
	}
	for _, id := range sortedJobIDs(wf.Jobs) {
		job := wf.Jobs[id]
		if !judged[id] {
			continue
		}
		label := rel + " job " + id
		var runs []string
		if job.Uses != "" {
			r, bad := sc.expandUses(job.Uses, 0)
			if bad != "" {
				hits = append(hits, label+": "+bad)
			}
			runs = append(runs, r...)
		}
		for _, s := range job.Steps {
			runs = append(runs, s.Run)
			if strings.HasPrefix(s.Uses, "./") {
				r, bad := sc.expandUses(s.Uses, 0)
				if bad != "" {
					hits = append(hits, label+": "+bad)
				}
				runs = append(runs, r...)
			}
		}
		if cmd := keepsDevInstall(strings.Join(runs, "\n"), false); cmd != "" {
			hits = append(hits, label+": "+cmd)
		}
	}
	return hits
}

// expandUses returns the run steps of a local action or reusable workflow, or why it could
// not be read. A remote reusable workflow cannot be read; a remote action is not expanded.
func (sc *installScan) expandUses(uses string, depth int) (runs []string, bad string) {
	if depth > 8 {
		return nil, "uses: nesting too deep at " + uses
	}
	if !strings.HasPrefix(uses, "./") {
		if strings.Contains(uses, ".github/workflows/") {
			return nil, "remote reusable workflow " + uses + " is not read"
		}
		return nil, ""
	}
	target := strings.TrimPrefix(path.Clean(uses), "./")
	if target == ".." || strings.HasPrefix(target, "../") || dynamicTok(target) {
		return nil, "uses: " + uses + " leaves the build dir"
	}
	if strings.HasPrefix(target, ".github/workflows/") {
		data, err := readRegular(filepath.Join(sc.real, filepath.FromSlash(target)))
		if err != nil {
			return nil, "reusable workflow " + uses + " unreadable"
		}
		var wf ghWorkflow
		if yaml.Unmarshal(data, &wf) != nil {
			return nil, "reusable workflow " + uses + " unparseable"
		}
		for _, id := range sortedJobIDs(wf.Jobs) {
			j := wf.Jobs[id]
			if j.Uses != "" {
				r, b := sc.expandUses(j.Uses, depth+1)
				if b != "" {
					return nil, b
				}
				runs = append(runs, r...)
			}
			for _, s := range j.Steps {
				runs = append(runs, s.Run)
				if strings.HasPrefix(s.Uses, "./") {
					r, b := sc.expandUses(s.Uses, depth+1)
					if b != "" {
						return nil, b
					}
					runs = append(runs, r...)
				}
			}
		}
		return runs, ""
	}
	var data []byte
	var err error
	for _, n := range []string{"action.yml", "action.yaml"} {
		if data, err = readRegular(filepath.Join(sc.real, filepath.FromSlash(target), n)); err == nil {
			break
		}
	}
	if err != nil {
		return nil, "local action " + uses + " unreadable"
	}
	var a ghAction
	if yaml.Unmarshal(data, &a) != nil {
		return nil, "local action " + uses + " unparseable"
	}
	for _, s := range a.Runs.Steps {
		runs = append(runs, s.Run)
		if strings.HasPrefix(s.Uses, "./") {
			r, b := sc.expandUses(s.Uses, depth+1)
			if b != "" {
				return nil, b
			}
			runs = append(runs, r...)
		}
	}
	if a.Runs.Entrypoint != "" || len(a.Runs.Args) > 0 {
		runs = append(runs, strings.TrimSpace(a.Runs.Entrypoint+" "+strings.Join(a.Runs.Args, " ")))
	}
	return runs, ""
}

func sortedJobIDs(jobs map[string]ghJob) []string {
	out := make([]string, 0, len(jobs))
	for k := range jobs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keepsDevInstall returns the first install command in text that leaves dev dependencies
// installed. A Dockerfile is judged stage by stage (FROM starts a stage); other text is one
// stage. Within a stage, NODE_ENV=production set before an install, or a later production
// prune or production install, clears it. An environment line that forces dev dependencies in
// (NPM_CONFIG_PRODUCTION=false, NPM_CONFIG_INCLUDE=dev) outranks NODE_ENV=production for the
// rest of the stage, including on the same line.
func keepsDevInstall(text string, docker bool) string {
	text = strings.ReplaceAll(text, "\\\r\n", " ")
	text = strings.ReplaceAll(text, "\\\n", " ")
	pending, prodEnv, keepDevEnv := "", false, false
	for _, line := range strings.Split(text, "\n") {
		if docker {
			if f := strings.Fields(line); len(f) > 0 && strings.EqualFold(f[0], "FROM") {
				if pending != "" {
					return pending
				}
				prodEnv, keepDevEnv = false, false
			}
		}
		if prodEnvLine.MatchString(line) {
			prodEnv = true
		}
		if keepDevLine.MatchString(line) {
			keepDevEnv = true
		}
		for _, seg := range segmentSplit.Split(line, -1) {
			switch classifyInstall(seg, prodEnv, keepDevEnv) {
			case installKeepsDev:
				if pending == "" {
					pending = strings.Join(strings.Fields(seg), " ")
				}
			case installProdOnly:
				pending = ""
			}
		}
	}
	return pending
}

type installKind int

const (
	installNone installKind = iota
	installKeepsDev
	installProdOnly // a production install or prune: dev dependencies are absent afterwards
)

func classifyInstall(seg string, prodEnv, keepDevEnv bool) installKind {
	toks, envProd, envKeepDev := stripCommandPrefix(strings.Fields(seg))
	for i, t := range toks {
		toks[i] = strings.Trim(t, `"'`)
	}
	prodEnv = prodEnv || envProd
	keepDevEnv = keepDevEnv || envKeepDev
	if len(toks) == 0 {
		return installNone
	}
	tool, args := toks[0], toks[1:]
	sub := ""
	var flags []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else if sub == "" {
			sub = a
		}
	}
	install := false
	switch tool {
	case "npm":
		switch sub {
		case "install", "i", "in", "ci", "add", "clean-install", "install-clean", "ic":
			install = true
		case "prune":
			if prodFlag(tool, flags, args) {
				return installProdOnly
			}
			return installNone
		}
	case "yarn":
		install = sub == "" || sub == "install" || sub == "add" || (sub == "workspaces" && containsReason(args, "focus"))
	case "pnpm":
		install = sub == "install" || sub == "i" || sub == "add"
	}
	if !install {
		return installNone
	}
	for _, f := range flags {
		if f == "-g" || f == "--global" {
			return installNone
		}
	}
	if keepDevFlag(flags, args) {
		return installKeepsDev
	}
	if !keepDevEnv && (prodEnv || prodFlag(tool, flags, args)) {
		return installProdOnly
	}
	return installKeepsDev
}

// stripCommandPrefix drops the words in front of a segment's command: RUN and its --mount/
// --network/--security flags, Makefile @-+ markers, `name:` labels, environment assignments,
// command wrappers (sudo, env, exec, eval, time, nice, nohup, timeout, command, builtin,
// corepack), shell keywords and grouping, and `sh -c` style shells, which run their argument.
// It reports whether the assignments select a production install (NODE_ENV=production,
// NPM_CONFIG_PRODUCTION=true) or force dev dependencies in (NPM_CONFIG_PRODUCTION=false,
// NPM_CONFIG_INCLUDE=dev).
func stripCommandPrefix(toks []string) (rest []string, prodEnv, keepDev bool) {
	for len(toks) > 0 {
		raw := toks[0]
		if strings.HasPrefix(raw, "--mount=") || strings.HasPrefix(raw, "--network=") || strings.HasPrefix(raw, "--security=") {
			toks = toks[1:]
			continue
		}
		t := strings.TrimLeft(raw, "@-+")
		t = strings.TrimLeft(t, "({")
		t = strings.Trim(t, `"'`)
		skip := 0 // extra tokens a wrapper consumes
		switch {
		case t == "":
		case strings.EqualFold(t, "RUN"), procLabel.MatchString(t):
		case t == "exec", t == "eval", t == "time", t == "nohup", t == "command", t == "builtin", t == "corepack",
			t == "!", t == "then", t == "do", t == "else", t == "elif", t == "if", t == "while", t == "until":
		case t == "sudo", t == "env", t == "nice", t == "timeout":
			// flags, then (timeout) a duration
			for skip+1 < len(toks) && strings.HasPrefix(toks[skip+1], "-") && !envAssignment.MatchString(toks[skip+1]) {
				f := toks[skip+1]
				skip++
				if (t == "sudo" && (f == "-u" || f == "-g" || f == "-C" || f == "-D")) || (t == "env" && (f == "-u" || f == "-C")) ||
					(t == "nice" && f == "-n") || (t == "timeout" && (f == "-s" || f == "-k" || f == "--signal" || f == "--kill-after")) {
					skip++
				}
			}
			if t == "timeout" && skip+1 < len(toks) {
				skip++
			}
		case t == "sh" || t == "bash" || t == "zsh" || t == "dash" || t == "ash" || t == "ksh":
			// `sh -c 'cmd'` runs cmd; `sh script` runs a script scanned as its own file.
			j := 1
			for j < len(toks) && strings.HasPrefix(toks[j], "-") && !strings.Contains(toks[j], "c") {
				j++
			}
			if j < len(toks) && strings.HasPrefix(toks[j], "-") {
				skip = j
			} else {
				toks[0] = t
				return toks, prodEnv, keepDev
			}
		case envAssignment.MatchString(t):
			k, v, _ := strings.Cut(t, "=")
			v = strings.ToLower(strings.Trim(v, `"'`))
			switch {
			case k == "NODE_ENV" && v == "production", strings.EqualFold(k, "NPM_CONFIG_PRODUCTION") && v == "true":
				prodEnv = true
			case strings.EqualFold(k, "NPM_CONFIG_PRODUCTION") && v == "false",
				(strings.EqualFold(k, "NPM_CONFIG_INCLUDE") || strings.EqualFold(k, "NPM_CONFIG_ALSO")) && v == "dev":
				keepDev = true
			}
		default:
			toks[0] = t
			return toks, prodEnv, keepDev
		}
		toks = toks[1+skip:]
	}
	return nil, prodEnv, keepDev
}

// keepDevFlag reports whether an install's flags force dev dependencies in, whatever NODE_ENV
// says: npm's --include=dev, --also=dev, --only=dev and --production=false, and an --omit that
// does not list dev (it replaces the omit list NODE_ENV=production sets).
func keepDevFlag(flags, args []string) bool {
	devVal := func(flag, v string) bool {
		v = strings.ToLower(strings.Trim(v, `"'`))
		switch flag {
		case "--include", "--also", "--only":
			return strings.HasPrefix(v, "dev")
		case "--omit":
			return !strings.Contains(v, "dev")
		}
		return false
	}
	for _, f := range flags {
		if f == "--production=false" {
			return true
		}
		if k, v, ok := strings.Cut(f, "="); ok && devVal(k, v) {
			return true
		}
	}
	for i := 0; i+1 < len(args); i++ {
		if devVal(args[i], args[i+1]) {
			return true
		}
	}
	return false
}

func prodFlag(tool string, flags, args []string) bool {
	for _, f := range flags {
		switch f {
		case "--omit=dev", "--production", "--production=true", "--only=prod", "--only=production", "--prod":
			return true
		case "-P": // pnpm's --prod; npm's -P is --save-prod
			if tool == "pnpm" {
				return true
			}
		}
	}
	for i := 0; i+1 < len(args); i++ {
		if (args[i] == "--omit" && args[i+1] == "dev") || (args[i] == "--only" && strings.HasPrefix(args[i+1], "prod")) {
			return true
		}
	}
	return false
}
