package jsanalysis

// prodinstall.go looks for evidence that the repo's deploy path installs dev dependencies,
// which voids the class (i) assumption (dev/tooling groups are not installed at runtime).
//
// Scope: Dockerfile*/Containerfile*, Makefile/*.mk, Procfile, shell scripts outside test
// directories, and GitHub workflows whose file name or `name:` says deploy/release/publish/
// docker, plus, in any workflow, a job that sets an `environment:` not named exactly test,
// testing, ci, dev or development (case-insensitive; an expression counts), uses
// docker/build-push-action or uses an action whose name says deploy/publish. Generic test CI
// does not count. An install
// (npm install/ci, yarn [install], pnpm install) keeps dev dependencies unless it passes a
// production flag, runs under NODE_ENV=production, or is followed in the same Dockerfile stage
// or script by a production prune or reinstall. Forcing dev dependencies in (--include=dev,
// --also=dev, --production=false, or NPM_CONFIG_PRODUCTION=false / NPM_CONFIG_INCLUDE=dev in the
// environment) outranks every production signal. Unreadable or unparseable files count as
// evidence: the check fails closed.

import (
	"os"
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
// "<file>: <command>", or "" when none is in scope.
func prodInstallKeepsDev(buildReal string) string {
	var hits []string
	_ = filepath.WalkDir(buildReal, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree holds no visible deploy config.
		}
		name := d.Name()
		if d.IsDir() {
			if p != buildReal && skipDir(name) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(buildReal, p)
		rel = filepath.ToSlash(rel)
		lower := strings.ToLower(name)
		docker := strings.HasPrefix(name, "Dockerfile") || strings.HasPrefix(name, "Containerfile") ||
			strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile")
		plain := name == "Makefile" || name == "makefile" || name == "GNUmakefile" || path.Ext(lower) == ".mk" ||
			name == "Procfile" || (path.Ext(lower) == ".sh" && !inTestDir(rel))
		if !docker && !plain {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			hits = append(hits, rel+": unreadable")
			return nil
		}
		if cmd := keepsDevInstall(string(data), docker); cmd != "" {
			hits = append(hits, rel+": "+cmd)
		}
		return nil
	})
	hits = append(hits, workflowsKeepingDev(buildReal)...)
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return hits[0]
}

func inTestDir(rel string) bool {
	for _, seg := range strings.Split(path.Dir(rel), "/") {
		if devSegments[seg] {
			return true
		}
	}
	return false
}

type ghWorkflow struct {
	Name string           `yaml:"name"`
	Jobs map[string]ghJob `yaml:"jobs"`
}

type ghJob struct {
	Environment yaml.Node `yaml:"environment"`
	Steps       []struct {
		Uses string `yaml:"uses"`
		Run  string `yaml:"run"`
	} `yaml:"steps"`
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

func workflowsKeepingDev(buildReal string) []string {
	dir := filepath.Join(buildReal, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var hits []string
	for _, e := range entries {
		ext := strings.ToLower(path.Ext(e.Name()))
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		rel := ".github/workflows/" + e.Name()
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			hits = append(hits, rel+": unreadable")
			continue
		}
		var wf ghWorkflow
		if yaml.Unmarshal(data, &wf) != nil {
			hits = append(hits, rel+": unparseable workflow")
			continue
		}
		deployFile := deployWord.MatchString(e.Name()) || deployWord.MatchString(wf.Name)
		for _, id := range sortedJobIDs(wf.Jobs) {
			job := wf.Jobs[id]
			if !deployFile && !job.isDeploy() {
				continue
			}
			var runs []string
			for _, s := range job.Steps {
				runs = append(runs, s.Run)
			}
			if cmd := keepsDevInstall(strings.Join(runs, "\n"), false); cmd != "" {
				hits = append(hits, rel+" job "+id+": "+cmd)
			}
		}
	}
	return hits
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

// stripCommandPrefix drops a segment's leading RUN/sudo/env words, `name:` labels, Makefile `@`, and
// environment assignments, reporting whether those assignments select a production install
// (NODE_ENV=production, NPM_CONFIG_PRODUCTION=true) or force dev dependencies in
// (NPM_CONFIG_PRODUCTION=false, NPM_CONFIG_INCLUDE=dev).
func stripCommandPrefix(toks []string) (rest []string, prodEnv, keepDev bool) {
	for len(toks) > 0 {
		t := strings.TrimPrefix(toks[0], "@")
		switch {
		case t == "":
		case strings.EqualFold(t, "RUN"), t == "-", t == "sudo", t == "exec", t == "env", procLabel.MatchString(t):
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
		toks = toks[1:]
	}
	return nil, prodEnv, keepDev
}

// keepDevFlag reports whether an install's flags force dev dependencies in, whatever NODE_ENV
// says: npm's --include=dev and --also=dev, and --production=false.
func keepDevFlag(flags, args []string) bool {
	for _, f := range flags {
		switch f {
		case "--include=dev", "--also=dev", "--also=development", "--production=false":
			return true
		}
	}
	for i := 0; i+1 < len(args); i++ {
		if (args[i] == "--include" || args[i] == "--also") && strings.HasPrefix(args[i+1], "dev") {
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
