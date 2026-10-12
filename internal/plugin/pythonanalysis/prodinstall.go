package pythonanalysis

// Production installs that keep dev dependencies. A class (i) refutation assumes the
// lockfile's dev/optional groups are not installed at runtime; a repository whose own
// production install keeps them (`uv sync` without --no-dev in a Dockerfile, say) breaks
// that assumption, and nothing refutes.
//
// Scope: Dockerfile*, Containerfile*, *.dockerfile, Makefile/*.mk, Procfile and shell
// scripts outside test directories; GitHub workflows named for deploy/release/publish/
// docker; and, in any workflow, a job that is a deploy step (it sets `environment:` to a
// non-test environment, uses docker/build-push-action, or uses a deploy/publish action).
// Test CI is not a production install. A workflow that fails to parse is scanned whole.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// productionKeepsDev returns where the repository's production install keeps dev or
// optional dependencies ("Dockerfile:12: uv sync"), or "" when no in-scope file does.
func productionKeepsDev(buildDir string) string {
	var hits []string
	walkProjectFiles(buildDir, func(rel, abs string) {
		if !prodInstallFile(filepath.Base(rel)) {
			return
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			hits = append(hits, rel+": unreadable")
			return
		}
		if loc := scanInstallLines(string(data)); loc != "" {
			hits = append(hits, rel+":"+loc)
		}
	})
	wfDir := filepath.Join(buildDir, ".github", "workflows")
	entries, _ := os.ReadDir(wfDir)
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		rel := ".github/workflows/" + e.Name()
		data, err := os.ReadFile(filepath.Join(wfDir, e.Name()))
		if err != nil {
			hits = append(hits, rel+": unreadable")
			continue
		}
		if loc := scanWorkflow(e.Name(), data); loc != "" {
			hits = append(hits, rel+":"+loc)
		}
	}
	sort.Strings(hits)
	if len(hits) == 0 {
		return ""
	}
	return hits[0]
}

func prodInstallFile(base string) bool {
	l := strings.ToLower(base)
	switch {
	case strings.HasPrefix(l, "dockerfile"), strings.HasPrefix(l, "containerfile"), strings.HasSuffix(l, ".dockerfile"):
		return true
	case l == "makefile", l == "gnumakefile", strings.HasSuffix(l, ".mk"), l == "procfile":
		return true
	case strings.HasSuffix(l, ".sh"), strings.HasSuffix(l, ".bash"):
		return true
	}
	return false
}

var deployWorkflowName = regexp.MustCompile(`(?i)deploy|release|publish|docker`)

// testEnvironments are the `environment:` names that mark a test job, not a deploy step:
// exact, case-insensitive. Staging, preview and expression values count as deploys.
var testEnvironments = regexp.MustCompile(`(?i)^(test|testing|ci|dev|development)$`)

type workflowFile struct {
	Name string                 `yaml:"name"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Environment yaml.Node `yaml:"environment"`
	Steps       []struct {
		Uses string `yaml:"uses"`
		Run  string `yaml:"run"`
	} `yaml:"steps"`
}

// scanWorkflow returns the location of a dev-keeping install in a workflow's deploy steps.
func scanWorkflow(fileName string, data []byte) string {
	var wf workflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return scanInstallLines(string(data)) // fail closed: an unreadable workflow is scanned whole
	}
	whole := deployWorkflowName.MatchString(fileName) || deployWorkflowName.MatchString(wf.Name)
	for _, id := range sortedMapKeys(wf.Jobs) {
		job := wf.Jobs[id]
		if !whole && !deployJob(job) {
			continue
		}
		for _, st := range job.Steps {
			if loc := scanInstallLines(st.Run); loc != "" {
				_, cmd, _ := strings.Cut(loc, ": ")
				return fmt.Sprintf(" job %s: %s", id, cmd)
			}
		}
	}
	return ""
}

// deployJob reports whether a job is a deploy step: it targets a non-test environment, or
// builds and pushes an image, or uses a deploy/publish action.
func deployJob(job workflowJob) bool {
	if env := workflowEnvironmentName(job.Environment); env != "" && !testEnvironments.MatchString(env) {
		return true
	}
	for _, st := range job.Steps {
		u := strings.ToLower(st.Uses)
		action, _, _ := strings.Cut(u, "@")
		if strings.HasPrefix(action, "docker/build-push-action") {
			return true
		}
		if strings.Contains(action, "deploy") || strings.Contains(action, "publish") {
			return true
		}
	}
	return false
}

// workflowEnvironmentName returns a job's environment name: the scalar, or the mapping's
// `name`. An expression stays as written, so it never matches a test name.
func workflowEnvironmentName(n yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		return strings.TrimSpace(n.Value)
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "name" {
				if v := strings.TrimSpace(n.Content[i+1].Value); v != "" {
					return v
				}
				return "<unnamed>"
			}
		}
		return "<unnamed>"
	}
	return ""
}

// scanInstallLines returns "<line>: <command>" for the first install command in text that
// keeps dev or optional dependencies, or "".
func scanInstallLines(text string) string {
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		start := i
		line := lines[i]
		for strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") && i+1 < len(lines) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\") + " " + lines[i+1]
			i++
		}
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") {
			continue
		}
		for _, seg := range splitShellCommands(line) {
			if cmd := keepsDevCommand(shellTokens(seg)); cmd != "" {
				return fmt.Sprintf("%d: %s", start+1, cmd)
			}
		}
	}
	return ""
}

var shellSeparators = regexp.MustCompile(`&&|\|\||;|\|`)

func splitShellCommands(line string) []string { return shellSeparators.Split(line, -1) }

// shellTokens splits a command into words, dropping quotes and JSON-array punctuation so the
// exec form `CMD ["uv", "run", "app"]` reads like the shell form.
func shellTokens(seg string) []string {
	seg = strings.NewReplacer(`"`, " ", `'`, " ", "[", " [", ",", " ").Replace(seg)
	var out []string
	for _, f := range strings.Fields(seg) {
		if f == "[" || f == "]" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func hasFlag(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}

// flagValue returns the value of a --flag value or --flag=value pair.
func flagValues(args []string, flag string) []string {
	var out []string
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			out = append(out, args[i+1])
		} else if v, ok := strings.CutPrefix(a, flag+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

// keepsDevCommand returns the install command a token list runs when it keeps dev or optional
// dependencies, or "".
func keepsDevCommand(tok []string) string {
	for i := 0; i < len(tok); i++ {
		w := filepath.Base(tok[i])
		rest := tok[i+1:]
		sub := ""
		if len(rest) > 0 {
			sub = rest[0]
		}
		switch {
		case w == "uv" && sub == "sync", w == "uv" && sub == "export":
			if !hasFlag(rest, "--no-dev") || hasFlag(rest, "--extra", "--all-extras", "--group", "--all-groups", "--dev", "--only-dev", "--only-group") {
				return "uv " + sub
			}
		case w == "uv" && sub == "run":
			if !hasFlag(rest, "--no-dev", "--no-sync", "--frozen-no-sync") || hasFlag(rest, "--extra", "--all-extras", "--group", "--all-groups", "--with") {
				return "uv run"
			}
		case w == "poetry" && sub == "install":
			drops := hasFlag(rest, "--no-dev")
			for _, v := range flagValues(rest, "--only") {
				drops = drops || v == "main"
			}
			for _, v := range flagValues(rest, "--without") {
				drops = drops || strings.Contains(v, "dev")
			}
			if !drops || hasFlag(rest, "--with", "-E", "--extras", "--all-extras", "--all-groups") {
				return "poetry install"
			}
		case w == "pdm" && (sub == "install" || sub == "sync"):
			if !hasFlag(rest, "--prod", "--production") || hasFlag(rest, "-G", "--group", "-d", "--dev") {
				return "pdm " + sub
			}
		case w == "pipenv" && (sub == "install" || sub == "sync"):
			if hasFlag(rest, "--dev", "-d") {
				return "pipenv " + sub + " --dev"
			}
		case strings.HasPrefix(w, "pip") && !strings.HasPrefix(w, "pipenv") && sub == "install":
			if c := pipKeepsDev(rest[1:]); c != "" {
				return "pip install " + c
			}
		}
	}
	return ""
}

// pipKeepsDev returns the argument of a pip install that installs dev or optional
// dependencies: a dev requirements file, or a local project with extras.
func pipKeepsDev(args []string) string {
	for i, a := range args {
		var file string
		switch {
		case (a == "-r" || a == "--requirement") && i+1 < len(args):
			file = args[i+1]
		case strings.HasPrefix(a, "--requirement="):
			file = strings.TrimPrefix(a, "--requirement=")
		case strings.HasPrefix(a, "-r") && len(a) > 2:
			file = a[2:]
		}
		if file != "" && devManifestPath(filepath.Base(file)) {
			return "-r " + file
		}
		if (strings.HasPrefix(a, ".") || strings.HasPrefix(a, "/")) && strings.Contains(a, "[") {
			return a
		}
	}
	return ""
}
