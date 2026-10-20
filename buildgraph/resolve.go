package buildgraph

import (
	"context"
	"os"
	"path/filepath"
)

// Tool selections a Request may state.
const (
	ToolAuto   = "auto"
	ToolMaven  = "maven"
	ToolGradle = "gradle"
)

// Request is one resolution: the repository root, the tool, the run conditions as handed in,
// and the directory step outputs and sidecars are written to, which must be empty.
type Request struct {
	Dir        string
	Tool       string // ToolAuto when empty
	Conditions Conditions
	WorkDir    string
	Env        []string // the job's environment; os.Environ() when nil
	Producer   Producer
}

// Resolve runs the repository's build tool and returns its graph, normalized and validated. Any
// failure is a *Failure carrying the typed cause.
func Resolve(ctx context.Context, req Request) (*Graph, error) {
	dir, err := filepath.Abs(req.Dir)
	if err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: "select", Log: err.Error()}
	}
	work, err := filepath.Abs(req.WorkDir)
	if err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: "select", Log: err.Error()}
	}
	// Generated POMs and the init script in the checkout would be read as build inputs.
	if within(dir, work) {
		return nil, &Failure{Kind: KindToolFailed, Detail: "select", Log: "work directory " + work + " is inside the repository"}
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, &Failure{Kind: KindToolFailed, Detail: "select", Log: err.Error()}
	}
	// Steps append to their outputs, so a previous run's files would read as this one's.
	if entries, err := os.ReadDir(work); err != nil || len(entries) > 0 {
		return nil, &Failure{Kind: KindToolFailed, Detail: "select", Log: "work directory " + work + " is not empty"}
	}
	tool, err := selectTool(dir, req.Tool)
	if err != nil {
		return nil, err
	}
	env := req.Env
	if env == nil {
		env = os.Environ()
	}
	env = environ(env, req.Conditions.Env)

	wrapper, onPath := "mvnw", "mvn"
	if tool == ToolGradle {
		wrapper, onPath = "gradlew", "gradle"
	}
	exe, shown, isWrapper, err := findTool(dir, wrapper, onPath, env)
	if err != nil {
		return nil, err
	}
	r := &runner{dir: dir, tool: exe, shown: shown, env: env, work: work}

	var g *Graph
	if tool == ToolGradle {
		g, err = resolveGradle(ctx, r, req.Conditions)
	} else {
		g, err = resolveMaven(ctx, r, req.Conditions)
	}
	if err != nil {
		return nil, err
	}
	g.Schema = Schema
	g.Producer = req.Producer
	g.Tool.Wrapper = isWrapper
	g.Conditions = req.Conditions
	g.Commands = r.commands
	g.Subject.Commit, g.Subject.Tree = gitSubject(ctx, dir)
	g.Subject.InputsDigest = InputsDigest(g.Subject.Inputs)
	g.Normalize()
	if check := g.Validate(); check != "" {
		return nil, &Failure{Kind: KindGraphRejected, Detail: check}
	}
	return g, nil
}

// selectTool honours a stated tool and otherwise picks the one whose build files the root holds.
// Both or neither is a failure: the producer does not guess.
func selectTool(dir, stated string) (string, error) {
	switch stated {
	case ToolMaven, ToolGradle:
		return stated, nil
	case "", ToolAuto:
	default:
		return "", &Failure{Kind: KindToolFailed, Detail: "select", Log: "unknown tool " + stated}
	}
	exists := func(names ...string) bool {
		for _, n := range names {
			if fi, err := os.Stat(filepath.Join(dir, n)); err == nil && fi.Mode().IsRegular() {
				return true
			}
		}
		return false
	}
	maven := exists("pom.xml")
	gradle := exists("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")
	switch {
	case maven && gradle:
		return "", &Failure{Kind: KindToolFailed, Detail: "select", Log: "both pom.xml and Gradle build files at the root; state the tool"}
	case maven:
		return ToolMaven, nil
	case gradle:
		return ToolGradle, nil
	}
	return "", &Failure{Kind: KindToolFailed, Detail: "select", Log: "no pom.xml or Gradle build file at the root"}
}
