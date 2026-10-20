package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// -build-graph values other than a graph file's path.
const (
	buildGraphAuto = "auto"
	buildGraphOff  = "off"
)

// graphRequest is how a JVM scan gets its build graph: -build-graph, and the conditions the
// caller states for the build.
type graphRequest struct {
	mode       string
	conditions buildgraph.Conditions
}

// jvmGraph is the build graph a JVM scan acquired: the accepted file, or the typed reason there
// is none.
type jvmGraph struct {
	file    string
	source  string
	failure *buildgraph.Failure
}

// record is the Report's build_graph field.
func (g *jvmGraph) record() *report.BuildGraph {
	if g == nil {
		return nil
	}
	bg := &report.BuildGraph{Source: g.source}
	if g.failure != nil {
		bg.Cause = &report.BuildGraphCause{Kind: g.failure.Kind, Detail: g.failure.Detail}
	}
	return bg
}

// err is the run's exit error once its Report is published: the typed cause, or nil when the
// scan read a graph or ran with it off.
func (g *jvmGraph) err() error {
	if g == nil || g.failure == nil {
		return nil
	}
	return g.failure
}

// acquireBuildGraph resolves dir's graph with the repository's own Maven or Gradle (auto), loads
// a graph resolved ahead of the scan (a path), or records that the scan runs without one (off).
// Either way the graph the plugin reads has passed buildgraph.Load against dir. There is no other
// source: a graph that cannot be had is a typed failure, never a fallback. The returned cleanup
// removes the resolution's work directory.
func acquireBuildGraph(ctx context.Context, dir string, req graphRequest) (*jvmGraph, func()) {
	noop := func() {}
	switch req.mode {
	case buildGraphOff:
		return &jvmGraph{source: report.BuildGraphSourceOff}, noop
	case buildGraphAuto, "":
	default:
		g := &jvmGraph{source: report.BuildGraphSourceFile}
		if _, err := buildgraph.Load(req.mode, dir, req.conditions); err != nil {
			g.failure = asFailure(err)
			return g, noop
		}
		g.file = req.mode
		return g, noop
	}

	g := &jvmGraph{source: report.BuildGraphSourceTool}
	work, err := os.MkdirTemp("", brand.Name+"-buildgraph-")
	if err != nil {
		g.failure = &buildgraph.Failure{Kind: buildgraph.KindToolFailed, Detail: "select", Log: err.Error()}
		return g, noop
	}
	cleanup := func() { _ = os.RemoveAll(work) }
	out := filepath.Join(work, "out")
	graph, err := buildgraph.Resolve(ctx, buildgraph.Request{
		Dir:        dir,
		Tool:       buildgraph.ToolAuto,
		Conditions: req.conditions,
		WorkDir:    out,
		Producer:   buildgraph.Producer{Name: brand.Name, Version: version},
	})
	if err == nil {
		file := filepath.Join(work, graphFileName)
		if err = writeGraph(file, graph); err == nil {
			if _, err = buildgraph.Load(file, dir, req.conditions); err == nil {
				g.file = file
				return g, cleanup
			}
		}
	}
	g.failure = asFailure(err)
	return g, cleanup
}

func writeGraph(file string, g *buildgraph.Graph) error {
	b, err := json.Marshal(g)
	if err != nil {
		return &buildgraph.Failure{Kind: buildgraph.KindToolFailed, Detail: "graph", Log: err.Error()}
	}
	if err := os.WriteFile(file, b, 0o644); err != nil {
		return &buildgraph.Failure{Kind: buildgraph.KindToolFailed, Detail: "graph", Log: err.Error()}
	}
	return nil
}

// asFailure types err, which buildgraph always returns as a *Failure, and prints the failing
// step's log for the job's output.
func asFailure(err error) *buildgraph.Failure {
	var f *buildgraph.Failure
	if !errors.As(err, &f) {
		f = &buildgraph.Failure{Kind: buildgraph.KindToolFailed, Detail: "graph", Log: err.Error()}
	}
	if f.Log != "" {
		fmt.Fprintln(os.Stderr, f.Log)
	}
	fmt.Fprintf(os.Stderr, "%s: no build graph: %s\n", brand.Name, f.Cause())
	return f
}

// graphRequest is -build-graph with the subject conditions run and baseline already take: the
// Java version, and the Maven profile selection in -P syntax ("," states none).
func (f *runFlags) graphRequest() graphRequest {
	req := graphRequest{mode: strings.TrimSpace(*f.buildGraph)}
	req.conditions.JDK = f.subjectJavaVersion()
	for _, p := range strings.Split(f.subjectMavenProfiles(), ",") {
		if p = strings.TrimSpace(p); p != "" {
			req.conditions.Profiles = append(req.conditions.Profiles, p)
		}
	}
	return req
}
