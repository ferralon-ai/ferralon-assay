package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// mavenCheckout is a one-module Maven checkout and a graph file for it that Load accepts under
// the conditions c.
func mavenCheckout(t *testing.T, c buildgraph.Conditions) (dir, file string) {
	t.Helper()
	dir = t.TempDir()
	pom := []byte("<project/>")
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), pom, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pom)
	inputs := []buildgraph.Input{{Path: "pom.xml", SHA256: hex.EncodeToString(sum[:])}}
	root := buildgraph.Node{Group: "com.example", Artifact: "app", Version: "1", Type: "jar"}
	root.ID = buildgraph.NodeID(root.Group, root.Artifact, root.Type, "", root.Version)
	g := buildgraph.Graph{
		Schema:     buildgraph.Schema,
		Tool:       buildgraph.Tool{Name: "maven", Version: "3.9.9"},
		JVM:        buildgraph.JVM{Version: "21.0.4"},
		Conditions: c,
		Subject:    buildgraph.Subject{Inputs: inputs, InputsDigest: buildgraph.InputsDigest(inputs)},
		Modules:    []buildgraph.Module{{ID: "com.example:app", Path: ".", Root: root.ID, Nodes: []buildgraph.Node{root}}},
	}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

func TestAcquireBuildGraph(t *testing.T) {
	stated := buildgraph.Conditions{Profiles: []string{"ci"}, JDK: "21"}
	dir, file := mavenCheckout(t, stated)
	// No wrapper in the checkout and nothing on PATH: auto cannot run Maven.
	t.Setenv("PATH", t.TempDir())

	tests := []struct {
		name       string
		req        graphRequest
		wantSource string
		wantCause  string
		wantFile   string
	}{
		{name: "off", req: graphRequest{mode: buildGraphOff}, wantSource: "off"},
		{name: "file accepted", req: graphRequest{mode: file, conditions: stated}, wantSource: "build_tool_file", wantFile: file},
		{name: "file under other conditions", req: graphRequest{mode: file}, wantSource: "build_tool_file", wantCause: "graph_rejected:conditions"},
		{name: "file missing", req: graphRequest{mode: filepath.Join(dir, "absent.json"), conditions: stated}, wantSource: "build_tool_file", wantCause: "graph_rejected:decode"},
		{name: "auto without a toolchain", req: graphRequest{mode: buildGraphAuto, conditions: stated}, wantSource: "build_tool", wantCause: "toolchain_absent"},
		{name: "unset is auto", req: graphRequest{conditions: stated}, wantSource: "build_tool", wantCause: "toolchain_absent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, cleanup := acquireBuildGraph(context.Background(), dir, tc.req)
			defer cleanup()
			rec := g.record()
			if rec.Source != tc.wantSource || g.file != tc.wantFile {
				t.Fatalf("source %q file %q, want %q %q", rec.Source, g.file, tc.wantSource, tc.wantFile)
			}
			var gotCause string
			if rec.Cause != nil {
				gotCause = rec.Cause.Kind
				if rec.Cause.Detail != "" {
					gotCause += ":" + rec.Cause.Detail
				}
			}
			if gotCause != tc.wantCause {
				t.Fatalf("cause %q, want %q", gotCause, tc.wantCause)
			}
			// A cause fails the run; off and an accepted graph do not.
			var f *buildgraph.Failure
			if err := g.err(); (err != nil) != (tc.wantCause != "") || (err != nil && (!errors.As(err, &f) || f.Cause() != tc.wantCause)) {
				t.Fatalf("err %v, want cause %q", err, tc.wantCause)
			}
		})
	}
}

func TestBuildGraphRecordNilForOtherLanguages(t *testing.T) {
	var g *jvmGraph
	if g.record() != nil || g.err() != nil {
		t.Fatal("a scan without a JVM graph records nothing and does not fail")
	}
	rep := report.Report{BuildGraph: g.record()}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["build_graph"]; ok {
		t.Fatal("build_graph present on a non-JVM report")
	}
}

// The subject conditions' env channels spelled out, so a rename of either side goes red.
const (
	subjectJavaEnv          = "ASSAY_SUBJECT_JAVA_VERSION"
	subjectMavenProfilesEnv = "ASSAY_SUBJECT_MAVEN_PROFILES"
)

func TestGraphRequestConditions(t *testing.T) {
	tests := []struct {
		name, java, profiles, javaEnv, profilesEnv string
		want                                       buildgraph.Conditions
	}{
		{name: "unstated"},
		{name: "stated", java: "17.0.12", profiles: "release, ci", want: buildgraph.Conditions{JDK: "17.0.12", Profiles: []string{"release", "ci"}}},
		{name: "none", profiles: ",", want: buildgraph.Conditions{}},
		{name: "env", javaEnv: "11.0.24", profilesEnv: "ci", want: buildgraph.Conditions{JDK: "11.0.24", Profiles: []string{"ci"}}},
		{name: "flag over env", java: "17", profiles: "release", javaEnv: "11", profilesEnv: "ci", want: buildgraph.Conditions{JDK: "17", Profiles: []string{"release"}}},
		{name: "blank flag falls back to env", java: "  ", profiles: " ", javaEnv: "11", profilesEnv: "ci", want: buildgraph.Conditions{JDK: "11", Profiles: []string{"ci"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(subjectJavaEnv, tc.javaEnv)
			t.Setenv(subjectMavenProfilesEnv, tc.profilesEnv)
			mode := buildGraphAuto
			f := &runFlags{buildGraph: &mode, subjectJava: &tc.java, subjectMvnProf: &tc.profiles}
			got := f.graphRequest()
			if got.mode != buildGraphAuto || got.conditions.JDK != tc.want.JDK || len(got.conditions.Profiles) != len(tc.want.Profiles) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range tc.want.Profiles {
				if got.conditions.Profiles[i] != tc.want.Profiles[i] {
					t.Fatalf("got %+v, want %+v", got, tc.want)
				}
			}
		})
	}
}
