package javaanalysis

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A session parses the source tree and opens the dependency JARs once for a whole scan: the
// call graph and ingress ops and three advisories' Reachability calls parse the tree once and
// open netkit's JAR once, and every answer is byte-for-byte the one a call without a session
// gives.
func TestSession_LoadsSourceAndJarsOncePerScan(t *testing.T) {
	build := buildNetkitFixture(t, false)
	withFirstPartySource(t, build, "src/com/acme/app/App.java", `package com.acme.app;
public final class App {
    public static void main(String[] args) { new App().run(); }
    void run() { helper(); }
    void helper() {}
    void unused() {}
}`)
	graph := netkitGraph(t, build)
	app := []string{"App"}
	advisories := [][]string{
		{methodSCIP("com.acme.app", app, "helper", 0)},
		{methodSCIP("com.acme.app", app, "unused", 0)},
		{"jvmref com/evil/netkit/UrlFetcher#fetch(Ljava/lang/String;)Ljava/lang/String;"},
	}

	// One scan's requests, in the order the pipeline makes them.
	scan := func(ctx context.Context) []string {
		t.Helper()
		var out []string
		add := func(v any, err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(b))
		}
		add(CallGraph(ctx, plugin.CallGraphRequest{BuildDir: build}, graph))
		add(FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: build}, graph))
		for _, symbols := range advisories {
			add(Reachability(ctx, plugin.ReachabilityRequest{BuildDir: build, Symbols: symbols}, graph))
		}
		return out
	}
	want := scan(context.Background())

	var parses, opens int
	parse, open := parseProgram, openDependencies
	t.Cleanup(func() { parseProgram, openDependencies = parse, open })
	parseProgram = func(dir string) (*program, error) {
		parses++
		return parse(dir)
	}
	openDependencies = func(dir string, opts ...Option) (*dependencyGraph, error) {
		opens++
		return open(dir, opts...)
	}

	got := scan(WithSession(context.Background()))
	if parses != 1 || opens != 1 {
		t.Errorf("one scan parsed the source %d times and opened the JARs %d times, want once each", parses, opens)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("answer %d with a session differs:\n got %s\nwant %s", i, got[i], want[i])
		}
	}

	// Without a session nothing is kept: each Reachability call parses and opens again.
	parses, opens = 0, 0
	for _, symbols := range advisories {
		if _, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: build, Symbols: symbols}, graph); err != nil {
			t.Fatal(err)
		}
	}
	if parses < len(advisories) || opens != len(advisories) {
		t.Errorf("without a session: %d parses and %d opens for %d calls", parses, opens, len(advisories))
	}
}
