package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
)

// graphFileName is the graph's name inside the -out directory, beside its sidecars.
const graphFileName = "buildgraph.json"

// listFlag collects a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// runResolveGraph runs the repository's Maven or Gradle and writes its assay.buildgraph/v1
// graph. A failed resolution prints its typed cause and exits nonzero; nothing is written in
// its place.
func runResolveGraph(args []string) error {
	fs := flag.NewFlagSet("resolve-graph", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root")
	out := fs.String("out", "", "output directory for "+graphFileName+" and its sidecars (required)")
	tool := fs.String("tool", buildgraph.ToolAuto, "build tool: auto, maven or gradle")
	profiles := fs.String("profiles", "", "comma-separated Maven profiles to activate")
	jdk := fs.String("java-version", "", "the JDK the job states; a different major version fails")
	var props, envs listFlag
	fs.Var(&props, "D", "build property key=value (repeatable): Maven -D, Gradle -P")
	fs.Var(&envs, "env", "environment variable key=value overlaid on the job's (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	c := buildgraph.Conditions{JDK: *jdk}
	if *profiles != "" {
		c.Profiles = strings.Split(*profiles, ",")
	}
	var err error
	if c.Properties, err = keyValues("-D", props); err != nil {
		return err
	}
	if c.Env, err = keyValues("-env", envs); err != nil {
		return err
	}

	g, err := buildgraph.Resolve(context.Background(), buildgraph.Request{
		Dir:        *dir,
		Tool:       *tool,
		Conditions: c,
		WorkDir:    *out,
		Producer:   buildgraph.Producer{Name: brand.Name, Version: version},
	})
	if err != nil {
		var f *buildgraph.Failure
		if errors.As(err, &f) && f.Log != "" {
			fmt.Fprintln(os.Stderr, f.Log)
		}
		return err
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, graphFileName), append(b, '\n'), 0o644)
}

func keyValues(name string, kvs []string) (map[string]string, error) {
	if len(kvs) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%s %q: want key=value", name, kv)
		}
		m[k] = v
	}
	return m, nil
}
