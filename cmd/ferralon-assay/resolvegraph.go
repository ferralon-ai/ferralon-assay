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

// runResolveGraph runs the repository's Maven or Gradle and writes its assay.buildgraph/v2
// graph. A failed resolution prints its typed cause and exits nonzero; nothing is written in
// its place.
func runResolveGraph(args []string) error {
	fs := flag.NewFlagSet("resolve-graph", flag.ContinueOnError)
	dir := fs.String("dir", ".", "repository root")
	out := fs.String("out", "", "output directory for "+graphFileName+" and its sidecars (required)")
	tool := fs.String("tool", buildgraph.ToolAuto, "build tool: auto, maven or gradle")
	profiles := fs.String("profiles", "", "comma-separated Maven profiles to activate")
	jdk := fs.String("java-version", "", "the JDK the job states, which the program runs on; a build tool on a different major version fails. Leave it unstated when the program runs on another JDK than the build")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	// The conditions are the ones a scan can state, normalised the same way, so a scan stating
	// them accepts the graph.
	c := buildgraph.Conditions{JDK: strings.TrimSpace(*jdk), Profiles: splitProfiles(*profiles)}

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
	if err := writableGraph(g); err != nil {
		return err
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, graphFileName), append(b, '\n'), 0o644)
}

// writableGraph refuses a graph no scan could load from a file: one whose build logic lies
// outside the checkout.
func writableGraph(g *buildgraph.Graph) error {
	if u := g.Subject.UnbindableIncludedBuilds; len(u) > 0 {
		return fmt.Errorf("included build outside the checkout (%s): resolve the graph in the scan with -build-graph auto", u[0])
	}
	return nil
}
