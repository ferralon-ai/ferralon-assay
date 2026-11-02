// Command floorcheck is the checker behind the nightly floor run (.github/workflows/floor.yml),
// which scans every demo repository in floor/targets.json with the scanner built from main.
//
//	floorcheck matrix -targets floor/targets.json
//	floorcheck check  -targets floor/targets.json -results DIR -summary floor-summary.json \
//	                  -markdown floor-summary.md -alert floor-alert.txt [-assay-commit SHA] [-run-url URL]
//
// `matrix` validates the targets file and prints the workflow's step outputs: the scan matrix and
// the corpus policy. `check` reads each scan job's result directory under -results (a meta.json and,
// when the scan wrote one, its report.json), and fails a repository on any not_exploitable finding
// without grounds, a disqualified finding on a basis that cannot ground it, a scan that failed, was
// cut short or left no result, and a report that does not decode or validate. It writes the JSON
// summary, the Markdown job summary and, when anything failed, the alert text.
//
// Exit status: 0 when every repository passed, 1 when any failed, 2 on a usage or input error.
// docs/floor.md describes the run.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: floorcheck matrix|check [flags]")
		return 2
	}
	switch args[0] {
	case "matrix":
		return runMatrix(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "floorcheck: unknown command %q (want matrix or check)\n", args[0])
		return 2
	}
}

func runMatrix(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetsPath := fs.String("targets", "floor/targets.json", "the targets file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	t, err := loadTargets(*targetsPath)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	out, err := matrixOutput(t)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	fmt.Fprint(stdout, out)
	return 0
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetsPath := fs.String("targets", "floor/targets.json", "the targets file")
	results := fs.String("results", "", "directory holding one result directory per scan job (required)")
	summaryPath := fs.String("summary", "floor-summary.json", "where to write the JSON summary")
	markdownPath := fs.String("markdown", "floor-summary.md", "where to write the Markdown job summary")
	alertPath := fs.String("alert", "floor-alert.txt", "where to write the failure alert; written only when a repo failed")
	assayCommit := fs.String("assay-commit", "", "the Assay commit the scanner was built from")
	runURL := fs.String("run-url", "", "the workflow run's URL, for the summary and the alert")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *results == "" {
		fmt.Fprintln(stderr, "floorcheck check: -results is required")
		return 2
	}
	t, err := loadTargets(*targetsPath)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	found, err := readResults(*results)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	s := summarize(t, found, *assayCommit, *runURL)
	js, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	md := s.markdown()
	if err := writeFiles(map[string][]byte{*summaryPath: append(js, '\n'), *markdownPath: []byte(md)}); err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	if s.Pass {
		fmt.Fprintf(stdout, "floor: PASS — %d repos\n", len(s.Repos))
		return 0
	}
	if err := writeFiles(map[string][]byte{*alertPath: []byte(s.alert())}); err != nil {
		fmt.Fprintln(stderr, "floorcheck:", err)
		return 2
	}
	fmt.Fprintf(stdout, "floor: FAIL — %d of %d repos failed\n", len(s.failedRepos()), len(s.Repos))
	for _, r := range s.failedRepos() {
		for _, f := range r.Failures {
			fmt.Fprintf(stdout, "  %s: %s: %s\n", r.Repo, f.Kind, f.Detail)
		}
	}
	return 1
}

func writeFiles(files map[string][]byte) error {
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
