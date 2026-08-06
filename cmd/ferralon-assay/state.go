package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/projection"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/statestore"
)

// runState dispatches the `state` operator subcommands: `show` (fetch the
// StateStore ref and open/emit its self-contained report.html) and `export`
// (produce a deliberate ZIP of the ref's contents to a -out path). Both are
// READ-ONLY with respect to the StateStore — they never write back to the ref.
func runState(args []string) error {
	if len(args) < 1 {
		stateUsage()
		return fmt.Errorf("state requires a subcommand (show | export)")
	}
	switch args[0] {
	case "show":
		return runStateShow(args[1:])
	case "export":
		return runStateExport(args[1:])
	case "help", "-h", "--help":
		stateUsage()
		return nil
	default:
		stateUsage()
		return fmt.Errorf("unknown state subcommand %q", args[0])
	}
}

func stateUsage() {
	fmt.Fprintf(os.Stdout, `%[1]s state — operator views of the persisted StateStore ref (read-only)

Usage:
  %[1]s state show   [flags]   fetch the ref and open/print its report.html
  %[1]s state export [flags]   write a ZIP of the ref's contents to -out

StateStore selection (both subcommands):
  -git-dir <path>   use the local git-ref StateStore at <path> (a repo or bare repo)
  -repo <o/r>       use the GitHub Refs-API StateStore for owner/repo
                    (token from -token or $GITHUB_TOKEN; -api-url overrides the API root)
  -ref <ref>        state ref to read (default: %[2]s)

Run "%[1]s state show -h" / "%[1]s state export -h" for the full flags.
`, brand.Name, statestore.DefaultRef)
}

// stateStoreFlags registers the StateStore-selection flags shared by show/export
// and returns a resolver that builds the selected store after Parse.
type stateStoreFlags struct {
	gitDir *string
	repo   *string
	token  *string
	apiURL *string
	ref    *string
}

func registerStateStoreFlags(fs *flag.FlagSet) *stateStoreFlags {
	return &stateStoreFlags{
		gitDir: fs.String("git-dir", "", "local git-ref StateStore path (a repo or bare repo)"),
		repo:   fs.String("repo", "", "GitHub StateStore as owner/repo (token from -token or $GITHUB_TOKEN)"),
		token:  fs.String("token", "", "GitHub API token (default: $GITHUB_TOKEN)"),
		apiURL: fs.String("api-url", "", "GitHub API root override (default: https://api.github.com)"),
		ref:    fs.String("ref", "", fmt.Sprintf("state ref to read (default: %s)", statestore.DefaultRef)),
	}
}

// resolve builds the selected StateStore. Exactly one of -git-dir / -repo must be
// given (or $GITHUB_TOKEN's implied repo is NOT inferred — selection is explicit).
func (f *stateStoreFlags) resolve() (statestore.StateStore, error) {
	switch {
	case *f.gitDir != "" && *f.repo != "":
		return nil, fmt.Errorf("specify only one of -git-dir or -repo")
	case *f.repo != "":
		owner, name, err := splitRepo(*f.repo)
		if err != nil {
			return nil, err
		}
		token := *f.token
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
		}
		return statestore.NewGitHubRefStore(statestore.GitHubConfig{
			Owner:   owner,
			Repo:    name,
			Token:   token,
			BaseURL: *f.apiURL,
			Ref:     *f.ref,
		}), nil
	case *f.gitDir != "":
		return statestore.NewGitRefStore(statestore.Config{GitDir: *f.gitDir, Ref: *f.ref}), nil
	default:
		return nil, fmt.Errorf("select a StateStore: -git-dir <path> or -repo <owner/repo>")
	}
}

func splitRepo(s string) (owner, name string, err error) {
	i := -1
	for j := 0; j < len(s); j++ {
		if s[j] == '/' {
			i = j
			break
		}
	}
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("-repo must be owner/repo, got %q", s)
	}
	return s[:i], s[i+1:], nil
}

func runStateShow(args []string) error {
	fs := flag.NewFlagSet("state show", flag.ContinueOnError)
	sf := registerStateStoreFlags(fs)
	outDir := fs.String("out", "", "directory to write report.html into (default: a temp dir)")
	noOpen := fs.Bool("no-open", false, "do not launch the OS browser; only print the file:// path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := sf.resolve()
	if err != nil {
		return err
	}
	return showFromStore(store, *outDir, *noOpen)
}

// showFromStore fetches the ref's Report, renders the self-contained report.html
// into dir (a temp dir when empty), and best-effort opens it. It is the seam the
// flag wrapper and tests both drive.
func showFromStore(store statestore.StateStore, outDir string, noOpen bool) error {
	ctx := context.Background()
	st, err := store.Read(ctx)
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	if st.Report == nil {
		return fmt.Errorf("state at ref has no report.json — run a baseline first")
	}

	html, err := projection.MarshalReportHTML(*st.Report)
	if err != nil {
		return fmt.Errorf("project HTML: %w", err)
	}

	dir := outDir
	if dir == "" {
		dir, err = os.MkdirTemp("", brand.Name+"-show-")
		if err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
	} else if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	htmlPath := filepath.Join(dir, resultsink.FileReportHTML)
	if err := os.WriteFile(htmlPath, html, 0o644); err != nil {
		return fmt.Errorf("write report.html: %w", err)
	}

	abs, _ := filepath.Abs(htmlPath)
	fileURL := pathToFileURL(abs)
	fmt.Fprintf(os.Stdout, "%s state show\n", brand.Name)
	fmt.Fprintf(os.Stdout, "  ref commit: %s\n", st.CommitSHA)
	fmt.Fprintf(os.Stdout, "  report:     %s\n", fileURL)
	if !noOpen {
		if err := openInBrowser(fileURL); err != nil {
			fmt.Fprintf(os.Stdout, "  (could not auto-open a browser: %v — open the path above manually)\n", err)
		}
	}
	return nil
}

func runStateExport(args []string) error {
	fs := flag.NewFlagSet("state export", flag.ContinueOnError)
	sf := registerStateStoreFlags(fs)
	out := fs.String("out", brand.Name+"-state.zip", "path to write the export ZIP to")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := sf.resolve()
	if err != nil {
		return err
	}
	return exportFromStore(store, *out)
}

// exportFromStore fetches the ref's Report (read-only — it never Writes back) and
// writes a deliberate ZIP of report.json + the projections to out. It is the seam
// the flag wrapper and tests both drive.
func exportFromStore(store statestore.StateStore, out string) error {
	ctx := context.Background()
	st, err := store.Read(ctx)
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	if st.Report == nil {
		return fmt.Errorf("state at ref has no report.json — run a baseline first")
	}

	files, err := exportFiles(*st.Report)
	if err != nil {
		return err
	}

	if err := writeZip(out, files); err != nil {
		return err
	}

	abs, _ := filepath.Abs(out)
	fmt.Fprintf(os.Stdout, "%s state export\n", brand.Name)
	fmt.Fprintf(os.Stdout, "  ref commit: %s\n", st.CommitSHA)
	fmt.Fprintf(os.Stdout, "  written:    %s\n", abs)
	for _, f := range files {
		fmt.Fprintf(os.Stdout, "    - %s (%d bytes)\n", f.name, len(f.data))
	}
	return nil
}

// exportFile is one entry in the export ZIP.
type exportFile struct {
	name string
	data []byte
}

// exportFiles renders the report and its three projections from the ref's Report.
// The ZIP carries report.json plus the projections (report.html, SARIF, OpenVEX),
// mirroring the local ResultSink layout so an operator's forked-PR fallback export
// is interchangeable with a baseline run's output directory.
func exportFiles(rep report.Report) ([]exportFile, error) {
	reportJSON, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report.json: %w", err)
	}
	html, err := projection.MarshalReportHTML(rep)
	if err != nil {
		return nil, fmt.Errorf("project HTML: %w", err)
	}
	sarif, err := projection.MarshalReportSARIF(rep)
	if err != nil {
		return nil, fmt.Errorf("project SARIF: %w", err)
	}
	vex, err := projection.MarshalReportVEX(rep)
	if err != nil {
		return nil, fmt.Errorf("project OpenVEX: %w", err)
	}
	return []exportFile{
		{resultsink.FileReportJSON, reportJSON},
		{resultsink.FileReportHTML, html},
		{resultsink.FileSARIF, sarif},
		{resultsink.FileOpenVEX, vex},
	}, nil
}

func writeZip(path string, files []exportFile) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create zip: %w", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for _, file := range files {
		w, err := zw.Create(file.name)
		if err != nil {
			_ = zw.Close()
			return fmt.Errorf("zip entry %s: %w", file.name, err)
		}
		if _, err := w.Write(file.data); err != nil {
			_ = zw.Close()
			return fmt.Errorf("zip write %s: %w", file.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("close zip: %w", err)
	}
	return nil
}

// pathToFileURL renders an absolute path as a file:// URL with proper escaping.
func pathToFileURL(abs string) string {
	u := &url.URL{Scheme: "file", Path: abs}
	return u.String()
}

// openInBrowser best-effort launches the OS default opener for url. It never
// blocks on the child and treats a missing opener as a non-fatal error so a
// headless CI runner does not fail `state show`.
func openInBrowser(target string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{target}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", target}
	default:
		name, args = "xdg-open", []string{target}
	}
	bin, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("no OS opener (%s) on PATH", name)
	}
	cmd := exec.Command(bin, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap the child without blocking so we never hang the CLI.
	go func() { _ = cmd.Wait() }()
	return nil
}
