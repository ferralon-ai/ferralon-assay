package cfamilycgx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/cfamilyanalysis/compiledb"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// edgeRow is one graph_query row: caller, edge kind, confidence, callee.
type edgeRow [4]string

// fakeGraph serves cgx's search and graph_query tools from fixed nodes and edge rows, in pages
// of pageLen, standing in for the SDK.
type fakeGraph struct {
	nodes    []node
	rows     []edgeRow
	pageLen  int
	version  func(tool string, page int) string // graph_version per page; default "v1"
	truncate bool                               // mark the last graph_query page truncated
	indexErr error
	calls    map[string]int
}

func (f *fakeGraph) Index(context.Context) error { return f.indexErr }

func (f *fakeGraph) Stats() json.RawMessage { return nil }

func (f *fakeGraph) Close() error { return nil }

func (f *fakeGraph) Call(_ context.Context, tool string, args map[string]any) (json.RawMessage, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	page := f.calls[tool]
	f.calls[tool]++
	n := f.pageLen
	if n == 0 {
		n = 1 << 30
	}
	start := 0
	if c, ok := args["cursor"].(string); ok {
		start, _ = strconv.Atoi(c)
	}
	version := "v1"
	if f.version != nil {
		version = f.version(tool, page)
	}
	out := map[string]any{"graph_version": version}
	var total int
	switch tool {
	case "search":
		total = len(f.nodes)
		end := min(start+n, total)
		out["results"] = f.nodes[start:end]
	case "graph_query":
		total = len(f.rows)
		end := min(start+n, total)
		rows := make([][]any, 0, end-start)
		for _, r := range f.rows[start:end] {
			cells := make([]any, 4)
			for i, c := range r {
				if c != "" {
					cells[i] = c
				}
			}
			rows = append(rows, cells)
		}
		out["columns"] = []string{"a.fqn", "r.kind", "r.confidence", "b.fqn"}
		out["rows"] = rows
		out["truncated"] = f.truncate && end == total
	default:
		return nil, fmt.Errorf("fake: unexpected tool %q", tool)
	}
	if end := start + n; end < total {
		out["has_more"] = true
		out["cursor"] = strconv.Itoa(end)
	}
	return json.Marshal(out)
}

// fakeOpener opens g for every operation and records each repository it was handed.
type fakeOpener struct {
	g     Graph
	err   error
	repos []string
	cfgs  []Config
}

func (o *fakeOpener) open(_ context.Context, repo string, cfg Config) (Graph, error) {
	o.repos = append(o.repos, repo)
	o.cfgs = append(o.cfgs, cfg)
	if o.err != nil {
		return nil, o.err
	}
	return o.g, nil
}

// newTestLane returns a Lane over open with its cache under a temp dir and its stats record
// discarded.
func newTestLane(t *testing.T, cfg Config, open Opener) *Lane {
	t.Helper()
	if cfg.CacheDir == "" {
		cfg.CacheDir = t.TempDir()
	}
	if cfg.Transport == "" {
		cfg.Transport = TransportWasm
	}
	l := New(cfg, open, "test-engine", "test-fallback")
	l.stderr = io.Discard
	return l
}

// withDB makes the lane read db as the build's compilation database.
func withDB(l *Lane, db *compiledb.DB) {
	l.sources = func(string) (cfamilyanalysis.GraphSources, error) {
		return cfamilyanalysis.GraphSources{Partiality: plugin.Complete(), DB: db}, nil
	}
}

// writeTree writes files (relative path -> content) under a new temp dir and returns it with
// symlinks resolved.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for p, c := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// stagedFiles lists the files committed to a snapshot repository.
func stagedFiles(t *testing.T, repo string) []string {
	t.Helper()
	cmd := exec.Command("git", "--git-dir="+filepath.Join(repo, ".git"), "ls-tree", "-r", "--name-only", "HEAD")
	cmd.Env = gitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ls-tree: %v", err)
	}
	return strings.Fields(string(out))
}

func hasReason(p plugin.Partiality, want string) bool {
	for _, r := range p.Reasons {
		if r == want {
			return true
		}
	}
	return false
}

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }
