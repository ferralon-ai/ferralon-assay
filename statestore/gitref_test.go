package statestore

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// newTempStore inits a hermetic bare repo in a temp dir and returns a Store over
// it. No network; everything is local git plumbing.
func newTempStore(t *testing.T) *GitRefStore {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "--bare", "-q")
	return NewGitRefStore(Config{GitDir: dir})
}

func sampleReport(commit, cursor string, ts time.Time, advIDs ...string) *report.Report {
	b := report.NewBuilder(report.Subject{
		Repo:           "github.com/example/widget",
		Revision:       "main",
		ResolvedCommit: commit,
	}).AddPackage(report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"}).
		WithProvenance(report.Provenance{
			CommitSHA:       commit,
			AnalyzerVersion: "test",
			AdvisoryCursor:  cursor,
			Timestamp:       ts,
		})
	for _, id := range advIDs {
		b.NotExploitable(
			report.Advisory{ID: id, Source: "osv"},
			&report.Package{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.7"},
			verdict.BasisSymbolAbsent, "symbol absent")
	}
	r := b.Build()
	return &r
}

func TestReadNotFoundOnEmptyRepo(t *testing.T) {
	s := newTempStore(t)
	if _, err := s.Read(context.Background()); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	r := sampleReport("c0ffee", "cursor-1", ts, "GO-2021-0001")
	stmt := json.RawMessage(`{"vulnerability":{"@id":"GO-2021-0001"},"status":"not_affected"}`)
	in := &State{Report: r, SBOM: r.SBOM, Cursor: "cursor-1", VEXLog: []json.RawMessage{stmt}}

	committed, err := s.Write(ctx, in)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if committed.CommitSHA == "" {
		t.Fatal("expected a commit SHA after write")
	}

	got, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Cursor != "cursor-1" {
		t.Errorf("cursor: got %q want cursor-1", got.Cursor)
	}
	if got.Report == nil || len(got.Report.Advisories) != 1 {
		t.Fatalf("report round-trip lost advisories: %+v", got.Report)
	}
	if got.Report.Advisories[0].Advisory.ID != "GO-2021-0001" {
		t.Errorf("advisory id: got %q", got.Report.Advisories[0].Advisory.ID)
	}
	if len(got.SBOM.Packages) != 1 || got.SBOM.Packages[0].Name != "golang.org/x/text" {
		t.Errorf("sbom round-trip wrong: %+v", got.SBOM)
	}
	if len(got.VEXLog) != 1 {
		t.Fatalf("vex log: got %d entries want 1", len(got.VEXLog))
	}
	var rt map[string]any
	if err := json.Unmarshal(got.VEXLog[0], &rt); err != nil {
		t.Fatalf("vex entry not valid json: %v", err)
	}
	if got.CommitSHA != committed.CommitSHA {
		t.Errorf("read CommitSHA %q != written %q", got.CommitSHA, committed.CommitSHA)
	}
}

func TestRevokeCounterRoundTrip(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	r := sampleReport("c0ffee", "cursor-1", ts, "GO-2021-0001")

	// A zero counter writes no revoke blob and reads back as 0.
	if _, err := s.Write(ctx, &State{Report: r, Cursor: "cursor-1"}); err != nil {
		t.Fatalf("write zero-counter: %v", err)
	}
	got, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.RevokeCount != 0 {
		t.Fatalf("fresh state RevokeCount: got %d want 0", got.RevokeCount)
	}

	// A signed revoke bumps it; the value round-trips.
	got.RevokeCount = 2
	if _, err := s.Write(ctx, got); err != nil {
		t.Fatalf("write counter=2: %v", err)
	}
	got, err = s.Read(ctx)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if got.RevokeCount != 2 {
		t.Fatalf("RevokeCount round-trip: got %d want 2", got.RevokeCount)
	}

	// Reset to 0 drops the blob; read-absent is 0 again.
	got.RevokeCount = 0
	if _, err := s.Write(ctx, got); err != nil {
		t.Fatalf("write reset: %v", err)
	}
	got, err = s.Read(ctx)
	if err != nil {
		t.Fatalf("read after reset: %v", err)
	}
	if got.RevokeCount != 0 {
		t.Fatalf("RevokeCount after reset: got %d want 0", got.RevokeCount)
	}
}

// TestUnchangedFileYieldsZeroNewBlobObjects is the acceptance criterion: writing an
// identical State re-writes no file blobs/tree (only a new commit object, because
// the parent changed). We assert the report/sbom/cursor/vex BLOBS are reused by
// checking that the new tree references the exact same blob SHAs.
func TestUnchangedFileYieldsZeroNewBlobObjects(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	r := sampleReport("c0ffee", "cursor-1", ts, "GO-2021-0001")
	in := &State{Report: r, Cursor: "cursor-1"}

	first, err := s.Write(ctx, in)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	blobsBefore := treeBlobSHAs(t, s.cfg.GitDir, first.CommitSHA)

	// Re-read and write back an identical state.
	read, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	second, err := s.Write(ctx, read)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	blobsAfter := treeBlobSHAs(t, s.cfg.GitDir, second.CommitSHA)

	if len(blobsBefore) == 0 {
		t.Fatal("no blobs in first tree")
	}
	for name, sha := range blobsBefore {
		if blobsAfter[name] != sha {
			t.Errorf("file %q produced a new blob: %s -> %s (expected reuse / zero new objects)",
				name, sha, blobsAfter[name])
		}
	}
	// The tree SHA itself must be identical (same content-addressed tree).
	if treeSHAOf(t, s.cfg.GitDir, first.CommitSHA) != treeSHAOf(t, s.cfg.GitDir, second.CommitSHA) {
		t.Error("tree SHA changed across identical writes; content-addressing broken")
	}
}

// TestHeartbeatWritesOnlyChangedCursorBlob proves file-granularity: bumping only
// the cursor reuses the report/sbom/vex blobs and writes exactly one new blob.
func TestHeartbeatWritesOnlyChangedCursorBlob(t *testing.T) {
	s := newTempStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	r := sampleReport("c0ffee", "cursor-1", ts, "GO-2021-0001")
	stmt := json.RawMessage(`{"vulnerability":{"@id":"GO-2021-0001"},"status":"not_affected"}`)
	first, err := s.Write(ctx, &State{Report: r, Cursor: "cursor-1", VEXLog: []json.RawMessage{stmt}})
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	before := treeBlobSHAs(t, s.cfg.GitDir, first.CommitSHA)

	read, _ := s.Read(ctx)
	read.Cursor = "cursor-2" // heartbeat: cursor only
	second, err := s.Write(ctx, read)
	if err != nil {
		t.Fatalf("heartbeat write: %v", err)
	}
	after := treeBlobSHAs(t, s.cfg.GitDir, second.CommitSHA)

	for _, name := range []string{fileReport, fileSBOM, fileVEXLog} {
		if before[name] != after[name] {
			t.Errorf("%s blob changed on a cursor-only heartbeat: %s -> %s", name, before[name], after[name])
		}
	}
	if before[fileCursor] == after[fileCursor] {
		t.Error("cursor blob did not change on a heartbeat")
	}
}

func treeSHAOf(t *testing.T, dir, commit string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "rev-parse", commit+"^{tree}").CombinedOutput()
	if err != nil {
		t.Fatalf("rev-parse tree: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func treeBlobSHAs(t *testing.T, dir, commit string) map[string]string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "ls-tree", commit+"^{tree}").CombinedOutput()
	if err != nil {
		t.Fatalf("ls-tree: %v\n%s", err, out)
	}
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		// "<mode> blob <sha>\t<name>"
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		fields := strings.Fields(line[:tab])
		if len(fields) != 3 {
			continue
		}
		m[line[tab+1:]] = fields[2]
	}
	return m
}
