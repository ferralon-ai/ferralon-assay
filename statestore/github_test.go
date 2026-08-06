package statestore

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockGitHub is a minimal in-memory implementation of the GitHub Git Data API
// (blobs / trees / commits / refs) sufficient to exercise GitHubRefStore
// hermetically — no live network. It content-addresses objects with real SHA-1 so
// identical bytes reuse a SHA (mirroring git), and enforces force=false CAS: a PATCH
// whose new commit's parent is not the current ref tip returns HTTP 422.
type mockGitHub struct {
	mu      sync.Mutex
	blobs   map[string][]byte        // sha -> raw bytes
	trees   map[string][]ghTreeEntry // sha -> entries
	commits map[string]mockCommit    // sha -> commit
	refs    map[string]string        // fully-qualified ref -> commit sha
	owner   string
	repo    string
	// rejectCustomRefs makes the GET /git/ref/{custom} probe return 422, simulating a
	// host (Gerrit/GitLab/Azure DevOps) that denies the custom namespace.
	rejectCustomRefs bool
}

type mockCommit struct {
	Tree    string
	Parents []string
}

func newMockGitHub(owner, repo string) *mockGitHub {
	return &mockGitHub{
		blobs:   map[string][]byte{},
		trees:   map[string][]ghTreeEntry{},
		commits: map[string]mockCommit{},
		refs:    map[string]string{},
		owner:   owner,
		repo:    repo,
	}
}

func mockSHA(kind string, b []byte) string {
	h := sha1.Sum(append([]byte(kind+":"), b...))
	return hex.EncodeToString(h[:])
}

func (m *mockGitHub) handler() http.Handler {
	prefix := "/repos/" + m.owner + "/" + m.repo
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.Error(w, "wrong repo path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, prefix)
		m.route(w, r, p)
	})
}

func (m *mockGitHub) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	return srv
}

func (m *mockGitHub) route(w http.ResponseWriter, r *http.Request, p string) {
	switch {
	case r.Method == http.MethodPost && p == "/git/blobs":
		m.createBlob(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/git/blobs/"):
		m.getBlob(w, strings.TrimPrefix(p, "/git/blobs/"))
	case r.Method == http.MethodPost && p == "/git/trees":
		m.createTree(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/git/trees/"):
		m.getTree(w, strings.TrimPrefix(p, "/git/trees/"))
	case r.Method == http.MethodPost && p == "/git/commits":
		m.createCommit(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/git/commits/"):
		m.getCommit(w, strings.TrimPrefix(p, "/git/commits/"))
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/git/ref/"):
		m.getRef(w, "refs/"+strings.TrimPrefix(p, "/git/ref/"))
	case r.Method == http.MethodPost && p == "/git/refs":
		m.createRef(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(p, "/git/refs/"):
		m.patchRef(w, r, "refs/"+strings.TrimPrefix(p, "/git/refs/"))
	default:
		http.Error(w, "unhandled "+r.Method+" "+p, http.StatusNotImplemented)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request, v any) error {
	b, _ := io.ReadAll(r.Body)
	return json.Unmarshal(b, v)
}

func (m *mockGitHub) createBlob(w http.ResponseWriter, r *http.Request) {
	var in ghBlob
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(in.Content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sha := mockSHA("blob", raw)
	m.blobs[sha] = raw
	writeJSON(w, http.StatusCreated, ghBlob{SHA: sha})
}

func (m *mockGitHub) getBlob(w http.ResponseWriter, sha string) {
	raw, ok := m.blobs[sha]
	if !ok {
		http.Error(w, "no blob", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ghBlob{
		SHA:      sha,
		Content:  base64.StdEncoding.EncodeToString(raw),
		Encoding: "base64",
	})
}

func (m *mockGitHub) createTree(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tree []ghTreeEntry `json:"tree"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	canon, _ := json.Marshal(in.Tree)
	sha := mockSHA("tree", canon)
	m.trees[sha] = in.Tree
	writeJSON(w, http.StatusCreated, ghTree{SHA: sha, Tree: in.Tree})
}

func (m *mockGitHub) getTree(w http.ResponseWriter, sha string) {
	entries, ok := m.trees[sha]
	if !ok {
		http.Error(w, "no tree", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ghTree{SHA: sha, Tree: entries})
}

func (m *mockGitHub) createCommit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Message string   `json:"message"`
		Tree    string   `json:"tree"`
		Parents []string `json:"parents"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	canon, _ := json.Marshal(in)
	sha := mockSHA("commit", canon)
	m.commits[sha] = mockCommit{Tree: in.Tree, Parents: in.Parents}
	writeJSON(w, http.StatusCreated, ghCommit{SHA: sha, Tree: ghRefObject{SHA: in.Tree}})
}

func (m *mockGitHub) getCommit(w http.ResponseWriter, sha string) {
	c, ok := m.commits[sha]
	if !ok {
		http.Error(w, "no commit", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ghCommit{SHA: sha, Tree: ghRefObject{SHA: c.Tree}})
}

func (m *mockGitHub) getRef(w http.ResponseWriter, ref string) {
	if m.rejectCustomRefs && isCustomRef(ref) {
		http.Error(w, "custom refs not permitted", http.StatusUnprocessableEntity)
		return
	}
	sha, ok := m.refs[ref]
	if !ok {
		http.Error(w, "no ref", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, ghRef{Ref: ref, Object: ghRefObject{SHA: sha}})
}

func (m *mockGitHub) createRef(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, exists := m.refs[in.Ref]; exists {
		http.Error(w, "ref already exists", http.StatusUnprocessableEntity)
		return
	}
	m.refs[in.Ref] = in.SHA
	writeJSON(w, http.StatusCreated, ghRef{Ref: in.Ref, Object: ghRefObject{SHA: in.SHA}})
}

// patchRef enforces force=false CAS: the update is accepted only when the new
// commit's first parent is the ref's current tip (a fast-forward). Otherwise it is a
// non-fast-forward → HTTP 422, the conflict signal.
func (m *mockGitHub) patchRef(w http.ResponseWriter, r *http.Request, ref string) {
	var in struct {
		SHA   string `json:"sha"`
		Force bool   `json:"force"`
	}
	if err := decodeBody(r, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cur, ok := m.refs[ref]
	if !ok {
		http.Error(w, "no ref", http.StatusNotFound)
		return
	}
	if !in.Force {
		c, ok := m.commits[in.SHA]
		if !ok || !contains(c.Parents, cur) {
			http.Error(w, "not a fast-forward", http.StatusUnprocessableEntity)
			return
		}
	}
	m.refs[ref] = in.SHA
	writeJSON(w, http.StatusOK, ghRef{Ref: ref, Object: ghRefObject{SHA: in.SHA}})
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// newMockStore wires a GitHubRefStore at a fresh mock GitHub server.
func newMockStore(t *testing.T, m *mockGitHub) *GitHubRefStore {
	t.Helper()
	srv := m.server(t)
	return NewGitHubRefStore(GitHubConfig{
		Owner:      m.owner,
		Repo:       m.repo,
		BaseURL:    srv.URL,
		HTTPClient: srv.Client(),
		Token:      "test-token",
	})
}

func TestGitHubInterfaceSatisfied(t *testing.T) {
	var _ StateStore = (*GitHubRefStore)(nil)
}

func TestGitHubWriteReadRoundTrip(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	s := newMockStore(t, m)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	if _, err := s.Read(ctx); err != ErrNotFound {
		t.Fatalf("fresh repo: want ErrNotFound, got %v", err)
	}

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
	if got.CommitSHA != committed.CommitSHA {
		t.Errorf("read CommitSHA %q != written %q", got.CommitSHA, committed.CommitSHA)
	}
}

// TestGitHubCASRejectsNonFastForwardAndMergeConverges is the keystone CAS test: a
// race-loser writing against a stale CommitSHA must hit the force=false 422, re-read
// the winner, Merge its intent, and converge — the final state unions both racers'
// advisories. It is the API analogue of TestCASRejectsNonFastForwardAndMergeConverges.
func TestGitHubCASRejectsNonFastForwardAndMergeConverges(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	s := newMockStore(t, m)
	ctx := context.Background()
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	if _, err := s.Write(ctx, &State{Report: sampleReport("base", "cursor-0", t0, "GO-0000-0000"), Cursor: "cursor-0"}); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	aRead, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("A read: %v", err)
	}
	bRead, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("B read: %v", err)
	}

	// B commits a newer state — B wins the ref.
	bRead.Report = sampleReport("bbb", "cursor-B", t0.Add(time.Hour), "GO-2021-B")
	bRead.Cursor = "cursor-B"
	if _, err := s.Write(ctx, bRead); err != nil {
		t.Fatalf("B write: %v", err)
	}

	// A writes against its now-stale CommitSHA: must 422 → merge → converge.
	aRead.Report = sampleReport("aaa", "cursor-A", t0.Add(2*time.Hour), "GO-2021-A")
	aRead.Cursor = "cursor-A"
	committed, err := s.Write(ctx, aRead)
	if err != nil {
		t.Fatalf("A write should converge, got: %v", err)
	}

	final, err := s.Read(ctx)
	if err != nil {
		t.Fatalf("final read: %v", err)
	}
	if final.CommitSHA != committed.CommitSHA {
		t.Errorf("committed SHA %q != final ref %q", committed.CommitSHA, final.CommitSHA)
	}
	ids := map[string]bool{}
	for _, f := range final.Report.Advisories {
		ids[f.Advisory.ID] = true
	}
	for _, want := range []string{"GO-2021-A", "GO-2021-B"} {
		if !ids[want] {
			t.Errorf("merged report missing advisory %q (have %v)", want, ids)
		}
	}
	if final.Report.Provenance.AdvisoryCursor != "cursor-A" {
		t.Errorf("later scan's cursor should win: got %q want cursor-A", final.Report.Provenance.AdvisoryCursor)
	}
}

// TestGitHubCASConflictRespectsRetryBudget: with MaxRetries=0 against a moved ref the
// stale write surfaces ErrConflict rather than looping forever.
func TestGitHubCASConflictRespectsRetryBudget(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	s := newMockStore(t, m)
	s.cfg.MaxRetries = 0
	ctx := context.Background()
	t0 := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	if _, err := s.Write(ctx, &State{Report: sampleReport("s", "c0", t0), Cursor: "c0"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stale, _ := s.Read(ctx)

	// Advance the ref so stale's CommitSHA is no longer current.
	if _, err := s.Write(ctx, &State{Report: sampleReport("s2", "c1", t0.Add(time.Hour)), Cursor: "c1", CommitSHA: stale.CommitSHA}); err != nil {
		t.Fatalf("advance: %v", err)
	}

	stale.Report = sampleReport("s3", "c2", t0.Add(2*time.Hour))
	if _, err := s.Write(ctx, stale); err == nil {
		t.Fatal("expected ErrConflict with zero retry budget against a moved ref")
	}
}

// TestGitHubHeartbeatReusesBlobs proves file-granular content addressing: a
// cursor-only heartbeat reuses the report/sbom/vex blob SHAs and rewrites only the
// cursor blob.
func TestGitHubHeartbeatReusesBlobs(t *testing.T) {
	m := newMockGitHub("acme", "widget")
	s := newMockStore(t, m)
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	r := sampleReport("c0ffee", "cursor-1", ts, "GO-2021-0001")

	first, err := s.Write(ctx, &State{Report: r, Cursor: "cursor-1"})
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	before := m.treeBlobsOf(t, first.CommitSHA)

	read, _ := s.Read(ctx)
	read.Cursor = "cursor-2"
	second, err := s.Write(ctx, read)
	if err != nil {
		t.Fatalf("heartbeat write: %v", err)
	}
	after := m.treeBlobsOf(t, second.CommitSHA)

	for _, name := range []string{fileReport, fileSBOM} {
		if before[name] == "" {
			continue
		}
		if before[name] != after[name] {
			t.Errorf("%s blob changed on a cursor-only heartbeat: %s -> %s", name, before[name], after[name])
		}
	}
	if before[fileCursor] == after[fileCursor] {
		t.Error("cursor blob did not change on a heartbeat")
	}
}

func (m *mockGitHub) treeBlobsOf(t *testing.T, commitSHA string) map[string]string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.commits[commitSHA]
	if !ok {
		t.Fatalf("no commit %s", commitSHA)
	}
	out := map[string]string{}
	for _, e := range m.trees[c.Tree] {
		out[e.Path] = e.SHA
	}
	return out
}

// TestGitHubRequestShape asserts the auth/version headers and force=false CAS body
// the adapter sends, so the HTTP contract is pinned, not just the in-memory effect.
func TestGitHubRequestShape(t *testing.T) {
	var sawAuth, sawAPIVersion string
	var patchBody map[string]any
	m := newMockGitHub("acme", "widget")
	inner := m.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawAPIVersion = r.Header.Get("X-GitHub-Api-Version")
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/git/refs/") {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			r.Body = io.NopCloser(strings.NewReader(string(b)))
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	s := NewGitHubRefStore(GitHubConfig{
		Owner: "acme", Repo: "widget", BaseURL: srv.URL, HTTPClient: srv.Client(), Token: "secret",
	})
	ctx := context.Background()
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	if _, err := s.Write(ctx, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"}); err != nil {
		t.Fatalf("create write: %v", err)
	}
	read, _ := s.Read(ctx)
	read.Cursor = "cur2"
	if _, err := s.Write(ctx, read); err != nil { // triggers a PATCH
		t.Fatalf("update write: %v", err)
	}

	if sawAuth != "Bearer secret" {
		t.Errorf("Authorization header: got %q", sawAuth)
	}
	if sawAPIVersion != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version: got %q", sawAPIVersion)
	}
	if patchBody == nil {
		t.Fatal("no PATCH /git/refs observed")
	}
	if force, ok := patchBody["force"].(bool); !ok || force {
		t.Errorf("CAS must send force=false, got %v", patchBody["force"])
	}
}
