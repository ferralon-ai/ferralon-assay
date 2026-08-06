package statestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// GitHubRefStore is the GitHub Refs-API analogue of GitRefStore: it persists State
// as a content-addressed tree committed to a ref, updated under a fast-forward-only
// compare-and-swap, but over the GitHub Git Data REST API instead of local git
// plumbing. The FF-only CAS is expressed as `PATCH /repos/{o}/{r}/git/refs/{ref}`
// with `force=false`: GitHub refuses the update (HTTP 422) when the new commit is
// not a fast-forward of the current ref tip, which is exactly the same conflict
// signal `git update-ref <ref> <new> <expected-old>` produces locally. On that
// conflict the Write loop re-reads the winner, re-applies the local intent via the
// shared Merge rule, and retries with bounded backoff — the identical convergence
// contract as the local store; only the CAS swap and tree read/write are
// re-expressed over HTTP.
//
// It implements the same StateStore interface and the same Read→mutate→Write
// protocol (Read captures CommitSHA as the CAS token; Write does the CAS).
type GitHubRefStore struct {
	cfg GitHubConfig

	// ref is the resolved state ref this store writes — DefaultRef when the host
	// accepts custom refs, FallbackRef when the capability probe finds it rejected.
	// It is resolved lazily and once (cached) by the capability probe; see
	// capability.go.
	ref string
	// probedFn is the capability resolver; it sets ref. Defaulted to
	// probeCapability, overridable in tests. probeState caches the one-time run.
	probedFn func(context.Context) error
	probeState
}

// GitHubConfig configures the GitHub Refs-API store.
type GitHubConfig struct {
	// Owner and Repo identify the repository (github.com/{Owner}/{Repo}).
	Owner string
	Repo  string
	// Token is the API token sent as `Authorization: Bearer`. May be empty for an
	// unauthenticated read against a public repo (writes will fail at the API).
	Token string
	// BaseURL is the API root, e.g. "https://api.github.com". Tests point it at an
	// httptest server. "" means the public GitHub API.
	BaseURL string
	// HTTPClient is injected so tests run against httptest with no live network.
	// "" / nil means http.DefaultClient.
	HTTPClient *http.Client
	// Ref overrides the candidate custom ref. Defaults to DefaultRef. The capability
	// probe may cascade it to FallbackRef when the host rejects the custom namespace.
	Ref string
	// MaxRetries bounds the CAS merge-retry loop. 0 means the default (8).
	MaxRetries int
	// BaseBackoff is the initial backoff between retries; it doubles each attempt
	// (capped at one second). 0 means the default (5ms).
	BaseBackoff time.Duration
	// CommitAuthor is the identity stamped on state commits ("Name <email>"). ""
	// means a fixed neutral default so commit content is reproducible.
	CommitAuthor string
}

const defaultGitHubBaseURL = "https://api.github.com"

var _ StateStore = (*GitHubRefStore)(nil)

// NewGitHubRefStore builds a GitHubRefStore. It performs no network I/O; the
// capability probe (which resolves the state ref) runs lazily on first Read/Write.
func NewGitHubRefStore(cfg GitHubConfig) *GitHubRefStore {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultGitHubBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.Ref == "" {
		cfg.Ref = DefaultRef
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.BaseBackoff == 0 {
		cfg.BaseBackoff = defaultBaseBackoff
	}
	if cfg.CommitAuthor == "" {
		cfg.CommitAuthor = defaultAuthor
	}
	s := &GitHubRefStore{cfg: cfg}
	s.probedFn = s.probeCapability
	return s
}

// StateRef returns the ref this store writes to after the capability probe has run.
// Before the first Read/Write it returns the configured candidate ref. Callers that
// record the baseline pointer (report.BaselineRef.StateRef) read it after a Write.
func (s *GitHubRefStore) StateRef() string {
	if s.ref != "" {
		return s.ref
	}
	return s.cfg.Ref
}

// Read returns the current State at the resolved ref, capturing the commit SHA as
// the CAS token. It returns ErrNotFound when the ref does not exist yet.
func (s *GitHubRefStore) Read(ctx context.Context) (*State, error) {
	if err := s.ensureRef(ctx); err != nil {
		return nil, err
	}
	return s.readAt(ctx)
}

// readAt reads the state at the already-resolved ref without re-probing capability.
func (s *GitHubRefStore) readAt(ctx context.Context) (*State, error) {
	commitSHA, err := s.refCommit(ctx, s.ref)
	if err != nil {
		return nil, err
	}
	if commitSHA == "" {
		return nil, ErrNotFound
	}
	treeSHA, err := s.commitTree(ctx, commitSHA)
	if err != nil {
		return nil, err
	}
	files, err := s.treeFiles(ctx, treeSHA)
	if err != nil {
		return nil, err
	}

	st := &State{CommitSHA: commitSHA}
	if b, ok := files[fileReport]; ok {
		r, err := decodeReport(b)
		if err != nil {
			return nil, err
		}
		st.Report = r
		st.SBOM = r.SBOM
	}
	if b, ok := files[fileSBOM]; ok {
		var sb report.SBOM
		if err := json.Unmarshal(b, &sb); err != nil {
			return nil, fmt.Errorf("statestore: decode %s: %w", fileSBOM, err)
		}
		st.SBOM = sb
	}
	if b, ok := files[fileCursor]; ok {
		st.Cursor = strings.TrimRight(string(b), "\n")
	}
	if b, ok := files[fileVEXLog]; ok {
		st.VEXLog, err = decodeVEXLog(b)
		if err != nil {
			return nil, err
		}
	}
	return st, nil
}

// Write commits next under a FF-only CAS against next.CommitSHA, mirroring
// GitRefStore.Write: on an HTTP-422 non-fast-forward it re-reads the winner, Merges
// next's intent onto it, and retries with bounded exponential backoff. It returns
// the State actually committed (with its new CommitSHA), or ErrConflict when retries
// are exhausted. The resolved StateRef is stamped onto the committed Report's
// BaselineRef so downstream readers know which namespace the baseline lives in.
func (s *GitHubRefStore) Write(ctx context.Context, next *State) (*State, error) {
	if err := s.ensureRef(ctx); err != nil {
		return nil, err
	}
	cur := next
	backoff := s.cfg.BaseBackoff
	var lastErr error
	for attempt := 0; attempt <= s.cfg.MaxRetries; attempt++ {
		committed, err := s.tryWrite(ctx, cur)
		if err == nil {
			return committed, nil
		}
		if err != ErrConflict {
			return nil, err
		}
		lastErr = err

		winner, rerr := s.readAt(ctx)
		if rerr != nil && rerr != ErrNotFound {
			return nil, rerr
		}
		if rerr == ErrNotFound {
			// The ref vanished between the failed CAS and the re-read; retry as create.
			cur = &State{Report: cur.Report, SBOM: cur.SBOM, Cursor: cur.Cursor, VEXLog: cur.VEXLog}
		} else {
			cur = Merge(winner, cur)
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < time.Second {
			backoff *= 2
		}
	}
	return nil, fmt.Errorf("%w (exhausted %d retries): %v", ErrConflict, s.cfg.MaxRetries, lastErr)
}

// tryWrite performs one CAS attempt over the Git Data API: write each state file as
// a blob, assemble a tree, commit it with the read commit as parent, then swap the
// ref. A fresh state (empty CommitSHA) creates the ref via POST; an existing ref is
// updated via PATCH with force=false. A non-fast-forward (the ref moved) surfaces as
// ErrConflict, the same signal GitRefStore gets from a stale `git update-ref`.
func (s *GitHubRefStore) tryWrite(ctx context.Context, st *State) (*State, error) {
	st = s.stampStateRef(st)

	treeSHA, err := s.buildTree(ctx, st)
	if err != nil {
		return nil, err
	}
	commitSHA, err := s.createCommit(ctx, treeSHA, st.CommitSHA)
	if err != nil {
		return nil, err
	}
	if err := s.swapRef(ctx, commitSHA, st.CommitSHA == ""); err != nil {
		return nil, err
	}

	out := *st
	out.CommitSHA = commitSHA
	if out.Report != nil {
		out.SBOM = out.Report.SBOM
	}
	return &out, nil
}

// stampStateRef records the resolved ref on the State's Report baseline pointer so a
// reader can tell which namespace (custom vs fallback) the baseline lives in. It is
// a no-op when there is no Report. It returns a shallow copy so the caller's input
// is not mutated.
func (s *GitHubRefStore) stampStateRef(st *State) *State {
	if st.Report == nil {
		return st
	}
	cp := *st
	r := *st.Report
	base := report.BaselineRef{StateRef: s.ref}
	if r.Baseline != nil {
		base = *r.Baseline
		base.StateRef = s.ref
	}
	r.Baseline = &base
	cp.Report = &r
	return &cp
}

// buildTree writes the four state files as blobs and assembles a tree, omitting
// files whose State field is empty (a heartbeat with no Report writes only cursor +
// vex.log). GitHub deduplicates blobs/trees by content, so an unchanged file's bytes
// resolve to the existing object — the API analogue of `git hash-object` reuse.
func (s *GitHubRefStore) buildTree(ctx context.Context, st *State) (string, error) {
	type entry struct {
		name string
		data []byte
	}
	var entries []entry

	if st.Report != nil {
		b, err := marshalCanonical(st.Report)
		if err != nil {
			return "", fmt.Errorf("statestore: marshal report: %w", err)
		}
		entries = append(entries, entry{fileReport, b})
	}
	sbom := st.SBOM
	if st.Report != nil {
		sbom = st.Report.SBOM
	}
	if len(sbom.Packages) > 0 {
		b, err := marshalCanonical(sbom)
		if err != nil {
			return "", fmt.Errorf("statestore: marshal sbom: %w", err)
		}
		entries = append(entries, entry{fileSBOM, b})
	}
	if st.Cursor != "" {
		entries = append(entries, entry{fileCursor, []byte(st.Cursor + "\n")})
	}
	if len(st.VEXLog) > 0 {
		entries = append(entries, entry{fileVEXLog, encodeVEXLog(st.VEXLog)})
	}

	treeEntries := make([]ghTreeEntry, 0, len(entries))
	for _, e := range entries {
		blobSHA, err := s.createBlob(ctx, e.data)
		if err != nil {
			return "", fmt.Errorf("statestore: create blob %s: %w", e.name, err)
		}
		treeEntries = append(treeEntries, ghTreeEntry{
			Path: e.name,
			Mode: "100644",
			Type: "blob",
			SHA:  blobSHA,
		})
	}
	return s.createTree(ctx, treeEntries)
}

// --- Git Data API request/response shapes ---

type ghRefObject struct {
	SHA string `json:"sha"`
}

type ghRef struct {
	Ref    string      `json:"ref"`
	Object ghRefObject `json:"object"`
}

type ghCommit struct {
	SHA  string      `json:"sha"`
	Tree ghRefObject `json:"tree"`
}

type ghTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type ghTree struct {
	SHA  string        `json:"sha"`
	Tree []ghTreeEntry `json:"tree"`
}

type ghBlob struct {
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// refCommit resolves a fully-qualified ref (refs/...) to its commit SHA, or "" when
// the ref does not exist (HTTP 404). The Git Data refs endpoint takes the ref
// without the leading "refs/" segment.
func (s *GitHubRefStore) refCommit(ctx context.Context, ref string) (string, error) {
	var r ghRef
	status, err := s.do(ctx, http.MethodGet, "/git/ref/"+refPath(ref), nil, &r)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", nil
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("statestore: get ref %s: unexpected status %d", ref, status)
	}
	return r.Object.SHA, nil
}

func (s *GitHubRefStore) commitTree(ctx context.Context, commitSHA string) (string, error) {
	var c ghCommit
	status, err := s.do(ctx, http.MethodGet, "/git/commits/"+commitSHA, nil, &c)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("statestore: get commit %s: unexpected status %d", commitSHA, status)
	}
	return c.Tree.SHA, nil
}

// treeFiles reads the (flat) state tree and returns each file's decoded bytes keyed
// by path. The state tree has no subdirectories, so a non-recursive listing
// suffices; each entry's blob is fetched and base64-decoded.
func (s *GitHubRefStore) treeFiles(ctx context.Context, treeSHA string) (map[string][]byte, error) {
	var t ghTree
	status, err := s.do(ctx, http.MethodGet, "/git/trees/"+treeSHA, nil, &t)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("statestore: get tree %s: unexpected status %d", treeSHA, status)
	}
	out := make(map[string][]byte, len(t.Tree))
	for _, e := range t.Tree {
		if e.Type != "blob" {
			continue
		}
		b, err := s.readBlob(ctx, e.SHA)
		if err != nil {
			return nil, fmt.Errorf("statestore: read blob %s (%s): %w", e.Path, e.SHA, err)
		}
		out[e.Path] = b
	}
	return out, nil
}

func (s *GitHubRefStore) readBlob(ctx context.Context, blobSHA string) ([]byte, error) {
	var b ghBlob
	status, err := s.do(ctx, http.MethodGet, "/git/blobs/"+blobSHA, nil, &b)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("statestore: get blob %s: unexpected status %d", blobSHA, status)
	}
	if b.Encoding != "base64" {
		return nil, fmt.Errorf("statestore: blob %s has unexpected encoding %q", blobSHA, b.Encoding)
	}
	// GitHub wraps base64 blob content at 76 columns; strip whitespace before decode.
	dec, err := base64.StdEncoding.DecodeString(stripWS(b.Content))
	if err != nil {
		return nil, fmt.Errorf("statestore: decode blob %s: %w", blobSHA, err)
	}
	return dec, nil
}

func (s *GitHubRefStore) createBlob(ctx context.Context, data []byte) (string, error) {
	body := ghBlob{Content: base64.StdEncoding.EncodeToString(data), Encoding: "base64"}
	var out ghBlob
	status, err := s.do(ctx, http.MethodPost, "/git/blobs", body, &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("statestore: create blob: unexpected status %d", status)
	}
	return out.SHA, nil
}

func (s *GitHubRefStore) createTree(ctx context.Context, entries []ghTreeEntry) (string, error) {
	body := struct {
		Tree []ghTreeEntry `json:"tree"`
	}{Tree: entries}
	var out ghTree
	status, err := s.do(ctx, http.MethodPost, "/git/trees", body, &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("statestore: create tree: unexpected status %d", status)
	}
	return out.SHA, nil
}

// createCommit creates a commit object pointing at treeSHA, with parentSHA as its
// single parent (omitted for a root commit when the ref is being created). The
// author/committer + a fixed date mirror GitRefStore's deterministic commitEnv.
func (s *GitHubRefStore) createCommit(ctx context.Context, treeSHA, parentSHA string) (string, error) {
	name, email := parseAuthor(s.cfg.CommitAuthor)
	const fixedDate = "2026-01-01T00:00:00Z"
	ident := map[string]string{"name": name, "email": email, "date": fixedDate}
	body := map[string]any{
		"message":   brand.Name + " state",
		"tree":      treeSHA,
		"author":    ident,
		"committer": ident,
	}
	if parentSHA != "" {
		body["parents"] = []string{parentSHA}
	} else {
		body["parents"] = []string{}
	}
	var out ghCommit
	status, err := s.do(ctx, http.MethodPost, "/git/commits", body, &out)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("statestore: create commit: unexpected status %d", status)
	}
	return out.SHA, nil
}

// swapRef performs the CAS swap: it POSTs a new ref when create is true, or PATCHes
// an existing ref with force=false otherwise. A force=false PATCH that is not a
// fast-forward returns HTTP 422 — the conflict signal that maps to ErrConflict. A
// create against an already-existing ref returns HTTP 422 too (ref already exists),
// which is likewise a CAS conflict (a concurrent create won).
func (s *GitHubRefStore) swapRef(ctx context.Context, commitSHA string, create bool) error {
	if create {
		body := map[string]string{"ref": s.ref, "sha": commitSHA}
		status, err := s.do(ctx, http.MethodPost, "/git/refs", body, nil)
		if err != nil {
			return err
		}
		switch status {
		case http.StatusCreated:
			return nil
		case http.StatusUnprocessableEntity:
			return ErrConflict
		default:
			return fmt.Errorf("statestore: create ref %s: unexpected status %d", s.ref, status)
		}
	}

	body := map[string]any{"sha": commitSHA, "force": false}
	status, err := s.do(ctx, http.MethodPatch, "/git/refs/"+refPath(s.ref), body, nil)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusUnprocessableEntity, http.StatusConflict:
		// Non-fast-forward: the ref moved since we read it. CAS conflict.
		return ErrConflict
	default:
		return fmt.Errorf("statestore: update ref %s: unexpected status %d", s.ref, status)
	}
}

// --- HTTP plumbing ---

// do issues one API request against {BaseURL}/repos/{owner}/{repo}{path}, encoding
// body as JSON when non-nil and decoding the response into out when non-nil. It
// returns the HTTP status so callers can branch on 404 (absent) / 422 (conflict)
// without those being treated as transport errors. Non-2xx-and-non-handled statuses
// are returned with their code for the caller to interpret.
func (s *GitHubRefStore) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("statestore: marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	url := s.cfg.BaseURL + "/repos/" + s.cfg.Owner + "/" + s.cfg.Repo + path
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return 0, fmt.Errorf("statestore: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("statestore: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("statestore: read response %s %s: %w", method, path, err)
	}
	if out != nil && len(raw) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("statestore: decode response %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// refPath strips the leading "refs/" the Git Data ref endpoints do not want:
// GET /git/ref/{type}/{name} and PATCH /git/refs/{type}/{name} address the ref as
// "heads/foo" or "assay/state", never "refs/heads/foo".
func refPath(ref string) string {
	return strings.TrimPrefix(ref, "refs/")
}

// stripWS removes all ASCII whitespace from s (GitHub line-wraps base64 blobs).
func stripWS(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}
