package statestore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// Config configures the git-orphan-ref Store.
type Config struct {
	// GitDir is the path to the repository (a working tree or a bare repo) whose ref
	// holds the state. The Store runs `git -C GitDir ...` plumbing against it.
	GitDir string
	// Bin is the git binary; "" means "git" on PATH.
	Bin string
	// Ref is the state ref. Defaults to DefaultRef ("refs/assay/state"). Set it to
	// FallbackRef ("refs/heads/assay/state") for hosts that reject custom refs — the
	// load-bearing portability cascade. The caller (an adapter) decides which ref the
	// host accepts; the Store just writes the one configured.
	Ref string
	// MaxRetries bounds the CAS merge-retry loop. 0 means the default (8).
	MaxRetries int
	// BaseBackoff is the initial backoff between retries; it doubles each attempt
	// (capped). 0 means the default (5ms — kept small because tests run offline and
	// real contention against a local ref resolves immediately).
	BaseBackoff time.Duration
	// CommitAuthor is the identity stamped on state commits. "" means a fixed neutral
	// default so commit SHAs are reproducible across machines for a given tree+parent.
	CommitAuthor string
}

const (
	defaultMaxRetries  = 8
	defaultBaseBackoff = 5 * time.Millisecond
)

// defaultAuthor is the neutral identity stamped on state commits. It is a var (not a
// const) so the brand name flows through at link time via the brand package.
var defaultAuthor = brand.Name + " <" + brand.Name + "@localhost>"

// GitRefStore is the git-orphan-ref StateStore: it persists State as a
// content-addressed, file-granular tree committed to Config.Ref, updated under a
// fast-forward-only CAS via `git update-ref` with an expected-old value. It is the
// portable default; the GitHub Refs-API adapter (Phase 3) implements the same
// StateStore contract over REST.
type GitRefStore struct {
	cfg Config
}

var _ StateStore = (*GitRefStore)(nil)

// NewGitRefStore builds a GitRefStore. It does not touch the repo; Read/Write do.
func NewGitRefStore(cfg Config) *GitRefStore {
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
	return &GitRefStore{cfg: cfg}
}

// StateRef returns the ref this store reads and writes — the configured Config.Ref,
// or DefaultRef when none was given (NewGitRefStore resolves the default at
// construction, so this is never empty). Lets a caller that already holds a Store —
// self-cleanup, notably — discover the ref the run was actually configured with
// instead of re-deriving it from environment/flags or assuming the default.
func (s *GitRefStore) StateRef() string {
	return s.cfg.Ref
}

// Read returns the current State at the ref. It resolves the ref to a commit, reads
// the four files out of that commit's tree, and records the commit SHA as the CAS
// token. Missing files (a partially-populated state) are tolerated: their fields
// stay zero. It returns ErrNotFound when the ref does not exist.
func (s *GitRefStore) Read(ctx context.Context) (*State, error) {
	sha, err := s.resolveRef(ctx)
	if err != nil {
		return nil, err
	}
	if sha == "" {
		return nil, ErrNotFound
	}
	st := &State{CommitSHA: sha}

	if b, ok, err := s.readFile(ctx, sha, fileReport); err != nil {
		return nil, err
	} else if ok {
		r, err := decodeReport(b)
		if err != nil {
			return nil, err
		}
		st.Report = r
		st.SBOM = r.SBOM
	}

	if b, ok, err := s.readFile(ctx, sha, fileSBOM); err != nil {
		return nil, err
	} else if ok {
		var sb report.SBOM
		if err := json.Unmarshal(b, &sb); err != nil {
			return nil, fmt.Errorf("statestore: decode %s: %w", fileSBOM, err)
		}
		st.SBOM = sb
	}

	if b, ok, err := s.readFile(ctx, sha, fileCursor); err != nil {
		return nil, err
	} else if ok {
		st.Cursor = strings.TrimRight(string(b), "\n")
	}

	if b, ok, err := s.readFile(ctx, sha, fileVEXLog); err != nil {
		return nil, err
	} else if ok {
		st.VEXLog, err = decodeVEXLog(b)
		if err != nil {
			return nil, err
		}
	}

	if b, ok, err := s.readFile(ctx, sha, fileRevoke); err != nil {
		return nil, err
	} else if ok {
		n, perr := strconv.Atoi(strings.TrimSpace(string(b)))
		if perr != nil {
			return nil, fmt.Errorf("statestore: decode %s: %w", fileRevoke, perr)
		}
		st.RevokeCount = n
	}
	return st, nil
}

// Write commits next under a FF-only CAS against next.CommitSHA. On a conflict
// (the ref moved) it re-reads, Merges next's intent onto the winner, and retries
// with bounded exponential backoff. It returns the State actually committed (with
// its new CommitSHA), or ErrConflict when retries are exhausted.
func (s *GitRefStore) Write(ctx context.Context, next *State) (*State, error) {
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

		winner, rerr := s.Read(ctx)
		if rerr != nil && rerr != ErrNotFound {
			return nil, rerr
		}
		if rerr == ErrNotFound {
			// The ref vanished between our failed CAS and the re-read; retry as a
			// create against an empty expected-old.
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

// tryWrite performs one CAS attempt: build the tree (reusing unchanged blobs),
// commit it with the read commit as parent, and atomically swap the ref only if it
// still points at st.CommitSHA. A non-fast-forward (the ref moved) surfaces as
// ErrConflict.
func (s *GitRefStore) tryWrite(ctx context.Context, st *State) (*State, error) {
	treeSHA, err := s.buildTree(ctx, st)
	if err != nil {
		return nil, err
	}

	commitArgs := []string{"commit-tree", treeSHA, "-m", brand.Name + " state"}
	if st.CommitSHA != "" {
		commitArgs = append(commitArgs, "-p", st.CommitSHA)
	}
	commitSHA, err := s.gitEnv(ctx, commitEnv(s.cfg.CommitAuthor), commitArgs...)
	if err != nil {
		return nil, fmt.Errorf("statestore: commit-tree: %w", err)
	}
	commitSHA = strings.TrimSpace(commitSHA)

	// CAS: update-ref with an expected-old value. git refuses the update (non-zero
	// exit) if the ref no longer points at st.CommitSHA, which is exactly the
	// fast-forward-only compare-and-swap. An empty old value asserts the ref must not
	// already exist (create).
	old := st.CommitSHA
	if old == "" {
		old = strings.Repeat("0", 40) // the zero OID: "ref must not exist"
	}
	if _, err := s.git(ctx, "update-ref", s.cfg.Ref, commitSHA, old); err != nil {
		// update-ref fails on a stale expected-old (the ref moved) — a CAS conflict.
		return nil, ErrConflict
	}

	out := *st
	out.CommitSHA = commitSHA
	if out.Report != nil {
		out.SBOM = out.Report.SBOM
	}
	return &out, nil
}

// buildTree writes the four state files as blobs and assembles a tree. Unchanged
// blobs are content-addressed: `git hash-object -w` returns the existing blob SHA
// for identical bytes and writes NO new object, so a write that changes only one
// file produces exactly one new blob (plus the new tree+commit). Files whose State
// field is empty are omitted from the tree (a heartbeat with no Report writes only
// cursor + vex.log).
func (s *GitRefStore) buildTree(ctx context.Context, st *State) (string, error) {
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
	// Persist the SBOM as its own file. When a Report is present its SBOM is the
	// source of truth (keeps the two consistent and byte-stable across writes).
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
	// The revoke counter is carried in the tree only while non-zero: a reset to 0
	// drops the blob (read-absent → 0), and a repo that never revokes writes none.
	if st.RevokeCount > 0 {
		entries = append(entries, entry{fileRevoke, []byte(strconv.Itoa(st.RevokeCount))})
	}

	var mktree bytes.Buffer
	for _, e := range entries {
		blobSHA, err := s.hashObject(ctx, e.data)
		if err != nil {
			return "", fmt.Errorf("statestore: hash-object %s: %w", e.name, err)
		}
		// mktree line: "<mode> blob <sha>\t<name>" (100644 = normal file).
		fmt.Fprintf(&mktree, "100644 blob %s\t%s\n", blobSHA, e.name)
	}

	treeSHA, err := s.gitStdin(ctx, mktree.Bytes(), "mktree")
	if err != nil {
		return "", fmt.Errorf("statestore: mktree: %w", err)
	}
	return strings.TrimSpace(treeSHA), nil
}

// resolveRef returns the commit SHA the ref points at, or "" if the ref does not
// exist.
func (s *GitRefStore) resolveRef(ctx context.Context) (string, error) {
	out, err := s.git(ctx, "rev-parse", "--verify", "--quiet", s.cfg.Ref+"^{commit}")
	if err != nil {
		// rev-parse --verify --quiet exits non-zero with empty output for a missing
		// ref; distinguish that from a real error by the empty stdout.
		if strings.TrimSpace(out) == "" {
			return "", nil
		}
		return "", fmt.Errorf("statestore: rev-parse %s: %w", s.cfg.Ref, err)
	}
	return strings.TrimSpace(out), nil
}

// readFile reads one file out of a commit's tree. ok is false when the file is
// absent from the tree (tolerated).
func (s *GitRefStore) readFile(ctx context.Context, commitSHA, name string) ([]byte, bool, error) {
	spec := commitSHA + ":" + name
	out, err := s.gitRaw(ctx, "cat-file", "-p", spec)
	if err != nil {
		// A missing path makes cat-file exit non-zero; treat as absent.
		return nil, false, nil
	}
	return out, true, nil
}

func (s *GitRefStore) hashObject(ctx context.Context, data []byte) (string, error) {
	out, err := s.gitStdin(ctx, data, "hash-object", "-w", "--stdin")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// --- git invocation helpers (mirroring checkout.GitCheckout's shelling style) ---

func (s *GitRefStore) bin() string {
	if s.cfg.Bin == "" {
		return "git"
	}
	return s.cfg.Bin
}

func (s *GitRefStore) baseArgs(args ...string) []string {
	return append([]string{"-C", s.cfg.GitDir}, args...)
}

func (s *GitRefStore) git(ctx context.Context, args ...string) (string, error) {
	out, err := s.gitRaw(ctx, args...)
	return string(out), err
}

func (s *GitRefStore) gitRaw(ctx context.Context, args ...string) ([]byte, error) {
	return s.runEnv(ctx, nil, nil, args...)
}

func (s *GitRefStore) gitStdin(ctx context.Context, stdin []byte, args ...string) (string, error) {
	out, err := s.runEnv(ctx, stdin, nil, args...)
	return string(out), err
}

func (s *GitRefStore) gitEnv(ctx context.Context, env []string, args ...string) (string, error) {
	out, err := s.runEnv(ctx, nil, env, args...)
	return string(out), err
}

func (s *GitRefStore) runEnv(ctx context.Context, stdin []byte, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.bin(), s.baseArgs(args...)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	if env != nil {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// commitEnv builds a deterministic git environment so commit SHAs depend only on
// tree + parent (not wall-clock / machine identity). A fixed author+committer and
// a fixed date make an unchanged write produce an identical commit SHA, reinforcing
// the zero-new-objects guarantee at the commit layer too. author is "Name <email>".
func commitEnv(author string) []string {
	name, email := parseAuthor(author)
	const fixedDate = "2026-01-01T00:00:00Z"
	base := append([]string{}, gitOSEnv()...)
	return append(base,
		"GIT_AUTHOR_NAME="+name,
		"GIT_AUTHOR_EMAIL="+email,
		"GIT_AUTHOR_DATE="+fixedDate,
		"GIT_COMMITTER_NAME="+name,
		"GIT_COMMITTER_EMAIL="+email,
		"GIT_COMMITTER_DATE="+fixedDate,
	)
}

func parseAuthor(author string) (name, email string) {
	name, email = brand.Name, brand.Name+"@localhost"
	if i := strings.Index(author, "<"); i >= 0 {
		name = strings.TrimSpace(author[:i])
		if j := strings.Index(author[i:], ">"); j >= 0 {
			email = author[i+1 : i+j]
		}
	}
	return name, email
}

// --- (de)serialization of the four files ---

// marshalCanonical marshals v with stable key order (encoding/json sorts struct
// fields by declaration and map keys lexically) and no trailing newline, so an
// unchanged value yields byte-identical output → the same blob SHA → zero new
// objects. report.Build already sorts SBOM + findings, so a re-marshalled
// unchanged Report is byte-identical.
func marshalCanonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

// encodeVEXLog renders the append-log as NDJSON: one statement per line, each
// canonicalised so an unchanged log is byte-stable.
func encodeVEXLog(log []json.RawMessage) []byte {
	var buf bytes.Buffer
	for _, e := range log {
		buf.Write(canonicalJSON(e))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func decodeVEXLog(b []byte) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for i, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, fmt.Errorf("statestore: %s line %d is not valid JSON", fileVEXLog, i+1)
		}
		out = append(out, append(json.RawMessage(nil), line...))
	}
	return out, nil
}

// gitOSEnv returns a minimal environment for git plumbing: it passes through the
// process env (so git finds its binary, config, and exec path) while commitEnv
// overrides author/committer for deterministic commits. Passing the full env keeps
// the Store hermetic-test-friendly without assuming a configured user.name/email
// (commitEnv supplies those).
func gitOSEnv() []string {
	return os.Environ()
}
