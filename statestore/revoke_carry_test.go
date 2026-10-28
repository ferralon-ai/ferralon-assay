package statestore

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

// storeHarness drives one StateStore implementation plus the out-of-band operations
// the revoke and carry-through tests need: planting a file the store does not model
// (what a newer writer leaves behind), deleting the ref, and inspecting a commit.
type storeHarness struct {
	store StateStore
	// plant commits a new state on top of the ref's tip whose tree is the tip's tree
	// plus one blob named name.
	plant func(t *testing.T, name string, data []byte)
	// dropRef deletes the state ref, so the next CAS against a read token conflicts
	// and the re-read finds nothing.
	dropRef func(t *testing.T)
	// blobs returns the commit's tree entries as name -> object SHA.
	blobs func(t *testing.T, commit string) map[string]string
	// parents returns the commit's parent count.
	parents func(t *testing.T, commit string) int
}

var storeHarnesses = []struct {
	name string
	new  func(t *testing.T) storeHarness
}{
	{"git ref", newGitRefHarness},
	{"github ref", newGitHubHarness},
}

func newGitRefHarness(t *testing.T) storeHarness {
	s := newTempStore(t)
	dir := s.cfg.GitDir
	git := func(t *testing.T, stdin string, args ...string) string {
		t.Helper()
		cmd := gittest.Command(append([]string{"-C", dir}, args...)...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out))
	}
	return storeHarness{
		store: s,
		plant: func(t *testing.T, name string, data []byte) {
			tip := git(t, "", "rev-parse", s.cfg.Ref)
			blob := git(t, string(data), "hash-object", "-w", "--stdin")
			listing := git(t, "", "ls-tree", tip)
			tree := git(t, listing+"\n100644 blob "+blob+"\t"+name+"\n", "mktree")
			commit := git(t, "", "-c", "user.name=newer", "-c", "user.email=newer@localhost",
				"commit-tree", tree, "-p", tip, "-m", "newer writer")
			git(t, "", "update-ref", s.cfg.Ref, commit, tip)
		},
		dropRef: func(t *testing.T) {
			git(t, "", "update-ref", "-d", s.cfg.Ref)
		},
		blobs: func(t *testing.T, commit string) map[string]string {
			return treeBlobSHAs(t, dir, commit)
		},
		parents: func(t *testing.T, commit string) int {
			return len(strings.Fields(git(t, "", "rev-list", "--parents", "-n", "1", commit))) - 1
		},
	}
}

func newGitHubHarness(t *testing.T) storeHarness {
	m := newMockGitHub("acme", "widget")
	// The mock answers a PATCH on a missing ref with 404; this harness answers 422 so
	// a write against a dropped ref reaches the store's conflict → re-read → re-create
	// path, the same path a CAS conflict followed by a vanished ref takes.
	inner := m.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/git/refs/") {
			ref := "refs/" + r.URL.Path[strings.Index(r.URL.Path, "/git/refs/")+len("/git/refs/"):]
			m.mu.Lock()
			_, ok := m.refs[ref]
			m.mu.Unlock()
			if !ok {
				http.Error(w, "reference does not exist", http.StatusUnprocessableEntity)
				return
			}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	s := NewGitHubRefStore(GitHubConfig{
		Owner: m.owner, Repo: m.repo, BaseURL: srv.URL, HTTPClient: srv.Client(), Token: "test-token",
	})
	return storeHarness{
		store: s,
		plant: func(t *testing.T, name string, data []byte) {
			m.mu.Lock()
			defer m.mu.Unlock()
			ref := s.StateRef()
			tip, ok := m.refs[ref]
			if !ok {
				t.Fatalf("plant: no ref %s", ref)
			}
			blob := mockSHA("blob", data)
			m.blobs[blob] = data
			entries := append(append([]ghTreeEntry(nil), m.trees[m.commits[tip].Tree]...),
				ghTreeEntry{Path: name, Mode: "100644", Type: "blob", SHA: blob})
			tree := mockSHA("tree", []byte(base64.StdEncoding.EncodeToString(data)+name+tip))
			m.trees[tree] = entries
			commit := mockSHA("commit", []byte(tree+tip))
			m.commits[commit] = mockCommit{Tree: tree, Parents: []string{tip}}
			m.refs[ref] = commit
		},
		dropRef: func(t *testing.T) {
			m.mu.Lock()
			defer m.mu.Unlock()
			delete(m.refs, s.StateRef())
		},
		blobs: func(t *testing.T, commit string) map[string]string {
			return m.treeBlobsOf(t, commit)
		},
		parents: func(t *testing.T, commit string) int {
			m.mu.Lock()
			defer m.mu.Unlock()
			return len(m.commits[commit].Parents)
		},
	}
}

// TestRevokeCountRoundTrip: the counter persists across a write → read in both stores,
// on the ordinary CAS update and on the re-create a write falls back to when the ref
// vanished. The blob exists exactly while the counter is non-zero.
func TestRevokeCountRoundTrip(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for _, h := range storeHarnesses {
		for _, recreate := range []bool{false, true} {
			name := h.name + "/cas update"
			if recreate {
				name = h.name + "/re-create"
			}
			t.Run(name, func(t *testing.T) {
				hs := h.new(t)
				ctx := context.Background()
				if _, err := hs.store.Write(ctx, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"}); err != nil {
					t.Fatalf("seed: %v", err)
				}
				for i, want := range []int{0, 1, 2, 0} {
					st, err := hs.store.Read(ctx)
					if err != nil {
						t.Fatalf("step %d read: %v", i, err)
					}
					st.RevokeCount = want
					if recreate {
						hs.dropRef(t)
					}
					committed, err := hs.store.Write(ctx, st)
					if err != nil {
						t.Fatalf("step %d write %d: %v", i, want, err)
					}
					if recreate && hs.parents(t, committed.CommitSHA) != 0 {
						t.Fatalf("step %d: write did not take the re-create path", i)
					}
					got, err := hs.store.Read(ctx)
					if err != nil {
						t.Fatalf("step %d re-read: %v", i, err)
					}
					if got.RevokeCount != want {
						t.Errorf("step %d: RevokeCount got %d want %d", i, got.RevokeCount, want)
					}
					if _, has := hs.blobs(t, committed.CommitSHA)[fileRevoke]; has != (want > 0) {
						t.Errorf("step %d: revoke blob present=%v with count %d", i, has, want)
					}
				}
			})
		}
	}
}

// TestRevokeCountMergeKeepsMax: a CAS race-loser's retry goes through Merge, which
// keeps the larger counter, so an increment the winner recorded is never lost.
func TestRevokeCountMergeKeepsMax(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for _, h := range storeHarnesses {
		t.Run(h.name, func(t *testing.T) {
			hs := h.new(t)
			ctx := context.Background()
			if _, err := hs.store.Write(ctx, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"}); err != nil {
				t.Fatalf("seed: %v", err)
			}
			a, _ := hs.store.Read(ctx)
			b, _ := hs.store.Read(ctx)
			b.RevokeCount = 2
			if _, err := hs.store.Write(ctx, b); err != nil {
				t.Fatalf("winner write: %v", err)
			}
			a.RevokeCount = 1
			if _, err := hs.store.Write(ctx, a); err != nil {
				t.Fatalf("loser write: %v", err)
			}
			got, err := hs.store.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if got.RevokeCount != 2 {
				t.Errorf("RevokeCount after merge: got %d want 2", got.RevokeCount)
			}
		})
	}
}

func mustWrite(t *testing.T, s StateStore, st *State) *State {
	t.Helper()
	out, err := s.Write(context.Background(), st)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	return out
}
