package statestore

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	// with the blob named name added or replaced.
	plant func(t *testing.T, name string, data []byte)
	// dropRef deletes the state ref, so the next CAS against a read token conflicts
	// and the re-read finds nothing.
	dropRef func(t *testing.T)
	// prune deletes the state ref and every commit it reached, as a GC of the
	// unreachable history would.
	prune func(t *testing.T)
	// failCommitRead makes reads of commit fail with an error other than "not
	// found" (the commit itself still exists): every git read of it, or the next
	// API GET of it.
	failCommitRead func(t *testing.T, commit string)
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
			var listing strings.Builder
			for _, line := range strings.Split(git(t, "", "ls-tree", tip), "\n") {
				if line != "" && !strings.HasSuffix(line, "\t"+name) {
					listing.WriteString(line + "\n")
				}
			}
			tree := git(t, listing.String()+"100644 blob "+blob+"\t"+name+"\n", "mktree")
			commit := git(t, "", "-c", "user.name=newer", "-c", "user.email=newer@localhost",
				"commit-tree", tree, "-p", tip, "-m", "newer writer")
			git(t, "", "update-ref", s.cfg.Ref, commit, tip)
		},
		dropRef: func(t *testing.T) {
			git(t, "", "update-ref", "-d", s.cfg.Ref)
		},
		prune: func(t *testing.T) {
			tip := git(t, "", "rev-parse", s.cfg.Ref)
			git(t, "", "update-ref", "-d", s.cfg.Ref)
			git(t, "", "reflog", "expire", "--expire=now", "--all")
			git(t, "", "gc", "-q", "--prune=now")
			if err := gittest.Command("-C", dir, "cat-file", "-e", tip).Run(); err == nil {
				t.Fatalf("prune: commit %s survived gc", tip)
			}
		},
		failCommitRead: func(t *testing.T, commit string) {
			// Front git with a script that fails any command naming the commit with
			// exit 128, the way an unreadable object store would, and passes
			// everything else through.
			real, err := exec.LookPath("git")
			if err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(t.TempDir(), "git")
			body := "#!/bin/sh\nfor a in \"$@\"; do\n" +
				"  case \"$a\" in " + commit + "|" + commit + "^{commit}) echo 'read failure' >&2; exit 128;; esac\n" +
				"done\nexec " + real + " \"$@\"\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			s.cfg.Bin = script
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
	var failCommit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		fail := failCommit != "" && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/commits/"+failCommit)
		if fail {
			failCommit = ""
		}
		m.mu.Unlock()
		if fail {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
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
			var entries []ghTreeEntry
			for _, e := range m.trees[m.commits[tip].Tree] {
				if e.Path != name {
					entries = append(entries, e)
				}
			}
			entries = append(entries, ghTreeEntry{Path: name, Mode: "100644", Type: "blob", SHA: blob})
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
		prune: func(t *testing.T) {
			m.mu.Lock()
			defer m.mu.Unlock()
			for c := m.refs[s.StateRef()]; c != ""; {
				parents := m.commits[c].Parents
				delete(m.commits, c)
				c = ""
				if len(parents) > 0 {
					c = parents[0]
				}
			}
			delete(m.refs, s.StateRef())
		},
		failCommitRead: func(t *testing.T, commit string) {
			m.mu.Lock()
			defer m.mu.Unlock()
			failCommit = commit
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

// TestUnmodelledEntryCarriedThrough: a file this version does not model (a newer
// writer's) survives every kind of write by its original object SHA, while modelled
// files keep their own semantics — a counter reset to 0 still drops the revoke blob
// even though the parent tree had one.
func TestUnmodelledEntryCarriedThrough(t *testing.T) {
	const newer = "depfetch.json"
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		// write performs the write under test against a state read after the plant. It
		// returns the committed state and the object SHA the newer file must carry,
		// or "" for the originally planted one.
		write      func(t *testing.T, hs storeHarness, st *State) (*State, string)
		wantRevoke bool
	}{
		{
			name: "cursor heartbeat",
			write: func(t *testing.T, hs storeHarness, st *State) (*State, string) {
				st.Cursor = "cur-2"
				return mustWrite(t, hs.store, st), ""
			},
			wantRevoke: true,
		},
		{
			name: "revoke reset drops the modelled file only",
			write: func(t *testing.T, hs storeHarness, st *State) (*State, string) {
				st.RevokeCount = 0
				return mustWrite(t, hs.store, st), ""
			},
			wantRevoke: false,
		},
		{
			// The winner is the newer writer updating its own file after our read, so
			// the retry must carry the winner's version, never the one in our stale read.
			name: "merge retry after a lost CAS carries the winner's version",
			write: func(t *testing.T, hs storeHarness, st *State) (*State, string) {
				stale := hs.blobs(t, st.CommitSHA)[newer]
				hs.plant(t, newer, []byte(`{"registries":{"npm":{}}}`))
				winner, err := hs.store.Read(context.Background())
				if err != nil {
					t.Fatalf("winner read: %v", err)
				}
				want := hs.blobs(t, winner.CommitSHA)[newer]
				if want == "" || want == stale {
					t.Fatalf("winner's %s %q does not differ from the stale %q", newer, want, stale)
				}
				st.Cursor = "cur-loser"
				committed := mustWrite(t, hs.store, st)
				if hs.parents(t, committed.CommitSHA) != 1 {
					t.Fatal("loser write did not land on top of the winner")
				}
				return committed, want
			},
			wantRevoke: true,
		},
	}
	for _, h := range storeHarnesses {
		for _, tc := range cases {
			t.Run(h.name+"/"+tc.name, func(t *testing.T) {
				hs := h.new(t)
				ctx := context.Background()
				if _, err := hs.store.Write(ctx, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur", RevokeCount: 1}); err != nil {
					t.Fatalf("seed: %v", err)
				}
				hs.plant(t, newer, []byte(`{"registries":{}}`))
				st, err := hs.store.Read(ctx)
				if err != nil {
					t.Fatalf("read: %v", err)
				}
				planted := hs.blobs(t, st.CommitSHA)[newer]
				if planted == "" {
					t.Fatal("plant did not land")
				}

				committed, want := tc.write(t, hs, st)
				if want == "" {
					want = planted
				}

				after := hs.blobs(t, committed.CommitSHA)
				if after[newer] != want {
					t.Errorf("%s: got object %q want %q (carried through unchanged)", newer, after[newer], want)
				}
				if _, has := after[fileRevoke]; has != tc.wantRevoke {
					t.Errorf("revoke blob present=%v want %v", has, tc.wantRevoke)
				}
				if after[fileReport] == "" || after[fileCursor] == "" {
					t.Errorf("modelled files missing after write: %v", after)
				}
			})
		}
	}
}

// TestWriteParentUnreadable: the carry read of the parent commit separates "the
// parent is gone" (ref deleted and its history pruned) from any other read failure.
// Gone takes the re-create path, as a deleted ref with intact history does; any
// other failure is returned, never read as "nothing to carry".
func TestWriteParentUnreadable(t *testing.T) {
	ts := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	for _, h := range storeHarnesses {
		t.Run(h.name+"/pruned parent re-creates", func(t *testing.T) {
			hs := h.new(t)
			ctx := context.Background()
			mustWrite(t, hs.store, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"})
			st, err := hs.store.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			hs.prune(t)
			st.RevokeCount = 1
			st.Cursor = "cur-2"
			committed, err := hs.store.Write(ctx, st)
			if err != nil {
				t.Fatalf("write over a pruned parent: %v", err)
			}
			if hs.parents(t, committed.CommitSHA) != 0 {
				t.Fatal("write did not take the re-create path")
			}
			got, err := hs.store.Read(ctx)
			if err != nil {
				t.Fatalf("re-read: %v", err)
			}
			if got.RevokeCount != 1 || got.Cursor != "cur-2" || got.Report == nil {
				t.Errorf("re-created state: revoke %d cursor %q report %v", got.RevokeCount, got.Cursor, got.Report != nil)
			}
		})
		t.Run(h.name+"/transient read failure is returned", func(t *testing.T) {
			hs := h.new(t)
			ctx := context.Background()
			mustWrite(t, hs.store, &State{Report: sampleReport("c0", "cur", ts), Cursor: "cur"})
			st, err := hs.store.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			hs.failCommitRead(t, st.CommitSHA)
			st.Cursor = "cur-2"
			out, err := hs.store.Write(ctx, st)
			if err == nil {
				t.Fatalf("write succeeded as %s over an unreadable parent", out.CommitSHA)
			}
			if errors.Is(err, ErrConflict) {
				t.Fatalf("read failure surfaced as a conflict: %v", err)
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
