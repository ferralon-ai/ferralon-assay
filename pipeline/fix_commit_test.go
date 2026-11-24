package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/gittest"
)

func fixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := gittest.Command(append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// fixHistory is a repository whose main line is base, fix, later, with a side branch off base that
// carries one commit of its own.
type fixHistory struct {
	dir                    string
	base, fix, later, side string
}

func newFixHistory(t *testing.T, files map[string]string) fixHistory {
	t.Helper()
	if !checkout.GitAvailable() {
		t.Skip("git not available")
	}
	h := fixHistory{dir: writeTree(t, files)}
	commit := func(msg string) string {
		fixtureGit(t, h.dir, "add", "-A")
		fixtureGit(t, h.dir, "commit", "-q", "--allow-empty", "-m", msg)
		return fixtureGit(t, h.dir, "rev-parse", "HEAD")
	}
	fixtureGit(t, h.dir, "init", "-q", "-b", "main")
	h.base = commit("base")
	fixtureGit(t, h.dir, "checkout", "-q", "-b", "side")
	h.side = commit("fix on a side branch")
	fixtureGit(t, h.dir, "checkout", "-q", "main")
	h.fix = commit("fix")
	h.later = commit("later")
	return h
}

func (h fixHistory) at(t *testing.T, commit string) fixHistory {
	t.Helper()
	fixtureGit(t, h.dir, "checkout", "-q", "--detach", commit)
	return h
}

func TestFixCommitID(t *testing.T) {
	const sha1 = "98fc40347885ad510a311b990a73397c6d4143db"
	sha256 := strings.Repeat("ab", 32)
	cases := []struct {
		name, ref, want string
		ok              bool
	}{
		{"commit URL", "https://github.com/gotenberg/gotenberg/commit/" + sha1, sha1, true},
		{"bare id", sha1, sha1, true},
		{"upper case", strings.ToUpper(sha1), sha1, true},
		{"sha256 id", "https://example.com/r/commit/" + sha256, sha256, true},
		{"abbreviated id", "https://github.com/gotenberg/gotenberg/commit/98fc4034", "", false},
		{"pull request URL", "https://github.com/gotenberg/gotenberg/pull/1234", "", false},
		{"id followed by a suffix", "https://github.com/gotenberg/gotenberg/commit/" + sha1 + ".patch", "", false},
		{"an option where the id belongs", "--all", "", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := fixCommitID(tc.ref)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Fatalf("fixCommitID(%q) = %q, %v; want %q, %v", tc.ref, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestHeadContainsCommit: only a complete history answers. It contains HEAD and its ancestors and
// lacks every other commit, held or not. A shallow history, a commit id that is not one, and a
// question git cannot answer leave it unanswered.
func TestHeadContainsCommit(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) (dir, commit string)
		want  historyAnswer
	}{
		{"the fix is HEAD", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.at(t, h.fix).dir, h.fix
		}, historyContains},
		{"the fix is an ancestor of HEAD", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, h.fix
		}, historyContains},
		{"asked from a subdirectory", func(t *testing.T) (string, string) {
			h := newFixHistory(t, map[string]string{"sub/x.txt": "x\n"})
			return filepath.Join(h.dir, "sub"), h.fix
		}, historyContains},
		{"HEAD is the parent of the fix", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.at(t, h.base).dir, h.fix
		}, historyLacks},
		{"the fix is on another branch", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, h.side
		}, historyLacks},
		{"the object store does not hold the fix", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, strings.Repeat("0123456789", 4)
		}, historyLacks},
		{"a shallow clone whose HEAD is the fix", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			h.at(t, h.fix)
			clone := t.TempDir()
			fixtureGit(t, clone, "clone", "-q", "--depth", "1", "file://"+h.dir, ".")
			if got := fixtureGit(t, clone, "rev-parse", "HEAD"); got != h.fix {
				t.Fatalf("shallow clone HEAD = %s, want the fix %s", got, h.fix)
			}
			return clone, h.fix
		}, historyUnanswered},
		{"a replacement object grafts the fix under HEAD", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			fixtureGit(t, h.dir, "replace", "--graft", h.later, h.side)
			if out := fixtureGit(t, h.dir, "rev-list", "HEAD"); !strings.Contains(out, h.side) {
				t.Fatalf("the replacement did not take effect:\n%s", out)
			}
			return h.dir, h.side
		}, historyLacks},
		{"the grafts file puts the fix under HEAD", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			grafts := filepath.Join(h.dir, ".git", "info", "grafts")
			if err := os.MkdirAll(filepath.Dir(grafts), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(grafts, []byte(h.later+" "+h.side+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if out := fixtureGit(t, h.dir, "rev-list", "HEAD"); !strings.Contains(out, h.side) {
				t.Fatalf("the grafts file did not take effect:\n%s", out)
			}
			return h.dir, h.side
		}, historyLacks},
		{"an abbreviated id", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, h.fix[:12]
		}, historyUnanswered},
		{"a ref name where the id belongs", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, "main"
		}, historyUnanswered},
		{"not a repository", func(t *testing.T) (string, string) {
			return t.TempDir(), strings.Repeat("0123456789", 4)
		}, historyUnanswered},
		{"HEAD names no commit", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			fixtureGit(t, h.dir, "symbolic-ref", "HEAD", "refs/heads/unborn")
			return h.dir, h.fix
		}, historyUnanswered},
		{"HEAD names no commit, asked about a commit the store does not hold", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			fixtureGit(t, h.dir, "symbolic-ref", "HEAD", "refs/heads/unborn")
			return h.dir, strings.Repeat("0123456789", 4)
		}, historyUnanswered},
		{"a full clone whose borrowed object store is gone", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			clone := t.TempDir()
			fixtureGit(t, clone, "clone", "-q", "--shared", h.dir, ".")
			fixtureGit(t, clone, "commit", "-q", "--allow-empty", "-m", "local")
			if err := os.Rename(h.dir, h.dir+".gone"); err != nil {
				t.Fatal(err)
			}
			// git may first complain about the missing alternate; the answer is the last line.
			out := fixtureGit(t, clone, "rev-parse", "--is-shallow-repository")
			if got := out[strings.LastIndex(out, "\n")+1:]; got != "false" {
				t.Fatalf("clone is shallow: %s", out)
			}
			return clone, h.fix
		}, historyUnanswered},
		{"no directory", func(t *testing.T) (string, string) {
			return "", strings.Repeat("0123456789", 4)
		}, historyUnanswered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !checkout.GitAvailable() {
				t.Skip("git not available")
			}
			dir, commit := tc.build(t)
			if got := headContainsCommit(context.Background(), dir, commit); got != tc.want {
				t.Fatalf("headContainsCommit = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHeadContainsCommit_NeverFetches: a partial clone can ask its remote for an object it lacks.
// The ancestry question is answered from what the checkout holds, so a fix only the remote has is
// one the clone's complete history lacks, and the remote's objects are never copied in.
func TestHeadContainsCommit_NeverFetches(t *testing.T) {
	h := newFixHistory(t, nil)
	fixtureGit(t, h.dir, "config", "uploadpack.allowFilter", "true")
	fixtureGit(t, h.dir, "config", "uploadpack.allowAnySHA1InWant", "true")
	clone := t.TempDir()
	fixtureGit(t, clone, "clone", "-q", "--filter=blob:none", "--single-branch", "--branch", "main", "file://"+h.dir, ".")
	if got := headContainsCommit(context.Background(), clone, h.side); got != historyLacks {
		t.Fatalf("a commit only the remote holds: got %v, want the clone's history to lack it", got)
	}
	cmd := gittest.Command("-C", clone, "cat-file", "-e", h.side)
	cmd.Env = append(cmd.Env, "GIT_NO_LAZY_FETCH=1")
	if cmd.Run() == nil {
		t.Fatal("the ancestry question fetched the commit from the remote")
	}
	if headContainsCommit(context.Background(), clone, h.fix) != historyContains {
		t.Fatal("a full-history partial clone did not answer for a commit it holds")
	}
}

// TestRangeEnteredBeforeFix: with HEAD at later and the fix at fix, a range is settled only when
// the tag for its first version resolves and everything it shares with HEAD is in the fix's
// history.
func TestRangeEnteredBeforeFix(t *testing.T) {
	const app = "example.com/app"
	bogus := strings.Repeat("0123456789", 4)
	nested := map[string]string{"sub/go.mod": "module example.com/app/sub\n"}
	type at = func(h fixHistory) string
	base := func(h fixHistory) string { return h.base }
	fix := func(h fixHistory) string { return h.fix }
	later := func(h fixHistory) string { return h.later }
	side := func(h fixHistory) string { return h.side }
	cases := []struct {
		name       string
		files      map[string]string
		sub        string
		mod, lower string
		tag        string
		tagAt      at
		annotated  bool
		commit     at
		want       bool
	}{
		{name: "tagged before the fix", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: base, want: true},
		{name: "tagged at the fix", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: fix, want: true},
		{name: "tagged after the fix", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: later},
		{name: "tagged after the named commit and before HEAD", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: fix, commit: base},
		{name: "annotated tag after the fix", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: later, annotated: true},
		{name: "annotated tag before the fix", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: base, annotated: true, want: true},
		{name: "tagged on a branch that left before the fix", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: side, want: true},
		{name: "no tag for the version", mod: app, lower: "1.3.0"},
		{name: "a tag without the v", mod: app, lower: "1.3.0", tag: "1.3.0", tagAt: base},
		{name: "a version written with its v", mod: app, lower: "v1.3.0", tag: "v1.3.0", tagAt: base, want: true},
		{name: "a version that is not canonical", mod: app, lower: "1.3", tag: "v1.3", tagAt: base},
		{name: "a pseudo-version", mod: app, lower: "0.0.0-20240101000000-abcdefabcdef", tag: "v0.0.0-20240101000000-abcdefabcdef", tagAt: base},
		{name: "an incompatible version", mod: app, lower: "2.0.0+incompatible", tag: "v2.0.0", tagAt: base, want: true},
		{name: "an incompatible version tagged after the fix", mod: app, lower: "2.0.0+incompatible", tag: "v2.0.0", tagAt: later},
		{name: "an incompatible version below v2", mod: app, lower: "1.3.0+incompatible", tag: "v1.3.0", tagAt: base},
		{name: "an incompatible version of a v2 module", mod: app + "/v2", lower: "2.1.0+incompatible", tag: "v2.1.0", tagAt: base},
		{name: "a major the module path does not allow", mod: app, lower: "2.0.0", tag: "v2.0.0", tagAt: base},
		{name: "a v2 module's own major", mod: app + "/v2", lower: "2.1.0", tag: "v2.1.0", tagAt: base, want: true},
		{name: "a v2 module and a v1 version", mod: app + "/v2", lower: "1.3.0", tag: "v1.3.0", tagAt: base},
		{name: "a nested module's prefixed tag before the fix", files: nested, sub: "sub", mod: app + "/sub", lower: "1.3.0", tag: "sub/v1.3.0", tagAt: base, want: true},
		{name: "a nested module's prefixed tag after the fix", files: nested, sub: "sub", mod: app + "/sub", lower: "1.3.0", tag: "sub/v1.3.0", tagAt: later},
		{name: "a nested module and the root module's tag", files: nested, sub: "sub", mod: app + "/sub", lower: "1.3.0", tag: "v1.3.0", tagAt: base},
		{name: "not a Go project", lower: "1.3.0", tag: "v1.3.0", tagAt: base},
		{name: "the fix is not an object the checkout holds", mod: app, lower: "1.3.0", tag: "v1.3.0", tagAt: base, commit: func(fixHistory) string { return bogus }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixHistory(t, tc.files)
			if tc.tag != "" {
				args := []string{"-c", "tag.gpgsign=false", "tag"}
				if tc.annotated {
					args = append(args, "-a", "-m", tc.tag)
				}
				fixtureGit(t, h.dir, append(args, tc.tag, tc.tagAt(h))...)
			}
			commit := h.fix
			if tc.commit != nil {
				commit = tc.commit(h)
			}
			if got := rangeEnteredBeforeFix(context.Background(), filepath.Join(h.dir, tc.sub), tc.mod, commit, tc.lower); got != tc.want {
				t.Fatalf("rangeEnteredBeforeFix = %v, want %v", got, tc.want)
			}
		})
	}
	// The remaining histories put the fix at fix and build on from later.
	tagAt := func(t *testing.T, h fixHistory, at string) {
		t.Helper()
		fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", "v1.3.0", at)
	}
	commitOn := func(t *testing.T, h fixHistory, msg string) string {
		t.Helper()
		fixtureGit(t, h.dir, "commit", "-q", "--allow-empty", "-m", msg)
		return fixtureGit(t, h.dir, "rev-parse", "HEAD")
	}
	t.Run("a release branch cut after the fix carries the tag", func(t *testing.T) {
		h := newFixHistory(t, nil)
		fixtureGit(t, h.dir, "checkout", "-q", "-b", "release", h.later)
		tagAt(t, h, commitOn(t, h, "release"))
		fixtureGit(t, h.dir, "checkout", "-q", "main")
		commitOn(t, h, "head")
		if rangeEnteredBeforeFix(context.Background(), h.dir, app, h.fix, "1.3.0") {
			t.Fatal("settled although HEAD shares history after the fix with the tagged release")
		}
	})
	t.Run("HEAD sits before a tag made later on the same line", func(t *testing.T) {
		h := newFixHistory(t, nil)
		tagAt(t, h, commitOn(t, h, "release"))
		h.at(t, h.later)
		if rangeEnteredBeforeFix(context.Background(), h.dir, app, h.fix, "1.3.0") {
			t.Fatal("settled although HEAD is past the fix on the way to the tagged release")
		}
	})
	t.Run("a release branch cut at the fix carries the tag", func(t *testing.T) {
		h := newFixHistory(t, nil)
		fixtureGit(t, h.dir, "checkout", "-q", "-b", "release", h.fix)
		tagAt(t, h, commitOn(t, h, "release"))
		fixtureGit(t, h.dir, "checkout", "-q", "main")
		if !rangeEnteredBeforeFix(context.Background(), h.dir, app, h.fix, "1.3.0") {
			t.Fatal("not settled although HEAD shares nothing past the fix with the tagged release")
		}
	})
	t.Run("two merge bases and only one is in the fix's history", func(t *testing.T) {
		h := newFixHistory(t, nil)
		fixtureGit(t, h.dir, "checkout", "-q", "-b", "a", h.base)
		x := commitOn(t, h, "x")
		fixtureGit(t, h.dir, "checkout", "-q", "-b", "b", h.base)
		y := commitOn(t, h, "y")
		fixtureGit(t, h.dir, "merge", "-q", "--no-ff", "-m", "b takes a", x)
		fixtureGit(t, h.dir, "checkout", "-q", "a")
		fixtureGit(t, h.dir, "merge", "-q", "--no-ff", "-m", "a takes b", y)
		tagAt(t, h, "a")
		fixtureGit(t, h.dir, "checkout", "-q", "b")
		if all := strings.Fields(fixtureGit(t, h.dir, "merge-base", "--all", "v1.3.0", "HEAD")); len(all) != 2 {
			t.Fatalf("merge bases = %v, want two", all)
		}
		// Whichever base git names first stands in for the fix; the other is not in its history.
		first := fixtureGit(t, h.dir, "merge-base", "v1.3.0", "HEAD")
		if rangeEnteredBeforeFix(context.Background(), h.dir, app, first, "1.3.0") {
			t.Fatal("settled on one merge base while the other is outside the fix's history")
		}
		if !rangeEnteredBeforeFix(context.Background(), h.dir, app, fixtureGit(t, h.dir, "rev-parse", "a"), "1.3.0") {
			t.Fatal("not settled although both merge bases are in the commit's history")
		}
	})
	t.Run("the tag shares no history with HEAD", func(t *testing.T) {
		h := newFixHistory(t, nil)
		fixtureGit(t, h.dir, "checkout", "-q", "--orphan", "unrelated")
		tagAt(t, h, commitOn(t, h, "unrelated"))
		fixtureGit(t, h.dir, "checkout", "-q", "main")
		if rangeEnteredBeforeFix(context.Background(), h.dir, app, h.fix, "1.3.0") {
			t.Fatal("settled with no merge base")
		}
	})
	t.Run("HEAD names no commit", func(t *testing.T) {
		h := newFixHistory(t, nil)
		fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", "v1.3.0", h.side)
		fixtureGit(t, h.dir, "symbolic-ref", "HEAD", "refs/heads/unborn")
		if rangeEnteredBeforeFix(context.Background(), h.dir, app, h.fix, "1.3.0") {
			t.Fatal("settled when the ancestry question had no answer")
		}
	})
	t.Run("not a repository", func(t *testing.T) {
		if rangeEnteredBeforeFix(context.Background(), t.TempDir(), app, bogus, "1.3.0") {
			t.Fatal("settled without a repository")
		}
	})
}

func TestFixCommitClears(t *testing.T) {
	fixed := affectedRange{UpperExclusive: "1.2.0"}
	yes := func() historyAnswer { return historyContains }
	no := func() historyAnswer { return historyLacks }
	unknown := func() historyAnswer { return historyUnanswered }
	later := affectedRange{LowerInclusive: "1.3.0", UpperExclusive: "1.3.4"}
	entered := func(lowers ...string) func(string) bool {
		return func(lower string) bool { return slices.Contains(lowers, lower) }
	}
	outside := presentRanges{presentPackage: presentPackage{Versions: []string{"v2.0.0"}, Complete: true}, Ranges: []affectedRange{{UpperExclusive: "1.0.0"}}, RangeKnown: true}
	inside := presentRanges{presentPackage: presentPackage{Versions: []string{"v0.9.0"}, Complete: true}, Ranges: []affectedRange{{UpperExclusive: "1.0.0"}}, RangeKnown: true}
	cases := []struct {
		name       string
		rngs       []affectedRange
		rangeKnown bool
		versions   []string
		others     []presentRanges
		inHistory  func() historyAnswer
		entered    func(string) bool
		want       bool
		unanswered bool
	}{
		{"every range fixed and the fix in history", []affectedRange{fixed}, true, nil, nil, yes, entered(), true, false},
		{"a later range entered after the fix", []affectedRange{fixed, later}, true, nil, nil, yes, entered(), false, false},
		{"a later range entered before the fix", []affectedRange{fixed, later}, true, nil, nil, yes, entered("1.3.0"), true, false},
		{"one of two later ranges entered after the fix", []affectedRange{fixed, later, {LowerInclusive: "1.5.0", UpperExclusive: "1.5.2"}}, true, nil, nil, yes, entered("1.3.0"), false, false},
		{"several ranges that all start at zero", []affectedRange{fixed, {LowerInclusive: "0", UpperExclusive: "2.1.0"}}, true, nil, nil, yes, entered(), true, false},
		{"a single range that starts above zero", []affectedRange{later}, true, nil, nil, yes, entered(), true, false},
		{"the fix is not in history", []affectedRange{fixed}, true, nil, nil, no, entered(), false, false},
		{"the history cannot say", []affectedRange{fixed}, true, nil, nil, unknown, entered(), false, true},
		{"the history cannot say, and a later range", []affectedRange{fixed, later}, true, nil, nil, unknown, entered("1.3.0"), false, true},
		{"the history cannot say, but the ranges refuse", []affectedRange{{LastAffected: "1.1000.0"}}, true, nil, nil, unknown, entered(), false, false},
		{"the history cannot say, but the project has a version", []affectedRange{fixed}, true, []string{"1.1.0"}, nil, unknown, entered(), false, false},
		{"the history cannot say, but another package is inside its ranges", []affectedRange{fixed}, true, nil, []presentRanges{inside}, unknown, entered(), false, false},
		{"an open-ended last_affected", []affectedRange{{LastAffected: "1.1000.0"}}, true, nil, nil, yes, entered(), false, false},
		{"an open-ended last_affected beside a fixed range", []affectedRange{fixed, {LowerInclusive: "1.3.0", LastAffected: "1.1000.0"}}, true, nil, nil, yes, entered(), false, false},
		{"a range with no upper end", []affectedRange{{LowerInclusive: "1.0.0"}}, true, nil, nil, yes, entered(), false, false},
		{"ranges the advisory does not state", []affectedRange{fixed}, false, nil, nil, yes, entered(), false, false},
		{"no ranges", nil, true, nil, nil, yes, entered(), false, false},
		{"the project has a version the axis did not clear", []affectedRange{fixed}, true, []string{"1.1.0"}, nil, yes, entered(), false, false},
		{"the project has a version outside every range", []affectedRange{{UpperExclusive: "v1.2.0", Scheme: "gomod"}}, true, []string{"v1.3.0"}, nil, yes, entered(), false, false},
		{"another affected package outside its ranges", []affectedRange{fixed}, true, nil, []presentRanges{outside}, yes, entered(), true, false},
		{"another affected package inside its ranges", []affectedRange{fixed}, true, nil, []presentRanges{outside, inside}, yes, entered(), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, unanswered := fixCommitClears(tc.rngs, tc.rangeKnown, tc.versions, tc.others, tc.inHistory, tc.entered)
			if got != tc.want || unanswered != tc.unanswered {
				t.Fatalf("fixCommitClears = %v, unanswered %v; want %v, %v", got, unanswered, tc.want, tc.unanswered)
			}
		})
	}
	t.Run("history is not asked when the ranges already refuse", func(t *testing.T) {
		fixCommitClears([]affectedRange{{LastAffected: "1.1000.0"}}, true, nil, nil, func() historyAnswer {
			t.Fatal("asked for history")
			return historyContains
		}, entered())
	})
	t.Run("range entry is not asked when the fix is not in history", func(t *testing.T) {
		for _, answer := range []func() historyAnswer{no, unknown} {
			fixCommitClears([]affectedRange{fixed, later}, true, nil, nil, answer, func(string) bool {
				t.Fatal("asked for range entry")
				return true
			})
		}
	})
}

// TestDisqualification_FixCommitInHistory runs intake, inventory and disqualification over a Go
// project with no version tag, where the version axis has nothing to compare.
func TestDisqualification_FixCommitInHistory(t *testing.T) {
	const gomod = "module example.com/app\n\ngo 1.22\n"
	own := map[string]string{"go.mod": gomod, "main.go": "package main\n"}
	fixedRange := []Range{{Introduced: "0", Fixed: "1.2.0"}}
	twoRanges := []Range{{Introduced: "0", Fixed: "1.2.0"}, {Introduced: "1.3.0", Fixed: "1.3.4"}}
	facts := func(module string, rngs []Range) AdvisoryFacts {
		return AdvisoryFacts{Module: module, PURL: "pkg:golang/" + module, AffectedRanges: rngs}
	}
	cases := []struct {
		name   string
		files  map[string]string
		facts  AdvisoryFacts
		head   func(h fixHistory) string
		commit func(h fixHistory) string
		tag    string
		tags   func(h fixHistory) map[string]string
		want   bool
	}{
		{name: "the fix is HEAD", files: own, facts: facts("example.com/app", fixedRange),
			head: func(h fixHistory) string { return h.fix }, commit: func(h fixHistory) string { return h.fix }, want: true},
		{name: "the fix is an ancestor of HEAD", files: own, facts: facts("example.com/app", fixedRange),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }, want: true},
		{name: "a package of the project", files: own, facts: facts("example.com/app/internal/x", fixedRange),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }, want: true},
		{name: "HEAD is the parent of the fix", files: own, facts: facts("example.com/app", fixedRange),
			head: func(h fixHistory) string { return h.base }, commit: func(h fixHistory) string { return h.fix }},
		{name: "the fix is on another branch", files: own, facts: facts("example.com/app", fixedRange),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.side }},
		{name: "an open-ended last_affected", files: own, facts: facts("example.com/app", []Range{{Introduced: "0", LastAffected: "1.1000.0"}}),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }},
		{name: "an abbreviated fix commit", files: own, facts: facts("example.com/app", fixedRange),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix[:12] }},
		{name: "a path another module may supply",
			files: map[string]string{"go.mod": gomod, "go.sum": "example.com/app/old v0.1.0/go.mod h1:y=\n", "main.go": "package main\n"},
			facts: facts("example.com/app/old/pkg", fixedRange),
			head:  func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }},
		{name: "HEAD tagged at an affected version", files: own, facts: facts("example.com/app", fixedRange), tag: "v1.1.0",
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }},
		{name: "a later range tagged after the named fix", files: own, facts: facts("example.com/app", twoRanges),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.base },
			tags: func(h fixHistory) map[string]string { return map[string]string{"v1.3.0": h.fix} }},
		{name: "a later range tagged before the named fix", files: own, facts: facts("example.com/app", twoRanges),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix },
			tags: func(h fixHistory) map[string]string { return map[string]string{"v1.3.0": h.base} }, want: true},
		{name: "a later range tagged on a branch that left before the fix", files: own, facts: facts("example.com/app", twoRanges),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix },
			tags: func(h fixHistory) map[string]string { return map[string]string{"v1.3.0": h.side} }, want: true},
		{name: "a later range with no tag", files: own, facts: facts("example.com/app", twoRanges),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }},
		{name: "two ranges that start at zero", files: own, facts: facts("example.com/app", []Range{{Introduced: "0", Fixed: "1.2.0"}, {Introduced: "0", Fixed: "2.1.0"}}),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }, want: true},
		{name: "a single range above zero with no tag", files: own, facts: facts("example.com/app", []Range{{Introduced: "1.3.0", Fixed: "1.3.4"}}),
			head: func(h fixHistory) string { return h.later }, commit: func(h fixHistory) string { return h.fix }, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixHistory(t, tc.files)
			h.at(t, tc.head(h))
			if tc.tag != "" {
				fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", tc.tag)
			}
			if tc.tags != nil {
				for name, at := range tc.tags(h) {
					fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", name, at)
				}
			}
			commit := tc.commit(h)
			tc.facts.Fix = FixHint{UpstreamCommit: "https://example.com/app/commit/" + commit}
			res := runRootDisqual(t, h.dir, tc.facts)
			if res.Disqualified != tc.want {
				t.Fatalf("disqualified = %v (%s), want %v", res.Disqualified, res.Reason, tc.want)
			}
			if !tc.want {
				return
			}
			if res.Reason != ReasonFixCommitInHistory || res.FixCommit != commit || res.Source == nil {
				t.Fatalf("cleared as %+v, want %s on %s with its source", res, ReasonFixCommitInHistory, commit)
			}
		})
	}

	// The same project and advisory, checked out shallow and in full: only the full history answers,
	// and the shallow one records the fix commit it could not place.
	checkouts := []struct {
		name           string
		depth          string
		commit         func(h fixHistory) string
		want           bool
		wantUnanswered bool
	}{
		{name: "a full clone holding the fix", commit: func(h fixHistory) string { return h.fix }, want: true},
		{name: "a full clone without the fix", commit: func(h fixHistory) string { return h.side }},
		{name: "a shallow clone", depth: "1", commit: func(h fixHistory) string { return h.fix }, wantUnanswered: true},
		{name: "a shallow clone whose depth reaches the fix", depth: "2", commit: func(h fixHistory) string { return h.fix }, wantUnanswered: true},
	}
	for _, tc := range checkouts {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixHistory(t, own)
			clone := t.TempDir()
			args := []string{"clone", "-q", "--single-branch", "--branch", "main"}
			if tc.depth != "" {
				args = append(args, "--depth", tc.depth)
			}
			fixtureGit(t, clone, append(args, "file://"+h.dir, ".")...)
			f := facts("example.com/app", fixedRange)
			commit := tc.commit(h)
			f.Fix = FixHint{UpstreamCommit: commit}
			res := runRootDisqual(t, clone, f)
			if res.Disqualified != tc.want || (tc.want && res.Reason != ReasonFixCommitInHistory) {
				t.Fatalf("got %+v, want disqualified %v on %s", res, tc.want, ReasonFixCommitInHistory)
			}
			wantCommit := ""
			if tc.wantUnanswered {
				wantCommit = commit
			}
			if res.FixCommitUnanswered != wantCommit {
				t.Fatalf("fix_commit_unanswered = %q, want %q", res.FixCommitUnanswered, wantCommit)
			}
		})
	}
	t.Run("a shallow clone of a dependency's advisory", func(t *testing.T) {
		h := newFixHistory(t, map[string]string{"go.mod": gomod + "\nrequire example.com/dep v1.0.0\n", "main.go": "package main\n"})
		clone := t.TempDir()
		fixtureGit(t, clone, "clone", "-q", "--depth", "1", "file://"+h.dir, ".")
		f := facts("example.com/dep", fixedRange)
		f.Fix = FixHint{UpstreamCommit: h.fix}
		if res := runRootDisqual(t, clone, f); res.FixCommitUnanswered != "" {
			t.Fatalf("a dependency's advisory was held on the project's history: %+v", res)
		}
	})

	npm := func(name string) AdvisoryFacts {
		return AdvisoryFacts{Coordinate: name, PURL: "pkg:npm/" + name, AffectedRanges: fixedRange}
	}
	t.Run("an npm project's own package", func(t *testing.T) {
		h := newFixHistory(t, map[string]string{"package.json": `{"name":"next","dependencies":{"left-pad":"^1.0.0"}}`, "index.js": "module.exports = 1\n"})
		f := npm("next")
		f.Fix = FixHint{UpstreamCommit: h.fix}
		if res := runRootDisqual(t, h.dir, f); res.Reason != ReasonFixCommitInHistory {
			t.Fatalf("got %+v, want %s", res, ReasonFixCommitInHistory)
		}
	})
	t.Run("an npm project's own package with a later range", func(t *testing.T) {
		h := newFixHistory(t, map[string]string{"package.json": `{"name":"next","dependencies":{"left-pad":"^1.0.0"}}`, "index.js": "module.exports = 1\n"})
		fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", "v1.3.0", h.base)
		f := npm("next")
		f.AffectedRanges = twoRanges
		f.Fix = FixHint{UpstreamCommit: h.fix}
		if res := runRootDisqual(t, h.dir, f); res.Disqualified {
			t.Fatalf("cleared on a tag convention npm does not define: %+v", res)
		}
	})
	t.Run("an npm dependency with no resolved version", func(t *testing.T) {
		h := newFixHistory(t, map[string]string{"package.json": `{"name":"next","dependencies":{"left-pad":"^1.0.0"}}`, "index.js": "module.exports = 1\n"})
		f := npm("left-pad")
		f.Fix = FixHint{UpstreamCommit: h.fix}
		if res := runRootDisqual(t, h.dir, f); res.Disqualified {
			t.Fatalf("a dependency's advisory cleared on the project's history: %+v", res)
		}
	})

	t.Run("a dependency's advisory", func(t *testing.T) {
		h := newFixHistory(t, map[string]string{
			"go.mod":  gomod + "\nrequire example.com/dep v1.0.0\n",
			"main.go": "package main\n",
		})
		f := facts("example.com/dep", fixedRange)
		f.Fix = FixHint{UpstreamCommit: h.fix}
		if res := runRootDisqual(t, h.dir, f); res.Reason == ReasonFixCommitInHistory {
			t.Fatalf("a dependency's advisory cleared on the project's history: %+v", res)
		}
	})
}

func runRootDisqual(t *testing.T, dir string, facts AdvisoryFacts) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-fix-commit", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "GHSA-fix-commit", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "acme/app",
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
		},
	}}
	src := rootAdvisorySource{facts: facts}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if err := (codebaseInventory{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	return runDisqual(t, store, c.ID)
}
