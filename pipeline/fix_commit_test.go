package pipeline

import (
	"context"
	"path/filepath"
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

// TestHeadContainsCommit: the answer is yes only for HEAD and its ancestors in a complete history
// the checkout holds. Everything else, whether the commit is absent from the history or the
// question cannot be answered, is no.
func TestHeadContainsCommit(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) (dir, commit string)
		want  bool
	}{
		{"the fix is HEAD", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.at(t, h.fix).dir, h.fix
		}, true},
		{"the fix is an ancestor of HEAD", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, h.fix
		}, true},
		{"asked from a subdirectory", func(t *testing.T) (string, string) {
			h := newFixHistory(t, map[string]string{"sub/x.txt": "x\n"})
			return filepath.Join(h.dir, "sub"), h.fix
		}, true},
		{"HEAD is the parent of the fix", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.at(t, h.base).dir, h.fix
		}, false},
		{"the fix is on another branch", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, h.side
		}, false},
		{"the object store does not hold the fix", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, strings.Repeat("0123456789", 4)
		}, false},
		{"a shallow clone whose HEAD is the fix", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			h.at(t, h.fix)
			clone := t.TempDir()
			fixtureGit(t, clone, "clone", "-q", "--depth", "1", "file://"+h.dir, ".")
			if got := fixtureGit(t, clone, "rev-parse", "HEAD"); got != h.fix {
				t.Fatalf("shallow clone HEAD = %s, want the fix %s", got, h.fix)
			}
			return clone, h.fix
		}, false},
		{"a replacement object grafts the fix under HEAD", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			fixtureGit(t, h.dir, "replace", "--graft", h.later, h.side)
			return h.dir, h.side
		}, false},
		{"an abbreviated id", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, h.fix[:12]
		}, false},
		{"a ref name where the id belongs", func(t *testing.T) (string, string) {
			h := newFixHistory(t, nil)
			return h.dir, "main"
		}, false},
		{"not a repository", func(t *testing.T) (string, string) {
			return t.TempDir(), strings.Repeat("0123456789", 4)
		}, false},
		{"no directory", func(t *testing.T) (string, string) {
			return "", strings.Repeat("0123456789", 4)
		}, false},
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
// The ancestry question is answered from what the checkout holds, so a fix only the remote has
// stays unanswered and the remote's objects are never copied in.
func TestHeadContainsCommit_NeverFetches(t *testing.T) {
	h := newFixHistory(t, nil)
	fixtureGit(t, h.dir, "config", "uploadpack.allowFilter", "true")
	fixtureGit(t, h.dir, "config", "uploadpack.allowAnySHA1InWant", "true")
	clone := t.TempDir()
	fixtureGit(t, clone, "clone", "-q", "--filter=blob:none", "--single-branch", "--branch", "main", "file://"+h.dir, ".")
	if headContainsCommit(context.Background(), clone, h.side) {
		t.Fatal("a commit only the remote holds was found in the clone's history")
	}
	cmd := gittest.Command("-C", clone, "cat-file", "-e", h.side)
	cmd.Env = append(cmd.Env, "GIT_NO_LAZY_FETCH=1")
	if cmd.Run() == nil {
		t.Fatal("the ancestry question fetched the commit from the remote")
	}
	if !headContainsCommit(context.Background(), clone, h.fix) {
		t.Fatal("a full-history partial clone did not answer for a commit it holds")
	}
}

func TestFixCommitClears(t *testing.T) {
	fixed := affectedRange{UpperExclusive: "1.2.0"}
	yes := func() bool { return true }
	outside := presentRanges{presentPackage: presentPackage{Versions: []string{"v2.0.0"}, Complete: true}, Ranges: []affectedRange{{UpperExclusive: "1.0.0"}}, RangeKnown: true}
	inside := presentRanges{presentPackage: presentPackage{Versions: []string{"v0.9.0"}, Complete: true}, Ranges: []affectedRange{{UpperExclusive: "1.0.0"}}, RangeKnown: true}
	cases := []struct {
		name       string
		rngs       []affectedRange
		rangeKnown bool
		versions   []string
		others     []presentRanges
		inHistory  func() bool
		want       bool
	}{
		{"every range fixed and the fix in history", []affectedRange{fixed}, true, nil, nil, yes, true},
		{"several fixed branch lines", []affectedRange{fixed, {LowerInclusive: "1.3.0", UpperExclusive: "1.3.4"}}, true, nil, nil, yes, true},
		{"the fix is not in history", []affectedRange{fixed}, true, nil, nil, func() bool { return false }, false},
		{"an open-ended last_affected", []affectedRange{{LastAffected: "1.1000.0"}}, true, nil, nil, yes, false},
		{"an open-ended last_affected beside a fixed range", []affectedRange{fixed, {LowerInclusive: "1.3.0", LastAffected: "1.1000.0"}}, true, nil, nil, yes, false},
		{"a range with no upper end", []affectedRange{{LowerInclusive: "1.0.0"}}, true, nil, nil, yes, false},
		{"ranges the advisory does not state", []affectedRange{fixed}, false, nil, nil, yes, false},
		{"no ranges", nil, true, nil, nil, yes, false},
		{"the project has a version the axis did not clear", []affectedRange{fixed}, true, []string{"1.1.0"}, nil, yes, false},
		{"another affected package outside its ranges", []affectedRange{fixed}, true, nil, []presentRanges{outside}, yes, true},
		{"another affected package inside its ranges", []affectedRange{fixed}, true, nil, []presentRanges{outside, inside}, yes, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fixCommitClears(tc.rngs, tc.rangeKnown, tc.versions, tc.others, tc.inHistory); got != tc.want {
				t.Fatalf("fixCommitClears = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("history is not asked when the ranges already refuse", func(t *testing.T) {
		fixCommitClears([]affectedRange{{LastAffected: "1.1000.0"}}, true, nil, nil, func() bool {
			t.Fatal("asked for history")
			return true
		})
	})
}

// TestDisqualification_FixCommitInHistory runs intake, inventory and disqualification over a Go
// project with no version tag, where the version axis has nothing to compare.
func TestDisqualification_FixCommitInHistory(t *testing.T) {
	const gomod = "module example.com/app\n\ngo 1.22\n"
	own := map[string]string{"go.mod": gomod, "main.go": "package main\n"}
	fixedRange := []Range{{Introduced: "0", Fixed: "1.2.0"}}
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixHistory(t, tc.files)
			h.at(t, tc.head(h))
			if tc.tag != "" {
				fixtureGit(t, h.dir, "-c", "tag.gpgsign=false", "tag", tc.tag)
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
