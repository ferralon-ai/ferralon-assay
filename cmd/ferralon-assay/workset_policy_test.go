// workset_policy_test.go
//
// A DECLARED advisory policy defines the scan's work set: the floor, plus every id the policy
// carries whose affected package is one of the repository's own dependencies. These tests pin that
// the policy narrows to the repository (a `full`-shaped corpus does not become the work set), that no
// OSV query is made in that mode, that a corpus which cannot enumerate falls back with a disclosure,
// that ids the policy carries but the pass cannot judge are disclosed, not dropped — and that a
// corpus configured WITHOUT a declared policy leaves the work set exactly as it was.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// countingOSV records every QueryBatch call and answers with fixed ids.
type countingOSV struct {
	fakeOSV
	calls int
}

func (c *countingOSV) QueryBatch(ctx context.Context, pkgs []report.Package) (trigger.OSVResult, error) {
	c.calls++
	return c.fakeOSV.QueryBatch(ctx, pkgs)
}

// lookupOnly hides every optional interface of the wrapped source, leaving a corpus reader that
// resolves facts but cannot enumerate its ids.
type lookupOnly struct{ src pipeline.AdvisorySource }

func (l lookupOnly) Lookup(id string) (pipeline.AdvisoryFacts, bool) { return l.src.Lookup(id) }

// goRecord is a minimal valid corpus record naming one Go module.
func goRecord(id, module string) map[string]any {
	return map[string]any{
		"schema_version": "ferralon.normalized_advisory.v3",
		"vuln_id":        id,
		"coordinate":     module,
		"purl":           "pkg:golang/" + module,
		"version_scheme": "gomod",
	}
}

// stdlibRecord is a Go standard-library record, matched through the toolchain.
func stdlibRecord(id string) map[string]any {
	return map[string]any{
		"schema_version": "ferralon.normalized_advisory.v3",
		"vuln_id":        id,
		"purl":           "pkg:golang/stdlib",
		"version_scheme": "go-toolchain",
	}
}

// npmRecord names an npm package: a real coordinate, in another ecosystem.
func npmRecord(id, name string) map[string]any {
	return map[string]any{
		"schema_version": "ferralon.normalized_advisory.v3",
		"vuln_id":        id,
		"coordinate":     name,
		"purl":           "pkg:npm/" + name,
		"version_scheme": "npm",
	}
}

// bareRecord carries no affected package at all, like most of the published corpus.
func bareRecord(id string) map[string]any {
	return map[string]any{
		"schema_version": "ferralon.normalized_advisory.v3",
		"vuln_id":        id,
		"summary":        "no affected package recorded",
	}
}

// corpusEntry is one record plus whether its digest should be deliberately wrong.
type corpusEntry struct {
	doc       map[string]any
	badDigest bool
}

func encodeRecord(t *testing.T, e corpusEntry) (id string, raw []byte, digest string) {
	t.Helper()
	raw, err := json.Marshal(e.doc)
	if err != nil {
		t.Fatalf("encode record: %v", err)
	}
	sum := sha256.Sum256(raw)
	digest = "sha256:" + hex.EncodeToString(sum[:])
	if e.badDigest {
		digest = "sha256:" + strings.Repeat("0", 64)
	}
	return e.doc["vuln_id"].(string), raw, digest
}

// writePolicyBundle writes entries as a <policy>.jsonl.gz corpus bundle.
func writePolicyBundle(t *testing.T, entries []corpusEntry) string {
	t.Helper()
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	for _, e := range entries {
		id, raw, digest := encodeRecord(t, e)
		if err := enc.Encode(map[string]string{
			"identifier":    id,
			"path":          "2099/01/" + id + ".json",
			"output_digest": digest,
			"bytes":         string(raw),
		}); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(body.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "full.jsonl.gz")
	if err := os.WriteFile(path, gz.Bytes(), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// writePolicyTree writes entries as a corpus directory (manifest.json + one file per record), the
// shape the Action's tree route materializes.
func writePolicyTree(t *testing.T, entries []corpusEntry) string {
	t.Helper()
	root := t.TempDir()
	type rec struct {
		Identifier   string `json:"identifier"`
		Path         string `json:"path"`
		OutputDigest string `json:"output_digest"`
	}
	var recs []rec
	for _, e := range entries {
		id, raw, digest := encodeRecord(t, e)
		rel := "2099/01/" + id + ".json"
		if err := os.MkdirAll(filepath.Join(root, "2099", "01"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(rel)), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec{Identifier: id, Path: rel, OutputDigest: digest})
	}
	man, err := json.Marshal(map[string]any{
		"manifest_version": "1.0.0",
		"schema_version":   "ferralon.normalized_advisory.v3",
		"record_count":     len(recs),
		"records":          recs,
		"corpus_digest":    "sha256:" + strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), man, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// fullShapedCorpus is a corpus in the shape of the `full` policy: many ids, almost none of which
// apply to fixtureGoMod's dependencies (golang.org/x/crypto, golang.org/x/text, Go 1.21 stdlib).
// It returns the entries and the ids that SHOULD be admitted.
func fullShapedCorpus() ([]corpusEntry, []string) {
	var entries []corpusEntry
	for i := 0; i < 400; i++ {
		entries = append(entries, corpusEntry{doc: goRecord(fmt.Sprintf("TEST-UNRELATED-GO-%04d", i), fmt.Sprintf("example.org/mod%d", i))})
	}
	for i := 0; i < 200; i++ {
		entries = append(entries, corpusEntry{doc: npmRecord(fmt.Sprintf("TEST-NPM-%04d", i), "golang.org/x/crypto")})
	}
	want := []string{"TEST-MATCH-CRYPTO", "TEST-MATCH-STDLIB", "TEST-MATCH-TEXT"}
	entries = append(entries,
		corpusEntry{doc: goRecord("TEST-MATCH-CRYPTO", "golang.org/x/crypto")},
		corpusEntry{doc: goRecord("TEST-MATCH-TEXT", "golang.org/x/text")},
		corpusEntry{doc: stdlibRecord("TEST-MATCH-STDLIB")},
	)
	return entries, want
}

func extraIDs(ws workSet, floorLen int) []string {
	return ids(ws.advisories[floorLen:])
}

// TestPolicyWorkSet_FullDoesNotExpandToCorpus is the acceptance gate: a `full`-shaped policy defines
// the work set as floor ∪ the few ids matching this repository, never the whole corpus. Both corpus
// shapes the Action can hand the scanner are exercised, through the same entrypoint a run uses.
func TestPolicyWorkSet_FullDoesNotExpandToCorpus(t *testing.T) {
	entries, want := fullShapedCorpus()
	for _, tc := range []struct {
		name string
		path string
	}{
		{"bundle", writePolicyBundle(t, entries)},
		{"tree", writePolicyTree(t, entries)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")
			t.Setenv(envOSVWorkSet, "")
			t.Setenv(envAdvisoryCorpusPolicy, "")
			f := runFlagsFor(t, "-advisory-corpus", tc.path, "-advisory-corpus-policy", "full")
			if _, err := f.advisoryCorpusOption(); err != nil {
				t.Fatalf("advisoryCorpusOption: %v", err)
			}
			acq := goFixture(t, fixtureGoMod)
			floorLen := len(acq.advisories)

			ws, err := f.scanWorkSet(context.Background(), acq)
			if err != nil {
				t.Fatalf("scanWorkSet: %v", err)
			}
			if ws.source != workSetSourceBuiltinUnionPolicy {
				t.Errorf("WorkSetSource = %q, want %q", ws.source, workSetSourceBuiltinUnionPolicy)
			}
			for i, a := range acq.advisories {
				if ws.advisories[i].ID != a.ID {
					t.Fatalf("floor not preserved in order at %d: got %q, want %q", i, ws.advisories[i].ID, a.ID)
				}
			}
			if got := extraIDs(ws, floorLen); !reflect.DeepEqual(got, want) {
				t.Errorf("policy additions = %v, want %v", got, want)
			}
			if len(ws.advisories) >= len(entries) {
				t.Errorf("work set = %d ids from a %d-record corpus: the policy expanded to the corpus instead of the repository", len(ws.advisories), len(entries))
			}
			if ws.widened != len(want) {
				t.Errorf("widened = %d, want %d", ws.widened, len(want))
			}
			if len(ws.partiality) != 0 {
				t.Errorf("every record carries a package and resolves, so nothing should be disclosed; got %+v", ws.partiality)
			}
		})
	}
}

// TestPolicyWorkSet_MakesNoOSVQuery proves the policy mode never asks OSV, even with the OSV widening
// explicitly switched on — at the client seam and at the transport.
func TestPolicyWorkSet_MakesNoOSVQuery(t *testing.T) {
	entries, want := fullShapedCorpus()
	bundle := writePolicyBundle(t, entries)
	corpus := pipeline.NewBundleSource(bundle)
	chain := pipeline.NewChainSource(corpus, pipeline.NewTableSource())

	t.Run("client seam", func(t *testing.T) {
		acq := goFixture(t, fixtureGoMod)
		osv := &countingOSV{fakeOSV: fakeOSV{ids: []string{"CVE-2023-39325", "GHSA-from-osv-only"}}}

		ws := selectWorkSet(context.Background(), acq, corpus, chain, "full", true, osv)

		if osv.calls != 0 {
			t.Fatalf("policy mode made %d OSV call(s); the policy, not OSV, defines the work set", osv.calls)
		}
		if got := extraIDs(ws, len(acq.advisories)); !reflect.DeepEqual(got, want) {
			t.Errorf("policy additions = %v, want %v (no OSV-reported id may enter)", got, want)
		}
	})

	t.Run("transport", func(t *testing.T) {
		t.Setenv(envAdvisoryCorpusDir, "")
		t.Setenv(envAdvisoryCorpusRequired, "")
		t.Setenv(envAdvisoryCorpusPolicy, "")
		trap := trapEgress(t)
		f := runFlagsFor(t, "-osv-work-set=true", "-advisory-corpus", bundle, "-advisory-corpus-policy", "full")
		if _, err := f.advisoryCorpusOption(); err != nil {
			t.Fatalf("advisoryCorpusOption: %v", err)
		}
		if _, err := f.scanWorkSet(context.Background(), goFixture(t, fixtureGoMod)); err != nil {
			t.Fatalf("scanWorkSet: %v", err)
		}
		if len(trap.hosts) != 0 {
			t.Fatalf("policy mode contacted %v", trap.hosts)
		}
	})
}

// TestPolicyWorkSet_NonEnumerableCorpusFallsBack proves a corpus whose reader cannot list its ids
// degrades to exactly the no-policy behaviour for the same OSV setting, plus a note saying the
// policy did not define the work set.
func TestPolicyWorkSet_NonEnumerableCorpusFallsBack(t *testing.T) {
	entries, _ := fullShapedCorpus()
	corpus := lookupOnly{src: pipeline.NewBundleSource(writePolicyBundle(t, entries))}
	chain := pipeline.NewChainSource(corpus, pipeline.NewTableSource())

	for _, tc := range []struct {
		name       string
		osvEnabled bool
	}{
		{"osv widening off", false},
		{"osv widening on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, fixtureGoMod)
			osvIDs := []string{"CVE-2023-39325", "GHSA-nope-nope-nope"}

			got := selectWorkSet(context.Background(), acq, corpus, chain, "full", tc.osvEnabled, &countingOSV{fakeOSV: fakeOSV{ids: osvIDs}})

			want := floorWorkSet(acq.advisories)
			if tc.osvEnabled {
				want = resolveWorkSet(context.Background(), acq, &fakeOSV{ids: osvIDs}, chain)
			}
			if !reflect.DeepEqual(got.advisories, want.advisories) || got.source != want.source || got.widened != want.widened {
				t.Errorf("fallback work set = (%v, %q, %d), want today's (%v, %q, %d)",
					ids(got.advisories), got.source, got.widened, ids(want.advisories), want.source, want.widened)
			}
			if !hasReason(got.partiality, reasonWorkSetPolicyNotEnumerable) {
				t.Fatalf("a policy that could not define the work set was not disclosed; notes = %+v", got.partiality)
			}
			if !strings.Contains(got.describe(), "did NOT define the work set") {
				t.Errorf("terminal line does not admit the fallback: %q", got.describe())
			}
		})
	}
}

// TestPolicyWorkSet_UnjudgeableIDsAreDisclosed proves policy ids with no affected package, and ids
// whose record fails validation, are neither admitted nor silently dropped: each class gets a note
// carrying its exact count and (bounded) identities.
func TestPolicyWorkSet_UnjudgeableIDsAreDisclosed(t *testing.T) {
	var entries []corpusEntry
	var bare []string
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("TEST-BARE-%02d", i)
		bare = append(bare, id)
		entries = append(entries, corpusEntry{doc: bareRecord(id)})
	}
	entries = append(entries,
		corpusEntry{doc: goRecord("TEST-BADDIGEST", "golang.org/x/crypto"), badDigest: true},
		corpusEntry{doc: goRecord("TEST-MATCH-CRYPTO", "golang.org/x/crypto")},
	)

	for _, tc := range []struct {
		name   string
		corpus pipeline.AdvisorySource
	}{
		{"bundle", pipeline.NewBundleSource(writePolicyBundle(t, entries))},
		{"tree", pipeline.NewArtifactSource(writePolicyTree(t, entries))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, fixtureGoMod)
			ws := selectWorkSet(context.Background(), acq, tc.corpus, pipeline.NewChainSource(tc.corpus, pipeline.NewTableSource()), "full", false, &fakeOSV{})

			if got := extraIDs(ws, len(acq.advisories)); !reflect.DeepEqual(got, []string{"TEST-MATCH-CRYPTO"}) {
				t.Errorf("admitted = %v, want only TEST-MATCH-CRYPTO", got)
			}
			for _, id := range append(append([]string{}, bare...), "TEST-BADDIGEST") {
				if hasID(ws.advisories, id) {
					t.Errorf("%s was admitted; it cannot be judged against this repository", id)
				}
			}
			if !reflect.DeepEqual(ws.noCoordinates, bare) {
				t.Errorf("noCoordinates = %v, want %v", ws.noCoordinates, bare)
			}
			if !reflect.DeepEqual(ws.policyUnresolvable, []string{"TEST-BADDIGEST"}) {
				t.Errorf("policyUnresolvable = %v, want [TEST-BADDIGEST]", ws.policyUnresolvable)
			}

			var noCoord, unresolvable *report.PartialityNote
			for i := range ws.partiality {
				switch ws.partiality[i].Reason {
				case reasonPolicyAdvisoryNoCoordinates:
					noCoord = &ws.partiality[i]
				case reasonPolicyAdvisoryUnresolvable:
					unresolvable = &ws.partiality[i]
				}
			}
			if noCoord == nil || unresolvable == nil {
				t.Fatalf("missing disclosure; notes = %+v", ws.partiality)
			}
			if !strings.HasPrefix(noCoord.Detail, "20 advisory id(s)") || !strings.Contains(noCoord.Detail, "and 8 more") {
				t.Errorf("no-coordinates Detail must carry the exact count and bound the ids: %q", noCoord.Detail)
			}
			if !strings.Contains(unresolvable.Detail, "TEST-BADDIGEST") {
				t.Errorf("unresolvable Detail must name the id: %q", unresolvable.Detail)
			}
			if report.ClassifyPartialityReason(noCoord.Reason) != report.PartialityDidNotRun {
				t.Errorf("unassessed policy ids must classify loud (did_not_run), got %q", report.ClassifyPartialityReason(noCoord.Reason))
			}
			line := ws.describe()
			if !strings.Contains(line, "name no affected package") || !strings.Contains(line, "TEST-BADDIGEST") {
				t.Errorf("terminal line does not carry the disclosures: %q", line)
			}
		})
	}
}

// TestPolicyWorkSet_NoInventoryIsDisclosed proves a policy run on a repository whose dependencies
// cannot be read stays on the floor and says why, instead of reporting a policy pass that matched
// nothing.
func TestPolicyWorkSet_NoInventoryIsDisclosed(t *testing.T) {
	entries, _ := fullShapedCorpus()
	corpus := pipeline.NewBundleSource(writePolicyBundle(t, entries))
	acq := goFixture(t, fixtureGoMod)
	if err := os.Remove(filepath.Join(acq.buildDir, "go.mod")); err != nil {
		t.Fatal(err)
	}

	ws := selectWorkSet(context.Background(), acq, corpus, corpus, "full", false, &fakeOSV{})

	if len(ws.advisories) != len(acq.advisories) {
		t.Errorf("work set = %d, want the floor's %d", len(ws.advisories), len(acq.advisories))
	}
	if ws.source != report.WorkSetBuiltinLanguageSet {
		t.Errorf("WorkSetSource = %q, want %q: only the floor ran", ws.source, report.WorkSetBuiltinLanguageSet)
	}
	if len(ws.partiality) == 0 {
		t.Fatal("an unreadable inventory on a policy run was not disclosed")
	}
}

// TestSelectWorkSet_NoCorpusIsUnchanged proves a run with no corpus resolves exactly what it did
// before the policy mode existed, for both OSV settings.
func TestSelectWorkSet_NoCorpusIsUnchanged(t *testing.T) {
	table := pipeline.NewTableSource()
	osvIDs := []string{"CVE-2023-39325", "GHSA-nope-nope-nope"}

	acq := goFixture(t, fixtureGoMod)
	if got, want := selectWorkSet(context.Background(), acq, nil, table, "", false, &fakeOSV{ids: osvIDs}), floorWorkSet(acq.advisories); !reflect.DeepEqual(got, want) {
		t.Errorf("no corpus, OSV off: got %+v, want the floor %+v", got, want)
	}
	got := selectWorkSet(context.Background(), acq, nil, table, "", true, &fakeOSV{ids: osvIDs})
	want := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: osvIDs}, table)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("no corpus, OSV on: got %+v, want resolveWorkSet's %+v", got, want)
	}
}

// TestSelectWorkSet_CorpusWithoutPolicyIsUnchanged is the compatibility gate for every run that
// configures a corpus but declares no policy — the Action's whole-corpus fetch and a bundle handed
// over by path alike. An enumerable corpus alone must NOT change the work set: the result is exactly
// what the pass resolved before policies existed, OSV widening included.
func TestSelectWorkSet_CorpusWithoutPolicyIsUnchanged(t *testing.T) {
	entries, _ := fullShapedCorpus()
	osvIDs := []string{"CVE-2023-39325", "TEST-MATCH-CRYPTO", "GHSA-nope-nope-nope"}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"bundle", writePolicyBundle(t, entries)},
		{"tree", writePolicyTree(t, entries)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")
			t.Setenv(envAdvisoryCorpusPolicy, "")
			t.Setenv(envOSVWorkSet, "")
			f := runFlagsFor(t, "-advisory-corpus", tc.path)
			if _, err := f.advisoryCorpusOption(); err != nil {
				t.Fatalf("advisoryCorpusOption: %v", err)
			}
			if _, ok := f.corpusReader.(pipeline.AdvisoryEnumerator); !ok {
				t.Fatal("test corpus does not enumerate; this test would not prove the policy gate")
			}

			acq := goFixture(t, fixtureGoMod)
			osv := &countingOSV{fakeOSV: fakeOSV{ids: osvIDs}}
			got := selectWorkSet(context.Background(), acq, f.corpusReader, f.resolvedSource, f.resolvedPolicy, true, osv)
			want := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: osvIDs}, f.resolvedSource)
			if osv.calls != 1 {
				t.Errorf("OSV calls = %d, want 1: with no policy declared the OSV widening runs as before", osv.calls)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("no declared policy, OSV on:\n got  %+v\n want %+v", got, want)
			}

			ws, err := f.scanWorkSet(context.Background(), acq)
			if err != nil {
				t.Fatalf("scanWorkSet: %v", err)
			}
			if !reflect.DeepEqual(ws, floorWorkSet(acq.advisories)) {
				t.Errorf("no declared policy, OSV off: got %+v, want the floor", ws)
			}
			if p := f.intelProvenance(ws); p.CorpusPolicy != "" {
				t.Errorf("Report CorpusPolicy = %q, want empty with no declared policy", p.CorpusPolicy)
			}
		})
	}
}

// TestAdvisoryCorpusPolicy_Precedence: the flag wins over the env var, either channel alone declares
// the policy, a malformed id fails loudly on either channel, and a policy with no corpus is refused.
// A declared policy is recorded on the Report's intel provenance.
func TestAdvisoryCorpusPolicy_Precedence(t *testing.T) {
	bundle := writePolicyBundle(t, []corpusEntry{{doc: goRecord("TEST-MATCH-CRYPTO", "golang.org/x/crypto")}})

	for _, tc := range []struct {
		name    string
		args    []string
		env     string
		want    string
		wantErr string
	}{
		{name: "neither", args: []string{"-advisory-corpus", bundle}, want: ""},
		{name: "flag only", args: []string{"-advisory-corpus", bundle, "-advisory-corpus-policy", "published-7d"}, want: "published-7d"},
		{name: "env only", args: []string{"-advisory-corpus", bundle}, env: "full", want: "full"},
		{name: "flag wins over env", args: []string{"-advisory-corpus", bundle, "-advisory-corpus-policy", "published-24h"}, env: "full", want: "published-24h"},
		{name: "malformed flag", args: []string{"-advisory-corpus", bundle, "-advisory-corpus-policy", "../full"}, wantErr: "is not a policy id"},
		{name: "malformed env", args: []string{"-advisory-corpus", bundle}, env: "Full", wantErr: "is not a policy id"},
		{name: "policy without a corpus", args: []string{"-advisory-corpus-policy", "full"}, wantErr: "no corpus path resolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envAdvisoryCorpusDir, "")
			t.Setenv(envAdvisoryCorpusRequired, "")
			t.Setenv(envAdvisoryCorpusPolicy, tc.env)
			f := runFlagsFor(t, tc.args...)

			_, err := f.advisoryCorpusOption()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("advisoryCorpusOption: %v", err)
			}
			if f.resolvedPolicy != tc.want {
				t.Errorf("resolved policy = %q, want %q", f.resolvedPolicy, tc.want)
			}
			if p := f.intelProvenance(floorWorkSet(nil)); p.CorpusPolicy != tc.want {
				t.Errorf("Report CorpusPolicy = %q, want %q", p.CorpusPolicy, tc.want)
			}
		})
	}
}
