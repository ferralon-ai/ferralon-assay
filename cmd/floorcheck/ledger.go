package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// LedgerSchema names the floor/expect/<target>.yaml format.
const LedgerSchema = "ferralon.floor-ledger.v1"

// Truth values: what a human (or, here, the comparator) says is the case, kept apart from what Assay
// emits today.
const (
	TruthReachable    = "reachable"
	TruthNotReachable = "not_reachable"
	TruthOutOfRange   = "out_of_range"
	TruthNotPresent   = "not_present"
	TruthConditional  = "conditional"
	TruthUnknown      = "unknown"
)

// VerdictNotEmitted is the engine_expected verdict of a row the comparator reports and Assay emits no
// finding for at all: a package instance or advisory the engine does not see.
const VerdictNotEmitted report.Verdict = "not_emitted"

var truths = []string{TruthReachable, TruthNotReachable, TruthOutOfRange, TruthNotPresent, TruthConditional, TruthUnknown}

// Ledger is one showcase target's expected-verdict ledger: the build scope the rows hold under and one
// row per advisory alias set, resolved package instance and scan target.
type Ledger struct {
	Schema string       `yaml:"schema"`
	Header LedgerHeader `yaml:"header"`
	Rows   []LedgerRow  `yaml:"rows"`
}

// LedgerHeader is the build scope of a ledger: change any of it and the rows may no longer hold.
type LedgerHeader struct {
	Target        string     `yaml:"target"`
	Repo          string     `yaml:"repo"`
	Tag           string     `yaml:"tag,omitempty"`
	UpstreamSHA   string     `yaml:"upstream_sha"`
	EntryPackages []string   `yaml:"entry_packages"`
	GOOS          string     `yaml:"goos"`
	GOARCH        string     `yaml:"goarch"`
	BuildTags     []string   `yaml:"build_tags"`
	CGO           bool       `yaml:"cgo"`
	TestScope     string     `yaml:"test_scope"`
	GoVersion     string     `yaml:"go_version"`
	CorpusRelease string     `yaml:"corpus_release"`
	Comparator    Comparator `yaml:"comparator"`
	// MainModule is the scanned repository's Go module path: the review aid marks a hop in it as the
	// target's own code.
	MainModule string `yaml:"main_module,omitempty"`
}

// Comparator names the tool the truth column was derived from, with the database state it read.
type Comparator struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	DBTimestamp string `yaml:"db_timestamp"`
	// Evidence is the committed normalized copy of the comparator's output, relative to floor/expect.
	Evidence string `yaml:"evidence"`
}

// LedgerRow is one expectation. Truth is the comparator-derived column, EngineExpected is what Assay
// emits today, and Gap names the tracker issue when the two differ.
type LedgerRow struct {
	// Advisory is the alias set, sorted: every id the engine files the vulnerability under.
	Advisory       []string `yaml:"advisory"`
	Package        string   `yaml:"package"`
	Target         string   `yaml:"target"`
	Truth          string   `yaml:"truth"`
	Basis          string   `yaml:"basis"`
	Source         string   `yaml:"source"`
	EngineExpected Engine   `yaml:"engine_expected"`
	Gap            string   `yaml:"gap,omitempty"`
	// PathReview is on every row whose engine_expected verdict is reachable_candidate, and only those.
	PathReview *PathReview `yaml:"path_review,omitempty"`
	// Featured marks a row a demo shows; allowed only once its path_review status is real.
	Featured bool `yaml:"featured,omitempty"`
}

// Engine is a verdict and the reason Assay gives for it: undetermined_reason for an undetermined
// finding, the evidence basis for a refutation, empty otherwise.
type Engine struct {
	Verdict report.Verdict `yaml:"verdict"`
	Reason  string         `yaml:"reason,omitempty"`
}

func (e Engine) String() string {
	if e.Reason == "" {
		return string(e.Verdict)
	}
	return string(e.Verdict) + "/" + e.Reason
}

// Key identifies a row: its alias set, package instance and scan target.
func (r LedgerRow) Key() string { return rowKey(r.Advisory, r.Package, r.Target) }

func rowKey(advisory []string, pkg, target string) string {
	return strings.Join(advisory, " / ") + " | " + pkg + " | " + target
}

// parseLedger decodes and validates a ledger. Unknown fields are refused, so a misspelt key fails here.
func parseLedger(data []byte) (Ledger, error) { return parseLedgerFor(data, true) }

// parseLedgerFor is parseLedger; with needReview false a reachable row may lack its path_review block,
// which is how `seed -update` reads a ledger written before path review existed.
func parseLedgerFor(data []byte, needReview bool) (Ledger, error) {
	var l Ledger
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&l); err != nil {
		return Ledger{}, fmt.Errorf("ledger: %w", err)
	}
	if err := l.validate(needReview); err != nil {
		return Ledger{}, fmt.Errorf("ledger %s: %w", l.Header.Target, err)
	}
	return l, nil
}

func loadLedger(path string) (Ledger, error) { return loadLedgerFor(path, true) }

func loadLedgerFor(path string, needReview bool) (Ledger, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Ledger{}, err
	}
	l, err := parseLedgerFor(data, needReview)
	if err != nil {
		return Ledger{}, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// ledgerPath is where a target's ledger lives, beside the targets file.
func ledgerPath(targetsPath, name string) string {
	return filepath.Join(filepath.Dir(targetsPath), "expect", name+".yaml")
}

func (l Ledger) validate(needReview bool) error {
	h := l.Header
	switch {
	case l.Schema != LedgerSchema:
		return fmt.Errorf("schema %q, want %q", l.Schema, LedgerSchema)
	case h.Target == "" || h.Repo == "":
		return fmt.Errorf("header needs target and repo")
	case !commitPattern.MatchString(h.UpstreamSHA):
		return fmt.Errorf("header upstream_sha %q is not a full commit id", h.UpstreamSHA)
	case len(h.EntryPackages) == 0 || h.GOOS == "" || h.GOARCH == "" || h.TestScope == "" || h.GoVersion == "":
		return fmt.Errorf("header needs entry_packages, goos, goarch, test_scope and go_version")
	case h.CorpusRelease == "":
		return fmt.Errorf("header needs corpus_release")
	case h.Comparator.Name == "" || h.Comparator.Version == "" || h.Comparator.DBTimestamp == "":
		return fmt.Errorf("header comparator needs name, version and db_timestamp")
	}
	seen := map[string]bool{}
	for i, r := range l.Rows {
		switch {
		case len(r.Advisory) == 0 || r.Package == "":
			return fmt.Errorf("row %d: needs an advisory alias set and a package", i+1)
		case !slices.IsSorted(r.Advisory):
			return fmt.Errorf("row %d (%s): advisory ids are not sorted", i+1, r.Key())
		case r.Target != h.Target:
			return fmt.Errorf("row %d (%s): target %q is not the ledger's %q", i+1, r.Key(), r.Target, h.Target)
		case !slices.Contains(truths, r.Truth):
			return fmt.Errorf("row %d (%s): truth %q is not one of %s", i+1, r.Key(), r.Truth, strings.Join(truths, ", "))
		case r.Basis == "" || r.Source == "":
			return fmt.Errorf("row %d (%s): basis and source are required", i+1, r.Key())
		case r.EngineExpected.Verdict == "":
			return fmt.Errorf("row %d (%s): engine_expected needs a verdict", i+1, r.Key())
		case seen[r.Key()]:
			return fmt.Errorf("row %d: duplicate row %s", i+1, r.Key())
		case r.validatePathReview(needReview) != nil:
			return fmt.Errorf("row %d (%s): %w", i+1, r.Key(), r.validatePathReview(needReview))
		case disagrees(r.Truth, r.EngineExpected) && r.Gap == "":
			return fmt.Errorf("row %d (%s): truth %s and engine_expected %s differ, so the row needs a gap", i+1, r.Key(), r.Truth, r.EngineExpected)
		}
		seen[r.Key()] = true
	}
	return nil
}

// disagrees reports whether truth and the engine's verdict contradict each other. `unknown` and
// `conditional` truths claim nothing to contradict.
func disagrees(truth string, e Engine) bool {
	switch truth {
	case TruthReachable:
		return e.Verdict != report.VerdictReachableCandidate
	case TruthNotReachable:
		return e.Verdict != report.VerdictNotExploitable && e.Verdict != VerdictNotEmitted &&
			!(e.Verdict == report.VerdictDisqualified && e.Reason == "vulnerable_symbol_absent")
	case TruthOutOfRange:
		return e.Verdict != report.VerdictDisqualified || e.Reason != "version_not_in_affected_range"
	case TruthNotPresent:
		return e.Verdict != report.VerdictDisqualified || e.Reason != ""
	default:
		return false
	}
}

// engineRow is what the engine emitted for one ledger key.
type engineRow struct {
	Advisory []string
	Package  string
	Engine   Engine
	// Path is the call path of a reachable_candidate, as qualified hops.
	Path []string
}

// packageInstance names the resolved package instance a finding concerns: module@version.
func packageInstance(f report.AdvisoryFinding) string {
	if f.Package == nil {
		return "-"
	}
	if f.Package.Version == "" {
		return f.Package.Name
	}
	return f.Package.Name + "@" + f.Package.Version
}

// engineOf is the verdict and reason of a finding.
func engineOf(f report.AdvisoryFinding) Engine {
	e := Engine{Verdict: f.Verdict}
	switch f.Verdict {
	case report.VerdictUndetermined:
		e.Reason = f.UndeterminedReason
	case report.VerdictNotExploitable, report.VerdictDisqualified:
		e.Reason = string(f.Evidence.Basis)
	}
	return e
}

// strength orders verdicts for a merged alias set whose findings disagree: the one that asserts the
// most wins, so a set is never shown cleaner than its worst finding.
var strength = map[report.Verdict]int{
	report.VerdictMaliciousPresent:   5,
	report.VerdictReachableCandidate: 4,
	report.VerdictUndetermined:       3,
	report.VerdictNotExploitable:     2,
	report.VerdictDisqualified:       1,
}

// engineRows groups a report's findings into ledger keys: findings on the same package instance that
// share any id or alias are one alias set. Rows come back sorted by key.
func engineRows(advisories []report.AdvisoryFinding) []engineRow {
	byPkg := map[string][]report.AdvisoryFinding{}
	for _, f := range advisories {
		if f.Advisory.ID == "" {
			continue
		}
		p := packageInstance(f)
		byPkg[p] = append(byPkg[p], f)
	}
	var out []engineRow
	for pkg, fs := range byPkg {
		parent := map[string]string{}
		var find func(string) string
		find = func(x string) string {
			if parent[x] != x {
				parent[x] = find(parent[x])
			}
			return parent[x]
		}
		idsOf := func(f report.AdvisoryFinding) []string {
			ids := []string{f.Advisory.ID}
			for _, a := range f.Advisory.Aliases {
				if a != "" {
					ids = append(ids, a)
				}
			}
			return ids
		}
		for _, f := range fs {
			ids := idsOf(f)
			for _, id := range ids {
				if _, ok := parent[id]; !ok {
					parent[id] = id
				}
			}
			for _, id := range ids[1:] {
				parent[find(id)] = find(ids[0])
			}
		}
		sets := map[string]*engineRow{}
		for _, f := range fs {
			root := find(f.Advisory.ID)
			row := sets[root]
			if row == nil {
				row = &engineRow{Package: pkg}
				sets[root] = row
			}
			row.Advisory = append(row.Advisory, idsOf(f)...)
			e := engineOf(f)
			var path []string
			if e.Verdict == report.VerdictReachableCandidate {
				path, _ = callPath(f)
			}
			// Equal verdicts keep the path that sorts first, so the row never depends on report order.
			if row.Engine.Verdict == "" || strength[e.Verdict] > strength[row.Engine.Verdict] ||
				(strength[e.Verdict] == strength[row.Engine.Verdict] && (e.Reason < row.Engine.Reason ||
					(e.Reason == row.Engine.Reason && slices.Compare(path, row.Path) < 0))) {
				row.Engine, row.Path = e, path
			}
		}
		for _, row := range sets {
			slices.Sort(row.Advisory)
			row.Advisory = slices.Compact(row.Advisory)
			out = append(out, *row)
		}
	}
	slices.SortFunc(out, func(a, b engineRow) int {
		return strings.Compare(rowKey(a.Advisory, a.Package, ""), rowKey(b.Advisory, b.Package, ""))
	})
	return out
}

// LedgerDiff is the difference between a ledger and the rows the engine emitted.
type LedgerDiff struct {
	// Lines is one line per differing row, in key order: missing, extra or changed, with the old and
	// new value.
	Lines []string
}

// compareLedger compares the engine's rows for target with the ledger's engine_expected: any missing,
// extra or changed row is a difference, whether it is a regression or an improvement.
func compareLedger(l Ledger, rows []engineRow) LedgerDiff {
	want := map[string]LedgerRow{}
	for _, r := range l.Rows {
		want[r.Key()] = r
	}
	got := map[string]engineRow{}
	for _, r := range rows {
		got[rowKey(r.Advisory, r.Package, l.Header.Target)] = r
	}
	keys := make([]string, 0, len(want)+len(got))
	for k := range want {
		keys = append(keys, k)
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var d LedgerDiff
	for _, k := range keys {
		w, inLedger := want[k]
		g, inReport := got[k]
		switch {
		case inLedger && !inReport && w.EngineExpected.Verdict == VerdictNotEmitted:
			// the engine still emits nothing for it, as the ledger expects
		case inLedger && !inReport:
			d.Lines = append(d.Lines, fmt.Sprintf("missing: %s: ledger %s, scan emitted no row", k, w.EngineExpected))
		case !inLedger:
			d.Lines = append(d.Lines, fmt.Sprintf("extra: %s: not in the ledger, scan emitted %s", k, g.Engine))
		case w.EngineExpected != g.Engine:
			d.Lines = append(d.Lines, fmt.Sprintf("changed: %s: %s -> %s", k, w.EngineExpected, g.Engine))
		case w.PathReview != nil && g.Engine.Verdict == report.VerdictReachableCandidate && pathSHA(g.Path) != w.PathReview.PathSHA:
			d.Lines = append(d.Lines, fmt.Sprintf("path changed: %s: was %s [%s], now %s [%s]: update path_review.path and reset its status to unreviewed in the same change",
				k, w.PathReview.PathSHA, strings.Join(w.PathReview.Path, " -> "), pathSHA(g.Path), strings.Join(g.Path, " -> ")))
		}
	}
	return d
}

// loadLedgers loads the ledger of every showcase target, keyed by target name; a ledger that cannot be
// loaded is reported by name, so the target fails with the reason instead of the run exiting.
func loadLedgers(targetsPath string, t Targets) (map[string]Ledger, map[string]error) {
	ledgers, errs := map[string]Ledger{}, map[string]error{}
	if t.Showcase == nil {
		return ledgers, errs
	}
	for _, tg := range t.Showcase.Targets {
		l, err := loadLedger(ledgerPath(targetsPath, tg.Name()))
		if err != nil {
			errs[tg.Name()] = err
			continue
		}
		ledgers[tg.Name()] = l
	}
	return ledgers, errs
}
