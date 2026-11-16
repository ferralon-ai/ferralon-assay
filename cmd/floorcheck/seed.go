package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// EvidenceSchema names the normalized comparator output committed under floor/expect/evidence/.
const EvidenceSchema = "ferralon.floor-govulncheck.v1"

// Levels govulncheck can see a vulnerability at, deepest first.
const (
	levelSymbol  = "symbol"
	levelPackage = "package"
	levelModule  = "module"
)

// Evidence is the committed normalized copy of one govulncheck run: enough to re-derive every
// comparator-derived observation, and small enough to read in review.
type Evidence struct {
	Schema      string           `json:"schema"`
	Comparator  EvidenceConfig   `json:"comparator"`
	Target      string           `json:"target"`
	UpstreamSHA string           `json:"upstream_sha"`
	Findings    []EvidenceFinder `json:"findings"`
}

// EvidenceConfig is govulncheck's own config message, with the build it was run under.
type EvidenceConfig struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	DB            string `json:"db"`
	DBLastModfied string `json:"db_last_modified"`
	GoVersion     string `json:"go_version"`
	ScanMode      string `json:"scan_mode"`
	ScanLevel     string `json:"scan_level"`
	Command       string `json:"command"`
}

// EvidenceFinder is one OSV entry affecting one module in the build: the deepest level govulncheck
// reached and, at symbol level, what it reached.
type EvidenceFinder struct {
	OSV     string   `json:"osv"`
	Aliases []string `json:"aliases,omitempty"`
	Module  string   `json:"module"`
	Version string   `json:"version"`
	Fixed   string   `json:"fixed,omitempty"`
	Level   string   `json:"level"`
	// Symbols are the vulnerable functions reached (at most maxSymbols), sorted.
	Symbols []string `json:"symbols,omitempty"`
	// CalledFrom is the outermost frame of the first call stack to a symbol.
	CalledFrom string `json:"called_from,omitempty"`
}

const maxSymbols = 8

// govulncheck's -format json stream: one message per top-level object.
type vulnMessage struct {
	Config  *vulnConfig  `json:"config"`
	OSV     *vulnOSV     `json:"osv"`
	Finding *vulnFinding `json:"finding"`
}

type vulnConfig struct {
	ScannerName    string `json:"scanner_name"`
	ScannerVersion string `json:"scanner_version"`
	DB             string `json:"db"`
	DBLastModified string `json:"db_last_modified"`
	GoVersion      string `json:"go_version"`
	ScanLevel      string `json:"scan_level"`
	ScanMode       string `json:"scan_mode"`
}

type vulnOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type vulnFinding struct {
	OSV          string      `json:"osv"`
	FixedVersion string      `json:"fixed_version"`
	Trace        []vulnFrame `json:"trace"`
}

type vulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
}

func (f vulnFrame) symbol() string {
	name := f.Package + "." + f.Function
	if f.Receiver != "" {
		name = f.Package + "." + f.Receiver + "." + f.Function
	}
	return name
}

// normalizeGovulncheck reads govulncheck's JSON stream and returns the comparator config and, per
// (OSV id, module, version), the deepest level reached.
func normalizeGovulncheck(r io.Reader, command string) (Evidence, error) {
	ev := Evidence{Schema: EvidenceSchema}
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	aliases := map[string][]string{}
	type key struct{ osv, module, version string }
	byKey := map[key]*EvidenceFinder{}
	depth := map[string]int{levelModule: 0, levelPackage: 1, levelSymbol: 2}
	for {
		var m vulnMessage
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return Evidence{}, fmt.Errorf("govulncheck json: %w", err)
		}
		switch {
		case m.Config != nil:
			c := m.Config
			ev.Comparator = EvidenceConfig{Name: c.ScannerName, Version: c.ScannerVersion, DB: c.DB,
				DBLastModfied: c.DBLastModified, GoVersion: c.GoVersion, ScanMode: c.ScanMode, ScanLevel: c.ScanLevel, Command: command}
		case m.OSV != nil:
			aliases[m.OSV.ID] = m.OSV.Aliases
		case m.Finding != nil:
			f := m.Finding
			if len(f.Trace) == 0 {
				continue
			}
			top := f.Trace[0]
			level := levelModule
			switch {
			case top.Function != "":
				level = levelSymbol
			case top.Package != "":
				level = levelPackage
			}
			k := key{f.OSV, top.Module, top.Version}
			e := byKey[k]
			if e == nil {
				e = &EvidenceFinder{OSV: f.OSV, Module: top.Module, Version: top.Version, Fixed: f.FixedVersion, Level: level}
				byKey[k] = e
			}
			if depth[level] > depth[e.Level] {
				e.Level = level
			}
			if level == levelSymbol {
				if s := top.symbol(); !slices.Contains(e.Symbols, s) && len(e.Symbols) < maxSymbols {
					e.Symbols = append(e.Symbols, s)
				}
				if e.CalledFrom == "" {
					e.CalledFrom = f.Trace[len(f.Trace)-1].symbol()
				}
			}
		}
	}
	if ev.Comparator.Name == "" {
		return Evidence{}, fmt.Errorf("govulncheck json: no config message")
	}
	for k, e := range byKey {
		e.Aliases = slices.Clone(aliases[k.osv])
		slices.Sort(e.Aliases)
		slices.Sort(e.Symbols)
		ev.Findings = append(ev.Findings, *e)
	}
	slices.SortFunc(ev.Findings, func(a, b EvidenceFinder) int {
		return strings.Compare(a.OSV+" "+a.Module+" "+a.Version, b.OSV+" "+b.Module+" "+b.Version)
	})
	return ev, nil
}

// toolchainModules are the "modules" whose rows depend on the Go toolchain, not on the repository.
var toolchainModules = []string{"stdlib", "toolchain"}

// moduleOf is the module path of a package instance (module@version).
func moduleOf(instance string) (module, version string) {
	module, version, _ = strings.Cut(instance, "@")
	return module, version
}

// derive maps an engine row onto the comparator's observation, mechanically and by these rules, in order:
//
//   - stdlib and toolchain rows: unknown, "depends on toolchain";
//   - govulncheck reached the advisory in this module at symbol level: reachable; at package level:
//     not_reachable, imported but the vulnerable function is not called; at module level:
//     not_reachable, required but the vulnerable package is never imported;
//   - Assay's own out-of-range verdict: out_of_range;
//   - anything else: unknown, the comparator has no view.
func derive(row engineRow, ev Evidence) (observed, basis, source string) {
	module, version := moduleOf(row.Package)
	comparator := ev.Comparator.Name + " " + ev.Comparator.Version
	if slices.Contains(toolchainModules, module) {
		return TruthUnknown, "depends on toolchain", "ledger rule: stdlib and toolchain rows"
	}
	var best *EvidenceFinder
	for i, f := range ev.Findings {
		if f.Module != module || (version != "" && f.Version != version) {
			continue
		}
		if !slices.Contains(row.Advisory, f.OSV) && !slices.ContainsFunc(f.Aliases, func(a string) bool { return slices.Contains(row.Advisory, a) }) {
			continue
		}
		if best == nil || levelRank(f.Level) > levelRank(best.Level) {
			best = &ev.Findings[i]
		}
	}
	if best != nil {
		switch best.Level {
		case levelSymbol:
			return TruthReachable, fmt.Sprintf("symbol-level: %s reached from %s", strings.Join(best.Symbols, ", "), best.CalledFrom), comparator
		case levelPackage:
			return TruthNotReachable, "imported, vulnerable function not called", comparator
		default:
			return TruthNotReachable, "required, vulnerable package never imported", comparator
		}
	}
	if row.Engine.Verdict == report.VerdictDisqualified && row.Engine.Reason == "version_not_in_affected_range" {
		return TruthOutOfRange, "resolved version is outside the advisory's affected range", "assay version comparison; " + comparator + " reports no finding"
	}
	return TruthUnknown, "comparator has no view: " + comparator + " reports no finding for this advisory in this module", comparator
}

func levelRank(l string) int {
	switch l {
	case levelSymbol:
		return 2
	case levelPackage:
		return 1
	}
	return 0
}

// gapFor names the tracker issue behind a row where the comparator's observation and the engine differ.
func gapFor(observed string, e Engine) string {
	if !disagrees(observed, e) {
		return ""
	}
	if e.Reason == "refutation_withheld" {
		return "#790"
	}
	return "unfiled: " + e.String()
}

// seedLedger builds a ledger from a report and the comparator's evidence. With prior, a row already in
// the ledger keeps its comparator_observed, basis, source and gap (never rewritten once recorded) and
// only its engine_expected follows the report; a gap the engine closed is dropped, and one a changed
// engine_expected opens is derived. A review (path_review past unreviewed, or an adjudication) is kept
// only while its path and every analysis input it is bound to are unchanged; otherwise the row is
// seeded unreviewed and unknown again, and loses featured. in is the scan's analysis inputs.
func seedLedger(hdr LedgerHeader, rep report.Report, ev Evidence, prior *Ledger, in scanInputs) Ledger {
	old := map[string]LedgerRow{}
	if prior != nil {
		for _, r := range prior.Rows {
			old[r.Key()] = r
		}
	}
	l := Ledger{Schema: LedgerSchema, Header: hdr}
	for _, er := range engineRows(rep.Advisories) {
		row := LedgerRow{Advisory: er.Advisory, Package: er.Package, Target: hdr.Target, EngineExpected: er.Engine,
			Adjudicated: Adjudicated{Status: TruthUnknown}}
		bound := boundFor(hdr.Target, er.Package, &er, in)
		if row.reachableRow() {
			row.PathReview = newPathReview(er.Path, bound)
		}
		if o, ok := old[row.Key()]; ok {
			keep := keepReviews(&row, o, bound)
			if keep && o.Featured {
				row.Featured = true
			}
			row.ComparatorObserved, row.Basis, row.Source, row.Gap = o.ComparatorObserved, o.Basis, o.Source, o.Gap
			if !disagrees(row.ComparatorObserved, row.EngineExpected) {
				row.Gap = ""
			} else if row.Gap == "" {
				row.Gap = gapFor(row.ComparatorObserved, row.EngineExpected)
			}
		} else {
			row.ComparatorObserved, row.Basis, row.Source = derive(er, ev)
			row.Gap = gapFor(row.ComparatorObserved, row.EngineExpected)
		}
		l.Rows = append(l.Rows, row)
	}
	// What the comparator reports in a module the engine emitted nothing for: a row, so the engine's
	// blind spot is on record and the check notices when it starts to see it. Toolchain rows are not
	// recorded this way: they depend on the toolchain, not on the repository.
	covered := func(pkg string, ids []string) bool {
		for _, r := range l.Rows {
			if r.Package == pkg && slices.ContainsFunc(r.Advisory, func(a string) bool { return slices.Contains(ids, a) }) {
				return true
			}
		}
		return false
	}
	var silent []LedgerRow
	for _, f := range ev.Findings {
		pkg := f.Module + "@" + f.Version
		ids := append([]string{f.OSV}, f.Aliases...)
		if slices.Contains(toolchainModules, f.Module) || covered(pkg, ids) {
			continue
		}
		slices.Sort(ids)
		er := engineRow{Advisory: slices.Compact(ids), Package: pkg, Engine: Engine{Verdict: VerdictNotEmitted}}
		row := LedgerRow{Advisory: er.Advisory, Package: pkg, Target: hdr.Target, EngineExpected: er.Engine,
			Adjudicated: Adjudicated{Status: TruthUnknown}}
		if o, ok := old[row.Key()]; ok {
			row.ComparatorObserved, row.Basis, row.Source = o.ComparatorObserved, o.Basis, o.Source
			if keepReviews(&row, o, boundFor(hdr.Target, pkg, nil, in)) && o.Featured {
				row.Featured = true
			}
		} else {
			row.ComparatorObserved, row.Basis, row.Source = derive(er, ev)
		}
		row.Gap = gapFor(row.ComparatorObserved, row.EngineExpected)
		if o, ok := old[row.Key()]; ok && o.Gap != "" {
			row.Gap = o.Gap
		}
		silent = append(silent, row)
	}
	l.Rows = append(l.Rows, silent...)
	slices.SortFunc(l.Rows, func(a, b LedgerRow) int { return strings.Compare(a.Key(), b.Key()) })
	return l
}

// keepReviews carries the prior row o's reviews onto row, which was freshly seeded and is bound to
// bound, and reports whether every review o held was kept (so its featured flag may stay). An
// unreviewed path_review is replaced by the fresh one, which refreshes its recorded inputs. A reviewed
// one stays only for the same path under the same inputs, and an adjudication only under the same
// inputs; anything else is reset, and the row loses featured.
func keepReviews(row *LedgerRow, o LedgerRow, bound BoundTo) bool {
	keep := true
	if row.PathReview != nil {
		switch pr := o.PathReview; {
		case pr == nil || pr.Status == StatusUnreviewed:
			keep = keep && pr != nil && pr.PathSHA == row.PathReview.PathSHA
		case pr.PathSHA == row.PathReview.PathSHA && pr.BoundTo != nil && len(pr.BoundTo.diff(bound)) == 0:
			row.PathReview = pr
		default:
			keep = false
		}
	}
	if o.Adjudicated.reviewed() {
		if o.Adjudicated.BoundTo != nil && len(o.Adjudicated.BoundTo.diff(bound)) == 0 {
			row.Adjudicated = o.Adjudicated
		} else {
			keep = false
		}
	}
	return keep
}

// writeLedger renders a ledger as YAML with a header comment.
func writeLedger(path string, l Ledger) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Expected verdicts for %s at %s. docs/floor.md says how to read and update this file.\n", l.Header.Repo, shortSHA(l.Header.UpstreamSHA))
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(l); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// runSeed implements `floorcheck seed`: build or update a showcase target's ledger from a scan's
// report.json and a govulncheck run.
//
//	floorcheck seed -targets floor/targets.json -target traefik -report report.json \
//	    -govulncheck govulncheck.json [-update]
func runSeed(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetsPath := fs.String("targets", "floor/targets.json", "the targets file")
	name := fs.String("target", "", "the showcase target's name (required)")
	reportPath := fs.String("report", "", "report.json of the pinned scan (required)")
	vulnPath := fs.String("govulncheck", "", "raw `govulncheck -mode source -format json ./...` output; omit it to reuse the committed evidence")
	command := fs.String("command", "govulncheck -mode source -format json ./...", "the comparator command line, recorded in the evidence")
	pathsOnly := fs.Bool("paths-only", false, "keep every row of the ledger as it is and only add the path_review of its reachable rows from the report; implies -update")
	update := fs.Bool("update", false, "keep the comparator_observed of rows already in the ledger; follow the report for engine_expected, and reset any review whose path or bound_to inputs changed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "floorcheck seed:", err)
		return 2
	}
	if *name == "" || *reportPath == "" {
		return fail(fmt.Errorf("-target and -report are required"))
	}
	t, err := loadTargets(*targetsPath)
	if err != nil {
		return fail(err)
	}
	var tg *Target
	if t.Showcase != nil {
		for i := range t.Showcase.Targets {
			if t.Showcase.Targets[i].Name() == *name {
				tg = &t.Showcase.Targets[i]
			}
		}
	}
	if tg == nil {
		return fail(fmt.Errorf("%q is not a showcase target", *name))
	}
	data, err := os.ReadFile(*reportPath)
	if err != nil {
		return fail(err)
	}
	rep, err := decodeReport(data)
	if err != nil {
		return fail(err)
	}
	evPath := filepath.Join(filepath.Dir(ledgerPath(*targetsPath, *name)), "evidence", *name+".govulncheck.json")
	var ev Evidence
	if *vulnPath != "" {
		f, err := os.Open(*vulnPath)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		if ev, err = normalizeGovulncheck(f, *command); err != nil {
			return fail(err)
		}
		ev.Target, ev.UpstreamSHA = *name, tg.Ref
		out, _ := json.MarshalIndent(ev, "", " ")
		if err := os.MkdirAll(filepath.Dir(evPath), 0o755); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(evPath, append(out, '\n'), 0o644); err != nil {
			return fail(err)
		}
	} else {
		raw, err := os.ReadFile(evPath)
		if err != nil {
			return fail(err)
		}
		if err := json.Unmarshal(raw, &ev); err != nil {
			return fail(fmt.Errorf("%s: %w", evPath, err))
		}
	}
	sc := t.Showcase
	hdr := LedgerHeader{
		Target: *name, Repo: tg.Repo, Tag: tg.Tag, UpstreamSHA: tg.Ref,
		EntryPackages: []string{"govulncheck: ./...", "assay: the entry points its Go analyzer discovers"},
		GOOS:          sc.GOOS, GOARCH: sc.GOARCH, BuildTags: []string{}, CGO: sc.CGO, TestScope: "tests excluded",
		GoVersion: sc.GoVersion, CorpusRelease: sc.CorpusRelease,
		Comparator: Comparator{Name: ev.Comparator.Name, Version: ev.Comparator.Version, DBTimestamp: ev.Comparator.DBLastModfied,
			Evidence: "evidence/" + *name + ".govulncheck.json"},
	}
	var prior *Ledger
	if *pathsOnly {
		*update = true
	}
	if *update {
		p, err := loadLedgerFor(ledgerPath(*targetsPath, *name), false)
		if err != nil {
			return fail(err)
		}
		prior = &p
		hdr.Comparator = p.Header.Comparator // comparator_observed was derived from that run
	}
	hdr.MainModule = mainModuleOf(rep)
	// The scan's meta.json, beside its report.json, names the scanner commit, corpus release and Go
	// version it ran under; without one the lane's pins stand for the last two.
	var meta Meta
	if raw, err := os.ReadFile(filepath.Join(filepath.Dir(*reportPath), fileMeta)); err == nil {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return fail(fmt.Errorf("%s: %w", filepath.Join(filepath.Dir(*reportPath), fileMeta), err))
		}
	}
	l := seedLedger(hdr, rep, ev, prior, scanInputsOf(sc, rep, meta))
	if *pathsOnly {
		var err error
		if l, err = withPaths(*prior, l); err != nil {
			return fail(err)
		}
	}
	if err := l.validate(true); err != nil {
		return fail(err)
	}
	if err := writeLedger(ledgerPath(*targetsPath, *name), l); err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "floorcheck seed: %s: %d rows\n", *name, len(l.Rows))
	return 0
}

// mainModuleOf is the scanned repository's Go module path, read from the call paths of the report.
func mainModuleOf(rep report.Report) string {
	for _, f := range rep.Advisories {
		if _, mod := callPath(f); mod != "" {
			return mod
		}
	}
	return ""
}

// withPaths is the prior ledger with the path_review of each reachable row taken from seeded, which was
// built from a report, where the row has none, its path moved, or nobody has reviewed it (which
// refreshes its recorded inputs): nothing else about a row changes. A reachable row the report does not show as
// reachable has no path to record, so the report is not the scan the ledger was built from.
func withPaths(prior, seeded Ledger) (Ledger, error) {
	byKey := map[string]LedgerRow{}
	for _, r := range seeded.Rows {
		byKey[r.Key()] = r
	}
	out := prior
	out.Header.MainModule = seeded.Header.MainModule
	out.Rows = slices.Clone(prior.Rows)
	for i, r := range out.Rows {
		if !r.reachableRow() {
			continue
		}
		if s, ok := byKey[r.Key()]; !ok || s.PathReview == nil {
			return Ledger{}, fmt.Errorf("row %s is reachable in the ledger, but the report has no path for it", r.Key())
		} else if r.PathReview == nil || r.PathReview.PathSHA != s.PathReview.PathSHA || r.PathReview.Status == StatusUnreviewed {
			out.Rows[i].PathReview, out.Rows[i].Featured = s.PathReview, false
		}
	}
	return out, nil
}
