package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// Change kinds between two observations.
const (
	ChangeAdded   = "added"
	ChangeRemoved = "removed"
	ChangeChanged = "changed"
)

// Change is one finding that differs between two observations, keyed by advisory id and package
// instance. A verdict, basis or path_sha difference is a change; Old or New is nil for an added or
// removed finding.
type Change struct {
	Advisory string    `json:"advisory"`
	Package  string    `json:"package"`
	Change   string    `json:"change"`
	Old      *Observed `json:"old,omitempty"`
	New      *Observed `json:"new,omitempty"`
}

func (c Change) String() string {
	show := func(o *Observed) string {
		if o == nil {
			return "-"
		}
		s := string(o.Verdict)
		if o.Basis != "" {
			s += "/" + string(o.Basis)
		}
		if o.UndeterminedReason != "" {
			s += "/" + o.UndeterminedReason
		}
		if o.PathSHA != "" {
			s += " path " + o.PathSHA
		}
		return s
	}
	return fmt.Sprintf("%s %s %s: %s -> %s", c.Change, c.Advisory, c.Package, show(c.Old), show(c.New))
}

// keyedObservations indexes findings by "id package"; a key held by several findings gets a "#n"
// suffix from the second on, in a stable order, so duplicates still line up run to run.
func keyedObservations(findings []report.AdvisoryFinding) (map[string]Observed, map[string][2]string) {
	byKey := map[string][]Observed{}
	names := map[string][2]string{}
	for _, f := range findings {
		k := f.Advisory.ID + " " + packageInstance(f)
		byKey[k] = append(byKey[k], observedOf(f))
		names[k] = [2]string{f.Advisory.ID, packageInstance(f)}
	}
	out := map[string]Observed{}
	outNames := map[string][2]string{}
	for k, obs := range byKey {
		slices.SortFunc(obs, func(a, b Observed) int {
			return cmp.Or(cmp.Compare(a.Verdict, b.Verdict), cmp.Compare(a.Basis, b.Basis),
				cmp.Compare(a.UndeterminedReason, b.UndeterminedReason), cmp.Compare(a.PathSHA, b.PathSHA))
		})
		for i, o := range obs {
			kk := k
			if i > 0 {
				kk = fmt.Sprintf("%s#%d", k, i+1)
			}
			out[kk], outNames[kk] = o, names[k]
		}
	}
	return out, outNames
}

// diffFindings is every finding added, removed or changed from old to new, sorted by advisory and
// package.
func diffFindings(old, new []report.AdvisoryFinding) []Change {
	o, oNames := keyedObservations(old)
	n, nNames := keyedObservations(new)
	var out []Change
	for k, ov := range o {
		nv, ok := n[k]
		switch {
		case !ok:
			out = append(out, Change{Advisory: oNames[k][0], Package: oNames[k][1], Change: ChangeRemoved, Old: &ov})
		case ov.Verdict != nv.Verdict || ov.Basis != nv.Basis || ov.PathSHA != nv.PathSHA:
			out = append(out, Change{Advisory: oNames[k][0], Package: oNames[k][1], Change: ChangeChanged, Old: &ov, New: &nv})
		}
	}
	for k, nv := range n {
		if _, ok := o[k]; !ok {
			out = append(out, Change{Advisory: nNames[k][0], Package: nNames[k][1], Change: ChangeAdded, New: &nv})
		}
	}
	slices.SortFunc(out, func(a, b Change) int {
		return cmp.Or(cmp.Compare(a.Advisory, b.Advisory), cmp.Compare(a.Package, b.Package), cmp.Compare(a.Change, b.Change))
	})
	return out
}

// FixtureDiff is one fixture's changes between two observation directories. Note explains a fixture
// that could not be compared (present on one side only, or without a readable report).
type FixtureDiff struct {
	Fixture string   `json:"fixture"`
	Note    string   `json:"note,omitempty"`
	Changes []Change `json:"changes,omitempty"`
}

// diffDirs compares two observation directories (each <fixture>/report.json), fixture by fixture.
func diffDirs(oldDir, newDir string) ([]FixtureDiff, error) {
	oldNames, err := observationNames(oldDir)
	if err != nil {
		return nil, err
	}
	newNames, err := observationNames(newDir)
	if err != nil {
		return nil, err
	}
	names := slices.Concat(oldNames, newNames)
	slices.Sort(names)
	names = slices.Compact(names)
	var out []FixtureDiff
	for _, name := range names {
		d := FixtureDiff{Fixture: name}
		o, oErr := readObservedReport(filepath.Join(oldDir, name))
		n, nErr := readObservedReport(filepath.Join(newDir, name))
		switch {
		case oErr != nil && nErr != nil:
			d.Note = fmt.Sprintf("no readable report on either side: old: %v; new: %v", oErr, nErr)
		case oErr != nil:
			d.Note = "old: " + oErr.Error()
		case nErr != nil:
			d.Note = "new: " + nErr.Error()
		default:
			d.Changes = diffFindings(o.Advisories, n.Advisories)
		}
		out = append(out, d)
	}
	return out, nil
}

// observationNames is the subdirectories of an observation directory.
func observationNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// readObservedReport reads and decodes dir/report.json.
func readObservedReport(dir string) (report.Report, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileReport))
	if errors.Is(err, fs.ErrNotExist) {
		return report.Report{}, errors.New("no report.json")
	}
	if err != nil {
		return report.Report{}, err
	}
	r, err := decodeReport(data)
	if err != nil {
		return report.Report{}, fmt.Errorf("report.json does not decode: %w", err)
	}
	return r, nil
}

func writeDiffText(w io.Writer, ds []FixtureDiff) {
	for _, d := range ds {
		switch {
		case d.Note != "":
			fmt.Fprintf(w, "== %s: not compared: %s\n", d.Fixture, d.Note)
		case len(d.Changes) == 0:
			fmt.Fprintf(w, "== %s: no change\n", d.Fixture)
		default:
			fmt.Fprintf(w, "== %s: %d changes\n", d.Fixture, len(d.Changes))
			for _, c := range d.Changes {
				fmt.Fprintf(w, "  %s\n", strings.TrimSpace(c.String()))
			}
		}
	}
}
