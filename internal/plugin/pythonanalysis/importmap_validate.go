package pythonanalysis

import (
	"fmt"
	"reflect"
)

// Validate enforces the D1 invariants on a DistImportMap. It is the type-level honesty check:
// a map that passes carries non-vacuous provenance on every contribution, a citation on every
// curated row (C5), the unknown⟺empty-import-with-partiality biconditional (C4), and a
// canonical sorted+deduped order (C6). Construction (NewDistImportMap) and validation are kept
// separate so a test can build a deliberately invalid map and assert the validator reddens.
func (m DistImportMap) Validate() error {
	for i, c := range m.Contributions {
		// C2a: non-zero, recognized Provenance.
		if c.Provenance == "" {
			return fmt.Errorf("importmap: contribution %d (%q→%q): zero-value Provenance (C2a)", i, c.Distribution, c.ImportPackage)
		}
		if !knownProvenance[c.Provenance] {
			return fmt.Errorf("importmap: contribution %d (%q): unrecognized Provenance %q", i, c.Distribution, c.Provenance)
		}
		if c.Distribution == "" {
			return fmt.Errorf("importmap: contribution %d: empty Distribution", i)
		}

		// C5: a curated row cites its Source + Date.
		if c.Provenance == ProvenanceCurated && (c.Source == "" || c.Date == "") {
			return fmt.Errorf("importmap: curated contribution %d (%q→%q): missing Source or Date (C5)", i, c.Distribution, c.ImportPackage)
		}

		// C4: unknown ⟺ ImportPackage=="" && Partiality!=nil (biconditional, both directions).
		isUnknown := c.Provenance == ProvenanceUnknown
		hasUnknownShape := c.ImportPackage == "" && c.Partiality != nil
		if isUnknown != hasUnknownShape {
			return fmt.Errorf("importmap: contribution %d (%q): unknown⟺(ImportPackage==\"\" && Partiality!=nil) violated (provenance=%q, importPkg=%q, partialityNil=%v) (C4)",
				i, c.Distribution, c.Provenance, c.ImportPackage, c.Partiality == nil)
		}

		// A resolved (non-unknown) contribution must NOT carry partiality — that field is the
		// unknown path's alone, so a curated/declared row cannot masquerade as partial.
		if !isUnknown && c.Partiality != nil {
			return fmt.Errorf("importmap: contribution %d (%q): non-unknown provenance %q must have nil Partiality (C4)", i, c.Distribution, c.Provenance)
		}
	}

	// C6/D1: canonical sorted + deduped by the full identity tuple.
	if !reflect.DeepEqual(m.Contributions, canonicalize(m.Contributions)) {
		return fmt.Errorf("importmap: Contributions not canonical (must be sorted + deduped by (Distribution, ImportPackage, Provenance))")
	}
	return nil
}
