package statestore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// DepFetch is the dependency-fetch record (depfetch.json): per npm registry, whether it has
// served this repository a fetch and how many cve-watch runs it has held the cursor, plus the
// advisories assessed without dependency code that a later run must assess again.
//
// It describes the report.json beside it and no other. A store stamps ReportSHA256 with the
// digest of the report bytes it writes, and a read whose report.json does not hash to it drops
// the record: a writer that does not model this file carries it unchanged past a report.json it
// rewrote, and the record would then describe a report that is gone.
//
// The format may only grow by adding fields: a reader checks report_sha256 before it decodes the
// rest, and fails on a record bound to its report whose other fields it cannot decode.
type DepFetch struct {
	// ReportSHA256 is the hex SHA-256 of the report.json this record was written beside, or ""
	// when it was written with none. A store sets it on write; a caller's value is ignored.
	ReportSHA256 string `json:"report_sha256"`
	// Registries is keyed by registry identity (acquire.RegistryID: scheme, host, port and
	// path, no credential).
	Registries map[string]RegistryFetch `json:"registries,omitempty"`
	// Reassess lists advisory IDs whose stored verdict was reached without the code of a package
	// the advisory may concern, because its fetch failed. Sorted, no duplicates.
	Reassess []string `json:"reassess,omitempty"`
}

// RegistryFetch is one registry's entry in DepFetch.
type RegistryFetch struct {
	// HasServed is set once the registry has served a tarball over the network for this
	// repository. A cache hit never sets it.
	HasServed bool `json:"has_served,omitempty"`
	// HeldRuns counts the cve-watch earnest runs this registry held the cursor on since it last
	// served a package: it served nothing and either answered a transient error or, having served
	// this repository before, failed for a reason other than a missing credential. Only a run
	// that reads from the registry resets it; a run between holds that neither holds nor reads
	// leaves it as it is.
	HeldRuns int `json:"held_runs,omitempty"`
	// FirstHeldAt is when the first of those runs ran; zero while HeldRuns is zero.
	FirstHeldAt time.Time `json:"first_held_at,omitzero"`
}

func (r RegistryFetch) zero() bool {
	return !r.HasServed && r.HeldRuns == 0 && r.FirstHeldAt.IsZero()
}

// normalized is d less its zero registry entries, with Reassess sorted and deduplicated, or nil
// when nothing is left: the form a store writes, so equal records encode to equal bytes.
func (d *DepFetch) normalized() *DepFetch {
	if d == nil {
		return nil
	}
	out := &DepFetch{}
	for k, r := range d.Registries {
		if r.zero() {
			continue
		}
		if out.Registries == nil {
			out.Registries = map[string]RegistryFetch{}
		}
		out.Registries[k] = r
	}
	if len(d.Reassess) > 0 {
		out.Reassess = slices.Compact(slices.Sorted(slices.Values(d.Reassess)))
	}
	if len(out.Registries) == 0 && len(out.Reassess) == 0 {
		return nil
	}
	return out
}

// reportDigest is the ReportSHA256 for report bytes b; nil b (no report.json) is "".
func reportDigest(b []byte) string {
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// encodeDepFetch is d's depfetch.json written beside report bytes reportJSON, or ok=false when d
// is empty and the file is omitted.
func encodeDepFetch(d *DepFetch, reportJSON []byte) (b []byte, ok bool, err error) {
	n := d.normalized()
	if n == nil {
		return nil, false, nil
	}
	n.ReportSHA256 = reportDigest(reportJSON)
	b, err = marshalCanonical(n)
	if err != nil {
		return nil, false, fmt.Errorf("statestore: marshal %s: %w", fileDepFetch, err)
	}
	return b, true, nil
}

// decodeDepFetch reads depfetch.json bytes b found beside report bytes reportJSON. A record
// written beside a different report.json is nil, whatever its other fields hold.
func decodeDepFetch(b, reportJSON []byte) (*DepFetch, error) {
	var bound struct {
		ReportSHA256 string `json:"report_sha256"`
	}
	if err := json.Unmarshal(b, &bound); err != nil {
		return nil, fmt.Errorf("statestore: decode %s: %w", fileDepFetch, err)
	}
	if bound.ReportSHA256 != reportDigest(reportJSON) {
		return nil, nil
	}
	var d DepFetch
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("statestore: decode %s: %w", fileDepFetch, err)
	}
	return &d, nil
}

// mergeDepFetch combines two records after a lost CAS so that neither side's evidence is lost:
// per registry it keeps the larger held count, the earliest first-held time and either side's
// has-served, and it unions the reassess lists.
func mergeDepFetch(base, mine *DepFetch) *DepFetch {
	if base == nil && mine == nil {
		return nil
	}
	out := &DepFetch{}
	for _, d := range []*DepFetch{base, mine} {
		if d == nil {
			continue
		}
		for k, r := range d.Registries {
			if out.Registries == nil {
				out.Registries = map[string]RegistryFetch{}
			}
			cur, seen := out.Registries[k]
			if !seen {
				out.Registries[k] = r
				continue
			}
			cur.HasServed = cur.HasServed || r.HasServed
			cur.HeldRuns = max(cur.HeldRuns, r.HeldRuns)
			if !r.FirstHeldAt.IsZero() && (cur.FirstHeldAt.IsZero() || r.FirstHeldAt.Before(cur.FirstHeldAt)) {
				cur.FirstHeldAt = r.FirstHeldAt
			}
			out.Registries[k] = cur
		}
		out.Reassess = append(out.Reassess, d.Reassess...)
	}
	return out.normalized()
}
