package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// Path-review statuses. A reachable row's call path is only worth showing once a person has read it.
const (
	StatusUnreviewed = "unreviewed"
	StatusReal       = "real"
	StatusArtifact   = "artifact"
	StatusUnclear    = "unclear"
)

var statuses = []string{StatusUnreviewed, StatusReal, StatusArtifact, StatusUnclear}

// PathReview records the call path Assay shows for a reachable row and whether a person has read it.
// Assay's output does not yet distinguish edge kinds (interface or reflection dispatch from a direct
// call), so there is no dynamic_edges count; the review aid marks the likely dynamic hops itself.
type PathReview struct {
	// Path is the call path, entrypoint first, as fully qualified functions.
	Path []string `yaml:"path"`
	Hops int      `yaml:"hops"`
	// PathSHA is pathSHA(Path): the check compares it with the engine's current path.
	PathSHA string `yaml:"path_sha"`
	Status  string `yaml:"status"`
	By      string `yaml:"by,omitempty"`
	Date    string `yaml:"date,omitempty"`
	Note    string `yaml:"note,omitempty"`
	// BoundTo is the analysis the path was read under; required once the status is not unreviewed,
	// and checked against every scan from then on.
	BoundTo *BoundTo `yaml:"bound_to,omitempty"`
}

// reachableRow is a row whose engine_expected verdict asserts a call path.
func (r LedgerRow) reachableRow() bool {
	return r.EngineExpected.Verdict == report.VerdictReachableCandidate
}

// pathSHA is a stable hash of a call path: its functions, in order.
func pathSHA(path []string) string {
	sum := sha256.Sum256([]byte(strings.Join(path, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// newPathReview is the unreviewed record for a path, bound to the analysis it was seeded from.
func newPathReview(path []string, b BoundTo) *PathReview {
	return &PathReview{Path: path, Hops: len(path), PathSHA: pathSHA(path), Status: StatusUnreviewed, BoundTo: &b}
}

// validatePathReview checks a row's review block: the row needs one if and only if it is reachable, the hash and
// hop count must describe the path, a reviewed status needs its reviewer, and only a real path may be
// featured.
func (r LedgerRow) validatePathReview(needReview bool) error {
	pr := r.PathReview
	switch {
	case pr == nil && r.reachableRow() && !needReview:
		return nil
	case pr == nil && r.reachableRow():
		return fmt.Errorf("reachable row has no path_review block")
	case pr == nil && r.Featured:
		return fmt.Errorf("featured: true needs a path_review with status real")
	case pr == nil:
		return nil
	case !r.reachableRow():
		return fmt.Errorf("path_review on a row whose engine_expected is %s, not reachable_candidate", r.EngineExpected)
	case !slices.Contains(statuses, pr.Status):
		return fmt.Errorf("path_review status %q is not one of %s", pr.Status, strings.Join(statuses, ", "))
	case pr.Hops != len(pr.Path):
		return fmt.Errorf("path_review hops %d, but the path has %d", pr.Hops, len(pr.Path))
	case pr.PathSHA != pathSHA(pr.Path):
		return fmt.Errorf("path_review path_sha %s does not hash the path (want %s)", pr.PathSHA, pathSHA(pr.Path))
	case pr.Status != StatusUnreviewed && (pr.By == "" || pr.Date == "" || pr.Note == ""):
		return fmt.Errorf("path_review status %s needs by, date and note", pr.Status)
	case pr.Date != "" && !validDate(pr.Date):
		return fmt.Errorf("path_review date %q is not YYYY-MM-DD", pr.Date)
	case pr.Status != StatusUnreviewed && pr.BoundTo.validate() != nil:
		return fmt.Errorf("path_review status %s: %w", pr.Status, pr.BoundTo.validate())
	case r.Featured && pr.Status != StatusReal:
		return fmt.Errorf("featured: true, but the path_review status is %s: only a real path may be featured", pr.Status)
	}
	return nil
}

func validDate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// A SCIP symbol: "scip-go gomod <module> <version> <descriptor>"; the main module's version is ".".
var scipSymbol = regexp.MustCompile(`^scip-go gomod (\S+) (\S+) (.+)$`)

// qualifiedHop renders a frame's symbol as a fully qualified function: "pkg/path.Func" or
// "pkg/path.Type.Method". A symbol it cannot parse is kept as given. isMain reports a frame in the
// scanned repository's own module.
func qualifiedHop(symbol string) (hop, module string, isMain bool) {
	m := scipSymbol.FindStringSubmatch(symbol)
	if m == nil {
		return symbol, "", false
	}
	desc := strings.TrimSuffix(m[3], ".")
	desc = strings.TrimSuffix(desc, "()")
	slash := strings.LastIndex(desc, "/")
	name := strings.ReplaceAll(desc[slash+1:], "#", ".")
	if slash < 0 {
		return name, m[1], m[2] == "."
	}
	return desc[:slash] + "." + name, m[1], m[2] == "."
}

// callPath is a finding's call path as qualified hops, and the module of the scanned repository when a
// frame names it.
func callPath(f report.AdvisoryFinding) (path []string, mainModule string) {
	for _, fr := range f.Evidence.CallPath {
		hop, mod, isMain := qualifiedHop(fr.Symbol)
		path = append(path, hop)
		if isMain && mainModule == "" {
			mainModule = mod
		}
	}
	return path, mainModule
}

// Hop packages, as the review aid marks them.
const (
	pkgTarget     = "target"
	pkgDependency = "dependency"
	pkgStdlib     = "stdlib"
)

// hopPackage classifies a hop: the Go standard library has no dot in its first path element; the
// scanned repository is the module (or a package under it); anything else is a dependency.
func hopPackage(hop, mainModule string) string {
	first, _, hasSlash := strings.Cut(hop, "/")
	if !hasSlash {
		first, _, _ = strings.Cut(hop, ".")
	}
	switch {
	case mainModule != "" && (strings.HasPrefix(hop, mainModule+"/") || strings.HasPrefix(hop, mainModule+".")):
		return pkgTarget
	case !strings.Contains(first, "."):
		return pkgStdlib
	}
	return pkgDependency
}

// genericMethods are the methods of the standard library's generic interfaces (io.Reader and Writer,
// fmt.Stringer, error, sort.Interface, http.Handler, …): a standard-library hop that is one of them
// is, or sits behind, an interface dispatch.
var genericMethods = []string{
	"Read", "Write", "ReadFrom", "WriteTo", "ReadByte", "WriteByte", "ReadRune", "WriteString", "Close", "Seek", "ReadAt", "WriteAt",
	"Error", "String", "Len", "Less", "Swap", "ServeHTTP", "RoundTrip", "Unwrap", "Is", "As",
	"MarshalJSON", "UnmarshalJSON", "MarshalText", "UnmarshalText", "Scan", "Value",
}

// dynamicHop reports whether the aid should mark hop i as a likely interface dispatch. Assay does not
// record edge kinds, so this is a reading of the path: a standard-library method named for a generic
// interface, or a standard-library hop whose next hop is back in the target or a dependency (the
// standard library can only reach that code through an interface or a function value).
func dynamicHop(path []string, i int, mainModule string) bool {
	if hopPackage(path[i], mainModule) != pkgStdlib {
		return false
	}
	if i+1 < len(path) && hopPackage(path[i+1], mainModule) != pkgStdlib {
		return true
	}
	parts := strings.Split(path[i][strings.LastIndex(path[i], "/")+1:], ".")
	return len(parts) == 3 && slices.Contains(genericMethods, parts[2])
}

// writeReviewAid prints every reachable row of a ledger with its path, one hop per line: the hop's
// package kind, a marker where the hop is a likely interface dispatch, and the review status.
func writeReviewAid(w io.Writer, l Ledger) (reachable, throughInterface int) {
	for _, r := range l.Rows {
		if !r.reachableRow() || r.PathReview == nil {
			continue
		}
		pr := r.PathReview
		reachable++
		dyn := 0
		for i := range pr.Path {
			if dynamicHop(pr.Path, i, l.Header.MainModule) {
				dyn++
			}
		}
		if dyn > 0 {
			throughInterface++
		}
		fmt.Fprintf(w, "%s | %s\n  status: %s", strings.Join(r.Advisory, " "), r.Package, pr.Status)
		if r.Featured {
			fmt.Fprint(w, " (featured)")
		}
		fmt.Fprintf(w, " | %d hops, %d likely interface dispatch | path_sha %s\n", pr.Hops, dyn, pr.PathSHA)
		for i, hop := range pr.Path {
			mark := ""
			if dynamicHop(pr.Path, i, l.Header.MainModule) {
				mark = "  <- likely interface dispatch"
			}
			fmt.Fprintf(w, "  %2d. [%-10s] %s%s\n", i+1, hopPackage(hop, l.Header.MainModule), hop, mark)
		}
		if pr.Note != "" {
			fmt.Fprintf(w, "  review: %s %s: %s\n", pr.By, pr.Date, pr.Note)
		}
	}
	return reachable, throughInterface
}
