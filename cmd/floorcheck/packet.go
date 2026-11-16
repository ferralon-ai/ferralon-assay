package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/build"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ferralon-ai/ferralon-assay/report"
)

// PacketSchema names the packet.json format.
const PacketSchema = "ferralon.floor-packet.v1"

// Packet is everything a reviewer needs to judge one reachable ledger row from the packet alone: the row
// as stored, its call path with a link to the source of each hop, the inputs of the analysis, the
// raw findings and how to run the scan again. It is generated and never read back: the ledger stays the
// record, and a packet decides nothing.
type Packet struct {
	Schema string       `json:"schema"`
	Target PacketTarget `json:"target"`
	// Row is the ledger row as stored.
	Row map[string]any `json:"ledger_row"`
	// Hops is the call path, one entry per frame, entrypoint first.
	Hops   []PacketHop  `json:"call_path"`
	Notes  []string     `json:"notes,omitempty"`
	Inputs PacketInputs `json:"analysis_inputs"`
	// AssayFinding is the report's raw finding(s) for the row; empty when no report was given.
	AssayFinding []json.RawMessage `json:"assay_finding,omitempty"`
	// Govulncheck is the committed comparator evidence for the same advisory and instance.
	Govulncheck []EvidenceFinder `json:"govulncheck"`
	Rerun       []string         `json:"rerun"`

	rowYAML string
}

// PacketTarget names the scanned repository at its pinned commit.
type PacketTarget struct {
	Name        string `json:"name"`
	Repo        string `json:"repo"`
	Tag         string `json:"tag,omitempty"`
	UpstreamSHA string `json:"upstream_sha"`
	MainModule  string `json:"main_module,omitempty"`
}

// PacketHop is one frame of the call path. Permalink is set only where the line is resolved and the
// source host has a stable link for it; Unresolved says why a hop has no file and line.
type PacketHop struct {
	N      int    `json:"n"`
	Symbol string `json:"symbol"`
	// Kind is target, dependency or stdlib. LikelyDispatch marks a likely interface dispatch, as
	// `floorcheck paths` reads it.
	Kind           string `json:"kind"`
	LikelyDispatch bool   `json:"likely_interface_dispatch,omitempty"`
	Module         string `json:"module,omitempty"`
	Version        string `json:"version,omitempty"`
	File           string `json:"file,omitempty"`
	Line           int    `json:"line,omitempty"`
	// Permalink is the line at the pinned commit (target) or exact version (dependency, stdlib).
	Permalink  string `json:"permalink,omitempty"`
	PkgGoDev   string `json:"pkg_go_dev,omitempty"`
	Unresolved string `json:"unresolved,omitempty"`
	// Note says where Assay's report and the source disagree about the hop.
	Note string `json:"note,omitempty"`
	// LinkCheck is the result of `-verify-links`: whether the permalink's line is the hop's declaration.
	LinkCheck string `json:"link_check,omitempty"`

	rawURL string
	name   hopName
}

// PacketInputs are the analysis inputs of the row: what the scan ran with.
type PacketInputs struct {
	// RecordedBy says where the Assay inputs come from: a review's bound_to, the report, or nowhere.
	RecordedBy       string   `json:"recorded_by"`
	AssayVersion     string   `json:"assay_version,omitempty"`
	AssayCommit      string   `json:"assay_commit,omitempty"`
	CorpusRelease    string   `json:"corpus_release"`
	CorpusDigest     string   `json:"corpus_digest"`
	CorpusPolicy     string   `json:"corpus_policy"`
	GoToolchain      string   `json:"go_toolchain"`
	GOOS             string   `json:"goos"`
	GOARCH           string   `json:"goarch"`
	CGO              bool     `json:"cgo"`
	BuildTags        []string `json:"build_tags"`
	TestScope        string   `json:"test_scope"`
	Component        string   `json:"component"`
	Symbol           string   `json:"symbol,omitempty"`
	SymbolConfidence string   `json:"symbol_confidence,omitempty"`
	ScanCommand      string   `json:"scan_command"`
	ComparatorCmd    string   `json:"comparator_command"`
}

// packetInput is what buildPacket assembles a packet from.
type packetInput struct {
	Ledger   Ledger
	Row      LedgerRow
	Target   Target
	Showcase *Showcase
	Evidence *Evidence
	// Report is the raw report.json of the pinned scan, empty when none is given; Meta its meta.json.
	Report []byte
	Meta   Meta
	// GoMod is the target's go.mod at the pinned commit.
	GoMod []byte
	Src   *sources
}

// frameLoc is what the report says about one frame.
type frameLoc struct {
	Module, Version string
	File            string
	Line            int
}

// reportFinding is a finding of the report, raw and decoded.
type reportFinding struct {
	Raw     json.RawMessage
	Finding report.AdvisoryFinding
}

// readReport reads a report's findings and provenance without validating or upgrading it: a packet
// shows what the report says.
func readReport(data []byte) (fs []reportFinding, prov report.Provenance, err error) {
	var doc struct {
		Provenance report.Provenance `json:"provenance"`
		Advisories []json.RawMessage `json:"advisories"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, report.Provenance{}, fmt.Errorf("report: %w", err)
	}
	for i, raw := range doc.Advisories {
		var f report.AdvisoryFinding
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, report.Provenance{}, fmt.Errorf("report: advisory %d: %w", i, err)
		}
		fs = append(fs, reportFinding{Raw: raw, Finding: f})
	}
	return fs, doc.Provenance, nil
}

// rowFindings are the report's findings behind a ledger row: the same package instance and any shared
// advisory id or alias.
func rowFindings(r LedgerRow, all []reportFinding) []reportFinding {
	var out []reportFinding
	for _, rf := range all {
		f := rf.Finding
		if packageInstance(f) != r.Package || f.Advisory.ID == "" {
			continue
		}
		for _, id := range append([]string{f.Advisory.ID}, f.Advisory.Aliases...) {
			if slices.Contains(r.Advisory, id) {
				out = append(out, rf)
				break
			}
		}
	}
	return out
}

// frameLocs reads each frame of a finding's call path as the hop it renders to.
func frameLocs(f report.AdvisoryFinding) map[string]frameLoc {
	out := map[string]frameLoc{}
	for _, fr := range f.Evidence.CallPath {
		hop, _, _ := qualifiedHop(fr.Symbol)
		l := frameLoc{File: fr.File, Line: fr.Line}
		if m := scipSymbol.FindStringSubmatch(fr.Symbol); m != nil && m[2] != "." {
			l.Module, l.Version = m[1], m[2]
		}
		out[hop] = l
	}
	return out
}

// repoRelative cleans a file the report names for a target frame; ok is false for one that is not a
// plain path inside the repository.
func repoRelative(file string) (string, bool) {
	if file == "" || filepath.IsAbs(file) {
		return "", false
	}
	c := filepath.ToSlash(filepath.Clean(file))
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

// splitComponent splits "module@version"; the version is empty when there is none.
func splitComponent(pkg string) (mod, version string) {
	i := strings.LastIndex(pkg, "@")
	if i < 0 {
		return pkg, ""
	}
	return pkg[:i], pkg[i+1:]
}

// buildPacket assembles the packet of one reachable row.
func buildPacket(in packetInput) (Packet, error) {
	r, h := in.Row, in.Ledger.Header
	pr := r.PathReview
	if !r.reachableRow() || pr == nil || len(pr.Path) == 0 {
		return Packet{}, fmt.Errorf("row %s: engine_expected is %s: only a reachable_candidate row has a call path to review", r.Key(), r.EngineExpected)
	}
	rowYAML, err := yaml.Marshal(r)
	if err != nil {
		return Packet{}, err
	}
	var rowMap map[string]any
	if err := yaml.Unmarshal(rowYAML, &rowMap); err != nil {
		return Packet{}, err
	}
	p := Packet{Schema: PacketSchema, Row: rowMap, Govulncheck: []EvidenceFinder{},
		Target: PacketTarget{Name: h.Target, Repo: h.Repo, Tag: h.Tag, UpstreamSHA: h.UpstreamSHA, MainModule: h.MainModule}}

	// The report's findings for the row, and their frames.
	var prov report.Provenance
	frames := map[string]frameLoc{}
	if len(in.Report) > 0 {
		all, pv, err := readReport(in.Report)
		if err != nil {
			return Packet{}, err
		}
		prov = pv
		found := rowFindings(r, all)
		if len(found) == 0 {
			p.Notes = append(p.Notes, "the report holds no finding for this row's advisory and component instance: its scan does not match the ledger")
		}
		for _, rf := range found {
			p.AssayFinding = append(p.AssayFinding, rf.Raw)
			if path, _ := callPath(rf.Finding); pathSHA(path) == pr.PathSHA {
				frames = frameLocs(rf.Finding)
			}
		}
		if len(found) > 0 && len(frames) == 0 {
			p.Notes = append(p.Notes, "the report's call path for this row is not the ledger's path (path_sha "+pr.PathSHA+"): its frames are not used")
		}
	}

	// Which version of each module a hop is in: the report's frames, then the row's component, then
	// the target's go.mod.
	mods := moduleSet{}
	for _, f := range frames {
		mods.add(f.Module, f.Version)
	}
	compMod, compVer := splitComponent(r.Package)
	mods.add(compMod, compVer)
	if len(in.GoMod) > 0 {
		if _, err := mods.readGoMod(in.GoMod); err != nil {
			return Packet{}, fmt.Errorf("target go.mod: %w", err)
		}
	}
	src := in.Src
	if src == nil {
		src = &sources{}
	}
	src.MainModule = h.MainModule
	src.Context = pinnedContext(h)

	exists := func(pkg string) bool {
		if src.Repo == "" && src.Modcache == "" && src.GOROOT == "" {
			return plausiblePackage(pkg)
		}
		return src.packageExists(pkg, mods)
	}
	for i := range pr.Path {
		p.Hops = append(p.Hops, resolveHop(i, pr.Path, h, src, mods, frames, exists))
	}
	p.Notes = append(p.Notes, attributionNotes(r, p.Hops)...)
	p.Inputs = packetInputs(in, prov)
	if in.Evidence != nil {
		p.Govulncheck = govulncheckFor(*in.Evidence, r, p.Hops)
	}
	p.Rerun = rerunCommands(in, p.Inputs)
	p.rowYAML = string(storedRow(r))
	return p, nil
}

// resolveHop finds a hop's source: its module and version, the file and line of its declaration, and the
// link that shows it. A hop it cannot place says why and carries no file or link: nothing is guessed.
func resolveHop(i int, path []string, h LedgerHeader, src *sources, mods moduleSet, frames map[string]frameLoc, exists func(string) bool) PacketHop {
	hop := path[i]
	ph := PacketHop{N: i + 1, Symbol: hop, Kind: hopPackage(hop, h.MainModule), LikelyDispatch: dynamicHop(path, i, h.MainModule)}
	name, ok := splitHop(hop, exists)
	if !ok {
		ph.Unresolved = "the hop does not split into a package and a function"
		return ph
	}
	ph.name = name
	var modPath, version string
	switch ph.Kind {
	case pkgDependency:
		var found bool
		if modPath, version, found = mods.owner(name.Pkg); !found {
			ph.Unresolved = "no module for the package: its version is in neither the report nor the target's go.mod"
			return ph
		}
		ph.Module, ph.Version = modPath, version
		ph.PkgGoDev = fmt.Sprintf("https://pkg.go.dev/%s@%s#%s", name.Pkg, version, name.symbol())
	case pkgStdlib:
		ph.Module, ph.Version = "std", "go"+strings.TrimPrefix(h.GoVersion, "go")
		ph.PkgGoDev = fmt.Sprintf("https://pkg.go.dev/%s@%s#%s", name.Pkg, ph.Version, name.symbol())
	}
	pos, why := src.locate(name, mods)
	loc, hasLoc := frames[hop]
	rel, relOK := repoRelative(loc.File)
	switch {
	case why == "" && ph.Kind == pkgTarget && relOK && loc.Line > 0 && (rel != pos.File || loc.Line != pos.Line):
		// the report and the source disagree: the declaration in the source is what a reviewer can check
		ph.File, ph.Line = pos.File, pos.Line
		ph.Note = fmt.Sprintf("Assay's report says %s:%d, the source declares it at %s:%d: the source is shown", rel, loc.Line, pos.File, pos.Line)
	case why == "":
		ph.File, ph.Line = pos.File, pos.Line
	case ph.Kind == pkgTarget && hasLoc && relOK && loc.Line > 0:
		ph.File, ph.Line = rel, loc.Line
	default:
		ph.Unresolved = why
		return ph
	}
	var link sourceLink
	switch ph.Kind {
	case pkgTarget:
		link = githubLink(h.Repo, h.UpstreamSHA, ph.File, ph.Line)
	case pkgDependency:
		link = depLink(modPath, version, ph.File, ph.Line)
		if link.URL == "" {
			ph.Unresolved = fmt.Sprintf("%s:%d is within %s@%s; its host has no stable line link", ph.File, ph.Line, modPath, version)
		}
	case pkgStdlib:
		link = stdlibLink(h.GoVersion, ph.File, ph.Line)
	}
	ph.Permalink, ph.rawURL = link.URL, link.RawURL
	return ph
}

// pinnedContext is the build the ledger's header pins.
func pinnedContext(h LedgerHeader) build.Context {
	c := build.Default
	c.GOOS, c.GOARCH, c.CgoEnabled = h.GOOS, h.GOARCH, h.CGO
	c.BuildTags = h.BuildTags
	c.UseAllFiles = false
	return c
}

// attributionNotes flags a path that does not end in the row's component: the row may be attributed
// to the wrong instance of a module (for one present in two major versions, say).
func attributionNotes(r LedgerRow, hops []PacketHop) []string {
	if len(hops) == 0 {
		return nil
	}
	mod, _ := splitComponent(r.Package)
	last := hops[len(hops)-1]
	pkg := last.name.Pkg
	if pkg == "" {
		return nil
	}
	// a hop's module is the longest module path that is a prefix of its package, so dep/v2 is not dep
	inComponent := pkg == mod || strings.HasPrefix(pkg, mod+"/") || ((mod == "stdlib" || mod == "toolchain") && stdlibPackage(pkg))
	if last.Module != "" && last.Module != "std" {
		inComponent = last.Module == mod
	}
	if inComponent {
		return nil
	}
	return []string{fmt.Sprintf("ATTRIBUTION MISMATCH: the call path ends in %s, which is not part of the row's component %s. The row may be attributed to the wrong instance of the module (one present in two major versions, for instance); read the path against the module it actually ends in.", pkg, r.Package)}
}

// packetInputs gathers the analysis inputs: a review's bound_to when the ledger has one, the report
// and its meta.json otherwise, and the ledger header and the showcase pins for the rest.
func packetInputs(in packetInput, prov report.Provenance) PacketInputs {
	h, r := in.Ledger.Header, in.Row
	pin := PacketInputs{RecordedBy: "not recorded in the ledger (the row is unreviewed) or a report: the nightly run's meta.json holds the scanner commit",
		CorpusRelease: h.CorpusRelease, CorpusDigest: strings.TrimPrefix(h.CorpusRelease, "corpus-") + " (the release tag's leading digest of the signed manifest's corpus_digest)",
		GoToolchain: "go" + strings.TrimPrefix(h.GoVersion, "go"), GOOS: h.GOOS, GOARCH: h.GOARCH, CGO: h.CGO, BuildTags: h.BuildTags,
		TestScope: h.TestScope, Component: r.Package, ComparatorCmd: ""}
	if pin.BuildTags == nil {
		pin.BuildTags = []string{}
	}
	if in.Showcase != nil {
		pin.CorpusPolicy = in.Showcase.Policy
	}
	var b *BoundTo
	switch {
	case r.PathReview != nil && r.PathReview.Status != StatusUnreviewed && r.PathReview.BoundTo != nil:
		b = r.PathReview.BoundTo
	case r.Adjudicated.reviewed() && r.Adjudicated.BoundTo != nil:
		b = r.Adjudicated.BoundTo
	}
	switch {
	case b != nil:
		pin.RecordedBy = "the review's bound_to in the ledger row"
		pin.AssayVersion, pin.AssayCommit = b.Analysis.AssayVersion, b.Analysis.AssayCommit
		pin.CorpusRelease, pin.Symbol, pin.SymbolConfidence = b.Analysis.CorpusRelease, b.Symbol, b.SymbolConfidence
		pin.GoToolchain = "go" + strings.TrimPrefix(b.Analysis.GoVersion, "go")
	case len(in.Report) > 0:
		pin.RecordedBy = "the scan's report.json and meta.json"
		pin.AssayVersion, pin.AssayCommit = prov.AnalyzerVersion, in.Meta.AssayCommit
		if prov.Intel != nil && prov.Intel.CorpusDigest != "" {
			pin.CorpusDigest = prov.Intel.CorpusDigest
		}
		if in.Meta.CorpusRelease != "" {
			pin.CorpusRelease = in.Meta.CorpusRelease
		}
	}
	if pr := r.PathReview; pr != nil && pin.Symbol == "" && len(pr.Path) > 0 {
		pin.Symbol = pr.Path[len(pr.Path)-1]
	}
	if in.Evidence != nil {
		pin.ComparatorCmd = in.Evidence.Comparator.Command
	}
	pin.ScanCommand = scanCommand(in, pin)
	return pin
}

// scanCommand is the scan as floor/scan.sh runs it on the pinned scan job, with its environment.
func scanCommand(in packetInput, pin PacketInputs) string {
	h := in.Ledger.Header
	cgo := "0"
	if h.CGO {
		cgo = "1"
	}
	var env strings.Builder
	fmt.Fprintf(&env, "GOTOOLCHAIN=go%s GOOS=%s GOARCH=%s CGO_ENABLED=%s ", strings.TrimPrefix(h.GoVersion, "go"), h.GOOS, h.GOARCH, cgo)
	fmt.Fprintf(&env, "ASSAY_ISSUE=0 ASSAY_PR_COMMENT=0 ASSAY_CODE_SCANNING=0 ")
	return strings.TrimSpace(env.String()) + fmt.Sprintf(" ferralon-assay baseline -target src -out out -subject-repo %s -revision %s -commit %s"+
		" -advisory-corpus corpus/%s.jsonl.gz -advisory-corpus-policy %s -advisory-signals corpus/signals.json.gz -require-advisory-corpus -scan-timeout 22m",
		h.Repo, h.UpstreamSHA, h.UpstreamSHA, pin.CorpusPolicy, pin.CorpusPolicy)
}

// govulncheckFor picks the comparator's entries for the row's advisory on its component instance, and
// on the module the path actually ends in when that is another one.
func govulncheckFor(ev Evidence, r LedgerRow, hops []PacketHop) []EvidenceFinder {
	mod, ver := splitComponent(r.Package)
	type inst struct{ mod, ver string }
	want := []inst{{mod, ver}}
	if n := len(hops); n > 0 && hops[n-1].Module != "" && hops[n-1].Module != mod {
		want = append(want, inst{hops[n-1].Module, hops[n-1].Version})
	}
	out := []EvidenceFinder{}
	for _, f := range ev.Findings {
		ids := append([]string{f.OSV}, f.Aliases...)
		if !slices.ContainsFunc(ids, func(id string) bool { return slices.Contains(r.Advisory, id) }) {
			continue
		}
		if slices.Contains(want, inst{f.Module, f.Version}) {
			out = append(out, f)
		}
	}
	return out
}

// rerunCommands is the minimal run that reproduces one row on a clean machine.
func rerunCommands(in packetInput, pin PacketInputs) []string {
	h, r := in.Ledger.Header, in.Row
	mod, ver := splitComponent(r.Package)
	assay := "<scanner commit>"
	if pin.AssayCommit != "" {
		assay = pin.AssayCommit
	}
	id := r.Advisory[0]
	for _, a := range r.Advisory {
		if strings.HasPrefix(a, "CVE-") {
			id = a
			break
		}
	}
	filter := fmt.Sprintf(`jq '.advisories[] | select(.package.name=="%s" and .package.version=="%s" and ([.advisory.id] + (.advisory.aliases // []) | index("%s")))' out/report.json`, mod, ver, id)
	cmds := []string{
		"# 1. the target at the pinned commit",
		fmt.Sprintf("git clone https://github.com/%s src && git -C src checkout %s", h.Repo, h.UpstreamSHA),
		"# 2. the module cache the analysis reads, under the pinned toolchain",
		fmt.Sprintf("(cd src && GOTOOLCHAIN=go%s go mod download)", strings.TrimPrefix(h.GoVersion, "go")),
		"# 3. the scanner at the commit the analysis ran with",
		"git clone https://github.com/ferralon-ai/ferralon-assay assay && git -C assay checkout " + assay,
		"(cd assay && CGO_ENABLED=0 go build -o ../bin/ferralon-assay ./cmd/ferralon-assay && CGO_ENABLED=0 go build -o ../bin/assay-plugin-go ./cmd/assay-plugin-go)",
		"# 4. the signed corpus release, verified as the floor run verifies it (needs cosign and gh)",
		fmt.Sprintf("(cd assay && DEST=../corpus CORPUS_REF=%s CORPUS_POLICY=%s bash scripts/fetch-corpus-bundle.sh)", h.CorpusRelease, pin.CorpusPolicy),
		"# 5. the scan",
		"export PATH=\"$PWD/bin:$PATH\"",
		pin.ScanCommand,
		"# 6. this row's finding",
		filter,
	}
	if pin.ComparatorCmd != "" {
		cmds = append(cmds, "# 7. the comparator, inside src (govulncheck "+in.Ledger.Header.Comparator.Version+")", "(cd src && "+pin.ComparatorCmd+")")
	}
	cmds = append(cmds, "# 8. this packet again, from the scan's report",
		fmt.Sprintf("floorcheck packet -target %s -row %q -report out/report.json -source src", h.Target, r.Key()))
	return cmds
}

// selectRows picks the reachable rows a -row selector names: a full row key, or any advisory id of an
// alias set. A selector that names no reachable row, or several, is refused with the keys it found.
func selectRows(l Ledger, sel string) ([]LedgerRow, error) {
	var named, reach []LedgerRow
	for _, r := range l.Rows {
		if r.Key() == sel || slices.Contains(r.Advisory, sel) {
			named = append(named, r)
			if r.reachableRow() {
				reach = append(reach, r)
			}
		}
	}
	switch {
	case len(named) == 0:
		return nil, fmt.Errorf("no ledger row has the key or advisory %q", sel)
	case len(reach) == 0:
		return nil, fmt.Errorf("%q names %d row(s), none with a reachable_candidate verdict (the packet is the review of a call path): %s", sel, len(named), rowKeys(named))
	case len(reach) > 1:
		return nil, fmt.Errorf("%q names %d reachable rows; give one full key: %s", sel, len(reach), rowKeys(reach))
	}
	return reach, nil
}

func rowKeys(rs []LedgerRow) string {
	keys := make([]string, len(rs))
	for i, r := range rs {
		keys[i] = r.Key()
	}
	return strings.Join(keys, "; ")
}

// packetDirName names a row's packet directory: the target, the first CVE (or first id) and the
// component instance.
func packetDirName(r LedgerRow, target string) string {
	id := r.Advisory[0]
	for _, a := range r.Advisory {
		if strings.HasPrefix(a, "CVE-") {
			id = a
			break
		}
	}
	return target + "-" + id + "-" + unsafeName.ReplaceAllString(r.Package, "-")
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9.]+`)

// verifyLinks fetches each permalink's file and records on the hop whether the linked line declares the
// hop's function. fetch returns a file's bytes by raw URL; a file is fetched once.
func verifyLinks(hops []PacketHop, fetch func(url string) ([]byte, error)) {
	cache := map[string][]byte{}
	failed := map[string]error{}
	for i := range hops {
		h := &hops[i]
		if h.Permalink == "" || h.rawURL == "" {
			continue
		}
		body, ok := cache[h.rawURL]
		if !ok && failed[h.rawURL] == nil {
			b, err := fetch(h.rawURL)
			if err != nil {
				failed[h.rawURL] = err
			} else {
				cache[h.rawURL], body = b, b
			}
		}
		switch {
		case failed[h.rawURL] != nil:
			h.LinkCheck = "NOT VERIFIED: " + failed[h.rawURL].Error()
		case declaresAt(body, h.Line, h.name):
			h.LinkCheck = "verified: the linked line declares " + h.name.symbol()
		default:
			h.LinkCheck = fmt.Sprintf("FAILED: line %d of the linked file does not declare %s", h.Line, h.name.symbol())
		}
	}
}

// declaresAt reports whether line (1-based) of a Go file is the declaration of the named function or
// method.
func declaresAt(body []byte, line int, n hopName) bool {
	lines := bytes.Split(body, []byte("\n"))
	if line < 1 || line > len(lines) {
		return false
	}
	text := string(lines[line-1])
	pat := `^func\s+`
	if n.Recv != "" {
		pat += `\(\s*\w*\s*\*?\s*` + regexp.QuoteMeta(n.Recv) + `(\[[^\]]*\])?\s*\)\s*`
	}
	pat += regexp.QuoteMeta(n.Func) + `\b`
	ok, _ := regexp.MatchString(pat, text)
	return ok
}

// httpFetch reads a URL's body.
func httpFetch(url string) ([]byte, error) {
	c := http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// runPacket implements `floorcheck packet`: a review and reproduction packet per reachable ledger row.
func runPacket(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("packet", flag.ContinueOnError)
	fs.SetOutput(stderr)
	targetsPath := fs.String("targets", "floor/targets.json", "the targets file")
	name := fs.String("target", "", "the showcase target's name (required)")
	row := fs.String("row", "", "the row: its full key, or an advisory id of its alias set")
	featured := fs.Bool("featured", false, "every featured row of the target")
	out := fs.String("out", "", "where to write the packets (default floor/expect/packets, beside the targets file)")
	reportPath := fs.String("report", "", "the pinned scan's report.json: adds Assay's raw finding and its frames' file and line")
	metaPath := fs.String("meta", "", "the scan's meta.json (default: beside -report)")
	source := fs.String("source", "", "a checkout of the target at the pinned commit: resolves each target hop's file and line, and the go.mod versions")
	modcache := fs.String("modcache", "", "a Go module cache holding the dependencies (default: go env GOMODCACHE)")
	goroot := fs.String("goroot", "", "the pinned toolchain's GOROOT (default: the one `go env GOROOT` names under GOTOOLCHAIN=go<go_version>)")
	verify := fs.Bool("verify-links", false, "fetch each permalink's file and check that the line declares the hop's function (needs the network)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "floorcheck packet:", err)
		return 2
	}
	if *name == "" || (*row == "") == !*featured {
		return fail(fmt.Errorf("-target and exactly one of -row and -featured are required"))
	}
	t, err := loadTargets(*targetsPath)
	if err != nil {
		return fail(err)
	}
	var tg *Target
	for _, c := range showcaseTargets(t) {
		if c.Name() == *name {
			c := c
			tg = &c
		}
	}
	if tg == nil {
		return fail(fmt.Errorf("no showcase target %q", *name))
	}
	l, err := loadLedger(ledgerPath(*targetsPath, *name))
	if err != nil {
		return fail(err)
	}
	var rows []LedgerRow
	if *featured {
		for _, r := range l.Rows {
			if r.Featured && r.reachableRow() {
				rows = append(rows, r)
			}
		}
		if len(rows) == 0 {
			return fail(fmt.Errorf("%s has no featured reachable row", *name))
		}
	} else if rows, err = selectRows(l, *row); err != nil {
		return fail(err)
	}
	dest := *out
	if dest == "" {
		dest = filepath.Join(filepath.Dir(*targetsPath), "expect", "packets")
	}
	in := packetInput{Ledger: l, Target: *tg, Showcase: t.Showcase}
	if ev, err := loadEvidence(filepath.Join(filepath.Dir(ledgerPath(*targetsPath, *name)), l.Header.Comparator.Evidence)); err == nil {
		in.Evidence = &ev
	} else {
		fmt.Fprintln(stderr, "floorcheck packet: comparator evidence:", err)
	}
	if *reportPath != "" {
		if in.Report, err = os.ReadFile(*reportPath); err != nil {
			return fail(err)
		}
		mp := *metaPath
		if mp == "" {
			mp = filepath.Join(filepath.Dir(*reportPath), "meta.json")
		}
		if data, err := os.ReadFile(mp); err == nil {
			if err := json.Unmarshal(data, &in.Meta); err != nil {
				return fail(fmt.Errorf("%s: %w", mp, err))
			}
		}
	}
	src := &sources{Repo: *source, Modcache: *modcache, GOROOT: *goroot}
	if src.Modcache == "" {
		src.Modcache = goEnv("GOMODCACHE", "")
	}
	if src.GOROOT == "" {
		src.GOROOT = pinnedGOROOT(l.Header.GoVersion)
	}
	if *source != "" {
		if err := checkSourceCommit(*source, l.Header.UpstreamSHA); err != nil {
			return fail(err)
		}
		in.GoMod = readFileOrEmpty(filepath.Join(*source, "go.mod"))
	}
	in.Src = src
	for _, r := range rows {
		in.Row = r
		p, err := buildPacket(in)
		if err != nil {
			return fail(err)
		}
		if *verify {
			verifyLinks(p.Hops, httpFetch)
		}
		dir := filepath.Join(dest, packetDirName(r, *name))
		if err := writePacket(dir, p); err != nil {
			return fail(err)
		}
		unresolved := 0
		for _, h := range p.Hops {
			if h.Permalink == "" {
				unresolved++
			}
		}
		fmt.Fprintf(stdout, "packet: %s: %d hops, %d without a permalink\n", dir, len(p.Hops), unresolved)
	}
	return 0
}

// writePacket writes packet.md and packet.json into dir.
func writePacket(dir string, p Packet) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	js, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFiles(map[string][]byte{
		filepath.Join(dir, "packet.json"): append(js, '\n'),
		filepath.Join(dir, "packet.md"):   []byte(p.markdown()),
	})
}

// checkSourceCommit refuses a source checkout that is not at the pinned commit.
func checkSourceCommit(dir, sha string) error {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return fmt.Errorf("-source %s: not a git checkout: %v", dir, err)
	}
	if got := strings.TrimSpace(string(out)); got != sha {
		return fmt.Errorf("-source %s is at %s, not the pinned commit %s", dir, got, sha)
	}
	return nil
}

// loadEvidence reads the committed comparator evidence.
func loadEvidence(path string) (Evidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Evidence{}, err
	}
	var ev Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		return Evidence{}, fmt.Errorf("%s: %w", path, err)
	}
	return ev, nil
}

// goEnv reads a `go env` variable, or def when go cannot say.
func goEnv(key, def string, env ...string) string {
	cmd := exec.Command("go", "env", key)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return def
	}
	return strings.TrimSpace(string(out))
}

// pinnedGOROOT is the GOROOT of the pinned toolchain when this machine already has it (the go command
// selects it by GOTOOLCHAIN); empty otherwise, which leaves standard-library hops unresolved.
func pinnedGOROOT(goVersion string) string {
	v := "go" + strings.TrimPrefix(goVersion, "go")
	root := goEnv("GOROOT", "", "GOTOOLCHAIN="+v+"+path")
	first, _, _ := strings.Cut(string(readFileOrEmpty(filepath.Join(root, "VERSION"))), "\n")
	if root == "" || first != v {
		return ""
	}
	return root
}

// storedRow is the row as the ledger writes it: struct order, two-space indent.
func storedRow(r LedgerRow) []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode([]LedgerRow{r})
	_ = enc.Close()
	return buf.Bytes()
}
