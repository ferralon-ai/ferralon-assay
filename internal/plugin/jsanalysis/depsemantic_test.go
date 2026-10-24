package jsanalysis

import (
	"cmp"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// semPkg is one package a pnpm or yarn classic fixture lock pins.
type semPkg struct {
	name, version string
	// deps are the package's lock edges: name → lock value (pnpm) or range (yarn).
	deps map[string]string
	// files are the tarball's package files; a manifest and an idle index.js are added.
	files map[string]string
	// key overrides the pnpm snapshot key (a peer variant).
	key string
	// res overrides the pnpm resolution flow map.
	res string
	// descs override the yarn descriptors; resolved and integrity override the yarn fields
	// ("-" drops the field).
	descs               []string
	resolved, integrity string
	tgz                 []byte
}

func sp(name, version string, deps map[string]string, files map[string]string) *semPkg {
	return &semPkg{name: name, version: version, deps: deps, files: files}
}

func (p *semPkg) build(t *testing.T) []byte {
	t.Helper()
	if p.tgz == nil {
		m := map[string]string{
			"package.json": fmt.Sprintf(`{"name":%q,"version":%q,"main":"index.js"}`, p.name, p.version),
			"index.js":     "exports.run = function run() {};\n",
		}
		for k, v := range p.files {
			m[k] = v
		}
		p.tgz = buildTgz(t, m)
	}
	return p.tgz
}

func (p *semPkg) ref(t *testing.T) artifactcache.Ref {
	return artifactcache.Ref{PURL: makePURL(p.name, p.version), Digest: mapIntegrity(sri(p.build(t)))}
}

func semStore(t *testing.T, pkgs ...*semPkg) artifactcache.Store {
	m := map[artifactcache.Ref][]byte{}
	for _, p := range pkgs {
		m[p.ref(t)] = p.build(t)
	}
	return artifactcache.NewMemStore(m)
}

func yq(s string) string { return "'" + s + "'" }

// pnpmLockText writes a pnpm lock of version ver ("5.4", "6.0", "9.0"). importers maps an
// importer directory to its dependencies (name → lock value).
func pnpmLockText(t *testing.T, ver string, importers map[string]map[string]string, pkgs ...*semPkg) string {
	t.Helper()
	var b strings.Builder
	q := "'" + ver + "'"
	if ver == "5.4" {
		q = ver
	}
	fmt.Fprintf(&b, "lockfileVersion: %s\n\n", q)
	deps := func(indent string, m map[string]string, v6style bool) {
		for _, n := range semKeys(m) {
			if v6style {
				fmt.Fprintf(&b, "%s%s:\n%s  specifier: %s\n%s  version: %s\n", indent, yq(n), indent, yq(m[n]), indent, yq(m[n]))
			} else {
				fmt.Fprintf(&b, "%s%s: %s\n", indent, yq(n), yq(m[n]))
			}
		}
	}
	if ver == "5.4" && len(importers) == 1 && importers["."] != nil {
		b.WriteString("specifiers:\n")
		deps("  ", importers["."], false)
		if len(importers["."]) > 0 {
			b.WriteString("\ndependencies:\n")
			deps("  ", importers["."], false)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("importers:\n\n")
		for _, dir := range semKeys(importers) {
			if len(importers[dir]) == 0 {
				fmt.Fprintf(&b, "  %s: {}\n\n", yq(dir))
				continue
			}
			fmt.Fprintf(&b, "  %s:\n    dependencies:\n", yq(dir))
			deps("      ", importers[dir], ver != "5.4")
			b.WriteString("\n")
		}
	}
	key := func(p *semPkg) string {
		switch ver {
		case "5.4":
			return "/" + p.name + "/" + p.version
		case "6.0":
			return "/" + p.name + "@" + p.version
		}
		return p.name + "@" + p.version
	}
	res := func(p *semPkg) string {
		if p.res != "" {
			return p.res
		}
		return "{integrity: " + sri(p.build(t)) + "}"
	}
	b.WriteString("packages:\n\n")
	seen := map[string]bool{}
	for _, p := range pkgs {
		k := key(p)
		if ver != "9.0" && p.key != "" {
			k = p.key
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		fmt.Fprintf(&b, "  %s:\n    resolution: %s\n", yq(k), res(p))
		if ver != "9.0" && len(p.deps) > 0 {
			b.WriteString("    dependencies:\n")
			deps("      ", p.deps, false)
		}
		b.WriteString("\n")
	}
	if ver == "9.0" {
		b.WriteString("snapshots:\n\n")
		for _, p := range pkgs {
			k := key(p)
			if p.key != "" {
				k = p.key
			}
			if len(p.deps) == 0 {
				fmt.Fprintf(&b, "  %s: {}\n\n", yq(k))
				continue
			}
			fmt.Fprintf(&b, "  %s:\n    dependencies:\n", yq(k))
			deps("      ", p.deps, false)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// pnpmImporterDep is one importer entry pnpmLockImporters writes: the field pnpm records it in,
// the specifier copied from the manifest and the version it resolves to.
type pnpmImporterDep struct{ field, name, spec, version string }

// pnpmLockImporters is a 9.0 pnpmLockText with each importer's entries given in full, for
// fixtures whose specifier differs from the resolved version or whose entries sit outside
// dependencies.
func pnpmLockImporters(t *testing.T, importers map[string][]pnpmImporterDep, pkgs ...*semPkg) string {
	t.Helper()
	_, rest, _ := strings.Cut(pnpmLockText(t, "9.0", nil, pkgs...), "packages:\n\n")
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\n\nimporters:\n\n")
	for _, dir := range semKeys(importers) {
		if len(importers[dir]) == 0 {
			fmt.Fprintf(&b, "  %s: {}\n\n", yq(dir))
			continue
		}
		fmt.Fprintf(&b, "  %s:\n", yq(dir))
		for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			head := false
			for _, d := range importers[dir] {
				if d.field != field {
					continue
				}
				if !head {
					fmt.Fprintf(&b, "    %s:\n", field)
					head = true
				}
				fmt.Fprintf(&b, "      %s:\n        specifier: %s\n        version: %s\n", yq(d.name), yq(d.spec), yq(d.version))
			}
		}
		b.WriteString("\n")
	}
	return b.String() + "packages:\n\n" + rest
}

// semJoin returns fields as further members of a JSON object, or nothing.
func semJoin(fields string) string {
	if fields == "" {
		return ""
	}
	return "," + fields
}

// pnpmImporterLines returns a lock edit adding lines at the head of importer dir's entry, as
// pnpmLockImporters writes it.
func pnpmImporterLines(lines string) func(lock, dir string) string {
	return func(lock, dir string) string {
		head := "  " + yq(dir) + ":\n"
		return strings.Replace(lock, head, head+lines, 1)
	}
}

// yarnLockText writes a yarn classic lock pinning pkgs.
func yarnLockText(t *testing.T, pkgs ...*semPkg) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n")
	for _, p := range pkgs {
		descs := p.descs
		if descs == nil {
			descs = []string{p.name + "@" + p.version}
		}
		quoted := make([]string, len(descs))
		for i, d := range descs {
			quoted[i] = fmt.Sprintf("%q", d)
		}
		fmt.Fprintf(&b, "%s:\n  version %q\n", strings.Join(quoted, ", "), p.version)
		resolved := p.resolved
		if resolved == "" {
			resolved = "https://registry.yarnpkg.com/" + p.name + "/-/" + p.name + "-" + p.version + ".tgz"
		}
		if resolved != "-" {
			fmt.Fprintf(&b, "  resolved %q\n", resolved)
		}
		integrity := p.integrity
		if integrity == "" {
			integrity = sri(p.build(t))
		}
		if integrity != "-" {
			fmt.Fprintf(&b, "  integrity %s\n", integrity)
		}
		if len(p.deps) > 0 {
			b.WriteString("  dependencies:\n")
			for _, n := range semKeys(p.deps) {
				fmt.Fprintf(&b, "    %s %q\n", n, p.deps[n])
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// manifestWith returns a package.json declaring deps (name → range).
func manifestWith(name string, deps map[string]string, extra string) string {
	d, _ := json.Marshal(deps)
	if deps == nil {
		d = []byte("{}")
	}
	return fmt.Sprintf(`{"name":%q,"version":"1.0.0","dependencies":%s%s}`, name, d, extra)
}

func reaches(cg plugin.CallGraphResult, name, version string) bool {
	want := scipManager + " " + name + " " + version + " "
	return slices.ContainsFunc(cg.Edges, func(e plugin.CallEdge) bool { return strings.HasPrefix(e.Callee.SCIP, want) })
}

func runWide(cg plugin.CallGraphResult) bool {
	return hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage)
}

func hasScopedTo(p plugin.Partiality, pkg, target string) bool {
	return slices.ContainsFunc(p.Scoped, func(s plugin.ScopedReason) bool {
		return s.Reason == plugin.PartialReasonUninspectablePackage && s.Package == pkg && slices.Equal(s.Targets, []string{target})
	})
}

const (
	callsQ       = "const q = require('q');\nexports.run = function run() { q.go(); };\n"
	qGo          = "exports.go = function go() {};\n"
	runsP        = "const p = require('p');\np.run();\n"
	pnpmLockFile = "pnpm-lock.yaml"
	yarnLockFile = "yarn.lock"
)

// semProgram writes a first-party program with a lock and extra files.
func semProgram(t *testing.T, lockName, lock string, files map[string]string) string {
	t.Helper()
	m := map[string]string{lockName: lock, "index.js": runsP}
	for k, v := range files {
		m[k] = v
	}
	if _, ok := m["package.json"]; !ok {
		m["package.json"] = manifestWith("app", map[string]string{"p": "1.0.0"}, "")
	}
	return writeProgram(t, m)
}

// pqFixture is the common shape: the program loads p, p calls q.
func pqFixture(t *testing.T, ver string, qs ...*semPkg) (string, artifactcache.Store) {
	t.Helper()
	p := sp("p", "1.0.0", map[string]string{"q": qs[0].version}, map[string]string{"index.js": callsQ})
	all := append([]*semPkg{p}, qs...)
	lock := pnpmLockText(t, ver, map[string]map[string]string{".": {"p": "1.0.0"}}, all...)
	return semProgram(t, pnpmLockFile, lock, nil), semStore(t, all...)
}

func qPkg(version string) *semPkg {
	return sp("q", version, nil, map[string]string{"index.js": qGo})
}

// TestSemantic_P1PlainPnpm9: a plain pnpm 9 project reads both packages and links first-party
// code through p into q.
func TestSemantic_P1PlainPnpm9(t *testing.T) {
	dir, store := pqFixture(t, "9.0", qPkg("1.0.0"))
	cg := semRun(t, dir, store)
	if !reaches(cg, "p", "1.0.0") || !reaches(cg, "q", "1.0.0") {
		t.Errorf("p and q must be read and linked; edges %+v", cg.Edges)
	}
	if runWide(cg) {
		t.Errorf("read packages withhold nothing run-wide; got %+v", cg.Partiality)
	}
}

// TestSemantic_P2PlainYarnClassic: a multi-descriptor block and an npm: alias both resolve.
func TestSemantic_P2PlainYarnClassic(t *testing.T) {
	q := qPkg("1.0.0")
	q.descs = []string{"q-alias@npm:q@1.0.0"}
	p := sp("p", "1.0.0", map[string]string{"q-alias": "npm:q@1.0.0"}, map[string]string{
		"index.js": "const q = require('q-alias');\nexports.run = function run() { q.go(); };\n",
	})
	p.descs = []string{"p@^1.0.0", "p@1.0.0"}
	dir := semProgram(t, yarnLockFile, yarnLockText(t, p, q), nil)
	cg := semRun(t, dir, semStore(t, p, q))
	if !reaches(cg, "p", "1.0.0") || !reaches(cg, "q", "1.0.0") {
		t.Errorf("p and the aliased q must be read and linked; edges %+v", cg.Edges)
	}
	if runWide(cg) {
		t.Errorf("got %+v", cg.Partiality)
	}
}

// TestSemantic_P3PnpmWorkspace: a pnpm 9 workspace with a link: member and gitea-shaped
// settings. The member's own importer resolves its dependency.
func TestSemantic_P3PnpmWorkspace(t *testing.T) {
	p := sp("p", "1.0.0", nil, nil)
	lock := pnpmLockImporters(t, map[string][]pnpmImporterDep{
		".":            {{"dependencies", "lib", "workspace:*", "link:packages/lib"}},
		"packages/lib": {{"dependencies", "p", "1.0.0", "1.0.0"}},
	}, p)
	lock = strings.Replace(lock, "importers:", "settings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:", 1)
	dir := semProgram(t, pnpmLockFile, lock, map[string]string{
		"package.json":              manifestWith("app", map[string]string{"lib": "workspace:*"}, ""),
		"index.js":                  "require('lib');\n",
		"pnpm-workspace.yaml":       "packages:\n  - 'packages/*'\nonlyBuiltDependencies:\n  - esbuild\nhoistPattern:\n  - '*'\n",
		"packages/lib/package.json": manifestWith("lib", map[string]string{"p": "1.0.0"}, ""),
		"packages/lib/index.js":     runsP,
	})
	cg := semRun(t, dir, semStore(t, p))
	if !reaches(cg, "p", "1.0.0") {
		t.Errorf("the member loads p through its own importer; edges %+v", cg.Edges)
	}
	if runWide(cg) {
		t.Errorf("a link: entry and accepted settings withhold nothing run-wide; got %+v", cg.Partiality)
	}
}

// pnpmRunWide asserts a pnpm fixture with the lock edited by edit and extra files withholds.
func pnpmVariant(t *testing.T, edit func(string) string, files map[string]string) plugin.CallGraphResult {
	t.Helper()
	return pnpmVariantQ(t, qPkg("1.0.0"), edit, files)
}

// pnpmVariantQ is pnpmVariant with q's tarball as given.
func pnpmVariantQ(t *testing.T, q *semPkg, edit func(string) string, files map[string]string) plugin.CallGraphResult {
	t.Helper()
	p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
	lock := pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}}, p, q)
	if edit != nil {
		lock = edit(lock)
	}
	return semRun(t, semProgram(t, pnpmLockFile, lock, files), semStore(t, p, q))
}

// TestSemantic_G1PnpmLockVersionGate: only 5.4, 6.0 and 9.0 are read.
func TestSemantic_G1PnpmLockVersionGate(t *testing.T) {
	if cg := pnpmVariant(t, nil, nil); runWide(cg) || !reaches(cg, "q", "1.0.0") {
		t.Fatalf("control: 9.0 reads; got %+v", cg.Partiality)
	}
	for name, edit := range map[string]func(string) string{
		"7.0":     func(s string) string { return strings.Replace(s, "'9.0'", "'7.0'", 1) },
		"missing": func(s string) string { return strings.Replace(s, "lockfileVersion: '9.0'\n", "", 1) },
		"duplicate": func(s string) string {
			return strings.Replace(s, "lockfileVersion: '9.0'\n", "lockfileVersion: '9.0'\nlockfileVersion: '9.0'\n", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if cg := pnpmVariant(t, edit, nil); !runWide(cg) || reaches(cg, "q", "1.0.0") {
				t.Errorf("must withhold and read nothing; got %+v", cg.Partiality)
			}
		})
	}
}

// TestSemantic_G1SelfDescribingUnknownVersion: a lock of an unread version whose packages name
// themselves would otherwise place cleanly; the version gate alone withholds it.
func TestSemantic_G1SelfDescribingUnknownVersion(t *testing.T) {
	q := qPkg("1.0.0")
	for _, tc := range []struct {
		ver      string
		withheld bool
	}{{"9.0", false}, {"7.0", true}} {
		lock := "lockfileVersion: '" + tc.ver + "'\n\nimporters:\n\n  '.': {}\n\npackages:\n\n  'opaque':\n    resolution: {integrity: " +
			sri(q.build(t)) + "}\n    name: q\n    version: 1.0.0\n\nsnapshots:\n\n  'opaque': {}\n"
		dir := semProgram(t, pnpmLockFile, lock, map[string]string{"package.json": manifestWith("app", nil, "")})
		if cg := semRun(t, dir, semStore(t, q)); runWide(cg) != tc.withheld {
			t.Errorf("%s: run-wide = %v, want %v; got %+v", tc.ver, runWide(cg), tc.withheld, cg.Partiality)
		}
	}
}

// TestSemantic_G2PnpmEnvDocument: pnpm 10's environment document is not placed; config
// dependencies or a third document withhold.
func TestSemantic_G2PnpmEnvDocument(t *testing.T) {
	env := "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    packageManagerDependencies:\n      pnpm:\n        specifier: 12.8.1\n        version: 12.8.1\n%s\npackages:\n\n  pnpm@12.8.1:\n    resolution: {integrity: sha512-AAAA}\n\nsnapshots:\n\n  pnpm@12.8.1: {}\n\n---\n"
	for _, tc := range []struct {
		name, prefix string
		withheld     bool
	}{
		{"env_document", fmt.Sprintf(env, ""), false},
		{"config_dependencies", fmt.Sprintf(env, "    configDependencies:\n      hook:\n        specifier: 1.0.0\n        version: 1.0.0\n"), true},
		{"three_documents", fmt.Sprintf(env, "") + "lockfileVersion: '9.0'\n---\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg := pnpmVariant(t, func(s string) string { return tc.prefix + s }, nil)
			if runWide(cg) != tc.withheld {
				t.Errorf("run-wide = %v, want %v; got %+v", runWide(cg), tc.withheld, cg.Partiality)
			}
			if !tc.withheld && (!reaches(cg, "q", "1.0.0") || slices.ContainsFunc(cg.Partiality.Scoped, func(s plugin.ScopedReason) bool { return strings.Contains(s.Package, "pnpm") })) {
				t.Errorf("the project document is read and the env document's pnpm is not placed; got %+v", cg.Partiality)
			}
		})
	}
}

// TestSemantic_G3PnpmDeclaredEdge: a declared load resolves to its edge target though two
// copies of the name are pinned, in every lock version.
func TestSemantic_G3PnpmDeclaredEdge(t *testing.T) {
	for _, ver := range []string{"5.4", "6.0", "9.0"} {
		t.Run(ver, func(t *testing.T) {
			q1, q2 := qPkg("2.0.0"), qPkg("1.0.0")
			other := sp("other", "1.0.0", map[string]string{"q": "1.0.0"}, nil)
			p := sp("p", "1.0.0", map[string]string{"q": "2.0.0"}, map[string]string{"index.js": callsQ})
			all := []*semPkg{p, q1, q2, other}
			lock := pnpmLockText(t, ver, map[string]map[string]string{".": {"p": "1.0.0", "other": "1.0.0"}}, all...)
			dir := semProgram(t, pnpmLockFile, lock, map[string]string{
				"package.json": manifestWith("app", map[string]string{"p": "1.0.0", "other": "1.0.0"}, ""),
			})
			cg := semRun(t, dir, semStore(t, all...))
			if !reaches(cg, "q", "2.0.0") || reaches(cg, "q", "1.0.0") || runWide(cg) {
				t.Errorf("p's declared q is 2.0.0 alone; got %+v edges %+v", cg.Partiality, cg.Edges)
			}
		})
	}
}

// TestSemantic_G4PnpmPeerVariants: two snapshots of one tarball are two entries, each with its
// own peer resolution.
func TestSemantic_G4PnpmPeerVariants(t *testing.T) {
	r1, r2 := sp("r", "1.0.0", nil, nil), sp("r", "2.0.0", nil, nil)
	pa := sp("p", "1.0.0", map[string]string{"r": "1.0.0"}, nil)
	pa.key = "p@1.0.0(r@1.0.0)"
	pb := sp("p", "1.0.0", map[string]string{"r": "2.0.0"}, nil)
	pb.key = "p@1.0.0(r@2.0.0)"
	lock := pnpmLockImporters(t, map[string][]pnpmImporterDep{
		".": {{"dependencies", "p", "1", "1.0.0(r@1.0.0)"}},
		"m": {{"dependencies", "p", "1", "1.0.0(r@2.0.0)"}},
	}, pa, pb, r1, r2)
	dir := writeProgram(t, map[string]string{pnpmLockFile: lock, "package.json": manifestWith("app", map[string]string{"p": "1"}, ""),
		"pnpm-workspace.yaml": "packages:\n  - m\n", "m/package.json": manifestWith("m", map[string]string{"p": "1"}, ""), "index.js": guardIdle})
	l := buildDepLayout(context.Background(), dir)
	if l.incomplete {
		t.Fatal("layout incomplete")
	}
	var ps []*depEntry
	for _, e := range l.entries() {
		if e.name == "p" {
			ps = append(ps, e)
		}
	}
	if len(ps) != 2 || ps[0].path == ps[1].path || ps[0].deps["r"].version == ps[1].deps["r"].version {
		t.Fatalf("want two p entries with distinct peers; got %+v", ps)
	}
	if a, b := l.lookup("", "p"), l.lookup("m", "p"); a == b || a.deps["r"].version != "1.0.0" || b.deps["r"].version != "2.0.0" {
		t.Errorf("each importer resolves its own variant")
	}
	cg := semRun(t, dir, semStore(t, pa, r1, r2))
	if runWide(cg) {
		t.Errorf("both variants read from one tarball; got %+v", cg.Partiality)
	}
}

// phantomFixture: p loads q, which it does not declare; copies of q are pinned through other.
func phantomFixture(t *testing.T, yarn bool, qs ...*semPkg) plugin.CallGraphResult {
	t.Helper()
	p := sp("p", "1.0.0", nil, map[string]string{"index.js": callsQ})
	imp := map[string]string{"p": "1.0.0"}
	all := []*semPkg{p}
	for i, q := range qs {
		o := sp(fmt.Sprintf("o%d", i), "1.0.0", map[string]string{"q": q.version}, nil)
		imp[o.name] = "1.0.0"
		all = append(all, o, q)
	}
	var dir string
	if yarn {
		dir = semProgram(t, yarnLockFile, yarnLockText(t, all...), map[string]string{"package.json": manifestWith("app", imp, "")})
	} else {
		dir = semProgram(t, pnpmLockFile, pnpmLockText(t, "9.0", map[string]map[string]string{".": imp}, all...), map[string]string{"package.json": manifestWith("app", imp, "")})
	}
	return semRun(t, dir, semStore(t, all...))
}

// TestSemantic_G5PhantomExactlyOne: a phantom load resolves to the one pinned copy; with two it
// takes a scoped limit bounded by the name, not a run-wide one.
func TestSemantic_G5PhantomExactlyOne(t *testing.T) {
	for _, yarn := range []bool{false, true} {
		t.Run(fmt.Sprintf("yarn=%v", yarn), func(t *testing.T) {
			one := phantomFixture(t, yarn, qPkg("1.0.0"))
			if !reaches(one, "q", "1.0.0") || runWide(one) {
				t.Errorf("one copy resolves; got %+v", one.Partiality)
			}
			two := phantomFixture(t, yarn, qPkg("1.0.0"), qPkg("2.0.0"))
			if reaches(two, "q", "1.0.0") || reaches(two, "q", "2.0.0") || runWide(two) ||
				!hasScopedTo(two.Partiality, makePURL("p", "1.0.0"), originPURL("q")) {
				t.Errorf("two copies: scoped to q, no edge, not run-wide; got %+v", two.Partiality)
			}
		})
	}
}

// TestSemantic_YarnPeerTwoCopies: a yarn package's peer is not in its lock block, so its load
// goes through the phantom rule: two pinned copies give a scoped limit.
func TestSemantic_YarnPeerTwoCopies(t *testing.T) {
	p := sp("p", "1.0.0", nil, map[string]string{
		"index.js":     callsQ,
		"package.json": `{"name":"p","version":"1.0.0","main":"index.js","peerDependencies":{"q":"*"}}`,
	})
	q1, q2 := qPkg("1.0.0"), qPkg("2.0.0")
	o0 := sp("o0", "1.0.0", map[string]string{"q": "1.0.0"}, nil)
	o1 := sp("o1", "1.0.0", map[string]string{"q": "2.0.0"}, nil)
	all := []*semPkg{p, q1, q2, o0, o1}
	dir := semProgram(t, yarnLockFile, yarnLockText(t, all...), map[string]string{
		"package.json": manifestWith("app", map[string]string{"p": "1.0.0", "o0": "1.0.0", "o1": "1.0.0"}, ""),
	})
	cg := semRun(t, dir, semStore(t, all...))
	if runWide(cg) || !hasScopedTo(cg.Partiality, makePURL("p", "1.0.0"), originPURL("q")) {
		t.Errorf("a peer with two copies is scoped; got %+v", cg.Partiality)
	}
}

// TestSemantic_G6BundledBeatsPhantom: a copy bundled in p's tarball is what p loads, not the
// pinned one; the bundled copy is unread and its install scripts unseen.
func TestSemantic_G6BundledBeatsPhantom(t *testing.T) {
	p := sp("p", "1.0.0", nil, map[string]string{"index.js": callsQ, "node_modules/q/index.js": qGo,
		"node_modules/q/package.json": `{"name":"q","version":"9.9.9"}`})
	q := qPkg("1.0.0")
	o := sp("o", "1.0.0", map[string]string{"q": "1.0.0"}, nil)
	imp := map[string]string{"p": "1.0.0", "o": "1.0.0"}
	dir := semProgram(t, pnpmLockFile, pnpmLockText(t, "9.0", map[string]map[string]string{".": imp}, p, q, o),
		map[string]string{"package.json": manifestWith("app", imp, "")})
	cg := semRun(t, dir, semStore(t, p, q, o))
	if reaches(cg, "q", "1.0.0") {
		t.Errorf("p's bundled q shadows the pinned one; edges %+v", cg.Edges)
	}
	if !runWide(cg) {
		t.Errorf("a bundled dependency withholds run-wide; got %+v", cg.Partiality)
	}
}

// TestSemantic_G7EdgeTargetMissing: an edge the lock cannot resolve withholds.
func TestSemantic_G7EdgeTargetMissing(t *testing.T) {
	cg := pnpmVariant(t, func(s string) string { return strings.Replace(s, "'q': '1.0.0'", "'q': '3.0.0'", 1) }, nil)
	if !runWide(cg) {
		t.Errorf("pnpm: got %+v", cg.Partiality)
	}
	p := sp("p", "1.0.0", map[string]string{"q": "^3.0.0"}, map[string]string{"index.js": callsQ})
	q := qPkg("1.0.0")
	if cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), nil), semStore(t, p, q)); !runWide(cg) {
		t.Errorf("yarn: got %+v", cg.Partiality)
	}
}

const patchHead = "diff --git a/lib/x.js b/lib/x.js\nindex 1111111..2222222 100644\n--- a/lib/x.js\n+++ b/lib/x.js\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n"

// TestSemantic_G8PnpmPatched: a patch that edits existing code limits its package alone and
// keeps its code unread; every trigger withholds.
func TestSemantic_G8PnpmPatched(t *testing.T) {
	patchedQ := func(q *semPkg, patch string, cfgKey string, lockKey string) plugin.CallGraphResult {
		edit := func(s string) string {
			s = strings.Replace(s, "importers:", "patchedDependencies:\n  "+yq(lockKey)+":\n    hash: abc\n    path: patches/q.patch\n\nimporters:", 1)
			return strings.Replace(s, "\n  'q@1.0.0': {}", "\n  'q@1.0.0(patch_hash=abc)': {}", 1)
		}
		files := map[string]string{
			"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, `,"pnpm":{"patchedDependencies":{"`+cfgKey+`":"patches/q.patch"}}`),
		}
		if patch != "" {
			files["patches/q.patch"] = patch
		}
		return pnpmVariantQ(t, q, func(s string) string {
			s = edit(s)
			return strings.Replace(s, "'q': '1.0.0'", "'q': '1.0.0(patch_hash=abc)'", 1)
		}, files)
	}
	patched := func(patch string, cfgKey string, lockKey string) plugin.CallGraphResult {
		return patchedQ(qPkg("1.0.0"), patch, cfgKey, lockKey)
	}
	cg := patched(patchHead, "q@1.0.0", "q@1.0.0")
	if runWide(cg) || reaches(cg, "q", "1.0.0") || !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, makePURL("q", "1.0.0")) {
		t.Fatalf("scoped patch: q limited alone, unread; got %+v edges %+v", cg.Partiality, cg.Edges)
	}
	for name, tc := range map[string]struct{ patch, cfg, lock string }{
		"package_json":    {strings.ReplaceAll(patchHead, "lib/x.js", "package.json"), "q@1.0.0", "q@1.0.0"},
		"binding_gyp":     {strings.ReplaceAll(patchHead, "lib/x.js", "binding.gyp"), "q@1.0.0", "q@1.0.0"},
		"addon":           {strings.ReplaceAll(patchHead, "lib/x.js", "build/q.node"), "q@1.0.0", "q@1.0.0"},
		"addon_upper":     {strings.ReplaceAll(patchHead, "lib/x.js", "build/q.NODE"), "q@1.0.0", "q@1.0.0"},
		"mode_change":     {strings.Replace(patchHead, "index 1111111..2222222 100644\n", "old mode 100644\nnew mode 100755\nindex 1111111..2222222\n", 1), "q@1.0.0", "q@1.0.0"},
		"absolute_path":   {"--- /lib/x.js\n+++ /lib/x.js\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n", "q@1.0.0", "q@1.0.0"},
		"new_file":        {"diff --git a/lib/y.js b/lib/y.js\nnew file mode 100644\n--- /dev/null\n+++ b/lib/y.js\n@@ -0,0 +1 @@\n+x\n", "q@1.0.0", "q@1.0.0"},
		"deleted_file":    {"diff --git a/lib/x.js b/lib/x.js\ndeleted file mode 100644\n--- a/lib/x.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n", "q@1.0.0", "q@1.0.0"},
		"unparseable":     {"this is not a diff\n", "q@1.0.0", "q@1.0.0"},
		"missing_file":    {"", "q@1.0.0", "q@1.0.0"},
		"config_mismatch": {patchHead, "q@1.0.0", "q@2.0.0"},
		"range_key":       {patchHead, "q@^1.0.0", "q@^1.0.0"},
	} {
		t.Run(name, func(t *testing.T) {
			if cg := patched(tc.patch, tc.cfg, tc.lock); !runWide(cg) {
				t.Errorf("must withhold; got %+v", cg.Partiality)
			}
		})
	}
	t.Run("patched_bundled", func(t *testing.T) {
		q := sp("q", "1.0.0", nil, map[string]string{"index.js": qGo,
			"node_modules/z/package.json": `{"name":"z","version":"1.0.0","scripts":{"postinstall":"x"}}`})
		if cg := patchedQ(q, patchHead, "q@1.0.0", "q@1.0.0"); !runWide(cg) {
			t.Errorf("a patched package's bundled install script still runs unseen; got %+v", cg.Partiality)
		}
	})
	t.Run("patch_hash_without_config", func(t *testing.T) {
		cg := pnpmVariant(t, func(s string) string {
			s = strings.Replace(s, "\n  'q@1.0.0': {}", "\n  'q@1.0.0(patch_hash=abc)': {}", 1)
			return strings.Replace(s, "'q': '1.0.0'", "'q': '1.0.0(patch_hash=abc)'", 1)
		}, nil)
		if !runWide(cg) {
			t.Errorf("a patch_hash key no patchedDependencies accounts for withholds; got %+v", cg.Partiality)
		}
	})
}

// TestSemantic_G9PnpmConfigHazards: a pnpmfile, package extensions and overrides the lock does
// not record withhold.
func TestSemantic_G9PnpmConfigHazards(t *testing.T) {
	withOverrides := func(s string) string {
		return strings.Replace(s, "importers:", "overrides:\n  q: 1.0.0\n\nimporters:", 1)
	}
	if cg := pnpmVariant(t, withOverrides, map[string]string{"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, `,"pnpm":{"overrides":{"q":"1.0.0"}}`)}); runWide(cg) {
		t.Fatalf("control: matching overrides read; got %+v", cg.Partiality)
	}
	for name, tc := range map[string]struct {
		edit  func(string) string
		files map[string]string
	}{
		"pnpmfile_cjs":   {nil, map[string]string{".pnpmfile.cjs": "module.exports = {}\n"}},
		"pnpmfile_mjs":   {nil, map[string]string{".pnpmfile.mjs": "export default {}\n"}},
		"npmrc_pnpmfile": {nil, map[string]string{".npmrc": "pnpmfile=hooks.cjs\n"}},
		"npmrc_global":   {nil, map[string]string{".npmrc": "global-pnpmfile = /etc/hooks.cjs\n"}},
		// pnpm 10 moves every package into the global virtual store; see
		// TestSemantic_PnpmGlobalVirtualStore. =false withholds too: the lane does not model
		// which values pnpm reads as off.
		"npmrc_gvs":           {nil, map[string]string{".npmrc": "enable-global-virtual-store=true\n"}},
		"npmrc_gvs_quoted":    {nil, map[string]string{".npmrc": "\"enable-global-virtual-store\"=true\n"}},
		"npmrc_gvs_false":     {nil, map[string]string{".npmrc": "enable-global-virtual-store=false\n"}},
		"package_extensions":  {nil, map[string]string{"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, `,"pnpm":{"packageExtensions":{"q":{"dependencies":{"x":"1"}}}}`)}},
		"resolutions_field":   {nil, map[string]string{"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, `,"resolutions":{"q":"1.0.0"}`)}},
		"overrides_manifest":  {nil, map[string]string{"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, `,"pnpm":{"overrides":{"q":"1.0.0"}}`)}},
		"overrides_workspace": {nil, map[string]string{"pnpm-workspace.yaml": "overrides:\n  q: 1.0.0\n"}},
		"overrides_lock_only": {withOverrides, nil},
	} {
		t.Run(name, func(t *testing.T) {
			if cg := pnpmVariant(t, tc.edit, tc.files); !runWide(cg) {
				t.Errorf("must withhold; got %+v", cg.Partiality)
			}
		})
	}
}

// TestSemantic_PnpmGlobalVirtualStore: pnpm 10 honours enable-global-virtual-store from .npmrc
// outside CI and moves every package to <store>/links/..., so the phantom walk climbs the store's
// ancestors and never reaches the region's hoist dir. With store-dir inside the checkout beside an
// npm region, p's undeclared require("q") resolves into that region's copy, an edge the layout
// does not model. Any .npmrc in the build that spells the setting withholds the layout, whatever
// its value. Each tree is web/, a pnpm region, beside tools/, an npm region pinning q@2.0.0.
func TestSemantic_PnpmGlobalVirtualStore(t *testing.T) {
	const (
		webLock = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      o:\n        specifier: 1.0.0\n        version: 1.0.0\n" +
			"      p:\n        specifier: 1.0.0\n        version: 1.0.0\n  packages/a: {}\n\npackages:\n\n" +
			"  o@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n\n  p@1.0.0:\n    resolution: {integrity: sha512-BBBB}\n\n" +
			"  q@1.0.0:\n    resolution: {integrity: sha512-CCCC}\n\nsnapshots:\n\n  o@1.0.0:\n    dependencies:\n      q: 1.0.0\n\n  p@1.0.0: {}\n\n  q@1.0.0: {}\n"
		toolsLock = `{"name":"tools","lockfileVersion":3,"requires":true,"packages":{"":{"name":"tools","version":"1.0.0","dependencies":{"q":"2.0.0"}},` +
			`"node_modules/q":{"version":"2.0.0","resolved":"https://registry.npmjs.org/q/-/q-2.0.0.tgz","integrity":"sha512-DDDD"}}}`
		sibling = "store-dir=../tools/.pnpm-store\n"
	)
	for _, tc := range []struct {
		name  string
		files map[string]string
		// withheld is whether the layout is incomplete.
		withheld bool
	}{
		// The killing rows: the setting is on and the store sits beside tools/.
		{"hole", map[string]string{"web/.npmrc": "enable-global-virtual-store=true\n" + sibling}, true},
		{"hole-quoted", map[string]string{"web/.npmrc": "\"enable-global-virtual-store\"=true\n" + sibling}, true},
		{"hole-bracket", map[string]string{"web/.npmrc": "enable-global-virtual-store[]=true\n" + sibling}, true},
		{"hole-bom", map[string]string{"web/.npmrc": "\xef\xbb\xbfenable-global-virtual-store=true\n" + sibling}, true},
		// pnpm 10 expands ${K} and unescapes a quoted key before it matches the name, so no word
		// of the setting appears in the text.
		{"hole-key-expansion", map[string]string{"web/.npmrc": "${GVS_KEY}=true\n" + sibling}, true},
		{"hole-key-escape", map[string]string{"web/.npmrc": "\"enable-global-\\u0076irtual-store\"=true\n" + sibling}, true},
		// pnpm splits lines on [\r\n]+, so a lone CR separates keys; the first = is in the registry
		// line, which hides the later key from a split on \n alone.
		{"hole-cr-only", map[string]string{"web/.npmrc": "registry=https://r/\r\"enable-global-virtual-store\"=true\rstore-dir=../tools/.pnpm-store\r"}, true},
		{"hole-cr-only-expansion", map[string]string{"web/.npmrc": "registry=https://r/\r${GVS_KEY}=true\r"}, true},
		{"hole-crlf", map[string]string{"web/.npmrc": "registry=https://r/\r\n${GVS_KEY}=true\r\n"}, true},
		{"hole-cr-escape-after-crlf", map[string]string{"web/.npmrc": "registry=https://r/\r\n//host/:_authToken=${T}\r\"enable-global-\\u0076irtual-store\"=true\n"}, true},
		{"ctl-cr-only", map[string]string{"web/.npmrc": "registry=https://r/\r" + sibling}, false},
		// An indirect key whose raw text starts with // (registry credentials) or @ (a scoped
		// registry) cannot resolve to a setting name: no pnpm 10 or 11 setting starts with / or @.
		{"ctl-carve-registry-key", map[string]string{"web/.npmrc": "//${REG}/:_authToken=${T}\n" + sibling}, false},
		{"ctl-carve-scope-key", map[string]string{"web/.npmrc": "@${S}:registry=https://r/\n" + sibling}, false},
		{"ctl-carve-spaced", map[string]string{"web/.npmrc": "  //${REG}/:_authToken=${T}\n" + sibling}, false},
		{"ctl-carve-escape-in-scope", map[string]string{"web/.npmrc": "@sc\\u006fpe:registry=https://r/\n" + sibling}, false},
		// The carve-out is literal; each of these still withholds.
		{"hole-carve-quoted", map[string]string{"web/.npmrc": "\"//${X}\"=true\n" + sibling}, true},
		{"hole-carve-single-slash", map[string]string{"web/.npmrc": "/${GVS_KEY}=true\n" + sibling}, true},
		{"hole-carve-late", map[string]string{"web/.npmrc": "${GVS_KEY}//=true\n" + sibling}, true},
		{"hole-carve-after-carved-line", map[string]string{"web/.npmrc": "//${REG}/:_authToken=${T}\n${GVS_KEY}=true\n" + sibling}, true},
		{"hole-carve-bom-lone-var", map[string]string{"web/.npmrc": "\xef\xbb\xbf${GVS_KEY}=true\n" + sibling}, true},

		// A member directory's .npmrc: the region-root check never reads it.
		{"hole-member-dir", map[string]string{"web/pnpm-workspace.yaml": "packages:\n  - packages/a\n", "web/packages/a/package.json": `{"name":"a","version":"1.0.0"}`,
			"web/packages/a/.npmrc": "enable-global-virtual-store=true\n"}, true},
		// An ancestor's .npmrc already withholds on main: inertDir admits an outer directory's
		// .npmrc only for outerNpmrcKeys. A guard against that allowlist growing the key.
		{"ancestor-npmrc", map[string]string{".npmrc": "enable-global-virtual-store=true\n"}, true},
		{"sibling-dir-npmrc", map[string]string{"other/.npmrc": "enable-global-virtual-store=true\n"}, true},

		// Over-withholds, kept on purpose. ctl-false: pnpm treats only the literal false as off
		// (a duplicate key, a [section] or CI change that too), and the lane does not model that.
		// ctl-outstore: with the store outside the checkout the runtime only loses the edge, which
		// costs precision, but the lane cannot tell where store-dir points.
		{"ctl-false", map[string]string{"web/.npmrc": "enable-global-virtual-store=false\n"}, true},
		{"ctl-outstore", map[string]string{"web/.npmrc": "enable-global-virtual-store=true\n"}, true},

		// Controls that stay complete: the same store-dir without the setting, no .npmrc, and
		// ${...} and backslashes in values, which the key check leaves alone.
		{"ctl-nogvs", map[string]string{"web/.npmrc": sibling}, false},
		{"ctl-no-npmrc", nil, false},
		{"ctl-value-expansion", map[string]string{"web/.npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\ncache=C:\\npm\n" + sibling}, false},

		// Already withheld on main: the workspace-file route is gated by pnpmWorkspaceKeys, which
		// holds neither enableGlobalVirtualStore nor storeDir. A guard against the allowlist
		// growing them.
		{"ws-region-root", map[string]string{"web/pnpm-workspace.yaml": "enableGlobalVirtualStore: true\nstoreDir: ../tools/.pnpm-store\n"}, true},
		// A pnpm-workspace.yaml outside the region root is not read by that allowlist; the word
		// GlobalVirtualStore withholds it (ws-ancestor already withholds on main through inertDir).
		{"ws-ancestor", map[string]string{"pnpm-workspace.yaml": "enableGlobalVirtualStore: true\n"}, true},
		{"ws-sibling-dir", map[string]string{"other/pnpm-workspace.yaml": "enableGlobalVirtualStore: true\n"}, true},
		{"ws-member-dir", map[string]string{"web/pnpm-workspace.yaml": "packages:\n  - packages/a\n", "web/packages/a/package.json": `{"name":"a","version":"1.0.0"}`,
			"web/packages/a/pnpm-workspace.yaml": "enableGlobalVirtualStore: true\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"web/package.json":        `{"name":"web","version":"1.0.0","private":true,"dependencies":{"p":"1.0.0","o":"1.0.0"}}`,
				"web/pnpm-lock.yaml":      webLock,
				"tools/package.json":      `{"name":"tools","version":"1.0.0","private":true,"dependencies":{"q":"2.0.0"}}`,
				"tools/package-lock.json": toolsLock,
			}
			maps.Copy(files, tc.files)
			l := buildDepLayout(context.Background(), writeProgram(t, files))
			if l.incomplete != tc.withheld {
				t.Errorf("layout incomplete = %v, want %v", l.incomplete, tc.withheld)
			}
		})
	}
}

// TestSemantic_PnpmAllowBuilds: an allowBuilds block mapping of scalars in pnpm-workspace.yaml
// is accepted with its values unread, and a value that stops a script never stops the script
// from withholding. Any other shape, and allowBuilds in package.json, withholds. Each tree holds
// packages/b, unlisted, declaring a dependency the lock installs nothing for.
func TestSemantic_PnpmAllowBuilds(t *testing.T) {
	const pkgs = "packages:\n  - packages/a\n"
	const postinstall = `{"name":"q","version":"1.0.0","main":"index.js","scripts":{"postinstall":"x"}}`
	for name, tc := range map[string]struct {
		ws       string
		manifest string
		qScript  bool
		placed   bool
	}{
		"control_mixed":         {ws: pkgs + "allowBuilds:\n  esbuild: true\n  '@scarf/scarf': false\n", placed: true},
		"script_without_key":    {ws: pkgs, qScript: true},
		"false_still_escalates": {ws: pkgs + "allowBuilds:\n  q: false\n", qScript: true},
		"list":                  {ws: pkgs + "allowBuilds:\n  - esbuild\n"},
		"nested":                {ws: pkgs + "allowBuilds:\n  esbuild:\n    x: 1\n"},
		"flow_map":              {ws: pkgs + "allowBuilds: {esbuild: true}\n"},
		"scalar":                {ws: pkgs + "allowBuilds: true\n"},
		"manifest_allow_builds": {ws: pkgs, manifest: `,"pnpm":{"allowBuilds":{"esbuild":true}}`},
	} {
		t.Run(name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			q := qPkg("1.0.0")
			if tc.qScript {
				q.files["package.json"] = postinstall
			}
			lock := pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}, "packages/a": {"q": "1.0.0"}}, p, q)
			dir := semProgram(t, pnpmLockFile, lock, map[string]string{
				"package.json":            manifestWith("app", map[string]string{"p": "1.0.0"}, tc.manifest),
				"pnpm-workspace.yaml":     tc.ws,
				"packages/a/package.json": manifestWith("a", map[string]string{"q": "1.0.0"}, ""),
				"packages/b/package.json": manifestWith("b", map[string]string{"absent-package": "1.0.0"}, ""),
			})
			cfg, ok := readPnpmConfig(dir)
			cg := semRun(t, dir, semStore(t, p, q))
			incomplete := buildDepLayout(context.Background(), dir).incomplete
			switch {
			case tc.placed:
				if !ok || !slices.Equal(cfg.members, []string{"packages/a"}) || incomplete || runWide(cg) || !reaches(cg, "q", "1.0.0") {
					t.Errorf("%q places the region with members [packages/a]; ok=%v cfg=%+v incomplete=%v got %+v", tc.ws, ok, cfg, incomplete, cg.Partiality)
				}
			case tc.qScript:
				if !ok || incomplete || !runWide(cg) || !reaches(cg, "q", "1.0.0") {
					t.Errorf("%q places the region and q's install script withholds run-wide; ok=%v incomplete=%v got %+v", tc.ws, ok, incomplete, cg.Partiality)
				}
			default:
				if ok || !incomplete || !runWide(cg) {
					t.Errorf("%q with manifest %q withholds; ok=%v incomplete=%v got %+v", tc.ws, tc.manifest, ok, incomplete, cg.Partiality)
				}
			}
		})
	}
}

// TestSemantic_G10PnpmRequiresBuildAbsent: a lock that records no requiresBuild leaves an
// unread package run-wide.
func TestSemantic_G10PnpmRequiresBuildAbsent(t *testing.T) {
	for _, ver := range []string{"6.0", "9.0"} {
		p := sp("p", "1.0.0", nil, nil)
		lock := pnpmLockText(t, ver, map[string]map[string]string{".": {"p": "1.0.0"}}, p)
		cg := semRun(t, semProgram(t, pnpmLockFile, lock, nil), artifactcache.NewDeclaredAbsentStore())
		if !runWide(cg) || !hasScoped(cg.Partiality, plugin.PartialReasonUninspectablePackage, makePURL("p", "1.0.0")) {
			t.Errorf("%s: unread and scripts unknown withholds run-wide; got %+v", ver, cg.Partiality)
		}
	}
}

// TestSemantic_G11UnknownOrUnreadableConfig: an unknown setting or a config file that cannot be
// read withholds.
func TestSemantic_G11UnknownOrUnreadableConfig(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"unknown_workspace_key": {"pnpm-workspace.yaml": "packages: []\nhooks: x\n"},
		"npmrc_directory":       {".npmrc/x": "x"},
		"workspace_directory":   {"pnpm-workspace.yaml/x": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if cg := pnpmVariant(t, nil, files); !runWide(cg) {
				t.Errorf("must withhold; got %+v", cg.Partiality)
			}
		})
	}
	p, q := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ}), qPkg("1.0.0")
	for name, files := range map[string]map[string]string{
		"yarnrc_directory":   {".yarnrc/x": "x"},
		"yarnrc_unknown_key": {".yarnrc": "registry \"https://r.example\"\n--modules-folder vendor\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), files), semStore(t, p, q)); !runWide(cg) {
				t.Errorf("must withhold; got %+v", cg.Partiality)
			}
		})
	}
	if cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), map[string]string{".yarnrc": "registry \"https://r.example\"\n"}), semStore(t, p, q)); runWide(cg) {
		t.Errorf("control: an accepted .yarnrc key reads; got %+v", cg.Partiality)
	}
}

// TestSemantic_PnpmBlockExoticSubdeps: blockExoticSubdeps set to true or false, plain or quoted,
// places the region with the members it lists; any other value withholds. Each tree holds
// packages/b, unlisted, declaring a dependency the lock installs nothing for.
func TestSemantic_PnpmBlockExoticSubdeps(t *testing.T) {
	const pkgs = "packages:\n  - packages/a\n"
	for name, tc := range map[string]struct {
		ws     string
		placed bool
	}{
		"control_true":   {pkgs + "blockExoticSubdeps: true\n", true},
		"control_false":  {pkgs + "blockExoticSubdeps: false\n", true},
		"control_quoted": {pkgs + "blockExoticSubdeps: 'false'\n", true},
		"yes":            {pkgs + "blockExoticSubdeps: yes\n", false},
		"capitalized":    {pkgs + "blockExoticSubdeps: True\n", false},
		"one":            {pkgs + "blockExoticSubdeps: 1\n", false},
		"list":           {pkgs + "blockExoticSubdeps:\n  - true\n", false},
		"flow_list":      {pkgs + "blockExoticSubdeps: [true]\n", false},
		"mapping":        {pkgs + "blockExoticSubdeps:\n  x: true\n", false},
		"empty":          {pkgs + "blockExoticSubdeps:\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			q := qPkg("1.0.0")
			lock := pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}, "packages/a": {"q": "1.0.0"}}, p, q)
			dir := semProgram(t, pnpmLockFile, lock, map[string]string{
				"pnpm-workspace.yaml":     tc.ws,
				"packages/a/package.json": manifestWith("a", map[string]string{"q": "1.0.0"}, ""),
				"packages/b/package.json": manifestWith("b", map[string]string{"absent-package": "1.0.0"}, ""),
			})
			cfg, ok := readPnpmConfig(dir)
			cg := semRun(t, dir, semStore(t, p, q))
			incomplete := buildDepLayout(context.Background(), dir).incomplete
			if tc.placed && (!ok || !slices.Equal(cfg.members, []string{"packages/a"}) || incomplete || runWide(cg) || !reaches(cg, "q", "1.0.0")) {
				t.Errorf("%q places the region with members [packages/a]; ok=%v cfg=%+v incomplete=%v got %+v", tc.ws, ok, cfg, incomplete, cg.Partiality)
			}
			if !tc.placed && (ok || !incomplete || !runWide(cg)) {
				t.Errorf("%q withholds; ok=%v incomplete=%v got %+v", tc.ws, ok, incomplete, cg.Partiality)
			}
		})
	}
}

// TestSemantic_G12PnpmExcludeLinks: a lock that leaves links out withholds.
func TestSemantic_G12PnpmExcludeLinks(t *testing.T) {
	cg := pnpmVariant(t, func(s string) string {
		return strings.Replace(s, "importers:", "settings:\n  excludeLinksFromLockfile: true\n\nimporters:", 1)
	}, nil)
	if !runWide(cg) {
		t.Errorf("got %+v", cg.Partiality)
	}
}

// TestSemantic_G13YarnResolutions: only a bare or "**/" key whose exact pin or decidable range
// every block of the name satisfies is trusted. For a range, every rewritable descriptor of the
// name must already share the block of the resolution's own pattern, which yarn writes onto it
// (pat).
func TestSemantic_G13YarnResolutions(t *testing.T) {
	for _, tc := range []struct {
		name, res string
		pat       bool
		withheld  bool
	}{
		{"bare_exact", `{"q":"1.0.0"}`, false, false},
		{"glob_exact", `{"**/q":"1.0.0"}`, false, false},
		{"unsatisfied", `{"q":"2.0.0"}`, false, true},
		{"nested", `{"p/q":"1.0.0"}`, false, true},
		{"range", `{"q":"^1.0.0"}`, true, false},
		{"range_pattern_unlocked", `{"q":"^1.0.0"}`, false, true},
		{"glob_range", `{"**/q":">=1.0.0 <2.0.0"}`, true, false},
		{"range_unsatisfied", `{"q":"^2.0.0"}`, true, true},
		{"x_range", `{"q":"1.x"}`, true, false},
		{"or_satisfied", `{"q":"^0.9.0 || ^1.0.0"}`, true, false},
		{"or_unsatisfied", `{"q":"^0.9.0 || ^2.0.0"}`, true, true},
		{"or_undecidable", `{"q":"^1.0.0 || latest"}`, true, true},
		{"hyphen_satisfied", `{"q":"0.5.0 - 1.2"}`, true, false},
		{"hyphen_unsatisfied", `{"q":"1.0.1 - 2.0.0"}`, true, true},
		{"range_prerelease", `{"q":"^1.0.0-beta"}`, true, true},
		{"protocol", `{"q":"npm:q@1.0.0"}`, false, true},
		{"nested_range", `{"p/q":"^1.0.0"}`, true, true},
		{"no_block", `{"r":"^9.0.0"}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, q := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ}), qPkg("1.0.0")
			if tc.pat {
				var res map[string]string
				if err := json.Unmarshal([]byte(tc.res), &res); err != nil {
					t.Fatal(err)
				}
				for _, v := range res {
					q.descs = []string{"q@1.0.0", "q@" + v}
				}
			}
			files := map[string]string{"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, `,"resolutions":`+tc.res)}
			cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), files), semStore(t, p, q))
			if runWide(cg) != tc.withheld {
				t.Errorf("run-wide = %v, want %v; got %+v", runWide(cg), tc.withheld, cg.Partiality)
			}
		})
	}
}

// TestSemantic_G13YarnRangeOneBlock: yarn rewrites every transitive descriptor of a range
// resolution's name to one pattern, so two blocks that each satisfy the range are a lock the
// install does not reproduce, and withhold. The root manifest's own descriptor is not rewritten
// and may keep a block of its own.
func TestSemantic_G13YarnRangeOneBlock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rootQ    bool
		withheld bool
	}{
		{"two_transitive_blocks", false, true},
		{"root_descriptor_kept", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "^1.0.0"}, map[string]string{"index.js": callsQ})
			q1, q2 := qPkg("1.0.0"), qPkg("1.5.0")
			q1.descs = []string{"q@^1.0.0"}
			q2.descs = []string{"q@^1.5.0"}
			rootDeps := map[string]string{"p": "1.0.0"}
			pkgs := []*semPkg{p, q1, q2}
			if tc.rootQ {
				rootDeps["q"] = "^1.5.0"
			} else {
				r := sp("r", "1.0.0", map[string]string{"q": "^1.5.0"}, nil)
				rootDeps["r"] = "1.0.0"
				pkgs = append(pkgs, r)
			}
			files := map[string]string{"package.json": manifestWith("app", rootDeps, `,"resolutions":{"q":"^1.0.0"}`)}
			cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, pkgs...), files), semStore(t, pkgs...))
			if runWide(cg) != tc.withheld {
				t.Errorf("run-wide = %v, want %v; got %+v", runWide(cg), tc.withheld, cg.Partiality)
			}
		})
	}
}

// TestSemantic_G14YarnSha1Fragment: a block with only a sha1 fragment reads and verifies; bytes
// that do not match stay unread; a git commit fragment is never a digest.
func TestSemantic_G14YarnSha1Fragment(t *testing.T) {
	sha1hex := func(b []byte) string { return fmt.Sprintf("%x", sha1.Sum(b)) }
	frag := func(tamper bool) plugin.CallGraphResult {
		p, q := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ}), qPkg("1.0.0")
		hex := sha1hex(q.build(t))
		q.integrity = "-"
		q.resolved = "https://registry.yarnpkg.com/q/-/q-1.0.0.tgz#" + hex
		m := map[artifactcache.Ref][]byte{p.ref(t): p.build(t)}
		qb := q.build(t)
		if tamper {
			qb = qPkg("1.0.0").build(t)
			qb = append(append([]byte{}, qb...), 0)
		}
		m[artifactcache.Ref{PURL: makePURL("q", "1.0.0"), Digest: "sha1:" + hex}] = qb
		return semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), nil), artifactcache.NewMemStore(m))
	}
	if cg := frag(false); !reaches(cg, "q", "1.0.0") || runWide(cg) {
		t.Errorf("a sha1 fragment reads; got %+v", cg.Partiality)
	}
	if cg := frag(true); reaches(cg, "q", "1.0.0") || !runWide(cg) {
		t.Errorf("tampered bytes stay unread; got %+v", cg.Partiality)
	}
	p, q := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ}), qPkg("1.0.0")
	q.integrity = "-"
	q.resolved = "git+https://github.com/x/q.git#" + strings.Repeat("a", 40)
	if cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), nil), semStore(t, p, q)); reaches(cg, "q", "1.0.0") || !runWide(cg) {
		t.Errorf("a git commit is not a digest; got %+v", cg.Partiality)
	}
	q = qPkg("1.0.0")
	q.integrity = "-"
	q.resolved = "https://registry.yarnpkg.com/q/-/q-1.0.0.tgz#" + strings.Repeat("g", 40)
	if cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), nil), semStore(t, p, q)); reaches(cg, "q", "1.0.0") || !runWide(cg) {
		t.Errorf("a non-hex fragment is not a digest; got %+v", cg.Partiality)
	}
}

// TestSemantic_G15NoSRIUnreadable: entries without a registry integrity are placed but never
// read, and withhold.
func TestSemantic_G15NoSRIUnreadable(t *testing.T) {
	// The git and directory rows carry the tarball's integrity too, so only the resolution's
	// type keeps them unread.
	integrity := sri(qPkg("1.0.0").build(t))
	for name, res := range map[string]string{
		"tarball":   "{tarball: https://example.com/q.tgz}",
		"git":       "{integrity: " + integrity + ", type: git, repo: https://github.com/x/q, commit: " + strings.Repeat("a", 40) + "}",
		"directory": "{integrity: " + integrity + ", type: directory, directory: ../q}",
	} {
		t.Run("pnpm_"+name, func(t *testing.T) {
			cg := pnpmVariant(t, func(s string) string {
				i := strings.Index(s, "'q@1.0.0':\n    resolution: ")
				j := i + len("'q@1.0.0':\n    resolution: ")
				k := strings.IndexByte(s[j:], '\n')
				return s[:j] + res + s[j+k:]
			}, nil)
			if reaches(cg, "q", "1.0.0") || !runWide(cg) {
				t.Errorf("got %+v", cg.Partiality)
			}
		})
	}
	for name, resolved := range map[string]string{"file": "file:../q", "git": "git+https://github.com/x/q.git#v1"} {
		t.Run("yarn_"+name, func(t *testing.T) {
			p, q := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ}), qPkg("1.0.0")
			q.resolved = resolved // the integrity stays: only the source keeps it unread
			if cg := semRun(t, semProgram(t, yarnLockFile, yarnLockText(t, p, q), nil), semStore(t, p, q)); reaches(cg, "q", "1.0.0") || !runWide(cg) {
				t.Errorf("got %+v", cg.Partiality)
			}
		})
	}
}

// TestSemantic_G16PlacedButUnread: placement alone retires nothing: a cache miss, a digest
// mismatch or a budget overrun withholds.
func TestSemantic_G16PlacedButUnread(t *testing.T) {
	dir, store := pqFixture(t, "9.0", qPkg("1.0.0"))
	p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
	miss := semStore(t, p)
	wrong := artifactcache.NewMemStore(map[artifactcache.Ref][]byte{p.ref(t): p.build(t), qPkg("1.0.0").ref(t): []byte("not it")})
	for name, s := range map[string]artifactcache.Store{"miss": miss, "mismatch": wrong} {
		if cg := semRun(t, dir, s); !runWide(cg) || reaches(cg, "q", "1.0.0") {
			t.Errorf("%s: got %+v", name, cg.Partiality)
		}
	}
	res, _, err := callGraphWithDeps(context.Background(), dir, store, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	qp := makePURL("q", "1.0.0")
	budgetScoped := slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool {
		return s.Reason == plugin.PartialReasonToolFailure && s.Package == qp
	})
	if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) || !budgetScoped {
		t.Errorf("budget: q must carry its own limit under a run-wide one; got %+v", res.Partiality)
	}
}

// TestSemantic_G17Regions: nested roots choose by longest prefix; the npm root keeps its
// physical walk; a listed member with its own lock is claimed twice and withholds.
func TestSemantic_G17Regions(t *testing.T) {
	npmLock := func(version string) string {
		q := qPkg(version)
		return `{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","dependencies":{"q":"` + version + `"}},"node_modules/q":{"version":"` + version + `","resolved":"https://registry.npmjs.org/q/-/q-` + version + `.tgz","integrity":"` + sri(q.build(t)) + `"}}}`
	}
	q1, q2 := qPkg("1.0.0"), qPkg("2.0.0")
	const loadQ = "const q = require('q');\nq.go();\n"
	t.Run("pnpm_in_npm", func(t *testing.T) {
		dir := writeProgram(t, map[string]string{
			"package.json": manifestWith("app", map[string]string{"q": "1.0.0"}, ""), "package-lock.json": npmLock("1.0.0"), "index.js": loadQ,
			"web/package.json": manifestWith("web", map[string]string{"q": "2.0.0"}, ""), "web/" + pnpmLockFile: pnpmLockText(t, "9.0", map[string]map[string]string{".": {"q": "2.0.0"}}, q2), "web/index.js": loadQ,
		})
		l := buildDepLayout(context.Background(), dir)
		if l.incomplete || l.lookup("", "q").version != "1.0.0" || l.lookup("web", "q").version != "2.0.0" || l.lookup("web/src", "q").version != "2.0.0" {
			t.Errorf("longest prefix: root npm q 1, web pnpm q 2")
		}
		if cg := semRun(t, dir, semStore(t, q1, q2)); !reaches(cg, "q", "1.0.0") || !reaches(cg, "q", "2.0.0") {
			t.Errorf("both regions read; edges %+v", cg.Edges)
		}
	})
	t.Run("npm_in_pnpm", func(t *testing.T) {
		dir := writeProgram(t, map[string]string{
			"package.json": manifestWith("app", map[string]string{"q": "2.0.0"}, ""), pnpmLockFile: pnpmLockText(t, "9.0", map[string]map[string]string{".": {"q": "2.0.0"}}, q2),
			"api/package.json": manifestWith("api", map[string]string{"q": "1.0.0"}, ""), "api/package-lock.json": npmLock("1.0.0"),
		})
		l := buildDepLayout(context.Background(), dir)
		if l.incomplete || l.lookup("api", "q").version != "1.0.0" || l.lookup("", "q").version != "2.0.0" {
			t.Errorf("longest prefix: api npm q 1, root pnpm q 2")
		}
		if l.lookup("api", "r") != nil {
			t.Errorf("an npm miss walks on into the pnpm root and finds no r")
		}
	})
	t.Run("listed_member_own_lock", func(t *testing.T) {
		dir := writeProgram(t, map[string]string{
			"package.json": manifestWith("app", nil, ""), "pnpm-workspace.yaml": "packages:\n  - 'm'\n",
			pnpmLockFile:     pnpmLockText(t, "9.0", map[string]map[string]string{".": {}, "m": {"q": "2.0.0"}}, q2),
			"m/package.json": manifestWith("m", map[string]string{"q": "1.0.0"}, ""), "m/package-lock.json": npmLock("1.0.0"),
		})
		if !buildDepLayout(context.Background(), dir).incomplete {
			t.Errorf("a member two locks claim is incomplete")
		}
	})
	t.Run("unlisted_member_own_lock", func(t *testing.T) {
		dir := writeProgram(t, map[string]string{
			"package.json": manifestWith("app", map[string]string{"q": "2.0.0"}, ""), pnpmLockFile: pnpmLockText(t, "9.0", map[string]map[string]string{".": {"q": "2.0.0"}}, q2),
			"tools/package.json": manifestWith("tools", map[string]string{"q": "1.0.0"}, ""), "tools/package-lock.json": npmLock("1.0.0"),
		})
		l := buildDepLayout(context.Background(), dir)
		if l.incomplete || l.lookup("tools", "q").version != "1.0.0" {
			t.Errorf("an unlisted member with its own lock takes longest prefix")
		}
	})
	t.Run("undecidable_dialect", func(t *testing.T) {
		dir := writeProgram(t, map[string]string{
			"package.json": manifestWith("app", map[string]string{"q": "2.0.0"}, ""), pnpmLockFile: pnpmLockText(t, "9.0", map[string]map[string]string{".": {"q": "2.0.0"}}, q2),
			yarnLockFile: yarnLockText(t, q2),
		})
		if !buildDepLayout(context.Background(), dir).incomplete {
			t.Errorf("two dialects at one root is incomplete")
		}
	})
}

// TestSemantic_DecoyAtSyntheticPath: a real directory at a synthetic install path, as an earlier
// install leaves, is never read: a decoy file there changes nothing, and neither does making
// the store directory unreadable.
func TestSemantic_DecoyAtSyntheticPath(t *testing.T) {
	t.Run("yarn_classic", func(t *testing.T) {
		p, q := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ}), qPkg("1.0.0")
		dir := semProgram(t, yarnLockFile, yarnLockText(t, p, q), nil)
		store := semStore(t, p, q)
		base := withDeps(t, dir, store)
		plant(t, filepath.Join(dir, "node_modules", ".yarn-classic", "q@1.0.0", "node_modules", "q"))
		if cg := withDeps(t, dir, store); !slices.Equal(cg.Edges, base.Edges) || !slices.Equal(cg.Partiality.Reasons, base.Partiality.Reasons) || len(cg.Partiality.Scoped) != len(base.Partiality.Scoped) {
			t.Errorf("the decoy changed the result: %+v vs %+v", cg.Partiality, base.Partiality)
		}
	})

	dir, store := pqFixture(t, "9.0", qPkg("1.0.0"))
	base := withDeps(t, dir, store)
	plant(t, filepath.Join(dir, "node_modules", ".pnpm", "q@1.0.0", "node_modules", "q"))
	same := func(label string) {
		t.Helper()
		cg := withDeps(t, dir, store)
		if !slices.Equal(cg.Edges, base.Edges) || !slices.Equal(cg.Partiality.Reasons, base.Partiality.Reasons) || len(cg.Partiality.Scoped) != len(base.Partiality.Scoped) {
			t.Errorf("%s: the decoy changed the result: %+v vs %+v", label, cg.Partiality, base.Partiality)
		}
	}
	same("decoy")
	plant(t, filepath.Join(dir, "node_modules", ".pnpm", "node_modules", "q"))
	same("decoy in the hoisted store")
	store0 := filepath.Join(dir, "node_modules", ".pnpm")
	if err := os.Chmod(store0, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store0, 0o755) })
	same("unreadable store directory")

}

// plant writes a decoy package at dir: code that would withhold if read, and an install script.
func plant(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{
		"index.js":     "exports.go = function go(s) { return eval(s); };\nexports.other = function other() {};\n",
		"package.json": `{"name":"q","version":"1.0.0","main":"index.js","scripts":{"postinstall":"x"}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSemantic_G18NestedPhantom: a phantom load in a nested region may find an in-region copy or,
// when none is hoisted where the walk passes, climb out to a copy above the region. With both
// present it resolves to neither, and the load's limit targets every candidate; with nothing above
// it resolves to the in-region copy. A virtual store or modules directory outside the region's
// node_modules puts the walk where the lane does not model, and withholds.
func TestSemantic_G18NestedPhantom(t *testing.T) {
	npmRoot := func(withQ bool) map[string]string {
		if !withQ {
			return map[string]string{"package.json": manifestWith("app", nil, ""), "package-lock.json": `{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x"}}}`}
		}
		return map[string]string{
			"package.json":      manifestWith("app", map[string]string{"q": "1.0.0"}, ""),
			"package-lock.json": `{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","dependencies":{"q":"1.0.0"}},"node_modules/q":{"version":"1.0.0","resolved":"https://registry.npmjs.org/q/-/q-1.0.0.tgz","integrity":"` + sri(qPkg("1.0.0").build(t)) + `"}}}`,
		}
	}
	webImp := map[string]string{"o": "1.0.0", "p": "1.0.0"}
	pnpmWeb := func(withQ bool, extra map[string]string) (string, artifactcache.Store) {
		o := sp("o", "1.0.0", map[string]string{"q": "2.0.0"}, nil)
		p := sp("p", "1.0.0", nil, map[string]string{"index.js": callsQ})
		q2 := qPkg("2.0.0")
		files := npmRoot(withQ)
		files["web/package.json"] = manifestWith("web", webImp, "")
		files["web/index.js"] = runsP
		files["web/"+pnpmLockFile] = pnpmLockText(t, "9.0", map[string]map[string]string{".": webImp}, o, p, q2)
		files["web/.npmrc"] = "hoist=false\n"
		maps.Copy(files, extra)
		return writeProgram(t, files), semStore(t, o, p, q2, qPkg("1.0.0"))
	}
	entry := func(l *depLayout, name string) *depEntry {
		for _, e := range l.entries() {
			if e.name == name && e.path != "" && strings.HasPrefix(e.path, "web/") {
				return e
			}
		}
		t.Fatalf("no %s entry in web/", name)
		return nil
	}
	versions := func(es []*depEntry) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.name+"@"+e.version)
		}
		sort.Strings(out)
		return out
	}
	pp := makePURL("p", "1.0.0")
	t.Run("pnpm_outer_copy", func(t *testing.T) {
		dir, store := pnpmWeb(true, nil)
		l := buildDepLayout(context.Background(), dir)
		p := entry(l, "p")
		if l.incomplete || l.lookup(p.path, "q") != nil || !slices.Equal(versions(l.lookupCandidates(p.path, "q")), []string{"q@1.0.0", "q@2.0.0"}) {
			t.Fatalf("p's phantom q may run the root's q@1.0.0 or the region's q@2.0.0; got %v", versions(l.lookupCandidates(p.path, "q")))
		}
		if cg := semRun(t, dir, store); reaches(cg, "q", "2.0.0") || !hasScopedTo(cg.Partiality, pp, originPURL("q")) {
			t.Errorf("no edge, a limit on p targeting q; got %+v", cg.Partiality)
		}
	})
	t.Run("pnpm_no_outer_copy", func(t *testing.T) {
		dir, store := pnpmWeb(false, nil)
		l := buildDepLayout(context.Background(), dir)
		if e := l.lookup(entry(l, "p").path, "q"); l.incomplete || e == nil || e.version != "2.0.0" {
			t.Fatalf("with nothing above the region the phantom resolves to its one copy")
		}
		if cg := semRun(t, dir, store); !reaches(cg, "q", "2.0.0") {
			t.Errorf("edge into q@2.0.0; got %+v", cg.Edges)
		}
	})
	t.Run("yarn_outer_copy_alias", func(t *testing.T) {
		o := sp("o", "1.0.0", map[string]string{"q": "npm:z@2.0.0"}, nil)
		p := sp("p", "1.0.0", nil, map[string]string{"index.js": callsQ})
		z := sp("z", "2.0.0", nil, map[string]string{"index.js": qGo})
		z.descs = []string{"q@npm:z@2.0.0"}
		files := npmRoot(true)
		files["web/package.json"] = manifestWith("web", webImp, "")
		files["web/index.js"] = runsP
		files["web/"+yarnLockFile] = yarnLockText(t, o, p, z)
		dir := writeProgram(t, files)
		l := buildDepLayout(context.Background(), dir)
		pe := entry(l, "p")
		if l.incomplete || l.lookup(pe.path, "q") != nil || !slices.Equal(versions(l.lookupCandidates(pe.path, "q")), []string{"q@1.0.0", "z@2.0.0"}) {
			t.Fatalf("p's phantom q may run the root's q or the region's z; got %v", versions(l.lookupCandidates(pe.path, "q")))
		}
		cg := semRun(t, dir, semStore(t, o, p, z, qPkg("1.0.0")))
		limited := slices.ContainsFunc(cg.Partiality.Scoped, func(s plugin.ScopedReason) bool {
			return s.Package == pp && slices.Contains(s.Targets, originPURL("q")) && slices.Contains(s.Targets, originPURL("z"))
		})
		if reaches(cg, "z", "2.0.0") || !limited {
			t.Errorf("no edge, a limit on p targeting q and z; got %+v", cg.Partiality)
		}
	})
	for name, extra := range map[string]map[string]string{
		"workspace_virtual_store_outside": {"web/pnpm-workspace.yaml": "virtualStoreDir: ../.pnpm-store\n"},
		"workspace_virtual_store_abs":     {"web/pnpm-workspace.yaml": "virtualStoreDir: /var/pnpm\n"},
		"workspace_modules_dir":           {"web/pnpm-workspace.yaml": "modulesDir: vendor\n"},
		"npmrc_virtual_store_outside":     {"web/.npmrc": "virtual-store-dir=../.pnpm-store\n"},
		"npmrc_modules_dir":               {"web/.npmrc": "modules-dir = vendor\n"},
		"workspace_virtual_store_dotdot":  {"web/pnpm-workspace.yaml": "virtualStoreDir: node_modules/../../store\n"},
		"workspace_virtual_store_env":     {"web/pnpm-workspace.yaml": "virtualStoreDir: node_modules/${STORE}\n"},
		"npmrc_virtual_store_env":         {"web/.npmrc": "virtual-store-dir=node_modules/$STORE\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, store := pnpmWeb(false, extra)
			if !buildDepLayout(context.Background(), dir).incomplete || !runWide(semRun(t, dir, store)) {
				t.Errorf("a store outside the region's node_modules withholds")
			}
		})
	}
	t.Run("virtual_store_inside", func(t *testing.T) {
		dir, _ := pnpmWeb(false, map[string]string{"web/pnpm-workspace.yaml": "virtualStoreDir: node_modules/.vs\nmodulesDir: node_modules\n"})
		if buildDepLayout(context.Background(), dir).incomplete {
			t.Errorf("a virtual store inside the region's node_modules reads")
		}
	})
}

func semKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// semRun builds dir's call graph with store's dependency code twice. The edges come from the
// build as written; the partiality comes from the same build with every first-party module
// emptied. A first-party load of a package always withholds run-wide in the base graph, so
// only the emptied build shows whether the dependency lane itself withholds.
func semRun(t *testing.T, dir string, store artifactcache.Store) plugin.CallGraphResult {
	t.Helper()
	loaded := withDeps(t, dir, store)
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && d.Name() == "node_modules":
			return filepath.SkipDir
		case !d.IsDir() && strings.HasSuffix(p, ".js"):
			return os.WriteFile(p, []byte(guardIdle), 0o644)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	idle := withDeps(t, dir, store)
	loaded.Partiality = idle.Partiality
	return loaded
}

// TestSemantic_G18OuterManifest: the walk out of a nested region is closed-world only over
// directories a lock installs for. A dependency-declaring package.json above the region that no
// lock covers may be installed with copies the lane never sees, and withholds; one a lock covers,
// or one that declares nothing, does not.
func TestSemantic_G18OuterManifest(t *testing.T) {
	imp := map[string]string{"o": "1.0.0", "p": "1.0.0"}
	nested := func(t *testing.T, region string, files map[string]string) (string, artifactcache.Store) {
		t.Helper()
		o := sp("o", "1.0.0", map[string]string{"q": "2.0.0"}, nil)
		p := sp("p", "1.0.0", nil, map[string]string{"index.js": callsQ})
		q2 := qPkg("2.0.0")
		files[region+"/package.json"] = manifestWith("web", imp, "")
		files[region+"/index.js"] = runsP
		files[region+"/"+pnpmLockFile] = pnpmLockText(t, "9.0", map[string]map[string]string{".": imp}, o, p, q2)
		files[region+"/.npmrc"] = "hoist=false\n"
		return writeProgram(t, files), semStore(t, o, p, q2)
	}
	emptyLock := `{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x"}}}`
	withholds := func(t *testing.T) func(string, artifactcache.Store) {
		return func(dir string, store artifactcache.Store) {
			t.Helper()
			if cg := semRun(t, dir, store); !buildDepLayout(context.Background(), dir).incomplete || !runWide(cg) {
				t.Errorf("an unaccounted directory above the region withholds; got %+v", cg.Partiality)
			}
		}
	}
	resolves := func(t *testing.T) func(string, artifactcache.Store) {
		return func(dir string, store artifactcache.Store) {
			t.Helper()
			if cg := semRun(t, dir, store); buildDepLayout(context.Background(), dir).incomplete || !reaches(cg, "q", "2.0.0") {
				t.Errorf("nothing unaccounted above the region: resolves to q@2.0.0; got %+v", cg.Partiality)
			}
		}
	}
	// Rows over directories above the region that no lock covers. Each map is the files beside
	// the region; a root lock (covered) is added unless the row writes its own root files. Script
	// rows run an opaque command the install veto cannot read as an install, so each pins the
	// scripts rule itself.
	locked := func(files map[string]string) map[string]string {
		if _, ok := files["package.json"]; !ok {
			files["package.json"] = `{"name":"app","private":true}`
			files["package-lock.json"] = emptyLock
		}
		return files
	}
	apps := func(manifest string) map[string]string {
		return locked(map[string]string{"apps/package.json": manifest})
	}
	for name, tc := range map[string]struct {
		region string
		files  map[string]string
	}{
		"root_manifest_no_lock":            {"web", map[string]string{"package.json": manifestWith("app", map[string]string{"q": "1.0.0"}, "")}},
		"root_deps_absent_intermediate":    {"apps/web", map[string]string{"package.json": manifestWith("app", map[string]string{"q": "1.0.0"}, "")}},
		"root_workspaces":                  {"web", map[string]string{"package.json": `{"name":"app","private":true,"workspaces":["packages/*"]}`, "packages/a/package.json": manifestWith("a", map[string]string{"q": "1.0.0"}, "")}},
		"root_pnpm_workspace":              {"web", map[string]string{"package.json": `{"name":"app","private":true}`, "pnpm-workspace.yaml": "packages:\n  - packages/*\n", ".npmrc": "shamefully-hoist=true\n", "packages/a/package.json": manifestWith("a", map[string]string{"q": "1.0.0"}, "")}},
		"root_pnpm_workspace_only":         {"web", map[string]string{"package.json": `{"name":"app","private":true}`, "pnpm-workspace.yaml": "packages:\n  - packages/*\n"}},
		"intermediate_manifest_no_lock":    {"apps/web", apps(manifestWith("apps", map[string]string{"q": "1.0.0"}, ""))},
		"intermediate_dev_dependencies":    {"apps/web", apps(`{"name":"apps","devDependencies":{"q":"1.0.0"}}`)},
		"intermediate_optional_deps":       {"apps/web", apps(`{"name":"apps","optionalDependencies":{"q":"1.0.0"}}`)},
		"intermediate_peer_dependencies":   {"apps/web", apps(`{"name":"apps","peerDependencies":{"q":"1.0.0"}}`)},
		"intermediate_workspaces":          {"apps/web", locked(map[string]string{"apps/package.json": `{"name":"apps","private":true,"workspaces":["lib"]}`, "apps/lib/package.json": manifestWith("lib", map[string]string{"q": "1.0.0"}, "")})},
		"intermediate_malformed":           {"apps/web", apps(`{"name":"apps",`)},
		"intermediate_unknown_key":         {"apps/web", apps(`{"name":"apps","overrides":{"q":"1.0.0"}}`)},
		"intermediate_install_script":      {"apps/web", apps(`{"name":"apps","scripts":{"postinstall":"node setup.js"}}`)},
		"intermediate_npmrc":               {"apps/web", locked(map[string]string{"apps/package.json": `{"name":"apps","private":true}`, "apps/.npmrc": "x=y\n"})},
		"intermediate_installed_on_disk":   {"apps/web", locked(map[string]string{"apps/node_modules/q/package.json": `{"name":"q","version":"1.0.0"}`})},
		"intermediate_pnpmfile":            {"apps/web", locked(map[string]string{"apps/package.json": `{"name":"apps","private":true}`, "apps/.pnpmfile.cjs": "module.exports = {}\n"})},
		"intermediate_empty_dependencies":  {"apps/web", apps(`{"name":"apps","dependencies":{}}`)},
		"intermediate_pnpm_dev_preinstall": {"apps/web", apps(`{"name":"apps","scripts":{"pnpm:devPreinstall":"node setup.js"}}`)},
		"intermediate_namespaced_script":   {"apps/web", apps(`{"name":"apps","scripts":{"yarn:bootstrap":"node setup.js"}}`)},
		"intermediate_pre_script":          {"apps/web", apps(`{"name":"apps","scripts":{"prebuild":"node setup.js"}}`)},
		"intermediate_post_script":         {"apps/web", apps(`{"name":"apps","scripts":{"posttest":"node setup.js"}}`)},
		"intermediate_prepare":             {"apps/web", apps(`{"name":"apps","scripts":{"prepare":"node setup.js"}}`)},
		"intermediate_install_hook":        {"apps/web", apps(`{"name":"apps","scripts":{"install":"node setup.js"}}`)},
		"intermediate_dependencies_hook":   {"apps/web", apps(`{"name":"apps","scripts":{"dependencies":"node setup.js"}}`)},
		"intermediate_binding_gyp":         {"apps/web", locked(map[string]string{"apps/package.json": `{"name":"apps","private":true}`, "apps/binding.gyp": "{'targets':[]}\n"})},
		"root_binding_gyp_no_lock":         {"web", map[string]string{"package.json": `{"name":"app","private":true}`, "binding.gyp": "{'targets':[]}\n"}},
		"intermediate_package_yaml":        {"apps/web", locked(map[string]string{"apps/package.yaml": "name: apps\ndependencies:\n  q: 1.0.0\n"})},
		"intermediate_package_json5":       {"apps/web", locked(map[string]string{"apps/package.json5": "{name: 'apps', dependencies: {q: '1.0.0'}}\n"})},
		"root_package_yaml_no_json":        {"web", map[string]string{"package.yaml": "name: app\ndependencies:\n  q: 1.0.0\n"}},
		"intermediate_npmrc_node_linker":   {"apps/web", locked(map[string]string{"apps/.npmrc": "registry=https://npm.acme.dev/\nnode-linker=hoisted\n"})},
		"intermediate_npmrc_peer_keys":     {"apps/web", locked(map[string]string{"apps/.npmrc": "registry=https://npm.acme.dev/\nlegacy-peer-deps=true\n"})},
		"intermediate_pnpm_key":            {"apps/web", apps(`{"name":"apps","private":true,"pnpm":{"neverBuiltDependencies":[]}}`)},
		"root_npmrc_hoist":                 {"web", map[string]string{"package.json": `{"name":"app","private":true}`, ".npmrc": "registry=https://npm.acme.dev/\npublic-hoist-pattern[]=*\n"}},
		"root_npmrc_unparseable":           {"web", map[string]string{"package.json": `{"name":"app","private":true}`, ".npmrc": "\"${HOIST}\"=true\n"}},
		// A build may run on a case-insensitive filesystem, where the package manager finds
		// these under their usual names.
		"intermediate_binding_gyp_case":  {"apps/web", locked(map[string]string{"apps/package.json": `{"name":"apps","private":true}`, "apps/Binding.gyp": "{'targets':[]}\n"})},
		"intermediate_package_yaml_case": {"apps/web", locked(map[string]string{"apps/Package.yaml": "name: apps\n"})},
		"intermediate_pnpmfile_case":     {"apps/web", locked(map[string]string{"apps/package.json": `{"name":"apps","private":true}`, "apps/.PNPMFILE.cjs": "module.exports = {}\n"})},
		"intermediate_npmrc_case":        {"apps/web", locked(map[string]string{"apps/.NPMRC": "registry=https://npm.acme.dev/\n"})},
		"intermediate_manifest_case":     {"apps/web", locked(map[string]string{"apps/Package.json": `{"name":"apps","private":true}`})},
	} {
		t.Run(name, func(t *testing.T) { withholds(t)(nested(t, tc.region, tc.files)) })
	}
	t.Run("intermediate_manifest_unreadable", func(t *testing.T) {
		dir, store := nested(t, "apps/web", apps(`{"name":"apps"}`))
		m := filepath.Join(dir, "apps", "package.json")
		if err := os.Chmod(m, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(m, 0o644) })
		withholds(t)(dir, store)
	})
	for name, files := range map[string]map[string]string{
		"absent_intermediate":         locked(map[string]string{}),
		"intermediate_name_private":   apps(`{"name":"apps","private":true}`),
		"intermediate_inert_metadata": apps(`{"name":"apps","version":"1.0.0","private":true,"type":"module","engines":{"node":">=20"},"scripts":{"build":"tsc"},"packageManager":"npm@11.0.0"}`),
		"intermediate_tool_config":    apps(`{"name":"apps","private":true,"prettier":{"semi":false},"browserslist":["defaults"],"eslintConfig":{"root":true}}`),
		"intermediate_npmrc_registry": locked(map[string]string{"apps/.npmrc": "@acme:registry=https://npm.acme.dev/\n//npm.acme.dev/:_authToken=${NPM_TOKEN}\nstrict-ssl=true\n"}),
	} {
		t.Run(name, func(t *testing.T) { resolves(t)(nested(t, "apps/web", files)) })
	}
	t.Run("root_npmrc_registry", func(t *testing.T) {
		resolves(t)(nested(t, "web", map[string]string{
			"package.json": `{"name":"app","private":true}`,
			".npmrc":       "registry=https://npm.acme.dev/\n@acme:registry=https://npm.acme.dev/\n",
		}))
	})
	t.Run("intermediate_pnpm_importer", func(t *testing.T) {
		sPkg := sp("s", "1.0.0", nil, nil)
		resolves(t)(nested(t, "apps/web", map[string]string{
			"package.json":        `{"name":"app","private":true}`,
			"pnpm-workspace.yaml": "packages:\n  - apps\n",
			pnpmLockFile:          pnpmLockText(t, "9.0", map[string]map[string]string{".": {}, "apps": {"s": "1.0.0"}}, sPkg),
			"apps/package.json":   manifestWith("apps", map[string]string{"s": "1.0.0"}, ""),
		}))
	})
	t.Run("intermediate_npm_workspace", func(t *testing.T) {
		resolves(t)(nested(t, "apps/web", map[string]string{
			"package.json":      `{"name":"app","private":true,"workspaces":["apps"]}`,
			"package-lock.json": `{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","workspaces":["apps"]},"apps":{"name":"apps","dependencies":{"r":"1.0.0"}},"node_modules/apps":{"resolved":"apps","link":true}}}`,
			"apps/package.json": manifestWith("apps", map[string]string{"r": "1.0.0"}, ""),
		}))
	})
}

// TestSemantic_LayoutVeto: the install veto reaches the pnpm and yarn classic layout readers. A
// script that may install a package no lock records leaves a read semantic layout incomplete, so
// the call graph withholds run-wide; each control resolves through the same layout.
func TestSemantic_LayoutVeto(t *testing.T) {
	const postinstall = `,"scripts":{"postinstall":"npm install --no-save q@2.0.0"}`
	ci := map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: npm install q@2.0.0\n")}
	for _, mgr := range []string{"pnpm", "yarn"} {
		for name, tc := range map[string]struct {
			extra    string
			files    map[string]string
			withheld bool
		}{
			"ci_install":  {"", ci, true},
			"postinstall": {postinstall, nil, true},
			"control":     {"", nil, false},
		} {
			t.Run(mgr+"_"+name, func(t *testing.T) {
				q := qPkg("1.0.0")
				p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
				lockName, lock := pnpmLockFile, pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}}, p, q)
				if mgr == "yarn" {
					lockName, lock = yarnLockFile, yarnLockText(t, p, q)
				}
				files := map[string]string{"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, tc.extra)}
				maps.Copy(files, tc.files)
				dir := semProgram(t, lockName, lock, files)
				cg := semRun(t, dir, semStore(t, p, q))
				incomplete := buildDepLayout(context.Background(), dir).incomplete
				if tc.withheld && (!incomplete || !runWide(cg)) {
					t.Errorf("a vetoed %s build withholds through the layout; incomplete=%v got %+v", mgr, incomplete, cg.Partiality)
				}
				if !tc.withheld && (incomplete || runWide(cg) || !reaches(cg, "q", "1.0.0")) {
					t.Errorf("control resolves q@1.0.0 through the %s layout; incomplete=%v got %+v", mgr, incomplete, cg.Partiality)
				}
			})
		}
	}
}

// TestSemantic_DepBindingGyp: a pnpm or yarn classic package that ships a binding.gyp and sets no
// install or preinstall script gets `node-gyp rebuild` at install, an install script the lock
// does not mark, so it withholds run-wide like an explicit one.
func TestSemantic_DepBindingGyp(t *testing.T) {
	for _, mgr := range []string{"pnpm", "yarn"} {
		for name, gypName := range map[string]string{"binding_gyp": "binding.gyp", "binding_gyp_case": "Binding.gyp", "control": ""} {
			t.Run(mgr+"_"+name, func(t *testing.T) {
				q := qPkg("1.0.0")
				pFiles := map[string]string{"index.js": callsQ}
				gyp := gypName != ""
				if gyp {
					pFiles[gypName] = "{'targets':[]}\n"
				}
				p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, pFiles)
				lockName, lock := pnpmLockFile, pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}}, p, q)
				if mgr == "yarn" {
					lockName, lock = yarnLockFile, yarnLockText(t, p, q)
				}
				dir := semProgram(t, lockName, lock, map[string]string{"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, "")})
				cg := semRun(t, dir, semStore(t, p, q))
				if gyp && !runWide(cg) {
					t.Errorf("a %s package with a binding.gyp and no install script withholds run-wide; got %+v", mgr, cg.Partiality)
				}
				if !gyp && (runWide(cg) || !reaches(cg, "q", "1.0.0")) {
					t.Errorf("control resolves q@1.0.0 through the %s layout; got %+v", mgr, cg.Partiality)
				}
			})
		}
	}
}

// TestSemantic_PnpmAltManifest: pnpm installs a region root or member from package.yaml or
// package.json5 when it has no package.json. The lane reads neither, so a region holding one
// withholds, beside a package.json (the root row) or alone (the member row).
func TestSemantic_PnpmAltManifest(t *testing.T) {
	for _, alt := range []string{"package.yaml", "package.json5"} {
		for name, files := range map[string]map[string]string{
			"root":        {alt: "name: app\n"},
			"member":      {"package.json": `{"name":"app","private":true}`, "pnpm-workspace.yaml": "packages:\n  - lib\n", "lib/" + alt: "name: lib\n"},
			"member_case": {"package.json": `{"name":"app","private":true}`, "pnpm-workspace.yaml": "packages:\n  - lib\n", "lib/P" + alt[1:]: "name: lib\n"},
		} {
			t.Run(alt+"_"+name, func(t *testing.T) {
				q := qPkg("1.0.0")
				p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
				importers := map[string]map[string]string{".": {"p": "1.0.0"}}
				if name != "root" {
					importers["lib"] = map[string]string{}
				}
				dir := semProgram(t, pnpmLockFile, pnpmLockText(t, "9.0", importers, p, q), files)
				cg := semRun(t, dir, semStore(t, p, q))
				if !buildDepLayout(context.Background(), dir).incomplete || !runWide(cg) {
					t.Errorf("a pnpm region with an unread %s withholds; got %+v", alt, cg.Partiality)
				}
			})
		}
	}
}

// TestSemantic_WorkspaceGlobs: the lane reads two workspace pattern shapes, a literal path and a
// literal prefix with one trailing "/*". Every other shape withholds for pnpm and yarn classic,
// one row per class, each a pattern the tool would read to select packages/a; so does a
// selection the lane can't show equal to the tool's (a pattern path in another case, a
// dot-named or node_modules/bower_components entry, a manifest in another case).
func TestSemantic_WorkspaceGlobs(t *testing.T) {
	type row struct {
		globs    []string
		member   string
		manifest string
		extra    string
		resolves bool
	}
	pkgA := func(globs ...string) row { return row{globs: globs, member: "packages/a"} }
	rows := map[string]row{
		"control_star":         {globs: []string{"packages/*"}, member: "packages/a", extra: "packages/docs/README.md", resolves: true},
		"control_literal":      {globs: []string{"packages/a"}, member: "packages/a", resolves: true},
		"negation":             pkgA("packages/*", "!packages/z"),
		"globstar":             pkgA("packages/**"),
		"star_affix":           pkgA("packages/a*"),
		"inner_star":           pkgA("pack*/a"),
		"braces":               pkgA("packages/{a,b}"),
		"extglob":              pkgA("packages/@(a|z)"),
		"bracket":              pkgA("packages/[a]"),
		"backslash":            pkgA("packages\\a"),
		"outside_root":         pkgA("packages/*", "../shared"),
		"absolute":             pkgA("/packages/a"),
		"dot_prefix":           pkgA("./packages/*"),
		"dot_segment":          pkgA("packages/./a"),
		"empty_segment":        pkgA("packages//a"),
		"trailing_slash":       pkgA("packages/a/"),
		"node_modules_segment": pkgA("packages/*", "node_modules/*"),
		"bower_segment":        pkgA("packages/*", "bower_components/*"),
		"question":             pkgA("packages/?"),
		"case_differs":         pkgA("Packages/*"),
		"literal_case":         pkgA("Packages/a"),
		"dot_directory":        {globs: []string{"packages/*"}, member: "packages/.a"},
		"manifest_case":        {globs: []string{"packages/*"}, member: "packages/a", manifest: "Package.json"},
		"yarn_json_member":     {globs: []string{"packages/*"}, member: "packages/a", manifest: "yarn.json"},
		"node_modules_entry":   {globs: []string{"packages/*"}, member: "packages/a", extra: "packages/node_modules/x/package.json"},
		"bower_entry":          {globs: []string{"packages/*"}, member: "packages/a", extra: "packages/bower_components/x/package.json"},
	}
	for _, mgr := range []string{"pnpm", "yarn"} {
		for name, tc := range rows {
			t.Run(mgr+"_"+name, func(t *testing.T) {
				q := qPkg("1.0.0")
				p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
				manifest := cmp.Or(tc.manifest, "package.json")
				files := map[string]string{tc.member + "/" + manifest: `{"name":"a","version":"1.0.0"}`}
				if tc.extra != "" {
					files[tc.extra] = `{"name":"x","version":"1.0.0"}`
				}
				lockName, lock := yarnLockFile, yarnLockText(t, p, q)
				if mgr == "pnpm" {
					quoted := make([]string, len(tc.globs))
					for i, g := range tc.globs {
						quoted[i] = "  - '" + g + "'\n"
					}
					files["pnpm-workspace.yaml"] = "packages:\n" + strings.Join(quoted, "")
					lockName, lock = pnpmLockFile, pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}, tc.member: {}}, p, q)
				} else {
					ws, _ := json.Marshal(tc.globs)
					files["package.json"] = manifestWith("app", map[string]string{"p": "1.0.0"}, `,"private":true,"workspaces":`+string(ws))
				}
				dir := semProgram(t, lockName, lock, files)
				cg := semRun(t, dir, semStore(t, p, q))
				incomplete := buildDepLayout(context.Background(), dir).incomplete
				if tc.resolves {
					if incomplete || runWide(cg) || !reaches(cg, "q", "1.0.0") {
						t.Errorf("%s workspace globs %q resolve q@1.0.0; got %+v", mgr, tc.globs, cg.Partiality)
					}
					return
				}
				if !incomplete || !runWide(cg) {
					t.Errorf("%s workspace globs %q the lane can't show it reads as the tool does withhold; got %+v", mgr, tc.globs, cg.Partiality)
				}
			})
		}
	}
}

// TestSemantic_PnpmDotMember: a pnpm packages entry that is exactly "." names the root, which
// pnpm always takes, so it adds no member and the rest of the list reads as before. Every other
// dot form withholds, as does "." in yarn classic workspaces (yarn links the root into its own
// node_modules). Each tree holds tools/b, unselected, declaring a dependency the lock installs
// nothing for, so a member set read too wide withholds rather than passes; the same trap on a
// selected member (dot_plus_star_unlocked_member) shows the member set reaches that check.
func TestSemantic_PnpmDotMember(t *testing.T) {
	for name, tc := range map[string]struct {
		ws       string
		members  []string
		resolves bool
	}{
		"control_dot_root_only":         {ws: "packages:\n  - '.'\n", members: []string{}, resolves: true},
		"control_dot_plus_star":         {ws: "packages:\n  - .\n  - 'packages/*'\n", members: []string{"packages/a"}, resolves: true},
		"control_star_plus_dot":         {ws: "packages:\n  - 'packages/*'\n  - '.'\n", members: []string{"packages/a"}, resolves: true},
		"dot_plus_star_unlocked_member": {ws: "packages:\n  - .\n  - 'packages/*'\n"},
		"dotdot":                        {ws: "packages:\n  - '..'\n"},
		"dot_slash":                     {ws: "packages:\n  - './'\n"},
		"dot_slash_dot":                 {ws: "packages:\n  - './.'\n"},
		"member_dot":                    {ws: "packages:\n  - 'packages/.'\n"},
		"dot_star":                      {ws: "packages:\n  - './*'\n"},
	} {
		t.Run(name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			q := qPkg("1.0.0")
			importers := map[string]map[string]string{".": {"p": "1.0.0"}}
			if slices.Contains(tc.members, "packages/a") {
				importers["packages/a"] = map[string]string{"q": "1.0.0"}
			}
			lock := pnpmLockText(t, "9.0", importers, p, q)
			dir := semProgram(t, pnpmLockFile, lock, map[string]string{
				"pnpm-workspace.yaml":     tc.ws,
				"packages/a/package.json": manifestWith("a", map[string]string{"q": "1.0.0"}, ""),
				"tools/b/package.json":    manifestWith("b", map[string]string{"absent-package": "1.0.0"}, ""),
			})
			cfg, ok := readPnpmConfig(dir)
			cg := semRun(t, dir, semStore(t, p, q))
			incomplete := buildDepLayout(context.Background(), dir).incomplete
			if tc.resolves && (!ok || !slices.Equal(cfg.members, tc.members) || incomplete || runWide(cg) || !reaches(cg, "q", "1.0.0")) {
				t.Errorf("%q places the region with members %v; ok=%v cfg=%+v incomplete=%v got %+v", tc.ws, tc.members, ok, cfg, incomplete, cg.Partiality)
			}
			if !tc.resolves && (!incomplete || !runWide(cg)) {
				t.Errorf("%q withholds; ok=%v incomplete=%v got %+v", tc.ws, ok, incomplete, cg.Partiality)
			}
		})
	}
	t.Run("yarn_dot", func(t *testing.T) {
		p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
		q := qPkg("1.0.0")
		dir := semProgram(t, yarnLockFile, yarnLockText(t, p, q), map[string]string{
			"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, `,"private":true,"workspaces":["."]`),
		})
		cg := semRun(t, dir, semStore(t, p, q))
		if incomplete := buildDepLayout(context.Background(), dir).incomplete; !incomplete || !runWide(cg) {
			t.Errorf("yarn classic workspaces [\".\"] withholds; incomplete=%v got %+v", incomplete, cg.Partiality)
		}
	})
}

// TestSemantic_PnpmImporterCoversDeclared: a pnpm region is read only when every importer is one
// pnpm's satisfiesPackageManifest takes as up to date with its manifest: the same names in each
// field after pnpm's precedence, the same specifiers, dependenciesMeta and publishDirectory, no
// key the lane does not compare, and each locked version inside its range. In every row p
// depends on q@1.0.0, so the lock pins q@1.0.0 for p; an importer that disagrees with its
// manifest is one pnpm re-resolves on any install that is not frozen, and the lane would
// otherwise place q at a copy the build does not install. Each shape runs for a root-only project
// and for a workspace member; rootManifest and rootImp replace the root's in the member run.
func TestSemantic_PnpmImporterCoversDeclared(t *testing.T) {
	type dep = pnpmImporterDep
	pOnly := []dep{{"dependencies", "p", "1.0.0", "1.0.0"}}
	for name, tc := range map[string]struct {
		manifest string // the fields of the declaring package.json after name and version
		imp      []dep
		idle     bool                          // the declaring project loads nothing
		edit     func(lock, dir string) string // applied to the lock text; dir is the importer's
		// rootManifest and rootImp are the workspace root's fields and importer in the member run.
		rootManifest string
		rootImp      []dep
		placed       bool
		reachesQ     bool
	}{
		"control_exact": {
			manifest: `"dependencies":{"p":"^1.0.0"},"devDependencies":{"q":"1.0.0"},"optionalDependencies":{"o":"~1.0.0"}`,
			imp:      []dep{{"dependencies", "p", "^1.0.0", "1.0.0"}, {"devDependencies", "q", "1.0.0", "1.0.0"}, {"optionalDependencies", "o", "~1.0.0", "1.0.0"}},
			placed:   true, reachesQ: true,
		},
		"control_no_deps": {manifest: `"description":"no dependencies"`, idle: true, placed: true},
		"control_dependencies_over_dev": {
			manifest: `"dependencies":{"p":"1.0.0","q":"1.0.0"},"devDependencies":{"q":"2.0.0"}`,
			imp:      append(slices.Clone(pOnly), dep{"dependencies", "q", "1.0.0", "1.0.0"}),
			placed:   true, reachesQ: true,
		},
		"control_optional_over_dependencies": {
			manifest: `"dependencies":{"p":"1.0.0","q":"2.0.0"},"optionalDependencies":{"q":"1.0.0"}`,
			imp:      append(slices.Clone(pOnly), dep{"optionalDependencies", "q", "1.0.0", "1.0.0"}),
			placed:   true, reachesQ: true,
		},
		"control_peer_also_dev": {
			manifest: `"dependencies":{"p":"1.0.0"},"devDependencies":{"q":"1.0.0"},"peerDependencies":{"q":"^1.0.0"}`,
			imp:      append(slices.Clone(pOnly), dep{"devDependencies", "q", "1.0.0", "1.0.0"}),
			placed:   true, reachesQ: true,
		},
		"missing_dependency":         {manifest: `"dependencies":{"p":"1.0.0","q":"2.0.0"}`, imp: pOnly},
		"missing_devDependency":      {manifest: `"dependencies":{"p":"1.0.0"},"devDependencies":{"q":"2.0.0"}`, imp: pOnly},
		"missing_optionalDependency": {manifest: `"dependencies":{"p":"1.0.0"},"optionalDependencies":{"q":"2.0.0"}`, imp: pOnly},
		"missing_only_dependency":    {manifest: `"devDependencies":{"q":"2.0.0"}`},
		"specifier_mismatch":         {manifest: `"dependencies":{"p":"^1.0.0"}`, imp: pOnly},
		"field_mismatch": {
			manifest: `"dependencies":{"p":"1.0.0"},"devDependencies":{"q":"1.0.0"}`,
			imp:      append(slices.Clone(pOnly), dep{"dependencies", "q", "1.0.0", "1.0.0"}),
		},
		"specifier_absent": {
			manifest: `"dependencies":{"p":""}`, imp: []dep{{"dependencies", "p", "", "1.0.0"}},
			edit: func(s, _ string) string { return strings.Replace(s, "        specifier: ''\n", "", 1) },
		},
		"extra_name": {
			manifest: `"dependencies":{"p":"1.0.0"}`, imp: append(slices.Clone(pOnly), dep{"dependencies", "q", "1.0.0", "1.0.0"}),
			rootManifest: `"dependencies":{"q":"2.0.0"}`, rootImp: []dep{{"dependencies", "q", "2.0.0", "2.0.0"}},
		},
		"extra_name_no_specifier": {
			manifest: `"dependencies":{"p":"1.0.0"}`, imp: append(slices.Clone(pOnly), dep{"dependencies", "q", "QSPEC", "2.0.0"}),
			edit: func(s, _ string) string { return strings.Replace(s, "        specifier: 'QSPEC'\n", "", 1) },
		},
		"extra_name_no_deps": {manifest: `"description":"no dependencies"`, idle: true, imp: []dep{{"dependencies", "q", "1.0.0", "1.0.0"}}},
		"duplicate_field": {
			manifest: `"dependencies":{"p":"1.0.0","q":"1.0.0"}`,
			imp:      append(slices.Clone(pOnly), dep{"dependencies", "q", "1.0.0", "1.0.0"}, dep{"devDependencies", "q", "2.0.0", "2.0.0"}),
		},
		"duplicate_field_same_spec": {
			manifest: `"dependencies":{"p":"1.0.0","q":"1.0.0"}`,
			imp:      append(slices.Clone(pOnly), dep{"dependencies", "q", "1.0.0", "1.0.0"}, dep{"devDependencies", "q", "1.0.0", "1.0.0"}),
		},
		"fields_swapped": {
			manifest: `"dependencies":{"p":"1.0.0"},"devDependencies":{"q":"1.0.0"}`,
			imp:      []dep{{"dependencies", "q", "1.0.0", "1.0.0"}, {"devDependencies", "p", "1.0.0", "1.0.0"}},
		},
		"empty_dependency_claims_nothing": {
			manifest: `"dependencies":{"p":"1.0.0","q":""},"devDependencies":{"q":"1.0.0"}`,
			imp:      append(slices.Clone(pOnly), dep{"dependencies", "q", "", "1.0.0"}),
		},
		"empty_specifier_claims_nothing": {
			manifest: `"dependencies":{"p":"1.0.0","q":""},"optionalDependencies":{"q":""}`,
			imp:      append(slices.Clone(pOnly), dep{"optionalDependencies", "q", "", "1.0.0"}),
		},
		"duplicate_field_empty_specifiers": {
			manifest: `"dependencies":{"p":"1.0.0","q":""},"optionalDependencies":{"q":""}`,
			imp:      append(slices.Clone(pOnly), dep{"optionalDependencies", "q", "", "1.0.0"}, dep{"dependencies", "q", "", "2.0.0"}),
		},
		"specifier_yaml_float": {
			manifest: `"dependencies":{"p":"1.0"}`, imp: []dep{{"dependencies", "p", "1.0", "1.0.0"}},
			edit: func(s, _ string) string { return strings.Replace(s, "specifier: '1.0'", "specifier: 1.0", 1) },
		},
		"control_specifier_quoted_number": {
			manifest: `"dependencies":{"p":"1.0"}`, imp: []dep{{"dependencies", "p", "1.0", "1.0.0"}},
			placed: true, reachesQ: true,
		},
		"control_specifier_plain_string": {
			manifest: `"dependencies":{"p":"^1.0.0"}`, imp: []dep{{"dependencies", "p", "^1.0.0", "1.0.0"}},
			edit:   func(s, _ string) string { return strings.Replace(s, "specifier: '^1.0.0'", "specifier: ^1.0.0", 1) },
			placed: true, reachesQ: true,
		},
		"injected_mismatch": {manifest: `"dependencies":{"p":"1.0.0"},"dependenciesMeta":{"p":{"injected":true}}`, imp: pOnly},
		"injected_quoted": {
			manifest: `"dependencies":{"p":"1.0.0"},"dependenciesMeta":{"p":{"injected":true}}`, imp: pOnly,
			edit: pnpmImporterLines("    dependenciesMeta:\n      p:\n        injected: 'true'\n"),
		},
		"control_injected_equal": {
			manifest: `"dependencies":{"p":"1.0.0"},"dependenciesMeta":{"p":{"injected":true}}`, imp: pOnly,
			edit:   pnpmImporterLines("    dependenciesMeta:\n      p:\n        injected: true\n"),
			placed: true, reachesQ: true,
		},
		"meta_quoted_empty": {
			manifest: `"dependencies":{"p":"1.0.0"}`, imp: pOnly,
			edit: pnpmImporterLines("    dependenciesMeta: ''\n"),
		},
		"meta_entry_quoted_map": {
			manifest: `"dependencies":{"p":"1.0.0"},"dependenciesMeta":{"p":{}}`, imp: pOnly,
			edit: pnpmImporterLines("    dependenciesMeta:\n      p: '{}'\n"),
		},
		"control_meta_empty": {
			manifest: `"dependencies":{"p":"1.0.0"}`, imp: pOnly,
			edit:   pnpmImporterLines("    dependenciesMeta: {}\n"),
			placed: true, reachesQ: true,
		},
		"unknown_importer_key": {manifest: `"dependencies":{"p":"1.0.0"}`, imp: pOnly, edit: pnpmImporterLines("    futureField: x\n")},
		"publish_directory_mismatch": {
			manifest: `"dependencies":{"p":"1.0.0"},"publishConfig":{"directory":"dist"}`, imp: pOnly,
			edit: pnpmImporterLines("    publishDirectory: lib\n"),
		},
		"publish_directory_yaml_null": {
			manifest: `"dependencies":{"p":"1.0.0"},"publishConfig":{"directory":"null"}`, imp: pOnly,
			edit: pnpmImporterLines("    publishDirectory: null\n"),
		},
		"publish_directory_yaml_bool": {
			manifest: `"dependencies":{"p":"1.0.0"},"publishConfig":{"directory":"true"}`, imp: pOnly,
			edit: pnpmImporterLines("    publishDirectory: true\n"),
		},
		"control_publish_directory_quoted": {
			manifest: `"dependencies":{"p":"1.0.0"},"publishConfig":{"directory":"1.0"}`, imp: pOnly,
			edit:   pnpmImporterLines("    publishDirectory: '1.0'\n"),
			placed: true, reachesQ: true,
		},
		"publish_directory_unrecorded": {manifest: `"dependencies":{"p":"1.0.0"},"publishConfig":{"directory":"dist"}`, imp: pOnly},
		"control_publish_directory": {
			manifest: `"dependencies":{"p":"1.0.0"},"publishConfig":{"directory":"dist"}`, imp: pOnly,
			edit:   pnpmImporterLines("    publishDirectory: dist\n"),
			placed: true, reachesQ: true,
		},
		"version_outside_range": {manifest: `"dependencies":{"p":"^2.0.0"}`, imp: []dep{{"dependencies", "p", "^2.0.0", "1.0.0"}}},
		"bare_peer":             {manifest: `"dependencies":{"p":"1.0.0"},"peerDependencies":{"q":"^2.0.0"}`, imp: pOnly},
	} {
		for _, member := range []string{"", "packages/m"} {
			t.Run(name+"/"+cmp.Or(member, "root"), func(t *testing.T) {
				p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
				q, q2, o := qPkg("1.0.0"), qPkg("2.0.0"), sp("o", "1.0.0", nil, nil)
				code := "require('q').go();\nrequire('p').run();\n"
				if tc.idle {
					code = ""
				}
				declaring := `{"name":"app","version":"1.0.0",` + tc.manifest + `}`
				importers := map[string][]dep{".": tc.imp}
				files := map[string]string{"package.json": declaring, "index.js": code}
				if member != "" {
					importers = map[string][]dep{".": tc.rootImp, member: tc.imp}
					files = map[string]string{
						"pnpm-workspace.yaml":    "packages:\n  - 'packages/*'\n",
						"package.json":           `{"name":"root","version":"1.0.0","private":true` + semJoin(tc.rootManifest) + `}`,
						"index.js":               "",
						member + "/package.json": declaring,
						member + "/index.js":     code,
					}
				}
				pkgs := []*semPkg{p, q, o}
				if slices.ContainsFunc(slices.Concat(importers["."], importers[member]), func(d dep) bool { return d.version == "2.0.0" }) {
					pkgs = append(pkgs, q2) // a lock pinning q@2.0.0 records it, so the reader can place the importer
				}
				lock := pnpmLockImporters(t, importers, pkgs...)
				if tc.edit != nil {
					edited := tc.edit(lock, cmp.Or(member, "."))
					if edited == lock {
						t.Fatal("edit changed nothing")
					}
					lock = edited
				}
				dir := semProgram(t, pnpmLockFile, lock, files)
				cg := semRun(t, dir, semStore(t, pkgs...))
				incomplete := buildDepLayout(context.Background(), dir).incomplete
				if tc.placed && (incomplete || runWide(cg) || tc.reachesQ != reaches(cg, "q", "1.0.0")) {
					t.Errorf("places the region; incomplete=%v reaches q@1.0.0=%v got %+v", incomplete, reaches(cg, "q", "1.0.0"), cg.Partiality)
				}
				if !tc.placed && (!incomplete || !runWide(cg)) {
					t.Errorf("withholds; incomplete=%v reaches q@1.0.0=%v got %+v", incomplete, reaches(cg, "q", "1.0.0"), cg.Partiality)
				}
			})
		}
	}
}

// TestPnpmVersionInRange: pnpm 10 and 11 reject an importer whose locked release version falls
// outside its semver-range specifier. A version equal to its specifier, a prerelease included,
// satisfies it; a form the lane does not model withholds.
func TestPnpmVersionInRange(t *testing.T) {
	for _, tc := range []struct {
		version, spec string
		want          bool
	}{
		{"1.2.0", "^1.0.0", true},
		{"2.0.0", "^1.0.0", false},
		{"0.1.0-rc2(supports-color@10.2.2)", "0.1.0-rc2", true},
		{"0.1.0-rc3", "0.1.0-rc2", false},
		{"link:../x", "workspace:*", true},
		{"1.0.0", "latest", false},
	} {
		if got := pnpmVersionInRange(tc.version, tc.spec); got != tc.want {
			t.Errorf("pnpmVersionInRange(%q, %q) = %v, want %v", tc.version, tc.spec, got, tc.want)
		}
	}
}

// TestSemantic_PnpmImporterCovers54: a 5.4 lock keeps its specifiers apart from the resolved
// entries, so a declared name the lock specifies but never resolves is missing from the importer.
func TestSemantic_PnpmImporterCovers54(t *testing.T) {
	p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
	q := qPkg("1.0.0")
	lock := pnpmLockText(t, "5.4", map[string]map[string]string{".": {"p": "1.0.0"}}, p, q)
	if lock = strings.Replace(lock, "specifiers:\n", "specifiers:\n  q: '1.0.0'\n", 1); !strings.Contains(lock, "  q: '1.0.0'\n") {
		t.Fatal("specifier not added")
	}
	dir := semProgram(t, pnpmLockFile, lock, map[string]string{
		"package.json": manifestWith("app", map[string]string{"p": "1.0.0", "q": "1.0.0"}, ""),
	})
	cg := semRun(t, dir, semStore(t, p, q))
	if !buildDepLayout(context.Background(), dir).incomplete || !runWide(cg) {
		t.Errorf("q is specified but never resolved; the region must withhold, got %+v", cg.Partiality)
	}
}

// TestSemantic_PnpmSpecifierTyped54: a 5.4 specifier pnpm reads as a number is no specifier to
// it, so the importer differs from the manifest; the quoted spelling is the control.
func TestSemantic_PnpmSpecifierTyped54(t *testing.T) {
	for name, tc := range map[string]struct {
		spelling string
		placed   bool
	}{
		"plain_float":    {"  p: 1.0\n", false},
		"control_quoted": {"  p: '1.0'\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			q := qPkg("1.0.0")
			lock := pnpmLockText(t, "5.4", map[string]map[string]string{".": {"p": "1.0.0"}}, p, q)
			if lock = strings.Replace(lock, "specifiers:\n  'p': '1.0.0'\n", "specifiers:\n"+tc.spelling, 1); !strings.Contains(lock, tc.spelling) {
				t.Fatal("specifier not rewritten")
			}
			dir := semProgram(t, pnpmLockFile, lock, map[string]string{
				"package.json": manifestWith("app", map[string]string{"p": "1.0"}, ""),
				"index.js":     "require('p').run();\n",
			})
			cg := semRun(t, dir, semStore(t, p, q))
			if incomplete := buildDepLayout(context.Background(), dir).incomplete; incomplete == tc.placed || runWide(cg) == tc.placed {
				t.Errorf("placed = %v, want %v; got %+v", !incomplete, tc.placed, cg.Partiality)
			}
		})
	}
}

// TestYAMLPlainString pins which specifier scalars pnpm reads back as the string written.
func TestYAMLPlainString(t *testing.T) {
	for _, tc := range []struct {
		val    string
		quoted bool
		want   bool
	}{
		{"^4.18.0", false, true}, {"1.0.0", false, true}, {"latest", false, true}, {"workspace:*", false, true},
		{"1.0", true, true}, {"", true, true}, {"true", true, true},
		{"1.0", false, false}, {"1", false, false}, {"-1", false, false}, {"1e3", false, false},
		{".5", false, false}, {".inf", false, false}, {"-.Inf", false, false}, {".nan", false, false},
		{"0x1F", false, false}, {"0o17", false, false}, {"017", false, false}, {"0b101", false, false},
		{"true", false, false}, {"False", false, false}, {"yes", false, false}, {"null", false, false},
		{"~", false, false}, {"", false, false}, {"{}", false, false}, {"[]", false, false},
	} {
		if got := yamlPlainString(&ynode{val: tc.val, quoted: tc.quoted}); got != tc.want {
			t.Errorf("yamlPlainString(%q, quoted=%v) = %v, want %v", tc.val, tc.quoted, got, tc.want)
		}
	}
}

// TestReadPnpmConfig_OwnGates pins the pnpm reader's own hook and case checks directly, without
// the install veto in play.
func TestReadPnpmConfig_OwnGates(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		ok    bool
	}{
		"control":           {map[string]string{".npmrc": "registry=https://npm.acme.dev/\n"}, true},
		"pnpmfile_cjs":      {map[string]string{".pnpmfile.cjs": "module.exports = {}\n"}, false},
		"pnpmfile_mjs":      {map[string]string{".pnpmfile.mjs": "export default {}\n"}, false},
		"npmrc_pnpmfile":    {map[string]string{".npmrc": "pnpmfile=hooks.cjs\n"}, false},
		"npmrc_global":      {map[string]string{".npmrc": "global-pnpmfile=hooks.cjs\n"}, false},
		"pnpmfile_case":     {map[string]string{".PNPMFILE.cjs": "module.exports = {}\n"}, false},
		"npmrc_case":        {map[string]string{".NPMRC": "registry=https://npm.acme.dev/\n"}, false},
		"package_yaml_case": {map[string]string{"Package.yaml": "name: app\n"}, false},
		"workspace_case":    {map[string]string{"Pnpm-Workspace.yaml": "packages: []\n"}, false},
		"workspace_list":    {map[string]string{"pnpm-workspace.yaml": "packages: []\n"}, true},
		"workspace_blank":   {map[string]string{"pnpm-workspace.yaml": "\n"}, false},
		"workspace_empty":   {map[string]string{"pnpm-workspace.yaml": ""}, false},
		"workspace_comment": {map[string]string{"pnpm-workspace.yaml": "# members are listed below\n"}, false},
		"workspace_null":    {map[string]string{"pnpm-workspace.yaml": "packages:\n"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			tc.files["package.json"] = `{"name":"app","private":true}`
			if _, ok := readPnpmConfig(writeProgram(t, tc.files)); ok != tc.ok {
				t.Errorf("readPnpmConfig ok = %v, want %v", ok, tc.ok)
			}
		})
	}
}

// TestSemantic_PnpmWorkspaceLeadingComment: pnpm reads a pnpm-workspace.yaml whose one document
// follows a comment-only block and a single "---" as that document, so the region is placed with
// the members it lists. Content or "..." before the marker, a second or trailing marker, and a
// prefix with no document after it are errors or root-only in pnpm, and withhold; so do the
// shapes pnpm reads but the lane holds strict (a directive, a BOM, CRLF, a tab, anything after
// the marker on its line). Each tree holds packages/b, unlisted, declaring a dependency the lock
// installs nothing for, so a member set read too wide withholds rather than passes.
func TestSemantic_PnpmWorkspaceLeadingComment(t *testing.T) {
	const b = "packages:\n  - packages/a\n"
	for name, tc := range map[string]struct {
		ws     string
		placed bool
	}{
		"control_lead_comment":          {"# c\n---\n" + b, true},
		"control_lead_comment_multi":    {"# c\n\n# d\n---\n" + b + "\n# trailing\n", true},
		"control_lead_comment_indented": {"  # indented c\n---\n" + b, true},
		"control_sep_only":              {"---\n" + b, true},
		"control_lead_blank":            {"\n\n---\n" + b, true},
		"lead_empty_doc":                {"# c\n---\n", false},
		"lead_key_before_sep":           {"x: 1\n---\n" + b, false},
		"lead_doc_end_in_prefix":        {"# c\n...\n---\n" + b, false},
		"lead_two_seps":                 {"# c\n---\n---\n" + b, false},
		"lead_trailing_sep":             {"# c\n---\n" + b + "---\n", false},
		"trailing_sep_no_lead":          {b + "---\n", false},
		"lead_yaml_directive":           {"%YAML 1.2\n---\n" + b, false},
		"lead_bom":                      {"\uFEFF# c\n---\n" + b, false},
		"lead_crlf":                     {strings.ReplaceAll("# c\n---\n"+b, "\n", "\r\n"), false},
		"lead_tab_comment":              {"# c\t\n---\n" + b, false},
		"lead_sep_comment":              {"# c\n--- # t\n" + b, false},
		"lead_sep_trailing_space":       {"# c\n---  \n" + b, false},
	} {
		t.Run(name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			q := qPkg("1.0.0")
			lock := pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}, "packages/a": {"q": "1.0.0"}}, p, q)
			dir := semProgram(t, pnpmLockFile, lock, map[string]string{
				"pnpm-workspace.yaml":     tc.ws,
				"packages/a/package.json": manifestWith("a", map[string]string{"q": "1.0.0"}, ""),
				"packages/b/package.json": manifestWith("b", map[string]string{"absent-package": "1.0.0"}, ""),
			})
			cfg, ok := readPnpmConfig(dir)
			cg := semRun(t, dir, semStore(t, p, q))
			incomplete := buildDepLayout(context.Background(), dir).incomplete
			if tc.placed && (!ok || !slices.Equal(cfg.members, []string{"packages/a"}) || incomplete || runWide(cg) || !reaches(cg, "q", "1.0.0")) {
				t.Errorf("%q places the region with members [packages/a]; ok=%v cfg=%+v incomplete=%v got %+v", tc.ws, ok, cfg, incomplete, cg.Partiality)
			}
			if !tc.placed && (ok || !incomplete || !runWide(cg)) {
				t.Errorf("%q withholds; ok=%v incomplete=%v got %+v", tc.ws, ok, incomplete, cg.Partiality)
			}
		})
	}
}

// TestInertDir_OwnGates pins inertDir's own manifest, hook and case checks directly, without the
// install veto in play.
func TestInertDir_OwnGates(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		inert bool
	}{
		"control":            {map[string]string{"apps/package.json": `{"name":"apps","private":true}`, "apps/.npmrc": "registry=https://npm.acme.dev/\n"}, true},
		"malformed":          {map[string]string{"apps/package.json": `{"name":"apps",`}, false},
		"pnpmfile":           {map[string]string{"apps/.pnpmfile.cjs": "module.exports = {}\n"}, false},
		"pnpmfile_case":      {map[string]string{"apps/.PNPMFILE.cjs": "module.exports = {}\n"}, false},
		"binding_gyp_case":   {map[string]string{"apps/Binding.gyp": "{'targets':[]}\n"}, false},
		"package_json5_case": {map[string]string{"apps/Package.json5": "{name: 'apps'}\n"}, false},
		"npmrc_case":         {map[string]string{"apps/.NPMRC": "registry=https://npm.acme.dev/\n"}, false},
		"manifest_case":      {map[string]string{"apps/Package.json": `{"name":"apps","private":true}`}, false},
	} {
		t.Run(name, func(t *testing.T) {
			root := writeProgram(t, tc.files)
			if got := inertDir(root, filepath.Join(root, "apps")); got != tc.inert {
				t.Errorf("inertDir = %v, want %v", got, tc.inert)
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-0 file")
		}
		root := writeProgram(t, map[string]string{"apps/package.json": `{"name":"apps"}`})
		m := filepath.Join(root, "apps", "package.json")
		if err := os.Chmod(m, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(m, 0o644) })
		if inertDir(root, filepath.Join(root, "apps")) {
			t.Error("an unreadable manifest is not inert")
		}
	})
}

// TestManifestFacts_BindingGypCase: the implicit node-gyp install is found for a binding.gyp in
// any case, and a patch touching one in any case is not scoped.
func TestManifestFacts_BindingGypCase(t *testing.T) {
	for _, f := range []string{"binding.gyp", "Binding.gyp", "BINDING.GYP"} {
		if install, native := manifestFacts([]byte(`{"name":"p"}`), map[string]bool{f: true}); !install || !native {
			t.Errorf("%s: install %v native %v, want both", f, install, native)
		}
		patch := "--- a/" + f + "\n+++ b/" + f + "\n@@ -1 +1 @@\n-x\n+y\n"
		if patchScoped([]byte(patch)) {
			t.Errorf("a patch touching %s is not scoped", f)
		}
	}
	if install, _ := manifestFacts([]byte(`{"name":"p"}`), map[string]bool{"src/binding.gyp": true}); install {
		t.Error("a nested binding.gyp triggers nothing")
	}
}

// TestPatchScoped_FileNameCase: a patch touching package.json or binding.gyp under another case
// is unscoped; pnpm applies it to the file the install reads on a case-insensitive filesystem.
func TestPatchScoped_FileNameCase(t *testing.T) {
	for _, f := range []string{"package.json", "Package.json", "PACKAGE.JSON", "lib/Package.json", "Binding.gyp"} {
		patch := "--- a/" + f + "\n+++ b/" + f + "\n@@ -1 +1 @@\n-x\n+y\n"
		if patchScoped([]byte(patch)) {
			t.Errorf("a patch touching %s is not scoped", f)
		}
	}
	if !patchScoped([]byte("--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-x\n+y\n")) {
		t.Error("a patch touching only index.js is scoped")
	}
}

// TestWorkspaceMembers pins the member resolver directly: what each shape selects, and each
// member rule that withholds without the rest of the layout in play.
func TestWorkspaceMembers(t *testing.T) {
	manifest := `{"name":"a"}`
	for name, tc := range map[string]struct {
		globs   []string
		files   map[string]string
		symlink [2]string // link name, target, both root-relative
		deny    string    // root-relative directory made unreadable
		want    []string
		ok      bool
	}{
		"star":                {globs: []string{"packages/*"}, files: map[string]string{"packages/a/package.json": manifest, "packages/b/index.js": "", "packages/README.md": ""}, want: []string{"packages/a"}, ok: true},
		"literal":             {globs: []string{"packages/a"}, files: map[string]string{"packages/a/package.json": manifest, "packages/b/package.json": manifest}, want: []string{"packages/a"}, ok: true},
		"overlap":             {globs: []string{"packages/*", "packages/a"}, files: map[string]string{"packages/a/package.json": manifest}, want: []string{"packages/a"}, ok: true},
		"absent_prefix":       {globs: []string{"libs/*"}, files: map[string]string{"packages/a/package.json": manifest}, ok: true},
		"prefix_is_file":      {globs: []string{"libs/*"}, files: map[string]string{"libs": ""}, ok: true},
		"dot_dir_no_manifest": {globs: []string{"packages/*"}, files: map[string]string{"packages/.cache/x": "", "packages/a/package.json": manifest}, want: []string{"packages/a"}, ok: true},
		"dot_dir_manifest":    {globs: []string{"packages/*"}, files: map[string]string{"packages/.a/package.json": manifest}},
		"prefix_case":         {globs: []string{"packages/*"}, files: map[string]string{"Packages/a/package.json": manifest}},
		"manifest_case":       {globs: []string{"packages/*"}, files: map[string]string{"packages/a/PACKAGE.JSON": manifest}},
		"manifest_not_file":   {globs: []string{"packages/*"}, files: map[string]string{"packages/a/package.json/x": ""}},
		"alt_manifest":        {globs: []string{"packages/*"}, files: map[string]string{"packages/a/package.yaml": "name: a\n"}},
		"alt_manifest_case":   {globs: []string{"packages/a"}, files: map[string]string{"packages/a/Package.json5": "{}"}},
		"yarn_json":           {globs: []string{"packages/*"}, files: map[string]string{"packages/a/yarn.json": manifest}},
		"yarn_json_beside":    {globs: []string{"packages/a"}, files: map[string]string{"packages/a/package.json": manifest, "packages/a/Yarn.json": manifest}},
		"node_modules_entry":  {globs: []string{"packages/*"}, files: map[string]string{"packages/node_modules/x/index.js": ""}},
		"bower_entry":         {globs: []string{"packages/*"}, files: map[string]string{"packages/Bower_Components/x/index.js": ""}},
		"symlink_member":      {globs: []string{"packages/*"}, files: map[string]string{"real/package.json": manifest, "packages/a/package.json": manifest}, symlink: [2]string{"packages/b", "real"}},
		"symlink_prefix":      {globs: []string{"packages/*"}, files: map[string]string{"real/a/package.json": manifest}, symlink: [2]string{"packages", "real"}},
		"symlink_manifest":    {globs: []string{"packages/a"}, files: map[string]string{"real.json": manifest, "packages/a/index.js": ""}, symlink: [2]string{"packages/a/package.json", "real.json"}},
		"refused_shape":       {globs: []string{"packages/a", "packages/**"}, files: map[string]string{"packages/a/package.json": manifest}},
		"unreadable_prefix":   {globs: []string{"packages/*"}, files: map[string]string{"packages/a/package.json": manifest}, deny: "packages"},
		"unreadable_segment":  {globs: []string{"packages/a"}, files: map[string]string{"packages/a/package.json": manifest}, deny: "packages"},
		"unreadable_member":   {globs: []string{"packages/*"}, files: map[string]string{"packages/a/package.json": manifest}, deny: "packages/a"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeProgram(t, tc.files)
			if tc.symlink[0] != "" {
				if err := os.Symlink(filepath.Join(dir, tc.symlink[1]), filepath.Join(dir, tc.symlink[0])); err != nil {
					t.Fatal(err)
				}
			}
			if tc.deny != "" {
				deny(t, filepath.Join(dir, tc.deny))
			}
			got, ok := workspaceMembers(dir, tc.globs)
			if ok != tc.ok || !slices.Equal(got, tc.want) {
				t.Errorf("workspaceMembers = %v, %v; want %v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestSemantic_YarnRootCase: a yarn classic root's .yarnrc, .npmrc or package.json named in
// another case withholds (yarn reads it under its usual name on a case-insensitive
// filesystem), as does a root .npmrc key outside outerNpmrcKeys, and a root yarn.json in any
// case (yarn merges it into the root manifest; the lane doesn't read it).
func TestSemantic_YarnRootCase(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"control":        {".yarnrc": "registry \"https://npm.acme.dev/\"\n"},
		"npmrc_control":  {".npmrc": "registry=https://npm.acme.dev/\n//npm.acme.dev/:_authToken=${NPM_TOKEN}\n"},
		"yarnrc_case":    {".YARNRC": "registry \"https://npm.acme.dev/\"\n"},
		"npmrc_case":     {".NPMRC": "registry=https://npm.acme.dev/\n"},
		"npmrc_unknown":  {".npmrc": "ignore-scripts=false\n"},
		"npmrc_hoisting": {".npmrc": "legacy-peer-deps=true\n"},
		"yarn_json":      {"yarn.json": `{"name":"app"}`},
		"yarn_json_case": {"Yarn.json": `{"name":"app"}`},
	} {
		t.Run(name, func(t *testing.T) {
			q := qPkg("1.0.0")
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			dir := semProgram(t, yarnLockFile, yarnLockText(t, p, q), files)
			cg := semRun(t, dir, semStore(t, p, q))
			incomplete := buildDepLayout(context.Background(), dir).incomplete
			control := strings.HasSuffix(name, "control")
			if control && (incomplete || runWide(cg) || !reaches(cg, "q", "1.0.0")) {
				t.Errorf("an allowlisted .yarnrc or .npmrc resolves q@1.0.0; got %+v", cg.Partiality)
			}
			if !control && (!incomplete || !runWide(cg)) {
				t.Errorf("a root config named in another case, an .npmrc key off the allowlist, or a yarn.json withholds; got %+v", cg.Partiality)
			}
		})
	}
}

// TestYAMLSubset_QuotedEscapes pins which double-quoted scalars the subset reader decodes: \" and
// \\ only. Any other escape is outside the subset, because the lane keeps no decoder for it and a
// verbatim \x31 is not the character a YAML loader reads. Rows named _guard
// were withheld before the escape gate.
func TestYAMLSubset_QuotedEscapes(t *testing.T) {
	for name, tc := range map[string]struct {
		doc     string
		want    string // the value of k when the document is read
		withold bool
	}{
		"key_hex":                  {doc: "\"k\\x31\": v\n", withold: true},
		"value_hex":                {doc: "k: \"\\x31.0.0\"\n", withold: true},
		"value_unicode":            {doc: "k: \"\\u0031\"\n", withold: true},
		"value_unicode32":          {doc: "k: \"\\U00000031\"\n", withold: true},
		"value_tab":                {doc: "k: \"a\\tb\"\n", withold: true},
		"value_newline":            {doc: "k: \"a\\nb\"\n", withold: true},
		"value_slash":              {doc: "k: \"a\\/b\"\n", withold: true},
		"value_nul":                {doc: "k: \"\\0\"\n", withold: true},
		"value_space":              {doc: "k: \"a\\ b\"\n", withold: true},
		"after_modelled":           {doc: "k: \"\\\\\\x31\"\n", withold: true},
		"after_quote":              {doc: "k: \"a\\\"\\x31\"\n", withold: true},
		"sequence_item":            {doc: "k:\n  - \"\\x31\"\n", withold: true},
		"nested_key":               {doc: "o:\n  \"\\x71\": v\n", withold: true},
		"value_trailing_guard":     {doc: "k: \"a\\\" # c\n", withold: true},
		"control_quote":            {doc: "k: \"a\\\"b\"\n", want: `a"b`},
		"control_slash":            {doc: "k: \"a\\\\b\"\n", want: `a\b`},
		"control_pair":             {doc: "k: \"\\\\x31\"\n", want: `\x31`},
		"control_key":              {doc: "\"k\\\"\": v\n", want: ""},
		"control_single":           {doc: "k: 'it''s'\n", want: "it's"},
		"control_single_backslash": {doc: "k: 'a\\x31'\n", want: `a\x31`},
		"control_plain":            {doc: "k: a\\x31\n", want: `a\x31`},
		"control_hex_in_comment":   {doc: "k: v # \"\\x31\"\n", want: "v"},
	} {
		t.Run(name, func(t *testing.T) {
			n, err := parseYAMLSubset(tc.doc)
			if tc.withold {
				if err != errYAMLSubset {
					t.Fatalf("parseYAMLSubset(%q) = %v, want errYAMLSubset", tc.doc, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseYAMLSubset(%q): %v", tc.doc, err)
			}
			if k, ok := n.kids["k"]; ok {
				if k.val != tc.want {
					t.Errorf("k = %q, want %q", k.val, tc.want)
				}
			} else if len(n.kids) != 1 {
				t.Errorf("keys = %v", n.keys)
			}
		})
	}
}

// TestSemantic_PnpmQuotedEscapes places a pnpm lock whose quoted scalars carry escapes. Rows
// named _guard withheld before the escape gate, by a compare against the manifest or a name check
// downstream; the rest placed a package under an identity other than the one pnpm installs, or
// kept an escaped digest.
func TestSemantic_PnpmQuotedEscapes(t *testing.T) {
	esc := func(old, repl string) func(string) string {
		return func(s string) string { return strings.ReplaceAll(s, old, repl) }
	}
	chain := func(fs ...func(string) string) func(string) string {
		return func(s string) string {
			for _, f := range fs {
				s = f(s)
			}
			return s
		}
	}
	qKeyRef := func(hex string) func(string) string {
		return chain(esc("\n  'q@1.0.0':", "\n  \"q@"+hex+".0.0\":"), esc("'q': '1.0.0'", "'q': \""+hex+".0.0\""))
	}
	for name, tc := range map[string]struct {
		edit   func(string) string
		placed bool
		// unread marks a row that places the lock but reads an entry as unreadable.
		unread bool
	}{
		"control_unchanged":        {edit: esc("", ""), placed: true},
		"control_double_quoted":    {edit: esc("\n  'q@1.0.0':", "\n  \"q@1.0.0\":"), placed: true},
		"control_unread_modelled":  {edit: esc("    resolution:", "    deprecated: \"say \\\"hi\\\" \\\\ bye\"\n    resolution:"), placed: true},
		"key_ref_hex":              {edit: qKeyRef(`\x31`)},
		"key_ref_unicode":          {edit: qKeyRef(`\u0031`)},
		"key_ref_wide_unicode":     {edit: qKeyRef(`\U00000031`)},
		"key_only_guard":           {edit: esc("\n  'q@1.0.0':", "\n  \"q@\\x31.0.0\":")},
		"unread_field":             {edit: esc("    resolution:", "    deprecated: \"a\\tb\"\n    resolution:")},
		"importer_version_guard":   {edit: esc("version: '1.0.0'", "version: \"\\x31.0.0\"")},
		"importer_specifier_guard": {edit: esc("specifier: '1.0.0'", "specifier: \"\\x31.0.0\"")},
		"dependency_name_guard":    {edit: esc("'q': '1.0.0'", "\"\\x71\": '1.0.0'")},
		"integrity":                {edit: esc("{integrity: sha512-", "{integrity: \"sha512-\\x41"), placed: true, unread: true},
	} {
		t.Run(name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			q := qPkg("1.0.0")
			base := pnpmLockText(t, "9.0", map[string]map[string]string{".": {"p": "1.0.0"}}, p, q)
			lock := tc.edit(base)
			if (lock != base) == (name == "control_unchanged") {
				t.Fatalf("edit did not apply to the lock:\n%s", base)
			}
			dir := semProgram(t, pnpmLockFile, lock, map[string]string{
				"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, ""),
				"index.js":     "require('p').run();\n",
			})
			l := buildDepLayout(context.Background(), dir)
			if l.incomplete == tc.placed {
				t.Errorf("incomplete = %v, want %v", l.incomplete, !tc.placed)
			}
			unread := false
			for _, e := range l.entries() {
				unread = unread || e.unreadable
			}
			if unread != tc.unread {
				t.Errorf("an entry is unreadable = %v, want %v", unread, tc.unread)
			}
		})
	}
}

// TestSemantic_YarnClassicQuotedEscapes places a yarn classic lock whose quoted scalars carry
// escapes. The reader only strips quotes, so an escape would place q under the text it spells;
// the lock is withheld and the layout is incomplete.
func TestSemantic_YarnClassicQuotedEscapes(t *testing.T) {
	esc := func(old, repl string) func(string) string {
		return func(s string) string { return strings.ReplaceAll(s, old, repl) }
	}
	for name, tc := range map[string]struct {
		edit   func(string) string
		placed bool
	}{
		"control_unchanged": {edit: esc("", ""), placed: true},
		"control_comment":   {edit: esc("# yarn lockfile v1", "# yarn lockfile v1 \"\\x31\""), placed: true},
		"version":           {edit: esc("  version \"1.0.0\"", "  version \"\\x31.0.0\"")},
		"header_guard":      {edit: esc("\"q@1.0.0\":", "\"q@\\x31.0.0\":")},
		"resolved":          {edit: esc("q-1.0.0.tgz", "q-\\x31.0.0.tgz")},
		"integrity":         {edit: esc("  integrity ", "  integrity \"\\x73\" ")},
	} {
		t.Run(name, func(t *testing.T) {
			p := sp("p", "1.0.0", map[string]string{"q": "1.0.0"}, map[string]string{"index.js": callsQ})
			base := yarnLockText(t, p, qPkg("1.0.0"))
			lock := tc.edit(base)
			if (lock != base) == (name == "control_unchanged") {
				t.Fatalf("edit did not apply to the lock:\n%s", base)
			}
			dir := semProgram(t, yarnLockFile, lock, map[string]string{
				"package.json": manifestWith("app", map[string]string{"p": "1.0.0"}, ""),
				"index.js":     "require('p').run();\n",
			})
			if incomplete := buildDepLayout(context.Background(), dir).incomplete; incomplete == tc.placed {
				t.Errorf("incomplete = %v, want %v", incomplete, !tc.placed)
			}
		})
	}
}
