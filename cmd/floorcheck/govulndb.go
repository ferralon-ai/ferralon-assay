package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// A fixture's govulncheck database is a slice of the Go vulnerability database in its v1 layout
// (index/db.json, index/modules.json, index/vulns.json, ID/<id>.json), holding only the entries for
// the advisories the fixture grades. The scan reads it through the scanner's ASSAY_GO_VULN_DB, so a
// rerun on the same fixture reads the same entries whatever vuln.go.dev serves that day.
const (
	goVulnDBEnv = "ASSAY_GO_VULN_DB"
	goVulnDBDir = "govulndb"
)

// fileURL is the file:// URL of an absolute path.
func fileURL(p string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(p)}).String()
}

// treeDigest is a directory's digest: the sha256 of one "<sha256 hex>  <path>\n" line per regular
// file, paths slash-separated and relative to dir, in byte order. It is what
//
//	cd <dir> && find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256
//
// prints. Anything other than a directory or a regular file is refused.
func treeDigest(dir string) (string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%s is not a regular file", p)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		sum, err := fileSHA256(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s  %s\n", sum, f)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyGoVulnDB resolves a fixture's govulncheck database inside the fixture, checks it is a v1
// database govulncheck will read as one, and checks its tree digest against the pin.
func verifyGoVulnDB(fixtureDir string, pf PinnedFile) (string, error) {
	dir, err := containedPath(fixtureDir, pf.Path)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(filepath.Join(dir, "index", "modules.json")); err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: no index/modules.json; not a govulncheck database", pf.Path)
	}
	got, err := treeDigest(dir)
	if err != nil {
		return "", err
	}
	if got != pf.SHA256 {
		return "", fmt.Errorf("%s: tree digest %s, scenario pins %s", pf.Path, got, pf.SHA256)
	}
	return dir, nil
}

// The v1 index shapes (golang.org/x/vuln/internal/client), with only the fields the database defines.
type (
	vulnDBMeta struct {
		Modified time.Time `json:"modified"`
	}
	vulnDBModule struct {
		Path  string             `json:"path"`
		Vulns []vulnDBModuleVuln `json:"vulns"`
	}
	vulnDBModuleVuln struct {
		ID       string    `json:"id"`
		Modified time.Time `json:"modified"`
		Fixed    string    `json:"fixed,omitempty"`
	}
	vulnDBEntry struct {
		ID       string    `json:"id"`
		Modified time.Time `json:"modified"`
		Aliases  []string  `json:"aliases,omitempty"`
	}
)

// vulnDBSource reads a v1 database's files: an https:// endpoint such as https://vuln.go.dev, or a
// local directory.
type vulnDBSource func(ctx context.Context, rel string) ([]byte, error)

func newVulnDBSource(src string) (vulnDBSource, error) {
	if strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "http://") {
		base, err := url.Parse(src)
		if err != nil {
			return nil, err
		}
		client := &http.Client{Timeout: 2 * time.Minute}
		return func(ctx context.Context, rel string) ([]byte, error) {
			u := *base
			u.Path = path.Join(u.Path, rel)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("GET %s: %s", u.String(), resp.Status)
			}
			return io.ReadAll(resp.Body)
		}, nil
	}
	root := src
	if strings.HasPrefix(src, "file://") {
		u, err := url.Parse(src)
		if err != nil {
			return nil, err
		}
		root = u.Path
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%s is neither an http(s) URL nor a database directory", src)
	}
	return func(_ context.Context, rel string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	}, nil
}

// fixtureAdvisoryNames is every name the fixture's advisories go by: each record's identifier, vuln_id
// and aliases. A Go database entry is the fixture's when its id or one of its aliases is among them.
func fixtureAdvisoryNames(fixtureDir string) (map[string]bool, error) {
	var sc Scenario
	if err := decodeStrict(filepath.Join(fixtureDir, fileScenario), &sc); err != nil {
		return nil, err
	}
	if sc.Lang != "go" {
		return nil, fmt.Errorf("%s: a govulncheck database belongs to the go lane, not %s", fixtureDir, sc.Lang)
	}
	if sc.Intel.Advisories == nil {
		return nil, fmt.Errorf("%s: intel names no advisories directory to cut the database by", fixtureDir)
	}
	manifest, err := containedPath(fixtureDir, sc.Intel.Advisories.Path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil, err
	}
	var m dirManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", manifest, err)
	}
	names := map[string]bool{}
	for _, r := range m.Records {
		rec, err := containedPath(filepath.Dir(manifest), r.Path)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(rec)
		if err != nil {
			return nil, err
		}
		var a struct {
			VulnID  string   `json:"vuln_id"`
			Aliases []string `json:"aliases"`
		}
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("%s: %w", rec, err)
		}
		for _, n := range append([]string{r.Identifier, a.VulnID}, a.Aliases...) {
			if n != "" {
				names[n] = true
			}
		}
	}
	return names, nil
}

// cutVulnDB writes into out the slice of the database src holds for names: every entry whose id or an
// alias is in names, with indexes covering exactly those entries. db.json's modified is the latest kept
// entry's, so the slice's bytes depend only on the entries it holds. It returns the kept ids.
func cutVulnDB(ctx context.Context, src vulnDBSource, names map[string]bool, out string) ([]string, error) {
	var entries []vulnDBEntry
	if err := readVulnDBJSON(ctx, src, "index/vulns.json", &entries); err != nil {
		return nil, err
	}
	var modules []vulnDBModule
	if err := readVulnDBJSON(ctx, src, "index/modules.json", &modules); err != nil {
		return nil, err
	}
	// A fixture whose advisories have no entry still gets a database, an empty one, so a later entry
	// for one of them cannot change its verdicts unseen.
	kept := []vulnDBEntry{}
	keep := map[string]bool{}
	var latest time.Time
	for _, e := range entries {
		if names[e.ID] || slices.ContainsFunc(e.Aliases, func(a string) bool { return names[a] }) {
			kept = append(kept, e)
			keep[e.ID] = true
			if e.Modified.After(latest) {
				latest = e.Modified
			}
		}
	}
	keptModules := []vulnDBModule{}
	for _, m := range modules {
		var vs []vulnDBModuleVuln
		for _, v := range m.Vulns {
			if keep[v.ID] {
				vs = append(vs, v)
			}
		}
		if len(vs) > 0 {
			keptModules = append(keptModules, vulnDBModule{Path: m.Path, Vulns: vs})
		}
	}
	files := map[string][]byte{}
	ids := make([]string, 0, len(kept))
	for _, e := range kept {
		data, err := src(ctx, "ID/"+e.ID+".json")
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, bytes.TrimSpace(data), "", "  "); err != nil {
			return nil, fmt.Errorf("ID/%s.json: %w", e.ID, err)
		}
		files["ID/"+e.ID+".json"] = append(buf.Bytes(), '\n')
		ids = append(ids, e.ID)
	}
	for rel, v := range map[string]any{
		"index/db.json":      vulnDBMeta{Modified: latest},
		"index/vulns.json":   kept,
		"index/modules.json": keptModules,
	} {
		js, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return nil, err
		}
		files[rel] = append(js, '\n')
	}
	if err := writeVulnDB(out, files); err != nil {
		return nil, err
	}
	return ids, nil
}

func readVulnDBJSON(ctx context.Context, src vulnDBSource, rel string, v any) error {
	data, err := src(ctx, rel)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

// writeVulnDB writes files under out and removes any ID/*.json a previous cut left that this one
// does not hold, so the directory is exactly the slice.
func writeVulnDB(out string, files map[string][]byte) error {
	for _, d := range []string{"index", "ID"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o755); err != nil {
			return err
		}
	}
	for rel, data := range files {
		if err := os.WriteFile(filepath.Join(out, filepath.FromSlash(rel)), data, 0o644); err != nil {
			return err
		}
	}
	ents, err := os.ReadDir(filepath.Join(out, "ID"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		if _, ok := files["ID/"+e.Name()]; !ok {
			if err := os.Remove(filepath.Join(out, "ID", e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// runGoVulnDB implements `floorcheck govulndb`: it cuts a Go fixture's govulncheck database from a full
// one and prints the intel.govulndb pin for its scenario.yaml.
//
//	floorcheck govulndb -fixture cmd/floorcheck/fixtures/<name> [-from https://vuln.go.dev|DIR]
func runGoVulnDB(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("govulndb", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fixture := fs.String("fixture", "", "the Go fixture directory (required)")
	from := fs.String("from", "https://vuln.go.dev", "the full database: an http(s) endpoint or a v1 database directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *fixture == "" {
		fmt.Fprintln(stderr, "floorcheck govulndb: -fixture is required")
		return 2
	}
	src, err := newVulnDBSource(*from)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck govulndb:", err)
		return 2
	}
	names, err := fixtureAdvisoryNames(*fixture)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck govulndb:", err)
		return 2
	}
	out := filepath.Join(*fixture, goVulnDBDir)
	ids, err := cutVulnDB(context.Background(), src, names, out)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck govulndb:", err)
		return 1
	}
	digest, err := treeDigest(out)
	if err != nil {
		fmt.Fprintln(stderr, "floorcheck govulndb:", err)
		return 1
	}
	fmt.Fprintf(stderr, "floorcheck govulndb: %d entries from %s\n", len(ids), *from)
	fmt.Fprintf(stdout, "  govulndb: { path: %s, sha256: %q }\n", goVulnDBDir, digest)
	return 0
}
