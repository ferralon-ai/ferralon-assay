package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/artifactcache/acquire"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TypeDependencyAcquisition is the artifact dependency_acquisition writes: which lock-pinned
// npm packages have integrity-verified bytes in the dependency cache, and why each other one
// does not. It names no credential, URL or registry host.
const TypeDependencyAcquisition artifact.Type = "dependency_acquisition"

// DependencyCodeMode selects how dependency_acquisition fills the dependency cache.
type DependencyCodeMode string

const (
	// DependencyCodeFetch fetches each lock-pinned tarball missing from the cache from the
	// registry the build's npm configuration names, and verifies it against the lock SRI.
	DependencyCodeFetch DependencyCodeMode = "fetch"
	// DependencyCodeOffline reads only an operator-seeded cache in the same layout. Nothing is
	// fetched; a package absent from it stays unread.
	DependencyCodeOffline DependencyCodeMode = "offline"
)

// Reasons an npm package stays unread, recorded on DependencyAcquisitionResult.Unread.
const (
	UnreadNoIntegrity        = "no_integrity"         // the lock records no SRI (file:, link:, git+ or an unpinned entry)
	UnreadMalformedIntegrity = "malformed_integrity"  // the SRI does not decode to a supported digest
	UnreadIntegrityMismatch  = "integrity_mismatch"   // the bytes do not hash to the lock SRI
	UnreadPolicyRefused      = "policy_refused"       // the fetch target or a redirect failed the registry policy
	UnreadNotServed          = "not_served"           // the registry answered that it does not serve the tarball
	UnreadUnavailable        = "registry_unavailable" // throttled, a server error, a timeout or a dropped connection: transient
	UnreadUnreachable        = "registry_unreachable" // the registry host did not resolve or refused the connection
	UnreadFetchFailed        = "fetch_failed"         // any other transport or cache write failure
	UnreadNotCached          = "not_cached"           // offline, and the cache does not hold it
	UnreadNPMRCMalformed     = "npmrc_malformed"      // the npm configuration failed closed; nothing was fetched
	UnreadCancelled          = "cancelled"            // the run's context ended first
)

// DependencyAcquisition configures dependency_acquisition. Absent the option the stage is not in
// the stage list at all, so a run without it is unchanged.
type DependencyAcquisition struct {
	Mode DependencyCodeMode
	// CacheDir is the artifactcache DiskStore root acquisition publishes into and the JS lane
	// reads from.
	CacheDir string
	// UncredentialedDir, when set, is a second artifactcache root that only ever holds tarballs
	// from a registry with no auth entry in the npm configuration, fetched without presenting
	// any credential: the directory a caller may persist across runs. Each such tarball is
	// fetched into it and linked into CacheDir. A tarball from a registry with an auth entry is
	// never written to it, and one found there is removed. Empty keeps the one directory.
	UncredentialedDir string
	// LookupEnv is the environment NPM_CONFIG_USERCONFIG, NPM_CONFIG_REGISTRY and .npmrc ${VAR}
	// references resolve against. Only acquire.DefaultNPMRCEnv and AllowEnv are read through it;
	// nil reads no variable.
	LookupEnv func(string) (string, bool)
	// AllowEnv names further variables a .npmrc ${VAR} reference may read.
	AllowEnv []string
	// Timeout bounds the whole stage; zero uses defaultAcquireTimeout. Pins not finished by then
	// are recorded UnreadCancelled.
	Timeout time.Duration
	// Client supplies the transport; nil uses one with a per-request timeout.
	Client *http.Client
	// Observe, when set, receives each build directory's result once, when acquisition for it
	// finishes.
	Observe func(DependencyAcquisitionResult)
}

// WithDependencyAcquisition adds dependency_acquisition between codebase_inventory and
// reachability for a JS build. The cache is filled once per build directory and shared by every
// advisory the option set assesses.
func WithDependencyAcquisition(cfg DependencyAcquisition) AssessOption {
	run := &dependencyAcquirer{cfg: cfg, byDir: map[string]*acquiredBuild{}}
	return func(c *AssessConfig) { c.DependencyAcquisition = run }
}

// DependencyAcquisitionResult is the TypeDependencyAcquisition payload.
type DependencyAcquisitionResult struct {
	Mode string `json:"mode"`
	// Read counts the distinct lock-pinned packages whose verified bytes are in the cache.
	Read int `json:"read"`
	// Unread lists every other lock-pinned npm package, sorted by PURL.
	Unread []UnreadDependency `json:"unread,omitempty"`
	// InventoryPartial carries the inventory's own partiality reasons: packages it could not
	// enumerate are absent from both Read and Unread. An inventory that fails outright,
	// including one cut off by the stage deadline, enumerates nothing and records
	// plugin.PartialReasonToolFailure, a run-wide reason, never a scoped absence.
	InventoryPartial []string `json:"inventory_partial,omitempty"`
	// InventoryCancelled marks an inventory failure caused by the stage deadline or the run's
	// context ending, so a timeout is not read as a plugin defect.
	InventoryCancelled bool `json:"inventory_cancelled,omitempty"`
	// Fallback is set when a fetch failed: the JS lane then reads no dependency code at all, as
	// with dependency code off, and Fallback names why. Only DependencyCodeFetch sets it.
	Fallback *DependencyCodeCause `json:"fallback,omitempty"`
}

// DependencyCodeCause is why a fetch-mode acquisition fell back to reading no dependency code.
type DependencyCodeCause struct {
	// Kind is FallbackInventoryFailed or the Unread reason of the first package, in PURL order,
	// whose fetch failed.
	Kind string `json:"kind"`
	// Detail names that package and, for UnreadPolicyRefused, the policy code, for
	// UnreadUnavailable and UnreadUnreachable, the artifactcache Fetch* code or, for
	// UnreadNPMRCMalformed, the configuration file and line. It never carries a URL, a host or a
	// credential.
	Detail string `json:"detail,omitempty"`
	// Registry is that package's UnreadDependency.Registry. It stays in process: the artifact
	// names no registry.
	Registry string `json:"-"`
}

// FallbackInventoryFailed is the DependencyCodeCause kind for an inventory that failed outright,
// so no package could be fetched.
const FallbackInventoryFailed = "inventory_failed"

// fetchFailed reports whether reason is a fetch that did not complete: the registry refused,
// failed or did not serve the tarball, the bytes it served were wrong, the npm configuration
// could not be read, or the deadline passed. A lock entry with no usable integrity is not one:
// nothing could have fetched it, and it stays a per-package limit.
func fetchFailed(reason string) bool {
	switch reason {
	case UnreadFetchFailed, UnreadNotServed, UnreadUnavailable, UnreadUnreachable, UnreadPolicyRefused, UnreadCancelled, UnreadIntegrityMismatch, UnreadNPMRCMalformed:
		return true
	}
	return false
}

// fallbackCause is why res, a fetch-mode acquisition, falls back to reading no dependency code,
// or nil. One failed package is enough: a partial fetch is never read as dependency code.
func fallbackCause(res DependencyAcquisitionResult) *DependencyCodeCause {
	if res.Mode != string(DependencyCodeFetch) {
		return nil
	}
	if slices.Contains(res.InventoryPartial, plugin.PartialReasonToolFailure) {
		detail := ""
		if res.InventoryCancelled {
			detail = UnreadCancelled
		}
		return &DependencyCodeCause{Kind: FallbackInventoryFailed, Detail: detail}
	}
	for _, u := range res.Unread {
		if !fetchFailed(u.Reason) {
			continue
		}
		detail := u.PURL
		if u.Detail != "" {
			detail += ": " + u.Detail
		}
		return &DependencyCodeCause{Kind: u.Reason, Detail: detail, Registry: u.Registry}
	}
	return nil
}

// UnreadDependency is one package acquisition left unread, with one of the Unread* reasons and,
// for UnreadPolicyRefused, the artifactcache policy code.
type UnreadDependency struct {
	PURL   string `json:"purl"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
	// Registry identifies the registry a fetch-mode package was fetched from: its configured
	// base URL with no userinfo, query or fragment. Empty when nothing was fetched. It stays in
	// process, for a caller keeping per-registry state through Observe; the artifact names no
	// registry.
	Registry string `json:"-"`
}

type dependencyAcquirer struct {
	cfg   DependencyAcquisition
	mu    sync.Mutex
	byDir map[string]*acquiredBuild
	// retrySleep, when set, replaces how the fetchers wait between attempts.
	retrySleep func(context.Context, time.Duration) error
}

type acquiredBuild struct {
	once sync.Once
	res  DependencyAcquisitionResult
}

// acquireWorkers bounds concurrent registry fetches.
const acquireWorkers = 8

// fetchTimeout bounds one tarball request when the caller supplies no client.
const fetchTimeout = 2 * time.Minute

// defaultAcquireTimeout bounds the whole stage when DependencyAcquisition.Timeout is zero.
const defaultAcquireTimeout = 15 * time.Minute

func (d *dependencyAcquirer) result(ctx context.Context, buildDir, checkoutRoot string, p plugin.LanguagePlugin) DependencyAcquisitionResult {
	d.mu.Lock()
	b, ok := d.byDir[buildDir]
	if !ok {
		b = &acquiredBuild{}
		d.byDir[buildDir] = b
	}
	d.mu.Unlock()
	b.once.Do(func() {
		b.res = d.acquire(ctx, buildDir, checkoutRoot, p)
		b.res.Fallback = fallbackCause(b.res)
		if d.cfg.Observe != nil {
			d.cfg.Observe(b.res)
		}
	})
	return b.res
}

type npmPin struct {
	purl, digest string
}

func (d *dependencyAcquirer) acquire(ctx context.Context, buildDir, checkoutRoot string, p plugin.LanguagePlugin) DependencyAcquisitionResult {
	res := DependencyAcquisitionResult{Mode: string(d.cfg.Mode)}
	timeout := d.cfg.Timeout
	if timeout <= 0 {
		timeout = defaultAcquireTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	inv, err := p.ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir})
	if err != nil {
		res.InventoryPartial = []string{plugin.PartialReasonToolFailure}
		res.InventoryCancelled = ctx.Err() != nil
		return res
	}
	if !inv.Partiality.Complete {
		res.InventoryPartial = append([]string(nil), inv.Partiality.Reasons...)
	}

	seen := map[npmPin]bool{}
	var pins []npmPin
	for _, n := range inv.Nodes {
		if purlEcosystem(n.PURL) != "npm" {
			continue
		}
		pin := npmPin{purl: n.PURL, digest: n.Artifact.Digest}
		if !seen[pin] {
			seen[pin] = true
			pins = append(pins, pin)
		}
	}

	// A split cache routes on the npm configuration even offline: which registries hold
	// credentials decides whether a package may be read from UncredentialedDir.
	var npmrc acquire.NPMConfig
	var npmrcErr error
	if d.cfg.Mode == DependencyCodeFetch || d.split() {
		npmrc, npmrcErr = acquire.LoadNPMConfig(acquire.NPMRCSources{ProjectDir: buildDir, CheckoutRoot: checkoutRoot, LookupEnv: d.cfg.LookupEnv, AllowEnv: d.cfg.AllowEnv})
	}
	var fetchers cacheFetchers
	if d.cfg.Mode == DependencyCodeFetch {
		client := d.cfg.Client
		if client == nil {
			client = &http.Client{Timeout: fetchTimeout}
		}
		fetchers.read = acquire.NewAcquirer(d.cfg.CacheDir, client)
		if d.split() {
			fetchers.uncredentialed = acquire.NewAcquirer(d.cfg.UncredentialedDir, client)
		}
		if d.retrySleep != nil {
			fetchers.read.SetRetrySleep(d.retrySleep)
			if fetchers.uncredentialed != nil {
				fetchers.uncredentialed.SetRetrySleep(d.retrySleep)
			}
		}
	}
	disk := artifactcache.NewDiskStore(d.cfg.CacheDir)

	outcomes := make([]*UnreadDependency, len(pins))
	sem := make(chan struct{}, acquireWorkers)
	var wg sync.WaitGroup
	for i, pin := range pins {
		if pin.digest == "" {
			outcomes[i] = &UnreadDependency{PURL: pin.purl, Reason: UnreadNoIntegrity}
			continue
		}
		if npmrcErr != nil {
			// npmrcError text names the file and line, never a value.
			outcomes[i] = &UnreadDependency{PURL: pin.purl, Reason: UnreadNPMRCMalformed, Detail: npmrcErr.Error()}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, pin npmPin) {
			defer wg.Done()
			defer func() { <-sem }()
			u := d.acquireOne(ctx, pin, npmrc, fetchers, disk)
			if u != nil && d.cfg.Mode == DependencyCodeFetch {
				u.Registry = registryOf(npmrc, pin.purl)
			}
			outcomes[i] = u
		}(i, pin)
	}
	wg.Wait()

	for _, o := range outcomes {
		if o == nil {
			res.Read++
			continue
		}
		res.Unread = append(res.Unread, *o)
	}
	sort.Slice(res.Unread, func(i, j int) bool { return res.Unread[i].PURL < res.Unread[j].PURL })
	return res
}

// cacheFetchers are the Acquirers acquisition publishes through: read is rooted at CacheDir,
// uncredentialed at UncredentialedDir when the cache is split.
type cacheFetchers struct {
	read, uncredentialed *acquire.Acquirer
}

func (d *dependencyAcquirer) split() bool { return d.cfg.UncredentialedDir != "" }

// viaUncredentialed reports whether a package's bytes go through UncredentialedDir. This is the
// routing gate: a package from a registry with an auth entry never does.
func (d *dependencyAcquirer) viaUncredentialed(credentialed bool) bool {
	return d.split() && !credentialed
}

// acquireOne leaves pin's verified bytes in CacheDir and returns nil, or says why it could not.
// Only reason codes leave this function: an error string can carry a URL, and nothing here may
// echo configuration back.
func (d *dependencyAcquirer) acquireOne(ctx context.Context, pin npmPin, npmrc acquire.NPMConfig, fetchers cacheFetchers, disk artifactcache.Store) *UnreadDependency {
	ref := artifactcache.Ref{PURL: pin.purl, Digest: pin.digest}
	unread := func(reason, detail string) *UnreadDependency {
		return &UnreadDependency{PURL: pin.purl, Reason: reason, Detail: detail}
	}
	if ctx.Err() != nil {
		return unread(UnreadCancelled, "")
	}
	if _, _, err := artifactcache.DecodeDigest(pin.digest); err != nil {
		return unread(UnreadMalformedIntegrity, "")
	}
	fetching := d.cfg.Mode == DependencyCodeFetch
	var policy acquire.Policy
	credentialed := false
	if fetching || d.split() {
		name, err := acquire.NPMNameOf(pin.purl)
		if err != nil {
			return unread(UnreadMalformedIntegrity, "")
		}
		policy = npmrc.PolicyFor(name)
		if d.split() {
			if credentialed, err = policy.Credentialed(pin.purl); err != nil {
				return classifyAcquireError(ctx, pin.purl, err)
			}
		}
	}
	shared := d.viaUncredentialed(credentialed)
	var sharedPath string
	if d.split() {
		sharedPath, _ = artifactcache.CanonicalPath(d.cfg.UncredentialedDir, pin.digest)
	}
	if d.split() && !shared {
		// A credentialed package found in UncredentialedDir was put there by something other
		// than this split: drop it rather than read or keep it.
		if err := removeEntry(sharedPath); err != nil {
			return classifyAcquireError(ctx, pin.purl, err)
		}
	}
	if shared {
		// A tarball bound for UncredentialedDir is fetched without presenting any credential,
		// so a registry redirect onto an authenticated host cannot carry one.
		policy.Credentials = acquire.RegistryCredentials{}
	}

	// fill fetches pin into the directory its route names and links a package fetched into
	// UncredentialedDir into CacheDir.
	fill := func() *UnreadDependency {
		if fetching {
			fetcher := fetchers.read
			if shared {
				fetcher = fetchers.uncredentialed
			}
			if _, err := fetcher.Acquire(ctx, ref, policy); err != nil {
				return classifyAcquireError(ctx, pin.purl, err)
			}
		}
		if shared {
			readPath, _ := artifactcache.CanonicalPath(d.cfg.CacheDir, pin.digest)
			if err := linkEntry(sharedPath, readPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return classifyAcquireError(ctx, pin.purl, err)
			}
		}
		return nil
	}
	if u := fill(); u != nil {
		return u
	}

	path, err := verifiedEntry(ctx, disk, ref)
	if err == nil {
		return nil
	}
	// A cached entry that fails verification in fetch mode is a poisoned or corrupt cache
	// file, not a registry finding: Acquire treats any published file as a hit, so drop that
	// one file, and the UncredentialedDir copy it links to, and fetch it once more.
	// Offline mode has no registry and falls back.
	if fetching && path != "" && errors.Is(err, artifactcache.ErrIntegrityMismatch) {
		rmErr := os.Remove(path)
		if rmErr == nil && shared {
			rmErr = removeEntry(sharedPath)
		}
		if rmErr != nil {
			return classifyAcquireError(ctx, pin.purl, err)
		}
		if u := fill(); u != nil {
			return u
		}
		if _, err = verifiedEntry(ctx, disk, ref); err == nil {
			return nil
		}
	}
	if errors.Is(err, artifactcache.ErrDeclaredAbsent) {
		return unread(UnreadNotCached, "")
	}
	return classifyAcquireError(ctx, pin.purl, err)
}

// removeEntry removes a cache entry and its acquisition record. An entry already absent is not
// an error.
func removeEntry(path string) error {
	for _, p := range []string{path, path + ".record.json"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// linkEntry makes the cache entry at src readable at dst: a hard link, or a copy published by
// rename when the two directories are on different filesystems. An existing dst is kept; the
// caller verifies whatever dst holds.
func linkEntry(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	err := os.Link(src, dst)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".link-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o444); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// verifiedEntry opens ref's cache entry and verifies it against the lock digest. On a
// verification failure it returns the entry's path so the caller can discard it.
func verifiedEntry(ctx context.Context, disk artifactcache.Store, ref artifactcache.Ref) (string, error) {
	h, err := disk.Lookup(ctx, ref)
	if err != nil {
		return "", err
	}
	defer h.Close()
	if err := artifactcache.Verify(h, ref); err != nil {
		return h.Path(), err
	}
	return "", nil
}

// registryOf is the Registry the npm configuration routes purl to, or "" when purl names no
// npm package.
func registryOf(npmrc acquire.NPMConfig, purl string) string {
	name, err := acquire.NPMNameOf(purl)
	if err != nil {
		return ""
	}
	return acquire.RegistryID(npmrc.RegistryFor(name))
}

// classifyAcquireError names why err left purl unread. A concrete finding (a policy refusal,
// bytes that do not match the lock, a malformed pin, a status the registry answered with) keeps
// its reason even when the deadline has since passed; only an error the deadline could itself
// have caused reads as cancelled. A registry that was unavailable or unreachable is never
// filed as not serving the package: that would say the package is absent.
func classifyAcquireError(ctx context.Context, purl string, err error) *UnreadDependency {
	u := &UnreadDependency{PURL: purl}
	var pr *artifactcache.PolicyReason
	var fr *artifactcache.FetchReason
	switch {
	case errors.As(err, &pr):
		u.Reason, u.Detail = UnreadPolicyRefused, pr.Code
	case errors.Is(err, artifactcache.ErrIntegrityMismatch):
		u.Reason = UnreadIntegrityMismatch
	case errors.Is(err, artifactcache.ErrMalformedRef), errors.Is(err, artifactcache.ErrUnpinnedArtifact):
		u.Reason = UnreadMalformedIntegrity
	case errors.As(err, &fr) && fr.Status != 0:
		u.Reason, u.Detail = UnreadUnavailable, fr.Code
	case ctx.Err() != nil:
		u.Reason = UnreadCancelled
	case errors.As(err, &fr) && errors.Is(fr, artifactcache.ErrRegistryUnreachable):
		u.Reason, u.Detail = UnreadUnreachable, fr.Code
	case errors.As(err, &fr):
		u.Reason, u.Detail = UnreadUnavailable, fr.Code
	case errors.Is(err, artifactcache.ErrDeclaredAbsent):
		u.Reason = UnreadNotServed
	default:
		u.Reason = UnreadFetchFailed
	}
	return u
}

// dependencyAcquisition is the stage. It runs only for a JS build whose plugin matches.
type dependencyAcquisition struct {
	acq    *dependencyAcquirer
	plugin plugin.LanguagePlugin
}

func (dependencyAcquisition) Name() string              { return "dependency_acquisition" }
func (dependencyAcquisition) Status() assessment.Status { return assessment.StatusInventory }

func (s dependencyAcquisition) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	if s.acq == nil || s.plugin == nil {
		return nil
	}
	buildDir, checkoutRoot, language, err := inventoryBuildLanguage(store, c.ID)
	if err != nil {
		return err
	}
	if buildDir == "" || language != checkout.LangJS || s.plugin.Language() != language {
		return nil
	}
	res := s.acq.result(ctx, buildDir, checkoutRoot, s.plugin)
	_, err = PutArtifact(store, c, s.Name(), TypeDependencyAcquisition, "npm", res)
	return err
}

// inventoryBuildLanguage returns the inventory's build dir, the workspace plan's root, and the
// language. Today's plans are single-project, so the root is the build dir itself and the
// containment check in acquire.LoadNPMConfig compares the build dir with itself; the root is
// passed so a multi-project plan, whose root differs, is contained without a further change.
func inventoryBuildLanguage(store artifact.Store, caseID string) (string, string, string, error) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return "", "", "", err
	}
	var inv struct {
		BuildDir      string `json:"build_dir"`
		CheckoutRoot  string `json:"checkout_root"`
		Language      string `json:"language"`
		WorkspacePlan struct {
			Root string `json:"root"`
		} `json:"workspace_plan"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return "", "", "", err
	}
	root := inv.WorkspacePlan.Root
	if root == "" {
		root = inv.CheckoutRoot
	}
	return inv.BuildDir, root, inv.Language, nil
}

// cacheFor returns the dependency cache the JS lane reads for caseID: set only when
// dependency_acquisition ran for it and did not fall back. A fallback hands the lane no cache, so
// it reads exactly what it reads with dependency code off.
func (a *dependencyAcquirer) cacheFor(store artifact.Store, caseID string) string {
	if a == nil {
		return ""
	}
	res, ok := DependencyAcquisitionOf(store, caseID)
	if !ok || res.Fallback != nil {
		return ""
	}
	return a.cfg.CacheDir
}

// DependencyAcquisitionOf returns the dependency_acquisition result recorded for caseID, and
// whether the stage ran.
func DependencyAcquisitionOf(store artifact.Store, caseID string) (DependencyAcquisitionResult, bool) {
	arts, err := store.Query(caseID, TypeDependencyAcquisition)
	if err != nil || len(arts) == 0 {
		return DependencyAcquisitionResult{}, false
	}
	var res DependencyAcquisitionResult
	if err := json.Unmarshal(arts[0].Payload, &res); err != nil {
		return DependencyAcquisitionResult{}, false
	}
	return res, true
}
