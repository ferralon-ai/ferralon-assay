package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
	UnreadNoIntegrity        = "no_integrity"        // the lock records no SRI (file:, link:, git+ or an unpinned entry)
	UnreadMalformedIntegrity = "malformed_integrity" // the SRI does not decode to a supported digest
	UnreadIntegrityMismatch  = "integrity_mismatch"  // the bytes do not hash to the lock SRI
	UnreadPolicyRefused      = "policy_refused"      // the fetch target or a redirect failed the registry policy
	UnreadNotServed          = "not_served"          // the registry did not serve the tarball
	UnreadFetchFailed        = "fetch_failed"        // transport failure
	UnreadNotCached          = "not_cached"          // offline, and the cache does not hold it
	UnreadNPMRCMalformed     = "npmrc_malformed"     // the npm configuration failed closed; nothing was fetched
	UnreadCancelled          = "cancelled"           // the run's context ended first
)

// DependencyAcquisition configures dependency_acquisition. Absent the option the stage is not in
// the stage list at all, so a run without it is unchanged.
type DependencyAcquisition struct {
	Mode DependencyCodeMode
	// CacheDir is the artifactcache DiskStore root acquisition publishes into and the JS lane
	// reads from.
	CacheDir string
	// LookupEnv is the environment .npmrc ${VAR} references, NPM_CONFIG_USERCONFIG and
	// NPM_CONFIG_REGISTRY resolve against. nil reads no variable.
	LookupEnv func(string) (string, bool)
	// Client supplies the transport; nil uses one with a per-request timeout.
	Client *http.Client
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
	// enumerate are absent from both Read and Unread.
	InventoryPartial []string `json:"inventory_partial,omitempty"`
}

// UnreadDependency is one package acquisition left unread, with one of the Unread* reasons and,
// for UnreadPolicyRefused, the artifactcache policy code.
type UnreadDependency struct {
	PURL   string `json:"purl"`
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

type dependencyAcquirer struct {
	cfg   DependencyAcquisition
	mu    sync.Mutex
	byDir map[string]*acquiredBuild
}

type acquiredBuild struct {
	once sync.Once
	res  DependencyAcquisitionResult
}

// acquireWorkers bounds concurrent registry fetches.
const acquireWorkers = 8

// fetchTimeout bounds one tarball request when the caller supplies no client.
const fetchTimeout = 2 * time.Minute

func (d *dependencyAcquirer) result(ctx context.Context, buildDir string, p plugin.LanguagePlugin) DependencyAcquisitionResult {
	d.mu.Lock()
	b, ok := d.byDir[buildDir]
	if !ok {
		b = &acquiredBuild{}
		d.byDir[buildDir] = b
	}
	d.mu.Unlock()
	b.once.Do(func() { b.res = d.acquire(ctx, buildDir, p) })
	return b.res
}

type npmPin struct {
	purl, digest string
}

func (d *dependencyAcquirer) acquire(ctx context.Context, buildDir string, p plugin.LanguagePlugin) DependencyAcquisitionResult {
	res := DependencyAcquisitionResult{Mode: string(d.cfg.Mode)}
	inv, err := p.ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: buildDir})
	if err != nil {
		res.InventoryPartial = []string{plugin.PartialReasonToolFailure}
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

	var npmrc acquire.NPMConfig
	npmrcErr := error(nil)
	if d.cfg.Mode == DependencyCodeFetch {
		npmrc, npmrcErr = acquire.LoadNPMConfig(acquire.NPMRCSources{ProjectDir: buildDir, LookupEnv: d.cfg.LookupEnv})
	}

	outcomes := make([]*UnreadDependency, len(pins))
	sem := make(chan struct{}, acquireWorkers)
	var wg sync.WaitGroup
	for i, pin := range pins {
		if pin.digest == "" {
			outcomes[i] = &UnreadDependency{PURL: pin.purl, Reason: UnreadNoIntegrity}
			continue
		}
		if npmrcErr != nil {
			outcomes[i] = &UnreadDependency{PURL: pin.purl, Reason: UnreadNPMRCMalformed}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, pin npmPin) {
			defer wg.Done()
			defer func() { <-sem }()
			outcomes[i] = d.acquireOne(ctx, pin, npmrc)
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

// acquireOne leaves pin's verified bytes in the cache and returns nil, or says why it could not.
// Only reason codes leave this function: an error string can carry a URL, and nothing here may
// echo configuration back.
func (d *dependencyAcquirer) acquireOne(ctx context.Context, pin npmPin, npmrc acquire.NPMConfig) *UnreadDependency {
	ref := artifactcache.Ref{PURL: pin.purl, Digest: pin.digest}
	unread := func(reason, detail string) *UnreadDependency {
		return &UnreadDependency{PURL: pin.purl, Reason: reason, Detail: detail}
	}
	if _, _, err := artifactcache.DecodeDigest(pin.digest); err != nil {
		return unread(UnreadMalformedIntegrity, "")
	}
	if d.cfg.Mode == DependencyCodeFetch {
		name, err := acquire.NPMNameOf(pin.purl)
		if err != nil {
			return unread(UnreadMalformedIntegrity, "")
		}
		client := d.cfg.Client
		if client == nil {
			client = &http.Client{Timeout: fetchTimeout}
		}
		if _, err := acquire.NewAcquirer(d.cfg.CacheDir, client).Acquire(ctx, ref, npmrc.PolicyFor(name, "")); err != nil {
			return classifyAcquireError(ctx, pin.purl, err)
		}
	}

	h, err := artifactcache.NewDiskStore(d.cfg.CacheDir).Lookup(ctx, ref)
	switch {
	case errors.Is(err, artifactcache.ErrDeclaredAbsent):
		return unread(UnreadNotCached, "")
	case err != nil:
		return classifyAcquireError(ctx, pin.purl, err)
	}
	defer h.Close()
	if err := artifactcache.Verify(h, ref); err != nil {
		return classifyAcquireError(ctx, pin.purl, err)
	}
	return nil
}

func classifyAcquireError(ctx context.Context, purl string, err error) *UnreadDependency {
	u := &UnreadDependency{PURL: purl}
	var pr *artifactcache.PolicyReason
	switch {
	case ctx.Err() != nil:
		u.Reason = UnreadCancelled
	case errors.As(err, &pr):
		u.Reason, u.Detail = UnreadPolicyRefused, pr.Code
	case errors.Is(err, artifactcache.ErrIntegrityMismatch):
		u.Reason = UnreadIntegrityMismatch
	case errors.Is(err, artifactcache.ErrMalformedRef), errors.Is(err, artifactcache.ErrUnpinnedArtifact):
		u.Reason = UnreadMalformedIntegrity
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
	buildDir, language, err := inventoryBuildLanguage(store, c.ID)
	if err != nil {
		return err
	}
	if buildDir == "" || language != checkout.LangJS || s.plugin.Language() != language {
		return nil
	}
	res := s.acq.result(ctx, buildDir, s.plugin)
	_, err = PutArtifact(store, c, s.Name(), TypeDependencyAcquisition, "npm", res)
	return err
}

func inventoryBuildLanguage(store artifact.Store, caseID string) (string, string, error) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return "", "", err
	}
	var inv struct {
		BuildDir string `json:"build_dir"`
		Language string `json:"language"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		return "", "", err
	}
	return inv.BuildDir, inv.Language, nil
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
