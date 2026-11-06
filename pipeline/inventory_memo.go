package pipeline

import (
	"context"
	"path/filepath"
	"slices"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// InventoryMemo caches the checkout-constant reads codebase_inventory makes: the language
// detection walk, the HEAD commit, the Go module root, the go.work, the Bazel workspace probe and
// the root package. A scan assesses every advisory against one checked-out tree, and each
// assessment otherwise repeats these reads, most of them git subprocesses.
//
// Every entry is a function of the tree on disk and the key it is stored under, so the memo is only
// sound while that tree does not change. It is meant to live for one scan over one checkout, as
// plugin.Memoize is; never share one across scans or keep one after the checkout is rewritten.
//
// A call that fails is not cached, and neither is one that ran under a cancelled context, since a
// cancelled git subprocess is indistinguishable from a tree with nothing to report. The next caller
// retries it exactly as it would without the memo. The zero value is ready to use, and a nil
// *InventoryMemo reads through to the underlying call.
type InventoryMemo struct {
	vendored   memoTable[string, checkout.WorkspacePlan]
	head       memoTable[string, string]
	moduleRoot memoTable[string, moduleRootEntry]
	workspace  memoTable[workspaceKey, GoWorkspace]
	bazel      memoTable[string, bool]
	rootPkg    memoTable[rootPkgKey, rootPkgEntry]
}

// NewInventoryMemo returns an empty memo for one scan.
func NewInventoryMemo() *InventoryMemo { return &InventoryMemo{} }

// WithInventoryMemo hands codebase_inventory the memo it reads its checkout-constant work through.
// Without it the stage repeats that work for every advisory. The caller creates one memo per scan,
// over the one checkout the scan assesses (see InventoryMemo).
func WithInventoryMemo(m *InventoryMemo) AssessOption {
	return func(c *AssessConfig) { c.InventoryMemo = m }
}

type moduleRootEntry struct {
	root string
	ok   bool
}

// workspaceKey is every input ResolveGoWorkspace reads: the module directory, the checkout root
// (the search bound when git names none, and what a relative declaration resolves against) and the
// declared go.work.
type workspaceKey struct{ buildDir, checkoutRoot, declared string }

type rootPkgKey struct{ buildDir, language string }

type rootPkgEntry struct {
	pkg RootPackage
	ok  bool
}

// memoTable is one memoized read. run reports whether its answer may be cached.
type memoTable[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]V
}

func (t *memoTable[K, V]) do(k K, run func() (V, bool)) V {
	t.mu.Lock()
	v, hit := t.m[k]
	t.mu.Unlock()
	if hit {
		return v
	}
	v, settled := run()
	if settled {
		t.mu.Lock()
		if t.m == nil {
			t.m = map[K]V{}
		}
		t.m[k] = v
		t.mu.Unlock()
	}
	return v
}

// resolveVendored is checkout.ResolveVendored. The path is keyed in absolute form, which is what
// the call resolves it to against the working directory.
func (m *InventoryMemo) resolveVendored(path string) (checkout.WorkspacePlan, error) {
	abs, err := filepath.Abs(path)
	if m == nil || path == "" || err != nil {
		return checkout.ResolveVendored(path)
	}
	var runErr error
	plan := m.vendored.do(abs, func() (checkout.WorkspacePlan, bool) {
		p, err := checkout.ResolveVendored(path)
		runErr = err
		return p, err == nil
	})
	if runErr != nil {
		return checkout.WorkspacePlan{}, runErr
	}
	plan.Projects = slices.Clone(plan.Projects)
	return plan, nil
}

// resolveHead is checkout.ResolveHead.
func (m *InventoryMemo) resolveHead(ctx context.Context, dir string) (string, error) {
	if m == nil {
		return checkout.ResolveHead(ctx, dir)
	}
	var runErr error
	sha := m.head.do(dir, func() (string, bool) {
		s, err := checkout.ResolveHead(ctx, dir)
		runErr = err
		return s, err == nil && ctx.Err() == nil
	})
	return sha, runErr
}

// goModuleRoot is checkout.FindGoModuleRoot.
func (m *InventoryMemo) goModuleRoot(dir string) (string, bool) {
	if m == nil {
		return checkout.FindGoModuleRoot(dir)
	}
	e := m.moduleRoot.do(dir, func() (moduleRootEntry, bool) {
		root, ok := checkout.FindGoModuleRoot(dir)
		return moduleRootEntry{root, ok}, true
	})
	return e.root, e.ok
}

// goWorkspace is ResolveGoWorkspace.
func (m *InventoryMemo) goWorkspace(ctx context.Context, buildDir, checkoutRoot, declared string) (GoWorkspace, error) {
	if m == nil {
		return ResolveGoWorkspace(ctx, buildDir, checkoutRoot, declared)
	}
	var runErr error
	ws := m.workspace.do(workspaceKey{buildDir, checkoutRoot, declared}, func() (GoWorkspace, bool) {
		w, err := ResolveGoWorkspace(ctx, buildDir, checkoutRoot, declared)
		runErr = err
		return w, err == nil && ctx.Err() == nil
	})
	return ws, runErr
}

// bazelWorkspaceAbove is BazelWorkspaceAbove. An answer is cached only when the git top-level it
// rests on could be determined.
func (m *InventoryMemo) bazelWorkspaceAbove(moduleRoot string) bool {
	if m == nil {
		return BazelWorkspaceAbove(moduleRoot)
	}
	return m.bazel.do(moduleRoot, func() (bool, bool) {
		return bazelWorkspaceAbove(moduleRoot)
	})
}

// readRootPackage is ReadRootPackage.
func (m *InventoryMemo) readRootPackage(ctx context.Context, buildDir, language string) (RootPackage, bool) {
	if m == nil {
		return ReadRootPackage(ctx, buildDir, language)
	}
	e := m.rootPkg.do(rootPkgKey{buildDir, language}, func() (rootPkgEntry, bool) {
		pkg, ok := ReadRootPackage(ctx, buildDir, language)
		return rootPkgEntry{pkg, ok}, ctx.Err() == nil
	})
	return e.pkg, e.ok
}
