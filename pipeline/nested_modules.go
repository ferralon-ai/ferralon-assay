package pipeline

import (
	"context"
	"sync"

	"github.com/ferralon-ai/ferralon-assay/checkout/gomodtree"
)

// nestedModuleMemo holds one nested-module walk per (checkout root, build dir).
type nestedModuleMemo struct {
	mu    sync.Mutex
	trees map[[2]string]gomodtree.Tree
}

type nestedModuleMemoKey struct{}

// WithNestedModuleMemo returns ctx carrying a memo of the nested-module walk intake's Go
// no-manifest-entry guard reads (goModRequires). Every advisory of a scan assesses one checked-out
// tree, so a scan installs one memo for all of them and the tree is walked once per build directory
// instead of once per advisory. Without a memo every advisory walks the tree itself. A ctx that
// already carries one is returned as is.
func WithNestedModuleMemo(ctx context.Context) context.Context {
	if _, ok := ctx.Value(nestedModuleMemoKey{}).(*nestedModuleMemo); ok {
		return ctx
	}
	return context.WithValue(ctx, nestedModuleMemoKey{}, &nestedModuleMemo{trees: map[[2]string]gomodtree.Tree{}})
}

// nestedModules returns gomodtree.Nested(root, buildDir), walked once per ctx memo.
func nestedModules(ctx context.Context, root, buildDir string) gomodtree.Tree {
	m, ok := ctx.Value(nestedModuleMemoKey{}).(*nestedModuleMemo)
	if !ok {
		return gomodtree.Nested(root, buildDir)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := [2]string{root, buildDir}
	t, ok := m.trees[key]
	if !ok {
		t = gomodtree.Nested(root, buildDir)
		m.trees[key] = t
	}
	return t
}
