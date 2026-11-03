package goanalysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type goWorkKey struct{}

// withGoWork returns ctx carrying the GOWORK the analyzed build runs under, as the host resolved it
// for the request: "" or "off" for none, else the absolute path of the build's go.work. The
// analyzer never derives it: the process's own GOWORK describes where the analyzer runs, not the
// build, and a relative path would resolve against whatever directory each go command runs in.
func withGoWork(ctx context.Context, goWork string) (context.Context, error) {
	if goWork != "" && goWork != "off" && !filepath.IsAbs(goWork) {
		return ctx, fmt.Errorf("go_work %q is neither off nor an absolute path", goWork)
	}
	return context.WithValue(ctx, goWorkKey{}, goWork), nil
}

// goWork is the GOWORK the analyzed build runs under: off unless the request named a go.work.
func goWork(ctx context.Context) string {
	if v, _ := ctx.Value(goWorkKey{}).(string); v != "" {
		return v
	}
	return "off"
}

// buildEnv returns base with GOWORK set to the build's, so a go command run under it loads the
// build's workspace and no other. The go command reads the last of duplicate keys.
func buildEnv(ctx context.Context, base []string) []string {
	out := make([]string, len(base), len(base)+1)
	copy(out, base)
	return append(out, "GOWORK="+goWork(ctx))
}

// analyzerEnv is buildEnv over the analyzer's own environment: the environment every go command and
// every cache key the analyzer derives from the tree uses.
func analyzerEnv(ctx context.Context) []string {
	return buildEnv(ctx, os.Environ())
}
