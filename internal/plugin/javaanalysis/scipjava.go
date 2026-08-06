package javaanalysis

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// scipjava.go is the Prove-path-ONLY container seam. It runs the digest-pinned
// scip-java analyzer image over a build dir to produce a semantic `index.scip`,
// which scipindex.go parses into resolved interface→impl call edges.
//
// THE GATE (inv.5 + the free/Assess separation): the analyzer container is
// invoked ONLY when the env var TEGRON_JAVA_ANALYZER_IMAGE is set (the Prove
// pipeline sets it to a digest-pinned ref; Assess never does). When it is unset,
// scipJavaResolve returns ok=false WITHOUT touching docker — so the Assess
// image and every existing Java test are byte-identical pure-Go, with no JDK, no
// container pull, no scip-java. On ANY failure (no docker, image pull/run error,
// non-zero exit / dirty compile, missing or unparseable index.scip) it also
// returns ok=false: the caller falls back to the pure-Go graph and declares
// Partial(tool_failure). It NEVER fabricates an edge — the analyzer does ANALYSIS
// only; the proof is still the sandbox canary detonation on the repro runtime
// image (a SEPARATE image from this analyzer image).

// scipAnalyzerImageEnv is the single env var that gates the Prove-only container
// seam. Set ⇒ Prove path (container-backed semantic graph). Unset ⇒ Assess
// (pure-Go lexical only).
const scipAnalyzerImageEnv = "TEGRON_JAVA_ANALYZER_IMAGE"

// scipDockerBinEnv optionally overrides the docker binary (defaults to "docker").
const scipDockerBinEnv = "TEGRON_JAVA_ANALYZER_DOCKER"

// scipJavaResolve runs the analyzer container over buildDir and parses the emitted
// index.scip into a resolved call graph + ingress set. ok is true ONLY when the
// env gate is set, the container exits cleanly, and a usable index.scip was
// produced and parsed. Every other path returns ok=false (and the caller keeps
// the pure-Go result, declaring Partial(tool_failure) when the gate WAS set but
// the run failed). It never returns a fabricated graph.
func scipJavaResolve(ctx context.Context, buildDir string) (graph scipGraph, gated bool, ok bool) {
	image := os.Getenv(scipAnalyzerImageEnv)
	if image == "" {
		return scipGraph{}, false, false // free/Assess: gate closed, pure-Go only.
	}
	// From here on the Prove gate is OPEN; any failure is an honest tool_failure
	// fallback, never an empty success.
	dockerBin := os.Getenv(scipDockerBinEnv)
	if dockerBin == "" {
		dockerBin = "docker"
	}
	if _, err := exec.LookPath(dockerBin); err != nil {
		return scipGraph{}, true, false
	}

	abs, err := filepath.Abs(buildDir)
	if err != nil {
		return scipGraph{}, true, false
	}

	// Don't mount the source tree directly: scip-java writes index.scip AND a
	// target/ build dir INTO /work, which would mutate (and risk committing into)
	// the vendored repro source. Copy the build dir into an ephemeral, Docker-shared
	// staging dir and mount the COPY instead. macOS Docker Desktop does NOT share
	// /var/folders (os.MkdirTemp's default), so a temp dir there yields an empty
	// bind mount — stage under $HOME, which Docker Desktop shares by default.
	stage, err := stagingDir()
	if err != nil {
		return scipGraph{}, true, false
	}
	defer os.RemoveAll(stage)
	if err := copyTree(abs, stage); err != nil {
		return scipGraph{}, true, false
	}

	// Mirror the validated recipe: bind-mount the staged copy at /work, run
	// `scip-java index` (the image ENTRYPOINT), which autodetects Maven and emits
	// /work/index.scip. The image must be a digest-pinned ref the Prove path owns.
	cmd := exec.CommandContext(ctx, dockerBin, "run", "--rm",
		"-v", stage+":/work",
		image,
		"index", "--output", "/work/index.scip",
	)
	if err := cmd.Run(); err != nil {
		return scipGraph{}, true, false // dirty compile / no docker daemon / pull failure.
	}

	data, err := os.ReadFile(filepath.Join(stage, "index.scip"))
	if err != nil {
		return scipGraph{}, true, false
	}
	g, err := readSCIPIndex(data)
	if err != nil {
		return scipGraph{}, true, false // malformed index ⇒ tool_failure, not a fake edge.
	}
	if len(g.edges) == 0 {
		// A clean run that resolved nothing is honestly no better than pure-Go;
		// signal tool_failure so the caller keeps the lexical (partial) result
		// rather than presenting an empty resolved graph as Complete.
		return scipGraph{}, true, false
	}
	return g, true, true
}

// stagingDir creates an ephemeral build-staging directory the analyzer container
// can bind-mount. It is rooted under $HOME (Docker Desktop's default shared scope
// on macOS) rather than the OS temp dir — /var/folders is NOT shared with Docker
// Desktop, so a bind mount from there appears empty inside the container. The
// caller is responsible for os.RemoveAll.
func stagingDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", err
	}
	base := filepath.Join(home, ".tegron", "java-analyzer-stage")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, "build-")
}

// copyTree recursively copies the regular files and directories under src into dst
// (which must already exist). It deliberately skips symlinks and build output
// (target/index.scip etc. via skipDir) so the staged copy is a clean source tree:
// scip-java's writes land in the disposable staging dir, never the real source.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			if skipDir(d.Name()) && path != src {
				return filepath.SkipDir
			}
			if rel == "." {
				return nil
			}
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinks/devices — not needed for analysis.
		}
		return copyFile(path, target)
	})
}

// copyFile copies a single regular file's contents from src to dst, creating dst's
// parent directory if needed.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
