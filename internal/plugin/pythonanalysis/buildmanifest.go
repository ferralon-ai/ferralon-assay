package pythonanalysis

// Build-context manifest derivation for Python (PLAN-173, §4.6 / §5.4 deliverable 8's
// build-context half: interpreter/version, platform, project roots, resolver provenance).
//
// BuildManifest is the build-context COUNTERPART to ResolveInventory: ResolveInventory
// answers "what is the selected dependency graph", this answers "for which runtime, on
// which platform, from which project root, resolved by which of the six manifest/lockfile
// formats". Every value is DECLARED — read from pyproject.toml (requires-python, optional
// extras, declared target environments), a lockfile's declared python constraint, a
// .python-version pin, and the manifest/lockfile set already on disk. No interpreter is
// launched, no package manager invoked, no PEP 517 backend or install hook runs (§3.3);
// the same C5-clean posture ResolveInventory holds.
//
// Honest partiality (§3.1/§3.5): an undeterminable interpreter version is a PARTIAL
// manifest naming what could not be determined — never a guessed version, and never
// Unsupported() (which after PLAN-173 would be a false claim that the op is unimplemented).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// BuildManifest derives the ecosystem-neutral build context for the checked-out Python
// module at req.BuildDir from DECLARED metadata only. A missing/unreadable build dir is a
// hard error (inv.4). When the interpreter version cannot be determined from any declared
// source, the result is partial-with-a-named-reason, not a guessed version (C2).
func BuildManifest(_ context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	info, err := os.Stat(req.BuildDir)
	if err != nil {
		return plugin.BuildManifestResult{}, fmt.Errorf("pythonanalysis: stat build dir %q: %w", req.BuildDir, err)
	}
	if !info.IsDir() {
		return plugin.BuildManifestResult{}, fmt.Errorf("pythonanalysis: build dir %q is not a directory", req.BuildDir)
	}

	meta := readPyprojectMeta(req.BuildDir)

	// Interpreter version: declared requires-python, falling back to a lockfile-declared
	// python constraint (uv.lock / pdm.lock), then a .python-version pin. Never probed by
	// launching an interpreter (§3.3); undetermined stays "" and is NOT guessed.
	pin := readPythonVersionPin(req.BuildDir)
	version := meta.requiresPython
	if version == "" {
		version = lockfileRequiresPython(req.BuildDir)
	}
	if version == "" {
		version = pin
	}

	// Toolchain: the stronger, exact pin when the manifest declares one — a .python-version
	// file, or an exact "==X.Y.Z" requires-python. A range/minimum requires-python is NOT a
	// toolchain pin, so Toolchain stays "".
	toolchain := pin
	if toolchain == "" {
		toolchain = exactPin(meta.requiresPython)
	}

	res := plugin.BuildManifestResult{
		Runtime:       plugin.RuntimeSpec{Name: "python", Version: version, Toolchain: toolchain},
		Target:        meta.target,
		Configuration: buildConfiguration(meta.extras, constraintFiles(req.BuildDir)),
		// The WorkspacePlan project root the pipeline resolves and passes in as BuildDir
		// (checkout.WorkspacePlan.Primary().Root); the inventory path likewise carries it as
		// DependencyMembership.Project. Multi-root enumeration is PLAN-400.
		ProjectRoot: req.BuildDir,
		Resolver:    detectResolver(req.BuildDir),
	}

	// PartialReasonEnvConditionUnresolved is the closest existing shared code (the runtime
	// environment descriptor is undetermined because the deciding environment fact — the
	// interpreter version — is unknown). The ":requires_python" suffix localises it per the
	// §4 naming convention documented on the constant, so the reason NAMES the missing input
	// without minting a new PartialReason constant.
	// TODO(PLAN-371): PLAN-371 owns the Python partiality vocabulary. If it mints a
	// manifest-specific runtime-undeclared reason code, adopt it here in place of the
	// env_condition_unresolved:requires_python ride.
	if version == "" {
		res.Partiality = plugin.Partial(plugin.PartialReasonEnvConditionUnresolved + ":requires_python")
	} else {
		res.Partiality = plugin.Complete()
	}
	return res, nil
}

// pyprojectMeta is the declared build-context read from a project's pyproject.toml.
type pyprojectMeta struct {
	requiresPython string   // [project] requires-python, verbatim (a range or an exact pin)
	extras         []string // [project.optional-dependencies] group names, sorted
	target         string   // declared sys_platform[/platform_machine], "" if undeclared
}

// readPyprojectMeta reads the build-context metadata pyproject.toml declares. It reuses the
// codebase's pure-Go BurntSushi/toml decoder (no shell-out — C5-clean); an absent or
// unparseable file yields the zero value (every field undetermined), degraded downstream to
// partiality rather than fabricated.
func readPyprojectMeta(dir string) pyprojectMeta {
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return pyprojectMeta{}
	}
	var doc struct {
		Project struct {
			RequiresPython       string              `toml:"requires-python"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		Tool struct {
			UV struct {
				Environments         interface{} `toml:"environments"`
				RequiredEnvironments interface{} `toml:"required-environments"`
			} `toml:"uv"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return pyprojectMeta{}
	}
	m := pyprojectMeta{requiresPython: strings.TrimSpace(doc.Project.RequiresPython)}
	for group := range doc.Project.OptionalDependencies {
		m.extras = append(m.extras, group)
	}
	sort.Strings(m.extras) // group names come from a map; sort for determinism (C7)
	markers := append(toStrings(doc.Tool.UV.Environments), toStrings(doc.Tool.UV.RequiredEnvironments)...)
	m.target = declaredTarget(markers)
	return m
}

// declaredTarget composes the declared target platform from PEP 508 environment markers
// (uv's declared target environments), extracting sys_platform / platform_machine equality
// constraints. It mirrors targetDescriptor's "plat/mach" shape (inventory.go) so the build
// context and the per-node provenance agree.
func declaredTarget(markers []string) string {
	var plat, mach string
	for _, mk := range markers {
		if plat == "" {
			plat = markerEquality(mk, "sys_platform")
		}
		if mach == "" {
			mach = markerEquality(mk, "platform_machine")
		}
	}
	switch {
	case plat != "" && mach != "":
		return plat + "/" + mach
	case plat != "":
		return plat
	case mach != "":
		return mach
	default:
		return ""
	}
}

// markerEquality extracts the string literal from a `key == "value"` clause in a PEP 508
// marker, or "" when key is not equality-constrained. It reads a declared equality only —
// it does not evaluate the marker (no environment is probed).
func markerEquality(marker, key string) string {
	i := strings.Index(marker, key)
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(marker[i+len(key):])
	if !strings.HasPrefix(rest, "==") {
		return ""
	}
	rest = strings.TrimSpace(rest[2:])
	if rest == "" {
		return ""
	}
	quote := rest[0]
	if quote != '\'' && quote != '"' {
		return ""
	}
	if j := strings.IndexByte(rest[1:], quote); j >= 0 {
		return rest[1 : 1+j]
	}
	return ""
}

// lockfileRequiresPython reads a declared python constraint from a lockfile when
// pyproject.toml declared none: uv.lock's top-level `requires-python`, then pdm.lock's
// `[metadata] requires_python`. This is the "lockfile environment metadata" fallback whose
// joint absence with requires-python triggers the partial manifest (C2 outcome b).
func lockfileRequiresPython(dir string) string {
	if data, err := os.ReadFile(filepath.Join(dir, "uv.lock")); err == nil {
		var doc struct {
			RequiresPython string `toml:"requires-python"`
		}
		if toml.Unmarshal(data, &doc) == nil {
			if v := strings.TrimSpace(doc.RequiresPython); v != "" {
				return v
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "pdm.lock")); err == nil {
		var doc struct {
			Metadata struct {
				RequiresPython string `toml:"requires_python"`
			} `toml:"metadata"`
		}
		if toml.Unmarshal(data, &doc) == nil {
			if v := strings.TrimSpace(doc.Metadata.RequiresPython); v != "" {
				return v
			}
		}
	}
	return ""
}

// readPythonVersionPin reads an exact interpreter pin from a .python-version file (pyenv /
// uv toolchain pin), returning the first non-empty line, or "" when absent.
func readPythonVersionPin(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, ".python-version"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}

// exactPin returns the pinned version from an exact "==X.Y.Z" requires-python, or "" for a
// range/minimum spec (which is a floor, not a toolchain pin).
func exactPin(requiresPython string) string {
	s := strings.TrimSpace(requiresPython)
	if strings.HasPrefix(s, "==") {
		return strings.TrimSpace(s[2:])
	}
	return ""
}

// constraintFiles lists the top-level constraints*.txt files (pip constraint files) in the
// build dir, sorted for determinism.
func constraintFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "constraints") && strings.HasSuffix(name, ".txt") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// buildConfiguration renders the declared extras selection and any constraint files in
// effect as the build configuration/profile string ("" when neither is declared).
func buildConfiguration(extras, constraints []string) string {
	var parts []string
	if len(extras) > 0 {
		parts = append(parts, "extras=["+strings.Join(extras, ",")+"]")
	}
	if len(constraints) > 0 {
		parts = append(parts, "constraints=["+strings.Join(constraints, ",")+"]")
	}
	return strings.Join(parts, "; ")
}

// detectResolver reports which of the six manifest/lockfile formats produced the answer,
// reusing PLAN-170's format detection (manifestFiles). A lockfile beats a bare manifest
// (a lock pins what a manifest only ranges); the priority matches nodeProvenance's
// lockfile→resolver mapping (inventory.go). Command is a NEUTRAL declared invocation, never
// executed (§3.3).
func detectResolver(dir string) plugin.ResolverSpec {
	present := map[string]bool{}
	for _, m := range manifestFiles(dir) {
		present[filepath.Base(m)] = true
	}
	switch {
	case present["pdm.lock"]:
		return plugin.ResolverSpec{Name: "pdm", Command: "pdm lock"}
	case present["uv.lock"]:
		return plugin.ResolverSpec{Name: "uv", Command: "uv lock"}
	case present["poetry.lock"]:
		return plugin.ResolverSpec{Name: "poetry", Command: "poetry lock"}
	case present["Pipfile.lock"]:
		return plugin.ResolverSpec{Name: "pipenv", Command: "pipenv lock"}
	case present["pyproject.toml"]:
		return plugin.ResolverSpec{Name: "pip", Command: "pip install ."}
	default:
		var reqs []string
		for base := range present {
			if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
				reqs = append(reqs, base)
			}
		}
		sort.Strings(reqs)
		if len(reqs) > 0 {
			return plugin.ResolverSpec{Name: "pip", Command: "pip install -r " + reqs[0]}
		}
		return plugin.ResolverSpec{}
	}
}

// toStrings coerces a TOML value that may be a single string or an array of strings into a
// []string (uv's `environments` accepts both shapes). Non-string entries are dropped.
func toStrings(v interface{}) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []interface{}:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
