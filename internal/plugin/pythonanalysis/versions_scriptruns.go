package pythonanalysis

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
)

// runRecorder wraps a lane Spec's Allowed to record the pip installs script surfaces run
// (scriptRun). A withheld run is kept only when the rule withholds on the surface that runs
// it, and an allowed self-upgrade only when the surface is not a sample hook, so a sample hook
// git never runs records nothing.
type runRecorder struct {
	inner   func(words []string, b scriptsurface.Binder) bool
	tooling map[string]bool
	surface string
	pending []scriptRun
	runs    []scriptRun
	// withheld holds each surface the rule withheld on, with its head, for rescan.
	withheld []surfaceHead
	// laneRead, set on a rescan's recorder, is the lane's read: a -r file it reads is a
	// manifest the inventory already holds. The rescan records every pip install, allowing
	// every command, and resolves each -r file against the directory the command runs in.
	laneRead func(string) bool
}

type surfaceHead struct {
	path string
	head []byte
}

func (r *runRecorder) allowed(words []string, b scriptsurface.Binder) bool {
	ok := r.inner(words, b)
	args, isPip := pipInstallArgs(words)
	switch {
	case !isPip:
	case r.laneRead != nil:
		r.pending = append(r.pending, r.resolve(args, b))
	case !ok, r.tooling != nil && pipSelfUpgrade(args):
		r.pending = append(r.pending, scriptRun{surface: r.surface, args: args})
	}
	return ok || r.laneRead != nil
}

// resolve is a run whose -r files are the build-tree files each names from every directory
// the command may run in (Binder.Hosts), less those the lane already reads. A -r naming no
// such file (an absolute path, an unknown directory) names nothing.
func (r *runRecorder) resolve(args []string, b scriptsurface.Binder) scriptRun {
	run := scriptRun{surface: r.surface, args: args}
	for _, p := range pipRequirementFiles(args) {
		for _, h := range b.Hosts(p) {
			if !r.laneRead(h) {
				run.files = append(run.files, filepath.Clean(h))
			}
		}
	}
	return run
}

// classify is veto's classifier, keeping the runs a surface recorded when the rule withholds
// on it (the classifier reports it without asking pyInstallSurface), or when the rule allows it
// and it is not a sample hook, for its self-upgrades.
func (r *runRecorder) classify(root string, veto *scriptsurface.Veto) func(string, []byte) (string, bool) {
	var matched bool
	inner := veto.Classify(func(path string, head []byte) (string, bool) {
		matched = true
		return pyInstallSurface(path, head)
	})
	return func(path string, head []byte) (string, bool) {
		r.surface, r.pending, matched = path, nil, false
		why, ok := inner(path, head)
		switch {
		case ok && !matched:
			r.withheld = append(r.withheld, surfaceHead{path, slices.Clone(head)})
			r.runs = append(r.runs, r.pending...)
		case !sampleHook(root, path):
			for _, run := range r.pending {
				if pipSelfUpgrade(run.args) {
					r.runs = append(r.runs, run)
				}
			}
		}
		r.pending = nil
		return why, ok
	}
}

// sampleHook reports whether p is a git sample hook (pre-commit.sample) directly in a .git
// hooks directory, the build root's, a nested repository's or a submodule's, which git never
// runs. It is scriptsurface's own test.
func sampleHook(root, p string) bool {
	if stem, ok := strings.CutSuffix(filepath.Base(p), ".sample"); !ok || stem == "" {
		return false
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	n := len(parts)
	if n < 3 || parts[n-2] != "hooks" {
		return false
	}
	if parts[n-3] == ".git" {
		return true
	}
	for i := 0; i+1 < n-3; i++ {
		if parts[i] == ".git" && parts[i+1] == "modules" {
			return true
		}
	}
	return false
}

// pipInstallArgs returns pip's arguments after install when words runs pip install: pip,
// python -m pip or uv pip.
func pipInstallArgs(words []string) ([]string, bool) {
	head, ok := scriptsurface.CommandName(words[0])
	if !ok {
		return nil, false
	}
	var rest []string
	switch {
	case pipHeadRE.MatchString(head):
		rest = words[1:]
	case pythonHeadRE.MatchString(head) && len(words) >= 3 && words[1] == "-m" && pipHeadRE.MatchString(words[2]):
		rest = words[3:]
	case head == "uv" && len(words) >= 2 && words[1] == "pip":
		rest = words[2:]
	default:
		return nil, false
	}
	if len(rest) == 0 || rest[0] != "install" {
		return nil, false
	}
	return rest[1:], true
}

// rescan replaces the runs recorded on each surface the rule withheld on with those a second
// read records when every command is allowed. The rule stops at a surface's first withholding
// command, so the first read records only the first pip install it rejects; the second reads
// on to a command it withholds for another reason. spec is a fresh lane Spec, and the second
// read treats every file as read so each -r resolves (Binder.Hosts), so it changes none of the
// first's installs, tooling or Veto state.
func (r *runRecorder) rescan(root string, read func(string) bool, spec scriptsurface.Spec) {
	if len(r.withheld) == 0 {
		return
	}
	again := map[string]bool{}
	for _, w := range r.withheld {
		again[w.path] = true
	}
	kept := r.runs[:0:0]
	for _, run := range r.runs {
		if !again[run.surface] {
			kept = append(kept, run)
		}
	}
	second := &runRecorder{inner: spec.Allowed, laneRead: read}
	spec.Allowed = second.allowed
	classify := scriptsurface.New(root, func(string) bool { return true }, spec).Classify(pyInstallSurface)
	for _, w := range r.withheld {
		second.surface, second.pending = w.path, nil
		classify(w.path, w.head)
		second.runs = append(second.runs, second.pending...)
	}
	r.runs = append(kept, second.runs...)
}
