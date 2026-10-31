package pythonanalysis

import (
	"slices"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
)

// runRecorder wraps a lane Spec's Allowed to record the pip installs script surfaces run
// (scriptRun). A withheld run is kept only when the rule withholds on the surface that runs
// it, so a sample hook git never runs records nothing; an allowed self-upgrade is kept
// wherever it runs, as the tooling it installs is.
type runRecorder struct {
	inner   func(words []string, b scriptsurface.Binder) bool
	tooling map[string]bool
	all     bool // allow every command, so the rule reads a surface past its pip installs
	surface string
	pending []scriptRun
	runs    []scriptRun
	// withheld holds each surface the rule withheld on, with its head, for rescan.
	withheld []surfaceHead
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
	case !ok:
		r.pending = append(r.pending, scriptRun{surface: r.surface, args: args})
	case r.tooling != nil && pipSelfUpgrade(args):
		r.runs = append(r.runs, scriptRun{surface: r.surface, args: args})
	}
	return ok || r.all
}

// classify is veto's classifier, keeping the runs a surface recorded when the rule withholds
// on it: the classifier reports it without asking pyInstallSurface.
func (r *runRecorder) classify(veto *scriptsurface.Veto) func(string, []byte) (string, bool) {
	var matched bool
	inner := veto.Classify(func(path string, head []byte) (string, bool) {
		matched = true
		return pyInstallSurface(path, head)
	})
	return func(path string, head []byte) (string, bool) {
		r.surface, r.pending, matched = path, nil, false
		why, ok := inner(path, head)
		if ok && !matched {
			r.withheld = append(r.withheld, surfaceHead{path, slices.Clone(head)})
			r.runs = append(r.runs, r.pending...)
		}
		r.pending = nil
		return why, ok
	}
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
// on to a command it withholds for another reason. spec is a fresh lane Spec, so the second
// read changes none of the first's installs or tooling.
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
	second := &runRecorder{inner: spec.Allowed, tooling: r.tooling, all: true}
	spec.Allowed = second.allowed
	// Allowing every command, the rule withholds on none of these surfaces for a pip install,
	// so every run it records is kept.
	classify := scriptsurface.New(root, read, spec).Classify(pyInstallSurface)
	for _, w := range r.withheld {
		second.surface, second.pending = w.path, nil
		classify(w.path, w.head)
		second.runs = append(second.runs, second.pending...)
	}
	r.runs = append(kept, second.runs...)
}
