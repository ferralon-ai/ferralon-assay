package pythonanalysis

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestResolveVersions_Strict: an answer practical mode gives on the assumption that an install
// command in a file nothing runs is inactive is withheld in strict mode as an unreadable install is:
// unresolved, not exhaustive, tool_failure, and no assumption annotation. An answer on no assumption
// is the same in both modes. Practical resolves the same whether or not a strict run shares its caches.
func TestResolveVersions_Strict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		assumed bool
	}{
		{name: "inactive install surface", files: map[string]string{"myDockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN uv sync --frozen && pip install PyJWT==1.0.0\n"}, assumed: true},
		{name: "no assumption"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			resolve := func(strict bool) (pin, absent plugin.DependencyVersionResult) {
				t.Helper()
				for coord, out := range map[string]*plugin.DependencyVersionResult{"jinja2": &pin, "PyJWT": &absent} {
					res, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: coord, Strict: strict})
					if err != nil {
						t.Fatal(err)
					}
					*out = res
				}
				return pin, absent
			}
			assumptions := func(r plugin.DependencyVersionResult) int {
				n := 0
				for _, a := range r.Annotations {
					if strings.HasPrefix(a.Reason, plugin.AnnotationAssumptionPrefix) {
						n++
					}
				}
				return n
			}

			// Strict first, so a practical run after it proves the caches carry nothing across modes.
			strictPin, strictAbsent := resolve(true)
			pin, absent := resolve(false)
			if !pin.Match.Resolved || !absent.Exhaustive {
				t.Fatalf("practical: jinja2 resolved %v, PyJWT exhaustive %v; want both", pin.Match.Resolved, absent.Exhaustive)
			}
			if tc.assumed {
				for _, r := range []plugin.DependencyVersionResult{pin, absent} {
					if !slices.ContainsFunc(r.Annotations, func(a plugin.Annotation) bool { return a.Reason == plugin.AnnotationInstallSurfaceInactive }) {
						t.Errorf("practical annotations = %+v, want %s", r.Annotations, plugin.AnnotationInstallSurfaceInactive)
					}
				}
				if strictPin.Match.Resolved || strictAbsent.Exhaustive {
					t.Errorf("strict: jinja2 resolved %v, PyJWT exhaustive %v; want neither", strictPin.Match.Resolved, strictAbsent.Exhaustive)
				}
				for _, r := range []plugin.DependencyVersionResult{strictPin, strictAbsent} {
					if assumptions(r) != 0 {
						t.Errorf("strict annotations = %+v, want no assumption", r.Annotations)
					}
					if !slices.Contains(r.Partiality.Reasons, plugin.PartialReasonToolFailure) {
						t.Errorf("strict partiality = %+v, want tool_failure", r.Partiality)
					}
				}
				return
			}
			if assumptions(pin)+assumptions(absent) != 0 {
				t.Errorf("control practical annotations = %+v, %+v, want none", pin.Annotations, absent.Annotations)
			}
			if !reflect.DeepEqual(pin, strictPin) || !reflect.DeepEqual(absent, strictAbsent) {
				t.Errorf("control differs by mode:\npractical %+v / %+v\nstrict    %+v / %+v", pin, absent, strictPin, strictAbsent)
			}
		})
	}
}
