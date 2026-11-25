package pythonanalysis

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// py2Tree is a build whose manifests are not all read in full (the Dockerfile installs a distribution by name), whose
// pkg/views.py imports its sibling module pkg/forms.py by bare name, as Python 2 reads an
// import the file does not declare absolute, and imports rest_framework, which only a curated
// row binds to its declared distribution.
func py2Tree(extra map[string]string) map[string]string {
	files := map[string]string{
		"requirements.txt": "djangorestframework==3.1.2\n",
		"Dockerfile":       "FROM python:2.7\nRUN pip install setuptools_scm\n",
		"pkg/__init__.py":  "",
		"pkg/forms.py":     "def clean():\n    pass\n",
		"pkg/views.py":     "import forms\nimport rest_framework\n\ndef view():\n    forms.clean()\n",
	}
	maps.Copy(files, extra)
	return files
}

// TestCallGraph_Py2RelativeImportStrictVersusPractical: practical mode attributes the bare
// sibling import as a Python 2 implicit relative import and names that assumption in an
// Annotation; strict mode leaves it unattributed and declares tool_failure, naming the import.
func TestCallGraph_Py2RelativeImportStrictVersusPractical(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncached", true: "run cache"}[cached], func(t *testing.T) {
			ctx := context.Background()
			if cached {
				ctx = cachedCtx(t)
			}
			dir := writeTree(t, py2Tree(nil))
			practical, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if hasReason(practical.Partiality, plugin.PartialReasonToolFailure) {
				t.Errorf("practical: tool_failure declared (reasons %v, cause %q)", practical.Partiality.Reasons, practical.Partiality.Cause)
			}
			if len(practical.Annotations) != 1 {
				t.Fatalf("practical: annotations = %+v, want one", practical.Annotations)
			}
			a := practical.Annotations[0]
			if a.Reason != AnnotationPy2RelativeImport || a.Path != "pkg/views.py" || !strings.Contains(a.Detail, "import of forms") || !strings.Contains(a.Detail, "Dockerfile") {
				t.Errorf("practical: annotation = %+v", a)
			}

			strict, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir, Strict: true})
			if err != nil {
				t.Fatalf("CallGraph strict: %v", err)
			}
			if !hasReason(strict.Partiality, plugin.PartialReasonToolFailure) {
				t.Errorf("strict: no tool_failure (reasons %v)", strict.Partiality.Reasons)
			}
			if len(strict.Annotations) != 0 {
				t.Errorf("strict: annotations = %+v, want none", strict.Annotations)
			}
			for _, want := range []string{"import of forms", "pkg/views.py", "Dockerfile", "Python 2"} {
				if !strings.Contains(strict.Partiality.Cause, want) {
					t.Errorf("strict: cause %q does not name %q", strict.Partiality.Cause, want)
				}
			}
			if hasReason(practical.Partiality, plugin.PartialReasonToolFailure) {
				t.Errorf("practical result changed after a strict call: %v", practical.Partiality.Reasons)
			}

			reach := func(strict bool) plugin.ReachabilityResult {
				r, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{"rest_framework.views.APIView"}, Strict: strict})
				if err != nil {
					t.Fatalf("Reachability strict=%v: %v", strict, err)
				}
				return r
			}
			if r := reach(false); len(r.Annotations) != 1 || r.Annotations[0] != a || hasReason(r.Partiality, plugin.PartialReasonToolFailure) {
				t.Errorf("practical reachability: annotations %+v, reasons %v", r.Annotations, r.Partiality.Reasons)
			}
			if r := reach(true); len(r.Annotations) != 0 || !hasReason(r.Partiality, plugin.PartialReasonToolFailure) || r.Partiality.Cause != strict.Partiality.Cause {
				t.Errorf("strict reachability: annotations %+v, reasons %v, cause %q", r.Annotations, r.Partiality.Reasons, r.Partiality.Cause)
			}
			if again, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir}); err != nil || len(again.Annotations) != 1 || hasReason(again.Partiality, plugin.PartialReasonToolFailure) {
				t.Errorf("practical call graph after strict calls: err %v, annotations %+v, reasons %v", err, again.Annotations, again.Partiality.Reasons)
			}
		})
	}
}

// TestCallGraph_Py2RelativeImportSkips: each condition under which the lane does not read a bare
// sibling import as relative leaves it unattributed, so the graph declares tool_failure naming
// it and rests on no assumption.
func TestCallGraph_Py2RelativeImportSkips(t *testing.T) {
	cases := []struct {
		name    string
		extra   map[string]string
		binding string
	}{
		{
			name:    "the file declares absolute imports",
			extra:   map[string]string{"pkg/views.py": "from __future__ import absolute_import\nimport forms\nimport rest_framework\n\ndef view():\n    forms.clean()\n"},
			binding: "import of forms",
		},
		{
			name:    "the build declares a Python 3 interpreter",
			extra:   map[string]string{".python-version": "3.11.9\n"},
			binding: "import of forms",
		},
		{
			name: "the bare name is a declared distribution's import name",
			extra: map[string]string{
				"requirements.txt":      "djangorestframework==3.1.2\nazure-core==1.30.0\n",
				"pkg/azure/__init__.py": "",
				"pkg/azure/identity.py": "",
				"pkg/views.py":          "import azure.identity\nimport rest_framework\n",
			},
			binding: "import of azure in",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, py2Tree(c.extra))})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) || len(res.Annotations) != 0 {
				t.Fatalf("reasons %v, annotations %+v: want tool_failure and no assumption", res.Partiality.Reasons, res.Annotations)
			}
			for _, want := range []string{c.binding, "pkg/views.py", "Dockerfile"} {
				if !strings.Contains(res.Partiality.Cause, want) {
					t.Errorf("cause %q does not name %q", res.Partiality.Cause, want)
				}
			}
			if strings.Contains(res.Partiality.Cause, "Python 2") {
				t.Errorf("cause %q names the relative reading the lane did not take", res.Partiality.Cause)
			}
		})
	}
}

// TestCallGraph_CuratedOnlyImportAttributed: an import only a curated row binds to a declared
// distribution (rest_framework, djangorestframework) is attributed even when a manifest is not
// read in full.
func TestCallGraph_CuratedOnlyImportAttributed(t *testing.T) {
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, py2Tree(map[string]string{
		"pkg/views.py": "import rest_framework\n",
	}))})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if hasReason(res.Partiality, plugin.PartialReasonToolFailure) || len(res.Annotations) != 0 {
		t.Errorf("reasons %v, cause %q, annotations %+v: want rest_framework attributed", res.Partiality.Reasons, res.Partiality.Cause, res.Annotations)
	}
}
