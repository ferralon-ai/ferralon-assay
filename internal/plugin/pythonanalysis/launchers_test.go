package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestFindIngresses_Launchers: an entry point a launcher starts — a Celery task, a WSGI or
// ASGI callable, a manifest's script or entry point, a Django URL pattern's view or
// application setting — is an ingress of its kind and a call-graph root, and a first-party
// launcher naming no function the lane sees makes ingress discovery partial.
func TestFindIngresses_Launchers(t *testing.T) {
	type ing struct{ kind, scip, selector string }
	cli := "def main():\n    return run()\n\ndef run():\n    return 0\n"
	cases := []struct {
		name    string
		files   map[string]string
		want    []ing    // ingresses that must be found
		absent  []string // symbols that must be no ingress
		roots   []string // must be call-graph roots
		partial bool     // ingress discovery is partial (unsupported)
	}{
		{
			name:  "Celery app task",
			files: map[string]string{"tasks.py": "from celery import Celery\napp = Celery()\n\n@app.task(bind=True)\ndef send(self, to):\n    return to\n"},
			want:  []ing{{"task", funcSCIP("tasks", nil, "send", 2), "task"}},
			roots: []string{funcSCIP("tasks", nil, "send", 2)},
		},
		{
			name:  "Celery shared task, bare decorator",
			files: map[string]string{"tasks.py": "from celery import shared_task\n\n@shared_task\ndef add(x, y):\n    return x + y\n"},
			want:  []ing{{"task", funcSCIP("tasks", nil, "add", 2), "shared_task"}},
		},
		{
			name:   "decorator that is no task",
			files:  map[string]string{"tasks.py": "import functools\n\n@functools.cache\ndef add(x, y):\n    return x + y\n"},
			absent: []string{funcSCIP("tasks", nil, "add", 2)},
		},
		{
			name:  "WSGI application function",
			files: map[string]string{"wsgi.py": "def application(environ, start_response):\n    return []\n"},
			want:  []ing{{"http_server", funcSCIP("wsgi", nil, "application", 2), "wsgi"}},
			roots: []string{funcSCIP("wsgi", nil, "application", 2)},
		},
		{
			name:  "ASGI application class",
			files: map[string]string{"asgi.py": "class App:\n    async def __call__(self, scope, receive, send):\n        return None\n"},
			want:  []ing{{"http_server", funcSCIP("asgi", []string{"App"}, "__call__", 4), "asgi"}},
		},
		{
			name:   "function with other parameters is no server callable",
			files:  map[string]string{"app.py": "def handle(environ, start_response, extra):\n    return []\n"},
			absent: []string{funcSCIP("app", nil, "handle", 3)},
		},
		{
			name: "pyproject console and GUI scripts",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n\n[project.gui-scripts]\ntool-gui = \"tool.cli:run [gui]\"\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			want: []ing{
				{"main", funcSCIP("tool/cli", nil, "main", 0), "tool"},
				{"main", funcSCIP("tool/cli", nil, "run", 0), "tool-gui"},
			},
			roots: []string{funcSCIP("tool/cli", nil, "main", 0)},
		},
		{
			name: "pyproject plugin entry point is a root, no ingress",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.entry-points.\"pytest11\"]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			absent: []string{funcSCIP("tool/cli", nil, "main", 0)},
			roots:  []string{funcSCIP("tool/cli", nil, "main", 0)},
		},
		{
			name: "entry point naming a module loads all of it",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.entry-points.pytest11]\ntool = \"tool.cli\"\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			roots: []string{funcSCIP("tool/cli", nil, "main", 0), funcSCIP("tool/cli", nil, "run", 0)},
		},
		{
			name: "Poetry scripts, string and table",
			files: map[string]string{
				"pyproject.toml":   "[tool.poetry]\nname = \"tool\"\n\n[tool.poetry.scripts]\ntool = \"tool.cli:main\"\nother = { callable = \"tool.cli:run\" }\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			want: []ing{
				{"main", funcSCIP("tool/cli", nil, "main", 0), "tool"},
				{"main", funcSCIP("tool/cli", nil, "run", 0), "other"},
			},
		},
		{
			name: "setup.cfg console script",
			files: map[string]string{
				"setup.cfg":        "[metadata]\nname = tool\n\n[options.entry_points]\nconsole_scripts =\n    tool = tool.cli:main\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			want: []ing{{"main", funcSCIP("tool/cli", nil, "main", 0), "tool"}},
		},
		{
			name: "setup.py console script, list and ini string",
			files: map[string]string{
				"setup.py":         "from setuptools import setup\n\nsetup(\n    name=\"tool\",\n    entry_points={\"console_scripts\": [\"tool = tool.cli:main\"]},\n)\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			want: []ing{{"main", funcSCIP("tool/cli", nil, "main", 0), "tool"}},
		},
		{
			name: "setup.py ini-style entry points",
			files: map[string]string{
				"setup.py":         "from setuptools import setup\n\nsetup(name=\"tool\", entry_points=\"\"\"\n[console_scripts]\ntool = tool.cli:run\n\"\"\")\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			want: []ing{{"main", funcSCIP("tool/cli", nil, "run", 0), "tool"}},
		},
		{
			name: "script through a package re-export",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool:main\"\n",
				"tool/__init__.py": "from .cli import main\n", "tool/cli.py": cli,
			},
			want: []ing{{"main", funcSCIP("tool/cli", nil, "main", 0), "tool"}},
		},
		{
			name: "script naming a nested def resolves to nothing",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/cli.py": "def make():\n    def main():\n        return 0\n    return main\n\nmain = make()\n",
			},
			absent:  []string{funcSCIP("tool/cli", nil, "main", 0)},
			roots:   []string{funcSCIP("tool/cli", nil, "make", 0)},
			partial: true,
		},
		{
			name: "script naming a dependency is no ingress and not partial",
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"click.testing:main\"\n",
				"app.py":         cli,
			},
			absent: []string{funcSCIP("app", nil, "main", 0)},
		},
		{
			name: "Django path to an imported views module",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def index(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom . import views\n\nurlpatterns = [\n    path(\"\", views.index, name=\"index\"),\n]\n",
			},
			want:  []ing{{"http_route", funcSCIP("site/views", nil, "index", 1), ""}},
			roots: []string{funcSCIP("site/views", nil, "index", 1)},
		},
		{
			name: "Django re_path to an imported view function",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def detail(request, pk):\n    return None\n",
				"site/urls.py": "from django.urls import re_path\nfrom site.views import detail\n\nurlpatterns = [re_path(r\"^item/(?P<pk>\\d+)$\", detail)]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "detail", 2), `^item/(?P<pk>\d+)$`}},
		},
		{
			name: "Django class-based view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "from django.views import View\n\nclass Items(View):\n    def get(self, request):\n        return None\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", []string{"Items"}, "get", 2), "items/"}},
		},
		{
			name: "Django include and a non-django path are no views",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def index(request):\n    return None\n",
				"site/urls.py": "from django.urls import include, path\nfrom pathlib import Path\nfrom site import views\n\nurlpatterns = [path(\"api/\", include(\"api.urls\"))]\nP = Path(\"x\", views.index)\n",
			},
			absent: []string{funcSCIP("site/views", nil, "index", 1)},
		},
		{
			name: "Django WSGI_APPLICATION naming a function",
			files: map[string]string{
				"site/__init__.py": "", "site/settings.py": "WSGI_APPLICATION = \"site.wsgi.app\"\n",
				"site/wsgi.py": "def app(env, start):\n    return []\n",
			},
			want: []ing{{"http_server", funcSCIP("site/wsgi", nil, "app", 2), "WSGI_APPLICATION"}},
		},
		{
			name: "Django WSGI_APPLICATION naming a value is not partial",
			files: map[string]string{
				"site/__init__.py": "", "site/settings.py": "WSGI_APPLICATION = \"site.wsgi.application\"\n",
				"site/wsgi.py": "from django.core.wsgi import get_wsgi_application\napplication = get_wsgi_application()\n",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("FindIngresses: %v", err)
			}
			for _, w := range tc.want {
				found := false
				for _, in := range res.Ingresses {
					found = found || (in.Kind == w.kind && in.Symbol.SCIP == w.scip && in.Selector == w.selector)
				}
				if !found {
					t.Errorf("missing ingress %+v; got %+v", w, res.Ingresses)
				}
			}
			for _, a := range tc.absent {
				if in, ok := ingressFor(res.Ingresses, a); ok {
					t.Errorf("unexpected ingress %+v", in)
				}
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonUnsupported); got != tc.partial {
				t.Errorf("unsupported = %v, want %v (partiality %+v)", got, tc.partial, res.Partiality)
			}
			if tc.partial == false && !res.Partiality.Complete {
				t.Errorf("ingress discovery must be complete; got %+v", res.Partiality)
			}
			roots := symbolSet(mustCallGraph(t, tc.files).Roots)
			for _, r := range tc.roots {
				if !roots[r] {
					t.Errorf("%s must be a root; roots %v", r, roots)
				}
			}
		})
	}
}

// TestFindIngresses_UnreadableManifestIsPartial: a manifest whose entry points cannot be
// read may hide a script, so ingress discovery is partial, while the call graph's
// partiality is left to the manifest readers that already judge it.
func TestFindIngresses_UnreadableManifestIsPartial(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"tool\"\n\n[project.scripts\n",
		"app.py":         "def main():\n    return 0\n",
	})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
		t.Errorf("unreadable manifest must make ingress discovery partial (tool_failure); got %+v", res.Partiality)
	}
}
