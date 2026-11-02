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
			name: "setup.py ini-style entry point before any section",
			files: map[string]string{
				"setup.py":         "from setuptools import setup\n\nsetup(name=\"tool\", entry_points=\"\"\"\ntool = tool.cli:main\n[console_scripts]\nother = tool.cli:run\n\"\"\")\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			want:    []ing{{"main", funcSCIP("tool/cli", nil, "run", 0), "other"}},
			partial: true,
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
			name: "Django view wrapped by dependency decorators, and a keyword view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n\ndef feed(request):\n    return None\n\ndef keyed(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom django.contrib.auth.decorators import login_required\nfrom django.views.decorators.cache import cache_page\nfrom site import views\n\nurlpatterns = [\n    path(\"d/\", login_required(views.dash)),\n    path(\"f/\", cache_page(60)(views.feed)),\n    path(\"k/\", view=views.keyed, name=\"k\"),\n]\n",
			},
			want: []ing{
				{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"},
				{"http_route", funcSCIP("site/views", nil, "feed", 1), "f/"},
				{"http_route", funcSCIP("site/views", nil, "keyed", 1), "k/"},
			},
		},
		{
			name: "Django view behind a decorator factory configured by a dependency",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n\ndef feed(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom django.conf import settings\nfrom django.views.decorators.cache import cache_page\nfrom limits import TTL\nfrom site import views\n\nurlpatterns = [\n    path(\"d/\", cache_page(settings.TTL)(views.dash)),\n    path(\"f/\", cache_page(TTL)(views.feed)),\n]\n",
			},
			want: []ing{
				{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"},
				{"http_route", funcSCIP("site/views", nil, "feed", 1), "f/"},
			},
		},
		{
			name: "Django view behind a decorator factory given a first-party function",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def is_staff(user):\n    return True\n\ndef panel(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom django.contrib.auth.decorators import user_passes_test\nfrom site import views\n\nurlpatterns = [path(\"p/\", user_passes_test(views.is_staff)(views.panel))]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", nil, "panel", 1), "p/"}},
			absent:  []string{funcSCIP("site/views", nil, "is_staff", 1)},
			partial: true,
		},
		{
			name: "Django view read through getattr",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"d/\", getattr(views, \"dash\"))]\n",
			},
			partial: true,
		},
		{
			name: "Django class-based view on a base from a first-party star import",
			files: map[string]string{
				"site/__init__.py": "", "site/base.py": "class Base:\n    def get(self, request):\n        return None\n",
				"site/views.py": "from site.base import *\n\nclass Items(Base):\n    pass\n",
				"site/urls.py":  "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/base", []string{"Base"}, "get", 2), "items/"}},
		},
		{
			name: "Django class-based view on object and a dependency star import's base",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "from django.views.generic import *\n\nclass Mixin(object):\n    def get(self, request):\n        return None\n\nclass Items(Mixin, View):\n    pass\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", []string{"Mixin"}, "get", 2), "items/"}},
		},
		{
			name: "Django class-based view on a base nothing binds",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "class Items(Base):\n    def get(self, request):\n        return None\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", []string{"Items"}, "get", 2), "items/"}},
			partial: true,
		},
		{
			name: "Django class-based view on star-expanded bases",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "class Mixin:\n    def get(self, request):\n        return None\n\nBASES = (Mixin,)\n\nclass Items(*BASES):\n    pass\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			partial: true,
		},
		{
			name: "Django class-based view on a first-party base that is no class",
			files: map[string]string{
				"site/__init__.py": "", "site/base.py": "def make():\n    return object\n\nBase = make()\n",
				"site/views.py": "from site.base import Base\n\nclass Items(Base):\n    def get(self, request):\n        return None\n",
				"site/urls.py":  "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			partial: true,
		},
		{
			name: "Django as_view on a name that is no class",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def make_view():\n    return None\n\nItems = make_view()\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			partial: true,
		},
		{
			name: "Django class-based view overriding a generic view's hook",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "from django.views.generic import ListView\n\nclass Items(ListView):\n    def get_queryset(self):\n        return []\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", []string{"Items"}, "get_queryset", 1), "items/"}},
		},
		{
			name: "Django class-based view inheriting a first-party handler",
			files: map[string]string{
				"site/__init__.py": "", "site/base.py": "from django.views import View\n\nclass Base(View):\n    def get(self, request):\n        return None\n",
				"site/views.py": "from site.base import Base\n\nclass Items(Base):\n    template = \"x\"\n",
				"site/urls.py":  "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want:  []ing{{"http_route", funcSCIP("site/base", []string{"Base"}, "get", 2), "items/"}},
			roots: []string{funcSCIP("site/base", []string{"Base"}, "get", 2)},
		},
		{
			name: "Django class-based view of a dependency is no ingress and not partial",
			files: map[string]string{
				"site/__init__.py": "",
				"site/urls.py":     "from django.urls import path\nfrom django.views.generic import RedirectView\n\nurlpatterns = [path(\"old/\", RedirectView.as_view(url=\"/\"))]\n",
			},
		},
		{
			name: "Django view built by first-party code is partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def build():\n    def view(request):\n        return None\n    return view\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"b/\", views.build())]\n",
			},
			partial: true,
		},
		{
			name: "Django view under a first-party wrapper is an ingress and partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/auth.py": "def guard(view):\n    return view\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\nfrom site.auth import guard\n\nurlpatterns = [path(\"d/\", guard(views.dash))]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
			partial: true,
		},
		{
			name: "a path that is not django's names no view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def index(request):\n    return None\n",
				"site/urls.py": "from os import path\nfrom site import views\n\nP = path(\"x\", views.index)\n",
			},
			absent: []string{funcSCIP("site/views", nil, "index", 1)},
		},
		{
			name: "setup.cfg interpolation with no entry points is complete",
			files: map[string]string{
				"setup.cfg":        "[metadata]\nname = tool\n\n[flake8]\nformat = %(path)s:%(row)d\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
		},
		{
			name: "setup.cfg interpolation inside the entry points is unsupported",
			files: map[string]string{
				"setup.cfg":        "[options.entry_points]\nconsole_scripts =\n    %(name)s = tool.cli:main\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			partial: true,
		},
		{
			name: "setup.py entry points passed by name are roots and unsupported",
			files: map[string]string{
				"setup.py":         "from setuptools import setup\n\nSCRIPTS = [\"tool = tool.cli:main\"]\nsetup(name=\"tool\", entry_points={\"console_scripts\": SCRIPTS})\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			roots:   []string{funcSCIP("tool/cli", nil, "main", 0)},
			partial: true,
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
		{
			name: "Django views from a first-party star import",
			files: map[string]string{
				"site/__init__.py": "",
				"site/views.py":    "def dash(request):\n    return None\n\nclass Items:\n    def get(self, request):\n        return None\n",
				"site/urls.py":     "from django.urls import path\nfrom django.contrib.auth.decorators import login_required\nfrom site.views import *\n\nurlpatterns = [\n    path(\"d/\", dash),\n    path(\"items/\", Items.as_view()),\n    path(\"l/\", login_required(dash)),\n]\n",
			},
			want: []ing{
				{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"},
				{"http_route", funcSCIP("site/views", []string{"Items"}, "get", 2), "items/"},
				{"http_route", funcSCIP("site/views", nil, "dash", 1), "l/"},
			},
		},
		{
			name: "Django view behind a nested first-party star import",
			files: map[string]string{
				"site/__init__.py": "", "site/impl.py": "def dash(request):\n    return None\n",
				"site/views.py": "from site.impl import *\n",
				"site/urls.py":  "from django.urls import path\nfrom site.views import *\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view behind a wrapper given a star-imported first-party function",
			files: map[string]string{
				"site/__init__.py": "", "site/checks.py": "def is_staff(user):\n    return True\n",
				"site/views.py": "def panel(request):\n    return None\n",
				"site/urls.py":  "from django.urls import path\nfrom django.contrib.auth.decorators import user_passes_test\nfrom site.checks import *\nfrom site import views\n\nurlpatterns = [path(\"p/\", user_passes_test(is_staff)(views.panel))]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", nil, "panel", 1), "p/"}},
			partial: true,
		},
		{
			name: "Django view name a first-party star import does not bind",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def feed(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom site.views import *\n\nurlpatterns = [path(\"f/\", feed), path(\"s/\", str)]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "feed", 1), "f/"}},
		},
		{
			name: "Django view a first-party star import rebinds over a dependency import",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom other.views import dash\nfrom site.views import *\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
		},
		{
			name: "Django view name behind an unread first-party star import",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom site.gone import *\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django dependency view a first-party star import re-exports",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "from django.views.generic import TemplateView\n",
				"site/urls.py": "from django.urls import path\nfrom site.views import *\n\nurlpatterns = [path(\"a/\", TemplateView.as_view(template_name=\"a.html\"))]\n",
			},
		},
		{
			name: "Django view behind a wrapper given a function from a nested star import",
			files: map[string]string{
				"site/__init__.py": "", "site/checks.py": "def is_staff(u):\n    return True\n", "site/reexp.py": "from site.checks import *\n",
				"site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py":  "from django.urls import path\nfrom django.contrib.auth.decorators import user_passes_test\nfrom site.reexp import *\nfrom site import views\n\nurlpatterns = [path(\"d/\", user_passes_test(is_staff)(views.dash))]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
			partial: true,
		},
		{
			name: "Django view name a later star import's nested star may rebind",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n", "site/models.py": "def dash(request):\n    return None\n",
				"site/forms.py": "from site.models import *\n",
				"site/urls.py":  "from django.urls import path\nfrom site.views import *\nfrom site.forms import *\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
			partial: true,
		},
		{
			name: "Django view an instance assignment binds beside a first-party star import",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n\nclass Dash:\n    def __call__(self, request):\n        return None\n",
				"site/urls.py": "from django.urls import path\nfrom site.views import *\ndash = Dash()\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view an instance of a first-party class",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "class Dash:\n    def __call__(self, request):\n        return None\n",
				"site/urls.py": "from django.urls import path\nfrom site.views import Dash\ndash = Dash()\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view a local def binds beside a dependency import",
			files: map[string]string{
				"site/__init__.py": "",
				"site/urls.py":     "from django.urls import path\nfrom thirdparty import dash\n\ndef dash(request):\n    return None\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/urls", nil, "dash", 1), "d/"}},
		},
		{
			name: "Django view an instance of a first-party class rebinding a dependency import",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "class Dash:\n    def __call__(self, request):\n        return None\n",
				"site/urls.py": "from django.urls import path\nfrom thirdparty import dash\nfrom site.views import Dash\ndash = Dash()\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view a call's result rebinding a dependency import",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom thirdparty import dash, wrap\nfrom site import views\ndash = wrap(views.dash)\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view a dependency's instance",
			files: map[string]string{
				"site/__init__.py": "",
				"site/urls.py":     "from django.urls import path\nfrom ninja import NinjaAPI\napi = NinjaAPI()\n\nurlpatterns = [path(\"api/\", api.urls)]\n",
			},
		},
		{
			name: "Django view a dependency's instance wrapping a first-party view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom deco import Wrap\nfrom site import views\ndash = Wrap(views.dash)\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view a lambda an assignment binds",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom django.http import HttpResponse\ndash = lambda request: HttpResponse(\"ok\")\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view a lambda written in place",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom django.http import HttpResponse\n\nurlpatterns = [path(\"d/\", lambda request: HttpResponse(\"ok\"))]\n",
			},
			partial: true,
		},
		{
			name: "Django view name a def's global write rebinds",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom thirdparty import dash\nfrom site import views\n\ndef setup():\n    global dash\n    dash = views.dash\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view name a for loop binds",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\nfrom thirdparty import dash\n\nfor dash in [views.dash]:\n    pass\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			partial: true,
		},
		{
			name: "Django view names assignments bind to each other",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\na = b\nb = a\n\nurlpatterns = [path(\"d/\", a)]\n",
			},
		},
		{
			name: "Django view name a later star import rebinds over a builtin's value",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\ndash = dict()\nfrom site.views import *\n\nurlpatterns = [path(\"d/\", dash)]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
		},
		{
			name: "Django class-based view on a base a dependency's factory builds",
			files: map[string]string{
				"site/__init__.py": "",
				"site/views.py":    "from deco import Factory\nBase = Factory()\n\nclass Items(Base):\n    def get(self, request):\n        return None\n",
				"site/urls.py":     "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", []string{"Items"}, "get", 2), "items/"}},
		},
		{
			name: "Django view behind a wrapper's trailing attribute",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom deco import wrap\nfrom site import views\n\nurlpatterns = [path(\"d/\", wrap(views.dash).inner)]\n",
			},
			partial: true,
		},
		{
			name: "Django view behind a wrapper given another first-party argument",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n\ndef is_staff(u):\n    return True\n",
				"site/urls.py": "import functools\nfrom django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"d/\", functools.partial(views.dash, check=views.is_staff))]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
			partial: true,
		},
		{
			name: "Django class-based view on object",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "class Items(object):\n    def get(self, request):\n        return None\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", []string{"Items"}, "get", 2), "items/"}},
		},
		{
			name: "Django as_view on a whole module",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def as_view():\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"x/\", views.as_view())]\n",
			},
			partial: true,
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
			if hasReason(res.Partiality, plugin.PartialReasonToolFailure) {
				t.Errorf("readable launchers must not be a tool failure; got %+v", res.Partiality)
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
