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
	fac := "def make():\n    return inner\n\ndef inner():\n    return 0\n\ndef patch(m):\n    setattr(m, \"main\", inner)\n"
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
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.entry-points.\"tool.plugins\"]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/cli.py": cli,
			},
			absent: []string{funcSCIP("tool/cli", nil, "main", 0)},
			roots:  []string{funcSCIP("tool/cli", nil, "main", 0)},
		},
		{
			name: "entry point naming a module loads all of it",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.entry-points.\"tool.plugins\"]\ntool = \"tool.cli\"\n",
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
			name: "script a global import in a def binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli,
				"tool/cli.py": "def init():\n    global main\n    from tool.impl import main\n\ninit()\n",
			},
			want:  []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			roots: []string{funcSCIP("tool/impl", nil, "main", 0)},
		},
		{
			name: "script through a module a global import in a def binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:app.main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli,
				"tool/cli.py": "def init():\n    global app\n    from tool import impl as app\n\ninit()\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
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
			name: "Django patterns() tuples naming views by import path",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def login(request):\n    return None\n\ndef home(request):\n    return None\n",
				"urls.py": "from django.conf.urls import patterns, include, url\nfrom django.contrib import admin\n\nurlpatterns = patterns('',\n    (r'^accounts/login/', 'site.views.login', {'next': '/'}),\n    (r'^admin/', include(admin.site.urls)),\n    url(r'^$', 'site.views.home', name='home'),\n)\n",
			},
			want: []ing{
				{"http_route", funcSCIP("site/views", nil, "login", 1), "^accounts/login/"},
				{"http_route", funcSCIP("site/views", nil, "home", 1), "^$"},
			},
			roots: []string{funcSCIP("site/views", nil, "login", 1)},
		},
		{
			name: "Django patterns() prefix joins onto its string views",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n\ndef feed(request):\n    return None\n\ndef keyed(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurlpatterns = patterns('site.views',\n    url(r'^d/$', 'dash'),\n    (r'^f/$', 'feed'),\n    url(r'^k/$', view='keyed'),\n)\n",
			},
			want: []ing{
				{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"},
				{"http_route", funcSCIP("site/views", nil, "feed", 1), "^f/$"},
				{"http_route", funcSCIP("site/views", nil, "keyed", 1), "^k/$"},
			},
		},
		{
			name: "Django url() outside patterns() naming a view by import path",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import url\n\nurlpatterns = [url(r'^d/$', 'site.views.dash')]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django patterns() prefix the lane cannot read leaves its string views partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nPREFIX = 'site.views'\nurlpatterns = patterns(PREFIX,\n    url(r'^d/$', 'dash'),\n    (r'^e/$', 'dash'),\n)\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "Django string view naming a dependency is no ingress and not partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py":     "from django.conf.urls import patterns\n\nurlpatterns = patterns('',\n    (r'^media/(?P<path>.*)$', 'django.views.static.serve', {'document_root': '/srv'}),\n)\n",
				"requirements.txt": "Django==1.8.7\n",
			},
		},
		{
			name: "Django string view naming no first-party function resolves to nothing",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns\n\nurlpatterns = patterns('', (r'^x/$', 'site.views.gone'))\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "Django string view naming a class attribute is no view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "class Obj:\n    def run(self, request):\n        return None\n",
				"site/urls.py": "from django.conf.urls import patterns\n\nurlpatterns = patterns('', (r'^r/$', 'site.views.Obj.run'))\n",
			},
			absent: []string{funcSCIP("site/views", []string{"Obj"}, "run", 2)},
		},
		{
			name: "Django string view rebound in its module",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def make():\n    def dash(request):\n        return None\n    return dash\n\ndef dash(request):\n    return None\n\ndash = make()\n",
				"site/urls.py": "from django.conf.urls import patterns\n\nurlpatterns = patterns('', (r'^d/$', 'site.views.dash'))\n",
			},
			partial: true,
		},
		{
			name: "Django string view re-exported by its module",
			files: map[string]string{
				"site/__init__.py": "", "site/impl.py": "def dash(request):\n    return None\n",
				"site/views.py": "from site.impl import dash\n",
				"site/urls.py":  "from django.conf.urls import patterns\n\nurlpatterns = patterns('', (r'^d/$', 'site.views.dash'))\n",
			},
			want: []ing{{"http_route", funcSCIP("site/impl", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django string view under a top-level name neither first-party nor a dependency is partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurlpatterns = patterns('', (r'^d/$', 'mysite.site.views.dash'))\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "Django single-name string view outside patterns() is partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurlpatterns = [url(r'^d/$', 'dash')]\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "Django patterns() spread argument is partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurls = [url(r'^d/$', 'dash')]\nurlpatterns = patterns('site.views', *urls)\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "Django patterns() name argument is partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nROUTES = (r'^d/$', 'site.views.dash')\nurlpatterns = patterns('', ROUTES)\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "Django url() literal prefix joins onto its string view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurlpatterns = [url(r'^d/$', 'dash', prefix='site.views')]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django url() positional prefix joins after the patterns() prefix",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurlpatterns = patterns('site', url(r'^d/$', 'dash', None, 'd', 'views'))\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django url() prefix the lane cannot read is partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nP = 'site.views'\nurlpatterns = [url(r'^d/$', 'dash', prefix=P)]\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "Django patterns() list argument names its view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurlpatterns = patterns('', [r'^d/$', 'site.views.dash'])\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django patterns() parenthesised registrar keeps the prefix",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nurlpatterns = patterns('site.views', (url(r'^d/$', 'dash')))\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django patterns() tuple with a callable view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nfrom site import views\nurlpatterns = patterns('nowhere', (r'^d/$', views.dash))\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django nested patterns() keeps its own prefix",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, include, url\n\nurlpatterns = patterns('nowhere',\n    url(r'^a/', include(patterns('site.views', url(r'^d/$', 'dash')))),\n)\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "^d/$"}},
		},
		{
			name: "Django patterns() argument from a non-django registrar is partial",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.conf.urls import patterns, url\n\nfrom routes import route\nurlpatterns = patterns('site.views', route(r'^d/$', 'dash'))\n",
			},
			absent:  []string{funcSCIP("site/views", nil, "dash", 1)},
			partial: true,
		},
		{
			name: "a patterns() call not bound from django is no view",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from routes import patterns\n\nurlpatterns = patterns('', (r'^d/$', 'site.views.dash'))\n",
			},
			absent: []string{funcSCIP("site/views", nil, "dash", 1)},
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
			name: "Django views module a global import in a def binds",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\n\ndef load():\n    global views\n    from site import views\n\nload()\nurlpatterns = [path(\"d/\", views.dash)]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
		},
		{
			name: "Django views module a global import in a def rebinds",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n", "site/views2.py": "def dash(request):\n    return None\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\n\ndef load():\n    global views\n    from site import views2 as views\n\nload()\nurlpatterns = [path(\"d/\", views.dash)]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}, {"http_route", funcSCIP("site/views2", nil, "dash", 1), "d/"}},
		},
		{
			name: "script also assigned a call result",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nfrom tool.fac import make\n\nmain = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global import in a def binds, also assigned a call result",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.fac import make\n\nmain = make()\n\ndef init():\n    global main\n    from tool.impl import main\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script also assigned a dependency's call result",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli,
				"tool/cli.py": "from tool.impl import main\nfrom depfac import make\n\nif make:\n    main = make()\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script also a tuple target",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nfrom tool.fac import make\n\nmain, other = make(), 0\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script the defining module also assigned a call result",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n", "tool/cli.py": "from tool.impl import main\n",
				"tool/impl.py": "from tool.fac import make\n\ndef main():\n    return 0\n\nmain = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script through a module alias also assigned a class",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:ns.main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def inner():\n    return 0\n\nclass NS:\n    main = inner\n",
				"tool/cli.py": "from tool import impl as ns\nfrom tool.fac import NS\n\nns = NS\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global def in a def binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli,
				"tool/cli.py": "from tool.impl import main\n\ndef init():\n    global main\n    def main():\n        return 1\n\ninit()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global class in a def binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli,
				"tool/cli.py": "from tool.impl import main\n\ndef init():\n    global main\n    class main:\n        pass\n\ninit()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global assignment in a class body binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nfrom tool.fac import make\n\nclass K:\n    global main\n    main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global def in a class body binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli,
				"tool/cli.py": "from tool.impl import main\n\nclass K:\n    global main\n    def main():\n        return 0\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global class in a class body binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nfrom tool.fac import make\n\nclass K:\n    global main\n    class main:\n        def __init__(self):\n            make()()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global import in a class body in a def binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\n\ndef setup():\n    class K:\n        global main\n        from tool.alt import main\n\nsetup()\n",
				"tool/alt.py": "from tool.fac import make\n\nmain = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a global import in a class body resolves",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "class K:\n    global main\n    from tool.impl import main\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script a store through the defining module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "from tool import impl\nfrom tool.fac import make\n\nimpl.main = make()\n", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star import may rebind",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nfrom tool.star import *\n", "tool/star.py": "from tool.fac import make\n\nmain = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star import may rebind past a dependency's import",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py":  "from tool.impl import main\nfrom tool.star import *\n",
				"tool/star.py": "from tool.fac import make\n\ntry:\n    from fastimpl import main\nexcept ImportError:\n    main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star import may rebind past a dependency's import with a def",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py":  "from tool.impl import main\nfrom tool.star import *\n",
				"tool/star.py": "try:\n    from fastimpl import main\nexcept ImportError:\n    def main():\n        return 0\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star import may rebind past a dependency's import with a first-party import",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py":  "from tool.impl import main\nfrom tool.star import *\n",
				"tool/star.py": "try:\n    from fastimpl import main\nexcept ImportError:\n    from .fb import main\n", "tool/fb.py": "from tool.fac import make\n\nmain = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star import may rebind past a dependency's import with a class-body global",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py":  "from tool.impl import main\nfrom tool.star import *\n",
				"tool/star.py": "from tool.fac import make\ntry:\n    from fastimpl import main\nexcept ImportError:\n    class K:\n        global main\n        main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star import may rebind past a dependency's import through a further star import",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py":  "from tool.impl import main\nfrom tool.star import *\n",
				"tool/star.py": "try:\n    from fastimpl import main\nexcept ImportError:\n    pass\nfrom tool.star2 import *\n", "tool/star2.py": "from tool.fac import make\n\nmain = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a store into a star-imported module may rebind",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nimport tool.b\nfrom tool.star import *\n", "tool/star.py": "try:\n    from fastimpl import main\nexcept ImportError:\n    pass\n",
				"tool/b.py": "import tool.star\nfrom tool.fac import make\n\ntool.star.main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star-imported module handed to setattr may rebind",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nimport tool.b\nfrom tool.star import *\n", "tool/star.py": "try:\n    from fastimpl import main\nexcept ImportError:\n    pass\n",
				"tool/b.py": "import tool.star\nfrom tool.fac import make\n\nsetattr(tool.star, \"main\", make())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a star import of a dependency's name resolves",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py":  "from tool.impl import main\nfrom tool.star import *\n",
				"tool/star.py": "try:\n    from fastimpl import main\nexcept ImportError:\n    pass\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script a star import of a star import may rebind",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"tool/cli.py": "from tool.impl import main\nfrom tool.star import *\n", "tool/star.py": "from tool.star2 import *\n",
				"tool/star2.py": "from tool.fac import make\n\nmain = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script the defining module handed to a first-party function",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "from tool import impl\nfrom tool.fac import patch\n\npatch(impl)\n", "tool/impl.py": cli,
				"tool/fac.py": "def inner():\n    return 0\n\ndef patch(m):\n    setattr(m, \"main\", inner)\n", "tool/cli.py": "from tool.impl import main\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own module handed to a first-party function",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\npatch(sys.modules[__name__])\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key assigned",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nglobals()[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script setattr on its own module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsetattr(sys.modules[__name__], \"main\", make())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script an attribute store on its own module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys.modules[__name__].main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal vars key assigned at module scope",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nvars()[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key assigned in a def",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef setup():\n    globals()[\"main\"] = make()\n\nsetup()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script globals updated by keyword",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nglobals().update(main=make())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a computed globals key assigned",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nname = \"main\"\nglobals()[name] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own module replaced",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nclass W:\n    main = staticmethod(make())\n\nsys.modules[__name__] = W()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own module imported by name and stored through",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nimport importlib\n\nimportlib.import_module(__name__).main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script an attribute store on its own module from sys.modules imported by name",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nfrom sys import modules\n\nmodules[__name__].main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script an attribute store on its own module got from sys.modules",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys.modules.get(__name__).main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a store into its own module's __dict__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys.modules[__name__].__dict__[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script another literal globals key assigned",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nglobals()[\"other\"] = make()\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script a literal vars key assigned in a def",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef setup():\n    vars()[\"main\"] = make()\n\nsetup()\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script a literal vars key assigned across lines after a def",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef setup():\n    return 0\n\nvars()[\"main\"] = make(\n)\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal vars key assigned in a def whose header spans lines",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef setup(a=0,\n          b=0):\n    vars()[\"main\"] = make()\n\nsetup()\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script a literal vars key assigned in a def after a dedented continuation",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef setup():\n    x = make(\n)\n    vars()[\"main\"] = make()\n\nsetup()\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script its own namespace only read",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\na = globals().get(\"main\")\nb = \"main\" in globals()\nc = getattr(sys.modules[__name__], \"main\")\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script its own namespace handed to __import__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nm = __import__(\"tool.fac\", globals(), locals(), [], 0)\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script its own namespace handed to a method named __import__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac + "\nclass Loader:\n    def __import__(self, name, ns):\n        ns[\"main\"] = inner\n",
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import Loader\n\nLoader().__import__(\"x\", globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key assigned in a tuple target",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nglobals()[\"main\"], x = make(), 1\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script an attribute of its own module assigned in a tuple target",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys.modules[__name__].main, x = make(), 1\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key assigned with an annotation",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nglobals()[\"main\"]: object = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script an attribute of its own module assigned with an annotation",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys.modules[__name__].main: object = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key bound as a for target",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nfor globals()[\"main\"] in [make()]:\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key bound as a with target",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nimport contextlib\nwith contextlib.nullcontext(make()) as globals()[\"main\"]:\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key assigned in parentheses",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\n(globals()[\"main\"]) = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own module's __dict__ fetched by getattr",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ngetattr(sys.modules[__name__], \"__dict__\")[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own module's __dict__ fetched by vars",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nvars(sys.modules[__name__])[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a dotted first-party set",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac + "\ndef set(ns):\n    ns[\"main\"] = inner\n",
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nimport tool.fac as fac\nfac.set(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a def named sorted",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef sorted(ns):\n    ns[\"main\"] = make()\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a def named __import__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef __import__(ns, *a):\n    ns[\"main\"] = make()\n\n__import__(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a callee bound through builtins",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac + "\ndef set(ns):\n    ns[\"main\"] = inner\n",
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nimport builtins\nfrom tool import fac\nbuiltins.store = fac.set\nstore(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to __import__ beside a method named __import__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nclass App:\n    def __import__(self, m):\n        return __import__(\"tool.fac\", globals(), locals(), [], 0)\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script its own namespace handed to a def named sorted in a class body",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nclass C:\n    def sorted(ns):\n        ns[\"main\"] = make()\n    sorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to an enclosing def named sorted",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef h():\n    def sorted(ns):\n        ns[\"main\"] = make()\n    def g():\n        sorted(globals())\n    g()\n\nh()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a def named sorted in a class body after a dedented continuation",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nclass C:\n    def sorted(ns):\n        ns[\"main\"] = make()\n    x = (1,\n0)\n    sorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script the globals builtin aliased",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nG = globals\nG()[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script the globals builtin handed to a function",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef p(ns):\n    ns()[\"main\"] = make()\n\np(globals)\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal key stored into its frame's globals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys._getframe().f_globals[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal key stored into a function's globals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef f():\n    pass\n\nf.__globals__[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module's literal store into a decorated function's globals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "from tool.fac import make\n\ndef fix(func):\n    func.__globals__[\"main\"] = make()\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script beside a test module's literal store into a decorated function's globals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tests/test_cli.py": "from tool.fac import make\nfrom tool.impl import main\n\ndef fix(func):\n    func.__globals__[\"main\"] = make()\n    return func\n\n@fix\ndef test_h():\n    pass\n",
				"tool/cli.py":       "from tool.impl import main\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script rebound by another module's computed store into a decorated function's globals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "from tool.fac import make\n\ndef fix(func, k=\"main\"):\n    func.__globals__[k] = make()\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script beside another module's literal store of another name into a decorated function's globals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "from tool.fac import make\n\ndef fix(func):\n    func.__globals__[\"other\"] = make()\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script beside another module's membership test on a decorated function's globals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "def fix(func):\n    if \"main\" in func.__globals__:\n        pass\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script beside another module handing a decorated function's globals to get_type_hints",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "import typing_extensions\n\ndef fix(func):\n    typing_extensions.get_type_hints(func, func.__globals__)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script rebound by another module handing a decorated function's globals to a get_type_hints not typing's",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "from tool import fac as typing\nimport typing\n\ndef fix(func):\n    typing.get_type_hints(func, func.__globals__)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module handing a decorated function's globals to get_type_hints on a typing it rebinds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "import typing\nfrom tool.fac import make\n\ntyping = make()\n\ndef fix(func):\n    typing.get_type_hints(func, func.__globals__)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module handing a decorated function's globals first to get_type_hints",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "import typing\n\ndef fix(func):\n    typing.get_type_hints(func.__globals__, func)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module handing a decorated function's globals to another typing function",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "import typing\n\ndef fix(func):\n    typing.cast(func, func.__globals__)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module handing a decorated function's globals to a bare get_type_hints",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "from tool.fac import make as get_type_hints\n\ndef fix(func):\n    get_type_hints(func, func.__globals__)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module handing a decorated function's globals to a bare get_type_hints after an import of typing",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/hints.py": "from tool.fac import inner\n\ndef get_type_hints(func, ns):\n    ns[\"main\"] = inner\n",
				"tool/deco.py":  "from tool.hints import get_type_hints\n\ndef fix(func):\n    import typing\n    get_type_hints(func, func.__globals__)\n    return func\n",
				"tool/cli.py":   "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module handing a decorated function's globals to get_type_hints on an attribute named typing",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "import typing\nfrom tool import fac\n\ndef fix(func):\n    fac.typing.get_type_hints(func, func.__globals__)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script rebound by another module handing a decorated function's globals to get_type_hints beside a star import",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/deco.py": "import typing\nfrom tool.fac import *\n\ndef fix(func):\n    typing.get_type_hints(func, func.__globals__)\n    return func\n",
				"tool/cli.py":  "from tool.deco import fix\nfrom tool.impl import main\n\n@fix\ndef h():\n    pass\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound by a literal globals key",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nglobals()[\"sorted\"] = ev\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound by setattr on its module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nsetattr(sys.modules[__name__], \"sorted\", ev)\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to __import__ rebound by a literal globals key",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef ev(m, g, *a):\n    g[\"main\"] = make()\n\nglobals()[\"__import__\"] = ev\n__import__(\"tool.fac\", globals(), locals(), [], 0)\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound in builtins by another module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import builtins\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nbuiltins.sorted = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound in builtins under an alias by another module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import builtins as B\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nB.sorted = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin when another module hands builtins on",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import builtins\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\ndef p(b):\n    b.sorted = ev\n\np(builtins)\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin another module names only in annotations",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import builtins\n\ndef names() -> builtins.list[str]:\n    return builtins.list()\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script its own namespace handed to a builtin rebound through an imported builtins module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nimport importlib\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nimportlib.import_module(\"builtins\").sorted = ev\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through __builtins__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\n__builtins__[\"sorted\"] = ev\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through another module's __builtins__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\njson.__builtins__[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through a __builtins__ key",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nglobals()[\"__builtins__\"][\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through a __builtins__ fetched by getattr",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\ngetattr(json, \"__builtins__\")[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through a __builtins__ fetched by get",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nvars(json).get(\"__builtins__\")[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through a __builtins__ fetched by attrgetter",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import operator\nimport json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\noperator.attrgetter(\"__builtins__\")(json)[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through a __builtins__ fetched by __getattribute__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\njson.__getattribute__(\"__builtins__\")[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through a __builtins__ fetched by a parenthesised name",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\ngetattr(json, (\"__builtins__\"))[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through a frame's f_builtins",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nsys._getframe().f_builtins[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through an imported __builtins__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nfrom json import __builtins__ as b\n\nb[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through another module's builtins fetched by getattr",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py":   "import tool.helper\nimport json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\ngetattr(tool.helper, \"builtins\").sorted = ev\n",
				"tool/helper.py": "import builtins\n",
				"tool/cli.py":    "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin beside a __builtins__ key in a dict display and a comparison",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\n\nexec(\"x = 1\", {\"__builtins__\": {}})\nnames = [k for k in vars(json) if k != \"__builtins__\"]\nhas = \"__builtins__\" in vars(json)\nsame = \"builtins\" == __name__\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script in a package whose __init__ stores computed names into its own namespace",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "import importlib\nfrom tool import impl\n\ndef __getattr__(name):\n    value = getattr(importlib.import_module(\"tool.fac\"), name)\n    globals()[name] = value\n    return value\n",
				"tool/impl.py":     cli, "tool/fac.py": fac,
				"tool/cli.py": "from tool.impl import main\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script in a package whose __init__ hands its own namespace to a rebound builtin",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "import tool.boot\nfrom tool import impl\n\nsorted(globals())\n",
				"tool/boot.py":     "import builtins\n\nbuiltins.sorted = lambda ns: list(ns)\n",
				"tool/impl.py":     cli, "tool/fac.py": fac,
				"tool/cli.py": "from tool.impl import main\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script its own namespace handed to a builtin rebound through its module's __builtins__",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "import json\nimport sys\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nsys.modules[__name__].__builtins__[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin after __builtins__ is replaced",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "from tool.impl import main\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\n__builtins__ = {**__builtins__, \"sorted\": ev}\n\ndef h():\n    sorted(globals())\n\nh()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin after a __builtins__ key is stored",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "from tool.impl import main\nfrom tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nglobals()[\"__builtins__\"] = {**__builtins__, \"sorted\": ev}\n\ndef h():\n    sorted(globals())\n\nh()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin rebound through __builtins__ by another module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/boot.py": "from tool.fac import make\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\n__builtins__[\"sorted\"] = ev\n",
				"tool/cli.py":  "import tool.boot\nfrom tool.impl import main\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a builtin after __builtins__ is stored by setattr",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli,
				"tool/fac.py": fac + "\ndef bt(f):\n    return {**len.__self__.__dict__, \"sorted\": f}\n",
				"tool/cli.py": "from tool.impl import main\nfrom tool.fac import make, bt\n\ndef ev(ns):\n    ns[\"main\"] = make()\n\nimport sys\nsetattr(sys.modules[__name__], \"__builtins__\", bt(ev))\n\ndef h():\n    sorted(globals())\n\nh()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script an attribute stored on its module by __spec__.name",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys.modules[__spec__.name].main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal globals key augmented by a shift",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac + "\nclass S:\n    def __rrshift__(self, o):\n        return inner\n",
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nfrom tool.fac import S\nglobals()[\"main\"] >>= S()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a star-imported sorted",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac + "\ndef sorted(ns):\n    ns[\"main\"] = inner\n",
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nfrom tool.fac import *\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to an import named sorted",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac + "\ndef set(ns):\n    ns[\"main\"] = inner\n",
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nfrom tool.fac import set as sorted\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace handed to a class named sorted",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nclass sorted(dict):\n    def __init__(self, ns):\n        ns[\"main\"] = make()\n\nsorted(globals())\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script a literal key stored into its module frame's locals",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsys._getframe().f_locals[\"main\"] = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "script its own namespace read beside targets",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nimport contextlib\nwith contextlib.nullcontext() as c: v = globals()[\"main\"]\nfor k in [globals()[\"main\"]]:\n    pass\nglobals()[\"main\"].x = 1\nw = getattr(sys.modules[__name__], \"main\")\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "script another name setattr on its own module",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool.cli:main\"\n",
				"tool/__init__.py": "", "tool/impl.py": cli, "tool/fac.py": fac,
				"tool/cli.py": "import sys\nfrom tool.impl import main\nfrom tool.fac import make, patch\n\nsetattr(sys.modules[__name__], \"other\", make())\n",
			},
			want: []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
		},
		{
			name: "package a store into a namespace package of the same name binds",
			files: map[string]string{
				"pyproject.toml":   "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool:main\"\n",
				"tool/__init__.py": "from tool.impl import main\n", "tool/impl.py": cli, "tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"a/tool/x.py": "", "b.py": "import a.tool\nfrom tool.fac import make\n\na.tool.main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "src package a store into a namespace package of the same name binds",
			files: map[string]string{
				"pyproject.toml":       "[project]\nname = \"tool\"\n\n[project.scripts]\ntool = \"tool:main\"\n",
				"src/tool/__init__.py": "from tool.impl import main\n", "src/tool/impl.py": cli, "src/tool/fac.py": "def make():\n    return inner\n\ndef inner():\n    return 0\n",
				"a/tool/x.py": "", "b.py": "import a.tool\nfrom tool.fac import make\n\na.tool.main = make()\n",
			},
			want:    []ing{{"main", funcSCIP("src/tool/impl", nil, "main", 0), "tool"}},
			partial: true,
		},
		{
			name: "Django views module a global assignment in a def rebinds",
			files: map[string]string{
				"site/__init__.py": "", "site/views.py": "def dash(request):\n    return None\n", "site/views2.py": "def dash(request):\n    return None\n",
				"site/fac.py":  "def make():\n    from site import views2\n    return views2\n",
				"site/urls.py": "from django.urls import path\nfrom site import views\nfrom site.fac import make\n\ndef load():\n    global views\n    views = make()\n\nload()\nurlpatterns = [path(\"d/\", views.dash)]\n",
			},
			want:    []ing{{"http_route", funcSCIP("site/views", nil, "dash", 1), "d/"}},
			partial: true,
		},
		{
			name: "Django class-based view on a base a global import in a def binds",
			files: map[string]string{
				"site/__init__.py": "", "site/base.py": "from django.views import View\n\nclass Base(View):\n    def get(self, request):\n        return None\n",
				"site/views.py": "def load():\n    global Base\n    from site.base import Base\n\nload()\n\nclass Items(Base):\n    template = \"x\"\n",
				"site/urls.py":  "from django.urls import path\nfrom site import views\n\nurlpatterns = [path(\"items/\", views.Items.as_view())]\n",
			},
			want: []ing{{"http_route", funcSCIP("site/base", []string{"Base"}, "get", 2), "items/"}},
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
