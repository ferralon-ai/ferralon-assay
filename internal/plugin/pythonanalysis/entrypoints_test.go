package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_DeclaredEntrypoints: a test-named module a declared entrypoint runs is
// production code, so its routes are roots and ingresses; one only a test runner, a shell
// script's module run or nothing at all names stays test code.
func TestCallGraph_DeclaredEntrypoints(t *testing.T) {
	const route = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef handle():\n    return 1\n\ndef main():\n    return 2\n"
	cases := []struct {
		name   string
		module string // the module whose handle is checked
		other  string // a second route module that must stay test code, if any
		files  map[string]string
		want   bool
	}{
		{"procfile gunicorn", "ab_test", "", map[string]string{"Procfile": "web: gunicorn ab_test:app\n", "ab_test.py": route}, true},
		{"procfile gunicorn bare module", "ab_test", "", map[string]string{"Procfile": "web: gunicorn -w 4 ab_test\n", "ab_test.py": route}, true},
		{"bare name falls back to the non-test module", "deploy/server", "tests/server", map[string]string{"Dockerfile": "CMD uvicorn server:app\n", "deploy/server.py": route, "tests/server.py": route}, true},
		{"gunicorn chdir picks its directory", "src/ab_test", "lib/ab_test", map[string]string{"Procfile": "web: gunicorn --chdir src ab_test:app\n", "src/ab_test.py": route, "lib/ab_test.py": route}, true},
		{"dockerfile exec form uvicorn", "load_test", "", map[string]string{"Dockerfile": "FROM python:3.12\nCMD [\"uvicorn\", \"load_test:app\", \"--host\", \"0.0.0.0\"]\n", "load_test.py": route}, true},
		{"dockerfile continued factory", "ab_test", "", map[string]string{"Dockerfile": "CMD gunicorn \\\n  --workers 2 \\\n  'ab_test:create_app()'\n", "ab_test.py": route}, true},
		{"compose hypercorn", "ab_test", "", map[string]string{"docker-compose.yml": "services:\n  web:\n    command: hypercorn ab_test:app --bind 0.0.0.0:80\n", "ab_test.py": route}, true},
		{"shell script python -m server", "ab_test", "", map[string]string{"run.sh": "#!/bin/sh\nexec python3 -m gunicorn ab_test:app\n", "ab_test.py": route}, true},
		{"waitress", "ab_test", "", map[string]string{"Procfile": "web: waitress-serve --port=8080 ab_test:app\n", "ab_test.py": route}, true},
		{"uwsgi module", "ab_test", "", map[string]string{"Dockerfile": "CMD uwsgi --http :80 --module ab_test:app\n", "ab_test.py": route}, true},
		{"supervisor program", "ab_test", "", map[string]string{"supervisord.conf": "[program:web]\ncommand=gunicorn ab_test:app\n", "ab_test.py": route}, true},
		{"celery app", "ab_test", "", map[string]string{"Procfile": "worker: celery -A ab_test worker -l info\n", "ab_test.py": route}, true},
		{"flask app env", "ab_test", "", map[string]string{"Dockerfile": "ENV FLASK_APP=ab_test.py\nCMD flask run\n", "ab_test.py": route}, true},
		{"dockerfile python -m", "agents/hackbot/test_plan_generator", "", map[string]string{"agents/hackbot/Dockerfile": "CMD [\"python\", \"-m\", \"test_plan_generator\"]\n", "agents/hackbot/test_plan_generator/__init__.py": route}, true},
		{"dockerfile python file", "ab_test", "", map[string]string{"Dockerfile": "CMD python -u ab_test.py\n", "ab_test.py": route}, true},
		{"dockerfile python -m under tests", "tests/load", "", map[string]string{"Dockerfile": "CMD [\"python\", \"-m\", \"tests.load\"]\n", "tests/load.py": route}, true},
		{"streamlit run", "ab_test", "", map[string]string{"Procfile": "web: streamlit run ab_test.py\n", "ab_test.py": route}, true},
		{"gunicorn config wsgi_app", "ab_test", "", map[string]string{"gunicorn.conf.py": "wsgi_app = \"ab_test:app\"\n", "ab_test.py": route}, true},
		{"django wsgi setting", "proj/ab_test", "", map[string]string{"proj/settings.py": "WSGI_APPLICATION = 'proj.ab_test.application'\n", "proj/ab_test.py": route}, true},
		{"pyproject script", "ab_test", "", map[string]string{"pyproject.toml": "[project]\nname = \"x\"\n\n[project.scripts]\nx = \"ab_test:main\"\n", "ab_test.py": route}, true},
		{"pyproject script in a src layout", "services/api/src/ab_test", "", map[string]string{"services/api/pyproject.toml": "[project.scripts]\napi = \"ab_test:main\"\n", "services/api/src/ab_test.py": route}, true},
		{"pyproject plugin entry point", "ab_test", "", map[string]string{"pyproject.toml": "[project.entry-points.\"acme.plugins\"]\nab = \"ab_test:main\"\n", "ab_test.py": route}, true},
		{"poetry script table", "ab_test", "", map[string]string{"pyproject.toml": "[tool.poetry.scripts]\nx = { callable = \"ab_test:main\" }\n", "ab_test.py": route}, true},
		{"setup.cfg console script", "ab_test", "", map[string]string{"setup.cfg": "[options.entry_points]\nconsole_scripts =\n    x = ab_test:main\n", "ab_test.py": route}, true},
		{"setup.py console script", "ab_test", "", map[string]string{"setup.py": "from setuptools import setup\nsetup(entry_points={'console_scripts': ['x = ab_test:main']})\n", "ab_test.py": route}, true},
		{"setup.py console script after a pytest plugin", "ab_test", "", map[string]string{"setup.py": "setup(entry_points={'pytest11': ['p = other:plugin'], 'console_scripts': ['x = ab_test:main']})\n", "ab_test.py": route}, true},
		{"workdir falls back to the named module", "web/ab_test", "", map[string]string{"Dockerfile": "WORKDIR /app/web\nCMD gunicorn ab_test:app\n", "web/ab_test.py": route}, true},
		{"django project under a subdirectory", "backend/mysite/ab_test", "", map[string]string{"backend/mysite/settings.py": "WSGI_APPLICATION = 'mysite.ab_test.application'\n", "backend/mysite/ab_test.py": route}, true},
		{"annotated setting", "proj/ab_test", "", map[string]string{"proj/settings.py": "WSGI_APPLICATION: str = 'proj.ab_test.application'\n", "proj/ab_test.py": route}, true},
		{"python options before -m", "ab_test", "", map[string]string{"Dockerfile": "CMD [\"python\", \"-u\", \"-m\", \"ab_test\"]\n", "ab_test.py": route}, true},
		{"python option value before the file", "ab_test", "", map[string]string{"Dockerfile": "CMD python -W ignore ab_test.py\n", "ab_test.py": route}, true},
		{"gunicorn module before its options", "proj/ab_test", "", map[string]string{"docker-compose.yml": "services:\n  web:\n    command: gunicorn proj.ab_test --bind 0.0.0.0:8000 --workers 3\n", "proj/ab_test.py": route}, true},
		{"gunicorn switch before the module", "ab_test", "", map[string]string{"Procfile": "web: gunicorn --reload ab_test\n", "ab_test.py": route}, true},
		{"gunicorn unix socket bind", "ab_test", "", map[string]string{"Procfile": "web: gunicorn --bind unix:app.sock ab_test\n", "ab_test.py": route}, true},
		{"factory with a quoted argument", "ab_test", "", map[string]string{"Procfile": "web: gunicorn 'ab_test:create_app(config=\"prod\")'\n", "ab_test.py": route}, true},
		{"uwsgi ini module", "ab_test", "", map[string]string{"conf/uwsgi.ini": "[uwsgi]\nmodule = ab_test:app\nmaster = true\n", "ab_test.py": route}, true},
		{"uwsgi ini callable", "ab_test", "", map[string]string{"uwsgi.ini": "[uwsgi]\nmodule = ab_test\ncallable = app\n", "ab_test.py": route}, true},
		{"flaskenv", "ab_test", "", map[string]string{".flaskenv": "FLASK_APP=ab_test\n", "ab_test.py": route}, true},
		{"dockerfile env without an equals sign", "ab_test", "", map[string]string{"Dockerfile": "ENV FLASK_APP ab_test.py\nCMD flask run\n", "ab_test.py": route}, true},
		{"kubernetes manifest", "ab_test", "", map[string]string{"k8s/deployment.yaml": "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          command:\n            - gunicorn\n          args:\n            - --bind=0.0.0.0:80\n            - ab_test:app\n", "ab_test.py": route}, true},
		{"serverless handler", "ab_test", "", map[string]string{"serverless.yml": "functions:\n  hello:\n    handler: ab_test.main\n", "ab_test.py": route}, true},
		{"sam handler", "fn/ab_test", "", map[string]string{"template.yaml": "Resources:\n  Fn:\n    Type: AWS::Serverless::Function\n    Properties:\n      CodeUri: fn/\n      Handler: ab_test.main\n", "fn/ab_test.py": route}, true},
		{"sam CodeUri beside a root module", "hello_world/ab_test", "ab_test", map[string]string{"template.yaml": "Resources:\n  Fn:\n    Type: AWS::Serverless::Function\n    Properties:\n      CodeUri: hello_world/\n      Handler: ab_test.main\n", "ab_test.py": route, "hello_world/ab_test.py": route}, true},
		{"sam Globals CodeUri", "src/ab_test", "ab_test", map[string]string{"template.yaml": "Globals:\n  Function:\n    CodeUri: src\nResources:\n  Fn:\n    Type: AWS::Serverless::Function\n    Properties:\n      Handler: ab_test.main\n", "ab_test.py": route, "src/ab_test.py": route}, true},
		{"systemd ExecStart bare command", "ab_test", "", map[string]string{"app.service": "[Service]\nExecStart=gunicorn ab_test:app\n", "ab_test.py": route}, true},
		{"kubernetes args before command", "ab_test", "", map[string]string{"k8s/d.yaml": "kind: Deployment\nspec:\n  containers:\n  - name: w\n    args:\n    - ab_test:app\n    command:\n    - gunicorn\n", "ab_test.py": route}, true},
		{"compose entrypoint with command", "ab_test", "", map[string]string{"docker-compose.yml": "services:\n  web:\n    entrypoint: [\"gunicorn\"]\n    command: [\"ab_test:app\"]\n", "ab_test.py": route}, true},
		{"launch after an install on one line", "ab_test", "", map[string]string{"entrypoint.sh": "pip install -r requirements.txt; gunicorn ab_test:app\n", "ab_test.py": route}, true},
		{"flaskenv quoted value", "ab_test", "", map[string]string{".flaskenv": "FLASK_APP=\"ab_test\"\n", "ab_test.py": route}, true},
		{"uvicorn access-log switch", "ab_test", "", map[string]string{"Dockerfile": "CMD uvicorn --host 0.0.0.0 --access-log ab_test:app\n", "ab_test.py": route}, true},
		{"granian ws switch", "ab_test", "", map[string]string{"Dockerfile": "CMD granian --interface asgi --ws ab_test:app\n", "ab_test.py": route}, true},
		{"gunicorn module before a log redirect", "ab_test", "", map[string]string{"start.sh": "nohup gunicorn ab_test > gunicorn.log 2>&1 &\n", "ab_test.py": route}, true},
		{"gunicorn dotted module before a stderr redirect", "proj/ab_test", "", map[string]string{"Procfile": "web: gunicorn proj.ab_test 2> error.log\n", "proj/__init__.py": "", "proj/ab_test.py": route}, true},
		{"exec-form value ending in equals", "ab_test", "", map[string]string{"Dockerfile": "CMD [\"gunicorn\", \"--env\", \"SECRET_KEY=\", \"ab_test:app\"]\n", "ab_test.py": route}, true},
		{"sam parameter runtime beside a nodejs function", "ab_test", "", map[string]string{"template.yaml": "Resources:\n  Js:\n    Type: AWS::Serverless::Function\n    Properties:\n      Runtime: nodejs18.x\n      Handler: index.handler\n  Py:\n    Type: AWS::Serverless::Function\n    Properties:\n      Runtime: !Ref PyRuntime\n      Handler: ab_test.main\n", "ab_test.py": route}, true},
		{"helm templated kind", "ab_test", "", map[string]string{"chart/templates/d.yaml": "kind: {{ .Values.kind }}\nspec:\n  containers:\n  - name: w\n    command: [\"gunicorn\", \"ab_test:app\"]\n", "ab_test.py": route}, true},
		{"gunicorn quoted inline value", "proj/ab_test", "", map[string]string{"docker-compose.yml": "services:\n  web:\n    command: gunicorn --worker-class=\"uvicorn.workers.UvicornWorker\" proj.ab_test\n", "proj/__init__.py": "", "proj/ab_test.py": route}, true},
		{"gunicorn module after an unlisted value flag", "ab_test", "", map[string]string{"Procfile": "web: gunicorn --new-option drop ab_test\n", "ab_test.py": route}, true},
		{"setup.py console script tuple after a pytest plugin tuple", "ab_test", "", map[string]string{"setup.py": "setup(entry_points=dict(pytest11=('p = other:plugin',), console_scripts=('x = ab_test:main',)))\n", "ab_test.py": route}, true},

		{"undeclared", "ab_test", "", map[string]string{"app.py": "def main():\n    return 1\n", "ab_test.py": route}, false},
		{"procfile names another module", "ab_test", "", map[string]string{"Procfile": "web: gunicorn app:app\n", "app.py": "def main():\n    return 1\n", "ab_test.py": route}, false},
		{"pytest plugin entry point", "ab_test", "", map[string]string{"pyproject.toml": "[project.entry-points.pytest11]\nab = \"ab_test\"\n", "ab_test.py": route}, false},
		{"setup.cfg pytest plugin", "ab_test", "", map[string]string{"setup.cfg": "[options.entry_points]\npytest11 =\n    ab = ab_test\n", "ab_test.py": route}, false},
		{"shell script python -m", "ab_test", "", map[string]string{"run.sh": "python -m ab_test\n", "ab_test.py": route}, false},
		{"makefile python file", "ab_test", "", map[string]string{"Makefile": "test:\n\tpython ab_test.py\n", "ab_test.py": route}, false},
		{"python -m a test module from a test runner", "ab_test", "", map[string]string{"Procfile": "web: python -m unittest ab_test\n", "ab_test.py": route}, false},
		{"gunicorn flag value", "ab_test", "", map[string]string{"Procfile": "web: gunicorn -k ab_test\n", "ab_test.py": route}, false},
		{"setup.py string without a callable", "ab_test", "", map[string]string{"setup.py": "setup(description='x = ab_test')\n", "ab_test.py": route}, false},
		{"dockerfile python -m a unittest suite", "test_jobs", "", map[string]string{"Dockerfile": "CMD [\"python3.11\", \"-m\", \"test_jobs\"]\n", "test_jobs.py": "import unittest\n" + route}, false},
		{"dockerfile python file importing pytest", "ab_test", "", map[string]string{"Dockerfile": "CMD python ab_test.py\n", "ab_test.py": "from pytest import fixture\n" + route}, false},
		{"declared inside a test directory", "tests/plugin/ab_test", "", map[string]string{"tests/plugin/pyproject.toml": "[project.entry-points.acme]\nab = \"ab_test:main\"\n", "tests/plugin/ab_test.py": route}, false},
		{"settings inside a test directory", "tests/ab_test", "", map[string]string{"tests/settings.py": "WSGI_APPLICATION = 'tests.ab_test.application'\n", "tests/ab_test.py": route}, false},
		{"bare name falls back past test modules", "tests/recorded/server", "", map[string]string{"Dockerfile": "CMD uvicorn server:app\n", "tests/recorded/server.py": route}, false},
		{"test-named compose file", "tests/mocks/server", "", map[string]string{"docker-compose.test.yml": "services:\n  mock:\n    command: uvicorn tests.mocks.server:app\n", "tests/mocks/server.py": route}, false},
		{"test-named dockerfile", "tests/e2e_runner", "", map[string]string{"Dockerfile.test": "CMD python tests/e2e_runner.py\n", "tests/e2e_runner.py": route}, false},
		{"setup.py pytest plugin with a callable", "ab_test", "", map[string]string{"setup.py": "setup(entry_points={'pytest11': ['ab = ab_test:plugin']})\n", "ab_test.py": route}, false},
		{"setup.py pytest plugin by keyword", "ab_test", "", map[string]string{"setup.py": "setup(entry_points=dict(pytest11=['ab = ab_test:plugin']))\n", "ab_test.py": route}, false},
		{"setup.py pytest plugin in an ini string", "ab_test", "", map[string]string{"setup.py": "setup(entry_points=\"\"\"\n[pytest11]\nab = ab_test:plugin\n\"\"\")\n", "ab_test.py": route}, false},
		{"hypothesis plugin", "ab_test", "", map[string]string{"pyproject.toml": "[project.entry-points.hypothesis]\nab = \"ab_test:main\"\n", "ab_test.py": route}, false},
		{"setting quoted in a docstring", "proj/ab_test", "", map[string]string{"proj/settings.py": "\"\"\"\nWSGI_APPLICATION = 'proj.ab_test.application'\n\"\"\"\n", "proj/ab_test.py": route}, false},
		{"makefile FLASK_APP", "ab_test", "", map[string]string{"Makefile": "routes:\n\tFLASK_APP=ab_test.py flask routes\n", "ab_test.py": route}, false},
		{"makefile flask --app", "ab_test", "", map[string]string{"Makefile": "routes:\n\tflask --app ab_test routes\n", "ab_test.py": route}, false},
		{"pip install of a server", "ab_test", "", map[string]string{"Dockerfile": "RUN pip install gunicorn ab_test\n", "ab_test.py": route}, false},
		{"yaml that launches nothing", "ab_test", "", map[string]string{"config.yaml": "command: gunicorn ab_test:app\n", "ab_test.py": route}, false},
		{"ci pipeline with containers", "load_test", "", map[string]string{"azure-pipelines.yml": "resources:\n  containers:\n  - container: py\n    image: python:3.11\nsteps:\n- script: python load_test.py\n", "load_test.py": route}, false},
		{"sam nodejs function beside a python one", "handler_test", "", map[string]string{"template.yaml": "Resources:\n  Js:\n    Type: AWS::Serverless::Function\n    Properties:\n      Runtime: nodejs18.x\n      Handler: handler_test.main\n  Py:\n    Type: AWS::Serverless::Function\n    Properties:\n      Runtime: python3.12\n      Handler: app.main\n", "handler_test.py": route}, false},
		{"kubernetes probe exec command", "health_test", "", map[string]string{"k8s/d.yaml": "kind: Deployment\nspec:\n  containers:\n  - name: w\n    livenessProbe:\n      exec:\n        command:\n        - python\n        - health_test.py\n", "health_test.py": route}, false},
		{"setup.py call inside a pytest plugin list", "ab_test", "", map[string]string{"setup.py": "setup(entry_points={'pytest11': [str('x'), 'ab = ab_test:plugin']})\n", "ab_test.py": route}, false},
		{"serverless node handler", "handler_test", "", map[string]string{"serverless.yml": "provider:\n  runtime: nodejs18.x\nfunctions:\n  a:\n    handler: handler_test.main\n", "handler_test.py": route}, false},
		{"compose healthcheck", "health_test", "", map[string]string{"docker-compose.yml": "services:\n  web:\n    healthcheck:\n      test: [\"CMD\", \"python\", \"health_test.py\"]\n  worker:\n    healthcheck:\n      test:\n        - CMD\n        - python\n        - health_test.py\n", "health_test.py": route}, false},
		{"setup.py pytest plugin tuple", "ab_test", "", map[string]string{"setup.py": "setup(entry_points=dict(pytest11=('ab = ab_test:plugin',)))\n", "ab_test.py": route}, false},
		{"conf without a program table", "ab_test", "", map[string]string{"nginx.conf": "command=gunicorn ab_test:app\n", "ab_test.py": route}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustCallGraph(t, c.files)
			ings, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: writeTree(t, c.files)})
			if err != nil {
				t.Fatalf("FindIngresses: %v", err)
			}
			check := func(module string, want bool) {
				handle := funcSCIP(module, nil, "handle", 0)
				if got := hasRoot(res.Roots, handle); got != want {
					t.Errorf("%s handle is a root = %v, want %v (roots %v)", module, got, want, res.Roots)
				}
				if _, got := ingressFor(ings.Ingresses, handle); got != want {
					t.Errorf("%s handle is an ingress = %v, want %v (ingresses %v)", module, got, want, ings.Ingresses)
				}
			}
			check(c.module, c.want)
			if c.other != "" {
				check(c.other, false)
			}
		})
	}
}

// TestCallGraph_EntrypointCallableRoots: the callable a declared entrypoint names is a root,
// followed through a first-party re-export; a same-named function elsewhere is not.
func TestCallGraph_EntrypointCallableRoots(t *testing.T) {
	const cli = "def main():\n    return 1\n"
	cases := []struct {
		name  string
		files map[string]string
		roots []string // modules whose main is a root
		not   []string // modules whose main is not
	}{
		{"console script", map[string]string{"pyproject.toml": "[project.scripts]\nx = \"pkg.cli:main\"\n", "pkg/__init__.py": "", "pkg/cli.py": cli, "pkg/other.py": cli}, []string{"pkg/cli"}, []string{"pkg/other"}},
		{"re-exported by the package", map[string]string{"pyproject.toml": "[project.scripts]\nx = \"pkg:main\"\n", "pkg/__init__.py": "from .cli import main\n", "pkg/cli.py": cli, "pkg/other.py": cli}, []string{"pkg/cli"}, []string{"pkg/other"}},
		{"re-exported by absolute import", map[string]string{"setup.cfg": "[options.entry_points]\nconsole_scripts =\n    x = pkg:main\n", "pkg/__init__.py": "from pkg.cli import main\n", "pkg/cli.py": cli}, []string{"pkg/cli"}, nil},
		{"re-exported from a test-named module", map[string]string{"pyproject.toml": "[project.scripts]\nx = \"scripts:main\"\n", "scripts/__init__.py": "from .test_retriever import main\n", "scripts/test_retriever.py": cli}, []string{"scripts/test_retriever"}, nil},
		{"re-export prefers the exact module", map[string]string{"pyproject.toml": "[project.scripts]\nx = \"pkg:main\"\n", "pkg/__init__.py": "from .cli import main\n", "pkg/cli.py": cli, "examples/pkg/cli.py": cli}, []string{"pkg/cli"}, []string{"examples/pkg/cli"}},
		{"sam handler under its CodeUri", map[string]string{"template.yaml": "Resources:\n  Fn:\n    Type: AWS::Serverless::Function\n    Properties:\n      CodeUri: hello_world/\n      Handler: app.main\n", "app.py": cli, "hello_world/app.py": cli}, []string{"hello_world/app"}, []string{"app"}},
		{"undeclared", map[string]string{"pkg/__init__.py": "", "pkg/cli.py": cli}, nil, []string{"pkg/cli"}},
		{"module-only launch roots no callable", map[string]string{"Dockerfile": "CMD python -m pkg.cli\n", "pkg/__init__.py": "", "pkg/cli.py": cli}, nil, []string{"pkg/cli"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustCallGraph(t, c.files)
			for _, m := range c.roots {
				if !hasRoot(res.Roots, funcSCIP(m, nil, "main", 0)) {
					t.Errorf("%s main is not a root (roots %v)", m, res.Roots)
				}
			}
			for _, m := range c.not {
				if hasRoot(res.Roots, funcSCIP(m, nil, "main", 0)) {
					t.Errorf("%s main is a root (roots %v)", m, res.Roots)
				}
			}
		})
	}
}

func hasRoot(roots []plugin.Symbol, scip string) bool {
	for _, r := range roots {
		if r.SCIP == scip {
			return true
		}
	}
	return false
}
