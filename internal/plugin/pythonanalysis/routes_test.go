package pythonanalysis

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestRouteHandlers_MatchesFindIngresses(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"app.py": flaskApp,
		"pkg/api/views.py": `
from fastapi import APIRouter

router = APIRouter()

class Items:
    @router.get('/items')
    def list_items(self):
        return []
`,
	})
	ctx := context.Background()

	got, part, err := RouteHandlers(ctx, dir)
	if err != nil {
		t.Fatalf("RouteHandlers: %v", err)
	}
	want := []RouteHandler{
		{Kind: "http_route", Selector: "route", QualifiedName: "app.handle_fetch"},
		{Kind: "http_route", Selector: "get", QualifiedName: "pkg.api.views.Items.list_items"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RouteHandlers = %+v, want %+v", got, want)
	}

	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(ing.Ingresses) != len(got) {
		t.Fatalf("RouteHandlers found %d handlers, FindIngresses %d", len(got), len(ing.Ingresses))
	}
	if !reflect.DeepEqual(part, ing.Partiality) {
		t.Errorf("partiality = %+v, FindIngresses declares %+v", part, ing.Partiality)
	}
}

func TestRouteHandlers_MissingDirIsHardError(t *testing.T) {
	if _, _, err := RouteHandlers(context.Background(), t.TempDir()+"/absent"); err == nil {
		t.Fatal("RouteHandlers on a missing dir: want error, got nil")
	}
}

// A handler registered inside a function (Flask's app-factory idiom) is named with its
// enclosing function chain, as Python's qualified name has it; the incumbent's SCIP id for the
// same ingress keeps ignoring enclosing functions.
func TestRouteHandlers_NestedHandlerNamesEnclosingFunctions(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"airflow/utils/serve_logs.py": `
from flask import Flask

def create_app():
    flask_app = Flask(__name__, static_folder=None)

    @flask_app.route("/log/<path:filename>")
    def serve_logs_view(filename):
        return filename

    return flask_app
`,
		"pkg/views.py": `
from fastapi import APIRouter

router = APIRouter()

class Api:
    def install(self):
        @router.get('/health')
        async def health():
            return {}
`,
	})
	ctx := context.Background()

	got, _, err := RouteHandlers(ctx, dir)
	if err != nil {
		t.Fatalf("RouteHandlers: %v", err)
	}
	want := []RouteHandler{
		{Kind: "http_route", Selector: "route", QualifiedName: "airflow.utils.serve_logs.create_app.serve_logs_view"},
		{Kind: "http_route", Selector: "get", QualifiedName: "pkg.views.Api.install.health"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RouteHandlers = %+v, want %+v", got, want)
	}

	ing, err := FindIngresses(ctx, plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	var scips []string
	for _, in := range ing.Ingresses {
		scips = append(scips, in.Symbol.SCIP)
	}
	wantSCIP := []string{
		funcSCIP("airflow/utils/serve_logs", nil, "serve_logs_view", 1),
		funcSCIP("pkg/views", []string{"Api"}, "health", 0),
	}
	if !reflect.DeepEqual(scips, wantSCIP) {
		t.Errorf("FindIngresses SCIP ids = %q, want %q (unchanged incumbent naming)", scips, wantSCIP)
	}
}
