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
