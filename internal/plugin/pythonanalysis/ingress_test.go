package pythonanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func ingressFor(ings []plugin.Ingress, symbol string) (plugin.Ingress, bool) {
	for _, in := range ings {
		if in.Symbol.SCIP == symbol {
			return in, true
		}
	}
	return plugin.Ingress{}, false
}

func TestFindIngresses_FlaskRouteDetected(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handle_fetch", 0)
	in, ok := ingressFor(res.Ingresses, handleFetch)
	if !ok {
		t.Fatalf("Flask route handler handle_fetch not found as ingress; got %+v", res.Ingresses)
	}
	if in.Kind != "http_route" {
		t.Errorf("Flask route ingress kind = %q, want http_route", in.Kind)
	}
	// A cleanly-parsed source declares ingress discovery Complete (distinct from the
	// always-Partial call graph).
	if !res.Partiality.Complete {
		t.Errorf("clean Flask parse must declare ingress discovery Complete; got %+v", res.Partiality)
	}
}

func TestFindIngresses_FastAPIRouteDetected(t *testing.T) {
	// FastAPI/Starlette: @app.get / @router.post / @app.websocket decorators, async defs.
	src := `
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter()

@app.get('/items')
async def list_items():
    return read_items()

@router.post('/items')
async def create_item(payload):
    return store_item(payload)

@app.websocket('/ws')
async def ws_endpoint(websocket):
    return handle_ws(websocket)

def read_items():
    return []

def store_item(payload):
    return payload

def handle_ws(ws):
    return ws
`
	dir := writeTree(t, map[string]string{"api.py": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	for _, want := range []struct {
		name  string
		arity int
	}{
		{"list_items", 0},
		{"create_item", 1},
		{"ws_endpoint", 1},
	} {
		scip := funcSCIP("api", nil, want.name, want.arity)
		in, ok := ingressFor(res.Ingresses, scip)
		if !ok {
			t.Errorf("FastAPI handler %s not found as ingress; got %+v", want.name, res.Ingresses)
			continue
		}
		if in.Kind != "http_route" {
			t.Errorf("FastAPI ingress %s kind = %q, want http_route", want.name, in.Kind)
		}
	}
}

// TestFindIngresses_NonRouteDecoratorIsNotIngress proves a plain decorator
// (@login_required, @staticmethod, @pytest.fixture) does not mark its def as an ingress.
func TestFindIngresses_NonRouteDecoratorIsNotIngress(t *testing.T) {
	src := `
import functools

@functools.wraps
def helper():
    return work()

@login_required
def guarded():
    return work()

def work():
    return 1
`
	dir := writeTree(t, map[string]string{"m.py": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Errorf("non-route decorators must not be ingresses; got %+v", res.Ingresses)
	}
}

// TestFindIngresses_MethodRouteHandler proves a route handler declared as a class method
// (a Flask/FastAPI view method) resolves its ingress under the class chain.
func TestFindIngresses_MethodRouteHandler(t *testing.T) {
	src := `
class Views:
    @app.route('/profile')
    def profile(self):
        return render()

def render():
    return ''
`
	dir := writeTree(t, map[string]string{"views.py": src})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	profile := funcSCIP("views", []string{"Views"}, "profile", 1)
	if _, ok := ingressFor(res.Ingresses, profile); !ok {
		t.Errorf("method route handler Views.profile not found as ingress; got %+v", res.Ingresses)
	}
}
