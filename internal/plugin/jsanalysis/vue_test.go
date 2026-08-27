package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// vueComment is a Vue `<script setup>` single-file component whose template `@click`
// binds a named handler that reaches an imported markdown renderer — the sink an XSS
// advisory would name. It exercises the whole SFC path: script-block ingestion (the
// setup functions become nodes), cross-module edge resolution (onSubmit -> renderMarkdown
// in ../lib), and template-event ingress discovery (@click -> onSubmit). Note the
// Prettier/Vue idiom: no semicolons.
const vueComment = `<template>
  <div>
    <button @click="onSubmit">Save</button>
    <span v-html="preview"></span>
  </div>
</template>

<script setup lang="ts">
import { renderMarkdown } from '../lib'
import { ref } from 'vue'

const preview = ref('')

function onSubmit() {
  preview.value = renderMarkdown(userInput())
}

function userInput() {
  return document.querySelector('#c').value
}
</script>
`

const vueLib = `export function renderMarkdown(raw) { return dangerousParse(raw); }
export function dangerousParse(s) { return s; }
`

// TestVueSFC_TemplateEventHandlerIsIngress proves a Vue template `@click="handler"`
// binding is recognized as a handler ingress naming the same call-graph node the script
// block declares — the framework-implicit entrypoint the pure-JS lane could not see
// (the whole `.vue` file was formerly skipped).
func TestVueSFC_TemplateEventHandlerIsIngress(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"components/Comment.vue": vueComment,
		"lib.ts":                 vueLib,
	})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	onSubmit := funcSCIP("components/Comment", nil, "onSubmit", 0)
	in, ok := ingressFor(res.Ingresses, onSubmit)
	if !ok {
		t.Fatalf("template @click handler onSubmit not found as ingress; got %+v", res.Ingresses)
	}
	if in.Kind != "handler" {
		t.Errorf("template event ingress kind = %q, want handler", in.Kind)
	}
}

// TestVueSFC_ScriptFunctionsAndEdges proves the `<script setup>` block is parsed as an
// ordinary module: its functions become nodes and its calls become edges, including a
// cross-module edge to an imported sink (onSubmit -> renderMarkdown in lib), and the
// handler is recorded as a call-graph root.
func TestVueSFC_ScriptFunctionsAndEdges(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"components/Comment.vue": vueComment,
		"lib.ts":                 vueLib,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	onSubmit := funcSCIP("components/Comment", nil, "onSubmit", 0)
	renderMarkdown := funcSCIP("lib", nil, "renderMarkdown", 1)
	if !hasEdge(res.Edges, onSubmit, renderMarkdown) {
		t.Fatalf("want SFC edge onSubmit -> renderMarkdown; got %+v", res.Edges)
	}
	var rooted bool
	for _, r := range res.Roots {
		if r.SCIP == onSubmit {
			rooted = true
		}
	}
	if !rooted {
		t.Fatalf("template handler onSubmit must be a call-graph root; got roots %+v", res.Roots)
	}
}

// TestReachability_VueTemplateToSink is the end-to-end proof: the template `@click`
// entrypoint reaches the imported sink through the SFC script, emitting one ingress→sink
// ReachPath (onSubmit -> renderMarkdown -> dangerousParse). Before Vue support the entire
// `.vue` file was invisible and the graph falsely declared Complete with the sink
// unreachable.
func TestReachability_VueTemplateToSink(t *testing.T) {
	ctx := context.Background()
	dir := writeProgram(t, map[string]string{
		"components/Comment.vue": vueComment,
		"lib.ts":                 vueLib,
	})
	sink := resolveSink(t, dir, "dangerousParse")

	res, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want exactly one reach path from the @click entrypoint to the sink, got %d: %+v", len(res.Paths), res.Paths)
	}
	p := res.Paths[0]
	if p.Sink.SCIP != sink {
		t.Fatalf("path sink = %q, want %q", p.Sink.SCIP, sink)
	}
	onSubmit := funcSCIP("components/Comment", nil, "onSubmit", 0)
	if p.Ingress.SCIP != onSubmit {
		t.Fatalf("path ingress = %q, want the template handler %q", p.Ingress.SCIP, onSubmit)
	}
	if p.Trace[0].SCIP != onSubmit || p.Trace[len(p.Trace)-1].SCIP != sink {
		t.Fatalf("trace must run from the handler to the sink; got %+v", p.Trace)
	}
}

// TestVueSFC_InlineHandlerIsNotIngress proves the honest-absence boundary for templates:
// an event value that is NOT a bare method reference — an inline expression, an inline
// arrow, or a member access — records no ingress (never a fabricated entry), exactly as
// an anonymous inline-arrow Express handler records none.
func TestVueSFC_InlineHandlerIsNotIngress(t *testing.T) {
	const sfc = `<template>
  <button @click="count++">inc</button>
  <button @click="() => remove(id)">del</button>
  <button @click="store.dispatch('act')">act</button>
  <input @input="v-on-nothing">
</template>

<script setup>
function remove(id) { wipe(id) }
function wipe(id) { return id }
</script>
`
	dir := writeProgram(t, map[string]string{"C.vue": sfc})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	if len(res.Ingresses) != 0 {
		t.Fatalf("inline expression / arrow / member-access handlers must not be ingresses; got %+v", res.Ingresses)
	}
}

// TestVueSFC_ExplicitCallHandlerIsIngress proves the explicit-call value form
// `@click="onSubmit()"` (and `@submit.prevent="onSubmit"` with a modifier) names the
// same bare handler as the shorthand.
func TestVueSFC_ExplicitCallHandlerIsIngress(t *testing.T) {
	const sfc = `<template>
  <form @submit.prevent="save()"><button>ok</button></form>
</template>

<script setup>
function save() { persist() }
function persist() { return 1 }
</script>
`
	dir := writeProgram(t, map[string]string{"F.vue": sfc})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	save := funcSCIP("F", nil, "save", 0)
	if _, ok := ingressFor(res.Ingresses, save); !ok {
		t.Fatalf("@submit.prevent=\"save()\" must name save as a handler ingress; got %+v", res.Ingresses)
	}
}

// TestImportWithoutSemicolonScansBody guards the JS-layer fix the Vue idiom exposed: a
// no-semicolon (ASI) `import` must not swallow the rest of the module. This is asserted
// on a plain `.js` file so the guard stands independent of Vue.
func TestImportWithoutSemicolonScansBody(t *testing.T) {
	const src = `import { danger } from './lib'
import { other } from './other'

function handler(req, res) {
  return danger(req.body)
}
`
	dir := writeProgram(t, map[string]string{
		"app.js":   src,
		"lib.js":   "export function danger(x) { return x; }\n",
		"other.js": "export function other() { return 1; }\n",
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handler := funcSCIP("app", nil, "handler", 2)
	danger := funcSCIP("lib", nil, "danger", 1)
	if !hasEdge(res.Edges, handler, danger) {
		t.Fatalf("no-semicolon imports must not swallow the body: want edge handler -> danger; got %+v", res.Edges)
	}
}

// TestVueSFC_NestedTemplateBlock proves the `<template>` extractor matches its close tag
// with nesting awareness: a handler inside a nested `<template v-if>` is still found, and
// the block does not end at the inner `</template>`.
func TestVueSFC_NestedTemplateBlock(t *testing.T) {
	const sfc = `<template>
  <div>
    <template v-if="ok">
      <button @click="onDeep">deep</button>
    </template>
  </div>
</template>

<script setup>
function onDeep() { sink() }
function sink() { return 1 }
</script>
`
	dir := writeProgram(t, map[string]string{"N.vue": sfc})
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	onDeep := funcSCIP("N", nil, "onDeep", 0)
	if _, ok := ingressFor(res.Ingresses, onDeep); !ok {
		t.Fatalf("handler in a nested <template> must be found; got %+v", res.Ingresses)
	}
}

// TestVueSFC_Deterministic proves repeated runs over the same SFC produce byte-identical
// ingress and edge ordering (C1).
func TestVueSFC_Deterministic(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"components/Comment.vue": vueComment,
		"lib.ts":                 vueLib,
	})
	ctx := context.Background()
	first, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	for i := 0; i < 3; i++ {
		got, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
		if err != nil {
			t.Fatalf("CallGraph rerun: %v", err)
		}
		if len(got.Edges) != len(first.Edges) {
			t.Fatalf("edge count drift: %d vs %d", len(got.Edges), len(first.Edges))
		}
		for j := range got.Edges {
			if got.Edges[j] != first.Edges[j] {
				t.Fatalf("edge order drift at %d: %+v vs %+v", j, got.Edges[j], first.Edges[j])
			}
		}
	}
}
