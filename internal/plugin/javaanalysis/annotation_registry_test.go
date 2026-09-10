package javaanalysis

import "testing"

// TestH1_RouteAndEntrypointRegistry proves the lexical H1 registry: an overlay-style
// registration is visible to the classifiers, and the built-in entries survive
// (registration is additive, never a replacement).
func TestH1_RouteAndEntrypointRegistry(t *testing.T) {
	if !routeAnnotations["GetMapping"] {
		t.Fatal("built-in GetMapping missing before registration")
	}
	registerRouteAnnotation("MessageMapping")
	defer delete(routeAnnotations, "MessageMapping")
	if !routeAnnotations["MessageMapping"] {
		t.Error("registerRouteAnnotation did not add MessageMapping")
	}
	if !routeAnnotations["GetMapping"] {
		t.Error("registration clobbered the built-in GetMapping")
	}

	registerContainerEntrypoint("SqsListener", "message_listener")
	defer delete(containerEntrypoints, "SqsListener")
	if containerEntrypoints["SqsListener"] != "message_listener" {
		t.Error("registerContainerEntrypoint did not add SqsListener")
	}
	if containerEntrypoints["Scheduled"] != "scheduled" {
		t.Error("registration clobbered the built-in Scheduled")
	}
}

// TestH1_SCIPRegistry proves the SCIP-space twin registry: a registered needle is
// matched by the classifier, built-in first-match order is preserved, and the append
// is undone so the global is left as found.
func TestH1_SCIPRegistry(t *testing.T) {
	if sel, ok := mappingSelector("scip-java maven x 0 com/e/C#GetMapping#"); !ok || sel != "GET" {
		t.Fatalf("built-in GetMapping needle: sel=%q ok=%v, want GET", sel, ok)
	}
	origMap := len(mappingSelectorRegistry)
	origEnt := len(containerEntrypointRegistry)
	defer func() {
		mappingSelectorRegistry = mappingSelectorRegistry[:origMap]
		containerEntrypointRegistry = containerEntrypointRegistry[:origEnt]
	}()

	registerMappingSelector("MessageMapping#", "MSG")
	if sel, ok := mappingSelector("scip-java maven x 0 com/e/C#MessageMapping#"); !ok || sel != "MSG" {
		t.Errorf("registered MessageMapping needle: sel=%q ok=%v, want MSG", sel, ok)
	}
	registerContainerEntrypointNeedle("SqsListener#", "message_listener")
	if k, ok := containerEntrypointKind("scip-java maven x 0 com/e/C#SqsListener#"); !ok || k != "message_listener" {
		t.Errorf("registered SqsListener needle: kind=%q ok=%v", k, ok)
	}
}
