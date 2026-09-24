// Package jvmingress is the single source of truth for the JVM ingress families
// the analyzers recognize. One family is declared once here; every JVM-language
// adapter (Java lexical, Java SCIP, Kotlin bytecode) derives its own match form
// from this shared vocabulary rather than maintaining a parallel table.
//
// The load-bearing principle: the registry unifies WHAT is an ingress (the
// vocabulary); each adapter keeps HOW it is matched, because the substrates
// differ (Java lexical scans source, Java SCIP matches symbol needles, Kotlin
// strips bytecode descriptors). The match key in every annotation lane is the
// annotation's simple name, so a family declares one canonical simple name and
// each adapter builds its own match form from it.
//
// Behavior-preservation is structural: SCIPNeedle is optional. A family with an
// empty needle is invisible to the SCIP adapter, which is exactly how JAX-RS and
// servlet ingresses are absent from SCIP today. Closing that gap later is a
// one-line data change (populate the needle); no mechanism changes.
package jvmingress

import "sort"

// Ingress Kind values. These are the plugin.Ingress.Kind strings the adapters
// emit; the registry declares them once so every lane agrees.
const (
	KindHTTPRoute       = "http_route"
	KindScheduled       = "scheduled"
	KindEventListener   = "event_listener"
	KindLifecycle       = "lifecycle"
	KindMessageListener = "message_listener"
	KindServlet         = "servlet"
)

// IngressFamily declares one ingress family. Declared once; every adapter reads
// this. Name is the stable id and sort key.
type IngressFamily struct {
	Name  string    // stable id, sort key: "spring.get", "jaxrs.get", "servlet", ...
	Kind  string    // one of the Kind* constants
	Match MatchSpec // substrate-agnostic recognition vocabulary

	// SCIPNeedle is the scip-java annotation-type descriptor needle for this
	// family (e.g. "GetMapping#"). Empty means the SCIP adapter does not cover
	// this family — JAX-RS and servlet carry no needle, preserving today's SCIP
	// absence.
	SCIPNeedle string

	// Verb is the HTTP method for an http_route family: "GET".."PATCH", or "" for
	// ANY (RequestMapping / all-verbs). Empty for non-route kinds.
	Verb string
}

// MatchSpec is the substrate-agnostic recognition vocabulary for a family.
type MatchSpec struct {
	Annotation  string   // simple name, e.g. "GetMapping"; "" for non-annotation families (servlet)
	SuperSuffix string   // direct-superclass name-suffix, e.g. "HttpServlet"; "" unless supertype-based
	Methods     []string // method-name set for supertype-method families (servlet); nil otherwise
}

// families is the behavior-preserving census. Declared in any order; Families()
// returns them sorted by Name so no declaration order and no map-iteration order
// can leak into any adapter's emitted output.
var families = []IngressFamily{
	{Name: "spring.request", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "RequestMapping"}, SCIPNeedle: "RequestMapping#", Verb: ""},
	{Name: "spring.get", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "GetMapping"}, SCIPNeedle: "GetMapping#", Verb: "GET"},
	{Name: "spring.post", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "PostMapping"}, SCIPNeedle: "PostMapping#", Verb: "POST"},
	{Name: "spring.put", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "PutMapping"}, SCIPNeedle: "PutMapping#", Verb: "PUT"},
	{Name: "spring.delete", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "DeleteMapping"}, SCIPNeedle: "DeleteMapping#", Verb: "DELETE"},
	{Name: "spring.patch", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "PatchMapping"}, SCIPNeedle: "PatchMapping#", Verb: "PATCH"},

	{Name: "jaxrs.path", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "Path"}, SCIPNeedle: "", Verb: ""},
	{Name: "jaxrs.get", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "GET"}, SCIPNeedle: "", Verb: "GET"},
	{Name: "jaxrs.post", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "POST"}, SCIPNeedle: "", Verb: "POST"},
	{Name: "jaxrs.put", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "PUT"}, SCIPNeedle: "", Verb: "PUT"},
	{Name: "jaxrs.delete", Kind: KindHTTPRoute, Match: MatchSpec{Annotation: "DELETE"}, SCIPNeedle: "", Verb: "DELETE"},

	{Name: "scheduled", Kind: KindScheduled, Match: MatchSpec{Annotation: "Scheduled"}, SCIPNeedle: "Scheduled#"},
	{Name: "event.listener", Kind: KindEventListener, Match: MatchSpec{Annotation: "EventListener"}, SCIPNeedle: "EventListener#"},
	{Name: "lifecycle.postconstruct", Kind: KindLifecycle, Match: MatchSpec{Annotation: "PostConstruct"}, SCIPNeedle: "PostConstruct#"},
	{Name: "lifecycle.predestroy", Kind: KindLifecycle, Match: MatchSpec{Annotation: "PreDestroy"}, SCIPNeedle: "PreDestroy#"},
	{Name: "msg.kafka", Kind: KindMessageListener, Match: MatchSpec{Annotation: "KafkaListener"}, SCIPNeedle: "KafkaListener#"},
	{Name: "msg.jms", Kind: KindMessageListener, Match: MatchSpec{Annotation: "JmsListener"}, SCIPNeedle: "JmsListener#"},
	{Name: "msg.rabbit", Kind: KindMessageListener, Match: MatchSpec{Annotation: "RabbitListener"}, SCIPNeedle: "RabbitListener#"},

	{Name: "servlet", Kind: KindServlet, Match: MatchSpec{SuperSuffix: "HttpServlet", Methods: []string{"doGet", "doPost", "doPut", "doDelete", "service"}}, SCIPNeedle: ""},
}

// sortedFamilies is the census sorted by Name once at package init, so every
// caller iterates in the same deterministic order.
var sortedFamilies = sortByName(families)

func sortByName(in []IngressFamily) []IngressFamily {
	out := make([]IngressFamily, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Families returns every ingress family in deterministic Name-sorted order. The
// returned slice is a fresh copy: callers may not mutate the registry.
func Families() []IngressFamily {
	out := make([]IngressFamily, len(sortedFamilies))
	copy(out, sortedFamilies)
	return out
}
