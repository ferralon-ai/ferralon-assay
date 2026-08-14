package com.example.web;

/**
 * SomeService is the @Autowired dispatch boundary. FetchController holds a field of THIS
 * interface type and calls svc.fetch(target); the concrete target of that call is
 * SomeServiceImpl.fetch, but only the type system (scip-java) can prove it.
 *
 * The pure-Go lexical analyzer keys the call on (simpleName, arity) = fetch/1 and finds
 * MORE THAN ONE declaration (this interface method and the impl override) -> it
 * fabricates NO edge and declares Partial(dynamic_dispatch). The container-backed
 * semantic graph resolves this interface->impl edge. That resolvable/unresolvable
 * asymmetry is exactly what makes this fixture not_exploitable when ungated and
 * undetermined (tool_failure) when the analyzer is gated-but-unavailable.
 */
interface SomeService {
    int fetch(String target) throws Exception;
}
