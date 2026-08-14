package com.example.web;

/**
 * FetchController is the @RestController INGRESS for TEGRON-JAVA-SSRF-0003.
 *
 * INTENDED BEHAVIOUR of this fixture (decided by a LATER consuming test, not here):
 *   ungated (pure-Go lexical)              -> not_exploitable
 *   analyzer gated-but-unavailable overlay -> undetermined with tool_failure over the
 *                                             retained lexical edges (never a clean
 *                                             empty graph).
 * The tool-unavailability is a RUN OVERLAY applied by the harness (analyzer image gated
 * on + binary absent); it is NOT present in this directory. This class is a plain
 * interface-dispatch ingress.
 *
 * The route method fetch(@RequestParam target) reaches the SSRF sink ONLY through the
 * @Autowired SomeService interface field — svc.fetch(target). Because svc's static type
 * is the interface SomeService, the pure-Go lexical call graph keys the call as fetch/1
 * and finds MORE THAN ONE fetch/1 declaration (the interface method AND the concrete
 * override), so it fabricates NO edge and declares Partial(dynamic_dispatch): no
 * ingress->sink path lexically. The container-backed scip-java semantic graph resolves
 * the dispatch and completes the path.
 */
@RestController
class FetchController {

    @Autowired
    SomeService svc;

    @GetMapping("/fetch")
    int fetch(@RequestParam("target") String target) throws Exception {
        // The load-bearing call site: dispatch is through the SomeService INTERFACE
        // type, so no resolvable candidate edge exists in the pure-Go lexical pass.
        return svc.fetch(target);
    }
}
