package com.example.web;

/**
 * FetchController is the @RestController INGRESS for TEGRON-JAVA-SPRING-SSRF-0001.
 * The route method fetch(@RequestParam target) reaches the SSRF sink ONLY through
 * the @Autowired UrlService interface field — svc.fetch(target). Because svc's
 * static type is the interface UrlService, the pure-Go lexical call-graph cannot
 * connect this call to the concrete UrlServiceImpl.fetch (it is one of two fetch/1
 * declarations) and declares Partial(dynamic_dispatch): no ingress→sink path, no
 * proof. The container-backed scip-java semantic graph resolves the dispatch and
 * completes the path — the verdict class this repro exists to demonstrate.
 */
@RestController
class FetchController {

    @Autowired
    UrlService svc;

    @GetMapping("/fetch")
    int fetch(@RequestParam("target") String target) throws Exception {
        return svc.fetch(target);
    }
}
