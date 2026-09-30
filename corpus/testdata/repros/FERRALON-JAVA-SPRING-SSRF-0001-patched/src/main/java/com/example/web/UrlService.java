package com.example.web;

/**
 * UrlService is the @Autowired dispatch boundary. The controller holds a field of
 * THIS interface type and calls svc.fetch(target); the concrete target of that
 * call is UrlServiceImpl.fetch, but only the type system (scip-java) can prove it.
 * The pure-Go lexical analyzer keys the call on (simpleName, arity) = fetch/1 and
 * finds TWO declarations (this interface method and the impl override) → it
 * fabricates NO edge and declares Partial(dynamic_dispatch). The container-backed
 * semantic graph resolves this interface→impl edge — the verdict class Increment 3
 * unlocks.
 */
interface UrlService {
    int fetch(String target) throws Exception;
}
