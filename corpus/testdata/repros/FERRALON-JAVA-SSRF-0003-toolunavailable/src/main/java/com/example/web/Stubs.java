package com.example.web;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * First-party annotation stubs shaped like Spring's @RestController / @Service /
 * @Autowired / @GetMapping / @RequestParam. Using first-party stubs (instead of a Spring
 * Boot dependency) keeps the project DEPENDENCY-LIGHT so the scip-java analyzer container
 * indexes it fully OFFLINE — no Maven Central fetch, no flaky network. scip-java still
 * resolves the @Autowired interface field's dispatch to the concrete impl via the type
 * system; the annotations only mark the ingress. The pure-Go lexical analyzer cannot
 * resolve svc.fetch() across the SomeService interface, so it stays
 * Partial(dynamic_dispatch) — which is what makes this fixture not_exploitable ungated
 * and undetermined under the gated-but-unavailable run overlay.
 */
final class Stubs {
    private Stubs() {
    }
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@interface RestController {
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@interface Service {
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@interface GetMapping {
    String value();
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
@interface RequestParam {
    String value();
}

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
@interface Autowired {
}
