package com.example.web;

// PLAN-040 symbol-profile characterization fixture.
//
// This source is PARSED for its declaration shapes only — it is NEVER compiled or
// executed (the javaanalysis engine is a source-declaration parser; see scip.go).
// Each construct below makes one row of ../../SYMBOL_PROFILE.md concrete, so the
// characterization test (symbol_profile_test.go) can pin the emitter's behaviour
// against the published profile. The bodies are deliberately trivial and exist
// only so the shapes parse; nothing here is meant to link or run.
public final class SymbolProfileFixture {
    private SymbolProfileFixture() {
    }
}

// UrlServiceImpl carries the SEPARATED type/method rows AND the COLLAPSED
// constructor row:
//   type              com/example/web/UrlServiceImpl#
//   constructor       com/example/web/UrlServiceImpl#UrlServiceImpl(1).   (no <init> marker)
//   method fetch      com/example/web/UrlServiceImpl#fetch(1).
//   method handle     com/example/web/UrlServiceImpl#handle(2).
class UrlServiceImpl {
    UrlServiceImpl(int retries) {
    }

    String fetch(String u) {
        return u;
    }

    Object handle(Object req, int flags) {
        return req;
    }
}

// Calc carries the COLLAPSED same-arity-overload row: f(int) and f(String) are two
// distinct source declarations that both erase to com/example/web/Calc#f(1).
class Calc {
    int f(int x) {
        return x;
    }

    int f(String s) {
        return s.length();
    }
}

// Service carries the SEPARATED nested-declaration rows:
//   nested type       com/example/web/Service#Config#
//   nested field      com/example/web/Service#Config#retries.
class Service {
    static class Config {
        int retries;
    }
}

// Outer carries the SEPARATED nested-class row: com/example/web/Outer#Inner#
class Outer {
    class Inner {
    }
}

// Box carries the COLLAPSED generics row: the <T> is lexically stripped, so this
// renders com/example/web/Box# — a raw Box would render identically.
class Box<T> {
}

// Gen carries the ABSENT generated/synthetic rows: the parser mints no symbol for
// the synthesized lambda, and the enum mints no values()/valueOf(). Only the
// user-declared members below (and the enum constants) ever appear in the index.
class Gen {
    Runnable make() {
        return () -> fetchNothing();
    }

    void fetchNothing() {
    }
}

enum Status {
    OK,
    FAILED
}
