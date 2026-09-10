// UrlKit is a tiny, offline parsed-only fixture the Java reference symbol profile
// (plugin/symboltest.JavaReferenceProfile) is driven against via
// javaanalysis.IndexSymbols. It exercises the real source constructs the eight
// §4.3 categories map to — a package clause, a type, a method, a constructor, a
// same-arity overload pair, a nested type, and a generic type — so the lexical
// producer emits real symbols for the ones it can see. Constructs the source
// parser CANNOT see (compiler-synthesized bridge/synthetic methods, shaded
// dependency coordinates) are targeted by the profile as measured gaps and have
// no declaration here by design. Nothing is compiled or run; the file is read as
// text.
package com.example.web;

// UrlService is a top-level type (category: types) carrying a constructor
// (category: constructors) and a method (category: methods), with a nested type
// (category: nested declarations).
public class UrlService {
    private final String base;

    // UrlService(String) is the constructor. The canonical profile targets it as
    // Kind=constructor Name=<init> with a full JVM parameter descriptor; the
    // lexical producer renders it as a method named for the class, no <init>.
    public UrlService(String base) {
        this.base = base;
    }

    // fetch(String) is a method on UrlService.
    public String fetch(String path) {
        return base + path;
    }

    // Config is a type nested under UrlService (category: nested declarations).
    public static class Config {
        public boolean verbose;
    }
}

// Calc carries a same-arity overload pair f(int)/f(String): identical name and
// parameter count, distinct parameter TYPES. The lexical producer disambiguates
// by arity, so both collapse to the same id; the canonical profile separates them
// by full JVM parameter descriptor (category: overloads/generics).
class Calc {
    public void f(int x) {
    }

    public void f(String s) {
    }
}

// Box<T> is a generic type whose get() returns T. The compiler synthesizes a
// bridge method get()Ljava/lang/Object; that the source parser never sees; the
// canonical profile targets that bridge as a generated symbol (category:
// generated symbols).
class Box<T> {
    private T value;

    public T get() {
        return value;
    }
}
