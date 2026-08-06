package com.example.web;

// Minimal Java source so the language detector classifies this vendored repro as Java.
// This fixture exists only to prove checkout + codebase_inventory accept a no-go.mod tree;
// it is not compiled or analyzed by the hermetic tests.
public class UrlFetcher {
    public String fetch(String target) {
        return target;
    }
}
