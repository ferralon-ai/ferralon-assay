package com.example.service;

// A record with a compact header and an extra method, exercising the record
// header (parenthesized components) being skipped before the body brace.
public record Point(int x, int y) {
    public int sum() {
        return x + y;
    }
}
