package com.example.service;

import com.example.util.Sink;
import java.util.List;

/**
 * Service exposes overloaded handle methods, a field, a constructor, a nested
 * type, and an inner interface to exercise the indexer's declaration coverage.
 */
public class Service {
    private final String name;

    public Service(String name) {
        this.name = name;
    }

    public String handle() {
        return handle(name, List.of("x"));
    }

    public String handle(String req, List<String> opts) {
        return Sink.forward(name + ":" + req + opts.size());
    }

    public static class Config {
        public int retries;
    }

    public interface Listener {
        void onEvent(String e);
    }
}
