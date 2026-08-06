package com.example.service;

// An enum and a record in one file: both are named types the indexer must emit.
public enum Status {
    OK,
    FAILED;

    public boolean isOk() {
        return this == OK;
    }
}
