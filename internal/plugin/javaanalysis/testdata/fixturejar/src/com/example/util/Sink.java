// A utility class whose method is the "sink" the call chain forwards to.
// Comments, a string literal with braces "}" and a "class" word, and a char
// literal '{' are present to exercise the lexical pre-pass.
package com.example.util;

public final class Sink {
    public static final String PREFIX = "sink: { not a class }";

    /* block comment mentioning interface and { braces } */
    public static String forward(String input) {
        char c = '{';
        return PREFIX + input + c;
    }
}
