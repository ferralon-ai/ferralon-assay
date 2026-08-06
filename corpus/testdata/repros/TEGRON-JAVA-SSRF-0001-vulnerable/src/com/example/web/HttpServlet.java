package com.example.web;

import com.sun.net.httpserver.HttpExchange;

/**
 * HttpServlet is a minimal servlet base shaped like javax.servlet.http.HttpServlet
 * so the repro models the servlet ingress idiom WITHOUT pulling in a servlet
 * container. A subclass overrides doGet/doPost; Main dispatches inbound requests
 * to doGet, exactly as a servlet container would. The pure-Go source analyzer
 * recognizes "extends HttpServlet" + doGet lexically as a servlet ingress.
 */
public abstract class HttpServlet {
    public void doGet(HttpExchange req, StringBuilder resp) throws Exception {
        // Default: not implemented. Subclasses override.
    }

    public void doPost(HttpExchange req, StringBuilder resp) throws Exception {
        // Default: not implemented. Subclasses override.
    }
}
