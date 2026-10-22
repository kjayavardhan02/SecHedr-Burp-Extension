package com.securityheaders;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public final class HeaderResult {

    private static final AtomicLong ID_GEN = new AtomicLong(0);

    private final long id;
    private final Instant observedAt;
    private final String host;
    private final int port;
    private final String method;
    private final String pathAndQuery;
    private final int statusCode;
    private final boolean hstsPresent;
    private final boolean cacheControlPresent;
    private final boolean xfoPresent;
    private final boolean xfoCoveredByCsp;
    private final boolean xctoPresent;
    private final boolean acaoPresent;
    private final boolean cspPresent;
    private final String rawRequest;
    private final String rawResponse;

    public HeaderResult(String host, int port, String method, String pathAndQuery,
                        int statusCode, boolean hstsPresent, boolean cacheControlPresent,
                        boolean xfoPresent, boolean xctoPresent,
                        boolean acaoPresent, boolean cspPresent) {
        this(host, port, method, pathAndQuery, statusCode, hstsPresent, cacheControlPresent,
                xfoPresent, false, xctoPresent, acaoPresent, cspPresent, null, null);
    }

    public HeaderResult(String host, int port, String method, String pathAndQuery,
                        int statusCode, boolean hstsPresent, boolean cacheControlPresent,
                        boolean xfoPresent, boolean xfoCoveredByCsp, boolean xctoPresent,
                        boolean acaoPresent, boolean cspPresent) {
        this(host, port, method, pathAndQuery, statusCode, hstsPresent, cacheControlPresent,
                xfoPresent, xfoCoveredByCsp, xctoPresent, acaoPresent, cspPresent, null, null);
    }

    public HeaderResult(String host, int port, String method, String pathAndQuery,
                        int statusCode, boolean hstsPresent, boolean cacheControlPresent,
                        boolean xfoPresent, boolean xfoCoveredByCsp, boolean xctoPresent,
                        boolean acaoPresent, boolean cspPresent,
                        String rawRequest, String rawResponse) {
        this.id = ID_GEN.incrementAndGet();
        this.observedAt = Instant.now();
        this.host = host;
        this.port = port;
        this.method = method;
        this.pathAndQuery = pathAndQuery;
        this.statusCode = statusCode;
        this.hstsPresent = hstsPresent;
        this.cacheControlPresent = cacheControlPresent;
        this.xfoPresent = xfoPresent;
        this.xfoCoveredByCsp = xfoCoveredByCsp;
        this.xctoPresent = xctoPresent;
        this.acaoPresent = acaoPresent;
        this.cspPresent = cspPresent;
        this.rawRequest = rawRequest;
        this.rawResponse = rawResponse;
    }

    public long id() { return id; }
    public Instant observedAt() { return observedAt; }
    public String host() { return host; }
    public int port() { return port; }
    public String method() { return method; }
    public String pathAndQuery() { return pathAndQuery; }
    public int statusCode() { return statusCode; }
    public boolean hstsPresent() { return hstsPresent; }
    public boolean cacheControlPresent() { return cacheControlPresent; }
    public boolean xfoPresent() { return xfoPresent; }
    public boolean xfoCoveredByCsp() { return xfoCoveredByCsp; }
    public boolean xctoPresent() { return xctoPresent; }
    public boolean acaoPresent() { return acaoPresent; }
    public boolean cspPresent() { return cspPresent; }
    public String rawRequest() { return rawRequest; }
    public String rawResponse() { return rawResponse; }

    public int missingCount() {
        int count = 0;
        if (!hstsPresent) count++;
        if (!cacheControlPresent) count++;
        if (!xfoPresent && !xfoCoveredByCsp) count++;
        if (!xctoPresent) count++;
        if (!acaoPresent) count++;
        if (!cspPresent) count++;
        return count;
    }

    public boolean hasAnyMissing() {
        return missingCount() > 0;
    }

    public String endpointKey() {
        return host + ":" + port + ":" + method + ":" + pathAndQuery;
    }
}
