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
    private final String acaoValue;
    private final String requestOrigin;
    private final boolean isHttps;

    public HeaderResult(String host, int port, String method, String pathAndQuery,
                        int statusCode, boolean hstsPresent, boolean cacheControlPresent,
                        boolean xfoPresent, boolean xctoPresent,
                        boolean acaoPresent, boolean cspPresent) {
        this(host, port, method, pathAndQuery, statusCode, hstsPresent, cacheControlPresent,
                xfoPresent, false, xctoPresent, acaoPresent, cspPresent, null, null, null, null, false);
    }

    public HeaderResult(String host, int port, String method, String pathAndQuery,
                        int statusCode, boolean hstsPresent, boolean cacheControlPresent,
                        boolean xfoPresent, boolean xfoCoveredByCsp, boolean xctoPresent,
                        boolean acaoPresent, boolean cspPresent,
                        String rawRequest, String rawResponse) {
        this(host, port, method, pathAndQuery, statusCode, hstsPresent, cacheControlPresent,
                xfoPresent, xfoCoveredByCsp, xctoPresent, acaoPresent, cspPresent,
                rawRequest, rawResponse, null, null, false);
    }

    public HeaderResult(String host, int port, String method, String pathAndQuery,
                        int statusCode, boolean hstsPresent, boolean cacheControlPresent,
                        boolean xfoPresent, boolean xfoCoveredByCsp, boolean xctoPresent,
                        boolean acaoPresent, boolean cspPresent,
                        String rawRequest, String rawResponse,
                        String acaoValue, String requestOrigin) {
        this(host, port, method, pathAndQuery, statusCode, hstsPresent, cacheControlPresent,
                xfoPresent, xfoCoveredByCsp, xctoPresent, acaoPresent, cspPresent,
                rawRequest, rawResponse, acaoValue, requestOrigin, false);
    }

    public HeaderResult(String host, int port, String method, String pathAndQuery,
                        int statusCode, boolean hstsPresent, boolean cacheControlPresent,
                        boolean xfoPresent, boolean xfoCoveredByCsp, boolean xctoPresent,
                        boolean acaoPresent, boolean cspPresent,
                        String rawRequest, String rawResponse,
                        String acaoValue, String requestOrigin, boolean isHttps) {
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
        this.acaoValue = acaoValue;
        this.requestOrigin = requestOrigin;
        this.isHttps = isHttps;
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
    public String acaoValue() { return acaoValue; }
    public String requestOrigin() { return requestOrigin; }
    public boolean isHttps() { return isHttps; }

    public boolean acaoCheckFailed() {
        if (!acaoPresent || acaoValue == null) return false;
        String v = acaoValue.trim();
        if ("*".equals(v)) return true;
        if ("null".equalsIgnoreCase(v)) return true;
        if (requestOrigin != null && !requestOrigin.isEmpty()
                && v.equalsIgnoreCase(requestOrigin.trim())) {
            return !isSameOriginReflection(v);
        }
        return false;
    }

    private boolean isSameOriginReflection(String acaoVal) {
        if (host == null || host.isEmpty()) return false;
        try {
            java.net.URI uri = java.net.URI.create(acaoVal.trim());
            String acaoHost = uri.getHost();
            int acaoPort = uri.getPort();
            if (acaoHost == null) return false;
            if (!acaoHost.equalsIgnoreCase(host)) return false;
            if (acaoPort > 0 && acaoPort != port) return false;
            if (acaoPort <= 0) {
                int defaultPort = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
                if (defaultPort != port && port > 0) return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

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
