package com.securityheaders;

import java.util.List;
import java.util.Set;

public final class EndpointSummary {

    private final String host;
    private final int port;
    private final String method;
    private final String pathAndQuery;
    private final int responses;
    private final List<Integer> statusCodes;
    private final int responsesWithMissing;
    private final int hstsMissing;
    private final int cacheControlMissing;
    private final int xfoMissing;
    private final int xctoMissing;
    private final int acaoMissing;
    private final int cspMissing;
    private final Set<String> headersEverMissing;

    public EndpointSummary(String host, int port, String method, String pathAndQuery,
                           int responses, List<Integer> statusCodes,
                           int responsesWithMissing, int hstsMissing,
                           int cacheControlMissing, int xfoMissing,
                           int xctoMissing, int acaoMissing, int cspMissing,
                           Set<String> headersEverMissing) {
        this.host = host;
        this.port = port;
        this.method = method;
        this.pathAndQuery = pathAndQuery;
        this.responses = responses;
        this.statusCodes = statusCodes;
        this.responsesWithMissing = responsesWithMissing;
        this.hstsMissing = hstsMissing;
        this.cacheControlMissing = cacheControlMissing;
        this.xfoMissing = xfoMissing;
        this.xctoMissing = xctoMissing;
        this.acaoMissing = acaoMissing;
        this.cspMissing = cspMissing;
        this.headersEverMissing = headersEverMissing;
    }

    public String host() { return host; }
    public int port() { return port; }
    public String method() { return method; }
    public String pathAndQuery() { return pathAndQuery; }
    public int responses() { return responses; }
    public List<Integer> statusCodes() { return statusCodes; }
    public int responsesWithMissing() { return responsesWithMissing; }
    public int hstsMissing() { return hstsMissing; }
    public int cacheControlMissing() { return cacheControlMissing; }
    public int xfoMissing() { return xfoMissing; }
    public int xctoMissing() { return xctoMissing; }
    public int acaoMissing() { return acaoMissing; }
    public int cspMissing() { return cspMissing; }
    public Set<String> headersEverMissing() { return headersEverMissing; }
}
