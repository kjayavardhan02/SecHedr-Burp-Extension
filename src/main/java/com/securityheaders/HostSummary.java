package com.securityheaders;

public final class HostSummary {

    private final String host;
    private final int responses;
    private final int uniqueEndpoints;
    private final int responsesWithMissing;
    private final int hstsMissing;
    private final int cacheControlMissing;
    private final int xfoMissing;
    private final int xctoMissing;
    private final int acaoMissing;
    private final int cspMissing;

    public HostSummary(String host, int responses, int uniqueEndpoints,
                       int responsesWithMissing, int hstsMissing,
                       int cacheControlMissing, int xfoMissing,
                       int xctoMissing, int acaoMissing, int cspMissing) {
        this.host = host;
        this.responses = responses;
        this.uniqueEndpoints = uniqueEndpoints;
        this.responsesWithMissing = responsesWithMissing;
        this.hstsMissing = hstsMissing;
        this.cacheControlMissing = cacheControlMissing;
        this.xfoMissing = xfoMissing;
        this.xctoMissing = xctoMissing;
        this.acaoMissing = acaoMissing;
        this.cspMissing = cspMissing;
    }

    public String host() { return host; }
    public int responses() { return responses; }
    public int uniqueEndpoints() { return uniqueEndpoints; }
    public int responsesWithMissing() { return responsesWithMissing; }
    public int hstsMissing() { return hstsMissing; }
    public int cacheControlMissing() { return cacheControlMissing; }
    public int xfoMissing() { return xfoMissing; }
    public int xctoMissing() { return xctoMissing; }
    public int acaoMissing() { return acaoMissing; }
    public int cspMissing() { return cspMissing; }
}
