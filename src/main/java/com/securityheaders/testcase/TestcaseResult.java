package com.securityheaders.testcase;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public final class TestcaseResult {

    private static final AtomicLong ID_GEN = new AtomicLong(0);

    private final long resultId;
    private final String testcaseId;
    private final String endpointKey;
    private final Instant observedAt;
    private final Instant completedAt;
    private final ExecutionMode mode;
    private final ResultStatus status;
    private final String summary;
    private final String expected;
    private final String actual;
    private final String evidence;
    private final String errorDetails;
    private final String host;
    private final String pathAndQuery;
    private final int statusCode;
    private final String requestData;
    private final String responseData;

    public TestcaseResult(String testcaseId, String endpointKey, Instant observedAt,
                          ExecutionMode mode, ResultStatus status,
                          String summary, String expected, String actual,
                          String evidence, String errorDetails,
                          String host, String pathAndQuery, int statusCode) {
        this(testcaseId, endpointKey, observedAt, mode, status, summary, expected,
             actual, evidence, errorDetails, host, pathAndQuery, statusCode, null, null);
    }

    public TestcaseResult(String testcaseId, String endpointKey, Instant observedAt,
                          ExecutionMode mode, ResultStatus status,
                          String summary, String expected, String actual,
                          String evidence, String errorDetails,
                          String host, String pathAndQuery, int statusCode,
                          String requestData, String responseData) {
        this.resultId = ID_GEN.incrementAndGet();
        this.testcaseId = testcaseId;
        this.endpointKey = endpointKey;
        this.observedAt = observedAt;
        this.completedAt = Instant.now();
        this.mode = mode;
        this.status = status;
        this.summary = summary;
        this.expected = expected;
        this.actual = actual;
        this.evidence = evidence;
        this.errorDetails = errorDetails;
        this.host = host;
        this.pathAndQuery = pathAndQuery;
        this.statusCode = statusCode;
        this.requestData = requestData;
        this.responseData = responseData;
    }

    public long resultId() { return resultId; }
    public String testcaseId() { return testcaseId; }
    public String endpointKey() { return endpointKey; }
    public Instant observedAt() { return observedAt; }
    public Instant completedAt() { return completedAt; }
    public ExecutionMode mode() { return mode; }
    public ResultStatus status() { return status; }
    public String summary() { return summary; }
    public String expected() { return expected; }
    public String actual() { return actual; }
    public String evidence() { return evidence; }
    public String errorDetails() { return errorDetails; }
    public String host() { return host; }
    public String pathAndQuery() { return pathAndQuery; }
    public int statusCode() { return statusCode; }
    public String requestData() { return requestData; }
    public String responseData() { return responseData; }
}
