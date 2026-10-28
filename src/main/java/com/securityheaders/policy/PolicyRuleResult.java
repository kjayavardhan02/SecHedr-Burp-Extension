package com.securityheaders.policy;

public final class PolicyRuleResult {

    private final String headerName;
    private final PolicyComplianceStatus status;
    private final String reason;
    private final String actualValue;
    private final String expectedDescription;

    public PolicyRuleResult(String headerName, PolicyComplianceStatus status, String reason,
                            String actualValue, String expectedDescription) {
        this.headerName = headerName;
        this.status = status;
        this.reason = reason;
        this.actualValue = actualValue;
        this.expectedDescription = expectedDescription;
    }

    public String headerName() { return headerName; }
    public PolicyComplianceStatus status() { return status; }
    public String reason() { return reason; }
    public String actualValue() { return actualValue; }
    public String expectedDescription() { return expectedDescription; }
}
