package com.securityheaders.policy;

public enum PolicyComplianceStatus {
    PASS, FAIL, NA, NOT_EVALUATED;

    public String displayLabel() {
        return switch (this) {
            case PASS -> "PASS";
            case FAIL -> "FAIL";
            case NA -> "N/A";
            case NOT_EVALUATED -> "NOT EVALUATED";
        };
    }
}
