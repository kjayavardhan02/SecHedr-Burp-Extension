package com.securityheaders.policy;

import java.util.List;

public final class PolicyEvaluationResult {

    private final PolicyComplianceStatus overallStatus;
    private final String policyId;
    private final String policyName;
    private final List<PolicyRuleResult> ruleResults;

    public PolicyEvaluationResult(PolicyComplianceStatus overallStatus, String policyId,
                                  String policyName, List<PolicyRuleResult> ruleResults) {
        this.overallStatus = overallStatus;
        this.policyId = policyId;
        this.policyName = policyName;
        this.ruleResults = List.copyOf(ruleResults);
    }

    public PolicyComplianceStatus overallStatus() { return overallStatus; }
    public String policyId() { return policyId; }
    public String policyName() { return policyName; }
    public List<PolicyRuleResult> ruleResults() { return ruleResults; }

    public static PolicyEvaluationResult notEvaluated() {
        return new PolicyEvaluationResult(PolicyComplianceStatus.NOT_EVALUATED, null, null, List.of());
    }
}
