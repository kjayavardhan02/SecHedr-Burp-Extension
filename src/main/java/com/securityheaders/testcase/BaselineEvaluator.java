package com.securityheaders.testcase;

import java.util.*;
import java.util.stream.Collectors;

public class BaselineEvaluator {

    private final ApprovedBaseline baseline;

    public BaselineEvaluator(ApprovedBaseline baseline) {
        this.baseline = baseline;
    }

    public EvalResult evaluate(String headerNameLower, String headerValue, boolean isHttps) {
        ApprovedBaseline.BaselineRule rule = baseline.getRule(headerNameLower);
        if (rule == null) {
            return new EvalResult(ResultStatus.NOT_TESTED, "No baseline rule for " + headerNameLower, "", "");
        }

        if (headerValue == null || headerValue.isBlank()) {
            if (rule.httpsOnly() && !isHttps) {
                return new EvalResult(ResultStatus.PASS,
                        rule.headerName() + " not required on plain HTTP", rule.expectedValue(), "N/A (HTTP)");
            }
            return new EvalResult(ResultStatus.FAIL,
                    rule.headerName() + " is missing", rule.expectedValue(), "(absent)");
        }

        String normalized = headerValue.trim().toLowerCase(Locale.ROOT);
        Set<String> directives = parseDirectives(normalized);

        List<String> missingRequired = new ArrayList<>();
        for (String req : rule.requiredDirectives()) {
            if (!directivePresent(directives, normalized, req)) {
                missingRequired.add(req);
            }
        }

        List<String> foundProhibited = new ArrayList<>();
        for (String prohib : rule.prohibitedDirectives()) {
            if (directivePresent(directives, normalized, prohib)) {
                foundProhibited.add(prohib);
            }
        }

        if (!missingRequired.isEmpty()) {
            return new EvalResult(ResultStatus.FAIL,
                    "Missing required directives: " + String.join(", ", missingRequired),
                    rule.expectedValue(), headerValue);
        }
        if (!foundProhibited.isEmpty()) {
            return new EvalResult(ResultStatus.FAIL,
                    "Prohibited directives found: " + String.join(", ", foundProhibited),
                    rule.expectedValue(), headerValue);
        }

        return new EvalResult(ResultStatus.PASS,
                rule.headerName() + " meets baseline", rule.expectedValue(), headerValue);
    }

    private Set<String> parseDirectives(String value) {
        return Arrays.stream(value.split("[;,]"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
    }

    private boolean directivePresent(Set<String> directives, String fullValue, String target) {
        if (directives.contains(target)) return true;
        return fullValue.contains(target);
    }

    public record EvalResult(ResultStatus status, String summary, String expected, String actual) {}
}
