package com.securityheaders.testcase;

import java.util.*;

public class ApprovedBaseline {

    private final Map<String, BaselineRule> rules = new LinkedHashMap<>();

    public ApprovedBaseline() {
        rules.put("strict-transport-security", new BaselineRule(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload",
                Set.of("max-age=31536000", "includesubdomains", "preload"),
                Set.of(),
                true
        ));
        rules.put("cache-control", new BaselineRule(
                "Cache-Control",
                "no-store, no-cache, must-revalidate",
                Set.of("no-store", "no-cache", "must-revalidate"),
                Set.of("public"),
                false
        ));
        rules.put("x-frame-options", new BaselineRule(
                "X-Frame-Options",
                "DENY",
                Set.of("deny"),
                Set.of(),
                false
        ));
        rules.put("x-content-type-options", new BaselineRule(
                "X-Content-Type-Options",
                "nosniff",
                Set.of("nosniff"),
                Set.of(),
                false
        ));
        rules.put("content-security-policy", new BaselineRule(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
                Set.of("default-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'"),
                Set.of("unsafe-inline", "unsafe-eval"),
                false
        ));
        rules.put("access-control-allow-origin", new BaselineRule(
                "Access-Control-Allow-Origin",
                "Exact trusted origin (no wildcard)",
                Set.of(),
                Set.of("*"),
                false
        ));
    }

    public BaselineRule getRule(String headerNameLower) {
        return rules.get(headerNameLower);
    }

    public Map<String, BaselineRule> allRules() {
        return Collections.unmodifiableMap(rules);
    }

    public void updateRule(String headerNameLower, BaselineRule rule) {
        rules.put(headerNameLower, rule);
    }

    public static final class BaselineRule {
        private final String headerName;
        private final String expectedValue;
        private final Set<String> requiredDirectives;
        private final Set<String> prohibitedDirectives;
        private final boolean httpsOnly;

        public BaselineRule(String headerName, String expectedValue,
                            Set<String> requiredDirectives, Set<String> prohibitedDirectives,
                            boolean httpsOnly) {
            this.headerName = headerName;
            this.expectedValue = expectedValue;
            this.requiredDirectives = Set.copyOf(requiredDirectives);
            this.prohibitedDirectives = Set.copyOf(prohibitedDirectives);
            this.httpsOnly = httpsOnly;
        }

        public String headerName() { return headerName; }
        public String expectedValue() { return expectedValue; }
        public Set<String> requiredDirectives() { return requiredDirectives; }
        public Set<String> prohibitedDirectives() { return prohibitedDirectives; }
        public boolean httpsOnly() { return httpsOnly; }
    }
}
