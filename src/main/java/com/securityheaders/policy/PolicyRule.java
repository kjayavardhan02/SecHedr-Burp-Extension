package com.securityheaders.policy;

import java.util.ArrayList;
import java.util.List;

public final class PolicyRule {

    public enum Mode { DIRECTIVES, ALLOWLIST, EXACT }

    private final String headerName;
    private boolean enabled;
    private Mode mode;

    // HSTS directives
    private long minMaxAge = -1;
    private boolean requireIncludeSubDomains;
    private boolean requirePreload;

    // Cache-Control directives (legacy flat fields used as default/fallback)
    private final List<String> requiredDirectives = new ArrayList<>();
    private final List<String> prohibitedDirectives = new ArrayList<>();

    // Cache-Control content-type conditions
    private final List<CacheControlCondition> cacheControlConditions = new ArrayList<>();

    // XFO allowlist / XCTO exact shared
    private final List<String> allowedValues = new ArrayList<>();
    private String expectedValue;

    // ACAO
    private final List<String> allowedOrigins = new ArrayList<>();
    private boolean allowWildcard;
    private boolean allowNull;

    // CSP
    private final List<String> cspRequiredDirectives = new ArrayList<>();
    private final List<String> cspProhibitedSources = new ArrayList<>();

    // CSP content-type conditions
    private final List<CacheControlCondition> cspConditions = new ArrayList<>();

    private PolicyRule(String headerName, boolean enabled, Mode mode) {
        this.headerName = headerName;
        this.enabled = enabled;
        this.mode = mode;
    }

    public static PolicyRule hsts(boolean enabled, long minMaxAge,
                                  boolean requireIncludeSubDomains, boolean requirePreload) {
        PolicyRule r = new PolicyRule("strict-transport-security", enabled, Mode.DIRECTIVES);
        r.minMaxAge = minMaxAge;
        r.requireIncludeSubDomains = requireIncludeSubDomains;
        r.requirePreload = requirePreload;
        return r;
    }

    public static PolicyRule cacheControl(boolean enabled, List<String> required, List<String> prohibited) {
        PolicyRule r = new PolicyRule("cache-control", enabled, Mode.DIRECTIVES);
        if (required != null) r.requiredDirectives.addAll(required);
        if (prohibited != null) r.prohibitedDirectives.addAll(prohibited);
        return r;
    }

    public static PolicyRule cacheControl(boolean enabled, List<CacheControlCondition> conditions) {
        PolicyRule r = new PolicyRule("cache-control", enabled, Mode.DIRECTIVES);
        if (conditions != null) r.cacheControlConditions.addAll(conditions);
        return r;
    }

    public static PolicyRule xFrameOptions(boolean enabled, List<String> allowed) {
        PolicyRule r = new PolicyRule("x-frame-options", enabled, Mode.ALLOWLIST);
        if (allowed != null) r.allowedValues.addAll(allowed);
        return r;
    }

    public static PolicyRule xContentTypeOptions(boolean enabled, String expected) {
        PolicyRule r = new PolicyRule("x-content-type-options", enabled, Mode.EXACT);
        r.expectedValue = expected;
        return r;
    }

    public static PolicyRule acao(boolean enabled, List<String> origins,
                                  boolean allowWildcard, boolean allowNull) {
        PolicyRule r = new PolicyRule("access-control-allow-origin", enabled, Mode.ALLOWLIST);
        if (origins != null) r.allowedOrigins.addAll(origins);
        r.allowWildcard = allowWildcard;
        r.allowNull = allowNull;
        return r;
    }

    public static PolicyRule csp(boolean enabled, List<String> requiredDirectives,
                                 List<String> prohibitedSources) {
        PolicyRule r = new PolicyRule("content-security-policy", enabled, Mode.DIRECTIVES);
        if (requiredDirectives != null) r.cspRequiredDirectives.addAll(requiredDirectives);
        if (prohibitedSources != null) r.cspProhibitedSources.addAll(prohibitedSources);
        return r;
    }

    public static PolicyRule cspWithConditions(boolean enabled, List<CacheControlCondition> conditions) {
        PolicyRule r = new PolicyRule("content-security-policy", enabled, Mode.DIRECTIVES);
        if (conditions != null) r.cspConditions.addAll(conditions);
        return r;
    }

    public String headerName() { return headerName; }
    public boolean enabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Mode mode() { return mode; }

    public long minMaxAge() { return minMaxAge; }
    public boolean requireIncludeSubDomains() { return requireIncludeSubDomains; }
    public boolean requirePreload() { return requirePreload; }

    public List<String> requiredDirectives() { return requiredDirectives; }
    public List<String> prohibitedDirectives() { return prohibitedDirectives; }

    public List<CacheControlCondition> cacheControlConditions() { return cacheControlConditions; }

    public boolean hasConditions() {
        return !cacheControlConditions.isEmpty();
    }

    public CacheControlCondition findMatchingCondition(String contentType) {
        for (CacheControlCondition c : cacheControlConditions) {
            if (c.matchesContentType(contentType)) return c;
        }
        return null;
    }

    public List<String> allowedValues() { return allowedValues; }
    public String expectedValue() { return expectedValue; }

    public List<String> allowedOrigins() { return allowedOrigins; }
    public boolean allowWildcard() { return allowWildcard; }
    public boolean allowNull() { return allowNull; }

    public List<String> cspRequiredDirectives() { return cspRequiredDirectives; }
    public List<String> cspProhibitedSources() { return cspProhibitedSources; }

    public List<CacheControlCondition> cspConditions() { return cspConditions; }

    public boolean hasCspConditions() {
        return !cspConditions.isEmpty();
    }

    public CacheControlCondition findMatchingCspCondition(String contentType) {
        for (CacheControlCondition c : cspConditions) {
            if (c.matchesContentType(contentType)) return c;
        }
        return null;
    }

    public PolicyRule copy() {
        return switch (headerName) {
            case "strict-transport-security" -> hsts(enabled, minMaxAge, requireIncludeSubDomains, requirePreload);
            case "cache-control" -> {
                if (hasConditions()) {
                    List<CacheControlCondition> copied = new ArrayList<>();
                    for (CacheControlCondition c : cacheControlConditions) copied.add(c.copy());
                    yield cacheControl(enabled, copied);
                } else {
                    yield cacheControl(enabled, requiredDirectives, prohibitedDirectives);
                }
            }
            case "x-frame-options" -> xFrameOptions(enabled, allowedValues);
            case "x-content-type-options" -> xContentTypeOptions(enabled, expectedValue);
            case "access-control-allow-origin" -> acao(enabled, allowedOrigins, allowWildcard, allowNull);
            case "content-security-policy" -> {
                if (hasCspConditions()) {
                    List<CacheControlCondition> copied = new ArrayList<>();
                    for (CacheControlCondition c : cspConditions) copied.add(c.copy());
                    yield cspWithConditions(enabled, copied);
                } else {
                    yield csp(enabled, cspRequiredDirectives, cspProhibitedSources);
                }
            }
            default -> new PolicyRule(headerName, enabled, mode);
        };
    }

    public List<String> validate() {
        List<String> errors = new ArrayList<>();
        if (!enabled) return errors;
        switch (headerName) {
            case "strict-transport-security" -> {
                if (minMaxAge < 0) errors.add("HSTS: min max-age must be non-negative");
            }
            case "cache-control" -> {
                if (hasConditions()) {
                    for (CacheControlCondition c : cacheControlConditions) {
                        errors.addAll(c.validate());
                    }
                } else {
                    if (requiredDirectives.isEmpty() && prohibitedDirectives.isEmpty())
                        errors.add("Cache-Control: at least one required or prohibited directive needed");
                }
            }
            case "x-frame-options" -> {
                if (allowedValues.isEmpty()) errors.add("X-Frame-Options: at least one allowed value needed");
            }
            case "x-content-type-options" -> {
                if (expectedValue == null || expectedValue.isBlank())
                    errors.add("X-Content-Type-Options: expected value required");
            }
            case "access-control-allow-origin" -> {
                if (allowedOrigins.isEmpty() && !allowWildcard && !allowNull)
                    errors.add("ACAO: at least one allowed origin, wildcard, or null must be configured");
                for (String o : allowedOrigins) {
                    if (o == null || o.isBlank()) errors.add("ACAO: empty origin in allowlist");
                }
            }
            case "content-security-policy" -> {
                if (hasCspConditions()) {
                    for (CacheControlCondition c : cspConditions) {
                        List<String> cErrs = c.validate();
                        for (String e : cErrs) {
                            errors.add(e.replace("Cache-Control", "CSP"));
                        }
                    }
                } else {
                    if (cspRequiredDirectives.isEmpty() && cspProhibitedSources.isEmpty())
                        errors.add("CSP: at least one required directive or prohibited source needed");
                }
            }
        }
        return errors;
    }
}
