package com.securityheaders.policy;

import com.securityheaders.HeaderResult;

import java.net.URI;
import java.util.*;

public class PolicyEvaluator {

    public PolicyEvaluationResult evaluate(HeaderResult response, PolicyProfile policy) {
        if (policy == null) return PolicyEvaluationResult.notEvaluated();

        List<PolicyRuleResult> ruleResults = new ArrayList<>();

        for (PolicyRule rule : policy.rules().values()) {
            if (!rule.enabled()) continue;
            PolicyRuleResult rr = evaluateRule(rule, response);
            if (rr != null) ruleResults.add(rr);
        }

        PolicyComplianceStatus overall = aggregate(ruleResults);
        return new PolicyEvaluationResult(overall, policy.id(), policy.name(), ruleResults);
    }

    private PolicyComplianceStatus aggregate(List<PolicyRuleResult> results) {
        if (results.isEmpty()) return PolicyComplianceStatus.NA;

        boolean anyFail = false;
        boolean anyPass = false;
        boolean allNa = true;
        boolean anyNotEvaluated = false;

        for (PolicyRuleResult r : results) {
            switch (r.status()) {
                case FAIL -> { anyFail = true; allNa = false; }
                case PASS -> { anyPass = true; allNa = false; }
                case NOT_EVALUATED -> { anyNotEvaluated = true; allNa = false; }
                case NA -> {}
            }
        }

        if (allNa) return PolicyComplianceStatus.NA;
        if (anyFail) return PolicyComplianceStatus.FAIL;
        if (anyNotEvaluated && !anyPass) return PolicyComplianceStatus.NOT_EVALUATED;
        if (anyNotEvaluated) return PolicyComplianceStatus.FAIL;
        return PolicyComplianceStatus.PASS;
    }

    private PolicyRuleResult evaluateRule(PolicyRule rule, HeaderResult response) {
        return switch (rule.headerName()) {
            case "strict-transport-security" -> evaluateHsts(rule, response);
            case "cache-control" -> evaluateCacheControl(rule, response);
            case "x-frame-options" -> evaluateXfo(rule, response);
            case "x-content-type-options" -> evaluateXcto(rule, response);
            case "access-control-allow-origin" -> evaluateAcao(rule, response);
            case "content-security-policy" -> evaluateCsp(rule, response);
            default -> null;
        };
    }

    // ── HSTS ──

    private PolicyRuleResult evaluateHsts(PolicyRule rule, HeaderResult response) {
        if (!response.isHttps()) {
            return new PolicyRuleResult("Strict-Transport-Security", PolicyComplianceStatus.NA,
                    "HSTS not applicable to HTTP responses", null, null);
        }

        if (!response.hstsPresent()) {
            String rawResp = response.rawResponse();
            String val = extractHeaderValue(rawResp, "strict-transport-security");
            if (val == null) {
                return new PolicyRuleResult("Strict-Transport-Security", PolicyComplianceStatus.FAIL,
                        "Header is absent", "(absent)",
                        "Required with min max-age=" + rule.minMaxAge());
            }
            return evaluateHstsValue(rule, val);
        }

        String rawResp = response.rawResponse();
        String val = extractHeaderValue(rawResp, "strict-transport-security");
        if (val == null) {
            return new PolicyRuleResult("Strict-Transport-Security", PolicyComplianceStatus.PASS,
                    "Header present (value not available for detailed check)", null, null);
        }
        return evaluateHstsValue(rule, val);
    }

    private PolicyRuleResult evaluateHstsValue(PolicyRule rule, String value) {
        Map<String, String> directives = parseDirectives(value);
        List<String> failures = new ArrayList<>();

        String maxAgeStr = directives.get("max-age");
        if (maxAgeStr == null) {
            failures.add("max-age directive is missing");
        } else {
            try {
                long maxAge = Long.parseLong(maxAgeStr);
                if (maxAge < 0) {
                    failures.add("max-age is negative: " + maxAge);
                } else if (rule.minMaxAge() >= 0 && maxAge < rule.minMaxAge()) {
                    failures.add("max-age=" + maxAge + " is below minimum " + rule.minMaxAge());
                }
            } catch (NumberFormatException e) {
                failures.add("max-age is malformed: " + maxAgeStr);
            }
        }

        if (rule.requireIncludeSubDomains() && !directives.containsKey("includesubdomains")) {
            failures.add("includeSubDomains directive is required but absent");
        }
        if (rule.requirePreload() && !directives.containsKey("preload")) {
            failures.add("preload directive is required but absent");
        }

        if (failures.isEmpty()) {
            return new PolicyRuleResult("Strict-Transport-Security", PolicyComplianceStatus.PASS,
                    "Compliant", value, null);
        }
        return new PolicyRuleResult("Strict-Transport-Security", PolicyComplianceStatus.FAIL,
                String.join("; ", failures), value,
                "min max-age=" + rule.minMaxAge()
                        + (rule.requireIncludeSubDomains() ? "; includeSubDomains required" : "")
                        + (rule.requirePreload() ? "; preload required" : ""));
    }

    // ── Cache-Control ──

    private PolicyRuleResult evaluateCacheControl(PolicyRule rule, HeaderResult response) {
        String rawResp = response.rawResponse();
        String contentType = extractHeaderValue(rawResp, "content-type");
        String val = extractHeaderValue(rawResp, "cache-control");

        if (rule.hasConditions()) {
            CacheControlCondition condition = rule.findMatchingCondition(contentType);
            if (condition == null) {
                return new PolicyRuleResult("Cache-Control", PolicyComplianceStatus.NA,
                        "No matching condition for content-type",
                        contentType != null ? contentType : "(unknown)",
                        null);
            }
            if (val == null && !response.cacheControlPresent()) {
                return new PolicyRuleResult("Cache-Control", PolicyComplianceStatus.FAIL,
                        "Header is absent", "(absent)",
                        "[" + condition.label() + "] Required: "
                                + String.join(", ", condition.requiredDirectives()));
            }
            if (val == null) {
                return new PolicyRuleResult("Cache-Control", PolicyComplianceStatus.PASS,
                        "Header present (value not available for detailed check)", null, null);
            }
            return evaluateCacheControlCondition(condition, val, contentType);
        }

        if (!response.cacheControlPresent()) {
            if (val == null) {
                return new PolicyRuleResult("Cache-Control", PolicyComplianceStatus.FAIL,
                        "Header is absent", "(absent)",
                        "Required: " + String.join(", ", rule.requiredDirectives()));
            }
            return evaluateCacheControlFlat(rule.requiredDirectives(), rule.prohibitedDirectives(), val, null);
        }

        if (val == null) {
            return new PolicyRuleResult("Cache-Control", PolicyComplianceStatus.PASS,
                    "Header present (value not available for detailed check)", null, null);
        }
        return evaluateCacheControlFlat(rule.requiredDirectives(), rule.prohibitedDirectives(), val, null);
    }

    private PolicyRuleResult evaluateCacheControlCondition(CacheControlCondition condition,
                                                            String value, String contentType) {
        String ctLabel = condition.label().isEmpty() ? "default" : condition.label();
        return evaluateCacheControlFlat(condition.requiredDirectives(),
                condition.prohibitedDirectives(), value, ctLabel);
    }

    private PolicyRuleResult evaluateCacheControlFlat(List<String> required, List<String> prohibited,
                                                       String value, String conditionLabel) {
        Set<String> directives = parseCacheControlDirectives(value);
        List<String> failures = new ArrayList<>();

        for (String req : required) {
            if (!directives.contains(req.toLowerCase(Locale.ROOT).trim())) {
                failures.add("required directive missing: " + req);
            }
        }
        for (String p : prohibited) {
            if (directives.contains(p.toLowerCase(Locale.ROOT).trim())) {
                failures.add("prohibited directive present: " + p);
            }
        }

        String expectedDesc = (conditionLabel != null ? "[" + conditionLabel + "] " : "")
                + "Required: " + String.join(", ", required);

        if (failures.isEmpty()) {
            return new PolicyRuleResult("Cache-Control", PolicyComplianceStatus.PASS,
                    "Compliant", value, expectedDesc);
        }
        return new PolicyRuleResult("Cache-Control", PolicyComplianceStatus.FAIL,
                String.join("; ", failures), value, expectedDesc);
    }

    // ── X-Frame-Options ──

    private PolicyRuleResult evaluateXfo(PolicyRule rule, HeaderResult response) {
        String rawResp = response.rawResponse();
        String val = extractHeaderValue(rawResp, "x-frame-options");

        if (val == null && !response.xfoPresent() && !response.xfoCoveredByCsp()) {
            return new PolicyRuleResult("X-Frame-Options", PolicyComplianceStatus.FAIL,
                    "Header is absent", "(absent)",
                    "Allowed values: " + String.join(", ", rule.allowedValues()));
        }
        if (val == null && response.xfoCoveredByCsp()) {
            return new PolicyRuleResult("X-Frame-Options", PolicyComplianceStatus.PASS,
                    "Covered by CSP frame-ancestors", "(covered by CSP)", null);
        }
        if (val == null) {
            return new PolicyRuleResult("X-Frame-Options", PolicyComplianceStatus.PASS,
                    "Header present (value not available for detailed check)", null, null);
        }

        String normalized = val.trim().toUpperCase(Locale.ROOT);
        for (String allowed : rule.allowedValues()) {
            if (allowed.trim().toUpperCase(Locale.ROOT).equals(normalized)) {
                return new PolicyRuleResult("X-Frame-Options", PolicyComplianceStatus.PASS,
                        "Compliant", val, null);
            }
        }
        return new PolicyRuleResult("X-Frame-Options", PolicyComplianceStatus.FAIL,
                "Value '" + val + "' is not in the allowed set",
                val, "Allowed: " + String.join(", ", rule.allowedValues()));
    }

    // ── X-Content-Type-Options ──

    private PolicyRuleResult evaluateXcto(PolicyRule rule, HeaderResult response) {
        String rawResp = response.rawResponse();
        String val = extractHeaderValue(rawResp, "x-content-type-options");

        if (val == null && !response.xctoPresent()) {
            return new PolicyRuleResult("X-Content-Type-Options", PolicyComplianceStatus.FAIL,
                    "Header is absent", "(absent)",
                    "Expected: " + rule.expectedValue());
        }
        if (val == null) {
            return new PolicyRuleResult("X-Content-Type-Options", PolicyComplianceStatus.PASS,
                    "Header present (value not available for detailed check)", null, null);
        }

        if (val.trim().equalsIgnoreCase(rule.expectedValue())) {
            return new PolicyRuleResult("X-Content-Type-Options", PolicyComplianceStatus.PASS,
                    "Compliant", val, null);
        }
        return new PolicyRuleResult("X-Content-Type-Options", PolicyComplianceStatus.FAIL,
                "Value '" + val + "' does not match expected '" + rule.expectedValue() + "'",
                val, "Expected: " + rule.expectedValue());
    }

    // ── ACAO ──

    private PolicyRuleResult evaluateAcao(PolicyRule rule, HeaderResult response) {
        String rawResp = response.rawResponse();
        String val = extractHeaderValue(rawResp, "access-control-allow-origin");

        if (val == null && !response.acaoPresent()) {
            if (rule.allowedOrigins().isEmpty() && !rule.allowWildcard()) {
                return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.NA,
                        "Header absent, no CORS response", "(absent)", null);
            }
            return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.FAIL,
                    "Header is absent", "(absent)",
                    "Allowed origins: " + describeAcaoPolicy(rule));
        }
        if (val == null) {
            return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.PASS,
                    "Header present (value not available for detailed check)", null, null);
        }

        String trimmed = val.trim();

        if ("*".equals(trimmed)) {
            if (rule.allowWildcard()) {
                return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.PASS,
                        "Wildcard allowed by policy", val, null);
            }
            return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.FAIL,
                    "Wildcard '*' is not allowed by policy", val,
                    "Allowed: " + describeAcaoPolicy(rule));
        }

        if ("null".equalsIgnoreCase(trimmed)) {
            if (rule.allowNull()) {
                return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.PASS,
                        "'null' origin allowed by policy", val, null);
            }
            return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.FAIL,
                    "'null' origin is not allowed by policy", val,
                    "Allowed: " + describeAcaoPolicy(rule));
        }

        for (String allowed : rule.allowedOrigins()) {
            if (originsMatch(trimmed, allowed)) {
                return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.PASS,
                        "Origin matches allowed origin", val, null);
            }
        }

        return new PolicyRuleResult("Access-Control-Allow-Origin", PolicyComplianceStatus.FAIL,
                "Origin '" + trimmed + "' is not in the allowed set", val,
                "Allowed: " + describeAcaoPolicy(rule));
    }

    private boolean originsMatch(String actual, String allowed) {
        try {
            URI actualUri = URI.create(actual.trim().toLowerCase(Locale.ROOT));
            URI allowedUri = URI.create(allowed.trim().toLowerCase(Locale.ROOT));

            if (!Objects.equals(actualUri.getScheme(), allowedUri.getScheme())) return false;
            if (!Objects.equals(actualUri.getHost(), allowedUri.getHost())) return false;

            int actualPort = effectivePort(actualUri);
            int allowedPort = effectivePort(allowedUri);
            return actualPort == allowedPort;
        } catch (Exception e) {
            return actual.trim().equalsIgnoreCase(allowed.trim());
        }
    }

    private int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port > 0) return port;
        return "https".equals(uri.getScheme()) ? 443 : 80;
    }

    private String describeAcaoPolicy(PolicyRule rule) {
        List<String> parts = new ArrayList<>(rule.allowedOrigins());
        if (rule.allowWildcard()) parts.add("*");
        if (rule.allowNull()) parts.add("null");
        return parts.isEmpty() ? "(none configured)" : String.join(", ", parts);
    }

    // ── CSP ──

    private PolicyRuleResult evaluateCsp(PolicyRule rule, HeaderResult response) {
        String rawResp = response.rawResponse();
        String contentType = extractHeaderValue(rawResp, "content-type");
        String val = extractHeaderValue(rawResp, "content-security-policy");

        if (rule.hasCspConditions()) {
            CacheControlCondition condition = rule.findMatchingCspCondition(contentType);
            if (condition == null) {
                return new PolicyRuleResult("Content-Security-Policy", PolicyComplianceStatus.NA,
                        "No matching condition for content-type",
                        contentType != null ? contentType : "(unknown)", null);
            }
            if (val == null && !response.cspPresent()) {
                return new PolicyRuleResult("Content-Security-Policy", PolicyComplianceStatus.FAIL,
                        "Header is absent", "(absent)",
                        "[" + condition.label() + "] Required: "
                                + String.join(", ", condition.requiredDirectives()));
            }
            if (val == null) {
                return new PolicyRuleResult("Content-Security-Policy", PolicyComplianceStatus.PASS,
                        "Header present (value not available for detailed check)", null, null);
            }
            return evaluateCspFlat(condition.requiredDirectives(),
                    condition.prohibitedDirectives(), val, condition.label());
        }

        if (val == null && !response.cspPresent()) {
            return new PolicyRuleResult("Content-Security-Policy", PolicyComplianceStatus.FAIL,
                    "Header is absent", "(absent)",
                    "Required directives: " + String.join(", ", rule.cspRequiredDirectives()));
        }
        if (val == null) {
            return new PolicyRuleResult("Content-Security-Policy", PolicyComplianceStatus.PASS,
                    "Header present (value not available for detailed check)", null, null);
        }
        return evaluateCspFlat(rule.cspRequiredDirectives(), rule.cspProhibitedSources(), val, null);
    }

    private PolicyRuleResult evaluateCspFlat(List<String> required, List<String> prohibited,
                                              String value, String conditionLabel) {
        Map<String, List<String>> directives = parseCspDirectives(value);
        List<String> failures = new ArrayList<>();

        for (String req : required) {
            if (!directives.containsKey(req.toLowerCase(Locale.ROOT).trim())) {
                failures.add("required directive missing: " + req);
            }
        }

        for (String p : prohibited) {
            String pLower = p.toLowerCase(Locale.ROOT).trim();
            for (Map.Entry<String, List<String>> entry : directives.entrySet()) {
                for (String source : entry.getValue()) {
                    if (source.equalsIgnoreCase(pLower)
                            || source.equalsIgnoreCase("'" + pLower + "'")) {
                        failures.add("prohibited source '" + p + "' found in " + entry.getKey());
                        break;
                    }
                }
            }
        }

        String expected = (conditionLabel != null ? "[" + conditionLabel + "] " : "")
                + "Required: " + String.join(", ", required);
        if (!prohibited.isEmpty()) {
            expected += "; Prohibited: " + String.join(", ", prohibited);
        }

        if (failures.isEmpty()) {
            return new PolicyRuleResult("Content-Security-Policy", PolicyComplianceStatus.PASS,
                    "Compliant", value, expected);
        }
        return new PolicyRuleResult("Content-Security-Policy", PolicyComplianceStatus.FAIL,
                String.join("; ", failures), value, expected);
    }

    Map<String, List<String>> parseCspDirectives(String headerValue) {
        Map<String, List<String>> directives = new LinkedHashMap<>();
        if (headerValue == null) return directives;
        for (String part : headerValue.split(";")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;
            String[] tokens = trimmed.split("\\s+");
            String directiveName = tokens[0].toLowerCase(Locale.ROOT);
            List<String> sources = new ArrayList<>();
            for (int i = 1; i < tokens.length; i++) {
                sources.add(tokens[i]);
            }
            directives.put(directiveName, sources);
        }
        return directives;
    }

    // ── Header parsing utilities ──

    String extractHeaderValue(String rawResponse, String headerName) {
        if (rawResponse == null || rawResponse.isEmpty()) return null;
        String lower = rawResponse.toLowerCase(Locale.ROOT);
        String needle = "\n" + headerName.toLowerCase(Locale.ROOT) + ":";
        int idx = lower.indexOf(needle);
        if (idx < 0) return null;

        int valueStart = idx + needle.length();
        int lineEnd = rawResponse.indexOf('\n', valueStart);
        if (lineEnd < 0) lineEnd = rawResponse.length();
        String value = rawResponse.substring(valueStart, lineEnd).trim();
        if (value.endsWith("\r")) value = value.substring(0, value.length() - 1).trim();
        return value;
    }

    Map<String, String> parseDirectives(String headerValue) {
        Map<String, String> directives = new LinkedHashMap<>();
        if (headerValue == null) return directives;
        for (String part : headerValue.split(";")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                directives.put(trimmed.substring(0, eq).trim().toLowerCase(Locale.ROOT),
                        trimmed.substring(eq + 1).trim());
            } else {
                directives.put(trimmed.toLowerCase(Locale.ROOT), "");
            }
        }
        return directives;
    }

    Set<String> parseCacheControlDirectives(String headerValue) {
        Set<String> directives = new LinkedHashSet<>();
        if (headerValue == null) return directives;
        for (String part : headerValue.split(",")) {
            String trimmed = part.trim().toLowerCase(Locale.ROOT);
            if (trimmed.isEmpty()) continue;
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                directives.add(trimmed.substring(0, eq).trim());
            } else {
                directives.add(trimmed);
            }
        }
        return directives;
    }
}
