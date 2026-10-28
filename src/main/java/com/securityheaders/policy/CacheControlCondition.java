package com.securityheaders.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class CacheControlCondition {

    private final String label;
    private final List<String> contentTypePatterns;
    private final List<String> requiredDirectives;
    private final List<String> prohibitedDirectives;

    public CacheControlCondition(String label, List<String> contentTypePatterns,
                                  List<String> requiredDirectives, List<String> prohibitedDirectives) {
        this.label = label != null ? label : "";
        this.contentTypePatterns = contentTypePatterns != null ? new ArrayList<>(contentTypePatterns) : new ArrayList<>();
        this.requiredDirectives = requiredDirectives != null ? new ArrayList<>(requiredDirectives) : new ArrayList<>();
        this.prohibitedDirectives = prohibitedDirectives != null ? new ArrayList<>(prohibitedDirectives) : new ArrayList<>();
    }

    public String label() { return label; }
    public List<String> contentTypePatterns() { return contentTypePatterns; }
    public List<String> requiredDirectives() { return requiredDirectives; }
    public List<String> prohibitedDirectives() { return prohibitedDirectives; }

    public boolean matchesContentType(String contentType) {
        if (contentTypePatterns.isEmpty()) return true;
        if (contentType == null || contentType.isBlank()) return false;
        String ct = contentType.toLowerCase(Locale.ROOT).trim();
        int semi = ct.indexOf(';');
        if (semi > 0) ct = ct.substring(0, semi).trim();

        for (String pattern : contentTypePatterns) {
            String p = pattern.toLowerCase(Locale.ROOT).trim();
            if (p.endsWith("/*")) {
                String prefix = p.substring(0, p.length() - 1);
                if (ct.startsWith(prefix)) return true;
            } else if (p.equals(ct)) {
                return true;
            }
        }
        return false;
    }

    public CacheControlCondition copy() {
        return new CacheControlCondition(label,
                new ArrayList<>(contentTypePatterns),
                new ArrayList<>(requiredDirectives),
                new ArrayList<>(prohibitedDirectives));
    }

    public List<String> validate() {
        List<String> errors = new ArrayList<>();
        if (requiredDirectives.isEmpty() && prohibitedDirectives.isEmpty()) {
            errors.add("Cache-Control [" + (label.isEmpty() ? "default" : label)
                    + "]: at least one required or prohibited directive needed");
        }
        return errors;
    }
}
