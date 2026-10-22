package com.securityheaders;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class ScopeManager {

    private volatile List<String> allowlist = Collections.emptyList();
    private volatile List<String> blocklist = Collections.emptyList();

    public void updateAllowlist(String text) {
        allowlist = parseEntries(text);
    }

    public void updateBlocklist(String text) {
        blocklist = parseEntries(text);
    }

    public boolean isInScope(String hostname) {
        if (hostname == null || hostname.isBlank()) {
            return false;
        }
        String host = hostname.toLowerCase(Locale.ROOT).trim();

        if (matchesAny(host, blocklist)) {
            return false;
        }

        if (allowlist.isEmpty()) {
            return true;
        }

        return matchesAny(host, allowlist);
    }

    private boolean matchesAny(String host, List<String> patterns) {
        for (String pattern : patterns) {
            if (matchesPattern(host, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Wildcard matching:
     * - "example.com" matches exactly "example.com"
     * - "*.example.com" matches subdomains like "api.example.com", "sub.api.example.com"
     *   but does NOT match the apex "example.com" itself
     */
    private boolean matchesPattern(String host, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            return host.endsWith(suffix) && host.length() > suffix.length();
        }
        return host.equals(pattern);
    }

    private List<String> parseEntries(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }
        List<String> entries = new ArrayList<>();
        for (String line : text.split("\\R")) {
            String trimmed = line.trim().toLowerCase(Locale.ROOT);
            if (!trimmed.isEmpty()) {
                entries.add(trimmed);
            }
        }
        return Collections.unmodifiableList(entries);
    }
}
