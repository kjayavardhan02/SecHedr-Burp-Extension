package com.securityheaders.testcase;

import java.util.*;
import java.util.stream.Collectors;

public class TestcaseLibrary {

    private final Map<String, TestcaseDefinition> testcases = new LinkedHashMap<>();

    private static final String BASELINE_EXPECTED =
            "HSTS: max-age=31536000; includeSubDomains; preload | "
            + "Cache-Control: no-store, no-cache, must-revalidate | "
            + "X-Frame-Options: DENY | X-Content-Type-Options: nosniff | "
            + "CSP: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'";

    public TestcaseLibrary() {
        loadBuiltIn();
    }

    public void addOrReplace(TestcaseDefinition tc) {
        testcases.put(tc.id(), tc);
    }

    public TestcaseDefinition get(String id) {
        return testcases.get(id);
    }

    public List<TestcaseDefinition> getAll() {
        return List.copyOf(testcases.values());
    }

    public List<TestcaseDefinition> getPassive() {
        return testcases.values().stream().filter(TestcaseDefinition::isPassive).collect(Collectors.toList());
    }

    public List<TestcaseDefinition> getActive() {
        return testcases.values().stream().filter(TestcaseDefinition::isActive).collect(Collectors.toList());
    }

    public int size() { return testcases.size(); }

    private void loadBuiltIn() {
        // Section 1: Endpoint / Content Type (TC-HDR-001 to TC-HDR-011)
        addPassiveOnly("TC-HDR-001", "HTML page response", "Security headers on HTML page response",
                "Endpoint / Content Type", "HTML response (Content-Type: text/html)");
        addBoth("TC-HDR-002", "JSON/API endpoint response", "Security headers on JSON/API endpoint response",
                "Endpoint / Content Type", "JSON/API response (Content-Type: application/json)");
        addPassiveOnly("TC-HDR-003", "CSS stylesheet response", "Security headers on CSS stylesheet response",
                "Endpoint / Content Type", "CSS response (Content-Type: text/css)");
        addPassiveOnly("TC-HDR-004", "JavaScript file response", "Security headers on JavaScript file response",
                "Endpoint / Content Type", "JavaScript response (Content-Type: application/javascript or text/javascript)");
        addPassiveOnly("TC-HDR-005", "Image resource response", "Security headers on Image resource response",
                "Endpoint / Content Type", "Image response (Content-Type: image/*)");
        addPassiveOnly("TC-HDR-006", "Font resource response", "Security headers on Font resource response",
                "Endpoint / Content Type", "Font response (Content-Type: font/* or application/font-*)");
        addPassiveOnly("TC-HDR-007", "File download response", "Security headers on File download response",
                "Endpoint / Content Type", "Response with Content-Disposition: attachment");
        addBoth("TC-HDR-008", "Authentication endpoint response", "Security headers on Authentication endpoint response",
                "Endpoint / Content Type", "Authentication endpoint (login/logout/callback path)");
        addBoth("TC-HDR-009", "Health/status endpoint response", "Security headers on Health/status endpoint response",
                "Endpoint / Content Type", "Health/status endpoint (/health, /status, /ping)");
        addBoth("TC-HDR-010", "Webhook/callback endpoint response", "Security headers on Webhook/callback endpoint response",
                "Endpoint / Content Type", "Webhook/callback endpoint (/webhook, /callback)");
        addBoth("TC-HDR-011", "GraphQL endpoint response", "Security headers on GraphQL endpoint response",
                "Endpoint / Content Type", "GraphQL endpoint (/graphql)");

        // Section 2: HTTP Status-Code Variations (TC-STATUS-*)
        addPassiveOnly("TC-STATUS-200",
                "Security headers with HTTP 200",
                "Security headers on HTTP 200 response",
                "Status Code", "Response with HTTP status 200");
        for (int code : new int[]{201, 202, 204, 206,
                301, 302, 304, 307, 308,
                400, 401, 403, 404, 405, 408, 409, 413, 415, 422, 429, 431, 451,
                500, 502, 503, 504}) {
            addBoth("TC-STATUS-" + code,
                    "Security headers with HTTP " + code,
                    "Security headers on HTTP " + code + " response",
                    "Status Code", "Response with HTTP status " + code);
        }

        // Section 3: Redirect Chain (TC-REDIRECT-001)
        addBoth("TC-REDIRECT-001", "Security headers across full redirect chain",
                "Follow redirect chain and verify security headers at each hop",
                "Redirect Chain", "Endpoint that returns 3xx redirect");

        // Section 4: Path/Query Variations (TC-PATH-001 to TC-PATH-006)
        addBoth("TC-PATH-001", "Security headers on root path (/)",
                "Check security headers on root path request",
                "Path / Query", "Accessible root endpoint");
        addBoth("TC-PATH-002", "Security headers on parent path segments (../)",
                "Check security headers with parent path traversal segments",
                "Path / Query", "Accessible endpoint with path segments");
        addBoth("TC-PATH-003", "Security headers on trailing-slash variant",
                "Check security headers with trailing-slash path variant",
                "Path / Query", "Accessible endpoint");
        addBoth("TC-PATH-004", "Security headers on non-existent path",
                "Check security headers on a non-existent path (404 expected)",
                "Path / Query", "Any in-scope host");
        addBoth("TC-PATH-005", "Security headers with query parameter variation",
                "Check security headers with added/modified query parameters",
                "Path / Query", "Accessible endpoint");
        addBoth("TC-PATH-006", "Security headers on encoded/normalized path",
                "Check security headers with URL-encoded path segments",
                "Path / Query", "Accessible endpoint");

        // Section 5: HTTP Methods (TC-METHOD-*)
        for (String m : new String[]{"GET", "POST", "PUT", "PATCH", "DELETE",
                "HEAD", "OPTIONS", "TRACE", "CONNECT", "QUERY"}) {
            addBoth("TC-METHOD-" + m,
                    "Security headers with " + m + " method",
                    "Security headers on HTTP " + m + " request",
                    "HTTP Method", "Endpoint supporting or responding to " + m);
        }

        // Section 6: CORS / Origin (TC-ACAO-001 to TC-ACAO-008)
        addBoth("TC-ACAO-001", "Security headers with No Origin header",
                "Check CORS/security headers when no Origin header is sent",
                "CORS / Origin", "Any endpoint");
        addBoth("TC-ACAO-002", "Security headers with Approved Origin",
                "Check CORS/security headers with an approved Origin",
                "CORS / Origin", "Endpoint with known approved CORS origin");
        addBoth("TC-ACAO-003", "Security headers with Unapproved Origin",
                "Check CORS/security headers with an unapproved Origin",
                "CORS / Origin", "Any endpoint");
        addBoth("TC-ACAO-004", "Security headers with Random attacker Origin",
                "Check CORS/security headers with a random attacker-controlled Origin",
                "CORS / Origin", "Any endpoint");
        addBoth("TC-ACAO-005", "Security headers with null Origin",
                "Check CORS/security headers with Origin: null",
                "CORS / Origin", "Any endpoint");
        addBoth("TC-ACAO-006", "Security headers with Subdomain Origin",
                "Check CORS/security headers with subdomain of target as Origin",
                "CORS / Origin", "Any endpoint");
        addBoth("TC-ACAO-007", "Security headers with Scheme variation Origin",
                "Check CORS/security headers with http:// instead of https:// Origin",
                "CORS / Origin", "Any endpoint");
        addBoth("TC-ACAO-008", "Security headers with Port variation Origin",
                "Check CORS/security headers with non-standard port in Origin",
                "CORS / Origin", "Any endpoint");

        // TC-CORS-001 to TC-CORS-005
        addBoth("TC-CORS-001", "Access-Control-Allow-Credentials validation",
                "Validate CORS credentials header is not true when ACAO is wildcard",
                "CORS / Origin", "Endpoint returning CORS headers");
        addBoth("TC-CORS-002", "Preflight allowed methods",
                "Validate Access-Control-Allow-Methods on preflight response",
                "CORS / Origin", "Endpoint supporting CORS preflight");
        addBoth("TC-CORS-003", "Preflight allowed headers",
                "Validate Access-Control-Allow-Headers on preflight response",
                "CORS / Origin", "Endpoint supporting CORS preflight");
        addBoth("TC-CORS-004", "Access-Control-Expose-Headers validation",
                "Validate exposed response headers via CORS",
                "CORS / Origin", "Endpoint returning CORS headers");
        addBoth("TC-CORS-005", "Preflight cache (Access-Control-Max-Age)",
                "Validate preflight caching behavior",
                "CORS / Origin", "Endpoint supporting CORS preflight");

        // Section 7: Request Header Variations — User-Agent (TC-UA-001 to TC-UA-006)
        addBoth("TC-UA-001", "Security headers with Desktop browser UA",
                "Check security headers with desktop browser User-Agent",
                "User-Agent", "Any endpoint");
        addBoth("TC-UA-002", "Security headers with Mobile browser UA",
                "Check security headers with mobile browser User-Agent",
                "User-Agent", "Any endpoint");
        addBoth("TC-UA-003", "Security headers with Bot/crawler UA",
                "Check security headers with bot/crawler User-Agent",
                "User-Agent", "Any endpoint");
        addBoth("TC-UA-004", "Security headers with cURL/non-browser UA",
                "Check security headers with cURL/non-browser User-Agent",
                "User-Agent", "Any endpoint");
        addBoth("TC-UA-005", "Security headers with Empty UA",
                "Check security headers with empty User-Agent header",
                "User-Agent", "Any endpoint");
        addBoth("TC-UA-006", "Security headers with Absent UA",
                "Check security headers with no User-Agent header",
                "User-Agent", "Any endpoint");

        // Sec-Fetch (TC-SECFETCH-001 to TC-SECFETCH-004)
        addBoth("TC-SECFETCH-001", "Security headers with Sec-Fetch-Mode: navigate",
                "Check security headers when Sec-Fetch-Mode: navigate is sent",
                "Sec-Fetch", "Any endpoint");
        addBoth("TC-SECFETCH-002", "Security headers with Sec-Fetch-Mode: cors",
                "Check security headers when Sec-Fetch-Mode: cors is sent",
                "Sec-Fetch", "Any endpoint");
        addBoth("TC-SECFETCH-003", "Security headers with Sec-Fetch cross-site iframe",
                "Check security headers with Sec-Fetch-Site: cross-site and Sec-Fetch-Dest: iframe",
                "Sec-Fetch", "Any endpoint");
        addBoth("TC-SECFETCH-004", "Security headers with all Sec-Fetch headers removed",
                "Check security headers when all Sec-Fetch-* headers are absent",
                "Sec-Fetch", "Any endpoint");

        // Referer (TC-REFERER-001 to TC-REFERER-005)
        addBoth("TC-REFERER-001", "Security headers with Absent Referer",
                "Check security headers when no Referer header is present",
                "Referer", "Any endpoint");
        addBoth("TC-REFERER-002", "Security headers with Same-origin Referer",
                "Check security headers with same-origin Referer",
                "Referer", "Any endpoint");
        addBoth("TC-REFERER-003", "Security headers with Cross-origin Referer",
                "Check security headers with cross-origin Referer",
                "Referer", "Any endpoint");
        addBoth("TC-REFERER-004", "Security headers with Suspicious/malicious Referer",
                "Check security headers with suspicious/malicious Referer value",
                "Referer", "Any endpoint");
        addBoth("TC-REFERER-005", "Security headers with Empty Referer",
                "Check security headers with empty Referer header",
                "Referer", "Any endpoint");

        // X-Forwarded-Proto (TC-XFP-001 to TC-XFP-003)
        addBoth("TC-XFP-001", "Security headers with X-Forwarded-Proto: http",
                "Check security headers when X-Forwarded-Proto: http is injected",
                "Forwarded Headers", "Endpoint behind proxy/CDN");
        addBoth("TC-XFP-002", "Security headers with X-Forwarded-Proto: https",
                "Check security headers when X-Forwarded-Proto: https is sent",
                "Forwarded Headers", "Endpoint behind proxy/CDN");
        addBoth("TC-XFP-003", "Security headers with Spoofed X-Forwarded-Proto",
                "Check security headers with spoofed/unusual X-Forwarded-Proto value",
                "Forwarded Headers", "Endpoint behind proxy/CDN");

        // X-Forwarded-Host (TC-XFH-001 to TC-XFH-002)
        addBoth("TC-XFH-001", "Security headers with X-Forwarded-Host: external",
                "Check security headers when X-Forwarded-Host is an external hostname",
                "Forwarded Headers", "Endpoint behind proxy/CDN");
        addBoth("TC-XFH-002", "Security headers with X-Forwarded-Host: localhost",
                "Check security headers when X-Forwarded-Host is internal/localhost",
                "Forwarded Headers", "Endpoint behind proxy/CDN");

        // X-Forwarded-For (TC-XFF-001 to TC-XFF-004)
        addBoth("TC-XFF-001", "Security headers with X-Forwarded-For: localhost",
                "Check security headers when X-Forwarded-For: 127.0.0.1",
                "Forwarded Headers", "Endpoint behind proxy/CDN/LB");
        addBoth("TC-XFF-002", "Security headers with X-Forwarded-For: private IP",
                "Check security headers when X-Forwarded-For is private IP range",
                "Forwarded Headers", "Endpoint behind proxy/CDN/LB");
        addBoth("TC-XFF-003", "Security headers with X-Forwarded-For: external IP",
                "Check security headers when X-Forwarded-For is external IP",
                "Forwarded Headers", "Endpoint behind proxy/CDN/LB");
        addBoth("TC-XFF-004", "Security headers with X-Forwarded-For: multiple IPs",
                "Check security headers when X-Forwarded-For has multiple IPs",
                "Forwarded Headers", "Endpoint behind proxy/CDN/LB");

        // Section 9: Authentication / Cookies (TC-COOKIE-001 to TC-COOKIE-005)
        addBoth("TC-COOKIE-001", "Security headers with No Cookie",
                "Check security headers when Cookie header is removed",
                "Authentication / Cookies", "Authenticated endpoint or session flow exists");
        addBoth("TC-COOKIE-002", "Security headers with Tampered session cookie",
                "Check security headers with tampered session cookie",
                "Authentication / Cookies", "Authenticated endpoint or session flow exists");
        addBoth("TC-COOKIE-003", "Security headers with Expired session cookie",
                "Check security headers with expired session cookie",
                "Authentication / Cookies", "Authenticated endpoint or session flow exists");
        addBoth("TC-COOKIE-004", "Security headers with Unknown/extra cookie",
                "Check security headers with unknown cookie values added",
                "Authentication / Cookies", "Authenticated endpoint or session flow exists");
        addBoth("TC-COOKIE-005", "Security headers with Malformed Cookie header",
                "Check security headers with malformed Cookie header",
                "Authentication / Cookies", "Authenticated endpoint or session flow exists");

        // TC-AUTH-001 to TC-AUTH-003
        addBoth("TC-AUTH-001", "Security headers – Authenticated vs unauthenticated",
                "Compare security headers on authenticated vs unauthenticated request",
                "Authentication / Cookies", "Authenticated endpoint or session flow exists");
        addBoth("TC-AUTH-002", "Security headers – SSO/OAuth redirect chain",
                "Check security headers across SSO/OAuth login/callback/logout flow",
                "Authentication / Cookies", "Authenticated endpoint with SSO/OAuth flow");
        addBoth("TC-AUTH-003", "Security headers – Logout/session termination",
                "Check security headers during logout/session termination",
                "Authentication / Cookies", "Authenticated endpoint or session flow exists");

        // Section 11: Header Validation Edge Cases
        addBoth("TC-EDGE-001", "Duplicate security headers",
                "Check for duplicate/conflicting security header instances",
                "Header Validation", "Representative valid and error responses available");
        addBoth("TC-EDGE-003", "Exact value and syntax",
                "Compare raw header values against approved baseline exactly",
                "Header Validation", "Representative valid and error responses available");
        addBoth("TC-EDGE-004", "Wildcard checks",
                "Inspect security headers for unintended wildcard values",
                "Header Validation", "Representative valid and error responses available");
        addBoth("TC-EDGE-005", "Error-page duplicate/conflict",
                "Inspect 4xx/5xx responses for duplicate/conflicting headers",
                "Header Validation", "Representative valid and error responses available");

    }

    private void addBoth(String id, String name, String desc, String category, String preconditions) {
        testcases.put(id, new TestcaseDefinition(id, name, desc, category,
                ExecutionMode.BOTH, SupportStatus.SUPPORTED,
                preconditions, "", "", BASELINE_EXPECTED, "All", null));
    }

    private void addPassiveOnly(String id, String name, String desc, String category, String preconditions) {
        testcases.put(id, new TestcaseDefinition(id, name, desc, category,
                ExecutionMode.PASSIVE, SupportStatus.SUPPORTED,
                preconditions, "", "", BASELINE_EXPECTED, "All", null));
    }

    private void addIncomplete(String id, String name, String desc, String category) {
        testcases.put(id, new TestcaseDefinition(id, name, desc, category,
                ExecutionMode.BOTH, SupportStatus.NOT_TESTED,
                "Not provided in workbook", "", "", "",
                "", "Incomplete testcase metadata in workbook — preserve ID, mark NOT_TESTED"));
    }
}
