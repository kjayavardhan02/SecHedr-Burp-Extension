package com.securityheaders.testcase;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class PassiveEngine {

    private static final String[] BASELINE_HEADERS = {
        "strict-transport-security", "cache-control", "x-frame-options",
        "x-content-type-options", "content-security-policy"
    };

    private final TestcaseLibrary library;
    private final BaselineEvaluator evaluator;
    private volatile TestcaseSelector selector;

    public PassiveEngine(TestcaseLibrary library, BaselineEvaluator evaluator) {
        this.library = library;
        this.evaluator = evaluator;
    }

    public void setTestcaseSelector(TestcaseSelector selector) { this.selector = selector; }

    private boolean isSelected(String tcId) {
        TestcaseSelector sel = this.selector;
        return sel == null || sel.isEnabled(tcId);
    }

    public List<TestcaseResult> analyze(ObservedResponse obs) {
        List<TestcaseResult> results = new ArrayList<>();

        // Endpoint / Content Type checks
        String contentTypeId = mapContentTypeToHdrId(obs);
        if (contentTypeId != null) {
            TestcaseDefinition tc = lookup(contentTypeId);
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }

        // Status code check
        String statusId = "STATUS-" + obs.statusCode();
        TestcaseDefinition statusTc = lookup(statusId);
        if (statusTc != null) {
            results.add(evaluateAllBaseline(statusTc, obs));
        }

        // Redirect chain — passive: check 3xx responses have security headers
        if (obs.statusCode() >= 300 && obs.statusCode() < 400) {
            TestcaseDefinition redirectTc = lookup("REDIRECT-001");
            if (redirectTc != null) {
                results.add(evaluateAllBaseline(redirectTc, obs));
            }
        }

        // Path checks
        evaluatePathChecks(obs, results);

        // Method check
        String methodId = "METHOD-" + obs.method().toUpperCase(Locale.ROOT);
        TestcaseDefinition methodTc = lookup(methodId);
        if (methodTc != null) {
            results.add(evaluateAllBaseline(methodTc, obs));
        }

        // CORS/Origin checks
        evaluateCorsChecks(obs, results);

        // User-Agent checks
        evaluateUaChecks(obs, results);

        // Sec-Fetch checks
        evaluateSecFetchChecks(obs, results);

        // Referer checks
        evaluateRefererChecks(obs, results);

        // Forwarded header checks
        evaluateForwardedChecks(obs, results);

        // Cookie / Auth checks
        evaluateCookieAuthChecks(obs, results);

        // Header validation edge cases
        evaluateEdgeChecks(obs, results);

        return results;
    }

    private String mapContentTypeToHdrId(ObservedResponse obs) {
        String ct = obs.headersLower().get("content-type");
        String path = obs.pathAndQuery().toLowerCase(Locale.ROOT);
        String disposition = obs.headersLower().get("content-disposition");

        if (disposition != null && disposition.toLowerCase(Locale.ROOT).contains("attachment")) {
            return "HDR-007";
        }

        if (path.contains("/login") || path.contains("/logout") || path.contains("/auth")
                || path.contains("/callback") || path.contains("/oauth")
                || path.contains("/signin") || path.contains("/signout")) {
            return "HDR-008";
        }
        if (path.matches(".*/(health|status|ping|ready|alive)(/.*)?$")) {
            return "HDR-009";
        }
        if (path.contains("/webhook") || path.contains("/callback") || path.contains("/hook")) {
            return "HDR-010";
        }
        if (path.contains("/graphql")) {
            return "HDR-011";
        }

        if (ct == null) return null;
        String ctLower = ct.toLowerCase(Locale.ROOT);

        if (ctLower.contains("text/html")) return "HDR-001";
        if (ctLower.contains("application/json") || ctLower.contains("application/xml")
                || ctLower.contains("text/xml")) return "HDR-002";
        if (ctLower.contains("text/css")) return "HDR-003";
        if (ctLower.contains("javascript") || ctLower.contains("ecmascript")) return "HDR-004";
        if (ctLower.startsWith("image/")) return "HDR-005";
        if (ctLower.contains("font") || ctLower.contains("woff") || ctLower.contains("ttf")
                || ctLower.contains("otf")) return "HDR-006";
        if (ctLower.contains("application/octet-stream") || ctLower.contains("application/pdf")
                || ctLower.contains("application/zip")) return "HDR-007";

        return null;
    }

    private void evaluatePathChecks(ObservedResponse obs, List<TestcaseResult> results) {
        String path = obs.pathAndQuery();

        if ("/".equals(path) || "".equals(path)) {
            TestcaseDefinition tc = lookup("PATH-001");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
        if (path.contains("..")) {
            TestcaseDefinition tc = lookup("PATH-002");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
        if (path.endsWith("/") && path.length() > 1) {
            TestcaseDefinition tc = lookup("PATH-003");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
        if (obs.statusCode() == 404) {
            TestcaseDefinition tc = lookup("PATH-004");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
        if (path.contains("?")) {
            TestcaseDefinition tc = lookup("PATH-005");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
        if (path.contains("%")) {
            TestcaseDefinition tc = lookup("PATH-006");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
    }

    private void evaluateCorsChecks(ObservedResponse obs, List<TestcaseResult> results) {
        String reqOrigin = obs.requestHeadersLower().get("origin");
        String acao = obs.headersLower().get("access-control-allow-origin");
        String creds = obs.headersLower().get("access-control-allow-credentials");

        if (reqOrigin == null) {
            TestcaseDefinition tc = lookup("ACAO-001");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        } else {
            boolean isOwnOrigin = reqOrigin.contains(obs.host());
            if (isOwnOrigin) {
                TestcaseDefinition tc = lookup("ACAO-002");
                if (tc != null) results.add(evaluateAcaoBaseline(tc, obs, acao, reqOrigin));
            } else {
                TestcaseDefinition tc = lookup("ACAO-003");
                if (tc != null) results.add(evaluateAcaoBaseline(tc, obs, acao, reqOrigin));

                if ("null".equals(reqOrigin)) {
                    TestcaseDefinition tcNull = lookup("ACAO-005");
                    if (tcNull != null) results.add(evaluateAcaoBaseline(tcNull, obs, acao, reqOrigin));
                }
            }
        }

        // CORS credential check
        if (acao != null) {
            TestcaseDefinition corsCreds = lookup("CORS-001");
            if (corsCreds != null) {
                boolean credsFail = "*".equals(acao.trim())
                        && "true".equalsIgnoreCase(creds != null ? creds.trim() : "");
                List<String> missing = checkBaselineMissing(obs);
                boolean fail = credsFail || !missing.isEmpty();
                String actual = missing.isEmpty() ? "All present" : "Missing: " + String.join(", ", missing);
                if (credsFail) actual += "; ACAO wildcard with credentials=true";
                results.add(makeResult(corsCreds, obs,
                        fail ? ResultStatus.FAIL : ResultStatus.PASS,
                        fail ? (credsFail ? "ACAO wildcard with credentials=true"
                                : "Missing: " + String.join(", ", missing))
                             : "CORS credentials safe",
                        corsCreds.expectedResult(), actual, ""));
            }

            // Exposed headers
            String exposed = obs.headersLower().get("access-control-expose-headers");
            TestcaseDefinition corsExpose = lookup("CORS-004");
            if (corsExpose != null && exposed != null) {
                results.add(evaluateAllBaseline(corsExpose, obs));
            }
        }

        // Preflight response (OPTIONS with CORS headers)
        if ("OPTIONS".equalsIgnoreCase(obs.method()) && acao != null) {
            String allowMethods = obs.headersLower().get("access-control-allow-methods");
            String allowHeaders = obs.headersLower().get("access-control-allow-headers");
            String maxAge = obs.headersLower().get("access-control-max-age");

            TestcaseDefinition corsMethods = lookup("CORS-002");
            if (corsMethods != null && allowMethods != null) {
                results.add(evaluateAllBaseline(corsMethods, obs));
            }
            TestcaseDefinition corsHeaders = lookup("CORS-003");
            if (corsHeaders != null && allowHeaders != null) {
                results.add(evaluateAllBaseline(corsHeaders, obs));
            }
            TestcaseDefinition corsCache = lookup("CORS-005");
            if (corsCache != null && maxAge != null) {
                results.add(evaluateAllBaseline(corsCache, obs));
            }
        }

        // Wildcard check — also for EDGE-004
        if (acao != null && "*".equals(acao.trim())) {
            TestcaseDefinition tcWild = lookup("EDGE-004");
            if (tcWild != null) {
                results.add(makeResult(tcWild, obs, ResultStatus.FAIL,
                        "ACAO wildcard * detected", tcWild.expectedResult(),
                        "ACAO: " + acao, ""));
            }
        }
    }

    private TestcaseResult evaluateAcaoBaseline(TestcaseDefinition tc, ObservedResponse obs,
                                                 String acao, String sentOrigin) {
        List<String> missing = checkBaselineMissing(obs);
        boolean acaoReflectsUntrusted = acao != null
                && (acao.trim().equals(sentOrigin) || "*".equals(acao.trim()));
        boolean isUntrusted = !sentOrigin.contains(obs.host()) && !"null".equals(sentOrigin);

        List<String> issues = new ArrayList<>(missing);
        if (acaoReflectsUntrusted && isUntrusted) {
            issues.add("ACAO reflects untrusted origin: " + acao);
        }

        if (issues.isEmpty()) {
            return makeResult(tc, obs, ResultStatus.PASS,
                    "All baseline headers present, ACAO safe",
                    tc.expectedResult(), "All present; ACAO: " + (acao != null ? acao : "(absent)"), "");
        }
        return makeResult(tc, obs, ResultStatus.FAIL,
                String.join("; ", issues), tc.expectedResult(),
                buildActual(missing, acao), "Origin: " + sentOrigin);
    }

    private void evaluateUaChecks(ObservedResponse obs, List<TestcaseResult> results) {
        String ua = obs.requestHeadersLower().get("user-agent");
        if (ua == null) {
            TestcaseDefinition tc = lookup("UA-006");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
            return;
        }
        if (ua.isEmpty()) {
            TestcaseDefinition tc = lookup("UA-005");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
            return;
        }
        String uaLower = ua.toLowerCase(Locale.ROOT);
        if (uaLower.contains("mobile") || uaLower.contains("android") || uaLower.contains("iphone")) {
            TestcaseDefinition tc = lookup("UA-002");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        } else if (uaLower.contains("bot") || uaLower.contains("crawler") || uaLower.contains("spider")
                || uaLower.contains("googlebot")) {
            TestcaseDefinition tc = lookup("UA-003");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        } else if (uaLower.contains("curl") || uaLower.contains("wget") || uaLower.contains("python")
                || uaLower.contains("httpie") || uaLower.contains("postman")) {
            TestcaseDefinition tc = lookup("UA-004");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        } else {
            TestcaseDefinition tc = lookup("UA-001");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
    }

    private void evaluateSecFetchChecks(ObservedResponse obs, List<TestcaseResult> results) {
        Map<String, String> reqHeaders = obs.requestHeadersLower();
        String sfMode = reqHeaders.get("sec-fetch-mode");
        String sfSite = reqHeaders.get("sec-fetch-site");
        String sfDest = reqHeaders.get("sec-fetch-dest");

        boolean hasAnySecFetch = sfMode != null || sfSite != null || sfDest != null
                || reqHeaders.containsKey("sec-fetch-user");

        if (!hasAnySecFetch) {
            TestcaseDefinition tc = lookup("SECFETCH-004");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
            return;
        }

        if ("navigate".equalsIgnoreCase(sfMode)) {
            TestcaseDefinition tc = lookup("SECFETCH-001");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
        if ("cors".equalsIgnoreCase(sfMode)) {
            TestcaseDefinition tc = lookup("SECFETCH-002");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
        if ("cross-site".equalsIgnoreCase(sfSite) && "iframe".equalsIgnoreCase(sfDest)) {
            TestcaseDefinition tc = lookup("SECFETCH-003");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        }
    }

    private void evaluateRefererChecks(ObservedResponse obs, List<TestcaseResult> results) {
        String referer = obs.requestHeadersLower().get("referer");

        if (referer == null) {
            TestcaseDefinition tc = lookup("REFERER-001");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
            return;
        }
        if (referer.isEmpty()) {
            TestcaseDefinition tc = lookup("REFERER-005");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
            return;
        }
        if (referer.contains(obs.host())) {
            TestcaseDefinition tc = lookup("REFERER-002");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
        } else {
            TestcaseDefinition tc = lookup("REFERER-003");
            if (tc != null) results.add(evaluateAllBaseline(tc, obs));
            String refLower = referer.toLowerCase(Locale.ROOT);
            if (refLower.contains("evil") || refLower.contains("malware") || refLower.contains("phish")
                    || refLower.contains("<script") || refLower.contains("javascript:")) {
                TestcaseDefinition tcSus = lookup("REFERER-004");
                if (tcSus != null) results.add(evaluateAllBaseline(tcSus, obs));
            }
        }
    }

    private void evaluateForwardedChecks(ObservedResponse obs, List<TestcaseResult> results) {
        Map<String, String> reqHeaders = obs.requestHeadersLower();

        String xfp = reqHeaders.get("x-forwarded-proto");
        if (xfp != null) {
            String xfpLower = xfp.toLowerCase(Locale.ROOT);
            if ("http".equals(xfpLower)) {
                evalTc("XFP-001", obs, results);
            } else if ("https".equals(xfpLower)) {
                evalTc("XFP-002", obs, results);
            } else {
                evalTc("XFP-003", obs, results);
            }
        }

        String xfh = reqHeaders.get("x-forwarded-host");
        if (xfh != null) {
            String xfhLower = xfh.toLowerCase(Locale.ROOT);
            if (xfhLower.contains("localhost") || xfhLower.contains("127.0.0.1")
                    || xfhLower.startsWith("10.") || xfhLower.startsWith("192.168.")) {
                evalTc("XFH-002", obs, results);
            } else {
                evalTc("XFH-001", obs, results);
            }
        }

        String xff = reqHeaders.get("x-forwarded-for");
        if (xff != null) {
            if (xff.contains(",")) {
                evalTc("XFF-004", obs, results);
            } else if (xff.contains("127.0.0.1") || xff.contains("::1") || xff.contains("localhost")) {
                evalTc("XFF-001", obs, results);
            } else if (xff.startsWith("10.") || xff.startsWith("192.168.")
                    || xff.startsWith("172.16.") || xff.startsWith("172.17.")
                    || xff.startsWith("172.18.") || xff.startsWith("172.19.")
                    || xff.startsWith("172.2") || xff.startsWith("172.3")) {
                evalTc("XFF-002", obs, results);
            } else {
                evalTc("XFF-003", obs, results);
            }
        }
    }

    private void evaluateCookieAuthChecks(ObservedResponse obs, List<TestcaseResult> results) {
        String cookie = obs.requestHeadersLower().get("cookie");
        if (cookie == null) {
            evalTc("COOKIE-001", obs, results);
        }
        // COOKIE-002 through 005 and AUTH-* are primarily active tests
        // Passive: just check baseline on auth-looking responses
        String path = obs.pathAndQuery().toLowerCase(Locale.ROOT);
        if (path.contains("/login") || path.contains("/auth") || path.contains("/oauth")
                || path.contains("/callback") || path.contains("/sso")) {
            evalTc("AUTH-001", obs, results);
        }
        if (path.contains("/logout") || path.contains("/signout")) {
            evalTc("AUTH-003", obs, results);
        }
    }

    private void evaluateEdgeChecks(ObservedResponse obs, List<TestcaseResult> results) {
        Map<String, List<String>> multi = obs.headerMultiLower();

        // EDGE-001: Duplicate security headers
        TestcaseDefinition tcDup = lookup("EDGE-001");
        if (tcDup != null) {
            List<String> duplicates = new ArrayList<>();
            for (String h : BASELINE_HEADERS) {
                List<String> vals = multi.get(h);
                if (vals != null && vals.size() > 1) {
                    duplicates.add(h + " (" + vals.size() + " instances)");
                }
            }
            List<String> xfoVals = multi.get("x-frame-options");
            if (xfoVals != null && xfoVals.size() > 1) {
                Set<String> unique = xfoVals.stream()
                        .map(v -> v.trim().toLowerCase(Locale.ROOT))
                        .collect(Collectors.toSet());
                if (unique.size() > 1) duplicates.add("x-frame-options has conflicting values: " + unique);
            }
            results.add(makeResult(tcDup, obs,
                    duplicates.isEmpty() ? ResultStatus.PASS : ResultStatus.FAIL,
                    duplicates.isEmpty() ? "No duplicate security headers" : "Duplicates: " + String.join("; ", duplicates),
                    tcDup.expectedResult(),
                    duplicates.isEmpty() ? "No duplicates" : String.join("; ", duplicates), ""));
        }

        // EDGE-003: Exact value and syntax
        TestcaseDefinition tcSyntax = lookup("EDGE-003");
        if (tcSyntax != null) {
            results.add(evaluateExactBaseline(tcSyntax, obs));
        }

        // EDGE-004: Wildcard checks
        TestcaseDefinition tcWild = lookup("EDGE-004");
        if (tcWild != null) {
            String acao = obs.headersLower().get("access-control-allow-origin");
            String csp = obs.headersLower().get("content-security-policy");
            List<String> issues = new ArrayList<>();
            if (acao != null && "*".equals(acao.trim())) issues.add("ACAO uses wildcard *");
            if (csp != null && csp.contains("*")) issues.add("CSP contains wildcard");
            results.add(makeResult(tcWild, obs,
                    issues.isEmpty() ? ResultStatus.PASS : ResultStatus.FAIL,
                    issues.isEmpty() ? "No unsafe wildcards" : String.join("; ", issues),
                    tcWild.expectedResult(),
                    issues.isEmpty() ? "No wildcards" : String.join("; ", issues), ""));
        }

        // EDGE-005: Error-page duplicate/conflict
        if (obs.statusCode() >= 400) {
            TestcaseDefinition tcErr = lookup("EDGE-005");
            if (tcErr != null) {
                List<String> dups = new ArrayList<>();
                for (String h : BASELINE_HEADERS) {
                    List<String> vals = multi.get(h);
                    if (vals != null && vals.size() > 1) dups.add(h + " duplicated");
                }
                results.add(makeResult(tcErr, obs,
                        dups.isEmpty() ? ResultStatus.PASS : ResultStatus.FAIL,
                        dups.isEmpty() ? "Error response has consistent headers"
                                : "Error response has duplicates: " + String.join("; ", dups),
                        tcErr.expectedResult(),
                        dups.isEmpty() ? "No duplicates" : String.join("; ", dups), ""));
            }
        }
    }

    private TestcaseDefinition lookup(String id) {
        if (!isSelected(id)) return null;
        TestcaseDefinition tc = library.get(id);
        if (tc == null) return null;
        if (tc.mode() != ExecutionMode.PASSIVE) return null;
        return tc;
    }

    private void evalTc(String id, ObservedResponse obs, List<TestcaseResult> results) {
        TestcaseDefinition tc = lookup(id);
        if (tc != null) results.add(evaluateAllBaseline(tc, obs));
    }

    private TestcaseResult evaluateAllBaseline(TestcaseDefinition tc, ObservedResponse obs) {
        List<String> missing = checkBaselineMissing(obs);
        boolean xfoCovered = !obs.headersLower().containsKey("x-frame-options")
                && isXfoCoveredByCsp(obs.headersLower());
        if (missing.isEmpty()) {
            String actual = xfoCovered ? "All present (XFO covered by CSP frame-ancestors)" : "All present";
            return makeResult(tc, obs, ResultStatus.PASS,
                    "All baseline headers present", tc.expectedResult(), actual, "");
        }
        return makeResult(tc, obs, ResultStatus.FAIL,
                "Missing: " + String.join(", ", missing), tc.expectedResult(),
                "Missing: " + String.join(", ", missing), "");
    }

    private TestcaseResult evaluateExactBaseline(TestcaseDefinition tc, ObservedResponse obs) {
        Map<String, String> headers = obs.headersLower();
        List<String> issues = new ArrayList<>();

        for (String headerName : BASELINE_HEADERS) {
            String value = headers.get(headerName);
            if (value == null) {
                if (headerName.equals("strict-transport-security") && !obs.isHttps()) continue;
                if (headerName.equals("x-frame-options") && isXfoCoveredByCsp(headers)) continue;
                issues.add(headerName + ": absent");
                continue;
            }
            BaselineEvaluator.EvalResult er = evaluator.evaluate(headerName, value, obs.isHttps());
            if (er.status() == ResultStatus.FAIL) {
                issues.add(headerName + ": " + er.summary());
            }
        }

        if (issues.isEmpty()) {
            return makeResult(tc, obs, ResultStatus.PASS,
                    "All headers match approved baseline exactly", tc.expectedResult(), "All match", "");
        }
        return makeResult(tc, obs, ResultStatus.FAIL,
                "Baseline mismatch: " + String.join("; ", issues), tc.expectedResult(),
                String.join("; ", issues), "");
    }

    private List<String> checkBaselineMissing(ObservedResponse obs) {
        Map<String, String> headers = obs.headersLower();
        List<String> missing = new ArrayList<>();
        for (String h : BASELINE_HEADERS) {
            if (h.equals("strict-transport-security") && !obs.isHttps()) continue;
            if (!headers.containsKey(h)) {
                if (h.equals("x-frame-options") && isXfoCoveredByCsp(headers)) continue;
                missing.add(h);
            }
        }
        return missing;
    }

    private boolean isXfoCoveredByCsp(Map<String, String> headers) {
        String csp = headers.get("content-security-policy");
        return csp != null && csp.toLowerCase(java.util.Locale.ROOT).contains("frame-ancestors");
    }

    private String buildActual(List<String> missing, String acao) {
        if (missing.isEmpty() && acao == null) return "All present";
        StringBuilder sb = new StringBuilder();
        if (!missing.isEmpty()) sb.append("Missing: ").append(String.join(", ", missing));
        if (acao != null) {
            if (sb.length() > 0) sb.append("; ");
            sb.append("ACAO: ").append(acao);
        }
        return sb.toString();
    }

    private TestcaseResult makeResult(TestcaseDefinition tc, ObservedResponse obs,
                                      ResultStatus status, String summary,
                                      String expected, String actual, String evidence) {
        return new TestcaseResult(tc.id(), obs.endpointKey(), obs.observedAt(),
                ExecutionMode.PASSIVE, status, summary, expected, actual, evidence, null,
                obs.host(), obs.pathAndQuery(), obs.statusCode(),
                obs.rawRequest(), obs.rawResponse());
    }

    public static final class ObservedResponse {
        private final String endpointKey;
        private final Instant observedAt;
        private final String host;
        private final int port;
        private final String method;
        private final String pathAndQuery;
        private final int statusCode;
        private final boolean isHttps;
        private final Map<String, String> headersLower;
        private final Map<String, List<String>> headerMultiLower;
        private final Map<String, String> requestHeadersLower;
        private final String rawRequest;
        private final String rawResponse;

        public ObservedResponse(String endpointKey, Instant observedAt, String host, int port,
                                String method, String pathAndQuery, int statusCode, boolean isHttps,
                                Map<String, String> headersLower,
                                Map<String, List<String>> headerMultiLower,
                                Map<String, String> requestHeadersLower) {
            this(endpointKey, observedAt, host, port, method, pathAndQuery, statusCode,
                 isHttps, headersLower, headerMultiLower, requestHeadersLower, null, null);
        }

        public ObservedResponse(String endpointKey, Instant observedAt, String host, int port,
                                String method, String pathAndQuery, int statusCode, boolean isHttps,
                                Map<String, String> headersLower,
                                Map<String, List<String>> headerMultiLower,
                                Map<String, String> requestHeadersLower,
                                String rawRequest, String rawResponse) {
            this.endpointKey = endpointKey;
            this.observedAt = observedAt;
            this.host = host;
            this.port = port;
            this.method = method;
            this.pathAndQuery = pathAndQuery;
            this.statusCode = statusCode;
            this.isHttps = isHttps;
            this.headersLower = headersLower;
            this.headerMultiLower = headerMultiLower;
            this.requestHeadersLower = requestHeadersLower != null ? requestHeadersLower : Map.of();
            this.rawRequest = rawRequest;
            this.rawResponse = rawResponse;
        }

        public String endpointKey() { return endpointKey; }
        public Instant observedAt() { return observedAt; }
        public String host() { return host; }
        public int port() { return port; }
        public String method() { return method; }
        public String pathAndQuery() { return pathAndQuery; }
        public int statusCode() { return statusCode; }
        public boolean isHttps() { return isHttps; }
        public Map<String, String> headersLower() { return headersLower; }
        public Map<String, List<String>> headerMultiLower() { return headerMultiLower; }
        public Map<String, String> requestHeadersLower() { return requestHeadersLower; }
        public String rawRequest() { return rawRequest; }
        public String rawResponse() { return rawResponse; }
    }
}
