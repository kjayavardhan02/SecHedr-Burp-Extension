package com.securityheaders.testcase;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.securityheaders.ScopeManager;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

public class ActiveRunner {

    private static final String MARKER_HEADER = "X-SecHeaders-Scanner";
    private static final String MARKER_VALUE = "active-test";
    private static final ThreadLocal<HttpRequest> lastRequest = new ThreadLocal<>();
    private static final ThreadLocal<burp.api.montoya.http.message.responses.HttpResponse> lastResponse = new ThreadLocal<>();

    private static final String[] BASELINE_HEADERS = {
        "strict-transport-security", "cache-control", "x-frame-options",
        "x-content-type-options", "content-security-policy"
    };

    private final MontoyaApi api;
    private final TestcaseLibrary library;
    private final BaselineEvaluator evaluator;
    private final ScopeManager scopeManager;
    private final EndpointRegistry endpointRegistry;
    private final TestcaseResultStore resultStore;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);
    private volatile boolean enabled = true;
    private volatile Runnable onResultsReady;
    private volatile TestcaseSelector selector;

    public ActiveRunner(MontoyaApi api, TestcaseLibrary library,
                        BaselineEvaluator evaluator, ScopeManager scopeManager,
                        EndpointRegistry endpointRegistry, TestcaseResultStore resultStore) {
        this.api = api;
        this.library = library;
        this.evaluator = evaluator;
        this.scopeManager = scopeManager;
        this.endpointRegistry = endpointRegistry;
        this.resultStore = resultStore;
    }

    public void setTestcaseSelector(TestcaseSelector selector) { this.selector = selector; }

    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public boolean isEnabled() { return enabled; }
    public void setOnResultsReady(Runnable cb) { this.onResultsReady = cb; }

    private boolean isSelected(String tcId) {
        TestcaseSelector sel = this.selector;
        return sel == null || sel.isEnabled(tcId);
    }

    private HttpRequestResponse send(HttpRequest request) {
        lastRequest.set(request);
        lastResponse.set(null);
        HttpRequestResponse rr = api.http().sendRequest(request);
        if (rr.response() != null) lastResponse.set(rr.response());
        return rr;
    }

    private void clearRequestContext() {
        lastRequest.remove();
        lastResponse.remove();
    }

    public static boolean isOwnRequest(HttpRequest request) {
        String val = request.headerValue(MARKER_HEADER);
        return MARKER_VALUE.equals(val);
    }

    public void scheduleActiveTests(String host, int port, String method,
                                     String pathAndQuery, boolean isHttps,
                                     HttpRequest baseRequest) {
        if (!enabled) return;

        String endpointKey = host + ":" + port + ":" + method + ":" + pathAndQuery;
        if (!endpointRegistry.markActiveScanned(endpointKey)) return;

        executor.submit(() -> {
            try {
                runActiveTests(host, port, method, pathAndQuery, isHttps, baseRequest, endpointKey);
            } catch (Exception e) {
                api.logging().logToError("Active runner error: " + e.getMessage());
            }
        });
    }

    private void runActiveTests(String host, int port, String method, String pathAndQuery,
                                 boolean isHttps, HttpRequest baseRequest, String endpointKey) {
        List<TestcaseResult> batch = new ArrayList<>();

        // Content-type probes (HDR-*)
        runContentTypeProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Status code probes (STATUS-*)
        runStatusCodeProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Redirect chain (REDIRECT-001)
        batch.add(runRedirectChain(host, port, isHttps, pathAndQuery, baseRequest, endpointKey));

        // Path variations (PATH-*)
        runPathProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Method variations (METHOD-*)
        runMethodProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // CORS / Origin (ACAO-*, CORS-*)
        runCorsProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // User-Agent (UA-*)
        runUaProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Sec-Fetch (SECFETCH-*)
        runSecFetchProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Referer (REFERER-*)
        runRefererProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Forwarded headers (XFP-*, XFH-*, XFF-*)
        runForwardedProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Cookie / Auth (COOKIE-*, AUTH-*)
        runCookieAuthProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        // Edge cases (EDGE-*)
        runEdgeProbes(host, port, isHttps, pathAndQuery, baseRequest, endpointKey, batch);

        batch.removeIf(Objects::isNull);
        if (!batch.isEmpty()) {
            resultStore.addAll(batch);
            Runnable cb = onResultsReady;
            if (cb != null) javax.swing.SwingUtilities.invokeLater(cb);
        }
    }

    // --- Content Type Probes ---

    private void runContentTypeProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                       HttpRequest base, String ek, List<TestcaseResult> batch) {
        // HDR-002: JSON/API — modifies Accept header
        HttpRequest jsonReq = replaceHeader(buildReq(host, port, isHttps, "GET", pathAndQuery, base),
                "Accept", "application/json");
        batch.add(sendAndCheck("HDR-002", jsonReq, ek, host));

        // HDR-008: Auth endpoint — probe first reachable auth path
        batch.add(sendFirstReachable("HDR-008", host, port, isHttps, base, ek,
                "/login", "/auth", "/signin"));

        // HDR-009: Health endpoint — probe first reachable health path
        batch.add(sendFirstReachable("HDR-009", host, port, isHttps, base, ek,
                "/health", "/status", "/ping"));

        // HDR-010: Webhook
        batch.add(sendAndCheck("HDR-010", buildReq(host, port, isHttps, "POST", "/webhook", base), ek, host));

        // HDR-011: GraphQL
        batch.add(sendAndCheck("HDR-011", buildReq(host, port, isHttps, "POST", "/graphql", base), ek, host));
    }

    // --- Status Code Probes ---

    private void runStatusCodeProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                      HttpRequest base, String ek, List<TestcaseResult> batch) {
        // 301 — HTTP→HTTPS redirect (only when original is HTTPS)
        batch.add(runHttpToHttpsRedirect(host, pathAndQuery, isHttps, base, ek));

        // 404 — non-existent path
        batch.add(sendAndCheck("STATUS-404", buildReq(host, port, isHttps, "GET", "/nonexistent-shtest-404", base), ek, host));

        // 405 — wrong method
        batch.add(sendAndCheck("STATUS-405", buildReq(host, port, isHttps, "PATCH", pathAndQuery, base), ek, host));
    }

    private TestcaseResult runHttpToHttpsRedirect(String host, String pathAndQuery,
                                                   boolean isHttps, HttpRequest base, String ek) {
        if (!isSelected("STATUS-301")) return null;
        TestcaseDefinition tc = library.get("STATUS-301");
        if (tc == null) return null;

        if (!isHttps) {
            return makeNotTested(tc, ek, host, pathAndQuery, "Original request is already HTTP — skipped to avoid duplication");
        }
        if (!scopeManager.isInScope(host)) {
            return makeNotTested(tc, ek, host, pathAndQuery, "Target host out of scope");
        }

        HttpRequest httpReq = addMarker(buildReq(host, 80, false, "GET", pathAndQuery, base));

        try {
            HttpRequestResponse rr = send(httpReq);
            var resp = rr.response();
            if (resp == null) {
                return makeResult(tc, ek, host, pathAndQuery, 0, ResultStatus.ERROR,
                        "No response from HTTP port 80", tc.expectedResult(), "", "Connection refused or timeout");
            }

            int status = resp.statusCode();
            String path = httpReq.path() != null ? httpReq.path() : "/";
            String location = resp.headerValue("Location");

            List<String> missing = new ArrayList<>();
            for (String h : BASELINE_HEADERS) {
                if (resp.headerValue(h) == null) {
                    if (h.equals("x-frame-options") && isXfoCoveredByCsp(resp)) continue;
                    missing.add(h);
                }
            }

            String redirectInfo = "HTTP " + status;
            if (location != null) redirectInfo += " → " + location;

            if (status == 301 || status == 302 || status == 307 || status == 308) {
                if (missing.isEmpty()) {
                    return makeResult(tc, ek, host, path, status, ResultStatus.PASS,
                            "Redirect response has all security headers (" + redirectInfo + ")",
                            tc.expectedResult(), "All present", redirectInfo);
                }
                return makeResult(tc, ek, host, path, status, ResultStatus.FAIL,
                        "Missing on redirect: " + String.join(", ", missing) + " (" + redirectInfo + ")",
                        tc.expectedResult(), "Missing: " + String.join(", ", missing), redirectInfo);
            }

            return makeResult(tc, ek, host, path, status, ResultStatus.INCONCLUSIVE,
                    "Expected 301 redirect but got HTTP " + status,
                    tc.expectedResult(), "HTTP " + status + " (no redirect)", redirectInfo);
        } catch (Exception e) {
            return makeResult(tc, ek, host, pathAndQuery, 0, ResultStatus.ERROR,
                    "HTTP request failed: " + e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    // --- Redirect Chain ---

    private TestcaseResult runRedirectChain(String host, int port, boolean isHttps,
                                             String pathAndQuery, HttpRequest base, String ek) {
        if (!isSelected("REDIRECT-001")) return null;
        TestcaseDefinition tc = library.get("REDIRECT-001");
        if (tc == null) return null;

        HttpRequest req = addMarker(buildReq(host, port, isHttps, "GET", pathAndQuery, base));
        if (!scopeManager.isInScope(host)) {
            return makeNotTested(tc, ek, host, pathAndQuery, "Out of scope");
        }

        try {
            int hops = 0;
            List<String> issues = new ArrayList<>();
            HttpRequest current = req;

            while (hops < 10) {
                HttpRequestResponse rr = send(current);
                var resp = rr.response();
                if (resp == null) break;

                int status = resp.statusCode();
                hops++;

                List<String> missing = new ArrayList<>();
                for (String h : BASELINE_HEADERS) {
                    if (resp.headerValue(h) == null) {
                        if (h.equals("x-frame-options") && isXfoCoveredByCsp(resp)) continue;
                        missing.add(h);
                    }
                }
                if (!missing.isEmpty()) {
                    issues.add("Hop " + hops + " (HTTP " + status + "): Missing " + String.join(", ", missing));
                }

                if (status >= 300 && status < 400) {
                    String location = resp.headerValue("Location");
                    if (location == null) break;
                    try {
                        java.net.URI uri = java.net.URI.create(
                                location.contains("://") ? location : "https://" + host + location);
                        String rHost = uri.getHost() != null ? uri.getHost().toLowerCase(Locale.ROOT) : host;
                        if (!scopeManager.isInScope(rHost)) {
                            issues.add("Redirect to out-of-scope host: " + rHost);
                            break;
                        }
                        int rPort = uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
                        boolean rHttps = "https".equalsIgnoreCase(uri.getScheme());
                        String rPath = uri.getRawPath() != null ? uri.getRawPath() : "/";
                        if (uri.getRawQuery() != null) rPath += "?" + uri.getRawQuery();
                        current = addMarker(buildReq(rHost, rPort, rHttps, "GET", rPath, null));
                    } catch (Exception e) { break; }
                } else {
                    break;
                }
            }

            if (issues.isEmpty()) {
                return makeResult(tc, ek, host, pathAndQuery, 0, ResultStatus.PASS,
                        hops + " hop(s) all have security headers", tc.expectedResult(),
                        hops + " hops checked, all present", "");
            }
            return makeResult(tc, ek, host, pathAndQuery, 0, ResultStatus.FAIL,
                    String.join("; ", issues), tc.expectedResult(),
                    String.join("; ", issues), "");
        } catch (Exception e) {
            return makeResult(tc, ek, host, pathAndQuery, 0, ResultStatus.ERROR,
                    e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    // --- Path Probes ---

    private void runPathProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                HttpRequest base, String ek, List<TestcaseResult> batch) {
        // PATH-001: Root path
        batch.add(sendAndCheck("PATH-001", buildReq(host, port, isHttps, "GET", "/", base), ek, host));

        // PATH-002: Parent path segments
        batch.add(sendAndCheck("PATH-002", buildReq(host, port, isHttps, "GET", "/../" + pathAndQuery, base), ek, host));

        // PATH-003: Trailing slash
        String trailingSlash = pathAndQuery.endsWith("/") ? pathAndQuery : pathAndQuery + "/";
        batch.add(sendAndCheck("PATH-003", buildReq(host, port, isHttps, "GET", trailingSlash, base), ek, host));

        // PATH-004: Non-existent path
        batch.add(sendAndCheck("PATH-004", buildReq(host, port, isHttps, "GET", "/nonexistent-shtest-path-" + System.nanoTime() % 10000, base), ek, host));

        // PATH-005: Query parameter variation
        String qPath = pathAndQuery.contains("?") ? pathAndQuery + "&_shtest=1" : pathAndQuery + "?_shtest=1";
        batch.add(sendAndCheck("PATH-005", buildReq(host, port, isHttps, "GET", qPath, base), ek, host));

        // PATH-006: Encoded path
        String encoded = pathAndQuery.replace("/", "/%2F").replaceFirst("/%2F", "/");
        batch.add(sendAndCheck("PATH-006", buildReq(host, port, isHttps, "GET", encoded, base), ek, host));
    }

    // --- Method Probes ---

    private void runMethodProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                  HttpRequest base, String ek, List<TestcaseResult> batch) {
        for (String m : new String[]{"GET", "POST", "PUT", "PATCH", "DELETE",
                "HEAD", "OPTIONS", "TRACE", "CONNECT", "QUERY"}) {
            batch.add(sendAndCheck("METHOD-" + m,
                    buildReq(host, port, isHttps, m, pathAndQuery, base), ek, host));
        }
    }

    // --- CORS Probes ---

    private void runCorsProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                HttpRequest base, String ek, List<TestcaseResult> batch) {
        HttpRequest baseGet = buildReq(host, port, isHttps, "GET", pathAndQuery, base);

        // ACAO-001: No Origin
        batch.add(sendAndCheck("ACAO-001", removeHeader(baseGet, "Origin"), ek, host));

        // ACAO-002: Approved Origin
        batch.add(sendAndCheckCors("ACAO-002",
                addHeader(baseGet, "Origin", "https://" + host), ek, host, "https://" + host));

        // ACAO-003: Unapproved Origin
        batch.add(sendAndCheckCors("ACAO-003",
                addHeader(baseGet, "Origin", "https://unapproved-test.example.com"), ek, host,
                "https://unapproved-test.example.com"));

        // ACAO-004: Random attacker Origin
        batch.add(sendAndCheckCors("ACAO-004",
                addHeader(baseGet, "Origin", "https://evil-attacker.com"), ek, host,
                "https://evil-attacker.com"));

        // ACAO-005: null Origin
        batch.add(sendAndCheckCors("ACAO-005",
                addHeader(baseGet, "Origin", "null"), ek, host, "null"));

        // ACAO-006: Subdomain Origin
        batch.add(sendAndCheckCors("ACAO-006",
                addHeader(baseGet, "Origin", "https://sub." + host), ek, host,
                "https://sub." + host));

        // ACAO-007: Scheme variation
        batch.add(sendAndCheckCors("ACAO-007",
                addHeader(baseGet, "Origin", "http://" + host), ek, host,
                "http://" + host));

        // ACAO-008: Port variation
        batch.add(sendAndCheckCors("ACAO-008",
                addHeader(baseGet, "Origin", "https://" + host + ":8443"), ek, host,
                "https://" + host + ":8443"));

        // CORS-001: Credentials check (send with Origin and check)
        batch.add(sendAndCheckCorsCredentials("CORS-001",
                addHeader(baseGet, "Origin", "https://" + host), ek, host));

        // CORS-002: Preflight allowed methods
        HttpRequest preflight = buildReq(host, port, isHttps, "OPTIONS", pathAndQuery, base);
        preflight = addHeader(preflight, "Origin", "https://" + host);
        preflight = addHeader(preflight, "Access-Control-Request-Method", "POST");
        batch.add(sendAndCheckCorsHeader("CORS-002", preflight, ek, host,
                "Access-Control-Allow-Methods"));

        // CORS-003: Preflight allowed headers
        HttpRequest preflightHdr = buildReq(host, port, isHttps, "OPTIONS", pathAndQuery, base);
        preflightHdr = addHeader(preflightHdr, "Origin", "https://" + host);
        preflightHdr = addHeader(preflightHdr, "Access-Control-Request-Method", "GET");
        preflightHdr = addHeader(preflightHdr, "Access-Control-Request-Headers", "X-Custom-Header");
        batch.add(sendAndCheckCorsHeader("CORS-003", preflightHdr, ek, host,
                "Access-Control-Allow-Headers"));

        // CORS-004: Expose headers
        batch.add(sendAndCheckCorsHeader("CORS-004",
                addHeader(baseGet, "Origin", "https://" + host), ek, host,
                "Access-Control-Expose-Headers"));

        // CORS-005: Preflight cache
        batch.add(sendAndCheckCorsHeader("CORS-005", preflight, ek, host,
                "Access-Control-Max-Age"));
    }

    // --- UA Probes ---

    private void runUaProbes(String host, int port, boolean isHttps, String pathAndQuery,
                              HttpRequest base, String ek, List<TestcaseResult> batch) {
        HttpRequest baseGet = buildReq(host, port, isHttps, "GET", pathAndQuery, base);

        batch.add(sendAndCheck("UA-001",
                replaceHeader(baseGet, "User-Agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"),
                ek, host));
        batch.add(sendAndCheck("UA-002",
                replaceHeader(baseGet, "User-Agent",
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148"),
                ek, host));
        batch.add(sendAndCheck("UA-003",
                replaceHeader(baseGet, "User-Agent",
                        "Googlebot/2.1 (+http://www.google.com/bot.html)"),
                ek, host));
        batch.add(sendAndCheck("UA-004",
                replaceHeader(baseGet, "User-Agent", "curl/8.4.0"),
                ek, host));
        batch.add(sendAndCheck("UA-005",
                replaceHeader(baseGet, "User-Agent", ""),
                ek, host));
        batch.add(sendAndCheck("UA-006",
                removeHeader(baseGet, "User-Agent"),
                ek, host));
    }

    // --- Sec-Fetch Probes ---

    private void runSecFetchProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                    HttpRequest base, String ek, List<TestcaseResult> batch) {
        HttpRequest baseGet = buildReq(host, port, isHttps, "GET", pathAndQuery, base);

        // SECFETCH-001: navigate
        HttpRequest sf1 = addHeader(baseGet, "Sec-Fetch-Mode", "navigate");
        sf1 = addHeader(sf1, "Sec-Fetch-Site", "none");
        sf1 = addHeader(sf1, "Sec-Fetch-Dest", "document");
        batch.add(sendAndCheck("SECFETCH-001", sf1, ek, host));

        // SECFETCH-002: cors
        HttpRequest sf2 = addHeader(baseGet, "Sec-Fetch-Mode", "cors");
        sf2 = addHeader(sf2, "Sec-Fetch-Site", "same-origin");
        batch.add(sendAndCheck("SECFETCH-002", sf2, ek, host));

        // SECFETCH-003: cross-site iframe
        HttpRequest sf3 = addHeader(baseGet, "Sec-Fetch-Mode", "navigate");
        sf3 = addHeader(sf3, "Sec-Fetch-Site", "cross-site");
        sf3 = addHeader(sf3, "Sec-Fetch-Dest", "iframe");
        batch.add(sendAndCheck("SECFETCH-003", sf3, ek, host));

        // SECFETCH-004: all removed
        HttpRequest sf4 = removeHeader(baseGet, "Sec-Fetch-Mode");
        sf4 = removeHeader(sf4, "Sec-Fetch-Site");
        sf4 = removeHeader(sf4, "Sec-Fetch-Dest");
        sf4 = removeHeader(sf4, "Sec-Fetch-User");
        batch.add(sendAndCheck("SECFETCH-004", sf4, ek, host));
    }

    // --- Referer Probes ---

    private void runRefererProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                   HttpRequest base, String ek, List<TestcaseResult> batch) {
        HttpRequest baseGet = buildReq(host, port, isHttps, "GET", pathAndQuery, base);

        batch.add(sendAndCheck("REFERER-001", removeHeader(baseGet, "Referer"), ek, host));
        batch.add(sendAndCheck("REFERER-002",
                addHeader(baseGet, "Referer", "https://" + host + "/page"), ek, host));
        batch.add(sendAndCheck("REFERER-003",
                addHeader(baseGet, "Referer", "https://external-site.example.com/page"), ek, host));
        batch.add(sendAndCheck("REFERER-004",
                addHeader(baseGet, "Referer", "https://evil-phishing-site.com/malware"), ek, host));
        batch.add(sendAndCheck("REFERER-005",
                addHeader(baseGet, "Referer", ""), ek, host));
    }

    // --- Forwarded Header Probes ---

    private void runForwardedProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                     HttpRequest base, String ek, List<TestcaseResult> batch) {
        HttpRequest baseGet = buildReq(host, port, isHttps, "GET", pathAndQuery, base);

        // XFP
        batch.add(sendAndCheck("XFP-001", addHeader(baseGet, "X-Forwarded-Proto", "http"), ek, host));
        batch.add(sendAndCheck("XFP-002", addHeader(baseGet, "X-Forwarded-Proto", "https"), ek, host));
        batch.add(sendAndCheck("XFP-003", addHeader(baseGet, "X-Forwarded-Proto", "ftp"), ek, host));

        // XFH
        batch.add(sendAndCheck("XFH-001", addHeader(baseGet, "X-Forwarded-Host", "evil-external.com"), ek, host));
        batch.add(sendAndCheck("XFH-002", addHeader(baseGet, "X-Forwarded-Host", "localhost"), ek, host));

        // XFF
        batch.add(sendAndCheck("XFF-001", addHeader(baseGet, "X-Forwarded-For", "127.0.0.1"), ek, host));
        batch.add(sendAndCheck("XFF-002", addHeader(baseGet, "X-Forwarded-For", "10.0.0.1"), ek, host));
        batch.add(sendAndCheck("XFF-003", addHeader(baseGet, "X-Forwarded-For", "1.2.3.4"), ek, host));
        batch.add(sendAndCheck("XFF-004", addHeader(baseGet, "X-Forwarded-For", "1.2.3.4, 5.6.7.8"), ek, host));
    }

    // --- Infrastructure Probes ---

    // --- Cookie / Auth Probes ---

    private void runCookieAuthProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                      HttpRequest base, String ek, List<TestcaseResult> batch) {
        HttpRequest baseGet = buildReq(host, port, isHttps, "GET", pathAndQuery, base);
        String origCookie = baseGet.headerValue("Cookie");
        String lsqAuth = extractCookieValue(origCookie, "LSQAUTH");

        // COOKIE-001: No cookie
        batch.add(sendAndCheck("COOKIE-001", removeHeader(baseGet, "Cookie"), ek, host));

        // COOKIE-002: Tampered cookie
        if (lsqAuth != null) {
            String tampered = replaceCookieValue(origCookie, "LSQAUTH", "TAMPERED_INVALID_VALUE");
            batch.add(sendAndCheck("COOKIE-002", replaceHeader(baseGet, "Cookie", tampered), ek, host));
        } else {
            batch.add(sendAndCheck("COOKIE-002", replaceHeader(baseGet, "Cookie", "session=TAMPERED_INVALID_VALUE"), ek, host));
        }

        // COOKIE-003: Expired cookie — random value for LSQAUTH
        if (lsqAuth != null) {
            String randomVal = "expired_" + Long.toHexString(System.nanoTime());
            String expired = replaceCookieValue(origCookie, "LSQAUTH", randomVal);
            batch.add(sendAndCheck("COOKIE-003", replaceHeader(baseGet, "Cookie", expired), ek, host));
        } else {
            batch.add(sendAndCheck("COOKIE-003", replaceHeader(baseGet, "Cookie", "session=expired_session_000"), ek, host));
        }

        // COOKIE-004: Unknown cookie — random value appended to LSQAUTH
        if (lsqAuth != null) {
            String randomVal = lsqAuth + "_random_" + Long.toHexString(System.nanoTime());
            String unknown = replaceCookieValue(origCookie, "LSQAUTH", randomVal);
            batch.add(sendAndCheck("COOKIE-004", replaceHeader(baseGet, "Cookie", unknown), ek, host));
        } else {
            batch.add(sendAndCheck("COOKIE-004", addHeader(baseGet, "Cookie", "unknown_cookie=test_value"), ek, host));
        }

        // COOKIE-005: Malformed cookie
        HttpRequest malformed = replaceHeader(baseGet, "Cookie", ";;;===malformed;;;");
        batch.add(sendAndCheck("COOKIE-005", malformed, ek, host));

        // AUTH-001: Authenticated vs unauthenticated
        batch.add(sendAndCheck("AUTH-001", removeHeader(baseGet, "Cookie"), ek, host));

        // AUTH-002: SSO/OAuth redirect — check auth paths
        addNotTested("AUTH-002", ek, host, pathAndQuery, batch,
                "Requires approved test accounts and callback endpoints");

        // AUTH-003: Logout
        batch.add(sendAndCheck("AUTH-003",
                buildReq(host, port, isHttps, "GET", "/logout", base), ek, host));
    }

    // --- Edge Case Probes ---

    private void runEdgeProbes(String host, int port, boolean isHttps, String pathAndQuery,
                                HttpRequest base, String ek, List<TestcaseResult> batch) {
        HttpRequest baseGet = buildReq(host, port, isHttps, "GET", pathAndQuery, base);

        // EDGE-001: Duplicate headers check
        batch.add(sendAndCheckDuplicates("EDGE-001", baseGet, ek, host));

        // EDGE-003: Exact syntax check
        batch.add(sendAndCheckExact("EDGE-003", baseGet, ek, host));

        // EDGE-004: Wildcard check
        batch.add(sendAndCheckWildcard("EDGE-004",
                addHeader(baseGet, "Origin", "https://wildcard-test.com"), ek, host));

        // EDGE-005: Error page duplicates
        batch.add(sendAndCheckDuplicates("EDGE-005",
                buildReq(host, port, isHttps, "GET", "/nonexistent-edge-test-404", base), ek, host));
    }

    // === Core send/check helpers ===

    private TestcaseResult sendAndCheck(String tcId, HttpRequest request, String ek, String host) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;

        request = addMarker(request);
        if (!scopeManager.isInScope(host)) {
            return makeNotTested(tc, ek, host, "", "Target host out of scope");
        }

        try {
            HttpRequestResponse rr = send(request);
            var resp = rr.response();
            if (resp == null) {
                return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                        "No response received", tc.expectedResult(), "", "Timeout or connection error");
            }

            int status = resp.statusCode();
            String path = request.path() != null ? request.path() : "/";

            List<String> missing = new ArrayList<>();
            for (String h : BASELINE_HEADERS) {
                if (resp.headerValue(h) == null) {
                    if (h.equals("x-frame-options") && isXfoCoveredByCsp(resp)) continue;
                    missing.add(h);
                }
            }

            if (missing.isEmpty()) {
                boolean xfoCovered = resp.headerValue("x-frame-options") == null && isXfoCoveredByCsp(resp);
                String actual = xfoCovered ? "All present (XFO covered by CSP frame-ancestors)" : "All present";
                return makeResult(tc, ek, host, path, status, ResultStatus.PASS,
                        "All baseline headers present (HTTP " + status + ")",
                        tc.expectedResult(), actual, "HTTP " + status);
            }
            return makeResult(tc, ek, host, path, status, ResultStatus.FAIL,
                    "Missing: " + String.join(", ", missing) + " (HTTP " + status + ")",
                    tc.expectedResult(), "Missing: " + String.join(", ", missing), "HTTP " + status);
        } catch (Exception e) {
            return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    "Request failed: " + e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    private TestcaseResult sendAndCheckCors(String tcId, HttpRequest request, String ek,
                                             String host, String sentOrigin) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;

        request = addMarker(request);
        if (!scopeManager.isInScope(host)) {
            return makeNotTested(tc, ek, host, "", "Out of scope");
        }

        try {
            HttpRequestResponse rr = send(request);
            var resp = rr.response();
            if (resp == null) {
                return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                        "No response", tc.expectedResult(), "", "");
            }

            String acao = resp.headerValue("Access-Control-Allow-Origin");
            String path = request.path() != null ? request.path() : "/";
            int status = resp.statusCode();

            List<String> missing = new ArrayList<>();
            for (String h : BASELINE_HEADERS) {
                if (resp.headerValue(h) == null) missing.add(h);
            }

            boolean untrusted = !sentOrigin.contains(host) && !"null".equals(sentOrigin);
            boolean acaoReflects = acao != null
                    && (acao.trim().equals(sentOrigin) || "*".equals(acao.trim()));

            List<String> issues = new ArrayList<>(missing.stream().map(h -> "Missing: " + h).toList());
            if (acaoReflects && untrusted) {
                issues.add("ACAO reflects untrusted origin: " + acao);
            }

            if (issues.isEmpty()) {
                return makeResult(tc, ek, host, path, status, ResultStatus.PASS,
                        "Headers present, ACAO safe", tc.expectedResult(),
                        "All present; ACAO: " + (acao != null ? acao : "(absent)"),
                        "Origin: " + sentOrigin);
            }
            return makeResult(tc, ek, host, path, status, ResultStatus.FAIL,
                    String.join("; ", issues), tc.expectedResult(),
                    String.join("; ", issues), "Origin: " + sentOrigin);
        } catch (Exception e) {
            return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    private TestcaseResult sendAndCheckCorsCredentials(String tcId, HttpRequest request,
                                                        String ek, String host) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;

        request = addMarker(request);
        if (!scopeManager.isInScope(host)) {
            return makeNotTested(tc, ek, host, "", "Out of scope");
        }

        try {
            HttpRequestResponse rr = send(request);
            var resp = rr.response();
            if (resp == null) return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    "No response", tc.expectedResult(), "", "");

            String acao = resp.headerValue("Access-Control-Allow-Origin");
            String creds = resp.headerValue("Access-Control-Allow-Credentials");
            String path = request.path() != null ? request.path() : "/";
            int status = resp.statusCode();

            boolean credsFail = acao != null && "*".equals(acao.trim())
                    && "true".equalsIgnoreCase(creds != null ? creds.trim() : "");

            List<String> missing = new ArrayList<>();
            for (String h : BASELINE_HEADERS) {
                if (resp.headerValue(h) == null) {
                    if (h.equals("x-frame-options") && isXfoCoveredByCsp(resp)) continue;
                    missing.add(h);
                }
            }

            boolean fail = credsFail || !missing.isEmpty();
            String actual = missing.isEmpty() ? "All present" : "Missing: " + String.join(", ", missing);
            if (credsFail) actual += "; ACAO wildcard with credentials=true";

            return makeResult(tc, ek, host, path, status,
                    fail ? ResultStatus.FAIL : ResultStatus.PASS,
                    fail ? (credsFail ? "ACAO wildcard with credentials=true"
                            : "Missing: " + String.join(", ", missing))
                         : "CORS credentials safe",
                    tc.expectedResult(), actual,
                    "Credentials: " + (creds != null ? creds : "(absent)"));
        } catch (Exception e) {
            return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    private TestcaseResult sendAndCheckDuplicates(String tcId, HttpRequest request, String ek, String host) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;

        request = addMarker(request);
        if (!scopeManager.isInScope(host)) return makeNotTested(tc, ek, host, "", "Out of scope");

        try {
            HttpRequestResponse rr = send(request);
            var resp = rr.response();
            if (resp == null) return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    "No response", tc.expectedResult(), "", "");

            String path = request.path() != null ? request.path() : "/";
            int status = resp.statusCode();

            Map<String, Integer> counts = new HashMap<>();
            for (var h : resp.headers()) {
                String name = h.name().toLowerCase(Locale.ROOT);
                counts.merge(name, 1, Integer::sum);
            }

            List<String> dups = new ArrayList<>();
            for (String secHeader : BASELINE_HEADERS) {
                int count = counts.getOrDefault(secHeader, 0);
                if (count > 1) dups.add(secHeader + " (" + count + "x)");
            }

            if (dups.isEmpty()) {
                return makeResult(tc, ek, host, path, status, ResultStatus.PASS,
                        "No duplicate security headers", tc.expectedResult(), "No duplicates", "HTTP " + status);
            }
            return makeResult(tc, ek, host, path, status, ResultStatus.FAIL,
                    "Duplicates: " + String.join(", ", dups), tc.expectedResult(),
                    String.join(", ", dups), "HTTP " + status);
        } catch (Exception e) {
            return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    private TestcaseResult sendAndCheckExact(String tcId, HttpRequest request, String ek, String host) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;

        request = addMarker(request);
        if (!scopeManager.isInScope(host)) return makeNotTested(tc, ek, host, "", "Out of scope");

        try {
            HttpRequestResponse rr = send(request);
            var resp = rr.response();
            if (resp == null) return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    "No response", tc.expectedResult(), "", "");

            String path = request.path() != null ? request.path() : "/";
            int status = resp.statusCode();

            Map<String, String> hdrs = resp.headers().stream()
                    .collect(Collectors.toMap(
                            h -> h.name().toLowerCase(Locale.ROOT),
                            h -> h.value(), (a, b) -> a));

            List<String> issues = new ArrayList<>();
            for (String h : BASELINE_HEADERS) {
                String val = hdrs.get(h);
                if (val == null) {
                    issues.add(h + ": absent");
                    continue;
                }
                BaselineEvaluator.EvalResult er = evaluator.evaluate(h, val, true);
                if (er.status() == ResultStatus.FAIL) {
                    issues.add(h + ": " + er.summary());
                }
            }

            if (issues.isEmpty()) {
                return makeResult(tc, ek, host, path, status, ResultStatus.PASS,
                        "All headers match baseline exactly", tc.expectedResult(),
                        "All match", "HTTP " + status);
            }
            return makeResult(tc, ek, host, path, status, ResultStatus.FAIL,
                    String.join("; ", issues), tc.expectedResult(),
                    String.join("; ", issues), "HTTP " + status);
        } catch (Exception e) {
            return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    private TestcaseResult sendAndCheckWildcard(String tcId, HttpRequest request, String ek, String host) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;

        request = addMarker(request);
        if (!scopeManager.isInScope(host)) return makeNotTested(tc, ek, host, "", "Out of scope");

        try {
            HttpRequestResponse rr = send(request);
            var resp = rr.response();
            if (resp == null) return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    "No response", tc.expectedResult(), "", "");

            String path = request.path() != null ? request.path() : "/";
            int status = resp.statusCode();
            String acao = resp.headerValue("Access-Control-Allow-Origin");
            String csp = resp.headerValue("Content-Security-Policy");

            List<String> issues = new ArrayList<>();
            if (acao != null && "*".equals(acao.trim())) issues.add("ACAO uses wildcard *");
            if (csp != null && csp.contains("*")) issues.add("CSP contains wildcard");

            if (issues.isEmpty()) {
                return makeResult(tc, ek, host, path, status, ResultStatus.PASS,
                        "No unsafe wildcards", tc.expectedResult(), "No wildcards", "HTTP " + status);
            }
            return makeResult(tc, ek, host, path, status, ResultStatus.FAIL,
                    String.join("; ", issues), tc.expectedResult(),
                    String.join("; ", issues), "HTTP " + status);
        } catch (Exception e) {
            return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    // === Specialized check helpers ===

    private TestcaseResult sendFirstReachable(String tcId, String host, int port, boolean isHttps,
                                               HttpRequest base, String ek, String... paths) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;
        if (!scopeManager.isInScope(host)) return makeNotTested(tc, ek, host, "", "Out of scope");

        for (String path : paths) {
            HttpRequest req = addMarker(buildReq(host, port, isHttps, "GET", path, base));
            try {
                HttpRequestResponse rr = send(req);
                var resp = rr.response();
                if (resp == null) continue;
                int status = resp.statusCode();
                if (status == 404 || status == 0) continue;

                List<String> missing = new ArrayList<>();
                for (String h : BASELINE_HEADERS) {
                    if (resp.headerValue(h) == null) missing.add(h);
                }
                if (missing.isEmpty()) {
                    return makeResult(tc, ek, host, path, status, ResultStatus.PASS,
                            "All baseline headers present on " + path + " (HTTP " + status + ")",
                            tc.expectedResult(), "All present", "HTTP " + status);
                }
                return makeResult(tc, ek, host, path, status, ResultStatus.FAIL,
                        "Missing on " + path + ": " + String.join(", ", missing) + " (HTTP " + status + ")",
                        tc.expectedResult(), "Missing: " + String.join(", ", missing), "HTTP " + status);
            } catch (Exception ignored) {}
        }
        return makeNotTested(tc, ek, host, paths[0], "No reachable endpoint found at " + String.join(", ", paths));
    }

    private TestcaseResult sendAndCheckCorsHeader(String tcId, HttpRequest request, String ek,
                                                    String host, String corsHeaderName) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc == null || !isSelected(tcId)) return null;
        request = addMarker(request);
        if (!scopeManager.isInScope(host)) return makeNotTested(tc, ek, host, "", "Out of scope");

        try {
            HttpRequestResponse rr = send(request);
            var resp = rr.response();
            if (resp == null) return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    "No response", tc.expectedResult(), "", "");

            String path = request.path() != null ? request.path() : "/";
            int status = resp.statusCode();
            String corsValue = resp.headerValue(corsHeaderName);

            List<String> missing = new ArrayList<>();
            for (String h : BASELINE_HEADERS) {
                if (resp.headerValue(h) == null) missing.add(h);
            }

            List<String> evidence = new ArrayList<>();
            evidence.add(corsHeaderName + ": " + (corsValue != null ? corsValue : "(absent)"));
            if (!missing.isEmpty()) evidence.add("Missing baseline: " + String.join(", ", missing));

            boolean pass = missing.isEmpty();
            return makeResult(tc, ek, host, path, status,
                    pass ? ResultStatus.PASS : ResultStatus.FAIL,
                    pass ? "Baseline present; " + corsHeaderName + ": " + (corsValue != null ? corsValue : "(absent)")
                         : "Missing: " + String.join(", ", missing),
                    tc.expectedResult(),
                    pass ? "All present" : "Missing: " + String.join(", ", missing),
                    String.join("; ", evidence));
        } catch (Exception e) {
            return makeResult(tc, ek, host, "", 0, ResultStatus.ERROR,
                    e.getMessage(), tc.expectedResult(), "", e.toString());
        }
    }

    // === Request builder helpers ===

    private HttpRequest buildReq(String host, int port, boolean isHttps,
                                  String method, String path, HttpRequest base) {
        if (base != null) {
            return base
                    .withService(burp.api.montoya.http.HttpService.httpService(host, port, isHttps))
                    .withMethod(method)
                    .withPath(path)
                    .withRemovedHeader("Host")
                    .withAddedHeader("Host", host);
        }
        return HttpRequest.httpRequest()
                .withService(burp.api.montoya.http.HttpService.httpService(host, port, isHttps))
                .withMethod(method)
                .withPath(path)
                .withHeader("Host", host);
    }

    private HttpRequest addMarker(HttpRequest req) {
        return req.withAddedHeader(MARKER_HEADER, MARKER_VALUE);
    }

    private HttpRequest addHeader(HttpRequest req, String name, String value) {
        return req.withAddedHeader(name, value);
    }

    private HttpRequest replaceHeader(HttpRequest req, String name, String value) {
        return req.withRemovedHeader(name).withAddedHeader(name, value);
    }

    private HttpRequest removeHeader(HttpRequest req, String name) {
        return req.withRemovedHeader(name);
    }

    private String extractCookieValue(String cookieHeader, String name) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return null;
        for (String pair : cookieHeader.split(";")) {
            String trimmed = pair.trim();
            if (trimmed.startsWith(name + "=")) {
                return trimmed.substring(name.length() + 1);
            }
        }
        return null;
    }

    private String replaceCookieValue(String cookieHeader, String name, String newValue) {
        StringBuilder sb = new StringBuilder();
        for (String pair : cookieHeader.split(";")) {
            String trimmed = pair.trim();
            if (sb.length() > 0) sb.append("; ");
            if (trimmed.startsWith(name + "=")) {
                sb.append(name).append("=").append(newValue);
            } else {
                sb.append(trimmed);
            }
        }
        return sb.toString();
    }

    private boolean isXfoCoveredByCsp(burp.api.montoya.http.message.responses.HttpResponse resp) {
        String csp = resp.headerValue("Content-Security-Policy");
        return csp != null && csp.toLowerCase(Locale.ROOT).contains("frame-ancestors");
    }

    // === Result helpers ===

    private void addNotTested(String tcId, String ek, String host, String path,
                               List<TestcaseResult> batch, String reason) {
        TestcaseDefinition tc = library.get(tcId);
        if (tc != null && isSelected(tcId)) {
            batch.add(makeNotTested(tc, ek, host, path, reason));
        }
    }

    private TestcaseResult makeNotTested(TestcaseDefinition tc, String ek, String host,
                                          String path, String reason) {
        return makeResult(tc, ek, host, path, 0, ResultStatus.NOT_TESTED,
                reason, tc.expectedResult(), "N/A", "");
    }

    private TestcaseResult makeResult(TestcaseDefinition tc, String ek, String host,
                                      String path, int status, ResultStatus rs,
                                      String summary, String expected, String actual, String evidence) {
        HttpRequest req = lastRequest.get();
        burp.api.montoya.http.message.responses.HttpResponse resp = lastResponse.get();
        String reqStr = null;
        String respStr = null;
        try { if (req != null) reqStr = req.toString(); } catch (Exception ignored) {}
        try { if (resp != null) respStr = resp.toString(); } catch (Exception ignored) {}
        return new TestcaseResult(tc.id(), ek, Instant.now(),
                ExecutionMode.ACTIVE, rs, summary, expected, actual, evidence, null,
                host, path, status, reqStr, respStr);
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
