package com.securityheaders;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;

import com.securityheaders.testcase.*;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class HeaderCheckHttpHandler implements HttpHandler {

    private static final String[] HEADER_NAMES = {
        "strict-transport-security",
        "cache-control",
        "x-frame-options",
        "x-content-type-options",
        "access-control-allow-origin",
        "content-security-policy"
    };

    private final ResultStore resultStore;
    private final ScopeManager scopeManager;
    private volatile boolean enabled = true;
    private volatile Runnable onNewResult;

    private volatile PassiveEngine passiveEngine;
    private volatile ActiveRunner activeRunner;
    private volatile TestcaseResultStore testcaseResultStore;
    private volatile EndpointRegistry endpointRegistry;
    private volatile boolean passiveEnabled = true;
    private volatile boolean activeEnabled = true;
    private volatile Runnable onTestcaseResult;

    private final Set<String> seenProxyUrls = ConcurrentHashMap.newKeySet();
    private volatile ResultStore repeaterResultStore;
    private volatile Runnable onRepeaterResult;
    private volatile ScanHealthTracker healthTracker;

    public HeaderCheckHttpHandler(ResultStore resultStore, ScopeManager scopeManager) {
        this.resultStore = resultStore;
        this.scopeManager = scopeManager;
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public void setOnNewResult(Runnable callback) { this.onNewResult = callback; }

    public boolean isPassiveEnabled() { return passiveEnabled; }
    public void setPassiveEnabled(boolean enabled) { this.passiveEnabled = enabled; }
    public boolean isActiveEnabled() { return activeEnabled; }
    public void setActiveEnabled(boolean enabled) {
        this.activeEnabled = enabled;
        if (activeRunner != null) activeRunner.setEnabled(enabled);
    }
    public void setOnTestcaseResult(Runnable callback) { this.onTestcaseResult = callback; }

    public void setPassiveEngine(PassiveEngine engine) { this.passiveEngine = engine; }
    public void setActiveRunner(ActiveRunner runner) { this.activeRunner = runner; }
    public void setTestcaseResultStore(TestcaseResultStore store) { this.testcaseResultStore = store; }
    public void setEndpointRegistry(EndpointRegistry registry) { this.endpointRegistry = registry; }
    public void setRepeaterResultStore(ResultStore store) { this.repeaterResultStore = store; }
    public void setOnRepeaterResult(Runnable callback) { this.onRepeaterResult = callback; }
    public void setHealthTracker(ScanHealthTracker tracker) { this.healthTracker = tracker; }
    public void clearSeenUrls() { seenProxyUrls.clear(); }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!enabled) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        var request = responseReceived.initiatingRequest();

        if (ActiveRunner.isOwnRequest(request)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        ToolType toolType = responseReceived.toolSource().toolType();
        if (toolType != ToolType.PROXY && toolType != ToolType.REPEATER) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        String host = extractHost(responseReceived);
        if (host == null || !scopeManager.isInScope(host)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        int port = extractPort(responseReceived);
        String method = extractMethod(request);
        String pathAndQuery = extractPath(responseReceived);
        int statusCode = responseReceived.statusCode();
        boolean isHttps = false;
        try { isHttps = request.httpService().secure(); } catch (Exception ignored) {}

        List<String> headerNamesLower = responseReceived.headers().stream()
                .map(h -> h.name().toLowerCase(Locale.ROOT))
                .toList();

        boolean[] present = new boolean[HEADER_NAMES.length];
        for (int i = 0; i < HEADER_NAMES.length; i++) {
            present[i] = headerNamesLower.contains(HEADER_NAMES[i]);
        }

        boolean xfoCoveredByCsp = false;
        if (!present[2] && present[5]) {
            for (var h : responseReceived.headers()) {
                if (h.name().equalsIgnoreCase("content-security-policy")
                        && h.value().toLowerCase(Locale.ROOT).contains("frame-ancestors")) {
                    xfoCoveredByCsp = true;
                    break;
                }
            }
        }

        String rawReq = extractRawRequest(request);
        String rawResp = extractRawResponse(responseReceived);

        String acaoValue = null;
        for (var h : responseReceived.headers()) {
            if (h.name().equalsIgnoreCase("access-control-allow-origin")) {
                acaoValue = h.value();
                break;
            }
        }
        String requestOrigin = request.headerValue("Origin");

        if (toolType == ToolType.REPEATER) {
            HeaderResult result = new HeaderResult(
                    host, port, method, pathAndQuery, statusCode,
                    present[0], present[1], present[2], xfoCoveredByCsp,
                    present[3], present[4], present[5],
                    rawReq, rawResp, acaoValue, requestOrigin, isHttps);

            ResultStore rStore = repeaterResultStore;
            if (rStore != null) {
                rStore.add(result);
                Runnable rcb = onRepeaterResult;
                if (rcb != null) javax.swing.SwingUtilities.invokeLater(rcb);
            }
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        String urlKey = host + ":" + port + ":" + method + ":" + pathAndQuery;
        if (!seenProxyUrls.add(urlKey)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HeaderResult result = new HeaderResult(
                host, port, method, pathAndQuery, statusCode,
                present[0], present[1], present[2], xfoCoveredByCsp,
                present[3], present[4], present[5],
                rawReq, rawResp, acaoValue, requestOrigin, isHttps
        );

        resultStore.add(result);
        if (healthTracker != null) healthTracker.recordRequestProcessed();

        Runnable cb = onNewResult;
        if (cb != null) {
            javax.swing.SwingUtilities.invokeLater(cb);
        }

        if (passiveEnabled && passiveEngine != null && testcaseResultStore != null) {
            try {
                String endpointKey = host + ":" + port + ":" + method + ":" + pathAndQuery;

                Map<String, String> headersLower = new HashMap<>();
                Map<String, List<String>> headerMultiLower = new HashMap<>();
                for (var h : responseReceived.headers()) {
                    String name = h.name().toLowerCase(Locale.ROOT);
                    headersLower.putIfAbsent(name, h.value());
                    headerMultiLower.computeIfAbsent(name, k -> new ArrayList<>()).add(h.value());
                }

                Map<String, String> requestHeadersLower = new HashMap<>();
                for (var h : request.headers()) {
                    requestHeadersLower.putIfAbsent(h.name().toLowerCase(Locale.ROOT), h.value());
                }

                PassiveEngine.ObservedResponse obs = new PassiveEngine.ObservedResponse(
                        endpointKey, Instant.now(), host, port, method, pathAndQuery,
                        statusCode, isHttps, headersLower, headerMultiLower, requestHeadersLower,
                        rawReq, rawResp);

                List<TestcaseResult> passiveResults = passiveEngine.analyze(obs);
                if (!passiveResults.isEmpty()) {
                    testcaseResultStore.addAll(passiveResults);
                    if (healthTracker != null) {
                        for (TestcaseResult tr : passiveResults) {
                            if (tr.status() == ResultStatus.ERROR) {
                                healthTracker.recordError(tr.testcaseId(), tr.endpointKey(), tr.errorDetails());
                            } else {
                                healthTracker.recordTestcaseCompleted();
                            }
                        }
                    }
                    Runnable tcb = onTestcaseResult;
                    if (tcb != null) javax.swing.SwingUtilities.invokeLater(tcb);
                }

                if (endpointRegistry != null) {
                    endpointRegistry.registerObserved(endpointKey);
                }
                if (activeEnabled && activeRunner != null) {
                    activeRunner.scheduleActiveTests(host, port, method, pathAndQuery, isHttps, request);
                }
            } catch (Exception ignored) {}
        }

        Annotations annotations = Annotations.annotations(HighlightColor.CYAN);
        return ResponseReceivedAction.continueWith(responseReceived, annotations);
    }

    private String extractHost(HttpResponseReceived responseReceived) {
        try {
            var request = responseReceived.initiatingRequest();
            String host = request.headerValue("Host");
            if (host != null) {
                int colonIndex = host.indexOf(':');
                if (colonIndex > 0) {
                    host = host.substring(0, colonIndex);
                }
                return host.trim().toLowerCase(Locale.ROOT);
            }
            return request.httpService().host().toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    private int extractPort(HttpResponseReceived responseReceived) {
        try {
            var service = responseReceived.initiatingRequest().httpService();
            return service.port();
        } catch (Exception e) {
            return 0;
        }
    }

    private String extractMethod(burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            return request.method().toUpperCase(Locale.ROOT);
        } catch (Exception e) {
            return "GET";
        }
    }

    private String extractPath(HttpResponseReceived responseReceived) {
        try {
            String path = responseReceived.initiatingRequest().path();
            if (path == null || path.isEmpty()) {
                return "/";
            }
            return path;
        } catch (Exception e) {
            return "/";
        }
    }

    private String extractRawRequest(burp.api.montoya.http.message.requests.HttpRequest request) {
        try {
            String raw = request.toString();
            if (raw != null && !raw.isEmpty()) return raw;
        } catch (Exception ignored) {}
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(request.method()).append(" ").append(request.path()).append(" ")
              .append(request.httpVersion()).append("\r\n");
            for (var h : request.headers()) {
                sb.append(h.name()).append(": ").append(h.value()).append("\r\n");
            }
            sb.append("\r\n");
            String body = request.bodyToString();
            if (body != null && !body.isEmpty()) sb.append(body);
            return sb.toString();
        } catch (Exception ignored) {}
        return null;
    }

    private String extractRawResponse(HttpResponseReceived responseReceived) {
        try {
            String raw = responseReceived.toString();
            if (raw != null && !raw.isEmpty()) return raw;
        } catch (Exception ignored) {}
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("HTTP/").append(responseReceived.httpVersion()).append(" ")
              .append(responseReceived.statusCode()).append(" ")
              .append(responseReceived.reasonPhrase()).append("\r\n");
            for (var h : responseReceived.headers()) {
                sb.append(h.name()).append(": ").append(h.value()).append("\r\n");
            }
            sb.append("\r\n");
            String body = responseReceived.bodyToString();
            if (body != null && !body.isEmpty()) sb.append(body);
            return sb.toString();
        } catch (Exception ignored) {}
        return null;
    }
}
