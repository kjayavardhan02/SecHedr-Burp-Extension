package com.securityheaders;

import java.util.*;
import java.util.stream.Collectors;

public class SummaryService {

    public SummaryStats computeStats(List<HeaderResult> records) {
        int total = records.size();
        int withMissing = 0;
        int missingOccurrences = 0;
        Set<String> hosts = new HashSet<>();

        for (HeaderResult r : records) {
            hosts.add(r.host());
            int mc = r.missingCount();
            if (mc > 0) withMissing++;
            missingOccurrences += mc;
        }

        return new SummaryStats(total, withMissing, hosts.size(), missingOccurrences);
    }

    public List<HostSummary> computeHostSummaries(List<HeaderResult> records) {
        Map<String, List<HeaderResult>> byHost = records.stream()
                .collect(Collectors.groupingBy(HeaderResult::host, LinkedHashMap::new, Collectors.toList()));

        List<HostSummary> summaries = new ArrayList<>();
        for (var entry : byHost.entrySet()) {
            String host = entry.getKey();
            List<HeaderResult> group = entry.getValue();
            int responses = group.size();
            Set<String> endpoints = group.stream()
                    .map(HeaderResult::endpointKey)
                    .collect(Collectors.toSet());
            int withMissing = 0;
            int hsts = 0, cc = 0, xfo = 0, xcto = 0, acao = 0, csp = 0;
            for (HeaderResult r : group) {
                if (r.hasAnyMissing()) withMissing++;
                if (!r.hstsPresent()) hsts++;
                if (!r.cacheControlPresent()) cc++;
                if (!r.xfoPresent() && !r.xfoCoveredByCsp()) xfo++;
                if (!r.xctoPresent()) xcto++;
                if (!r.acaoPresent()) acao++;
                if (!r.cspPresent()) csp++;
            }
            summaries.add(new HostSummary(host, responses, endpoints.size(),
                    withMissing, hsts, cc, xfo, xcto, acao, csp));
        }
        return summaries;
    }

    public List<EndpointSummary> computeEndpointSummaries(List<HeaderResult> records) {
        Map<String, List<HeaderResult>> byEndpoint = records.stream()
                .collect(Collectors.groupingBy(HeaderResult::endpointKey,
                        LinkedHashMap::new, Collectors.toList()));

        List<EndpointSummary> summaries = new ArrayList<>();
        for (var entry : byEndpoint.entrySet()) {
            List<HeaderResult> group = entry.getValue();
            HeaderResult first = group.get(0);
            int responses = group.size();

            List<Integer> statusCodes = group.stream()
                    .map(HeaderResult::statusCode)
                    .distinct().sorted()
                    .collect(Collectors.toList());

            int withMissing = 0;
            int hsts = 0, cc = 0, xfo = 0, xcto = 0, acao = 0, csp = 0;
            Set<String> everMissing = new LinkedHashSet<>();

            for (HeaderResult r : group) {
                if (r.hasAnyMissing()) withMissing++;
                if (!r.hstsPresent()) { hsts++; everMissing.add("HSTS"); }
                if (!r.cacheControlPresent()) { cc++; everMissing.add("Cache-Control"); }
                if (!r.xfoPresent() && !r.xfoCoveredByCsp()) { xfo++; everMissing.add("XFO"); }
                if (!r.xctoPresent()) { xcto++; everMissing.add("XCTO"); }
                if (!r.acaoPresent()) { acao++; everMissing.add("ACAO"); }
                if (!r.cspPresent()) { csp++; everMissing.add("CSP"); }
            }

            summaries.add(new EndpointSummary(
                    first.host(), first.port(), first.method(), first.pathAndQuery(),
                    responses, statusCodes, withMissing,
                    hsts, cc, xfo, xcto, acao, csp, everMissing));
        }
        return summaries;
    }
}
