package com.securityheaders;

import java.util.List;
import java.util.stream.Collectors;

public class ResultFilterService {

    public List<HeaderResult> apply(List<HeaderResult> results, FilterState filter) {
        if (!filter.isActive()) {
            return results;
        }
        return results.stream()
                .filter(r -> matchesSearch(r, filter.searchText()))
                .filter(r -> matchesHost(r, filter.hostFilter()))
                .filter(r -> matchesStatus(r, filter.statusCodes()))
                .filter(r -> matchesHeader(r, filter.headerFilter()))
                .collect(Collectors.toList());
    }

    private boolean matchesSearch(HeaderResult r, String search) {
        if (search.isEmpty()) return true;
        return r.host().contains(search)
                || r.pathAndQuery().toLowerCase().contains(search);
    }

    private boolean matchesHost(HeaderResult r, String host) {
        if (host == null) return true;
        return r.host().equals(host);
    }

    private boolean matchesStatus(HeaderResult r, java.util.Set<Integer> codes) {
        if (codes.isEmpty()) return true;
        return codes.contains(r.statusCode());
    }

    private boolean matchesHeader(HeaderResult r, FilterState.HeaderFilter hf) {
        return switch (hf) {
            case ALL -> true;
            case ANY_MISSING -> r.hasAnyMissing();
            case HSTS_MISSING -> !r.hstsPresent();
            case CACHE_CONTROL_MISSING -> !r.cacheControlPresent();
            case XFO_MISSING -> !r.xfoPresent() && !r.xfoCoveredByCsp();
            case XCTO_MISSING -> !r.xctoPresent();
            case ACAO_MISSING -> !r.acaoPresent();
            case CSP_MISSING -> !r.cspPresent();
        };
    }
}
