package com.securityheaders;

import com.securityheaders.policy.PolicyComplianceStatus;

import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class ResultFilterService {

    public List<HeaderResult> apply(List<HeaderResult> results, FilterState filter) {
        return apply(results, filter, null);
    }

    public List<HeaderResult> apply(List<HeaderResult> results, FilterState filter,
                                     Function<HeaderResult, PolicyComplianceStatus> policyStatusFn) {
        if (!filter.isActive()) {
            return results;
        }
        return results.stream()
                .filter(r -> matchesSearch(r, filter.searchText()))
                .filter(r -> matchesHost(r, filter.hostFilter()))
                .filter(r -> matchesStatus(r, filter.statusCodes()))
                .filter(r -> matchesHeader(r, filter.headerFilter()))
                .filter(r -> matchesPolicyCompliance(r, filter.policyComplianceFilter(), policyStatusFn))
                .collect(Collectors.toList());
    }

    private boolean matchesPolicyCompliance(HeaderResult r, String filterValue,
                                             Function<HeaderResult, PolicyComplianceStatus> fn) {
        if (filterValue == null || "All".equals(filterValue)) return true;
        if (fn == null) return true;
        PolicyComplianceStatus status = fn.apply(r);
        return status.displayLabel().equals(filterValue);
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
            case ALL_MISSING -> r.missingCount() == 6;
            case HSTS_MISSING -> !r.hstsPresent();
            case CACHE_CONTROL_MISSING -> !r.cacheControlPresent();
            case XFO_MISSING -> !r.xfoPresent() && !r.xfoCoveredByCsp();
            case XCTO_MISSING -> !r.xctoPresent();
            case ACAO_MISSING -> !r.acaoPresent();
            case CSP_MISSING -> !r.cspPresent();
        };
    }
}
